#!/usr/bin/env python3
# agent1.py - C阶段：双Agent对抗审计，输出符合新D阶段格式
# 优化点：并发处理、流式写入、证据精简、verification_context自动推断、结果缓存

import argparse
import functools
import json
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

from openai import OpenAI

# ==================== 配置（可根据实际情况调整）====================
MODEL_NAME = "deepseek-v4-flash"          # 使用Flash模型，速度更快
API_KEY = "sk-accf76251b06423b8c02257bb8da0758"
BASE_URL = "https://api.deepseek.com/v1"
CONFIDENCE_THRESHOLD = 0.60               # 放宽到0.60，让更多假设进入D阶段（原0.65）
STATIC_CONFIDENCE_THRESHOLD = 0.90        # P0：C阶段静态强确认，直接进入静态报告
MAX_WORKERS = 5                           # 并发线程数，平衡速度与稳定性
MAX_CALL_CHAIN = 8                        # 调用序列最多保留个数（精简token）
MAX_SINK_SOURCE = 3                       # sink/source最多保留个数（精简token）

client = OpenAI(api_key=API_KEY, base_url=BASE_URL, timeout=60, max_retries=0)


# ==================== 数据加载模块 ====================
def parse_args():
    parser = argparse.ArgumentParser(description="C阶段：基于A阶段LLM证据和B阶段候选执行双Agent审计")
    parser.add_argument("--llm-input", default="data/samples.llm.jsonl", help="A阶段导出的 samples.llm.jsonl")
    parser.add_argument("--b-candidates", default="data/candidates.scored.jsonl", help="B阶段输出 candidates.scored.jsonl")
    parser.add_argument("--output", default="data/hypotheses.jsonl", help="C阶段输出给D验证的 hypotheses.jsonl")
    parser.add_argument("--static-output", default="", help="P0静态强确认报告；默认从 --output 推导")
    parser.add_argument("--audit-output", default="", help="P3和错误审计日志；默认从 --output 推导")
    parser.add_argument("--max-samples", type=int, default=None, help="最多审计候选数量；默认不限制")
    return parser.parse_args()


def utc_now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def default_side_output(output_path: Path, subdir: str, filename: str) -> Path:
    if output_path.parent.name == "out":
        return output_path.parent.parent / subdir / filename
    return output_path.with_name(f"{output_path.stem}.{filename}")


def read_jsonl(path):
    records = []
    with open(path, encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_no}: invalid JSON: {exc}") from exc
    return records


def load_candidates(path):
    """加载B阶段输出的候选样本（candidates.scored.jsonl），每行一个JSON对象"""
    return read_jsonl(path)


def load_llm_samples(path):
    """加载A阶段导出的LLM证据（samples.llm.jsonl），建立sample_id到证据的映射"""
    llm_map = {}
    for obj in read_jsonl(path):
        sample_id = obj.get("sample_id")
        if not sample_id:
            raise ValueError(f"{path}: LLM evidence record missing sample_id")
        if sample_id in llm_map:
            raise ValueError(f"{path}: duplicate LLM evidence sample_id={sample_id}")
        llm_map[sample_id] = obj
    return llm_map


def validate_inputs(candidates, llm_map):
    missing = sorted(
        {
            str(cand.get("sample_id"))
            for cand in candidates
            if not cand.get("sample_id") or cand.get("sample_id") not in llm_map
        }
    )
    if missing:
        preview = ", ".join(missing[:10])
        suffix = "" if len(missing) <= 10 else f" ... (+{len(missing) - 10} more)"
        raise ValueError(f"B candidates missing matching A LLM evidence sample_id(s): {preview}{suffix}")


# ==================== verification_context 自动推断模块 ====================
@functools.lru_cache(maxsize=128)
def infer_verification_context(repo_path: str) -> dict:
    """
    根据代码仓库根目录自动推断编译运行环境。
    优化点：使用缓存避免重复扫描同一仓库；只检查少量常见文件名，速度极快。
    返回D阶段所需的verification_context字典。
    """
    ctx = {
        "repo_path": repo_path,
        "config_cmd": "",
        "build_cmd": "",
        "run_cmd": "",
        "oracle": {
            "failure_patterns": ["Segmentation fault", "AddressSanitizer", "null pointer", "core dumped"],
            "expect_nonzero_exit": True
        },
        "input_source": "unknown",
        "seed_inputs": []
    }
    if not repo_path or not os.path.isdir(repo_path):
        return ctx

    # 检测构建系统（只检查根目录固定文件名）
    if os.path.exists(os.path.join(repo_path, "Makefile")):
        ctx["build_cmd"] = "make -j4"
        if os.path.exists(os.path.join(repo_path, "configure")):
            ctx["config_cmd"] = "./configure"
        elif os.path.exists(os.path.join(repo_path, "CMakeLists.txt")):
            ctx["config_cmd"] = "cmake ."
    elif os.path.exists(os.path.join(repo_path, "pom.xml")):
        ctx["build_cmd"] = "mvn compile"
    elif os.path.exists(os.path.join(repo_path, "package.json")):
        ctx["build_cmd"] = "npm install"
    elif os.path.exists(os.path.join(repo_path, "setup.py")) or os.path.exists(os.path.join(repo_path, "requirements.txt")):
        ctx["build_cmd"] = "pip install -r requirements.txt"

    # 检测常见测试脚本/PoC入口
    common_scripts = ["poc.py", "test.py", "run_test.sh", "fuzz.py", "exploit.py", "run.sh"]
    for script in common_scripts:
        script_path = os.path.join(repo_path, script)
        if os.path.exists(script_path):
            ctx["run_cmd"] = f"python3 {script}" if script.endswith(".py") else f"./{script}"
            break
    else:
        ctx["run_cmd"] = "AUTO_DETECT_FAILED"

    # 根据常见文件推断输入来源
    if os.path.exists(os.path.join(repo_path, "pom.xml")):
        ctx["input_source"] = "Java HTTP endpoint"
    elif os.path.exists(os.path.join(repo_path, "requirements.txt")):
        ctx["input_source"] = "Python script stdin"
    elif os.path.exists(os.path.join(repo_path, "Cargo.toml")):
        ctx["input_source"] = "Rust binary"
    elif os.path.exists(os.path.join(repo_path, "go.mod")):
        ctx["input_source"] = "Go binary"
    else:
        ctx["input_source"] = "unknown"

    ctx["seed_inputs"] = ["empty", "malformed", "large"]
    return ctx


# ==================== 证据文本构建模块（精简版） ====================
def compact_text(value, max_chars=600):
    text = " ".join(str(value or "").split())
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "..."


def build_evidence_brief(cand, llm_map):
    """
    为大模型构建精简但完整的审计证据。
    输入来自A阶段samples.llm.jsonl和B阶段candidates.scored.jsonl。
    """
    sample_id = cand.get("sample_id")
    llm = llm_map.get(sample_id, {})

    lines = []
    lines.append(f"项目:{cand.get('project_id','?')} 样本:{sample_id}")
    lines.append(f"路由:{cand.get('route','?')}")

    ep = llm.get("entrypoint", {})
    entry_desc = []
    if ep.get("file"):
        entry_desc.append(str(ep.get("file")))
    if ep.get("function"):
        entry_desc.append(f"::{ep.get('function')}")
    if ep.get("line"):
        entry_desc.append(f":{ep.get('line')}")
    if entry_desc:
        lines.append(f"入口:{''.join(entry_desc)}")

    focus = llm.get("focus", {})
    focus_file = focus.get("file") or cand.get("file", "?")
    focus_line = focus.get("line") or cand.get("line", 0)
    lines.append(f"位置:{focus_file}:{focus_line}")
    lines.append(f"B阶段证据:{cand.get('evidence_slice','')}")
    if llm.get("evidence_slice"):
        lines.append(f"A阶段证据:{compact_text(llm.get('evidence_slice'))}")

    # A阶段代表性source-sink流
    flows = llm.get("source_sink_flows", [])
    for flow in flows[:MAX_SINK_SOURCE]:
        source_token = flow.get("source_token", flow.get("source_id", ""))
        sink_token = flow.get("sink_token", flow.get("sink_id", ""))
        status = flow.get("status", "")
        flow_kind = flow.get("flow_kind", "")
        lines.append(f"流:{source_token}->{sink_token} status={status} kind={flow_kind}")

    # A阶段代表性trace
    traces = llm.get("representative_traces", [])
    for trace in traces[:MAX_SINK_SOURCE]:
        tokens = trace.get("tokens", [])
        if tokens:
            lines.append(f"Trace:{' -> '.join(tokens[:MAX_CALL_CHAIN])}")
        if trace.get("evidence_slice"):
            lines.append(f"Trace证据:{compact_text(trace.get('evidence_slice'))}")

    # A阶段代码片段
    code_slices = llm.get("code_slices", [])
    for item in code_slices[:MAX_SINK_SOURCE]:
        roles = ",".join(item.get("roles", []))
        loc = f"{item.get('file','?')}:{item.get('line_start','?')}-{item.get('line_end','?')}"
        lines.append(f"代码片段[{roles}] {loc}: {compact_text(item.get('text'))}")

    # A阶段内部函数摘要
    summaries = llm.get("internal_function_summaries", [])
    for item in summaries[:2]:
        loc = f"{item.get('file','?')}:{item.get('line_start','?')}-{item.get('line_end','?')}"
        calls = " -> ".join(item.get("calls", [])[:MAX_CALL_CHAIN])
        lines.append(f"函数:{item.get('function','?')} {loc} 调用:{calls}")
        excerpt = (item.get("excerpt") or {}).get("text", "")
        if excerpt:
            lines.append(f"函数证据:{compact_text(excerpt)}")

    # B阶段风险评分
    lines.append(f"风险:稀有度{cand.get('rarity_score',0.5):.2f} sink{cand.get('sink_score',0.5):.2f} 偏离{cand.get('pattern_deviation_score',0.5):.2f} 综合{cand.get('risk_score',0.5):.2f}")
    lines.append(f"标签:{', '.join(cand.get('reason_tags', []))}")

    return "\n".join(lines)


# ==================== 红队三轮提示词 ====================
PROPOSER_PROMPT = """你是一位红队安全审计专家。基于以下代码证据，高召回判断是否存在安全漏洞。

**审计信息**：
{evidence_brief}

**任务**：
- 如果存在安全漏洞（如缓冲区溢出、整数溢出、空指针解引用、权限缺失、SQL注入等），输出漏洞描述、CWE编号、**假设条件集合**、**触发路径**、攻击前提条件，以及对漏洞存在的置信度（0~1）。
- 如果确定没有任何漏洞，输出 "NO_VULNERABILITY_FOUND"。

**输出格式（严格JSON）**：
{{
  "claim": "漏洞描述，无漏洞写'NO_VULNERABILITY_FOUND'",
  "cwe_candidates": ["CWE-XXX"],
  "hypothesis_conditions": [
    {{"id": "A1", "description": "假设条件"}}
  ],
  "trigger_path": [
    {{"step": 1, "loc": "L? 或 描述", "code": "关键代码行"}}
  ],
  "preconditions": ["攻击者能够控制某个输入或参数"],
  "confidence": 0.8
}}

**注意**：即使代码中可能存在防御检查，你也必须输出假设条件和路径，不要提前过滤。"""

RED_REVIEW_PROMPT = """你仍然是红队安全审计专家，不是蓝队。请对第一轮判断做自查和修正。

**代码证据**：
{evidence_brief}

**第一轮判断**：
{proposer_json}

**任务**：
- 如果第一轮已发现漏洞，检查 source/sink 或 API misuse 路径是否真实、是否引用了不存在的代码。
- 如果第一轮判断为 NO_VULNERABILITY_FOUND，但证据中存在具体可验证漏洞路径，必须纠正为漏洞。
- 只有发现硬矛盾（路径不可达、sink不存在、source和sink不连通、把good路径当bad路径等）时，才列入 hard_contradictions。

**输出格式（严格JSON）**：
{{
  "claim": "漏洞描述，无漏洞写'NO_VULNERABILITY_FOUND'",
  "cwe_candidates": ["CWE-XXX"],
  "trigger_path": [
    {{"step": 1, "loc": "L? 或 描述", "code": "关键代码行"}}
  ],
  "preconditions": ["攻击者能够控制某个输入或参数"],
  "confidence": 0.8,
  "hard_contradictions": [],
  "evidence_complete": true,
  "review_notes": "自查结论"
}}"""

RED_FINAL_PROMPT = """你是红队最终整理者。请汇总前两轮结果，输出可用于分流的最终漏洞假设。

**代码证据**：
{evidence_brief}

**第一轮判断**：
{proposer_json}

**第二轮自查**：
{review_json}

**分流要求**：
- 如果存在可验证漏洞路径，输出具体漏洞假设。
- 如果无漏洞，输出 NO_VULNERABILITY_FOUND。
- 如果发现硬矛盾，写入 hard_contradictions。
- 不要输出 HTTP/base_url/token/*.http 等Web验证内容；这里的API指C/C++函数调用接口或调用序列。

**输出格式（严格JSON）**：
{{
  "claim": "最终漏洞描述或NO_VULNERABILITY_FOUND",
  "cwe_candidates": ["CWE-XXX"],
  "trigger_path": [
    {{"step": 1, "loc": "L? 或 描述", "code": "关键代码行"}}
  ],
  "preconditions": ["攻击者能够控制某个输入或参数"],
  "confidence": 0.8,
  "hard_contradictions": [],
  "evidence_complete": true,
  "stability": "stable_vulnerability|corrected_to_vulnerability|unstable_vulnerability|no_vulnerability|hard_contradiction",
  "final_notes": "最终整理说明"
}}"""


# ==================== LLM调用与假设构建模块 ====================
def call_llm(prompt):
    """调用大模型API，返回解析后的JSON字典。设置max_tokens=2000确保输出完整。"""
    try:
        r = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[{"role": "user", "content": prompt}],
            response_format={"type": "json_object"},
            max_tokens=2000,      # 保持足够大，避免截断
            temperature=0.0
        )
        return json.loads(r.choices[0].message.content)
    except Exception as e:
        print(f"LLM调用失败: {e}")
        return None


def response_claim(resp):
    if not isinstance(resp, dict):
        return ""
    return str(resp.get("claim") or resp.get("final_claim") or "")


def response_confidence(resp, default=0.0):
    if not isinstance(resp, dict):
        return default
    for key in ("confidence", "final_confidence", "adjusted_confidence"):
        value = resp.get(key)
        if value in (None, ""):
            continue
        try:
            return float(value)
        except (TypeError, ValueError):
            continue
    return default


def response_cwes(resp):
    if not isinstance(resp, dict):
        return []
    value = resp.get("cwe_candidates") or resp.get("CWE_candidates") or resp.get("cwe_list") or []
    if isinstance(value, list):
        return value
    if value:
        return [value]
    return []


def no_vulnerability_claim(claim):
    text = " ".join(str(claim or "").split()).lower()
    markers = [
        "no_vulnerability_found",
        "no vulnerability",
        "not a vulnerability",
        "无漏洞",
        "不存在漏洞",
        "没有漏洞",
    ]
    return not text or any(marker in text for marker in markers)


def is_vulnerability_response(resp):
    claim = response_claim(resp)
    return bool(claim) and not no_vulnerability_claim(claim)


def hard_contradictions(resp):
    if not isinstance(resp, dict):
        return []
    result = []
    for key in ("hard_contradictions", "contradictions", "blocking_guards"):
        value = resp.get(key)
        if value in (None, "", []):
            continue
        if isinstance(value, list):
            result.extend(value)
        else:
            result.append(value)
    stability = str(resp.get("stability") or "").lower()
    if stability == "hard_contradiction" and not result:
        result.append("stability=hard_contradiction")
    return result


def trigger_path_items(resp):
    if not isinstance(resp, dict):
        return []
    value = resp.get("trigger_path") or resp.get("attack_path") or []
    if isinstance(value, list):
        return value
    if value:
        return [value]
    return []


def attack_path_strings(resp, cand):
    attack_path_strs = []
    for step in trigger_path_items(resp):
        if isinstance(step, dict):
            desc = str(step.get("code") or step.get("function") or step.get("loc") or "").strip()
            loc = str(step.get("loc") or "").strip()
            if desc and loc and loc != "unknown" and loc not in desc:
                attack_path_strs.append(f"{desc} @ {loc}")
            elif desc:
                attack_path_strs.append(desc)
        elif step not in (None, "", []):
            attack_path_strs.append(str(step))
    if not attack_path_strs and cand.get("route"):
        attack_path_strs = [cand["route"]]
    return attack_path_strs


def evidence_complete(resp, cand):
    required = ("project_id", "sample_id", "route", "file", "line", "evidence_slice")
    if any(cand.get(field) in (None, "", []) for field in required):
        return False
    if not attack_path_strings(resp, cand):
        return False
    if isinstance(resp, dict) and resp.get("evidence_complete") is False:
        return False
    return True


def selected_vulnerability_response(responses):
    for resp in reversed(responses):
        if is_vulnerability_response(resp):
            return resp
    return responses[-1] if responses else {}


def route_record(cand, responses):
    first_is_vuln = is_vulnerability_response(responses[0]) if responses else False
    vuln_flags = [is_vulnerability_response(resp) for resp in responses]
    vuln_count = sum(1 for flag in vuln_flags if flag)
    any_vuln = bool(vuln_count)
    selected = selected_vulnerability_response(responses)
    contradictions = []
    for resp in responses:
        contradictions.extend(hard_contradictions(resp))

    if not any_vuln:
        return selected, "P3", "audit_only", "red_team_no_vulnerability", contradictions

    if contradictions and not is_vulnerability_response(responses[-1]):
        return selected, "P3", "audit_only", "hard_contradiction", contradictions

    if not evidence_complete(selected, cand):
        return selected, "P3", "audit_only", "evidence_incomplete", contradictions

    confidence = response_confidence(selected)
    all_vuln = vuln_count == len(responses)
    has_cwe = bool(response_cwes(selected))
    if all_vuln and confidence >= STATIC_CONFIDENCE_THRESHOLD and has_cwe:
        return selected, "P0", "static_confirmed", "red_team_static_strong", contradictions

    if not first_is_vuln and any_vuln:
        return selected, "P1", "candidate_for_d", "corrected_to_vulnerability", contradictions
    if vuln_count >= 2 and confidence >= CONFIDENCE_THRESHOLD:
        return selected, "P1", "candidate_for_d", "red_team_stable_needs_dynamic_verification", contradictions
    return selected, "P2", "candidate_for_d", "red_team_vulnerability_once", contradictions


def build_hypothesis(cand, selected, priority, agent_verdict, routing_reason, contradictions, red_team_rounds, repo_path):
    attack_path = attack_path_strings(selected, cand)
    confidence = response_confidence(selected)
    record = {
        "project_id": cand["project_id"],
        "sample_id": cand["sample_id"],
        "hypothesis_id": f"hyp_{cand['sample_id']}",
        "claim": response_claim(selected) or "NO_VULNERABILITY_FOUND",
        "CWE_candidates": response_cwes(selected),
        "preconditions": selected.get("preconditions", []) if isinstance(selected, dict) else [],
        "attack_path": attack_path,
        "confidence": confidence,
        "priority": priority,
        "agent_verdict": agent_verdict,
        "routing_decision": agent_verdict,
        "suspicion_reason": routing_reason,
        "hard_contradictions": contradictions,
        "red_team_rounds": red_team_rounds,
        "route": cand.get("route", ""),
        "file": cand.get("file", ""),
        "line": cand.get("line", 0),
        "evidence_slice": cand.get("evidence_slice", ""),
        "verification_context": infer_verification_context(repo_path),
        "timestamps": {"routed_at": utc_now()},
    }
    if priority == "P0":
        record["status"] = "static_confirmed"
        record["verification_stage"] = "C"
        record["d_verification"] = "skipped_by_policy"
    elif priority in {"P1", "P2"}:
        record["status"] = "pending_dynamic_verification"
        record["d_verification"] = "pending"
    else:
        record["status"] = "audit_only"
        record["d_verification"] = "not_applicable"
    return record


def audit_error_record(cand, exc):
    return {
        "project_id": cand.get("project_id"),
        "sample_id": cand.get("sample_id"),
        "hypothesis_id": f"hyp_{cand.get('sample_id', 'unknown')}",
        "priority": "P3",
        "agent_verdict": "audit_only",
        "routing_decision": "audit_only",
        "suspicion_reason": "stage_c_processing_error",
        "error": str(exc),
        "route": cand.get("route", ""),
        "file": cand.get("file", ""),
        "line": cand.get("line", 0),
        "evidence_slice": cand.get("evidence_slice", ""),
        "timestamps": {"routed_at": utc_now()},
    }


def audit_one(cand, llm_map):
    """
    单个样本的三轮红队审计流程：
    1. 红队提出高召回漏洞假设。
    2. 红队自查并修正，特别捕捉先非漏洞后纠正为漏洞的样本。
    3. 红队最终整理，按P0/P1/P2/P3分流。
    """
    sample_id = cand["sample_id"]
    brief = build_evidence_brief(cand, llm_map)
    repo_path = llm_map.get(sample_id, {}).get("repo_path", "")

    print(f"[C] red round 1 proposer {sample_id}")
    prop_resp = call_llm(PROPOSER_PROMPT.format(evidence_brief=brief))
    if not prop_resp:
        prop_resp = {"claim": "NO_VULNERABILITY_FOUND", "confidence": 0.0, "llm_error": "round_1_failed"}

    print(f"[C] red round 2 review {sample_id}")
    review_resp = call_llm(RED_REVIEW_PROMPT.format(
        evidence_brief=brief,
        proposer_json=json.dumps(prop_resp, ensure_ascii=False),
    ))
    if not review_resp:
        review_resp = dict(prop_resp)
        review_resp["llm_error"] = "round_2_failed_reused_round_1"

    print(f"[C] red round 3 final {sample_id}")
    final_resp = call_llm(RED_FINAL_PROMPT.format(
        evidence_brief=brief,
        proposer_json=json.dumps(prop_resp, ensure_ascii=False),
        review_json=json.dumps(review_resp, ensure_ascii=False),
    ))
    if not final_resp:
        final_resp = dict(review_resp)
        final_resp["llm_error"] = "round_3_failed_reused_round_2"

    red_team_rounds = [
        {"round": 1, "role": "red_proposer", "response": prop_resp},
        {"round": 2, "role": "red_self_review", "response": review_resp},
        {"round": 3, "role": "red_final", "response": final_resp},
    ]
    responses = [prop_resp, review_resp, final_resp]
    selected, priority, decision, reason, contradictions = route_record(cand, responses)
    return build_hypothesis(cand, selected, priority, decision, reason, contradictions, red_team_rounds, repo_path)


# ==================== 主程序（并发 + 即时分流写入）====================
def truncate_jsonl(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8"):
        pass


def append_jsonl(file_obj, row):
    file_obj.write(json.dumps(row, ensure_ascii=False) + "\n")
    file_obj.flush()


def main():
    """主流程：加载数据，并发处理每个候选样本，并按P0/P1/P2/P3即时分流写入。"""
    args = parse_args()
    candidates_path = Path(args.b_candidates)
    llm_samples_path = Path(args.llm_input)
    output_path = Path(args.output)
    static_output_path = Path(args.static_output) if args.static_output else default_side_output(
        output_path, "final", "static_confirmed.jsonl"
    )
    audit_output_path = Path(args.audit_output) if args.audit_output else default_side_output(
        output_path, "audit", "audit.jsonl"
    )

    candidates = load_candidates(candidates_path)
    llm_map = load_llm_samples(llm_samples_path)
    validate_inputs(candidates, llm_map)

    # 测试限制（可注释掉或调整数量）
    if args.max_samples is not None:
        candidates = candidates[:args.max_samples]

    truncate_jsonl(output_path)
    truncate_jsonl(static_output_path)
    truncate_jsonl(audit_output_path)

    d_count = 0
    static_count = 0
    audit_count = 0

    # 使用线程池并发处理，提高整体吞吐量
    with (
        open(output_path, "a", encoding="utf-8", buffering=1) as d_file,
        open(static_output_path, "a", encoding="utf-8", buffering=1) as static_file,
        open(audit_output_path, "a", encoding="utf-8", buffering=1) as audit_file,
        ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor,
    ):
        future_to_cand = {executor.submit(audit_one, cand, llm_map): cand for cand in candidates}
        for future in as_completed(future_to_cand):
            cand = future_to_cand[future]
            try:
                hyp = future.result()
            except Exception as e:
                hyp = audit_error_record(cand, e)

            if hyp.get("priority") == "P0":
                append_jsonl(static_file, hyp)
                static_count += 1
            elif hyp.get("priority") in {"P1", "P2"}:
                append_jsonl(d_file, hyp)
                d_count += 1
            else:
                append_jsonl(audit_file, hyp)
                audit_count += 1
            print(
                f"[C] {cand['sample_id']} priority={hyp.get('priority')} "
                f"decision={hyp.get('routing_decision')} reason={hyp.get('suspicion_reason')}"
            )

    print(f"[C] D candidates: {d_count} -> {output_path}")
    print(f"[C] P0 static confirmed: {static_count} -> {static_output_path}")
    print(f"[C] audit only: {audit_count} -> {audit_output_path}")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(f"error: {exc}") from exc
