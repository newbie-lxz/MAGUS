#!/usr/bin/env python3
# agent1.py - C阶段：双Agent对抗审计，输出符合新D阶段格式
# 优化点：并发处理、流式写入、证据精简、verification_context自动推断、结果缓存

import argparse
import functools
import json
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from openai import OpenAI

# ==================== 配置（可根据实际情况调整）====================
MODEL_NAME = "deepseek-v4-flash"          # 使用Flash模型，速度更快
API_KEY = "sk-accf76251b06423b8c02257bb8da0758"
BASE_URL = "https://api.deepseek.com/v1"
CONFIDENCE_THRESHOLD = 0.60               # 放宽到0.60，让更多假设进入D阶段（原0.65）
MAX_WORKERS = 5                           # 并发线程数，平衡速度与稳定性
MAX_CALL_CHAIN = 8                        # 调用序列最多保留个数（精简token）
MAX_SINK_SOURCE = 3                       # sink/source最多保留个数（精简token）

client = OpenAI(api_key=API_KEY, base_url=BASE_URL, timeout=60, max_retries=0)


# ==================== 数据加载模块 ====================
def parse_args():
    parser = argparse.ArgumentParser(description="C阶段：基于A阶段LLM证据和B阶段候选执行双Agent审计")
    parser.add_argument("--llm-input", default="data/samples.llm.jsonl", help="A阶段导出的 samples.llm.jsonl")
    parser.add_argument("--b-candidates", default="data/candidates.scored.jsonl", help="B阶段输出 candidates.scored.jsonl")
    parser.add_argument("--output", default="data/hypotheses.jsonl", help="C阶段输出 hypotheses.jsonl")
    parser.add_argument("--max-samples", type=int, default=20, help="最多审计候选数量")
    return parser.parse_args()


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


# ==================== 提示词模板（完整，未修改）====================
PROPOSER_PROMPT = """你是一位安全审计专家。基于以下代码证据，判断是否存在安全漏洞。

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

CHALLENGER_PROMPT = """你是独立复审专家，请严格审查红队提出的漏洞假设，并给出调整后的置信度。

**代码证据**：
{evidence_brief}

**红队假设**：
{proposer_json}

**任务**：检查假设条件合理性、路径上的防御措施，给出调整后的置信度。

**输出格式（严格JSON）**：
{{
  "condition_checks": [{{"condition_id": "A1", "status": "valid|contradicted", "reason": "..."}}],
  "guard_checks": [{{"target_step": 1, "guard_location": "L?", "guard_code": "...", "reason": "..."}}],
  "adjusted_confidence": 0.5,
  "summary": "结论"
}}"""

REBUTTAL_PROMPT = """你是原红队专家，请回应蓝队的审查结果。

**原假设**：
{proposer_json}

**蓝队审查**：
{challenger_json}

**输出JSON**：
{{
  "final_claim": "最终漏洞描述或NO_VULNERABILITY_FOUND",
  "final_confidence": 0.5,
  "rebuttal_notes": "理由"
}}"""


# ==================== LLM调用与假设构建模块 ====================
def call_llm(prompt):
    """调用大模型API，返回解析后的JSON字典。设置max_tokens=400确保输出完整。"""
    try:
        r = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[{"role": "user", "content": prompt}],
            response_format={"type": "json_object"},
            max_tokens=400,       # 保持足够大，避免截断
            temperature=0.0
        )
        return json.loads(r.choices[0].message.content)
    except Exception as e:
        print(f"LLM调用失败: {e}")
        return None


def build_hypothesis(cand, prop, final_claim, final_conf, agent_verdict, repo_path):
    """
    构造最终输出的一条假设，符合新D阶段输入格式。
    将红方的trigger_path转换为字符串数组attack_path，并自动生成verification_context。
    """
    # 将触发路径步骤列表转为字符串数组
    attack_path_strs = []
    for step in prop.get("trigger_path", []):
        desc = step.get("code", "")
        loc = step.get("loc", "")
        if loc and loc != "unknown":
            attack_path_strs.append(f"{desc} @ {loc}")
        else:
            attack_path_strs.append(desc)
    if not attack_path_strs and cand.get("route"):
        attack_path_strs = [cand["route"]]

    return {
        "project_id": cand["project_id"],
        "sample_id": cand["sample_id"],
        "hypothesis_id": f"hyp_{cand['sample_id']}",
        "claim": final_claim,
        "CWE_candidates": prop.get("cwe_candidates", []),
        "preconditions": prop.get("preconditions", []),
        "attack_path": attack_path_strs,
        "confidence": final_conf,
        "agent_verdict": agent_verdict,
        "route": cand.get("route", ""),
        "file": cand.get("file", ""),
        "line": cand.get("line", 0),
        "evidence_slice": cand.get("evidence_slice", ""),
        "verification_context": infer_verification_context(repo_path)   # 自动推断环境配置
    }


def audit_one(cand, llm_map):
    """
    单个样本的红蓝对抗审计流程：
    1. 红方Proposer提出漏洞假设
    2. 若红方认为无漏洞则直接剪枝返回
    3. 蓝方Challenger审查并调整置信度
    4. 红方Rebuttal回应并给出最终置信度与漏洞描述
    5. 根据最终置信度和阈值决定agent_verdict
    """
    sample_id = cand["sample_id"]
    brief = build_evidence_brief(cand, llm_map)
    repo_path = llm_map.get(sample_id, {}).get("repo_path", "")

    # 红方
    print(f"🔴 Proposer {sample_id}")
    prop_resp = call_llm(PROPOSER_PROMPT.format(evidence_brief=brief))
    if not prop_resp:
        prop_resp = {"claim": "NO_VULNERABILITY_FOUND", "confidence": 0.0}

    # 无漏洞剪枝（直接拒绝，不进入蓝队）
    if "NO_VULNERABILITY_FOUND" in prop_resp.get("claim", ""):
        return build_hypothesis(cand, prop_resp, "NO_VULNERABILITY_FOUND", 0.0, "reject", repo_path)

    # 蓝方
    print(f"🔵 Challenger {sample_id}")
    chall_resp = call_llm(CHALLENGER_PROMPT.format(
        evidence_brief=brief,
        proposer_json=json.dumps(prop_resp, ensure_ascii=False)
    ))
    adjusted_conf = chall_resp.get("adjusted_confidence", prop_resp.get("confidence", 0.5)) if chall_resp else prop_resp.get("confidence", 0.5)

    # 红方回应
    print(f"🟡 Rebuttal {sample_id}")
    rebut_resp = call_llm(REBUTTAL_PROMPT.format(
        proposer_json=json.dumps(prop_resp, ensure_ascii=False),
        challenger_json=json.dumps(chall_resp, ensure_ascii=False) if chall_resp else "{}"
    ))
    if rebut_resp:
        final_claim = rebut_resp.get("final_claim", prop_resp.get("claim", ""))
        final_conf = rebut_resp.get("final_confidence", adjusted_conf)
    else:
        final_claim = prop_resp.get("claim", "")
        final_conf = adjusted_conf

    agent_verdict = "accept" if (final_conf >= CONFIDENCE_THRESHOLD and "NO_VULNERABILITY_FOUND" not in final_claim) else "reject"
    return build_hypothesis(cand, prop_resp, final_claim, final_conf, agent_verdict, repo_path)


# ==================== 主程序（并发 + 流式写入）====================
def main():
    """主流程：加载数据，并发处理每个候选样本，流式写入结果文件。"""
    args = parse_args()
    candidates_path = Path(args.b_candidates)
    llm_samples_path = Path(args.llm_input)
    output_path = Path(args.output)

    candidates = load_candidates(candidates_path)
    llm_map = load_llm_samples(llm_samples_path)
    validate_inputs(candidates, llm_map)

    # 测试限制（可注释掉或调整数量）
    if args.max_samples is not None:
        candidates = candidates[:args.max_samples]

    # 清空输出文件（流式写入前准备）
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        pass

    # 使用线程池并发处理，提高整体吞吐量
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_cand = {executor.submit(audit_one, cand, llm_map): cand for cand in candidates}
        for future in as_completed(future_to_cand):
            cand = future_to_cand[future]
            try:
                hyp = future.result()
                # 每完成一个立即追加写入，避免内存积压，防止程序崩溃导致数据丢失
                with open(output_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(hyp, ensure_ascii=False) + "\n")
                print(f"✅ {cand['sample_id']} conf={hyp['confidence']:.2f} verdict={hyp['agent_verdict']}")
            except Exception as e:
                print(f"❌ 处理 {cand['sample_id']} 失败: {e}")

    print(f"🎉 完成，结果保存到 {output_path}")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(f"error: {exc}") from exc
