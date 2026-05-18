#!/usr/bin/env python3
# agent1.py - C阶段：双Agent对抗审计，输出符合新D阶段格式
# 优化点：并发处理、流式写入、证据精简、verification_context自动推断、结果缓存

import json
import os
import functools
from concurrent.futures import ThreadPoolExecutor, as_completed
from openai import OpenAI

# ==================== 配置（可根据实际情况调整）====================
MODEL_NAME = "deepseek-v4-flash"          # 使用Flash模型，速度更快
API_KEY = ""
BASE_URL = "https://api.deepseek.com/v1"
CONFIDENCE_THRESHOLD = 0.60               # 放宽到0.60，让更多假设进入D阶段（原0.65）
MAX_WORKERS = 5                           # 并发线程数，平衡速度与稳定性
MAX_CALL_CHAIN = 8                        # 调用序列最多保留个数（精简token）
MAX_SINK_SOURCE = 3                       # sink/source最多保留个数（精简token）

client = OpenAI(api_key=API_KEY, base_url=BASE_URL, timeout=60, max_retries=0)

# ==================== 数据加载模块 ====================
def load_candidates(path):
    """加载B阶段输出的候选样本（candidates.scored.jsonl），每行一个JSON对象"""
    with open(path, encoding='utf-8') as f:
        return [json.loads(line) for line in f if line.strip()]

def load_raw_samples(path):
    """加载A阶段输出的原始样本（samples.raw.jsonl），建立sample_id到数据的映射"""
    raw_map = {}
    with open(path, encoding='utf-8') as f:
        for line in f:
            if line.strip():
                obj = json.loads(line)
                raw_map[obj.get("sample_id")] = obj
    return raw_map

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
def build_evidence_brief(cand, raw_map):
    """
    为大模型构建精简但完整的审计证据。
    优化点：去掉冗余空格/换行，调用链只取前8个，sink/source只取前3个，入口点精简。
    显著降低输入token数，提高处理速度，同时保留关键信息。
    """
    sample_id = cand.get("sample_id")
    raw = raw_map.get(sample_id, {})

    lines = []
    lines.append(f"项目:{cand.get('project_id','?')} 样本:{sample_id}")
    lines.append(f"路由:{cand.get('route','?')}")
    ep = raw.get('entrypoint', {})
    lines.append(f"入口:{ep.get('http_method','')} {ep.get('route','')}")
    lines.append(f"位置:{cand.get('file','?')}:{cand.get('line',0)}")
    lines.append(f"代码:{cand.get('evidence_slice','')}")

    # 调用序列（最多保留前MAX_CALL_CHAIN个）
    api_seq = raw.get('api_sequence', [])
    if api_seq:
        short_seq = api_seq[:MAX_CALL_CHAIN]
        lines.append(f"调用链:{' -> '.join(short_seq)}")

    # Sink位置精简
    sink_locs = raw.get('sink_locs', [])
    if sink_locs:
        sinks = []
        for s in sink_locs[:MAX_SINK_SOURCE]:
            sinks.append(f"{s.get('type','')}@{s.get('file','')}:{s.get('line','')}")
        lines.append(f"Sink:{'; '.join(sinks)}")

    # Source位置精简
    source_locs = raw.get('source_locs', [])
    if source_locs:
        srcs = []
        for s in source_locs[:MAX_SINK_SOURCE]:
            srcs.append(f"{s.get('file','')}:{s.get('line','')}")
        lines.append(f"Source:{'; '.join(srcs)}")

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

def audit_one(cand, raw_map):
    """
    单个样本的红蓝对抗审计流程：
    1. 红方Proposer提出漏洞假设
    2. 若红方认为无漏洞则直接剪枝返回
    3. 蓝方Challenger审查并调整置信度
    4. 红方Rebuttal回应并给出最终置信度与漏洞描述
    5. 根据最终置信度和阈值决定agent_verdict
    """
    sample_id = cand["sample_id"]
    brief = build_evidence_brief(cand, raw_map)
    repo_path = raw_map.get(sample_id, {}).get("repo_path", "")

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
    candidates_path = "data/candidates.scored.jsonl"
    raw_samples_path = "data/samples.raw.jsonl"
    output_path = "data/hypotheses.jsonl"

    candidates = load_candidates(candidates_path)
    raw_map = load_raw_samples(raw_samples_path)

    # 测试限制（可注释掉或调整数量）
    max_samples = 20
    candidates = candidates[:max_samples]

    # 清空输出文件（流式写入前准备）
    with open(output_path, "w", encoding="utf-8") as f:
        pass

    # 使用线程池并发处理，提高整体吞吐量
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_cand = {executor.submit(audit_one, cand, raw_map): cand for cand in candidates}
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
    main()