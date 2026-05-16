#!/usr/bin/env python3
# agent1.py - C阶段：双Agent对抗审计，符合计划书格式的漏洞假设
# 改进版：假设条件验证融合到Challenger中，利用A阶段samples.raw.jsonl获取完整上下文

import json
import os
from datetime import datetime, timezone
from openai import OpenAI

# ==================== 配置 ====================
# 使用DeepSeek V4 Flash模型（速度快，成本低）
MODEL_NAME = "deepseek-v4-flash"
API_KEY = "sk-5d81901d00da47ff8f6f7e7de5818e47"
BASE_URL = "https://api.deepseek.com/v1"
# 计划书要求：confidence >= 0.65 才发送给D阶段
CONFIDENCE_THRESHOLD = 0.65

client = OpenAI(api_key=API_KEY, base_url=BASE_URL)


# ==================== 加载数据 ====================
def load_candidates(path):
    """加载B阶段输出的候选样本（candidates.scored.jsonl）"""
    with open(path, encoding='utf-8') as f:
        return [json.loads(line) for line in f if line.strip()]


def load_raw_samples(path):
    """加载A阶段输出的samples.raw.jsonl，建立sample_id -> 原始数据的映射，用于获取调用序列、sink位置等上下文"""
    raw_map = {}
    with open(path, encoding='utf-8') as f:
        for line in f:
            if line.strip():
                obj = json.loads(line)
                raw_map[obj.get("sample_id")] = obj
    return raw_map


# ==================== 构建证据文本（融合A+B信息）====================
def build_evidence_brief(cand, raw_map):
    """
    根据candidates.scored.jsonl中的字段 + 关联的samples.raw.jsonl中的字段构建证据文本。
    包含：路由、文件、行号、evidence_slice、调用序列(api_sequence)、入口点、sink位置等。
    这些信息将作为LLM的输入，用于红方和蓝方审计。
    """
    sample_id = cand.get("sample_id")
    raw = raw_map.get(sample_id, {})

    # 基础信息
    brief = f"""
【项目】{cand.get('project_id', 'unknown')}
【样本ID】{sample_id}
【路由】{cand.get('route', 'unknown')}
【入口点】{raw.get('entrypoint', {})}
【文件位置】{cand.get('file', 'unknown')}:{cand.get('line', 0)}
【代码片段（B阶段提供）】
{cand.get('evidence_slice', '无')}
"""
    # 添加调用序列（来自A阶段）
    api_seq = raw.get('api_sequence', [])
    if api_seq:
        brief += f"\n【调用序列】\n{json.dumps(api_seq, indent=2)}"
    else:
        brief += "\n【调用序列】无"

    # 添加sink位置（来自A阶段，例如数据库更新、命令执行等）
    sink_locs = raw.get('sink_locs', [])
    if sink_locs:
        brief += f"\n【Sink位置】\n{json.dumps(sink_locs, indent=2)}"

    # 添加source位置（来自A阶段，例如用户输入入口）
    source_locs = raw.get('source_locs', [])
    if source_locs:
        brief += f"\n【Source位置】\n{json.dumps(source_locs, indent=2)}"

    # 添加B阶段的风险评分
    brief += f"""
【风险评分】
- 稀有度: {cand.get('rarity_score', 0.5)}
- Sink危险度: {cand.get('sink_score', 0.5)}
- 模式偏离度: {cand.get('pattern_deviation_score', 0.5)}
- 综合风险分: {cand.get('risk_score', 0.5)}
【原因标签】{', '.join(cand.get('reason_tags', []))}
"""
    return brief


# ==================== 提示词模板 ====================
# 红方提示词：提出漏洞假设（强制输出假设条件和触发路径）
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
    {{"id": "A1", "description": "假设条件，例如：攻击者能控制输入长度且长度大于缓冲区大小"}}
  ],
  "trigger_path": [
    {{"step": 1, "loc": "L? 或 描述", "code": "关键代码行"}}
  ],
  "preconditions": ["攻击者能够控制某个输入或参数"],
  "confidence": 0.8
}}

**注意**：
- 即使代码中可能存在防御检查，你也**必须**输出假设条件和路径，不要提前过滤。
- 如果无法推断具体行号，loc可填"unknown"。
"""

# 蓝方提示词：审查红方假设，检查条件合理性 + 路径防御，调整置信度
CHALLENGER_PROMPT = """你是独立复审专家，请严格审查红队提出的漏洞假设，并给出调整后的置信度。

**代码证据**：
{evidence_brief}

**红队假设**：
{proposer_json}

**你的审查任务（综合性）**：
1. **检查每个假设条件的合理性**：结合代码证据，判断红队提出的 hypothesis_conditions 是否与代码明显矛盾（例如代码中已有防御性检查、常量限制、错误处理等）。如果某个条件与代码矛盾，标记为 "contradicted"。
2. **检查触发路径上的防御措施**：对于 trigger_path 中的每个步骤，检查是否存在会阻止漏洞实际触发的代码，例如：
   - 长度/边界检查（if (len > MAX) return;）
   - 空指针检查（if (ptr == NULL) return;）
   - 权限验证（if (!hasPermission()) throw;）
   - 提前返回、异常抛出、资源释放等。
   如果存在这样的防御，记录下具体位置和代码内容。
3. **给出调整后的置信度**：基于以上审查：
   - 如果发现任何假设条件为 "contradicted" 或存在有效防御，**适当降低置信度**（例如从0.8降至0.5或0.3）。
   - 如果未发现任何问题，可保持原置信度或略为提高。
   - 调整后的置信度应合理反映漏洞可利用的可能性（0~1）。
4. **总结总体判断**：简要说明是否认为该假设仍然成立。

**输出格式（严格JSON）**：
{{
  "condition_checks": [
    {{"condition_id": "A1", "status": "valid|contradicted|plausible", "reason": "依据"}}
  ],
  "guard_checks": [
    {{"target_step": 2, "guard_location": "L48", "guard_code": "if (strlen(input) > 256) return;", "reason": "该检查位于敏感操作之前"}}
  ],
  "adjusted_confidence": 0.5,
  "summary": "总体判断：假设是否仍成立"
}}
"""

# 红方回应：针对蓝方审查进行最终决策
REBUTTAL_PROMPT = """你是原红队专家，请回应蓝队的审查结果。

**原假设**：
{proposer_json}

**蓝队审查**：
{challenger_json}

**任务**：
- 如果蓝队降低了置信度，你可以尝试反驳蓝队的理由，并给出最终的置信度。
- 如果蓝队发现条件矛盾或有效防御，你可以选择接受并进一步降低置信度，或者提出新的证据反驳。
- 输出最终漏洞描述和最终置信度。

**输出格式（严格JSON）**：
{{
  "final_claim": "最终漏洞描述（若无漏洞写'NO_VULNERABILITY_FOUND'）",
  "final_confidence": 0.5,
  "rebuttal_notes": "简要说明最终决策理由"
}}
"""


# ==================== 辅助函数 ====================
def call_llm(prompt):
    """调用LLM并返回解析后的JSON字典；如果调用失败则返回None"""
    try:
        r = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[{"role": "user", "content": prompt}],
            response_format={"type": "json_object"}
        )
        return json.loads(r.choices[0].message.content)
    except Exception as e:
        print(f"LLM调用失败: {e}")
        return None


def audit_one(cand, raw_map):
    """对单个候选样本执行完整的红蓝对抗审计，返回符合计划书格式的假设"""
    sample_id = cand["sample_id"]
    brief = build_evidence_brief(cand, raw_map)

    # ---------- 1. Proposer 红方：提出假设 ----------
    print(f"🔴 Proposer 分析 {sample_id} ...")
    prop_resp = call_llm(PROPOSER_PROMPT.format(evidence_brief=brief))
    if not prop_resp:
        prop_resp = {"claim": "NO_VULNERABILITY_FOUND", "confidence": 0.0}

    # 如果红方直接认为无漏洞，则跳过后续辩论，直接返回拒绝
    if "NO_VULNERABILITY_FOUND" in prop_resp.get("claim", ""):
        return build_hypothesis(cand, prop_resp, final_claim="NO_VULNERABILITY_FOUND",
                                final_conf=0.0, agent_verdict="reject")

    # ---------- 2. Challenger 蓝方：审查假设（包含条件验证+防御检查）----------
    print(f"🔵 Challenger 审查 {sample_id} ...")
    chall_resp = call_llm(CHALLENGER_PROMPT.format(
        evidence_brief=brief,
        proposer_json=json.dumps(prop_resp, ensure_ascii=False, indent=2)
    ))
    if not chall_resp:
        # 如果蓝方调用失败，则使用红方原始置信度
        adjusted_conf = prop_resp.get("confidence", 0.5)
    else:
        adjusted_conf = chall_resp.get("adjusted_confidence", prop_resp.get("confidence", 0.5))

    # ---------- 3. Rebuttal 红方回应：基于蓝方审查做出最终决策 ----------
    print(f"🟡 Rebuttal 回应 {sample_id} ...")
    rebut_resp = call_llm(REBUTTAL_PROMPT.format(
        proposer_json=json.dumps(prop_resp, ensure_ascii=False, indent=2),
        challenger_json=json.dumps(chall_resp, ensure_ascii=False, indent=2) if chall_resp else "{}"
    ))
    if rebut_resp:
        final_claim = rebut_resp.get("final_claim", prop_resp.get("claim", ""))
        final_conf = rebut_resp.get("final_confidence", adjusted_conf)
    else:
        final_claim = prop_resp.get("claim", "")
        final_conf = adjusted_conf

    # 质量门禁：计划书要求 confidence >= 0.65 才可发送给D阶段
    agent_verdict = "accept" if (
                final_conf >= CONFIDENCE_THRESHOLD and "NO_VULNERABILITY_FOUND" not in final_claim) else "reject"

    return build_hypothesis(cand, prop_resp, final_claim, final_conf, agent_verdict,
                            condition_checks=chall_resp.get("condition_checks", []) if chall_resp else [],
                            guard_checks=chall_resp.get("guard_checks", []) if chall_resp else [])


def build_hypothesis(cand, prop, final_claim, final_conf, agent_verdict, condition_checks=None, guard_checks=None):
    """构建符合计划书 hypotheses.jsonl 格式的输出"""
    return {
        "project_id": cand["project_id"],
        "sample_id": cand["sample_id"],
        "hypothesis_id": f"hyp_{cand['sample_id']}",
        "claim": final_claim,
        "cwe_candidates": prop.get("cwe_candidates", []),
        "preconditions": prop.get("preconditions", []),
        "attack_path": prop.get("trigger_path", []),  # 计划书要求字段
        "counter_arguments": [gc.get("reason", "") for gc in (guard_checks or [])],
        "rebuttal": [cc.get("reason", "") for cc in (condition_checks or [])],
        "confidence": final_conf,
        "agent_verdict": agent_verdict,
        "route": cand.get("route", ""),
        "file": cand.get("file", ""),
        "line": cand.get("line", 0),
        "evidence_slice": cand.get("evidence_slice", ""),
        "citations": [],  # 可由D阶段填充
        "timestamps": {"audited_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
    }


# ==================== 主程序 ====================
def main():
    # 文件路径配置（请根据实际项目目录调整）
    candidates_path = "data/candidates.scored.jsonl"  # B阶段输出
    raw_samples_path = "data/samples.raw.jsonl"      # A阶段输出
    output_path = "data/hypotheses.jsonl"            # C阶段输出

    # 加载数据
    candidates = load_candidates(candidates_path)
    raw_map = load_raw_samples(raw_samples_path)

    # 测试阶段可先处理少量样本，确认无误后去掉限制或增大数量
    max_samples = 20
    results = []
    for i, cand in enumerate(candidates):
        if i >= max_samples:
            break
        hyp = audit_one(cand, raw_map)
        results.append(hyp)
        print(f"✅ {cand['sample_id']} final_conf={hyp['confidence']:.2f} verdict={hyp['agent_verdict']}")

    # 输出结果，供D阶段使用
    with open(output_path, "w", encoding="utf-8") as f:
        for hyp in results:
            f.write(json.dumps(hyp, ensure_ascii=False) + "\n")
    print(f"🎉 完成，共处理 {len(results)} 个样本，结果保存到 {output_path}")


if __name__ == "__main__":
    main()