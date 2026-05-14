#!/usr/bin/env python3
"""
Stage B：多维深度挖掘引擎 (Intelligence Miner) — APP-Miner 完全对齐版
-----------------------------------------------------------------
与APP-Miner论文对应的改进：
  1. 拓扑化：每个 API 路径视为已去环有向无环拓扑（由 Stage A 提供）
  2. Completion：非连续子序列匹配（传递边使任意前驱→后继连通）
  3. 索引矩阵 + 倒排索引：整数位掩码（Python int），位运算加速
  4. 下闭性质：仅从频繁 (k-1)-模式扩展，非频繁直接剪枝
  5. 分层BFS候选生成：每层只组合有公共前缀的频繁模式
  6. 最大频繁模式：仅保留不被其他模式包含的最大模式

输入：samples.stats.jsonl（Stage A 派生的 flat edge-token 统计视图）
输出1：patterns.json（频繁模式）
输出2：candidates.scored.jsonl（高疑点候选）
输出3：b_miner_stats.json（聚合统计）

评分公式（固定）：
  risk_score = 0.40 * rarity_score + 0.35 * sink_score + 0.25 * pattern_deviation_score

质量门禁：
  - 必须输出全部子分数
  - risk_score >= 0.50 才通过当前输出摘要门禁
  - 记录不可为空字段
"""

import argparse
import json
import math
import sys
from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# ============================================================
# 1. 数据结构
# ============================================================

@dataclass
class StageAStatsSample:
    """Stage A `samples.stats.jsonl` 记录。"""
    project_id: str
    sample_id: str
    location_id: int
    location: dict
    seed_id: str
    seed_token: str
    edge_ids: list[int]
    edge_tokens: list[str]
    source_kinds: list[str]
    sink_types: list[str]
    focus: dict

    @property
    def sequence_tokens(self) -> list[str]:
        """从 edge_tokens 和 seed_token 推导完整 token 序列（已拓扑化）"""
        if not self.edge_tokens:
            return [self.seed_token] if self.seed_token else []
        first_edge = self.edge_tokens[0]
        first_node = first_edge.split("->", 1)[0].strip()
        path_nodes = [first_node]
        for et in self.edge_tokens:
            parts = et.split("->", 1)
            if len(parts) == 2:
                path_nodes.append(parts[1].strip())
        return [self.seed_token] + path_nodes if self.seed_token else path_nodes

    @property
    def route(self) -> str:
        loc_file = self.location.get("file", "")
        loc_func = self.location.get("function", "")
        if loc_file and loc_func:
            return f"{loc_file}::{loc_func}"
        if self.seed_id:
            return self.seed_id.rsplit(":", 1)[0]
        return ""

    @property
    def primary_file(self) -> str:
        return self.focus.get("file", self.location.get("file", ""))

    @property
    def primary_line(self) -> int:
        return int(self.focus.get("line", 0))

    @property
    def evidence_slice(self) -> str:
        return self.seed_token

    def sink_type_weights(self) -> list[float]:
        weights = []
        for st in self.sink_types:
            weights.append(SINK_SEVERITY_WEIGHTS.get(st.strip().lower(), 0.3))
        return weights


@dataclass
class PatternRecord:
    pattern_id: str
    sequence_tokens: list[str]
    support: float
    confidence: float
    projects_covered: int
    is_maximal: bool = True  # 是否为最大频繁模式


@dataclass
class ScoredCandidate:
    project_id: str
    sample_id: str
    rarity_score: float
    sink_score: float
    pattern_deviation_score: float
    risk_score: float
    reason_tags: list[str]
    route: str
    file: str
    line: int
    evidence_slice: str
    threshold_pass: bool
    timestamps: dict


# ============================================================
# 2. 加载数据
# ============================================================

REQUIRED_STATS_FIELDS = {
    "project_id",
    "sample_id",
    "location_id",
    "location",
    "seed_id",
    "seed_token",
    "edge_ids",
    "edge_tokens",
    "source_kinds",
    "sink_types",
    "focus",
}

RAW_SAMPLE_MARKER_FIELDS = {
    "entrypoint",
    "seed",
    "source_candidates",
    "sink_candidates",
    "source_sink_flows",
    "graph",
    "evidence_slice",
}


class InputContractError(ValueError):
    """Stage B 输入不符合 `samples.stats.jsonl` 合同。"""


def _require_type(data: dict[str, Any], field_name: str, expected_type: type, line_no: int) -> None:
    value = data[field_name]
    if expected_type is int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise InputContractError(f"line {line_no}: `{field_name}` must be an integer")
        return
    if not isinstance(value, expected_type):
        raise InputContractError(f"line {line_no}: `{field_name}` must be {expected_type.__name__}")


def _require_list_items(data: dict[str, Any], field_name: str, item_type: type, line_no: int) -> None:
    _require_type(data, field_name, list, line_no)
    if item_type is int:
        valid = all(isinstance(item, int) and not isinstance(item, bool) for item in data[field_name])
    else:
        valid = all(isinstance(item, item_type) for item in data[field_name])
    if not valid:
        raise InputContractError(f"line {line_no}: `{field_name}` items must be {item_type.__name__}")


def validate_stats_record(data: Any, line_no: int) -> None:
    if not isinstance(data, dict):
        raise InputContractError(f"line {line_no}: expected a JSON object")

    missing = sorted(REQUIRED_STATS_FIELDS - data.keys())
    if missing:
        raw_markers = sorted(RAW_SAMPLE_MARKER_FIELDS & data.keys())
        if raw_markers:
            raise InputContractError(
                f"line {line_no}: Stage B expects Stage A samples.stats.jsonl records, "
                f"not samples.raw.jsonl records; missing {missing}"
            )
        raise InputContractError(f"line {line_no}: missing required stats fields: {missing}")

    _require_type(data, "project_id", str, line_no)
    _require_type(data, "sample_id", str, line_no)
    _require_type(data, "location_id", int, line_no)
    _require_type(data, "location", dict, line_no)
    _require_type(data, "seed_id", str, line_no)
    _require_type(data, "seed_token", str, line_no)
    _require_list_items(data, "edge_ids", int, line_no)
    _require_list_items(data, "edge_tokens", str, line_no)
    _require_list_items(data, "source_kinds", str, line_no)
    _require_list_items(data, "sink_types", str, line_no)
    _require_type(data, "focus", dict, line_no)


def load_stats_samples(path: Path) -> list[StageAStatsSample]:
    samples = []
    with path.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError as exc:
                raise InputContractError(f"line {line_no}: invalid JSON: {exc.msg}") from exc
            validate_stats_record(data, line_no)
            sample = StageAStatsSample(
                project_id=data.get("project_id", ""),
                sample_id=data.get("sample_id", ""),
                location_id=data.get("location_id", 0),
                location=data.get("location", {}),
                seed_id=data.get("seed_id", ""),
                seed_token=data.get("seed_token", ""),
                edge_ids=data.get("edge_ids", []),
                edge_tokens=data.get("edge_tokens", []),
                source_kinds=data.get("source_kinds", []),
                sink_types=data.get("sink_types", []),
                focus=data.get("focus", {}),
            )
            samples.append(sample)
    return samples


# ============================================================
# 3. BitIndexMiner — 整数位掩码索引 + APP-Miner 完整流程
# ============================================================

class BitIndexMiner:
    """
    基于整数位掩码（bitmask）的频繁模式挖掘器。

    核心数据结构：
      - token_bitmask[tid] = Python int，第 sidx 位 = 1 表示 tid 出现在样本 sidx
      - order_bitmask[(a, b)] = Python int，第 sidx 位 = 1 表示 a 出现在 b 之前
      - sample_positions[sidx] = {tid: max_position}（用于快速判断顺序）

    算法流程（逐层BFS + 下闭性质 + 最大频繁）：
      Level 1: 单 token 频繁性
      Level 2: 所有频繁 token 对（双向验证顺序）
      Level k: 组合 Level-(k-1) 中具有共同前缀的模式，生成 Level-k 候选
               候选验证通过位运算 O(1) 完成
      最终: 过滤掉所有非最大频繁模式
    """

    def __init__(self, samples: list[StageAStatsSample], min_support_abs: int = 3):
        self.samples = samples
        self.min_support_abs = min_support_abs
        self.total_samples = len(samples)

        self._build_index()

    def _build_index(self):
        """
        构建：
          1. token_bitmask: list[int] — 每个 token 出现在哪些样本
          2. order_bitmask: dict[(int,int), int] — a→b 顺序关系位图
          3. 样本最大位置: sample_pos[sidx][tid] = max_position
        """
        # 收集所有 token
        all_tokens_set: set[str] = set()
        for s in self.samples:
            for t in s.sequence_tokens:
                all_tokens_set.add(t)
        all_tokens = sorted(all_tokens_set)

        self.token_to_id: dict[str, int] = {t: i for i, t in enumerate(all_tokens)}
        self.id_to_token: dict[int, str] = {i: t for i, t in enumerate(all_tokens)}
        self.n_tokens = len(all_tokens)

        # 初始化
        token_bitmask = [0] * self.n_tokens
        sample_pos: list[dict[int, int]] = []

        for sidx, s in enumerate(self.samples):
            tokens = s.sequence_tokens
            pos_map: dict[int, int] = {}
            for pos, t in enumerate(tokens):
                tid = self.token_to_id[t]
                token_bitmask[tid] |= (1 << sidx)
                pos_map[tid] = pos  # 最后一次出现的位置
            sample_pos.append(pos_map)

        self.token_bitmask = token_bitmask
        self.sample_pos = sample_pos

        # 预计算所有共现 token 对的先后关系位图
        # order_bitmask[(a,b)]: 第 sidx 位 = 1 表示在样本 sidx 中 a 在 b 之前
        self.order_bitmask: dict[tuple[int, int], int] = {}

        # 只对频繁 token 预计算（提升内存和速度）
        freq_tids = [
            tid for tid in range(self.n_tokens)
            if token_bitmask[tid].bit_count() >= self.min_support_abs
        ]

        for i in range(len(freq_tids)):
            tid_a = freq_tids[i]
            for j in range(i + 1, len(freq_tids)):
                tid_b = freq_tids[j]
                # 共现掩码
                co_bitmask = token_bitmask[tid_a] & token_bitmask[tid_b]
                if co_bitmask.bit_count() < self.min_support_abs:
                    continue

                a_before_b = 0
                b_before_a = 0
                # 遍历共现样本
                m = co_bitmask
                while m:
                    # 取最低位
                    lsb = m & -m
                    sidx = (lsb.bit_length() - 1)
                    m ^= lsb

                    pos_a = None
                    for pos, t in enumerate(self.samples[sidx].sequence_tokens):
                        if self.token_to_id[t] == tid_a:
                            pos_a = pos
                            break
                    pos_b = None
                    for pos, t in enumerate(self.samples[sidx].sequence_tokens):
                        if self.token_to_id[t] == tid_b:
                            pos_b = pos
                            break

                    if pos_a is not None and pos_b is not None:
                        if pos_a < pos_b:
                            a_before_b |= (1 << sidx)
                        elif pos_b < pos_a:
                            b_before_a |= (1 << sidx)

                if a_before_b.bit_count() >= self.min_support_abs:
                    self.order_bitmask[(tid_a, tid_b)] = a_before_b
                if b_before_a.bit_count() >= self.min_support_abs:
                    self.order_bitmask[(tid_b, tid_a)] = b_before_a

    # ---------- 位运算支持度计算 ----------

    def pattern_support_bitmask(self, tid_list: list[int]) -> int:
        """计算 tid_list 的绝对支持度（位掩码），O(k) 位运算"""
        if not tid_list:
            return 0
        mask = self.token_bitmask[tid_list[0]]
        for tid in tid_list[1:]:
            mask &= self.token_bitmask[tid]
        return mask

    def support_count(self, tid_list: list[int]) -> int:
        """计算 tid_list 的支持度计数"""
        mask = self.pattern_support_bitmask(tid_list)
        if mask.bit_count() < self.min_support_abs:
            return 0
        # 由于 order_bitmask 预计算了的顺序，还需验证顺序
        mask = self._verify_order(tid_list, mask)
        return mask.bit_count()

    def _verify_order(self, tid_list: list[int], candidate_mask: int) -> int:
        """验证在候选样本中 tid_list 是否满足顺序约束"""
        if len(tid_list) <= 1:
            return candidate_mask

        result_mask = candidate_mask
        for i in range(len(tid_list) - 1):
            a, b = tid_list[i], tid_list[i + 1]
            order_key = (a, b)
            order_mask = self.order_bitmask.get(order_key)
            if order_mask is None:
                return 0
            result_mask &= order_mask
            if result_mask.bit_count() < self.min_support_abs:
                return 0
        return result_mask

    # ---------- 逐层BFS + 下闭性质 ----------

    def mine(self, max_length: int = 16) -> list[PatternRecord]:
        """
        分层BFS挖掘（完全对齐 APP-Miner）：

        流程：
          Level 2: 枚举所有频繁 token 对
          Level k: 取所有 Level-(k-1) 模式，按共同前缀分组，
                   每组内两两组合生成长度 k 的候选
                   通过位掩码 O(1) 验证支持度
                   下闭性质：非频繁立即丢弃
          Maximal: 最终只保留不被其他模式包含的模式
        """
        all_patterns: list[PatternRecord] = []
        pattern_id_counter = [0]

        # ----- Level 1: 单 token 频繁性 -----
        # 用于置信度计算

        # ----- Level 2: 频繁 token 对 -----
        freq_pairs: list[tuple[int, int, int]] = []  # (a, b, support_count)

        for (a, b), mask in self.order_bitmask.items():
            cnt = mask.bit_count()
            if cnt >= self.min_support_abs:
                freq_pairs.append((a, b, cnt))

        if not freq_pairs:
            return []

        print(f"    Level-2 频繁模式: {len(freq_pairs)} 个")

        # ----- 逐层扩展（Level k） -----
        # levels[k] = dict[prefix_key -> list[(tid_list, support_mask)]]
        # 其中 prefix_key = tuple(tid_list[:-1]) 即共同前缀
        current_level: dict[tuple[int, ...], list[tuple[list[int], int]]] = defaultdict(list)

        # 将 Level-2 的模式按前缀分组
        for a, b, cnt in freq_pairs:
            current_level[(a,)].append(([a, b], cnt))

        level_num = 2
        while current_level and level_num < max_length:
            next_level: dict[tuple[int, ...], list[tuple[list[int], int]]] = defaultdict(list)
            total_candidates = 0

            for prefix_key, group in current_level.items():
                # 组内两两组合：有共同前缀的模式可以组合
                n = len(group)
                if n < 2:
                    continue

                for i in range(n):
                    tid_list_i, _ = group[i]
                    last_i = tid_list_i[-1]
                    for j in range(i + 1, n):
                        tid_list_j, _ = group[j]
                        last_j = tid_list_j[-1]

                        if last_i == last_j:
                            continue

                        # 生成长度 k 的候选：tid_list_i 中除最后一个元素外的前缀 + last_i + last_j
                        # 但需确保 last_i 在 last_j 之前出现（已完成拓扑排序）
                        candidate = list(tid_list_i) + [last_j]

                        # 下闭性质：先检查候选的所有 (k-1)-子模式是否频繁
                        # 即检查 candidate 去掉第一个元素后的子序列
                        sub_key = tuple(candidate[1:])
                        # 我们只处理连续扩展，所以只需确保前缀频繁（已保证）

                        # 位运算验证支持度
                        mask = self.token_bitmask[candidate[0]]
                        for tid in candidate[1:]:
                            mask &= self.token_bitmask[tid]
                        if mask.bit_count() < self.min_support_abs:
                            continue

                        # 验证顺序
                        mask = self._verify_order(candidate, mask)
                        cnt = mask.bit_count()
                        if cnt >= self.min_support_abs:
                            new_prefix = tuple(candidate[:-1])
                            next_level[new_prefix].append((candidate, cnt))
                            total_candidates += 1

            print(f"    Level-{level_num + 1}: {total_candidates} 个候选")

            # 产出当前层所有模式
            patterns_this_level = []
            for group in next_level.values():
                for tid_list, cnt in group:
                    # 计算置信度
                    prefix_key = tuple(tid_list[:-1])
                    prefix_cnt = self.support_count(list(prefix_key)) if prefix_key else self.total_samples
                    confidence = cnt / max(prefix_cnt, 1)
                    confidence = min(max(confidence, 0.0), 1.0)

                    # 计算 projects_covered
                    mask = self.pattern_support_bitmask(tid_list)
                    mask = self._verify_order(tid_list, mask)
                    covered_projects = set()
                    m = mask
                    while m:
                        lsb = m & -m
                        sidx = (lsb.bit_length() - 1)
                        m ^= lsb
                        covered_projects.add(self.samples[sidx].project_id)

                    pattern = PatternRecord(
                        pattern_id=f"pat_{pattern_id_counter[0]:04d}",
                        sequence_tokens=[self.id_to_token[tid] for tid in tid_list],
                        support=round(cnt / self.total_samples, 4),
                        confidence=round(confidence, 4),
                        projects_covered=len(covered_projects),
                        is_maximal=True,
                    )
                    pattern_id_counter[0] += 1
                    patterns_this_level.append(pattern)
                    all_patterns.append(pattern)

            current_level = next_level
            level_num += 1

        # ----- 最大频繁模式过滤 -----
        # is_maximal: 如果某模式是另一更长模式的子序列，则标记为非最大
        # 按长度降序排列，较长模式优先
        if all_patterns:
            # 先按 token 序列去重（同一个 token 序列可能从不同路径产生）
            seen_seqs: set[str] = set()
            unique_patterns: list[PatternRecord] = []
            for p in all_patterns:
                seq_str = "|".join(p.sequence_tokens)
                if seq_str not in seen_seqs:
                    seen_seqs.add(seq_str)
                    unique_patterns.append(p)

            # 按长度降序排列
            unique_patterns.sort(key=lambda p: -len(p.sequence_tokens))

            # 标记非最大模式
            for i, p1 in enumerate(unique_patterns):
                if not p1.is_maximal:
                    continue
                for j, p2 in enumerate(unique_patterns):
                    if i == j or not p2.is_maximal:
                        continue
                    if len(p2.sequence_tokens) > len(p1.sequence_tokens):
                        # 检查 p1 是否是 p2 的保序子序列
                        if self._is_subsequence(p2.sequence_tokens, p1.sequence_tokens):
                            p1.is_maximal = False
                            break

            # 只保留最大频繁模式
            maximal_patterns = [p for p in unique_patterns if p.is_maximal]

            print(f"    去重后: {len(unique_patterns)} 个模式, 最大频繁: {len(maximal_patterns)} 个")
            return maximal_patterns

        return all_patterns

    @staticmethod
    def _is_subsequence(full: list[str], sub: list[str]) -> bool:
        """检查 sub 是否是 full 的保序子序列（非连续，完成语义）"""
        it = iter(full)
        return all(token in it for token in sub)


# ============================================================
# 4. 评分系统（不变）
# ============================================================

RISK_THRESHOLD = 0.50

SINK_SEVERITY_WEIGHTS = {
    "command": 1.0,
    "database": 1.0,
    "filesystem": 0.8,
    "memory": 0.7,
    "resource": 0.6,
    "compression": 0.4,
    "crypto": 0.5,
    "network": 0.9,
    "call": 0.3,
    "check": 0.1,
    "input": 0.5,
    "env": 0.4,
}


def compute_rarity_score(sample: StageAStatsSample, all_samples: list[StageAStatsSample]) -> float:
    tokens = sample.sequence_tokens
    if not tokens:
        return 0.0
    total = len(all_samples)
    if total == 0:
        return 0.0
    token_df: dict[str, int] = {}
    for s in all_samples:
        for token in set(s.sequence_tokens):
            token_df[token] = token_df.get(token, 0) + 1
    idf_sum = 0.0
    for token in tokens:
        df = token_df.get(token, 0)
        idf = math.log((total + 1) / (df + 1)) if df > 0 else math.log(total + 1)
        max_idf = math.log(total + 1)
        normalized_idf = idf / max_idf if max_idf > 0 else 0.0
        idf_sum += normalized_idf
    rarity = idf_sum / len(tokens)
    return round(min(max(rarity, 0.0), 1.0), 4)


def compute_sink_score(sample: StageAStatsSample) -> float:
    weights = sample.sink_type_weights()
    if not weights:
        return 0.0
    return round(max(weights), 4)


def compute_pattern_deviation_score(
    sample: StageAStatsSample,
    frequent_patterns: list[PatternRecord],
    min_support: float = 0.05,
) -> float:
    tokens = sample.sequence_tokens
    if not tokens:
        return 1.0
    high_freq_patterns = [p for p in frequent_patterns if p.support >= min_support]
    if not high_freq_patterns:
        return 0.5
    max_match_ratio = 0.0
    sample_token_set = set(tokens)
    for pattern in high_freq_patterns:
        pattern_tokens = pattern.sequence_tokens
        if not all(t in sample_token_set for t in pattern_tokens):
            continue
        current_pos = -1
        matched = True
        for t in pattern_tokens:
            try:
                pos = tokens.index(t, current_pos + 1)
                current_pos = pos
            except ValueError:
                matched = False
                break
        if matched:
            match_ratio = len(pattern_tokens) / len(tokens)
            support_factor = 1.0 - pattern.support
            score = match_ratio * (1.0 - support_factor)
            max_match_ratio = max(max_match_ratio, score)
    deviation = 1.0 - max_match_ratio
    return round(min(max(deviation, 0.0), 1.0), 4)


def determine_reason_tags(
    sample: StageAStatsSample,
    rarity_score: float,
    sink_score: float,
    pattern_deviation_score: float,
) -> list[str]:
    tags = []
    if rarity_score >= 0.7:
        tags.append("rare_path")
    if sink_score >= 0.7:
        tags.append("high_risk_sink")
    if rarity_score >= 0.5 and sink_score >= 0.5:
        tags.append("rare_sink_combination")
    if pattern_deviation_score >= 0.7:
        tags.append("pattern_anomaly")
    if sink_score >= 0.8:
        for st in sample.sink_types:
            st_lower = st.strip().lower()
            if st_lower == "command":
                tags.append("command_injection_risk")
                break
            if st_lower == "database":
                tags.append("sql_injection_risk")
                break
            if st_lower == "filesystem":
                tags.append("file_operation_risk")
                break
            if st_lower == "network":
                tags.append("network_exposure_risk")
                break
            if st_lower == "memory":
                tags.append("memory_risk")
                break
    if not tags:
        tags.append("low_risk")
    return tags


# ============================================================
# 5. 主流程
# ============================================================

def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def save_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
        f.write("\n")


def save_jsonl(path: Path, records: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for record in records:
            f.write(json.dumps(record, ensure_ascii=False))
            f.write("\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="Stage B 多维深度挖掘引擎，读取 Stage A samples.stats.jsonl")
    parser.add_argument("--input", "-i", required=True, help="输入文件路径: samples.stats.jsonl")
    parser.add_argument("--output-dir", "-o", required=True, help="输出目录")
    parser.add_argument("--min-support", type=int, default=3, help="频繁模式最低支持度（绝对计数）")
    parser.add_argument("--max-length", type=int, default=16, help="模式最大长度上限")
    args = parser.parse_args()

    input_path = Path(args.input)
    output_dir = Path(args.output_dir)
    min_support = args.min_support
    max_length = args.max_length

    print(f"加载输入: {input_path}", flush=True)
    samples = load_stats_samples(input_path)
    print(f"共 {len(samples)} 个样本")

    print(f"阶段1: 构建位掩码索引 + 频繁模式挖掘 (min_support={min_support})")
    miner = BitIndexMiner(samples, min_support_abs=min_support)
    print(f"  索引: {miner.n_tokens} tokens, {len(miner.order_bitmask)} 个顺序关系")

    patterns = miner.mine(max_length=max_length)
    print(f"  发现 {len(patterns)} 个最大频繁模式")

    patterns_output = [asdict(p) for p in patterns]
    patterns_path = output_dir / "patterns.json"
    save_json(patterns_path, patterns_output)
    print(f"  输出 patterns.json -> {patterns_path}")

    print(f"阶段2: 为所有样本评分")
    candidates: list[ScoredCandidate] = []
    for sample in samples:
        rarity = compute_rarity_score(sample, samples)
        sink = compute_sink_score(sample)
        deviation = compute_pattern_deviation_score(sample, patterns)
        risk = 0.40 * rarity + 0.35 * sink + 0.25 * deviation

        candidate = ScoredCandidate(
            project_id=sample.project_id,
            sample_id=sample.sample_id,
            rarity_score=rarity,
            sink_score=sink,
            pattern_deviation_score=deviation,
            risk_score=round(risk, 4),
            reason_tags=determine_reason_tags(sample, rarity, sink, deviation),
            route=sample.route,
            file=sample.primary_file,
            line=sample.primary_line,
            evidence_slice=sample.evidence_slice,
            threshold_pass=risk >= RISK_THRESHOLD,
            timestamps={"scored_at": utc_now()},
        )
        candidates.append(candidate)

    candidates.sort(key=lambda c: c.risk_score, reverse=True)

    all_candidates_output = [asdict(c) for c in candidates]
    candidates_path = output_dir / "candidates.scored.jsonl"
    save_jsonl(candidates_path, all_candidates_output)
    print(f"  输出 candidates.scored.jsonl -> {candidates_path}")

    passed = [c for c in candidates if c.threshold_pass]
    print(f"质量门禁: risk_score >= {RISK_THRESHOLD:.2f} 通过 {len(passed)}/{len(candidates)} 个")

    stats = {
        "total_samples": len(samples),
        "total_patterns": len(patterns),
        "total_candidates": len(candidates),
        "passed_threshold": len(passed),
        "failed_threshold": len(candidates) - len(passed),
        "index_type": "python_int_bitmask",
        "n_tokens": miner.n_tokens,
        "n_order_relations": len(miner.order_bitmask),
        "risk_score_distribution": {
            "0.0-0.3": sum(1 for c in candidates if c.risk_score < 0.3),
            "0.3-0.5": sum(1 for c in candidates if 0.3 <= c.risk_score < 0.5),
            "0.5-0.7": sum(1 for c in candidates if 0.5 <= c.risk_score < 0.7),
            "0.7-0.9": sum(1 for c in candidates if 0.7 <= c.risk_score < 0.9),
            "0.9-1.0": sum(1 for c in candidates if c.risk_score >= 0.9),
        },
    }
    stats_path = output_dir / "b_miner_stats.json"
    save_json(stats_path, stats)
    print(f"统计信息 -> {stats_path}")
    print(json.dumps(stats, ensure_ascii=False, indent=2))
    print("完成!")


if __name__ == "__main__":
    try:
        main()
    except InputContractError as exc:
        print(f"contract error: {exc}", file=sys.stderr)
        raise SystemExit(1)
