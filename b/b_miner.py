#!/usr/bin/env python3
"""
Stage B feature-absence miner.

Input: Stage A `samples.stats.jsonl` records with schema
`stagea.stats.features.v1`.

Stage B groups samples by `api_group`, finds high-support API relation
features, and scores samples that miss those high-support features. It does not
perform sequence mining and does not accept the old `edge_tokens` stats schema.
"""

import argparse
import hashlib
import json
import math
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "stagea.stats.features.v1"
PATTERN_SCHEMA_VERSION = "stageb.feature_patterns.v1"
CANDIDATE_SCHEMA_VERSION = "stageb.feature_candidates.v1"

REQUIRED_FIELDS = {
    "schema_version",
    "project_id",
    "sample_id",
    "api_group",
    "location_id",
    "location",
    "seed_id",
    "seed_token",
    "feature_tokens",
    "feature_details",
    "source_kinds",
    "sink_types",
    "focus",
    "feature_stats",
}

SINK_SEVERITY_WEIGHTS = {
    "command": 1.0,
    "database": 1.0,
    "network": 0.9,
    "filesystem": 0.8,
    "memory": 0.7,
    "resource": 0.6,
    "crypto": 0.5,
    "input": 0.5,
    "compression": 0.4,
    "env": 0.4,
    "call": 0.3,
    "check": 0.1,
}

FEATURE_WEIGHTS = {
    "command": 1.0,
    "database": 1.0,
    "network": 0.9,
    "filesystem": 0.8,
    "memory": 0.75,
    "resource": 0.75,
    "synchronization": 0.7,
    "crypto": 0.65,
    "permission": 0.65,
    "process": 0.65,
    "check": 0.55,
}


@dataclass
class StageAStatsSample:
    project_id: str
    sample_id: str
    api_group: str
    location_id: int
    location: dict[str, Any]
    seed_id: str
    seed_token: str
    feature_tokens: list[str]
    feature_details: list[dict[str, Any]]
    source_kinds: list[str]
    sink_types: list[str]
    focus: dict[str, Any]
    feature_stats: dict[str, Any]
    feature_set: set[str] = field(init=False)

    def __post_init__(self) -> None:
        self.feature_set = set(self.feature_tokens)

    @property
    def route(self) -> str:
        loc_file = str(self.location.get("file", "")).strip()
        loc_func = str(self.location.get("function", "")).strip()
        if loc_file and loc_func:
            return f"{loc_file}::{loc_func}"
        if self.seed_id:
            return self.seed_id.rsplit(":", 1)[0]
        return ""

    @property
    def primary_file(self) -> str:
        return str(self.focus.get("file") or self.location.get("file", "")).strip()

    @property
    def primary_line(self) -> int:
        return int(self.focus.get("line", 0) or 0)

    @property
    def evidence_slice(self) -> str:
        return self.seed_token

    def sink_score(self) -> float:
        scores = [SINK_SEVERITY_WEIGHTS.get(kind.strip().lower(), 0.3) for kind in self.sink_types]
        return round(max(scores), 4) if scores else 0.0


@dataclass
class FeatureStats:
    token: str
    support_count: int
    support: float
    sample_ids: list[str]


@dataclass
class GroupModel:
    api_group: str
    samples: list[StageAStatsSample]
    threshold_abs: int
    feature_stats: dict[str, FeatureStats]
    expected_features: list[str]


@dataclass
class ScoredCandidate:
    schema_version: str
    candidate_id: str
    project_id: str
    sample_id: str
    api_group: str
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
    expected_features: list[str]
    present_features: list[str]
    missing_features: list[dict[str, Any]]
    expected_feature_count: int
    present_expected_feature_count: int
    missing_feature_count: int
    support_threshold: int
    group_size: int
    reference_sample_ids: list[str]
    source_kinds: list[str]
    sink_types: list[str]
    feature_stats: dict[str, Any]
    llm_join: dict[str, str]
    timestamps: dict[str, str]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Stage B high-support feature absence miner")
    parser.add_argument("--input", "-i", required=True, help="Stage A samples.stats.jsonl path")
    parser.add_argument("--output-dir", "-o", required=True, help="Stage B output directory")
    parser.add_argument("--min-support", type=int, default=3, help="minimum absolute support")
    parser.add_argument(
        "--min-support-ratio",
        type=float,
        default=0.90,
        help="minimum within-api_group support ratio",
    )
    parser.add_argument(
        "--risk-threshold",
        type=float,
        default=0.60,
        help="risk_score threshold for threshold_pass",
    )
    return parser.parse_args()


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def stable_id(prefix: str, *parts: str) -> str:
    digest = hashlib.sha1("|".join(parts).encode("utf-8")).hexdigest()
    return f"{prefix}_{digest[:12]}"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def require_string(value: Any, field: str, line_no: int, allow_empty: bool = False) -> str:
    require(isinstance(value, str), f"line {line_no}: {field} must be a string")
    text = value.strip()
    if not allow_empty:
        require(bool(text), f"line {line_no}: {field} must not be empty")
    return text


def require_list(value: Any, field: str, line_no: int) -> list[Any]:
    require(isinstance(value, list), f"line {line_no}: {field} must be a list")
    return value


def require_dict(value: Any, field: str, line_no: int) -> dict[str, Any]:
    require(isinstance(value, dict), f"line {line_no}: {field} must be an object")
    return value


def unique_strings(values: list[Any], field: str, line_no: int) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        require(isinstance(value, str), f"line {line_no}: {field} entries must be strings")
        text = value.strip()
        require(bool(text), f"line {line_no}: {field} entries must not be empty")
        if text in seen:
            continue
        seen.add(text)
        result.append(text)
    return result


def validate_record(data: dict[str, Any], line_no: int) -> StageAStatsSample:
    missing = sorted(REQUIRED_FIELDS - set(data))
    require(not missing, f"line {line_no}: missing required fields: {', '.join(missing)}")
    schema = require_string(data.get("schema_version"), "schema_version", line_no)
    require(schema == SCHEMA_VERSION, f"line {line_no}: unsupported schema_version {schema!r}")

    location_id = data.get("location_id")
    require(isinstance(location_id, int), f"line {line_no}: location_id must be an integer")

    return StageAStatsSample(
        project_id=require_string(data.get("project_id"), "project_id", line_no),
        sample_id=require_string(data.get("sample_id"), "sample_id", line_no),
        api_group=require_string(data.get("api_group"), "api_group", line_no),
        location_id=location_id,
        location=require_dict(data.get("location"), "location", line_no),
        seed_id=require_string(data.get("seed_id"), "seed_id", line_no, allow_empty=True),
        seed_token=require_string(data.get("seed_token"), "seed_token", line_no, allow_empty=True),
        feature_tokens=unique_strings(require_list(data.get("feature_tokens"), "feature_tokens", line_no), "feature_tokens", line_no),
        feature_details=require_list(data.get("feature_details"), "feature_details", line_no),
        source_kinds=unique_strings(require_list(data.get("source_kinds"), "source_kinds", line_no), "source_kinds", line_no),
        sink_types=unique_strings(require_list(data.get("sink_types"), "sink_types", line_no), "sink_types", line_no),
        focus=require_dict(data.get("focus"), "focus", line_no),
        feature_stats=require_dict(data.get("feature_stats"), "feature_stats", line_no),
    )


def load_stats_samples(path: Path) -> list[StageAStatsSample]:
    samples: list[StageAStatsSample] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, 1):
            line = line.strip()
            if not line:
                continue
            data = json.loads(line)
            require(isinstance(data, dict), f"line {line_no}: record must be an object")
            samples.append(validate_record(data, line_no))
    require(bool(samples), f"no Stage A stats records found: {path}")
    return samples


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)
        handle.write("\n")


def write_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False))
            handle.write("\n")


def feature_weight(token: str) -> float:
    left, _, right = token.partition("->")
    prefixes = []
    for part in (left, right):
        prefix, _, _ = part.partition(":")
        if prefix:
            prefixes.append(prefix.strip().lower())
    scores = [FEATURE_WEIGHTS.get(prefix, 0.5) for prefix in prefixes]
    return max(scores) if scores else 0.5


def support_threshold(group_size: int, min_support_abs: int, min_support_ratio: float) -> int:
    ratio_threshold = math.ceil(min_support_ratio * group_size)
    return max(min_support_abs, ratio_threshold)


def build_group_model(
    api_group: str,
    samples: list[StageAStatsSample],
    min_support_abs: int,
    min_support_ratio: float,
) -> GroupModel:
    group_size = len(samples)
    threshold = support_threshold(group_size, min_support_abs, min_support_ratio)
    feature_to_sample_ids: dict[str, set[str]] = defaultdict(set)

    for sample in samples:
        for feature in sample.feature_set:
            feature_to_sample_ids[feature].add(sample.sample_id)

    feature_stats: dict[str, FeatureStats] = {}
    for feature, sample_ids in feature_to_sample_ids.items():
        support_count = len(sample_ids)
        feature_stats[feature] = FeatureStats(
            token=feature,
            support_count=support_count,
            support=round(support_count / group_size, 4),
            sample_ids=sorted(sample_ids),
        )

    expected_features = sorted(
        feature
        for feature, stats in feature_stats.items()
        if stats.support_count >= threshold
    )

    return GroupModel(
        api_group=api_group,
        samples=samples,
        threshold_abs=threshold,
        feature_stats=feature_stats,
        expected_features=expected_features,
    )


def build_models(
    samples: list[StageAStatsSample],
    min_support_abs: int,
    min_support_ratio: float,
) -> dict[str, GroupModel]:
    grouped: dict[str, list[StageAStatsSample]] = defaultdict(list)
    for sample in samples:
        grouped[sample.api_group].append(sample)

    return {
        api_group: build_group_model(api_group, grouped_samples, min_support_abs, min_support_ratio)
        for api_group, grouped_samples in sorted(grouped.items())
    }


def pattern_records(models: dict[str, GroupModel]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for api_group, model in models.items():
        for feature in model.expected_features:
            stats = model.feature_stats[feature]
            records.append(
                {
                    "schema_version": PATTERN_SCHEMA_VERSION,
                    "pattern_id": stable_id("pat", api_group, feature),
                    "api_group": api_group,
                    "feature_tokens": [feature],
                    "support": stats.support,
                    "support_count": stats.support_count,
                    "group_size": len(model.samples),
                    "support_threshold": model.threshold_abs,
                    "reference_sample_ids": stats.sample_ids[:5],
                }
            )
    return records


def compute_rarity_score(sample: StageAStatsSample, model: GroupModel) -> float:
    if not sample.feature_tokens:
        return 0.0
    total = len(model.samples)
    max_idf = math.log(total + 1)
    if max_idf <= 0:
        return 0.0

    idf_sum = 0.0
    for feature in sample.feature_tokens:
        stats = model.feature_stats.get(feature)
        df = stats.support_count if stats is not None else 0
        idf = math.log((total + 1) / (df + 1)) if df > 0 else max_idf
        idf_sum += idf / max_idf
    return round(min(max(idf_sum / len(sample.feature_tokens), 0.0), 1.0), 4)


def compute_deviation_score(missing: list[str], expected: list[str], model: GroupModel) -> float:
    if not expected:
        return 0.0
    denominator = 0.0
    numerator = 0.0
    missing_set = set(missing)
    for feature in expected:
        stats = model.feature_stats[feature]
        weight = stats.support * feature_weight(feature)
        denominator += weight
        if feature in missing_set:
            numerator += weight
    if denominator <= 0:
        return 0.0
    return round(min(max(numerator / denominator, 0.0), 1.0), 4)


def reason_tags(sample: StageAStatsSample, missing: list[str], sink_score: float, deviation: float) -> list[str]:
    tags: list[str] = []
    if missing:
        tags.append("missing_high_support_relation")
    if deviation >= 0.7:
        tags.append("strong_pattern_deviation")
    elif deviation >= 0.4:
        tags.append("moderate_pattern_deviation")
    if sink_score >= 0.7:
        tags.append("high_risk_sink")
    for kind in sample.sink_types:
        normalized = kind.strip().lower()
        if normalized:
            tags.append(f"{normalized}_sink")
    if not tags:
        tags.append("no_high_support_missing_relation")
    return tags


def reference_samples_for_missing(model: GroupModel, missing: list[str], current_sample_id: str) -> list[str]:
    if not missing:
        return []
    candidate_ids: set[str] | None = None
    for feature in missing:
        ids = set(model.feature_stats[feature].sample_ids)
        candidate_ids = ids if candidate_ids is None else candidate_ids & ids
    if candidate_ids is None:
        return []
    candidate_ids.discard(current_sample_id)
    return sorted(candidate_ids)[:5]


def missing_feature_payload(model: GroupModel, missing: list[str]) -> list[dict[str, Any]]:
    payload: list[dict[str, Any]] = []
    group_size = len(model.samples)
    for feature in missing:
        stats = model.feature_stats[feature]
        payload.append(
            {
                "token": feature,
                "support": stats.support,
                "support_count": stats.support_count,
                "group_size": group_size,
                "weight": round(feature_weight(feature), 4),
                "reference_sample_ids": stats.sample_ids[:5],
            }
        )
    return payload


def score_candidates(
    models: dict[str, GroupModel],
    risk_threshold: float,
) -> list[ScoredCandidate]:
    scored_at = utc_now()
    candidates: list[ScoredCandidate] = []

    for api_group, model in models.items():
        expected = model.expected_features
        expected_set = set(expected)
        for sample in model.samples:
            present = sorted(sample.feature_set & expected_set)
            missing = sorted(expected_set - sample.feature_set)
            rarity = compute_rarity_score(sample, model)
            sink = sample.sink_score()
            deviation = compute_deviation_score(missing, expected, model)
            risk = round(0.25 * rarity + 0.25 * sink + 0.50 * deviation, 4)
            refs = reference_samples_for_missing(model, missing, sample.sample_id)

            candidate = ScoredCandidate(
                schema_version=CANDIDATE_SCHEMA_VERSION,
                candidate_id=stable_id("cand", sample.project_id, sample.sample_id, api_group, "|".join(missing)),
                project_id=sample.project_id,
                sample_id=sample.sample_id,
                api_group=api_group,
                rarity_score=rarity,
                sink_score=sink,
                pattern_deviation_score=deviation,
                risk_score=risk,
                reason_tags=reason_tags(sample, missing, sink, deviation),
                route=sample.route,
                file=sample.primary_file,
                line=sample.primary_line,
                evidence_slice=sample.evidence_slice,
                threshold_pass=bool(missing and risk >= risk_threshold),
                expected_features=expected,
                present_features=present,
                missing_features=missing_feature_payload(model, missing),
                expected_feature_count=len(expected),
                present_expected_feature_count=len(present),
                missing_feature_count=len(missing),
                support_threshold=model.threshold_abs,
                group_size=len(model.samples),
                reference_sample_ids=refs,
                source_kinds=sample.source_kinds,
                sink_types=sample.sink_types,
                feature_stats=sample.feature_stats,
                llm_join={"file": "samples.llm.jsonl", "key": "sample_id"},
                timestamps={"scored_at": scored_at},
            )
            candidates.append(candidate)

    candidates.sort(key=lambda item: (item.risk_score, item.pattern_deviation_score, item.sink_score), reverse=True)
    return candidates


def risk_distribution(candidates: list[ScoredCandidate]) -> dict[str, int]:
    return {
        "0.0-0.3": sum(1 for c in candidates if c.risk_score < 0.3),
        "0.3-0.5": sum(1 for c in candidates if 0.3 <= c.risk_score < 0.5),
        "0.5-0.7": sum(1 for c in candidates if 0.5 <= c.risk_score < 0.7),
        "0.7-0.9": sum(1 for c in candidates if 0.7 <= c.risk_score < 0.9),
        "0.9-1.0": sum(1 for c in candidates if c.risk_score >= 0.9),
    }


def stats_payload(samples: list[StageAStatsSample], models: dict[str, GroupModel], candidates: list[ScoredCandidate]) -> dict[str, Any]:
    passed = [candidate for candidate in candidates if candidate.threshold_pass]
    return {
        "schema_version": "stageb.feature_miner_stats.v1",
        "input_schema_version": SCHEMA_VERSION,
        "total_samples": len(samples),
        "total_groups": len(models),
        "total_patterns": sum(len(model.expected_features) for model in models.values()),
        "total_candidates": len(candidates),
        "passed_threshold": len(passed),
        "failed_threshold": len(candidates) - len(passed),
        "min_support_by_group": {
            api_group: model.threshold_abs
            for api_group, model in models.items()
        },
        "expected_feature_count_by_group": {
            api_group: len(model.expected_features)
            for api_group, model in models.items()
        },
        "risk_score_distribution": risk_distribution(candidates),
    }


def main() -> None:
    args = parse_args()
    input_path = Path(args.input)
    output_dir = Path(args.output_dir)

    print(f"加载输入: {input_path}")
    samples = load_stats_samples(input_path)
    print(f"共 {len(samples)} 个样本")

    print(
        "阶段1: 高频 feature 统计 "
        f"(min_support={args.min_support}, min_support_ratio={args.min_support_ratio})"
    )
    models = build_models(samples, args.min_support, args.min_support_ratio)
    patterns = pattern_records(models)
    print(f"  分组 {len(models)} 个, 高频 feature {len(patterns)} 个")

    patterns_path = output_dir / "patterns.json"
    write_json(patterns_path, patterns)
    print(f"  输出 patterns.json -> {patterns_path}")

    print("阶段2: 缺失高频 feature 评分")
    candidates = score_candidates(models, args.risk_threshold)
    candidate_records = [candidate.__dict__ for candidate in candidates]
    candidates_path = output_dir / "candidates.scored.jsonl"
    write_jsonl(candidates_path, candidate_records)
    print(f"  输出 candidates.scored.jsonl -> {candidates_path}")

    passed = [candidate for candidate in candidates if candidate.threshold_pass]
    print(f"质量门禁: risk_score >= {args.risk_threshold:.2f} 且存在缺失 feature 通过 {len(passed)}/{len(candidates)} 个")

    stats_path = output_dir / "b_miner_stats.json"
    stats = stats_payload(samples, models, candidates)
    write_json(stats_path, stats)
    print(f"统计信息 -> {stats_path}")
    print(json.dumps(stats, ensure_ascii=False, indent=2))
    print("完成!")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(f"error: {exc}") from exc
