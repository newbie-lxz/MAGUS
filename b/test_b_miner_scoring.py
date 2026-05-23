#!/usr/bin/env python3
import importlib.util
import sys
import unittest
from pathlib import Path


def _load_b_miner():
    module_path = Path(__file__).with_name("b_miner.py")
    spec = importlib.util.spec_from_file_location("b_miner_for_scoring_tests", module_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


b_miner = _load_b_miner()


class RiskScoringTests(unittest.TestCase):
    def test_risk_score_uses_current_weights(self):
        self.assertEqual(b_miner.compute_risk_score(rarity=1.0, sink=0.0, deviation=0.0), 0.1)
        self.assertEqual(b_miner.compute_risk_score(rarity=0.0, sink=1.0, deviation=0.0), 0.45)
        self.assertEqual(b_miner.compute_risk_score(rarity=0.0, sink=0.0, deviation=1.0), 0.45)

    def test_static_confirmation_support_blocks_low_signal_routes(self):
        support = b_miner.static_confirmation_support_payload(
            threshold_pass=False,
            missing_feature_count=0,
            max_sink_score=0.0,
            max_pattern_deviation_score=0.0,
        )
        self.assertFalse(support["supported"])
        self.assertEqual(support["reason"], "no_missing_feature_no_deviation_low_sink")

    def test_static_confirmation_support_allows_high_sink_routes(self):
        support = b_miner.static_confirmation_support_payload(
            threshold_pass=False,
            missing_feature_count=0,
            max_sink_score=0.9,
            max_pattern_deviation_score=0.0,
        )
        self.assertTrue(support["supported"])
        self.assertEqual(support["reason"], "high_risk_sink")


class CReadyPriorityTests(unittest.TestCase):
    def _record(
        self,
        *,
        file,
        route,
        source_kinds,
        sink_types,
        seed_tokens,
        max_risk_score=0.4,
        max_sink_score=0.7,
        candidate_count=4,
        evidence_slice="",
    ):
        return {
            "project_id": "p",
            "route": route,
            "file": file,
            "evidence_slice": evidence_slice,
            "stage_b": {
                "threshold_pass": False,
                "max_risk_score": max_risk_score,
                "max_sink_score": max_sink_score,
                "max_pattern_deviation_score": 0.0,
                "max_rarity_score": 0.0,
                "candidate_count": candidate_count,
                "source_kinds": source_kinds,
                "sink_types": sink_types,
                "seed_tokens": seed_tokens,
                "static_confirmation_support": {"supported": True},
            },
        }

    def test_c_ready_priority_boosts_external_input_routes(self):
        environment_route = self._record(
            file="project/load_from_environment.c",
            route="project/load_from_environment.c::configure_runtime_path",
            source_kinds=["environment"],
            sink_types=["memory"],
            seed_tokens=["env:getenv", "call:LoadLibraryA"],
            evidence_slice="data = getenv(\"ADD\"); LoadLibraryA(data);",
        )
        file_route = self._record(
            file="project/load_from_file.c",
            route="project/load_from_file.c::configure_runtime_path",
            source_kinds=["filesystem"],
            sink_types=["filesystem"],
            seed_tokens=["filesystem:fopen"],
            max_risk_score=0.5,
            max_sink_score=0.8,
        )

        env_priority = b_miner.c_ready_priority_payload(environment_route)
        file_priority = b_miner.c_ready_priority_payload(file_route)

        self.assertGreater(env_priority["score"], file_priority["score"])
        self.assertIn("environment_source", env_priority["components"])
        self.assertIn("filesystem_file_source_without_external_input", file_priority["components"])

    def test_c_ready_priority_does_not_let_threshold_pass_dominate_high_signal_route(self):
        threshold_route = self._record(
            file="low.c",
            route="low.c::route",
            source_kinds=[],
            sink_types=[],
            seed_tokens=[],
            max_risk_score=0.1,
            max_sink_score=0.0,
        )
        threshold_route["stage_b"]["threshold_pass"] = True
        high_signal_route = self._record(
            file="project/load_from_environment.c",
            route="project/load_from_environment.c::configure_runtime_path",
            source_kinds=["environment"],
            sink_types=["memory"],
            seed_tokens=["env:getenv"],
            max_risk_score=0.9,
            max_sink_score=0.9,
            candidate_count=20,
        )

        self.assertLess(
            b_miner.c_ready_priority_payload(threshold_route)["score"],
            b_miner.c_ready_priority_payload(high_signal_route)["score"],
        )

    def test_c_ready_priority_requires_observed_source_not_route_name_only(self):
        route_named_environment = self._record(
            file="project/environment_handler.c",
            route="project/environment_handler.c::configure_path",
            source_kinds=[],
            sink_types=["filesystem"],
            seed_tokens=["call:append_path"],
            evidence_slice="data = fixed_buffer; append_path(data, DEFAULT_PATH);",
        )
        observed_environment = self._record(
            file="project/environment_handler.c",
            route="project/environment_handler.c::configure_path_from_input",
            source_kinds=[],
            sink_types=["filesystem"],
            seed_tokens=["env:getenv", "call:append_path"],
            evidence_slice="data = getenv(\"CONFIG_PATH\"); append_path(data, DEFAULT_PATH);",
        )

        route_named_priority = b_miner.c_ready_priority_payload(route_named_environment)
        observed_priority = b_miner.c_ready_priority_payload(observed_environment)

        self.assertNotIn("environment_source", route_named_priority["components"])
        self.assertIn("filesystem_sink_without_external_input", route_named_priority["components"])
        self.assertIn("environment_source", observed_priority["components"])
        self.assertGreater(observed_priority["score"], route_named_priority["score"])


if __name__ == "__main__":
    unittest.main()
