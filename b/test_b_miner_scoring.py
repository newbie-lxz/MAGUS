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


if __name__ == "__main__":
    unittest.main()
