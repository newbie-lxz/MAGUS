#!/usr/bin/env python3
import importlib.util
import sys
import types
import unittest
from pathlib import Path


class _OpenAIStub:
    def __init__(self, *args, **kwargs):
        pass


def _load_agent1():
    sys.modules.setdefault("openai", types.SimpleNamespace(OpenAI=_OpenAIStub))
    module_path = Path(__file__).with_name("agent1.py")
    spec = importlib.util.spec_from_file_location("agent1_for_routing_tests", module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


agent1 = _load_agent1()


def _candidate():
    return {
        "project_id": "p",
        "sample_id": "s",
        "route": "file.c::bad",
        "file": "file.c",
        "line": 10,
        "evidence_slice": "call:sink",
    }


def _vuln(confidence=0.8, evidence_complete=True):
    return {
        "claim": "externally controlled data reaches a configuration sink",
        "cwe_candidates": ["CWE-15"],
        "trigger_path": [{"step": 1, "loc": "file.c:10", "code": "sink(data);"}],
        "confidence": confidence,
        "evidence_complete": evidence_complete,
    }


def _no_vuln(**extra):
    resp = {
        "claim": "NO_VULNERABILITY_FOUND",
        "cwe_candidates": [],
        "trigger_path": [],
        "confidence": 0.0,
        "evidence_complete": True,
    }
    resp.update(extra)
    return resp


class RouteRecordTests(unittest.TestCase):
    def test_all_no_vulnerability_routes_to_p3(self):
        _, priority, verdict, reason, _ = agent1.route_record(
            _candidate(), [_no_vuln(), _no_vuln(), _no_vuln()]
        )
        self.assertEqual((priority, verdict, reason), ("P3", "audit_only", "red_team_no_vulnerability"))

    def test_disputed_vulnerability_does_not_route_to_p3(self):
        _, priority, verdict, reason, contradictions = agent1.route_record(
            _candidate(),
            [
                _vuln(),
                _no_vuln(hard_contradictions=["sink not shown"]),
                _no_vuln(stability="hard_contradiction"),
            ],
        )
        self.assertEqual((priority, verdict, reason), ("P2", "candidate_for_d", "red_team_vulnerability_once"))
        self.assertIn("sink not shown", contradictions)

    def test_incomplete_vulnerability_does_not_route_to_p3(self):
        _, priority, verdict, reason, _ = agent1.route_record(
            _candidate(), [_vuln(evidence_complete=False), _vuln(evidence_complete=False), _no_vuln()]
        )
        self.assertEqual((priority, verdict, reason), ("P1", "candidate_for_d", "red_team_stable_needs_dynamic_verification"))

    def test_complete_consensus_vulnerability_can_route_to_p0(self):
        _, priority, verdict, reason, _ = agent1.route_record(
            _candidate(), [_vuln(0.95), _vuln(0.95), _vuln(0.95)]
        )
        self.assertEqual((priority, verdict, reason), ("P0", "static_confirmed", "red_team_static_strong"))


if __name__ == "__main__":
    unittest.main()
