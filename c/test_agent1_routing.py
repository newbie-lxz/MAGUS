#!/usr/bin/env python3
import importlib.util
import io
import json
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


class OutputRoutingTests(unittest.TestCase):
    def _p0_record(self):
        return {
            "project_id": "p",
            "sample_id": "s",
            "hypothesis_id": "hyp_s",
            "priority": "P0",
            "agent_verdict": "static_confirmed",
            "routing_decision": "static_confirmed",
            "route": "file.c::bad",
            "file": "file.c",
            "line": 10,
            "evidence_slice": "call:sink",
            "status": "static_confirmed",
            "d_verification": "pending_routing_decision",
        }

    def test_p0_goes_to_d_when_time_remains(self):
        d_file, static_file, audit_file = io.StringIO(), io.StringIO(), io.StringIO()
        bucket = agent1.process_completed_future(
            agent1.CompletedFuture(self._p0_record()),
            _candidate(),
            d_file,
            static_file,
            audit_file,
            p0_to_d=True,
        )
        self.assertEqual(bucket, "p0_d")
        self.assertEqual(static_file.getvalue(), "")
        row = json.loads(d_file.getvalue())
        self.assertEqual(row["status"], "pending_dynamic_verification")
        self.assertEqual(row["d_verification"], "pending")
        self.assertEqual(row["stage_c_p0_routing"], "sent_to_d_with_time_remaining")

    def test_p0_falls_back_to_static_when_no_time_remains(self):
        d_file, static_file, audit_file = io.StringIO(), io.StringIO(), io.StringIO()
        bucket = agent1.process_completed_future(
            agent1.CompletedFuture(self._p0_record()),
            _candidate(),
            d_file,
            static_file,
            audit_file,
            p0_to_d=False,
        )
        self.assertEqual(bucket, "static")
        self.assertEqual(d_file.getvalue(), "")
        row = json.loads(static_file.getvalue())
        self.assertEqual(row["status"], "static_confirmed")
        self.assertEqual(row["d_verification"], "skipped_no_time_remaining")
        self.assertEqual(row["stage_c_p0_routing"], "static_fallback_no_time_remaining")


if __name__ == "__main__":
    unittest.main()
