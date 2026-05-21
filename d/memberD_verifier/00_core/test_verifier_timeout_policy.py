#!/usr/bin/env python3
import json
import tempfile
import unittest
from pathlib import Path

import verifier


def _hyp(priority):
    return {
        "project_id": "p",
        "sample_id": "s",
        "hypothesis_id": f"hyp_{priority.lower()}",
        "priority": priority,
        "route": "file.c::bad",
        "file": "file.c",
        "line": 1,
        "evidence_slice": "call:sink",
    }


def _target_with_context_timeout():
    return {
        "target_type": "source_api",
        "verification_context": {
            "repo_path": ".",
            "run_cmd": "true",
            "timeout_sec": 123,
        },
    }


class TimeoutPolicyTests(unittest.TestCase):
    def _plan_for(self, hyp):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "plan.json"
            verifier.write_source_api_plan(
                path,
                hyp,
                {"oracle": {}},
                _target_with_context_timeout(),
                verifier.timeout_for_hypothesis(hyp),
            )
            return json.loads(path.read_text(encoding="utf-8"))

    def test_p0_has_fixed_timeout(self):
        hyp = _hyp("P0")
        self.assertEqual(verifier.timeout_for_hypothesis(hyp), 10.0)
        self.assertEqual(self._plan_for(hyp)["build"]["timeout_sec"], 10.0)

    def test_non_p0_has_no_d_timeout(self):
        for priority in ("P1", "P2", "P3"):
            with self.subTest(priority=priority):
                hyp = _hyp(priority)
                self.assertIsNone(verifier.timeout_for_hypothesis(hyp))
                self.assertIsNone(self._plan_for(hyp)["build"]["timeout_sec"])


if __name__ == "__main__":
    unittest.main()
