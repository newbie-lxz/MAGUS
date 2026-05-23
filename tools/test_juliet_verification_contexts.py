#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class JulietContextToolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parents[1]
        cls.tool = load_module("gen_juliet_verification_contexts", root / "tools" / "gen_juliet_verification_contexts.py")

    def test_project_sidecar_uses_template_context_without_oracle_markers(self):
        rows = self.tool.context_rows(["cwe114"], Path("/workspace"))

        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["project_id"], "cwe114")
        self.assertEqual(row["repo_path"], "/workspace")
        self.assertIn("tools/juliet_win_shim/run_juliet_win_case.py", row["test_cmd"])
        self.assertIn("${source_file}", row["test_cmd"])
        self.assertIn("${entry_symbol}", row["test_cmd"])
        self.assertIn("${route}", row["test_cmd"])
        oracle_text = json.dumps(row["oracle"], ensure_ascii=False)
        self.assertIn("MAGUS_ROUTE_CONFIRMED", oracle_text)
        self.assertIn("MAGUS_ORACLE_UNSUPPORTED", oracle_text)
        self.assertNotIn("MAGUS_JULIET", oracle_text)


class JulietHelperOutputTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parents[1]
        cls.runner = load_module(
            "run_juliet_win_case",
            root / "tools" / "juliet_win_shim" / "run_juliet_win_case.py",
        )

    def test_runtime_markers_are_project_agnostic_for_oracle_matching(self):
        stdout = "\n".join(
            [
                "MAGUS_JULIET_FLAW name=CryptDeriveKey reason=broken_cipher_algorithm value=",
                "MAGUS_JULIET_SINK name=system tainted=1 value=payload",
            ]
        )

        generic = self.runner.generic_oracle_output(stdout)

        self.assertIn("MAGUS_ORACLE_FLAW name=CryptDeriveKey reason=broken_cipher_algorithm", generic)
        self.assertIn("MAGUS_ORACLE_SINK name=system tainted=1", generic)
        self.assertNotIn("MAGUS_JULIET", generic)

    def test_rpc_failure_semantic_marker_is_generic(self):
        stdout = "MAGUS_JULIET_FLAW name=RpcImpersonateClient reason=forced_non_ok_return_for_privilege_drop_check value="

        self.assertEqual(self.runner.route_bound_semantic_markers(stdout, False), [])
        self.assertEqual(
            self.runner.route_bound_semantic_markers(stdout, True),
            ["MAGUS_ORACLE_FLAW name=RpcImpersonateClient reason=forced_non_ok_return_not_propagated value="],
        )


if __name__ == "__main__":
    unittest.main()
