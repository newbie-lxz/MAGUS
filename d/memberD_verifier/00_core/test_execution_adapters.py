#!/usr/bin/env python3
import importlib.util
import json
import unittest
from pathlib import Path

import gen_targets_from_hypotheses as target_gen


def load_juliet_runner_module():
    root = Path(__file__).resolve().parents[3]
    path = root / "tools" / "juliet_win_shim" / "run_juliet_win_case.py"
    spec = importlib.util.spec_from_file_location("run_juliet_win_case", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ExecutionAdapterTests(unittest.TestCase):
    def test_juliet_adapter_injects_execution_without_juliet_oracle_markers(self):
        hyp = {
            "project_id": "srcs_sanitized/juliet-api-misuse",
            "sample_id": "s1",
            "hypothesis_id": "h1",
            "route": "file.c::LoadLibraryA",
            "file": "juliet-api-misuse/testcases/CWE114_Process_Control/example.c",
            "claim": "relative path reaches dynamic library loading",
            "evidence_slice": "LoadLibraryA(data);",
        }

        case = target_gen.make_source_api_case(hyp, auto_fill=True)

        self.assertEqual(case["execution_adapter_id"], "juliet_win32_linux_shim")
        self.assertIn("tools/juliet_win_shim/run_juliet_win_case.py", case["execution"]["test_cmd"])
        oracle_text = json.dumps(case["oracle"], ensure_ascii=False)
        self.assertIn("MAGUS_ROUTE_CONFIRMED", oracle_text)
        self.assertIn("MAGUS_ORACLE_UNSUPPORTED", oracle_text)
        self.assertNotIn("MAGUS_JULIET", oracle_text)

    def test_non_adapter_project_stays_context_free(self):
        hyp = {
            "project_id": "openssl",
            "sample_id": "s1",
            "hypothesis_id": "h1",
            "route": "parse_config -> LoadLibraryA",
            "file": "crypto/example.c",
            "claim": "relative path reaches dynamic library loading",
            "evidence_slice": "LoadLibraryA(data);",
        }

        case = target_gen.make_source_api_case(hyp, auto_fill=True)

        self.assertNotIn("execution_adapter_id", case)
        self.assertNotIn("execution", case)
        oracle_text = json.dumps(case["oracle"], ensure_ascii=False)
        self.assertIn("MAGUS_ORACLE_FLAW name=LoadLibraryA reason=relative_library_path", oracle_text)
        self.assertIn("MAGUS_ROUTE_EXECUTED", oracle_text)
        self.assertNotIn("MAGUS_JULIET", oracle_text)


class JulietHelperOutputTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.runner = load_juliet_runner_module()

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
