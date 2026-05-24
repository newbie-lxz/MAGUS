import json
import unittest

import gen_targets_from_hypotheses as target_gen


class ExplicitContextTests(unittest.TestCase):
    def test_auto_fill_does_not_inject_benchmark_execution_context(self):
        hyp = {
            "project_id": "benchmark_project",
            "sample_id": "s1",
            "hypothesis_id": "h1",
            "route": "file.c::LoadLibraryA",
            "file": "benchmarks/source_api/example.c",
            "claim": "relative path reaches dynamic library loading",
            "evidence_slice": "LoadLibraryA(data);",
        }

        case = target_gen.make_source_api_case(hyp, auto_fill=True)

        self.assertNotIn("execution", case)
        oracle_text = json.dumps(case["oracle"], ensure_ascii=False)
        self.assertIn("MAGUS_ROUTE_EXECUTED", oracle_text)
        self.assertIn("MAGUS_ORACLE_UNSUPPORTED", oracle_text)

    def test_regular_project_stays_context_free_without_sidecar(self):
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

        self.assertNotIn("execution", case)
        oracle_text = json.dumps(case["oracle"], ensure_ascii=False)
        self.assertIn("MAGUS_ORACLE_FLAW name=LoadLibraryA reason=relative_library_path", oracle_text)
        self.assertIn("MAGUS_ROUTE_EXECUTED", oracle_text)

    def test_resource_lifecycle_requires_oracle_capability_marker(self):
        hyp = {
            "project_id": "posix_project",
            "sample_id": "s1",
            "hypothesis_id": "h1",
            "route": "load_config -> open",
            "file": "src/config.c",
            "claim": "file descriptor returned by open can miss close on an error path",
            "evidence_slice": "fd = open(path, O_RDONLY); if (parse(fd) < 0) return -1;",
        }

        case = target_gen.make_source_api_case(hyp, auto_fill=True)

        self.assertEqual(case["oracle_profile_id"], "resource.fd_lifecycle.user_posix")
        self.assertIn(
            "MAGUS_ORACLE_RAN profile=resource.fd_lifecycle.user_posix",
            case["oracle"]["capability_patterns"],
        )

    def test_explicit_hypothesis_verification_context_is_preserved(self):
        hyp = {
            "project_id": "repo_source_api_exec",
            "sample_id": "s1",
            "hypothesis_id": "h1",
            "route": "parse_request -> ASN1_OCTET_STRING_new -> dereference",
            "file": "src/crypto/example.c",
            "claim": "returned pointer is dereferenced before null check",
            "evidence_slice": "obj = ASN1_OCTET_STRING_new(); return obj->length;",
            "verification_context": {
                "repo_path": "01_demo_test/mock_source_project",
                "run_cmd": "${PYTHON} poc.py",
                "oracle": {
                    "failure_patterns": ["AddressSanitizer", "null pointer"],
                    "expect_nonzero_exit": True,
                },
            },
        }

        case = target_gen.make_source_api_case(hyp, auto_fill=True)

        self.assertEqual(
            case["verification_context"]["repo_path"],
            "01_demo_test/mock_source_project",
        )
        self.assertEqual(case["verification_context"]["run_cmd"], "${PYTHON} poc.py")
        self.assertEqual(case["oracle"]["failure_patterns"], ["AddressSanitizer", "null pointer"])
        self.assertTrue(case["oracle"]["expect_nonzero_exit"])
        self.assertNotIn("MAGUS_ROUTE_EXECUTED", case["oracle"].get("required_patterns", []))


if __name__ == "__main__":
    unittest.main()