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


if __name__ == "__main__":
    unittest.main()
