#!/usr/bin/env python3
import json
import argparse
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

import pipeline  # noqa: E402
import evaluate_juliet_report  # noqa: E402


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text(
        "".join(json.dumps(row, separators=(",", ":")) + "\n" for row in rows),
        encoding="utf-8",
    )


class ReportRunNameTests(unittest.TestCase):
    def test_stage_d_output_prefers_unique_juliet_cwe_source_folder(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            out_dir = Path(temp_dir)
            write_jsonl(
                out_dir / "verification.jsonl",
                [
                    {
                        "project_id": "cwe15",
                        "file": (
                            "juliet-api-misuse/testcases/"
                            "CWE15_External_Control_of_System_or_Configuration_Setting/case.c"
                        ),
                    }
                ],
            )
            write_jsonl(out_dir / "verification.failed.jsonl", [])

            self.assertEqual(
                pipeline.report_run_name_from_stage_d_output(out_dir),
                "CWE15_External_Control_of_System_or_Configuration_Setting",
            )

    def test_stage_d_output_uses_normalized_project_id_without_cwe_folder(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            out_dir = Path(temp_dir)
            write_jsonl(out_dir / "verification.jsonl", [])
            write_jsonl(out_dir / "verification.failed.jsonl", [{"project_id": "cwe15", "file": "src/example.c"}])

            self.assertEqual(pipeline.report_run_name_from_stage_d_output(out_dir), "CWE15")

    def test_juliet_eval_output_defaults_under_run_name(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            out_root = Path(temp_dir) / "juliet_eval"
            args = argparse.Namespace(out_dir=None, out_root=out_root)

            self.assertEqual(
                evaluate_juliet_report.resolve_output_dir(args, "CWE15"),
                out_root / "CWE15",
            )

    def test_juliet_eval_maps_sanitized_report_paths_to_original_truth(self):
        original_rel = (
            "testcases/CWE15_Example/"
            "CWE15_Example__w32_01_bad.c"
        )
        sanitized_rel = (
            "testcases/CWE15_Example/"
            "CWE15_Example__w32_01_case0.c"
        )
        truth = {
            "CWE-15/CWE15_Example__w32_01": evaluate_juliet_report.TruthItem(
                key="CWE-15/CWE15_Example__w32_01",
                is_vulnerable=True,
                cwe="CWE-15",
                files={original_rel},
            )
        }
        sanitization = evaluate_juliet_report.SanitizationMap(
            reverse_path_map={sanitized_rel: original_rel},
            reverse_token_map={"case0": "bad", "Case0": "Bad", "CASE0": "BAD"},
        )
        findings = evaluate_juliet_report.classify_findings(
            [
                {
                    "file": "juliet-api-misuse/" + sanitized_rel,
                    "route": "juliet-api-misuse/" + sanitized_rel + "::CWE15_Example__w32_01_case0",
                }
            ],
            truth,
            Path("/original/srcs/juliet-api-misuse"),
            Path("/workspace"),
            sanitization,
        )

        self.assertEqual(findings[0].classification, "TP")
        self.assertEqual(findings[0].juliet_file, original_rel)
        self.assertEqual(findings[0].route_symbol, "CWE15_Example__w32_01_bad")


if __name__ == "__main__":
    unittest.main()
