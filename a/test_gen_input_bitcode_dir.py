#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


def load_gen_input():
    module_path = Path(__file__).resolve().parent / "cmd" / "gen_input.py"
    spec = importlib.util.spec_from_file_location("stage_a_gen_input_for_bitcode_tests", module_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


gen_input = load_gen_input()


class GenInputBitcodeDirectoryTests(unittest.TestCase):
    def test_default_bitcode_directory_is_project_scoped(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            repo = Path(temp_dir) / "repo"
            repo.mkdir()
            source = repo / "src.c"
            source.write_text("int main(void) { return 0; }\n", encoding="utf-8")
            compile_commands = repo / "compile_commands.json"
            compile_commands.write_text(
                json.dumps(
                    [
                        {
                            "directory": str(repo),
                            "command": f"clang -c {source}",
                            "file": str(source),
                        }
                    ]
                ),
                encoding="utf-8",
            )
            args = argparse.Namespace(
                bc_dir="",
                project_id="demo",
                language="c",
                framework="generic",
                default_branch="",
                analyzer_jobs=2,
                analysis_timeout=1800,
                clang="clang",
                clangxx="clang++",
                source_glob=[],
            )

            record = gen_input.build_project_record(args, repo, compile_commands, repo / "input.jsonl")

            self.assertEqual(record["extensions"]["bitcode_globs"], ["bc.demo/**/*.bc"])
            self.assertIn("/bc.demo/", record["extensions"]["build_cmd"])


if __name__ == "__main__":
    unittest.main()
