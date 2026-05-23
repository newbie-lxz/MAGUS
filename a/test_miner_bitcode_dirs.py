#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


def load_miner():
    module_path = Path(__file__).resolve().parent / "cmd" / "miner.py"
    spec = importlib.util.spec_from_file_location("stage_a_miner_for_bitcode_tests", module_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


miner = load_miner()


def project(repo_path: Path, *, bitcode_globs=None):
    extensions = {
        "analysis_backend": "llvm_api_dfa",
        "build_cmd": "true",
        "analyzer_jobs": 2,
    }
    if bitcode_globs is not None:
        extensions["bitcode_globs"] = bitcode_globs
    return miner.ProjectInput(
        project_id="sample",
        repo_path=str(repo_path),
        language="c",
        framework="generic",
        extensions=extensions,
    )


class BitcodeDirectoryContractTests(unittest.TestCase):
    def test_build_based_project_requires_explicit_bitcode_globs(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            record = project(Path(temp_dir))

            with self.assertRaisesRegex(ValueError, "missing extensions.bitcode_globs"):
                record.validate()

    def test_bitcode_globs_need_concrete_output_directory(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            record = project(Path(temp_dir), bitcode_globs=["**/*.bc"])

            with self.assertRaisesRegex(ValueError, "concrete output directory"):
                record.validate()

    def test_prepare_bitcode_output_dirs_removes_stale_generated_tree_only(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            repo = Path(temp_dir)
            stale = repo / "bc.sample" / "old.bc"
            stale.parent.mkdir(parents=True)
            stale.write_bytes(b"stale")
            sibling = repo / "bc.other" / "keep.bc"
            sibling.parent.mkdir(parents=True)
            sibling.write_bytes(b"keep")
            record = project(repo, bitcode_globs=["bc.sample/**/*.bc"])
            run_manifest = {}

            record.validate()
            miner.prepare_bitcode_output_dirs(record, run_manifest)

            self.assertFalse((repo / "bc.sample").exists())
            self.assertTrue(sibling.exists())
            self.assertEqual(run_manifest["bitcode_prepare"]["cleaned_dirs"], ["bc.sample"])


if __name__ == "__main__":
    unittest.main()
