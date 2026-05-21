#!/usr/bin/env python3
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import sanitize_juliet_tree


class JulietSanitizerTests(unittest.TestCase):
    def test_neutralizes_labels_without_mutating_non_label_words(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source_root = root / "srcs"
            output_root = root / "srcs_sanitized"
            source_file = (
                source_root
                / "juliet-api-misuse"
                / "testcases"
                / "CWE15_Example"
                / "CWE15_Example__w32_81_bad.cpp"
            )
            source_file.parent.mkdir(parents=True)
            source_file.write_text(
                "\n".join(
                    [
                        "/* FLAW: bad path */",
                        "#ifndef OMITBAD",
                        "#define PREFIX_VALUE 1",
                        "void CWE15_Example__w32_81_badSink() {}",
                        "#endif /* OMITBAD */",
                        "#ifndef OMITGOOD",
                        "void CWE15_Example__w32_81_goodG2BSource() {}",
                        "/* FIX: good path */",
                        "#endif /* OMITGOOD */",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            mapping = sanitize_juliet_tree.sanitize_tree(source_root, output_root, "map.json", force=False)
            sanitized_rel = mapping["path_map"][
                "juliet-api-misuse/testcases/CWE15_Example/CWE15_Example__w32_81_bad.cpp"
            ]
            sanitized_file = output_root / sanitized_rel
            text = sanitized_file.read_text(encoding="utf-8")

            self.assertTrue(sanitized_rel.endswith("CWE15_Example__w32_81_case0.cpp"))
            self.assertNotIn("FLAW", text)
            self.assertNotIn("/* FIX", text)
            self.assertNotIn("ISSUE", text)
            self.assertNotIn("bad", text)
            self.assertNotIn("good", text)
            self.assertNotIn("G2B", text)
            self.assertIn("OMITCASE0", text)
            self.assertIn("OMITCASE1", text)
            self.assertIn("PREFIX_VALUE", text)
            self.assertEqual(mapping["reverse_path_map"][sanitized_rel], source_file.relative_to(source_root).as_posix())

            persisted = json.loads((output_root / "map.json").read_text(encoding="utf-8"))
            self.assertEqual(persisted["schema"], sanitize_juliet_tree.SCHEMA)


if __name__ == "__main__":
    unittest.main()
