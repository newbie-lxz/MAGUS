import unittest

import oracle_profiles


class OracleProfileSelectionTests(unittest.TestCase):
    def test_selects_library_load_without_cwe(self):
        profile = oracle_profiles.build_oracle_profile(
            {
                "route": "parse_config -> LoadLibraryA",
                "claim": "user controlled relative DLL path reaches dynamic library loading",
                "evidence_slice": "LoadLibraryA(dllName);",
            }
        )

        self.assertEqual(profile["profile_id"], "process.untrusted_library_load")
        self.assertTrue(profile["supported"])
        self.assertIn("LoadLibraryA", profile["matched_apis"])
        self.assertIn("MAGUS_ORACLE_FLAW name=LoadLibraryA reason=relative_library_path", profile["confirm_patterns"])

    def test_selects_command_execution_without_cwe(self):
        profile = oracle_profiles.build_oracle_profile(
            {
                "route": "handle_request -> system",
                "claim": "external input can reach shell command execution",
                "evidence_slice": "system(user_command);",
            }
        )

        self.assertEqual(profile["profile_id"], "process.command_execution")
        self.assertTrue(profile["supported"])
        self.assertIn("MAGUS_ORACLE_SINK name=system tainted=1", profile["confirm_patterns"])

    def test_selects_path_environment_update_without_cwe(self):
        profile = oracle_profiles.build_oracle_profile(
            {
                "route": "read_config -> _putenv",
                "claim": "user controlled data updates the PATH search path environment",
                "evidence_slice": '_putenv(path_value); /* path_value begins with "PATH=" */',
            }
        )

        self.assertEqual(profile["profile_id"], "path.untrusted_search_path")
        self.assertTrue(profile["supported"])
        self.assertIn("_putenv", profile["matched_apis"])
        self.assertIn(
            "MAGUS_ORACLE_FLAW name=_putenv reason=tainted_search_path_environment",
            profile["confirm_patterns"],
        )

    def test_selects_set_environment_variable_path_update(self):
        profile = oracle_profiles.build_oracle_profile(
            {
                "route": "apply_setting -> SetEnvironmentVariableA",
                "claim": "attacker controlled path text is assigned to PATH",
                "evidence_slice": 'SetEnvironmentVariableA("PATH", user_path);',
            }
        )

        self.assertEqual(profile["profile_id"], "path.untrusted_search_path")
        self.assertTrue(profile["supported"])
        self.assertIn("SetEnvironmentVariableA", profile["matched_apis"])
        self.assertIn(
            "MAGUS_ORACLE_FLAW name=SetEnvironmentVariableA reason=tainted_search_path_environment",
            profile["confirm_patterns"],
        )

    def test_selects_search_path_api_without_cwe(self):
        profile = oracle_profiles.build_oracle_profile(
            {
                "route": "resolve_tool -> SearchPathW",
                "claim": "attacker controlled directory participates in search path resolution",
                "evidence_slice": "SearchPathW(user_path, tool_name, NULL, cap, out, &part);",
            }
        )

        self.assertEqual(profile["profile_id"], "path.untrusted_search_path")
        self.assertTrue(profile["supported"])
        self.assertIn("SearchPathW", profile["matched_apis"])
        self.assertIn(
            "MAGUS_ORACLE_FLAW name=SearchPathW reason=tainted_search_path_api",
            profile["confirm_patterns"],
        )

    def test_selects_dll_search_directory_api_without_cwe(self):
        profile = oracle_profiles.build_oracle_profile(
            {
                "route": "load_plugin -> SetDllDirectoryW",
                "claim": "user supplied plugin directory changes the DLL search directory",
                "evidence_slice": "SetDllDirectoryW(plugin_dir);",
            }
        )

        self.assertEqual(profile["profile_id"], "path.untrusted_search_path")
        self.assertTrue(profile["supported"])
        self.assertIn("SetDllDirectoryW", profile["matched_apis"])
        self.assertIn(
            "MAGUS_ORACLE_FLAW name=SetDllDirectoryW reason=tainted_dll_search_directory",
            profile["confirm_patterns"],
        )

    def test_search_path_profile_has_generic_runtime_markers(self):
        profile = oracle_profiles.build_oracle_profile(
            {
                "route": "case route without expanded sink wrapper",
                "claim": "uncontrolled search path element can be reached from external input",
                "cwe_candidates": ["CWE-427"],
                "evidence_slice": "data flows through a wrapper before the sink call",
            }
        )

        self.assertEqual(profile["profile_id"], "path.untrusted_search_path")
        self.assertTrue(profile["supported"])
        self.assertEqual(profile["matched_apis"], [])
        self.assertIn(
            "MAGUS_ORACLE_FLAW name=_putenv reason=tainted_search_path_environment",
            profile["confirm_patterns"],
        )

    def test_search_path_profile_keeps_runtime_equivalents_when_api_is_matched(self):
        profile = oracle_profiles.build_oracle_profile(
            {
                "route": "entry -> PUTENV",
                "claim": "CWE-427 uncontrolled search path element through PATH",
                "evidence_slice": "PUTENV(data);",
            }
        )

        self.assertEqual(profile["profile_id"], "path.untrusted_search_path")
        self.assertTrue(profile["supported"])
        self.assertIn("putenv", profile["matched_apis"])
        self.assertIn(
            "MAGUS_ORACLE_FLAW name=putenv reason=tainted_search_path_environment",
            profile["confirm_patterns"],
        )
        self.assertIn(
            "MAGUS_ORACLE_FLAW name=_wputenv reason=tainted_search_path_environment",
            profile["confirm_patterns"],
        )

    def test_unclassified_profile_is_explicitly_unsupported(self):
        profile = oracle_profiles.build_oracle_profile(
            {
                "route": "parse -> custom_wrapper",
                "claim": "unknown source/API misuse pattern",
                "evidence_slice": "custom_wrapper(x);",
            }
        )

        self.assertEqual(profile["profile_id"], "unsupported.unclassified_source_api")
        self.assertFalse(profile["supported"])
        self.assertEqual(profile["confirm_patterns"], [])

    def test_cwe_disambiguates_multi_semantic_api_families(self):
        profile = oracle_profiles.build_oracle_profile(
            {
                "route": "crypto_flow -> CryptHashData",
                "claim": "CryptoAPI operation misses a required cryptographic step",
                "cwe_candidates": ["CWE-325"],
                "evidence_slice": "CryptHashData(hHash, data, data_len, 0) without CryptCreateHash first;",
            }
        )

        self.assertEqual(profile["profile_id"], "crypto.missing_required_step")
        self.assertTrue(profile["supported"])
        self.assertEqual(profile["matched_apis"], ["CryptHashData"])

    def test_does_not_infer_api_from_substring(self):
        profile = oracle_profiles.build_oracle_profile(
            {
                "route": "filesystem_policy_check",
                "claim": "unsupported filesystem policy behavior",
                "evidence_slice": "filesystem state controls behavior",
            }
        )

        self.assertEqual(profile["profile_id"], "unsupported.unclassified_source_api")
        self.assertFalse(profile["supported"])
        self.assertNotIn("system", profile["inferred_apis"])

    def test_cwe_tokens_match_exactly(self):
        profile = oracle_profiles.build_oracle_profile(
            {
                "route": "crypto_flow -> CryptEncrypt",
                "claim": "RSA operation without OAEP",
                "cwe_candidates": ["CWE-780"],
                "evidence_slice": "CryptEncrypt(hKey, 0, TRUE, 0, data, &len, cap);",
            }
        )

        self.assertEqual(profile["profile_id"], "crypto.broken_algorithm")
        self.assertTrue(profile["supported"])

    def test_cwe325_unsupported_subtype_is_preserved(self):
        profile = oracle_profiles.build_oracle_profile(
            {
                "route": "crypto_flow -> CryptDeriveKey",
                "claim": "CryptoAPI operation misses a required cryptographic step",
                "cwe_candidates": ["CWE-325"],
                "evidence_slice": "CryptDeriveKey(hCryptProv, CALG_AES_256, hHash, 0, &hKey);",
            }
        )

        self.assertEqual(profile["profile_id"], "unsupported.unclassified_source_api")
        self.assertFalse(profile["supported"])
        self.assertEqual(profile["matched_apis"], [])
        self.assertIn("CryptDeriveKey", profile["inferred_apis"])

    def test_selects_rpc_impersonation_without_cwe(self):
        profile = oracle_profiles.build_oracle_profile(
            {
                "route": "rpc_server -> RpcImpersonateClient",
                "claim": "RpcImpersonateClient failure return is not checked before continuing",
                "evidence_slice": "RpcImpersonateClient(0);",
            }
        )

        self.assertEqual(profile["profile_id"], "return_value.unchecked_failure")
        self.assertTrue(profile["supported"])
        self.assertIn("RpcImpersonateClient", profile["matched_apis"])
        self.assertIn(
            "MAGUS_ORACLE_FLAW name=RpcImpersonateClient reason=forced_non_ok_return_not_propagated",
            profile["confirm_patterns"],
        )

    def test_named_pipe_impersonation_requires_post_failure_use(self):
        profile = oracle_profiles.build_oracle_profile(
            {
                "route": "pipe_server -> ImpersonateNamedPipeClient",
                "claim": "ImpersonateNamedPipeClient failure is ignored",
                "evidence_slice": "ImpersonateNamedPipeClient(hPipe); RevertToSelf();",
            }
        )

        self.assertEqual(profile["profile_id"], "return_value.unchecked_failure")
        self.assertIn(
            "MAGUS_ORACLE_FLAW name=RevertToSelf reason=called_after_failed_impersonation",
            profile["confirm_patterns"],
        )
        self.assertNotIn(
            "MAGUS_ORACLE_FLAW name=ImpersonateNamedPipeClient reason=forced_false_return_for_privilege_drop_check",
            profile["confirm_patterns"],
        )

    def test_profile_markers_are_project_agnostic(self):
        for profile in oracle_profiles.PROFILES:
            for marker_group in profile.api_markers.values():
                for marker in marker_group:
                    self.assertNotIn("JULIET", marker.upper())


if __name__ == "__main__":
    unittest.main()
