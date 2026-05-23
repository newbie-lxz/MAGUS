#!/usr/bin/env python3
"""
Reusable Stage D oracle profiles.

Profiles are selected from hypothesis semantics: APIs, routes, evidence text,
and claim wording. CWE identifiers are optional tie-breakers, not required
inputs.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Tuple


def as_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        return " ".join(as_text(item) for item in value)
    if isinstance(value, dict):
        return " ".join(f"{key} {as_text(item)}" for key, item in value.items())
    return str(value)


def hypothesis_text(hypothesis: Dict[str, Any]) -> str:
    parts = [
        hypothesis.get("route"),
        hypothesis.get("file"),
        hypothesis.get("claim"),
        hypothesis.get("preconditions"),
        hypothesis.get("attack_path"),
        hypothesis.get("api_sequence"),
        hypothesis.get("evidence_slice"),
        hypothesis.get("cwe_candidates") or hypothesis.get("CWE_candidates") or hypothesis.get("cwe_list"),
    ]
    return as_text(parts)


@dataclass(frozen=True)
class OracleProfile:
    profile_id: str
    description: str
    api_markers: Dict[str, Tuple[str, ...]]
    keywords: Tuple[str, ...] = ()
    cwe_tokens: Tuple[str, ...] = ()
    accepted_evidence: Tuple[str, ...] = ()
    generic_markers: Tuple[str, ...] = ()

    @property
    def api_names(self) -> Tuple[str, ...]:
        return tuple(self.api_markers.keys())


PROFILES: Tuple[OracleProfile, ...] = (
    OracleProfile(
        profile_id="process.untrusted_library_load",
        description="Untrusted or relative path reaches dynamic library loading.",
        cwe_tokens=("cwe-114", "cwe114"),
        keywords=("loadlibrary", "library load", "dll", "relative_library_path", "process control"),
        api_markers={
            "LoadLibraryA": (
                "MAGUS_ORACLE_FLAW name=LoadLibraryA reason=relative_library_path",
                "MAGUS_ORACLE_SINK name=LoadLibraryA tainted=1",
            ),
            "LoadLibraryW": (
                "MAGUS_ORACLE_FLAW name=LoadLibraryW reason=relative_library_path",
                "MAGUS_ORACLE_SINK name=LoadLibraryW tainted=1",
            ),
        },
        accepted_evidence=(
            "route-bound dynamic library load used an attacker-controlled or relative path",
        ),
    ),
    OracleProfile(
        profile_id="process.command_execution",
        description="Attacker-controlled data reaches process or shell execution.",
        cwe_tokens=("cwe-78", "cwe78"),
        keywords=("command injection", "shell", "process execution", "execute command", "os command"),
        api_markers={
            "system": ("MAGUS_ORACLE_SINK name=system tainted=1",),
            "_wsystem": ("MAGUS_ORACLE_SINK name=_wsystem tainted=1",),
            "popen": ("MAGUS_ORACLE_SINK name=popen tainted=1",),
            "_spawnl": ("MAGUS_ORACLE_SINK name=_spawnl tainted=1",),
            "_spawnlp": ("MAGUS_ORACLE_SINK name=_spawnlp tainted=1",),
            "_spawnv": ("MAGUS_ORACLE_SINK name=_spawnv tainted=1",),
            "_spawnvp": ("MAGUS_ORACLE_SINK name=_spawnvp tainted=1",),
            "_execl": ("MAGUS_ORACLE_SINK name=_execl tainted=1",),
            "_execlp": ("MAGUS_ORACLE_SINK name=_execlp tainted=1",),
            "_execv": ("MAGUS_ORACLE_SINK name=_execv tainted=1",),
            "_execvp": ("MAGUS_ORACLE_SINK name=_execvp tainted=1",),
            "CreateProcessA": ("MAGUS_ORACLE_SINK name=CreateProcessA tainted=1",),
            "CreateProcessW": ("MAGUS_ORACLE_SINK name=CreateProcessW tainted=1",),
        },
        accepted_evidence=("route-bound process execution consumed attacker-controlled command text",),
    ),
    OracleProfile(
        profile_id="ldap.injection",
        description="Attacker-controlled LDAP filter reaches search API.",
        cwe_tokens=("cwe-90", "cwe90"),
        keywords=("ldap injection", "ldap_search", "ldap filter"),
        api_markers={
            "ldap_search_ext_sA": ("MAGUS_ORACLE_SINK name=ldap_search_ext_sA tainted=1",),
            "ldap_search_ext_sW": ("MAGUS_ORACLE_SINK name=ldap_search_ext_sW tainted=1",),
            "ldap_search_sA": ("MAGUS_ORACLE_SINK name=ldap_search_sA tainted=1",),
            "ldap_search_sW": ("MAGUS_ORACLE_SINK name=ldap_search_sW tainted=1",),
        },
        accepted_evidence=("route-bound LDAP search used attacker-controlled filter text",),
    ),
    OracleProfile(
        profile_id="config.external_control",
        description="External input controls security-sensitive configuration API.",
        cwe_tokens=("cwe-15", "cwe15"),
        keywords=("external control", "configuration setting", "computer name", "registry"),
        api_markers={
            "SetComputerNameA": ("MAGUS_ORACLE_SINK name=SetComputerNameA tainted=1",),
            "SetComputerNameW": ("MAGUS_ORACLE_SINK name=SetComputerNameW tainted=1",),
            "RegSetValueExA": ("MAGUS_ORACLE_SINK name=RegSetValueExA tainted=1",),
            "RegSetValueExW": ("MAGUS_ORACLE_SINK name=RegSetValueExW tainted=1",),
        },
        accepted_evidence=("route-bound configuration API consumed attacker-controlled data",),
    ),
    OracleProfile(
        profile_id="crypto.broken_algorithm",
        description="Cryptographic API selected a broken primitive or mode.",
        cwe_tokens=("cwe-327", "cwe327", "cwe-328", "cwe328", "cwe-780", "cwe780"),
        keywords=(
            "broken crypto",
            "broken cipher",
            "broken hash",
            "weak hash",
            "rsa without oaep",
            "des",
            "3des",
            "rc5",
            "md5",
            "sha1",
            "sha-1",
        ),
        api_markers={
            "CryptCreateHash": ("MAGUS_ORACLE_FLAW name=CryptCreateHash reason=broken_hash_algorithm",),
            "CryptDeriveKey": ("MAGUS_ORACLE_FLAW name=CryptDeriveKey reason=broken_cipher_algorithm",),
            "CryptEncrypt": ("MAGUS_ORACLE_FLAW name=CryptEncrypt reason=rsa_without_oaep",),
        },
        accepted_evidence=("route-bound crypto API selected a broken algorithm or missing padding mode",),
    ),
    OracleProfile(
        profile_id="crypto.missing_required_step",
        description="Cryptographic operation skipped a required setup step.",
        cwe_tokens=("cwe-325", "cwe325"),
        keywords=("missing required cryptographic step", "missing required step", "without create hash"),
        api_markers={
            "CryptHashData": ("MAGUS_ORACLE_FLAW name=CryptHashData reason=hash_used_without_create_hash",),
        },
        accepted_evidence=("route-bound cryptographic API was used before the required setup step",),
    ),
    OracleProfile(
        profile_id="crypto.weak_prng",
        description="Security-sensitive code used a predictable PRNG.",
        cwe_tokens=("cwe-338", "cwe338"),
        keywords=("weak prng", "predictable random", "rand(", "cryptographically weak"),
        api_markers={
            "rand": ("MAGUS_ORACLE_FLAW name=rand reason=cryptographically_weak_prng",),
        },
        accepted_evidence=("route-bound random generation used a predictable PRNG",),
    ),
    OracleProfile(
        profile_id="tempfile.insecure_name",
        description="Temporary file name was created before exclusive open or creation.",
        cwe_tokens=("cwe-377", "cwe377"),
        keywords=("insecure temporary file", "temporary_name_created_before_open", "tmpnam", "mktemp", "tempnam"),
        api_markers={
            "mktemp": ("MAGUS_ORACLE_FLAW name=mktemp reason=temporary_name_created_before_open",),
            "tempnam": ("MAGUS_ORACLE_FLAW name=tempnam reason=temporary_name_created_before_open",),
            "tmpnam": ("MAGUS_ORACLE_FLAW name=tmpnam reason=temporary_name_created_before_open",),
            "_wmktemp": ("MAGUS_ORACLE_FLAW name=_wmktemp reason=temporary_name_created_before_open",),
            "_wtmpnam": ("MAGUS_ORACLE_FLAW name=_wtmpnam reason=temporary_name_created_before_open",),
            "_wtempnam": ("MAGUS_ORACLE_FLAW name=_wtempnam reason=temporary_name_created_before_open",),
            "GetTempFileNameA": ("MAGUS_ORACLE_FLAW name=GetTempFileNameA reason=uUnique_zero_creates_then_closes_file",),
            "GetTempFileNameW": ("MAGUS_ORACLE_FLAW name=GetTempFileNameW reason=uUnique_zero_creates_then_closes_file",),
        },
        accepted_evidence=("route-bound temporary-file primitive exposed a predictable or pre-created name",),
    ),
    OracleProfile(
        profile_id="path.fixed_buffer_append",
        description="Path append API requires a MAX_PATH-sized destination buffer.",
        cwe_tokens=("cwe-785", "cwe785"),
        keywords=("path manipulation", "pathappend", "without max sized buffer", "max_path"),
        api_markers={
            "PathAppendA": ("MAGUS_ORACLE_FLAW name=PathAppendA reason=pathappend_requires_max_path_sized_buffer",),
            "PathAppendW": ("MAGUS_ORACLE_FLAW name=PathAppendW reason=pathappend_requires_max_path_sized_buffer",),
        },
        accepted_evidence=("route-bound PathAppend call used the fixed-buffer API contract",),
    ),
    OracleProfile(
        profile_id="dns.security_decision",
        description="Reverse DNS lookup influences a security decision.",
        cwe_tokens=("cwe-247", "cwe247"),
        keywords=("dns lookup", "security decision", "reverse dns", "gethostbyaddr"),
        api_markers={
            "gethostbyaddr": ("MAGUS_ORACLE_FLAW name=gethostbyaddr reason=reverse_dns_used_for_security_decision",),
        },
        accepted_evidence=("route-bound reverse DNS lookup was used in the decision path",),
    ),
    OracleProfile(
        profile_id="return_value.unchecked_failure",
        description="Failure return from an API was not handled before use.",
        cwe_tokens=("cwe-252", "cwe252", "cwe-253", "cwe253", "cwe-273", "cwe273", "cwe-690", "cwe690"),
        keywords=("unchecked return", "incorrect check", "dropped privileges", "null deref", "forced_null_return"),
        api_markers={
            "CreateMutexA": ("MAGUS_ORACLE_FLAW name=CreateMutexA reason=forced_null_return_for_return_value_check",),
            "CreateMutexW": ("MAGUS_ORACLE_FLAW name=CreateMutexW reason=forced_null_return_for_return_value_check",),
            "CreateNamedPipeA": ("MAGUS_ORACLE_FLAW name=CreateNamedPipeA reason=forced_invalid_handle_for_return_value_check",),
            "CreateNamedPipeW": ("MAGUS_ORACLE_FLAW name=CreateNamedPipeW reason=forced_invalid_handle_for_return_value_check",),
            "ConnectNamedPipe": ("MAGUS_ORACLE_FLAW name=ConnectNamedPipe reason=invalid_or_failed_handle_used",),
            "ImpersonateNamedPipeClient": (
                "MAGUS_ORACLE_FLAW name=RevertToSelf reason=called_after_failed_impersonation",
            ),
            "RpcImpersonateClient": (
                "MAGUS_ORACLE_FLAW name=RpcImpersonateClient reason=forced_non_ok_return_not_propagated",
            ),
            "_wfopen": ("MAGUS_ORACLE_FLAW name=_wfopen reason=forced_null_return_for_null_deref_check",),
            "fclose": ("MAGUS_ORACLE_FLAW name=fclose reason=null_file_pointer_used",),
        },
        accepted_evidence=("route-bound API failure was forced and later used without a valid check",),
    ),
    OracleProfile(
        profile_id="resource.handle_lifecycle",
        description="Handle or resource lifecycle is invalid, duplicated, or missing release.",
        cwe_tokens=("cwe-404", "cwe404", "cwe-672", "cwe672", "cwe-675", "cwe675", "cwe-773", "cwe773", "cwe-775", "cwe775"),
        keywords=("resource shutdown", "after expiration", "duplicate operations", "missing release", "handle leak"),
        api_markers={
            "CloseHandle": (
                "MAGUS_ORACLE_FLAW name=CloseHandle reason=invalid_or_failed_handle_used",
                "MAGUS_ORACLE_FLAW name=CloseHandle reason=duplicate_close",
                "MAGUS_ORACLE_FLAW name=CloseHandle reason=unrecognized_handle_or_wrong_close_api",
            ),
            "CreateFile": ("MAGUS_ORACLE_FLAW name=CreateFile reason=missing_closehandle",),
            "FreeLibrary": ("MAGUS_ORACLE_SINK name=FreeLibrary tainted=1",),
        },
        accepted_evidence=("route-bound resource lifecycle marker showed invalid or missing release behavior",),
    ),
    OracleProfile(
        profile_id="memory.sensitive_without_lock",
        description="Sensitive data was used without memory locking.",
        cwe_tokens=("cwe-591", "cwe591"),
        keywords=("sensitive data", "virtuallock", "locked memory", "improperly locked memory"),
        api_markers={
            "LogonUserA": ("MAGUS_ORACLE_FLAW name=LogonUserA reason=sensitive_password_not_virtually_locked",),
            "LogonUserW": ("MAGUS_ORACLE_FLAW name=LogonUserW reason=sensitive_password_not_virtually_locked",),
        },
        accepted_evidence=("route-bound credential API observed sensitive data without VirtualLock protection",),
    ),
    OracleProfile(
        profile_id="path.untrusted_search_path",
        description="Search path state or API uses attacker-influenced path resolution.",
        cwe_tokens=("cwe-426", "cwe426", "cwe-427", "cwe427"),
        keywords=(
            "untrusted search path",
            "uncontrolled search path",
            "search path",
            "searchpath",
            "path environment",
            "path=",
            "dll search directory",
            "setdll",
            "putenv",
        ),
        api_markers={
            "SearchPathA": (
                "MAGUS_ORACLE_FLAW name=SearchPathA reason=tainted_search_path_api",
                "MAGUS_ORACLE_SINK name=SearchPathA tainted=1",
            ),
            "SearchPathW": (
                "MAGUS_ORACLE_FLAW name=SearchPathW reason=tainted_search_path_api",
                "MAGUS_ORACLE_SINK name=SearchPathW tainted=1",
            ),
            "putenv": (
                "MAGUS_ORACLE_FLAW name=putenv reason=tainted_search_path_environment",
                "MAGUS_ORACLE_SINK name=putenv key=PATH tainted=1",
            ),
            "_putenv": (
                "MAGUS_ORACLE_FLAW name=_putenv reason=tainted_search_path_environment",
                "MAGUS_ORACLE_SINK name=_putenv key=PATH tainted=1",
            ),
            "_wputenv": (
                "MAGUS_ORACLE_FLAW name=_wputenv reason=tainted_search_path_environment",
                "MAGUS_ORACLE_SINK name=_wputenv key=PATH tainted=1",
            ),
            "SetEnvironmentVariableA": (
                "MAGUS_ORACLE_FLAW name=SetEnvironmentVariableA reason=tainted_search_path_environment",
                "MAGUS_ORACLE_SINK name=SetEnvironmentVariableA key=PATH tainted=1",
            ),
            "SetEnvironmentVariableW": (
                "MAGUS_ORACLE_FLAW name=SetEnvironmentVariableW reason=tainted_search_path_environment",
                "MAGUS_ORACLE_SINK name=SetEnvironmentVariableW key=PATH tainted=1",
            ),
            "SetDllDirectoryA": (
                "MAGUS_ORACLE_FLAW name=SetDllDirectoryA reason=tainted_dll_search_directory",
                "MAGUS_ORACLE_SINK name=SetDllDirectoryA tainted=1",
            ),
            "SetDllDirectoryW": (
                "MAGUS_ORACLE_FLAW name=SetDllDirectoryW reason=tainted_dll_search_directory",
                "MAGUS_ORACLE_SINK name=SetDllDirectoryW tainted=1",
            ),
            "AddDllDirectory": (
                "MAGUS_ORACLE_FLAW name=AddDllDirectory reason=tainted_dll_search_directory",
                "MAGUS_ORACLE_SINK name=AddDllDirectory tainted=1",
            ),
        },
        generic_markers=(
            "MAGUS_ORACLE_FLAW name=SearchPathA reason=tainted_search_path_api",
            "MAGUS_ORACLE_FLAW name=SearchPathW reason=tainted_search_path_api",
            "MAGUS_ORACLE_FLAW name=putenv reason=tainted_search_path_environment",
            "MAGUS_ORACLE_FLAW name=_putenv reason=tainted_search_path_environment",
            "MAGUS_ORACLE_FLAW name=_wputenv reason=tainted_search_path_environment",
            "MAGUS_ORACLE_FLAW name=SetEnvironmentVariableA reason=tainted_search_path_environment",
            "MAGUS_ORACLE_FLAW name=SetEnvironmentVariableW reason=tainted_search_path_environment",
            "MAGUS_ORACLE_FLAW name=SetDllDirectoryA reason=tainted_dll_search_directory",
            "MAGUS_ORACLE_FLAW name=SetDllDirectoryW reason=tainted_dll_search_directory",
            "MAGUS_ORACLE_FLAW name=AddDllDirectory reason=tainted_dll_search_directory",
        ),
        accepted_evidence=(
            "route-bound search path API or PATH update consumed attacker-controlled path text",
        ),
    ),
)


API_NAMES = tuple(sorted({api for profile in PROFILES for api in profile.api_names}, key=len, reverse=True))


def _token_words(value: str) -> List[str]:
    return re.findall(r"[a-z0-9]+", value.lower())


def _contains_token(haystack_lower: str, token: str) -> bool:
    token_words = _token_words(token)
    if not token_words:
        return False
    haystack_words = _token_words(haystack_lower)
    width = len(token_words)
    return any(haystack_words[index : index + width] == token_words for index in range(len(haystack_words) - width + 1))


def infer_api_names(hypothesis: Dict[str, Any]) -> List[str]:
    haystack_lower = hypothesis_text(hypothesis).lower()
    found = [api for api in API_NAMES if _contains_token(haystack_lower, api)]
    return sorted(set(found), key=lambda item: API_NAMES.index(item))


def _score_profile(profile: OracleProfile, haystack_lower: str, api_names: Iterable[str]) -> int:
    score = 0
    api_set = set(api_names)
    score += 6 * sum(1 for api in profile.api_names if api in api_set)
    score += 3 * sum(1 for keyword in profile.keywords if _contains_token(haystack_lower, keyword))
    score += 8 * sum(1 for cwe in profile.cwe_tokens if _contains_token(haystack_lower, cwe))
    return score


def select_profile(hypothesis: Dict[str, Any]) -> Tuple[OracleProfile | None, List[str], int]:
    haystack_lower = hypothesis_text(hypothesis).lower()
    api_names = infer_api_names(hypothesis)
    best: Tuple[OracleProfile | None, int] = (None, 0)
    for profile in PROFILES:
        score = _score_profile(profile, haystack_lower, api_names)
        if score > best[1]:
            best = (profile, score)
    profile = best[0]
    if profile is None or best[1] <= 0:
        return None, api_names, 0
    matched = [api for api in api_names if api in profile.api_markers]
    if not matched and not profile.generic_markers:
        return None, api_names, best[1]
    return profile, matched, best[1]


def _confirm_patterns(profile: OracleProfile, matched_apis: List[str]) -> List[str]:
    patterns: List[str] = list(profile.generic_markers)
    if matched_apis:
        for api in matched_apis:
            patterns.extend(profile.api_markers.get(api, ()))
        return sorted(set(patterns))

    return sorted(set(patterns))


def build_oracle_profile(hypothesis: Dict[str, Any]) -> Dict[str, Any]:
    profile, matched_apis, score = select_profile(hypothesis)
    inferred_apis = infer_api_names(hypothesis)
    if profile is None:
        return {
            "profile_id": "unsupported.unclassified_source_api",
            "supported": False,
            "selection_score": score,
            "matched_apis": [],
            "inferred_apis": inferred_apis,
            "confirm_patterns": [],
            "accepted_evidence": [
                "route execution can be observed, but Stage D has no semantic oracle profile for this hypothesis",
            ],
        }

    return {
        "profile_id": profile.profile_id,
        "supported": True,
        "selection_score": score,
        "description": profile.description,
        "matched_apis": matched_apis,
        "inferred_apis": inferred_apis,
        "confirm_patterns": _confirm_patterns(profile, matched_apis),
        "accepted_evidence": list(profile.accepted_evidence),
    }


def compact_profile_for_json(profile: Dict[str, Any]) -> Dict[str, Any]:
    return json.loads(json.dumps(profile, ensure_ascii=False))
