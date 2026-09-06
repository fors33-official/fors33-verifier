#!/usr/bin/env python3
"""
Verify attested data segment.

Standalone script for Fors33 Verifier. Supports:
- Remote: download from presigned URL (supports HTTP Range for segments)
- Local: hash entire file or specific byte ranges
- Record: verify using FORS33 attestation record JSON
- Sidecar: verify .f33 sidecar (SHA-256 + Ed25519) for attested file
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import sys
import threading
import unicodedata
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Literal, Optional, Sequence

try:  # Support both package and flat-module imports
    from .hash_core import (  # type: ignore[import]
        default_dpk_worker_count,
        hash_file,
        hash_file_algos,
        hash_stream,
        infer_algo_from_digest,
        is_epoch_upload_companion_basename,
        path_for_kernel,
    )
    from .manifest_core import (  # type: ignore[import]
        ManifestEntry,
        discover_bagit_layout,
        load_manifest,
        resolve_manifest_member_path,
        verify_manifest_hash_chain,
        _is_manifest_abs_path,
    )
except ImportError:  # pragma: no cover - flat layout
    from hash_core import (  # type: ignore[import]
        default_dpk_worker_count,
        hash_file,
        hash_file_algos,
        hash_stream,
        infer_algo_from_digest,
        is_epoch_upload_companion_basename,
        path_for_kernel,
    )
    from manifest_core import (  # type: ignore[import]
        ManifestEntry,
        discover_bagit_layout,
        load_manifest,
        resolve_manifest_member_path,
        verify_manifest_hash_chain,
        _is_manifest_abs_path,
    )

try:
    import urllib.request
except ImportError:
    urllib = None

_CTA = "[TOOLCHAIN] : Fors33 Verifier"
_ERR_INVALID_SEAL_FORMAT = "[ ERR_INVALID_SEAL_FORMAT ]"
_ERR_MISSING_SEAL = "[ ERR_MISSING_SEAL ]"
_ERR_MANIFEST_COMPROMISED = "[ ERR_MANIFEST_COMPROMISED: Root of trust invalid ]"
_ERR_BAD_SIGNATURE = "[ TAMPER DETECTED: BAD SIGNATURE ]"
_ERR_DATA_DRIFT = "[ SEAL BROKEN: DATA DRIFT ]"
_ERR_TSA_INVALID = "[ ERR_INVALID_TSA ]"
_ERR_SIG_ALG_UNSUPPORTED = "[ SIG_ALG_UNSUPPORTED ]"
_ERR_SIG_ALG_NOT_IMPLEMENTED = "[ SIG_ALG_NOT_IMPLEMENTED ]"
_ERR_SIG_X509_CHAIN_INVALID = "[ SIG_X509_CHAIN_INVALID ]"

_EXIT_OK = 0
EXIT_DRIFT = 1
EXIT_USAGE = 2
EXIT_SEVERE = 3

_COMPLIANCE_NOTICE_LINES = (
    "[NOTICE]  Fors33 Verifier",
    "[NOTICE]  Output describes integrity checks only; it is not legal advice.",
    "[NOTICE]  Full legal terms: https://fors33.com/legal",
    "[NOTICE]  Validate results in your own compliance and audit workflow.",
    "[NOTICE]  Unauthorized use is prohibited.",
)

# Thread-safe print lock for batch mode
print_lock = threading.Lock()


class VerifyCancelled(RuntimeError):
    """Operator cancelled an in-flight verify (cooperative stop)."""


def _check_verify_cancel(should_cancel: Callable[[], bool] | None) -> None:
    if should_cancel is not None and should_cancel():
        raise VerifyCancelled("Cancelled by operator")


@dataclass
class BatchVerificationResult:
    """Result of a single package verification in batch mode."""
    file_path: str
    package_type: str
    status: str  # "SUCCESS" or "ERROR"
    error_message: str | None = None


def _print_compliance_notice() -> None:
    """Print startup compliance lines to stderr before any CLI parsing."""
    for line in _COMPLIANCE_NOTICE_LINES:
        print(line, file=sys.stderr)


def resolve_manifest_worker_count(cli_workers: int | None) -> int:
    """
    Worker pool size: positive --workers wins; else positive FORS33_WORKERS;
    else default_dpk_worker_count() (FORS33_DPK_MAX_WORKERS applied inside that).
    Non-positive CLI or env values mean auto.
    """
    if cli_workers is not None and cli_workers > 0:
        return min(64, int(cli_workers))
    env_raw = os.environ.get("FORS33_WORKERS", "").strip()
    if env_raw:
        try:
            ev = int(env_raw, 10)
        except ValueError:
            raise ValueError("FORS33_WORKERS must be an integer") from None
        if ev > 0:
            return min(64, ev)
    return default_dpk_worker_count()


_DISALLOWED_BIDI = frozenset({"RLE", "LRE", "RLO", "LRO", "RLI", "LRI", "FSI", "PDF"})


def seal_utf8_normalize_and_validate(label: str, value: str, max_len: int = 512) -> str:
    """NFC-normalize and reject C0/C1 controls, unassigned code points, Cf format chars, and bidi embedding."""
    s = unicodedata.normalize("NFC", str(value))
    if len(s) > max_len:
        raise ValueError(f"{label} exceeds max length ({max_len})")
    for ch in s:
        o = ord(ch)
        if o < 0x20 or (0x7F <= o < 0xA0):
            raise ValueError(f"{label} contains disallowed control characters")
        cat = unicodedata.category(ch)
        if cat == "Cn":
            raise ValueError(f"{label} contains unassigned code points")
        if cat == "Cf":
            raise ValueError(f"{label} contains disallowed format characters")
        b = unicodedata.bidirectional(ch)
        if b in _DISALLOWED_BIDI:
            raise ValueError(f"{label} contains disallowed bidirectional control characters")
    return s


def sanitize_seal_metadata_value(value: object, max_len: int = 256) -> str | None:
    """Coerce seal metadata to a safe string; None when empty after sanitization."""
    s = str(value if value is not None else "").strip()
    if not s:
        return None
    out: list[str] = []
    for ch in s:
        if ch in '"\\':
            continue
        if ord(ch) < 32:
            continue
        out.append(ch)
        if len(out) >= max_len:
            break
    cleaned = "".join(out).strip()
    return cleaned or None


SIGNATURE_INTENT_VALUES = ("Authored", "Reviewed", "Approved")
REASON_FOR_CHANGE_MAX_LEN = 512
SIG_ALG_ED25519 = "ed25519"
SIG_ALG_X509_RSA_PSS_SHA256 = "x509-rsa-pss-sha256"
SIG_ALG_X509_ECDSA_P256_SHA256 = "x509-ecdsa-p256-sha256"
SIG_ALG_VALUES = (
    SIG_ALG_ED25519,
    SIG_ALG_X509_RSA_PSS_SHA256,
    SIG_ALG_X509_ECDSA_P256_SHA256,
)


def _validate_sig_alg(value: str | None) -> str:
    if value is None:
        return SIG_ALG_ED25519
    s = str(value).strip().lower()
    if not s:
        return SIG_ALG_ED25519
    for canonical in SIG_ALG_VALUES:
        if s == canonical.lower():
            return canonical
    raise ValueError(f"sig_alg must be one of {SIG_ALG_VALUES}; got {value!r}")


def _validate_signature_intent(value: str | None) -> str | None:
    """Validate FDA 21 CFR 11.50 signature intent; return canonical casing or None."""
    if value is None:
        return None
    s = str(value).strip()
    if not s:
        return None
    for canonical in SIGNATURE_INTENT_VALUES:
        if s.lower() == canonical.lower():
            return canonical
    raise ValueError(
        f"signature_intent must be one of {SIGNATURE_INTENT_VALUES}; got {value!r}"
    )


_SOURCE_FINGERPRINT_STRUCT_KEYS = (
    "tls_fingerprint_sha256",
    "tls_subject",
    "tls_subject_alt_names",
    "tls_issuer",
)


def canonical_source_fingerprint_string(struct: dict) -> str | None:
    """Deterministic compact JSON for canonical payload SOURCE_FINGERPRINT (V2)."""
    if not isinstance(struct, dict) or not struct:
        return None
    cleaned = {k: struct[k] for k in _SOURCE_FINGERPRINT_STRUCT_KEYS if k in struct}
    if not cleaned:
        return None
    return json.dumps(cleaned, sort_keys=True, separators=(",", ":"))


def source_fingerprint_from_predicate(predicate: dict) -> str | None:
    """Resolve the signed source_fingerprint string from a sidecar predicate."""
    raw = predicate.get("source_fingerprint")
    if isinstance(raw, str) and raw.strip():
        return raw.strip()
    struct = predicate.get("source_fingerprint_struct")
    if isinstance(struct, dict):
        return canonical_source_fingerprint_string(struct)
    return None


def build_canonical_payload(
    target_name: str,
    byte_start: int,
    byte_end: int,
    timestamp: str,
    file_hash: str,
    hash_algo: str = "sha256",
    *,
    payload_version: int = 2,
    operator_id: str | None = None,
    operator_key_id: str | None = None,
    authorized_operator: str | None = None,
    organization: str | None = None,
    source_fingerprint: str | None = None,
    signature_intent: str | None = None,
    reason_for_change: str | None = None,
    sig_alg: str | None = None,
) -> bytes:
    """Deterministic UTF-8 payload bytes for Ed25519 (V1 four lines or V2 with optional custody lines)."""
    if os.path.sep in target_name:
        raise ValueError("target_name must be a basename, not a path")
    if byte_start < 0 or byte_end <= byte_start:
        raise ValueError("byte_start/byte_end must define a non-empty, non-negative range")
    algo_l = (hash_algo or "sha256").lower()
    if algo_l == "sha512":
        if len(file_hash) != 128 or not all(c in "0123456789abcdef" for c in file_hash):
            raise ValueError("file_hash must be 128-char lowercase hex for sha512")
        line = f"SHA512:{file_hash}"
    else:
        if len(file_hash) != 64 or not all(c in "0123456789abcdef" for c in file_hash):
            raise ValueError("file_hash must be 64-char lowercase hex for sha256")
        line = f"SHA256:{file_hash}"

    if payload_version == 1:
        payload_str = (
            f"TARGET:{target_name}\n"
            f"RANGE:{byte_start}:{byte_end}\n"
            f"TIMESTAMP:{timestamp}\n"
            f"{line}"
        )
        return payload_str.encode("utf-8")

    tgt = seal_utf8_normalize_and_validate("TARGET", target_name, max_len=4096)
    ts = seal_utf8_normalize_and_validate("TIMESTAMP", timestamp, max_len=64)

    if payload_version != 2:
        raise ValueError(f"unsupported payload_version: {payload_version}")

    lines = [
        "PAYLOAD_VERSION:2",
        f"TARGET:{tgt}",
        f"RANGE:{byte_start}:{byte_end}",
        f"TIMESTAMP:{ts}",
        line,
    ]
    oid = sanitize_seal_metadata_value(operator_id)
    okid = sanitize_seal_metadata_value(operator_key_id)
    ao = sanitize_seal_metadata_value(authorized_operator)
    org = sanitize_seal_metadata_value(organization)
    if oid:
        lines.append(f"OPERATOR_ID:{seal_utf8_normalize_and_validate('OPERATOR_ID', oid)}")
    if okid:
        lines.append(f"OPERATOR_KEY_ID:{seal_utf8_normalize_and_validate('OPERATOR_KEY_ID', okid, max_len=256)}")
    if ao:
        lines.append(f"AUTHORIZED_OPERATOR:{seal_utf8_normalize_and_validate('AUTHORIZED_OPERATOR', ao)}")
    if org:
        lines.append(f"ORGANIZATION:{seal_utf8_normalize_and_validate('ORGANIZATION', org)}")
    if source_fingerprint:
        sf = seal_utf8_normalize_and_validate("SOURCE_FINGERPRINT", source_fingerprint)
        lines.append(f"SOURCE_FINGERPRINT:{sf}")
    intent = _validate_signature_intent(signature_intent)
    if intent:
        lines.append(f"SIGNATURE_INTENT:{intent}")
    if reason_for_change is not None:
        rfc = sanitize_seal_metadata_value(reason_for_change, max_len=REASON_FOR_CHANGE_MAX_LEN)
        if rfc:
            lines.append(
                "REASON_FOR_CHANGE:"
                + seal_utf8_normalize_and_validate(
                    "REASON_FOR_CHANGE", rfc, max_len=REASON_FOR_CHANGE_MAX_LEN
                )
            )
    sig_alg_canonical = _validate_sig_alg(sig_alg)
    if sig_alg_canonical != SIG_ALG_ED25519:
        lines.append(f"SIG_ALG:{sig_alg_canonical}")
    return "\n".join(lines).encode("utf-8")


def verify_manifest_hmac(manifest_path: str, pepper_bytes: bytes | None) -> tuple[bool, str]:
    """Verify ``fors33-manifest.hmac`` sidecar when present; legacy absent sidecar is OK."""
    import hmac as _hmac
    import hashlib as _hashlib

    sidecar = manifest_path + ".hmac"
    if not os.path.isfile(path_for_kernel(sidecar)):
        return True, "absent"
    try:
        with open(path_for_kernel(sidecar), "rb") as f:
            raw = f.read()
        rec = json.loads(raw.decode("utf-8"))
    except Exception as e:
        return False, f"manifest_hmac_failed:malformed:{e}"
    if not isinstance(rec, dict):
        return False, "manifest_hmac_failed:not_a_dict"
    expected_hex = str(rec.get("hmac_hex") or "").strip().lower()
    if not expected_hex:
        return False, "manifest_hmac_failed:missing_hmac_hex"
    if pepper_bytes is None:
        return False, "manifest_hmac_failed:no_pepper"
    try:
        with open(path_for_kernel(manifest_path), "rb") as mfp:
            manifest_bytes = mfp.read()
    except OSError as e:
        return False, f"manifest_hmac_failed:read_manifest:{e}"
    actual_hex = _hmac.new(pepper_bytes, manifest_bytes, _hashlib.sha256).hexdigest()
    if not _hmac.compare_digest(actual_hex, expected_hex):
        return False, "manifest_hmac_failed:mismatch"
    return True, "verified"


# --- lineage.json (derived-data provenance; schema v1.0, see docs if published) ---


def _normalize_manifest_entry_path(file_path: str, fallback_root_dir: str | None) -> str:
    """Match manifest_core path normalization for manifest entries."""
    p = str(file_path)
    if fallback_root_dir and os.path.isabs(p):
        try:
            return os.path.relpath(p, os.path.abspath(fallback_root_dir)).replace("\\", "/")
        except Exception:
            return p.replace("\\", "/")
    return p.replace("\\", "/")


def _iter_trusted_manifest_segments(manifest_path: str, fallback_root_dir: str) -> List[dict]:
    """Load fors33-manifest.json entries as trust rows for lineage cross-check."""
    rows: List[dict] = []
    try:
        with open(path_for_kernel(manifest_path), encoding="utf-8") as f:
            raw = json.load(f)
    except (OSError, json.JSONDecodeError):
        return rows
    if not isinstance(raw, dict):
        return rows
    entries = raw.get("entries")
    if not isinstance(entries, list):
        return rows
    root_abs = os.path.abspath(fallback_root_dir)
    for item in entries:
        if not isinstance(item, dict):
            continue
        fp = item.get("path")
        if not fp:
            continue
        dg = item.get("sha256") or item.get("sha512")
        if not dg:
            continue
        ha = str(item.get("hash_algo") or ("sha512" if item.get("sha512") else "sha256")).lower()
        if ha not in ("sha256", "sha512"):
            ha = "sha256"
        try:
            ri = int(item.get("root_index", 0) or 0)
        except (TypeError, ValueError):
            ri = 0
        try:
            bs_i = int(item.get("byte_start", 0) or 0)
            be_i = int(item.get("byte_end", 0) or 0)
        except (TypeError, ValueError):
            bs_i, be_i = 0, 0
        rows.append(
            {
                "path_norm": _normalize_manifest_entry_path(str(fp), root_abs),
                "digest": str(dg).lower().strip(),
                "algo": ha,
                "byte_start": bs_i,
                "byte_end": be_i,
                "root_index": ri,
            }
        )
    return rows


def _lineage_declared_path_norm(declared: str) -> str | None:
    s = declared.strip().replace("\\", "/")
    if not s or s.startswith("/"):
        return None
    parts = [p for p in s.split("/") if p]
    if any(p == ".." for p in parts):
        return None
    return "/".join(parts)


def _lineage_input_matches_trusted(trusted: Sequence[dict], inp: object) -> tuple[bool, str]:
    if not isinstance(inp, dict):
        return False, "input entry must be an object"
    path_norm = _lineage_declared_path_norm(str(inp.get("path") or ""))
    if path_norm is None:
        return False, "invalid or unsafe path"
    alg = str(inp.get("digest_alg") or "").lower().strip()
    if alg not in ("sha256", "sha512"):
        return False, "digest_alg must be sha256 or sha512"
    dg = str(inp.get("digest_hex") or "").lower().strip()
    if alg == "sha256":
        if len(dg) != 64 or any(c not in "0123456789abcdef" for c in dg):
            return False, "digest_hex must be 64 lowercase hex chars for sha256"
    elif len(dg) != 128 or any(c not in "0123456789abcdef" for c in dg):
        return False, "digest_hex must be 128 lowercase hex chars for sha512"

    bs_raw = inp.get("byte_start", None)
    be_raw = inp.get("byte_end", None)
    has_range = bs_raw is not None or be_raw is not None
    if has_range:
        if bs_raw is None or be_raw is None:
            return False, "byte_start and byte_end must both be set when either is present"
        try:
            bs_i = int(bs_raw)
            be_i = int(be_raw)
        except (TypeError, ValueError):
            return False, "byte_start and byte_end must be integers"
        if be_i <= bs_i:
            return False, "byte_end must be greater than byte_start"
    else:
        bs_i = be_i = None

    for row in trusted:
        if row["path_norm"] != path_norm:
            continue
        if row["digest"] != dg:
            continue
        if row["algo"] != alg:
            continue
        if has_range:
            if row["byte_start"] == bs_i and row["byte_end"] == be_i:
                return True, ""
        else:
            return True, ""

    if has_range:
        return False, "no trusted manifest row matches path, digest, and byte range"
    return False, "no trusted manifest row matches path and digest"


def _parse_lineage_document(data: object) -> tuple[dict | None, str]:
    if not isinstance(data, dict):
        return None, "lineage.json root must be a JSON object"
    if data.get("schema_version") != "1.0":
        return None, 'schema_version must be "1.0"'
    deriv = data.get("derivation_id")
    if not isinstance(deriv, str) or not deriv.strip():
        return None, "derivation_id must be a non-empty string"
    deriv_s = deriv.strip()
    if len(deriv_s) > 256:
        return None, "derivation_id exceeds 256 characters"
    if any(ord(c) < 32 for c in deriv_s):
        return None, "derivation_id must not contain control characters"
    inputs = data.get("inputs")
    if not isinstance(inputs, list):
        return None, "inputs must be a JSON array"
    return {"schema_version": "1.0", "derivation_id": deriv_s, "inputs": inputs}, ""


def _resolve_lineage_file_path(path_norm: str, roots_resolved: Sequence[str]) -> str | None:
    rel = path_norm.replace("/", os.sep)
    for r in roots_resolved:
        cand = os.path.join(os.path.abspath(r), rel)
        try:
            k = path_for_kernel(cand)
            if os.path.isfile(k):
                return k
        except OSError:
            continue
    return None


def _verify_lineage_json_against_manifest(
    manifest_path: str,
    roots_resolved: Sequence[str],
    modified: List[dict],
    deleted: List[dict],
) -> tuple[dict, List[dict]]:
    """
    After per-file .f33 verification, validate lineage.json semantics against the same manifest.

    Returns (lineage_summary_dict, extra_modified_rows for drift UI).
    """
    primary_root = os.path.abspath(roots_resolved[0] if roots_resolved else os.getcwd())
    trusted = _iter_trusted_manifest_segments(manifest_path, primary_root)
    modified_paths = {str(m.get("path") or "").replace("\\", "/") for m in modified}
    deleted_paths = {str(d.get("path") or "").replace("\\", "/") for d in deleted}

    lineage_targets: dict[tuple[int, str], None] = {}
    for row in trusted:
        pn = row["path_norm"]
        if os.path.basename(pn) != "lineage.json":
            continue
        lineage_targets[(int(row.get("root_index", 0)), pn)] = None

    reports: List[dict] = []
    extra_modified: List[dict] = []

    for _ri, path_norm in sorted(lineage_targets.keys(), key=lambda x: (x[1], x[0])):
        entry_report: dict = {"path": path_norm, "derivation_id": None, "inputs_checked": 0, "ok": True, "errors": []}

        if path_norm in modified_paths:
            entry_report["ok"] = False
            entry_report["errors"].append("lineage skipped: file failed cryptographic verification earlier in this run")
            reports.append(entry_report)
            continue
        if path_norm in deleted_paths:
            entry_report["ok"] = False
            entry_report["errors"].append("lineage skipped: file marked deleted relative to manifest")
            reports.append(entry_report)
            continue

        full_path = _resolve_lineage_file_path(path_norm, roots_resolved)
        if not full_path:
            entry_report["ok"] = False
            entry_report["errors"].append("lineage.json not found on disk under verify roots")
            extra_modified.append(
                {
                    "path": path_norm,
                    "digest": None,
                    "expected_digest": None,
                    "algo": "sha256",
                    "status": "[ LINEAGE BROKEN: missing lineage.json on disk ]",
                }
            )
            reports.append(entry_report)
            continue

        try:
            with open(full_path, encoding="utf-8") as lf:
                doc = json.load(lf)
        except (OSError, json.JSONDecodeError) as e:
            entry_report["ok"] = False
            entry_report["errors"].append(f"invalid lineage.json: {e}")
            extra_modified.append(
                {
                    "path": path_norm,
                    "digest": None,
                    "expected_digest": None,
                    "algo": "sha256",
                    "status": "[ LINEAGE BROKEN: invalid JSON ]",
                }
            )
            reports.append(entry_report)
            continue

        parsed, perr = _parse_lineage_document(doc)
        if parsed is None:
            entry_report["ok"] = False
            entry_report["errors"].append(perr)
            extra_modified.append(
                {
                    "path": path_norm,
                    "digest": None,
                    "expected_digest": None,
                    "algo": "sha256",
                    "status": f"[ LINEAGE BROKEN: {perr} ]",
                }
            )
            reports.append(entry_report)
            continue

        entry_report["derivation_id"] = parsed["derivation_id"]
        inputs_list: List[object] = parsed["inputs"]
        entry_report["inputs_checked"] = len(inputs_list)

        input_errs: List[str] = []
        for idx, inp in enumerate(inputs_list):
            ok, msg = _lineage_input_matches_trusted(trusted, inp)
            if not ok:
                input_errs.append(f"inputs[{idx}]: {msg}")
        if input_errs:
            entry_report["ok"] = False
            entry_report["errors"].extend(input_errs)
            extra_modified.append(
                {
                    "path": path_norm,
                    "digest": None,
                    "expected_digest": None,
                    "algo": "sha256",
                    "status": "[ LINEAGE BROKEN: upstream digest not found in trusted manifest ]",
                    "lineage_errors": input_errs,
                }
            )

        reports.append(entry_report)

    broken = any(not r.get("ok", False) for r in reports)
    summary = {
        "status": "broken" if broken else "ok",
        "files_checked": len(reports),
        "reports": reports,
    }
    return summary, extra_modified


class ManifestCompromisedError(RuntimeError):
    """Raised when the central manifest and signature-verified sidecars disagree."""

    def __init__(
        self,
        message: str,
        *,
        rel: str | None = None,
        expected_digest: str | None = None,
        sidecar_digest: str | None = None,
    ) -> None:
        super().__init__(message)
        self.rel = rel
        self.expected_digest = expected_digest
        self.sidecar_digest = sidecar_digest


def _resolve_manifest_verify_compat_kwargs(
    *,
    legacy_manifest_json: bool,
    manifest_compromise_action: Literal["fail_fast", "record_and_continue"],
    created_paths_format: Literal["extension", "stripped_filtered"],
    manifest_modified_include_reason: bool,
    lineage_broken_maps_to_severe_exit: bool,
) -> tuple[Literal["fail_fast", "record_and_continue"], Literal["extension", "stripped_filtered"], bool, bool]:
    """Apply ``FORS33_VERIFIER_LEGACY_MANIFEST_JSON=1`` or ``legacy_manifest_json=True`` OSS 0.8.x-style presets."""
    if legacy_manifest_json or _env_bool("FORS33_VERIFIER_LEGACY_MANIFEST_JSON"):
        return ("record_and_continue", "stripped_filtered", True, False)
    return (
        manifest_compromise_action,
        created_paths_format,
        manifest_modified_include_reason,
        lineage_broken_maps_to_severe_exit,
    )


@dataclass
class VerificationReport:
    """Unified report for L3dgr-style consumers: modified, created, deleted, skipped, mutated."""

    modified: List[dict]
    created: List[dict]
    deleted: List[dict]
    skipped: List[dict]
    mutated: List[dict]
    schema_version: str
    baseline: str
    root: str
    roots: List[str] | None
    timing: dict
    files_scanned: int = 0
    lineage: dict | None = None
    lineage_broken_maps_to_severe_exit: bool = True
    series_sha256: Dict[str, str] | None = None
    series_reference: Dict[str, str] | None = None


def _strip_mount_prefix(path: str, prefix: str) -> str:
    """Strip Docker host-mount prefix from path for stored/logged/JSON output."""
    if not prefix:
        return path
    norm_path = os.path.normpath(path)
    norm_prefix = os.path.normpath(prefix).rstrip(os.sep)
    if not norm_prefix:
        return path
    if norm_path == norm_prefix:
        return "."
    sep = os.sep
    if norm_path.startswith(norm_prefix + sep):
        stripped = norm_path[len(norm_prefix) + len(sep) :]
        return stripped if stripped else "."
    return path


def _env_bool(key: str) -> bool:
    """Strict string-to-bool: True only for 1, true, yes, y; False otherwise."""
    v = os.environ.get(key, "").strip().lower()
    return v in ("1", "true", "yes", "y")


def _load_f33ignore_patterns(root: str) -> List[str]:
    """Load glob patterns from root-level .f33ignore (gitignore-style)."""
    patterns: List[str] = []
    ignore_path = os.path.join(root, ".f33ignore")
    if not os.path.isfile(ignore_path):
        return patterns
    try:
        with open(path_for_kernel(ignore_path), encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                patterns.append(line)
    except OSError:
        pass
    return patterns

# --- .f33 sidecar (in-toto Statement v0.1 or v1) ---

_IN_TOTO_STATEMENT_V0_1 = "https://in-toto.io/Statement/v0.1"
_IN_TOTO_STATEMENT_V1 = "https://in-toto.io/Statement/v1"


def _f33_validate_subject_digest(sub: dict, index: int) -> None:
    """Ensure subject[index] has a digest object with valid sha256 or sha512 hex."""
    digest = sub.get("digest")
    if not isinstance(digest, dict):
        raise ValueError(f"{_ERR_INVALID_SEAL_FORMAT} subject[{index}].digest missing/invalid")
    sha256_hex = digest.get("sha256")
    sha512_hex = digest.get("sha512")
    if isinstance(sha256_hex, str) and sha256_hex.strip():
        h = sha256_hex.strip().lower()
        if len(h) != 64 or any(c not in "0123456789abcdef" for c in h):
            raise ValueError(f"{_ERR_INVALID_SEAL_FORMAT} subject[{index}].digest.sha256 must be 64 hex chars")
    elif isinstance(sha512_hex, str) and sha512_hex.strip():
        h = sha512_hex.strip().lower()
        if len(h) != 128 or any(c not in "0123456789abcdef" for c in h):
            raise ValueError(f"{_ERR_INVALID_SEAL_FORMAT} subject[{index}].digest.sha512 must be 128 hex chars")
    else:
        raise ValueError(
            f"{_ERR_INVALID_SEAL_FORMAT} subject[{index}].digest.sha256 or sha512 missing/invalid"
        )


def _parse_f33(sidecar_path: str) -> dict:
    """Parse `.f33` as in-toto Statement JSON (v0.1 or v1). Raises ValueError on contract mismatch."""
    try:
        with open(path_for_kernel(sidecar_path), encoding="utf-8") as f:
            statement = json.load(f)
    except FileNotFoundError:
        raise
    except json.JSONDecodeError as e:
        raise ValueError(f"{_ERR_INVALID_SEAL_FORMAT} non-json sidecar: {e}") from e
    except OSError as e:
        raise ValueError(f"{_ERR_INVALID_SEAL_FORMAT} cannot read sidecar: {e}") from e

    if not isinstance(statement, dict):
        raise ValueError(f"{_ERR_INVALID_SEAL_FORMAT} root must be JSON object")

    raw_type = statement.get("_type")
    if raw_type is None or (isinstance(raw_type, str) and not str(raw_type).strip()):
        stmt_type = _IN_TOTO_STATEMENT_V0_1
    else:
        stmt_type = str(raw_type).strip()
    if stmt_type not in (_IN_TOTO_STATEMENT_V0_1, _IN_TOTO_STATEMENT_V1):
        raise ValueError(f"{_ERR_INVALID_SEAL_FORMAT} unsupported _type {stmt_type!r}")

    subject = statement.get("subject")
    if not isinstance(subject, list) or not subject:
        raise ValueError(f"{_ERR_INVALID_SEAL_FORMAT} missing subject[]")

    for idx, sub in enumerate(subject):
        if not isinstance(sub, dict):
            raise ValueError(f"{_ERR_INVALID_SEAL_FORMAT} subject[{idx}] must be an object")
        _f33_validate_subject_digest(sub, idx)

    s0 = subject[0]
    target_name = s0.get("name")
    digest = s0.get("digest")
    if not isinstance(target_name, str) or not target_name:
        raise ValueError(f"{_ERR_INVALID_SEAL_FORMAT} subject[0].name missing/invalid")
    if not isinstance(digest, dict):
        raise ValueError(f"{_ERR_INVALID_SEAL_FORMAT} subject[0].digest missing/invalid")
    sha256_hex = digest.get("sha256")
    sha512_hex = digest.get("sha512")
    file_hash_raw: str
    digest_algo: str
    if isinstance(sha256_hex, str) and sha256_hex.strip():
        file_hash_raw = sha256_hex
        digest_algo = "sha256"
    elif isinstance(sha512_hex, str) and sha512_hex.strip():
        file_hash_raw = sha512_hex
        digest_algo = "sha512"
    else:
        raise ValueError(f"{_ERR_INVALID_SEAL_FORMAT} subject[0].digest.sha256 or sha512 missing/invalid")

    predicate = statement.get("predicate")
    if not isinstance(predicate, dict):
        raise ValueError(f"{_ERR_INVALID_SEAL_FORMAT} missing predicate object")

    byte_start = (
        predicate.get("byte_start", None)
        if "byte_start" in predicate
        else predicate.get("range_start", None)
    )
    byte_end = (
        predicate.get("byte_end", None) if "byte_end" in predicate else predicate.get("range_end", None)
    )
    range_obj = predicate.get("range")
    if isinstance(range_obj, dict):
        if byte_start is None:
            byte_start = range_obj.get("start")
        if byte_end is None:
            byte_end = range_obj.get("end")
    timestamp = predicate.get("timestamp", None)
    public_key_hex = predicate.get("public_key_hex", None) or predicate.get("pubkey_ed25519", None)
    signature_hex = predicate.get("signature_hex", None) or predicate.get("signature_ed25519", None)
    sig_nested = predicate.get("signature")
    if isinstance(sig_nested, dict):
        if not public_key_hex:
            public_key_hex = sig_nested.get("public_key_hex") or sig_nested.get("pubkey_ed25519")
        if not signature_hex:
            signature_hex = sig_nested.get("signature_hex") or sig_nested.get("signature_ed25519")
    operator_key_id = predicate.get("operator_key_id", None)

    def _pred_opt_str(pred: dict, key: str) -> str | None:
        v = pred.get(key)
        if v is None:
            return None
        s = str(v).strip()
        return s or None

    cpv_raw = predicate.get("canonical_payload_version")
    if cpv_raw is None or (isinstance(cpv_raw, str) and not str(cpv_raw).strip()):
        canonical_payload_version_explicit = False
        canonical_payload_version: int | None = None
    else:
        canonical_payload_version_explicit = True
        try:
            canonical_payload_version = int(cpv_raw)
        except (TypeError, ValueError) as e:
            raise ValueError(f"{_ERR_INVALID_SEAL_FORMAT} canonical_payload_version must be an integer") from e
        if canonical_payload_version not in (1, 2):
            raise ValueError(f"{_ERR_INVALID_SEAL_FORMAT} unsupported canonical_payload_version")

    if byte_start is None or byte_end is None or timestamp is None or public_key_hex is None or signature_hex is None:
        raise ValueError(f"{_ERR_INVALID_SEAL_FORMAT} missing required predicate fields")

    if not isinstance(byte_start, int) or not isinstance(byte_end, int):
        raise ValueError(f"{_ERR_INVALID_SEAL_FORMAT} predicate.byte_start/byte_end must be integers")
    if byte_end <= byte_start:
        raise ValueError(f"{_ERR_INVALID_SEAL_FORMAT} predicate byte range must be non-empty (end > start)")
    if not isinstance(timestamp, str) or not timestamp:
        raise ValueError(f"{_ERR_INVALID_SEAL_FORMAT} predicate.timestamp missing/invalid")
    if not isinstance(public_key_hex, str) or not public_key_hex:
        raise ValueError(f"{_ERR_INVALID_SEAL_FORMAT} predicate.public_key_hex missing/invalid")
    if not isinstance(signature_hex, str) or not signature_hex:
        raise ValueError(f"{_ERR_INVALID_SEAL_FORMAT} predicate.signature_hex missing/invalid")

    file_hash_l = file_hash_raw.lower()
    public_key_hex_l = public_key_hex.lower()
    signature_hex_l = signature_hex.lower()

    tsa_public_key_hex = (
        predicate.get("tsa_public_key_hex")
        or predicate.get("tsa_pubkey_ed25519")
        or predicate.get("public_key_hex_tsa")
        or predicate.get("pubkey_ed25519_tsa")
    )
    tsa_signature_hex = (
        predicate.get("tsa_signature_hex")
        or predicate.get("tsa_signature_ed25519")
        or predicate.get("signature_hex_tsa")
        or predicate.get("signature_ed25519_tsa")
    )
    tsa_public_key_hex_l = tsa_public_key_hex.lower() if isinstance(tsa_public_key_hex, str) else None
    tsa_signature_hex_l = tsa_signature_hex.lower() if isinstance(tsa_signature_hex, str) else None

    # TSA token: match L3dgr order (top-level rfc3161, nested rfc3161, then response_token).
    rfc3161_raw = predicate.get("rfc3161_token_b64")
    rfc3161_b64 = rfc3161_raw.strip() if isinstance(rfc3161_raw, str) and rfc3161_raw.strip() else None
    if not rfc3161_b64:
        tsa_obj = predicate.get("tsa")
        if isinstance(tsa_obj, dict):
            nested = tsa_obj.get("rfc3161_token_b64")
            if isinstance(nested, str) and nested.strip():
                rfc3161_b64 = nested.strip()
            else:
                response_token = tsa_obj.get("response_token")
                if isinstance(response_token, str) and response_token.strip():
                    rfc3161_b64 = response_token.strip()

    if digest_algo == "sha512":
        if len(file_hash_l) != 128 or any(c not in "0123456789abcdef" for c in file_hash_l):
            raise ValueError(f"{_ERR_INVALID_SEAL_FORMAT} subject[0].digest.sha512 must be 128 hex chars")
    elif len(file_hash_l) != 64 or any(c not in "0123456789abcdef" for c in file_hash_l):
        raise ValueError(f"{_ERR_INVALID_SEAL_FORMAT} subject[0].digest.sha256 must be 64 hex chars")
    if len(public_key_hex_l) != 64 or any(c not in "0123456789abcdef" for c in public_key_hex_l):
        raise ValueError(f"{_ERR_INVALID_SEAL_FORMAT} predicate.public_key_hex must be 64 hex chars")
    if len(signature_hex_l) != 128 or any(c not in "0123456789abcdef" for c in signature_hex_l):
        raise ValueError(f"{_ERR_INVALID_SEAL_FORMAT} predicate.signature_hex must be 128 hex chars")

    meta = predicate.get("metadata") if isinstance(predicate.get("metadata"), dict) else {}
    raw_ts = meta.get("time_source", "PAYLOAD_NATIVE")
    if isinstance(raw_ts, str) and raw_ts.strip() in ("PAYLOAD_NATIVE", "LOCAL_CONTAINER", "HARDWARE_PTP"):
        time_source = raw_ts.strip()
    else:
        time_source = "PAYLOAD_NATIVE"

    return {
        "target": target_name,
        "range_start": byte_start,
        "range_end": byte_end,
        "timestamp": timestamp,
        "file_digest": file_hash_l,
        "digest_algo": digest_algo,
        "public_key_hex": public_key_hex_l,
        "signature_hex": signature_hex_l,
        "operator_key_id": str(operator_key_id) if operator_key_id is not None else "",
        "canonical_payload_version": canonical_payload_version,
        "canonical_payload_version_explicit": canonical_payload_version_explicit,
        "operator_id": _pred_opt_str(predicate, "operator_id"),
        "operator_key_id_canonical": _pred_opt_str(predicate, "operator_key_id"),
        "authorized_operator": _pred_opt_str(predicate, "authorized_operator"),
        "organization": _pred_opt_str(predicate, "organization"),
        "source_fingerprint": source_fingerprint_from_predicate(predicate),
        "signature_intent": _pred_opt_str(predicate, "signature_intent"),
        "reason_for_change": _pred_opt_str(predicate, "reason_for_change"),
        "sig_alg": _pred_opt_str(predicate, "sig_alg"),
        "nonce_hex": _pred_opt_str(predicate, "nonce_hex"),
        "tsa_public_key_hex": tsa_public_key_hex_l,
        "tsa_signature_hex": tsa_signature_hex_l,
        "rfc3161_token_b64": rfc3161_b64,
        "tsa": predicate.get("tsa") if isinstance(predicate.get("tsa"), dict) else None,
        "time_source": time_source,
    }


def _legacy_json_canonical_payload(parsed: dict) -> bytes:
    """Legacy OSS JSON canonicalization (sha256 key) for key-absent tri-state only."""
    payload_obj = {
        "target": parsed["target"],
        "range_start": int(parsed["range_start"]),
        "range_end": int(parsed["range_end"]),
        "timestamp": parsed["timestamp"],
        "sha256": str(parsed["file_digest"]).lower(),
    }
    return json.dumps(payload_obj, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _build_payload_for_version(parsed: dict, payload_version: int) -> bytes:
    okid = parsed.get("operator_key_id_canonical")
    if not okid:
        raw = str(parsed.get("operator_key_id") or "").strip()
        okid = raw or None
    return build_canonical_payload(
        str(parsed["target"]),
        int(parsed["range_start"]),
        int(parsed["range_end"]),
        str(parsed["timestamp"]),
        str(parsed["file_digest"]),
        str(parsed.get("digest_algo") or "sha256"),
        payload_version=payload_version,
        operator_id=parsed.get("operator_id"),
        operator_key_id=okid,
        authorized_operator=parsed.get("authorized_operator"),
        organization=parsed.get("organization"),
        source_fingerprint=parsed.get("source_fingerprint"),
        signature_intent=parsed.get("signature_intent"),
        reason_for_change=parsed.get("reason_for_change"),
        sig_alg=parsed.get("sig_alg"),
    )


def _verify_signature_pick_payload(parsed: dict) -> bytes:
    """Dispatch signature verification by optional ``sig_alg`` (Wave 3B)."""
    sig_alg_raw = str(parsed.get("sig_alg") or "").strip().lower()
    if not sig_alg_raw or sig_alg_raw == "ed25519":
        return _verify_ed25519_pick_payload(parsed)
    if sig_alg_raw in ("x509-rsa-pss-sha256", "x509-ecdsa-p256-sha256"):
        raise ValueError(f"{_ERR_SIG_ALG_NOT_IMPLEMENTED} {sig_alg_raw}")
    raise ValueError(f"{_ERR_SIG_ALG_UNSUPPORTED} {sig_alg_raw}")


def _verify_ed25519_pick_payload(parsed: dict) -> bytes:
    """
    Return the payload bytes that verify the Ed25519 signature.
    When canonical_payload_version is absent, try V2 line, V1 line, then legacy JSON.
    When explicit 1 or 2, only that line format (no JSON fallback).
    """
    explicit = bool(parsed.get("canonical_payload_version_explicit"))
    pk = str(parsed["public_key_hex"])
    sig = str(parsed["signature_hex"])
    if explicit:
        v = int(parsed["canonical_payload_version"])
        payload = _build_payload_for_version(parsed, v)
        _verify_ed25519_f33(pk, sig, payload)
        return payload
    last_err: Exception | None = None
    for pv in (2, 1):
        try:
            payload = _build_payload_for_version(parsed, pv)
            _verify_ed25519_f33(pk, sig, payload)
            return payload
        except Exception as e:
            last_err = e
    try:
        legacy = _legacy_json_canonical_payload(parsed)
        _verify_ed25519_f33(pk, sig, legacy)
        return legacy
    except Exception as e:
        last_err = e
    raise last_err or RuntimeError("Ed25519 verification failed")


def _registry_path_from_env() -> str:
    return str(os.environ.get("F33_KEY_REGISTRY_PATH") or "").strip()


def _parse_utc(ts: str) -> datetime | None:
    try:
        return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except Exception:
        return None


def _validate_key_registry_window(parsed: dict) -> None:
    operator_key_id = str(parsed.get("operator_key_id") or "").strip()
    if not operator_key_id:
        return
    reg_path = _registry_path_from_env()
    if not reg_path:
        raise ValueError("operator_key_id present but F33_KEY_REGISTRY_PATH is not set")
    if not os.path.isfile(path_for_kernel(reg_path)):
        raise ValueError("operator_key_id present but public-key registry file is missing or unreadable")
    with open(path_for_kernel(reg_path), encoding="utf-8") as f:
        reg = json.load(f)
    keys = reg.get("keys", []) if isinstance(reg, dict) else []
    signed_at = _parse_utc(str(parsed.get("timestamp") or ""))
    if signed_at is None:
        raise ValueError("invalid signature timestamp for registry validation")
    matched = False
    for row in keys if isinstance(keys, list) else []:
        if not isinstance(row, dict):
            continue
        if str(row.get("operator_key_id") or "") != operator_key_id:
            continue
        pub_hex = str(row.get("public_key_hex") or "").lower()
        if pub_hex and pub_hex != str(parsed.get("public_key_hex") or "").lower():
            continue
        valid_from = _parse_utc(str(row.get("valid_from") or ""))
        valid_to = _parse_utc(str(row.get("valid_to") or "")) if row.get("valid_to") else None
        if valid_from is None:
            continue
        if signed_at < valid_from:
            continue
        if valid_to is not None and signed_at > valid_to:
            continue
        revoked_at = _parse_utc(str(row.get("revoked_at") or "")) if row.get("revoked_at") else None
        if revoked_at is not None and signed_at >= revoked_at:
            continue
        matched = True
        break
    if not matched:
        raise ValueError("public-key registry validity check failed for operator_key_id")


def _verify_ed25519_f33(public_key_hex: str, signature_hex: str, payload_bytes: bytes) -> None:
    """Verify Ed25519 signature; raises on failure."""
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.exceptions import InvalidSignature

    public_bytes = bytes.fromhex(public_key_hex)
    signature_bytes = bytes.fromhex(signature_hex)
    public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_bytes)
    public_key.verify(signature_bytes, payload_bytes)


def _tsa_imprint_oid_to_hash_name(oid: str) -> str:
    """Map messageImprint.hashAlgorithm OID to hashlib name; reject weak algorithms."""
    weak = {"1.3.14.3.2.26", "1.2.840.113549.2.5"}  # SHA-1, MD5 — rejected for TSA imprint
    if oid in weak:
        raise ValueError(f"TSA imprint uses rejected weak hash OID {oid}")
    mapping = {
        "2.16.840.1.101.3.4.2.1": "sha256",
        "2.16.840.1.101.3.4.2.2": "sha384",
        "2.16.840.1.101.3.4.2.3": "sha512",
    }
    if oid not in mapping:
        raise ValueError(f"unsupported TSA imprint hash OID: {oid}")
    return mapping[oid]


def _cms_signed_data_from_content_info(ci) -> object:
    from asn1crypto import cms, core

    ct = ci["content_type"].dotted
    if ct != "1.2.840.113549.1.7.2":
        raise ValueError(f"expected CMS signedData, got content type {ct}")
    content = ci["content"]
    if isinstance(content, cms.SignedData):
        return content
    if content is None:
        raise ValueError("empty signedData")
    if isinstance(content, core.OctetString):
        return cms.SignedData.load(content.native)
    return cms.SignedData.load(content.dump())


def _cms_certificates(signed_data) -> List[object]:
    out: List[object] = []
    bag = signed_data["certificates"]
    if bag is None:
        return out
    for i in range(len(bag)):
        ch = bag[i]
        if ch.name == "certificate":
            out.append(ch.chosen)
    return out


def _cms_match_signer_cert(signer_info, certs: Sequence[object]) -> object:
    sid = signer_info["sid"]
    if sid.name != "issuer_and_serial_number":
        raise ValueError("unsupported SignerIdentifier (expected issuer and serial number)")
    ias = sid.chosen
    issuer = ias["issuer"]
    serial = ias["serial_number"].native
    for c in certs:
        if c.serial_number.native == serial and c.issuer.dump() == issuer.dump():
            return c
    raise ValueError("signer certificate not found in timestamp token")


def _cms_extract_tst_info(signed_data) -> object:
    from asn1crypto import tsp as tsp_mod

    encap = signed_data["encap_content_info"]
    tst_oid = "1.2.840.113549.1.9.16.1.4"
    if encap["content_type"].dotted != tst_oid:
        raise ValueError(f"expected id-ct-TSTInfo encapsulated content, got {encap['content_type'].dotted}")
    raw = encap["content"]
    if raw is None:
        raise ValueError("missing TSTInfo encapsulated content")
    inner = raw.native
    if not isinstance(inner, (bytes, bytearray)):
        raise ValueError("TSTInfo encapsulated content must be octet string bytes")
    return tsp_mod.TSTInfo.load(bytes(inner))


def _cms_verify_signer_info(signer_info, signer_cert, signed_data) -> None:
    from cryptography import x509 as crypto_x509
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa as rsa_alg

    cert_crypto = crypto_x509.load_der_x509_certificate(signer_cert.dump(), default_backend())
    pub = cert_crypto.public_key()
    sig = signer_info["signature"].native
    sa_oid = signer_info["signature_algorithm"]["algorithm"].dotted
    signed_attrs = signer_info["signed_attrs"]
    if signed_attrs is not None:
        to_sign = signed_attrs.dump()
    else:
        encap = signed_data["encap_content_info"]
        c = encap["content"]
        to_sign = c.dump() if c is not None else b""

    try:
        if isinstance(pub, rsa_alg.RSAPublicKey):
            if sa_oid == "1.2.840.113549.1.1.11":
                pub.verify(sig, to_sign, padding.PKCS1v15(), hashes.SHA256())
            elif sa_oid == "1.2.840.113549.1.1.12":
                pub.verify(sig, to_sign, padding.PKCS1v15(), hashes.SHA384())
            elif sa_oid == "1.2.840.113549.1.1.13":
                pub.verify(sig, to_sign, padding.PKCS1v15(), hashes.SHA512())
            else:
                raise ValueError(f"unsupported RSA signature algorithm OID {sa_oid}")
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            if sa_oid == "1.2.840.10045.4.3.2":
                ha = hashes.SHA256()
            elif sa_oid == "1.2.840.10045.4.3.3":
                ha = hashes.SHA384()
            elif sa_oid == "1.2.840.10045.4.3.4":
                ha = hashes.SHA512()
            else:
                raise ValueError(f"unsupported ECDSA signature algorithm OID {sa_oid}")
            pub.verify(sig, to_sign, ec.ECDSA(ha))
        else:
            raise ValueError("unsupported public key type in TSA signer certificate")
    except InvalidSignature as e:
        raise ValueError("CMS signature verification failed") from e
    except AttributeError:
        # Older cryptography: isinstance checks may differ
        raise ValueError("unsupported public key type in TSA signer certificate") from None


def _cms_assert_timestamping_eku(signer_cert) -> None:
    """Require id-kp-timeStamping ExtendedKeyUsage on the TSA signer certificate."""
    from cryptography import x509 as crypto_x509
    from cryptography.hazmat.backends import default_backend

    cert_crypto = crypto_x509.load_der_x509_certificate(signer_cert.dump(), default_backend())
    try:
        ext = cert_crypto.extensions.get_extension_for_class(crypto_x509.ExtendedKeyUsage)
    except crypto_x509.ExtensionNotFound:
        raise ValueError("TSA_EKU_MISSING: signer cert lacks ExtendedKeyUsage extension") from None
    timestamping_oid = "1.3.6.1.5.5.7.3.8"
    found = False
    for usage in ext.value:
        if getattr(usage, "dotted_string", None) == timestamping_oid:
            found = True
            break
    if not found:
        raise ValueError("TSA_EKU_MISSING: signer cert lacks id-kp-timeStamping EKU") from None


def _pki_status_granted(status_field) -> bool:
    """Return True when PKIStatus is granted (0 or asn1crypto native 'granted')."""
    if status_field is None:
        return False
    native = getattr(status_field, "native", status_field)
    if isinstance(native, str):
        lowered = native.strip().lower()
        if lowered in ("granted", "0"):
            return True
        try:
            return int(native, 10) == 0
        except (TypeError, ValueError):
            return False
    try:
        return int(native) == 0
    except (TypeError, ValueError):
        return False


_TSA_TRUST_ANCHORS_CACHE: list[object] | None = None


def _reset_tsa_trust_anchor_cache() -> None:
    """Test helper: clear cached TSA trust anchors."""
    global _TSA_TRUST_ANCHORS_CACHE
    _TSA_TRUST_ANCHORS_CACHE = None


def _load_pem_x509(path: str, crypto_x509, default_backend) -> object | None:
    try:
        with open(path, "rb") as fh:
            pem_data = fh.read()
    except OSError:
        return None
    try:
        return crypto_x509.load_pem_x509_certificate(pem_data, default_backend())
    except Exception:
        return None


def _load_tsa_trust_anchor_certs() -> list[object]:
    """Load pinned TSA trust anchors from bundle dir and/or comma-separated PEM paths.

    OSS inlines PEM reads (no tsa_trust package). Operator supplies PEMs via
    F33_TSA_TRUST_BUNDLE and/or F33_TSA_TRUST_ANCHORS.
    """
    global _TSA_TRUST_ANCHORS_CACHE
    if _TSA_TRUST_ANCHORS_CACHE is not None:
        return _TSA_TRUST_ANCHORS_CACHE
    from cryptography import x509 as crypto_x509
    from cryptography.hazmat.backends import default_backend

    anchors: list[object] = []
    bundle_dir = os.environ.get("F33_TSA_TRUST_BUNDLE", "").strip()
    if bundle_dir and os.path.isdir(bundle_dir):
        try:
            names = sorted(os.listdir(bundle_dir))
        except OSError:
            names = []
        for name in names:
            lower = name.lower()
            if not (lower.endswith(".pem") or lower.endswith(".crt") or lower.endswith(".cer")):
                continue
            cert = _load_pem_x509(os.path.join(bundle_dir, name), crypto_x509, default_backend)
            if cert is not None:
                anchors.append(cert)

    raw = os.environ.get("F33_TSA_TRUST_ANCHORS", "").strip()
    if raw:
        for part in raw.split(","):
            path = part.strip()
            if not path or not os.path.isfile(path):
                continue
            cert = _load_pem_x509(path, crypto_x509, default_backend)
            if cert is not None:
                anchors.append(cert)
    _TSA_TRUST_ANCHORS_CACHE = anchors
    return anchors


def _cert_fingerprint_sha256(cert_crypto) -> bytes:
    from cryptography.hazmat.primitives import hashes

    return cert_crypto.fingerprint(hashes.SHA256())


def _cert_chains_to_anchor(leaf_crypto, pool: list, anchor_crypto) -> bool:
    if _cert_fingerprint_sha256(leaf_crypto) == _cert_fingerprint_sha256(anchor_crypto):
        return True
    issuer = leaf_crypto.issuer
    for candidate in pool:
        if candidate.subject == issuer:
            if _cert_chains_to_anchor(candidate, pool, anchor_crypto):
                return True
    return False


def _cms_assert_eutl_trust_anchor(signer_cert, all_certs: Sequence[object]) -> None:
    """Regulated-only: require TSA signer chain to a configured trust anchor."""
    from cryptography import x509 as crypto_x509
    from cryptography.hazmat.backends import default_backend

    anchors = _load_tsa_trust_anchor_certs()
    if not anchors:
        raise ValueError(
            "TSA_TRUST_ANCHORS_UNCONFIGURED: set F33_TSA_TRUST_BUNDLE or F33_TSA_TRUST_ANCHORS"
        )
    signer_crypto = crypto_x509.load_der_x509_certificate(signer_cert.dump(), default_backend())
    pool = [
        crypto_x509.load_der_x509_certificate(c.dump(), default_backend()) for c in all_certs
    ]
    for anchor in anchors:
        if _cert_chains_to_anchor(signer_crypto, pool, anchor):
            return
    raise ValueError("TSA_TRUST_ANCHOR_FAILED: signer cert does not chain to a pinned anchor")


def _verify_rfc3161_token_b64(
    b64s: str,
    canonical_payload: bytes,
    *,
    expected_nonce_hex: str | None = None,
    regulated_verify: bool = False,
) -> None:
    """Decode RFC 3161 TimeStampResp; verify imprint, optional TSTInfo nonce match, EKU, CMS."""
    try:
        from asn1crypto import cms, tsp as tsp_mod
    except ImportError as e:
        raise ValueError(f"asn1crypto required for RFC 3161 TSA verification: {e}") from e

    raw = base64.standard_b64decode(b64s)
    resp = tsp_mod.TimeStampResp.load(raw)
    st = resp["status"]["status"]
    if not _pki_status_granted(st):
        st_native = getattr(st, "native", st)
        raise ValueError(f"TSA status not granted (status={st_native!r})")

    tst_ci = resp["time_stamp_token"]
    if tst_ci is None:
        raise ValueError("missing time_stamp_token")

    ci = tst_ci if isinstance(tst_ci, cms.ContentInfo) else cms.ContentInfo.load(tst_ci.dump())
    signed_data = _cms_signed_data_from_content_info(ci)
    tst_info = _cms_extract_tst_info(signed_data)

    mi = tst_info["message_imprint"]
    ha_oid = mi["hash_algorithm"]["algorithm"].dotted
    hname = _tsa_imprint_oid_to_hash_name(ha_oid)
    digest = hashlib.new(hname, canonical_payload).digest()
    if digest != mi["hashed_message"].native:
        raise ValueError("TSA message imprint does not match canonical attestation payload")

    if expected_nonce_hex:
        try:
            expected_nonce = int(str(expected_nonce_hex), 16)
        except (TypeError, ValueError):
            raise ValueError("TSA_NONCE_MISMATCH: malformed predicate nonce") from None
        try:
            response_nonce = tst_info["nonce"].native
        except Exception:
            response_nonce = None
        if response_nonce is None or int(response_nonce) != expected_nonce:
            raise ValueError("TSA_NONCE_MISMATCH: response nonce does not match request nonce") from None

    signer_infos = signed_data["signer_infos"]
    if len(signer_infos) == 0:
        raise ValueError("no signer_infos in timestamp token")
    certs = _cms_certificates(signed_data)
    if not certs:
        raise ValueError("no certificates in timestamp token")
    signer_cert = _cms_match_signer_cert(signer_infos[0], certs)
    _cms_assert_timestamping_eku(signer_cert)
    if regulated_verify:
        _cms_assert_eutl_trust_anchor(signer_cert, certs)
    _cms_verify_signer_info(signer_infos[0], signer_cert, signed_data)


def _verify_tsa(
    parsed: dict,
    canonical_payload_bytes: bytes,
    *,
    regulated_verify: bool = False,
) -> tuple[bool, str]:
    """Verify TSA when --verify-tsa: RFC 3161 token or legacy Ed25519 predicate.tsa; fail-closed if neither."""
    rfc = parsed.get("rfc3161_token_b64")
    if isinstance(rfc, str) and rfc.strip():
        nonce_hex = parsed.get("nonce_hex")
        nonce_s = str(nonce_hex).strip() if isinstance(nonce_hex, str) and nonce_hex else ""
        if regulated_verify and not nonce_s:
            return False, "TSA_NONCE_REQUIRED: regulated verification requires nonce_hex in predicate"
        try:
            _verify_rfc3161_token_b64(
                rfc.strip(),
                canonical_payload_bytes,
                expected_nonce_hex=nonce_s or None,
                regulated_verify=regulated_verify,
            )
            return True, "tsa_rfc3161_verified"
        except Exception as e:
            return False, f"{_ERR_TSA_INVALID} {e}"

    tsa = parsed.get("tsa")
    if isinstance(tsa, dict):
        payload = tsa.get("payload")
        public_key_hex = str(tsa.get("public_key_hex", "")).lower()
        signature_hex = str(tsa.get("signature_hex", "")).lower()
        if payload is not None and len(public_key_hex) == 64 and len(signature_hex) == 128:
            try:
                _verify_ed25519_f33(public_key_hex, signature_hex, str(payload).encode("utf-8"))
                return True, "tsa_legacy_ed25519_verified"
            except Exception as e:
                return False, f"{_ERR_TSA_INVALID} {e}"

    return False, f"{_ERR_TSA_INVALID} --verify-tsa requires predicate.tsa.rfc3161_token_b64 or legacy Ed25519 tsa fields"


def _verify_manifest_ed25519_signature(
    manifest_path: str,
    signature_path: str,
    public_key_path: str,
) -> tuple[bool, str]:
    """
    Verify a detached Ed25519 signature over the raw manifest bytes.

    Signature file is expected to contain a Base64-encoded signature.
    Public key file is expected to contain either raw 32-byte key material
    or a PEM-encoded Ed25519 public key.
    """
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization
    from cryptography.exceptions import InvalidSignature

    try:
        with open(path_for_kernel(manifest_path), "rb") as f:
            payload = f.read()
    except OSError as e:
        return False, f"Failed to read manifest for signature verification: {e}"

    try:
        with open(path_for_kernel(signature_path), "rb") as f:
            sig_raw = f.read().strip()
        signature_bytes = base64.b64decode(sig_raw)
    except Exception as e:
        return False, f"Failed to read or decode signature file: {e}"

    try:
        with open(path_for_kernel(public_key_path), "rb") as f:
            key_bytes = f.read()
        try:
            if len(key_bytes) == 32:
                public_key = ed25519.Ed25519PublicKey.from_public_bytes(key_bytes)
            else:
                public_key = serialization.load_pem_public_key(key_bytes)
        except Exception as e:
            return False, f"Failed to parse Ed25519 public key: {e}"

        public_key.verify(signature_bytes, payload)
    except InvalidSignature:
        return False, "Manifest signature verification failed"
    except Exception as e:
        return False, f"Manifest signature verification error: {e}"

    return True, "Manifest signature verified"


def verify_sidecar_f33(
    sidecar_path: str,
    target_dir: str | None = None,
    verify_tsa: bool = False,
    regulated_verify: bool = False,
) -> tuple[bool, str]:
    """Verify .f33 sidecar: resolve target, hash range, check digest and Ed25519. Returns (success, message)."""
    try:
        parsed = _parse_f33(sidecar_path)
    except ValueError:
        return False, "[ ERR_INVALID_SEAL_FORMAT ]"
    base = os.path.dirname(os.path.abspath(sidecar_path)) if target_dir is None else target_dir
    target_path = os.path.join(base, parsed["target"])
    if not os.path.isfile(path_for_kernel(target_path)):
        return False, f"Target file not found: {target_path}"
    try:
        _validate_key_registry_window(parsed)
        payload = _verify_signature_pick_payload(parsed)
    except Exception as e:
        return False, f"{_ERR_BAD_SIGNATURE} {e}"
    if verify_tsa:
        tsa_ok, tsa_msg = _verify_tsa(parsed, payload, regulated_verify=regulated_verify)
        if not tsa_ok:
            return False, tsa_msg
    algo = str(parsed.get("digest_algo") or "sha256").lower()
    computed = hash_file(
        path_for_kernel(target_path),
        algo=algo,
        start=int(parsed["range_start"]),
        end=int(parsed["range_end"]),
    )
    if computed.lower() != str(parsed["file_digest"]).lower():
        return False, f"{_ERR_DATA_DRIFT} computed {computed}, expected {parsed['file_digest']}"
    return True, "VERIFIED"


def _ansi_status(status: str) -> str:
    """ANSI wrap for status when stderr is a TTY. VERIFIED=green, MISMATCH/TAMPERED=bold red, SKIPPED=dim gray."""
    if not sys.stderr.isatty():
        return status
    if status == "VERIFIED":
        return "\033[32mVERIFIED\033[0m"
    if status in ("MISMATCH", "TAMPERED"):
        return "\033[1;31m" + status + "\033[0m"
    if status == "SKIPPED":
        return "\033[90mSKIPPED\033[0m"
    return status


def _log_output(target: str, computed_hash: str, status: str) -> None:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    print(f"[SYS.TIME]  : {ts}", file=sys.stderr)
    print(f"[TARGET]    : {target}", file=sys.stderr)
    print(f"[SHA-256]   : {computed_hash}", file=sys.stderr)
    print(f"[STATUS]    : {_ansi_status(status)}", file=sys.stderr)
    print(f"[NOTICE]    : {_CTA}", file=sys.stderr)


def hash_file_range(file_path: str, byte_start: int = 0, byte_end: int | None = None) -> str:
    """Hash file or byte range safely using memory-efficient chunks."""
    return hash_file(file_path, algo="sha256", start=byte_start, end=byte_end)


def _series_reference_from_manifest(
    manifest: Dict[str, ManifestEntry],
    series_sha256: Dict[str, str],
    modified: List[dict],
) -> Dict[str, str]:
    """SHA-256 reference: sealed sha256 digests; unchanged sha512 members use live SHA-256."""
    drifted: set[str] = set()
    for row in modified or []:
        if not isinstance(row, dict):
            continue
        p = str(row.get("path") or "").replace("\\", "/")
        if p:
            drifted.add(p)
    out: Dict[str, str] = {}
    live_sha = {
        str(k).replace("\\", "/"): str(v).strip().lower()
        for k, v in (series_sha256 or {}).items()
        if str(k or "").strip() and str(v or "").strip()
    }
    for entry in (manifest or {}).values():
        path = str(getattr(entry, "path", "") or "").replace("\\", "/")
        if not path:
            continue
        algo = str(getattr(entry, "algo", "") or "sha256").strip().lower() or "sha256"
        digest = str(getattr(entry, "digest", "") or "").strip().lower()
        if algo == "sha256" and digest:
            out[path] = digest
            continue
        live = live_sha.get(path, "")
        if live and path not in drifted:
            out[path] = live
    return out


def _hash_pair_for_series(
    path: str,
    algo: str,
    *,
    start: int = 0,
    end: int | None = None,
    progress_callback: Callable[[int, int], None] | None = None,
) -> tuple[str, str]:
    """One read: (algo digest, sha256 digest)."""
    algo_l = str(algo or "sha256").strip().lower() or "sha256"
    kwargs: dict = {}
    if start:
        kwargs["start"] = start
    if end is not None:
        kwargs["end"] = end
    if progress_callback is not None:
        kwargs["progress_callback"] = progress_callback
    if algo_l == "sha256":
        digest = hash_file(path, algo="sha256", **kwargs)
        lower = str(digest).lower()
        return lower, lower
    digests = hash_file_algos(path, [algo_l, "sha256"], **kwargs)
    return str(digests[algo_l]).lower(), str(digests["sha256"]).lower()


def download_and_hash(
    url: str,
    byte_start: int | None = None,
    byte_end: int | None = None,
    algo: str = "sha256",
) -> str:
    """Download URL (or specific byte range via HTTP Range) and return a hex digest."""
    if urllib is None:
        raise RuntimeError("urllib required for --url")

    req = urllib.request.Request(url)
    if byte_start is not None and byte_end is not None:
        req.add_header("Range", f"bytes={byte_start}-{byte_end - 1}")

    with urllib.request.urlopen(req, timeout=60) as resp:
        def _iter_chunks():
            while True:
                chunk = resp.read(65536)
                if not chunk:
                    break
                yield chunk

        return hash_stream(_iter_chunks(), algo=algo)


def verify_directory_from_manifest(
    manifest_path: str,
    root_dir: str,
    default_algo: str = "sha256",
    schema_version: str = "0.2",
    ignore_patterns: Sequence[str] | None = None,
    exclude_dirs: Sequence[str] | None = None,
    follow_symlinks: bool = False,
    force_insecure: bool = False,
    progress_event_callback: Callable[[dict], None] | None = None,
    strip_mount_prefix: str = "",
    verify_tsa: bool = False,
    max_workers: Optional[int] = None,
    *,
    legacy_manifest_json: bool = False,
    manifest_compromise_action: Literal["fail_fast", "record_and_continue"] = "fail_fast",
    created_paths_format: Literal["extension", "stripped_filtered"] = "extension",
    manifest_modified_include_reason: bool = False,
    lineage_broken_maps_to_severe_exit: bool = True,
    should_cancel: Callable[[], bool] | None = None,
) -> dict:
    """
    Verify a directory tree against a manifest.

    Returns a JSON-serializable dict with:
      - schema_version
      - modified, created, deleted, mutated_during_verification, skipped
      - files_scanned, lineage (manifest lineage.json summary when applicable)
      - algo_stats, timing
      - lineage_broken_maps_to_severe_exit (for CLI/embedders setting exit policy)

    Compatibility (kwargs are source of truth; ``--legacy-manifest-json`` and
    ``FORS33_VERIFIER_LEGACY_MANIFEST_JSON=1`` set the pre-0.9.0-style bundle):
      - ``manifest_compromise_action="record_and_continue"``: append compromise to
        ``modified`` and continue instead of failing fast (weaker audit posture).
      - ``created_paths_format="stripped_filtered"``: normalize ``created[].path``
        for multi-root (strip ``root_idx:`` prefix; skip cryptographic artifacts).
      - ``manifest_modified_include_reason=True``: add redundant ``reason`` on
        ``modified`` rows where useful (pre-0.9.0 JSON shape).
      - ``lineage_broken_maps_to_severe_exit=False``: callers/CLI should not map
        broken lineage alone to severe exit (drift-only line).
    """
    import fnmatch

    _check_verify_cancel(should_cancel)

    compromise_action, created_fmt, mod_inc_reason, lineage_severe = _resolve_manifest_verify_compat_kwargs(
        legacy_manifest_json=legacy_manifest_json,
        manifest_compromise_action=manifest_compromise_action,
        created_paths_format=created_paths_format,
        manifest_modified_include_reason=manifest_modified_include_reason,
        lineage_broken_maps_to_severe_exit=lineage_broken_maps_to_severe_exit,
    )

    start_ts = datetime.now(timezone.utc)
    start_monotonic = start_ts.timestamp()

    preflight = verify_manifest_bundle_preflight(manifest_path, root_dir)
    if preflight:
        raise ValueError(preflight)

    if sys.stderr.isatty():
        print("[SYS] Building manifest tree...", end="", file=sys.stderr)
        sys.stderr.flush()
    manifest, roots = load_manifest(manifest_path, fallback_root_dir=root_dir)
    try:
        with open(path_for_kernel(manifest_path), encoding="utf-8") as mf:
            raw_manifest_obj = json.load(mf)
        if isinstance(raw_manifest_obj, dict):
            ok_ch, ch_err = verify_manifest_hash_chain(raw_manifest_obj)
            if not ok_ch:
                raise ValueError(ch_err)
    except ValueError:
        raise
    except Exception:
        pass
    roots_resolved = roots if roots else [os.path.abspath(root_dir)]
    ignore_patterns = tuple(ignore_patterns or ())
    exclude_dir_set = {d for d in (exclude_dirs or ())}

    modified: List[dict] = []
    created: List[dict] = []
    deleted: List[dict] = []
    mutated: List[dict] = []
    skipped: List[dict] = []

    # Track live files under all roots (key: "root_index:rel_path" or "rel_path" for single-root)
    live_paths: Dict[str, str] = {}
    for root_idx, root in enumerate(roots_resolved):
        root_abs = os.path.abspath(root)
        walk_root = path_for_kernel(root_abs)
        visited_dirs: set[tuple[int, int]] = set()
        if follow_symlinks:
            try:
                st_root = os.stat(walk_root, follow_symlinks=False)
                visited_dirs.add((st_root.st_dev, st_root.st_ino))
            except OSError:
                pass
        for dirpath, dirnames, filenames in os.walk(walk_root, followlinks=follow_symlinks):
            if follow_symlinks:
                keep: list[str] = []
                for d in dirnames:
                    if d in exclude_dir_set:
                        continue
                    full = os.path.join(dirpath, d)
                    try:
                        st = os.stat(path_for_kernel(full), follow_symlinks=True)
                        key = (st.st_dev, st.st_ino)
                        if key in visited_dirs:
                            continue
                        visited_dirs.add(key)
                    except OSError:
                        continue
                    keep.append(d)
                dirnames[:] = keep
            else:
                dirnames[:] = [d for d in dirnames if d not in exclude_dir_set]
            rel_dir = os.path.relpath(dirpath, walk_root)
            rel_dir = "" if rel_dir == "." else rel_dir
            for name in filenames:
                # Exclude cryptographic artifacts and epoch bundle companions from created drift.
                if (
                    name.endswith(".f33")
                    or name == "fors33-manifest.json"
                    or is_epoch_upload_companion_basename(name)
                ):
                    continue
                rel_path = os.path.join(rel_dir, name) if rel_dir else name
                norm_rel = rel_path.replace("\\", "/")
                if ignore_patterns and any(
                    fnmatch.fnmatch(norm_rel, pat) for pat in ignore_patterns
                ):
                    continue
                live_key = f"{root_idx}:{norm_rel}" if len(roots_resolved) > 1 else norm_rel
                live_paths[live_key] = os.path.join(dirpath, name)

    if not force_insecure:
        for key, entry in manifest.items():
            algo_check = (entry.algo or default_algo).lower()
            if algo_check in ("md5", "sha1"):
                raise ValueError(
                    f"Manifest contains deprecated algorithm ({algo_check}) for {entry.path}. "
                    "Use --force-insecure for legacy manifests."
                )

    def _work_generator():
        """Yield manifest entries for hashing; no materialized list."""
        for key, entry in manifest.items():
            norm_rel = entry.path.replace("\\", "/")
            if ":" in key and key[0].isdigit():
                _, norm_rel = key.split(":", 1)
            if ignore_patterns and any(
                fnmatch.fnmatch(norm_rel, pat) for pat in ignore_patterns
            ):
                continue
            root_idx = getattr(entry, "root_index", 0)
            root_for_file = roots_resolved[root_idx] if root_idx < len(roots_resolved) else roots_resolved[0]
            full_path = resolve_manifest_member_path(
                root_for_file, norm_rel, basename_fallback=True
            )
            algo = entry.algo or default_algo
            work_key = f"{root_idx}:{norm_rel}" if len(roots_resolved) > 1 else norm_rel
            yield (work_key, norm_rel, full_path, algo, entry.digest)

    if sys.stderr.isatty():
        print("\r\033[K", end="", file=sys.stderr)

    _abort_event = threading.Event()
    series_sha256: Dict[str, str] = {}
    series_lock = threading.Lock()

    def _hash_worker(item: tuple[str, str, str, str, str]):
        work_key, rel, path, algo, expected = item
        if _abort_event.is_set():
            return ("skipped", work_key, rel, algo, expected, None, "abort_event_set", None)

        if not path or not os.path.isfile(path_for_kernel(path)):
            return ("modified", work_key, rel, algo, expected, None, None, _ERR_INVALID_SEAL_FORMAT)

        target_basename = os.path.basename(path)
        sidecar_path = os.path.join(os.path.dirname(path), f"{target_basename}.f33")
        sidecar_target_expected = target_basename

        try:
            parsed = _parse_f33(sidecar_path)
        except FileNotFoundError:
            return ("modified", work_key, rel, algo, expected, None, None, _ERR_MISSING_SEAL)
        except PermissionError:
            return ("skipped", work_key, rel, algo, expected, None, "access_denied", None)
        except ValueError:
            return ("modified", work_key, rel, algo, expected, None, None, _ERR_INVALID_SEAL_FORMAT)
        except OSError as e:
            return ("skipped", work_key, rel, algo, expected, None, str(e), None)
        except Exception as e:
            return ("skipped", work_key, rel, algo, expected, None, f"sidecar_parse_error: {e}", None)

        if parsed.get("target") != sidecar_target_expected:
            return ("modified", work_key, rel, algo, expected, None, None, _ERR_INVALID_SEAL_FORMAT)

        try:
            _validate_key_registry_window(parsed)
            payload = _verify_signature_pick_payload(parsed)
        except Exception as e:
            return (
                "modified",
                work_key,
                rel,
                algo,
                expected,
                None,
                None,
                f"{_ERR_BAD_SIGNATURE} {e}",
            )

        if verify_tsa:
            tsa_ok, tsa_msg = _verify_tsa(parsed, payload)
            if not tsa_ok:
                return (
                    "modified",
                    work_key,
                    rel,
                    algo,
                    expected,
                    None,
                    None,
                    tsa_msg or _ERR_TSA_INVALID,
                )

        kpath = path_for_kernel(path)
        try:
            st_before = os.stat(kpath)
            before_key: int | tuple[int, int] = (
                (st_before.st_dev, st_before.st_ino)
                if st_before.st_ino != 0
                else int(st_before.st_mtime)
            )
            size = os.path.getsize(kpath)
            progress_cb = None
            if progress_event_callback is not None:

                def _progress_headless(br: int, tb: int) -> None:
                    if tb > 0:
                        pct = min(100, int(br * 100 / tb))
                        progress_event_callback(
                            {"event": "progress", "file": rel, "pct": pct}
                        )

                progress_cb = _progress_headless
            elif size >= 500 * 1024 * 1024 and sys.stderr.isatty():
                last_pct = [0]

                def _progress(br: int, tb: int) -> None:
                    if tb > 0:
                        pct = min(100, int(br * 100 / tb))
                        if pct != last_pct[0] and (pct % 5 == 0 or pct == 100):
                            last_pct[0] = pct
                            print(f"\r\033[K[VERIFY] Hashing {rel}: {pct}%", end="", file=sys.stderr)

                progress_cb = _progress

            sidecar_algo = str(parsed.get("digest_algo") or algo or "sha256").strip().lower() or "sha256"
            computed = hash_file(
                kpath,
                algo=sidecar_algo,
                start=int(parsed["range_start"]),
                end=int(parsed["range_end"]),
                progress_callback=progress_cb,
            )
            # Series live SHA-256 is the full file, not the attested range.
            digest_sha256 = hash_file(kpath, algo="sha256").lower()
            if progress_cb and sys.stderr.isatty():
                print(file=sys.stderr)
            st_after = os.stat(kpath)
            after_key: int | tuple[int, int] = (
                (st_after.st_dev, st_after.st_ino)
                if st_after.st_ino != 0
                else int(st_after.st_mtime)
            )
        except FileNotFoundError:
            return ("deleted", work_key, rel, algo, expected, None, None, None)
        except PermissionError:
            return ("skipped", work_key, rel, algo, expected, None, "access_denied", None)
        except OSError as e:
            return ("skipped", work_key, rel, algo, expected, None, str(e), None)
        except Exception as e:
            msg = f"Unhandled worker exception: {e}"
            print(f"[ERROR] {msg}", file=sys.stderr)
            return ("skipped", work_key, rel, algo, expected, None, msg, None)

        if before_key != after_key:
            return (
                "mutated",
                work_key,
                rel,
                algo,
                expected,
                None,
                "inode_or_mtime_changed_during_hash",
                None,
            )

        if digest_sha256:
            with series_lock:
                series_sha256[rel.replace("\\", "/")] = digest_sha256

        computed_l = computed.lower()
        sidecar_digest_l = str(parsed["file_digest"]).lower()
        if computed_l != sidecar_digest_l:
            return (
                "modified",
                work_key,
                rel,
                algo,
                expected,
                computed_l,
                None,
                _ERR_DATA_DRIFT,
            )

        expected_l = str(expected or "").lower()
        if sidecar_digest_l != expected_l:
            _abort_event.set()
            raise ManifestCompromisedError(
                _ERR_MANIFEST_COMPROMISED,
                rel=rel,
                expected_digest=str(expected or ""),
                sidecar_digest=sidecar_digest_l,
            )

        return ("ok", work_key, rel, algo, expected, None, None, None)

    effective_workers = resolve_manifest_worker_count(max_workers)
    executor = ThreadPoolExecutor(max_workers=effective_workers)
    aborted = False
    try:
        for kind, wk, rel, algo, expected, computed, err, status in executor.map(
            _hash_worker, _work_generator()
        ):
            _check_verify_cancel(should_cancel)
            work_key = wk
            if kind == "modified":
                mrow = {
                    "path": rel,
                    "digest": computed,
                    "expected_digest": expected,
                    "algo": algo,
                    "status": status or "modified",
                }
                rel_key = rel.replace("\\", "/")
                if rel_key in series_sha256:
                    mrow["digest_sha256"] = series_sha256[rel_key]
                if mod_inc_reason:
                    st = status or "modified"
                    mrow["reason"] = err if err is not None else st
                modified.append(mrow)
            elif kind == "mutated":
                mutated.append(
                    {
                        "path": rel,
                        "algo": algo,
                        "reason": err,
                        "status": "mutated",
                    }
                )
            elif kind == "deleted":
                deleted.append({"path": rel, "status": "deleted"})
            elif kind == "skipped":
                skipped.append(
                    {
                        "path": rel,
                        "error": err or "unknown",
                        "status": "skipped",
                    }
                )
            live_paths.pop(work_key, None)
    except ManifestCompromisedError as e:
        aborted = True
        _abort_event.set()
        executor.shutdown(wait=False, cancel_futures=True)
        if compromise_action == "record_and_continue":
            for k in list(live_paths.keys()):
                rel_only = k.split(":", 1)[1] if ":" in k and k[0].isdigit() else k
                if rel_only == (e.rel or ""):
                    live_paths.pop(k, None)
            crow = {
                "path": e.rel or "",
                "expected_digest": e.expected_digest,
                "digest": e.sidecar_digest,
                "status": _ERR_MANIFEST_COMPROMISED,
            }
            if mod_inc_reason:
                crow["reason"] = _ERR_MANIFEST_COMPROMISED
            modified.append(crow)
        else:
            raise
    except KeyboardInterrupt:
        executor.shutdown(wait=False, cancel_futures=True)
        sys.exit(130)
    finally:
        if not aborted:
            executor.shutdown(wait=True)

    # Remaining live_paths keys are "created" drift (extension: verbatim keys; legacy: stripped + filtered).
    for norm_rel in sorted(live_paths.keys()):
        if created_fmt == "stripped_filtered":
            rel_only = norm_rel.split(":", 1)[1] if ":" in norm_rel and norm_rel[0].isdigit() else norm_rel
            rl = rel_only.lower()
            if rl.endswith(".f33") or rl.endswith("/fors33-manifest.json") or rl == "fors33-manifest.json":
                continue
            created.append({"path": rel_only, "status": "created"})
        else:
            created.append({"path": norm_rel, "status": "created"})

    lineage_summary, lineage_extra = _verify_lineage_json_against_manifest(
        manifest_path,
        roots_resolved,
        modified,
        deleted,
    )
    modified.extend(lineage_extra)

    end_monotonic = datetime.now(timezone.utc).timestamp()

    root_display = roots_resolved[0] if roots_resolved else os.path.abspath(root_dir)
    if strip_mount_prefix:
        root_display = _strip_mount_prefix(root_display, strip_mount_prefix)
        roots_resolved = [_strip_mount_prefix(r, strip_mount_prefix) for r in roots_resolved]
    result = {
        "schema_version": schema_version,
        "baseline": str(Path(manifest_path)),
        "root": root_display,
        "roots": roots_resolved if len(roots_resolved) > 1 else None,
        "modified": modified,
        "created": created,
        "deleted": deleted,
        "mutated_during_verification": mutated,
        "skipped": skipped,
        "algo_stats": {
            "default_algo": default_algo,
        },
        "timing": {
            "started_at": start_ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "duration_seconds": max(0.0, end_monotonic - start_monotonic),
        },
        # Mirrors extension semantics: residual live_paths keys after manifest pops (often "created" count).
        "files_scanned": len(live_paths),
        "lineage": lineage_summary,
        "lineage_broken_maps_to_severe_exit": lineage_severe,
        "series_sha256": dict(series_sha256),
        "series_reference": _series_reference_from_manifest(
            manifest, series_sha256, modified
        ),
    }
    return result


def verify_directory_from_sidecars(
    root_dir: str,
    ignore_patterns: Sequence[str] | None = None,
    exclude_dirs: Sequence[str] | None = None,
    follow_symlinks: bool = False,
    verify_tsa: bool = False,
    strip_mount_prefix: str = "",
    regulated_verify: bool = False,
    should_cancel: Callable[[], bool] | None = None,
) -> dict:
    """Verify directory by walking checksum and .f33 sidecar files."""
    import fnmatch

    _check_verify_cancel(should_cancel)

    start_ts = datetime.now(timezone.utc)
    start_monotonic = start_ts.timestamp()
    root = os.path.abspath(root_dir)
    ignore_patterns = tuple(list(ignore_patterns or ()) + _load_f33ignore_patterns(root))
    exclude_dir_set = {d for d in (exclude_dirs or ())}

    def _matches_ignore(path: str) -> bool:
        return any(fnmatch.fnmatch(path, pat) for pat in ignore_patterns)

    verified: List[dict] = []
    failed: List[dict] = []
    skipped: List[dict] = []
    series_sha256: Dict[str, str] = {}
    series_reference: Dict[str, str] = {}

    walk_root = path_for_kernel(root)
    visited_dirs: set[tuple[int, int]] = set()
    if follow_symlinks:
        try:
            st_root = os.stat(walk_root, follow_symlinks=False)
            visited_dirs.add((st_root.st_dev, st_root.st_ino))
        except OSError:
            pass
    for dirpath, dirnames, filenames in os.walk(walk_root, followlinks=follow_symlinks):
        _check_verify_cancel(should_cancel)
        if follow_symlinks:
            keep: list[str] = []
            for d in dirnames:
                if d in exclude_dir_set:
                    continue
                full = os.path.join(dirpath, d)
                try:
                    st = os.stat(path_for_kernel(full), follow_symlinks=True)
                    key = (st.st_dev, st.st_ino)
                    if key in visited_dirs:
                        continue
                    visited_dirs.add(key)
                except OSError:
                    continue
                keep.append(d)
            dirnames[:] = keep
        else:
            dirnames[:] = [d for d in dirnames if d not in exclude_dir_set]
        rel_dir = os.path.relpath(dirpath, walk_root)
        rel_dir = "" if rel_dir == "." else rel_dir
        for name in filenames:
            rel_path = os.path.join(rel_dir, name) if rel_dir else name
            norm_rel = rel_path.replace("\\", "/")
            if _matches_ignore(norm_rel):
                continue
            full_path = os.path.join(dirpath, name)
            lower = name.lower()
            if lower.endswith(".f33"):
                target_name = name[:-4]
                target_rel = (
                    os.path.join(rel_dir, target_name) if rel_dir else target_name
                ).replace("\\", "/")
                target_full = os.path.join(dirpath, target_name)
                try:
                    parsed = _parse_f33(full_path)
                except Exception:
                    parsed = None
                if isinstance(parsed, dict):
                    algo_f33 = str(parsed.get("digest_algo") or "sha256").strip().lower() or "sha256"
                    expected_digest = str(parsed.get("file_digest") or "").strip().lower()
                    if algo_f33 == "sha256" and expected_digest:
                        series_reference[target_rel] = expected_digest
                ktarget = path_for_kernel(target_full)
                hash_path = ktarget if os.path.isfile(ktarget) else target_full
                if os.path.isfile(hash_path):
                    try:
                        _computed, digest_sha256 = _hash_pair_for_series(hash_path, "sha256")
                    except PermissionError:
                        skipped.append({"path": target_rel, "error": "access_denied"})
                        continue
                    except OSError as e:
                        skipped.append({"path": target_rel, "error": str(e)})
                        continue
                    if digest_sha256:
                        series_sha256[target_rel] = digest_sha256
                try:
                    ok, msg = verify_sidecar_f33(
                        full_path, verify_tsa=verify_tsa, regulated_verify=regulated_verify
                    )
                except Exception as e:
                    skipped.append({"path": norm_rel, "error": str(e)})
                    continue
                if ok:
                    verified.append({"path": norm_rel, "type": "f33"})
                else:
                    failed.append({"path": norm_rel, "type": "f33", "reason": msg})
                continue

            for ext, algo in ((".sha256", "sha256"), (".sha512", "sha512"), (".md5", "md5")):
                if lower.endswith(ext):
                    target_rel = norm_rel[: -len(ext)]
                    target_full = os.path.join(dirpath, name[: -len(ext)])
                    if not os.path.isfile(path_for_kernel(target_full)):
                        failed.append(
                            {
                                "path": target_rel or norm_rel,
                                "type": ext.lstrip("."),
                                "reason": "target_missing",
                            }
                        )
                        break
                    try:
                        with open(path_for_kernel(full_path), encoding="utf-8") as sf:
                            first_line = sf.readline().strip()
                        expected = first_line.split()[0]
                    except Exception as e:
                        skipped.append({"path": norm_rel, "error": str(e)})
                        break
                    try:
                        computed, digest_sha256 = _hash_pair_for_series(target_full, algo)
                    except Exception as e:
                        skipped.append({"path": target_rel, "error": str(e)})
                        break
                    target_key = target_rel.replace("\\", "/")
                    if digest_sha256:
                        series_sha256[target_key] = digest_sha256
                    if algo == "sha256":
                        series_reference[target_key] = expected.lower()
                    elif computed.lower() == expected.lower() and digest_sha256:
                        series_reference[target_key] = digest_sha256
                    if computed.lower() == expected.lower():
                        verified.append({"path": target_rel, "type": ext.lstrip(".")})
                    else:
                        failed.append(
                            {
                                "path": target_rel,
                                "type": ext.lstrip("."),
                                "expected": expected.lower(),
                                "computed": computed.lower(),
                            }
                        )
                    break

    modified: List[dict] = []
    for item in failed:
        path = str(item.get("path") or item.get("sidecar") or "")
        reason = str(item.get("reason") or item.get("type") or "verify_failed")
        row: dict = {"path": path, "status": "modified", "reason": reason}
        if item.get("expected"):
            row["expected"] = item["expected"]
        if item.get("computed"):
            row["computed"] = item["computed"]
        modified.append(row)

    root_display = _strip_mount_prefix(root, strip_mount_prefix) if strip_mount_prefix else root
    end_monotonic = datetime.now(timezone.utc).timestamp()
    files_scanned = len(verified) + len(failed)
    return {
        "schema_version": "0.2",
        "baseline": "sidecars",
        "root": root_display,
        "roots": None,
        "modified": modified,
        "created": [],
        "deleted": [],
        "mutated_during_verification": [],
        "skipped": skipped,
        "files_scanned": files_scanned,
        "algo_stats": {"default_algo": "sha256"},
        "timing": {
            "started_at": start_ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "duration_seconds": max(0.0, end_monotonic - start_monotonic),
        },
        "lineage": None,
        "series_sha256": series_sha256,
        "series_reference": series_reference,
    }


def verify_directory_from_bagit(
    bag_root: str,
    strip_mount_prefix: str = "",
    default_algo: str = "sha256",
    should_cancel: Callable[[], bool] | None = None,
) -> dict:
    """Verify an on-disk BagIt bag (RFC 8493 subset: complete + checksum valid)."""
    from manifest_core import BAGIT_PAYLOAD_DIRNAME

    _check_verify_cancel(should_cancel)

    start_ts = datetime.now(timezone.utc)
    start_monotonic = start_ts.timestamp()
    layout = discover_bagit_layout(bag_root)
    if not layout:
        raise ValueError(
            "ERR_VERIFY_BAG_INVALID: Folder is not a complete checksum bundle."
        )
    if layout.has_fetch_txt:
        raise ValueError(
            "ERR_VERIFY_BAG_FETCH_UNSUPPORTED: Remote fetch lists are not supported. "
            "Verify a complete on-disk bundle."
        )

    payload_files: set[str] = set()
    walk_root = path_for_kernel(layout.payload_dir)
    for dirpath, _dirnames, filenames in os.walk(walk_root):
        _check_verify_cancel(should_cancel)
        rel_dir = os.path.relpath(dirpath, walk_root)
        rel_dir = "" if rel_dir == "." else rel_dir.replace("\\", "/")
        for name in filenames:
            rel_payload = f"{rel_dir}/{name}" if rel_dir else name
            norm = f"{BAGIT_PAYLOAD_DIRNAME}/{rel_payload}".replace("\\", "/")
            payload_files.add(norm)

    manifest_sets: list[set[str]] = []
    checks: list[tuple[str, str, str]] = []
    for manifest_path, algo in layout.payload_manifests:
        entries, _roots = load_manifest(manifest_path, fallback_root_dir=layout.bag_root)
        paths: set[str] = set()
        for entry in entries.values():
            norm = str(entry.path or "").replace("\\", "/").lstrip("/")
            if not norm.startswith(f"{BAGIT_PAYLOAD_DIRNAME}/"):
                norm = f"{BAGIT_PAYLOAD_DIRNAME}/{norm}"
            paths.add(norm)
            digest = str(entry.digest or "").strip()
            if digest:
                checks.append((norm, algo, digest.lower()))
        manifest_sets.append(paths)

    if not manifest_sets:
        raise ValueError(
            "ERR_VERIFY_BAG_INCOMPLETE: Bundle is missing payload checksum manifests."
        )
    expected = manifest_sets[0]
    for other in manifest_sets[1:]:
        if other != expected:
            raise ValueError(
                "ERR_VERIFY_BAG_INCOMPLETE: Bundle checksum manifests list different payload files."
            )
    if expected != payload_files:
        raise ValueError(
            "ERR_VERIFY_BAG_INCOMPLETE: Bundle file listing does not match payload on disk."
        )

    modified: List[dict] = []
    created: List[dict] = []
    deleted: List[dict] = []
    files_scanned = 0
    seen_paths: set[str] = set()
    for norm_rel, algo, expected_digest in checks:
        _check_verify_cancel(should_cancel)
        if norm_rel in seen_paths:
            continue
        seen_paths.add(norm_rel)
        member = norm_rel[len(BAGIT_PAYLOAD_DIRNAME) + 1 :]
        full = os.path.join(layout.bag_root, BAGIT_PAYLOAD_DIRNAME, member.replace("/", os.sep))
        if not os.path.isfile(path_for_kernel(full)):
            deleted.append({"path": norm_rel, "status": "deleted"})
            continue
        try:
            computed = hash_file(full, algo=algo or default_algo)
        except OSError as e:
            modified.append({"path": norm_rel, "status": "modified", "reason": str(e)})
            continue
        files_scanned += 1
        if computed.lower() != expected_digest:
            modified.append(
                {
                    "path": norm_rel,
                    "status": "modified",
                    "expected": expected_digest,
                    "computed": computed.lower(),
                }
            )

    root_display = layout.bag_root
    if strip_mount_prefix:
        root_display = _strip_mount_prefix(root_display, strip_mount_prefix)
    end_monotonic = datetime.now(timezone.utc).timestamp()
    return {
        "schema_version": "0.2",
        "baseline": "bagit",
        "root": root_display,
        "roots": None,
        "modified": modified,
        "created": created,
        "deleted": deleted,
        "mutated_during_verification": [],
        "skipped": [],
        "files_scanned": files_scanned,
        "algo_stats": {"default_algo": default_algo},
        "timing": {
            "started_at": start_ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "duration_seconds": max(0.0, end_monotonic - start_monotonic),
        },
        "lineage": None,
    }


def verify_directory_from_checksum_manifest(
    manifest_path: str,
    root_dir: str,
    strip_mount_prefix: str = "",
    default_algo: str = "sha256",
    should_cancel: Callable[[], bool] | None = None,
) -> dict:
    """Verify folder files against a standalone GNU/BSD checksum manifest at root."""
    _check_verify_cancel(should_cancel)
    start_ts = datetime.now(timezone.utc)
    start_monotonic = start_ts.timestamp()
    root = os.path.abspath(root_dir)
    entries, roots = load_manifest(manifest_path, fallback_root_dir=root)
    base = os.path.abspath(roots[0] if roots else root)
    modified: List[dict] = []
    deleted: List[dict] = []
    files_scanned = 0
    for entry in entries.values():
        _check_verify_cancel(should_cancel)
        rel = str(entry.path or "").replace("\\", "/").lstrip("/")
        full = os.path.join(base, rel.replace("/", os.sep))
        expected = str(entry.digest or "").strip().lower()
        algo = infer_algo_from_digest(expected) or default_algo
        if not os.path.isfile(path_for_kernel(full)):
            deleted.append({"path": rel, "status": "deleted"})
            continue
        try:
            computed = hash_file(full, algo=algo)
        except OSError as e:
            modified.append({"path": rel, "status": "modified", "reason": str(e)})
            continue
        files_scanned += 1
        if computed.lower() != expected:
            modified.append(
                {
                    "path": rel,
                    "status": "modified",
                    "expected": expected,
                    "computed": computed.lower(),
                }
            )
    root_display = _strip_mount_prefix(root, strip_mount_prefix) if strip_mount_prefix else root
    end_monotonic = datetime.now(timezone.utc).timestamp()
    return {
        "schema_version": "0.2",
        "baseline": "checksum_manifest",
        "root": root_display,
        "roots": None,
        "modified": modified,
        "created": [],
        "deleted": deleted,
        "mutated_during_verification": [],
        "skipped": [],
        "files_scanned": files_scanned,
        "algo_stats": {"default_algo": default_algo},
        "timing": {
            "started_at": start_ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "duration_seconds": max(0.0, end_monotonic - start_monotonic),
        },
        "lineage": None,
    }


_CHECKSUM_MANIFEST_FILENAMES: tuple[str, ...] = (
    "manifest-sha256.txt",
    "manifest-sha512.txt",
    "manifest-md5.txt",
    "SHA256SUMS",
    "sha256sum.txt",
    "checksums.sha256",
    "checksums.md5",
)


@dataclass(frozen=True)
class VerifyStrategyPlan:
    strategy: str
    root_dir: str
    manifest_path: str = ""


def verify_manifest_bundle_preflight(manifest_path: str, root_dir: str) -> str | None:
    """Customer-safe layout check before manifest verify. None when the bundle looks verifiable."""
    root = os.path.abspath(root_dir)
    try:
        with open(path_for_kernel(manifest_path), encoding="utf-8") as mf:
            raw_doc = json.load(mf)
    except (OSError, json.JSONDecodeError):
        return None
    raw_entries = raw_doc.get("entries") if isinstance(raw_doc, dict) else []
    if not isinstance(raw_entries, list) or not raw_entries:
        return None

    try:
        manifest, _roots = load_manifest(manifest_path, fallback_root_dir=root)
    except Exception:
        return None
    if not manifest:
        return None

    try:
        names = set(os.listdir(root))
    except OSError:
        return None

    manifest_in_folder = any(
        n.startswith("fors33-manifest") and n.endswith(".json") and not n.endswith(".lock")
        for n in names
    )
    if manifest_in_folder:
        for n in names:
            if n.endswith(".jsonl") and f"{n}.f33" not in names:
                return (
                    "ERR_VERIFY_BUNDLE_RENAME: A .jsonl file is missing its matching .f33 sidecar. "
                    "Restore original filenames from your sealed upload."
                )

    sealed_count = 0
    resolved_count = 0
    non_portable_abs = any(
        isinstance(item, dict)
        and _is_manifest_abs_path(str(item.get("path") or "").strip())
        for item in raw_entries
    )

    for entry in manifest.values():
        path_raw = str(entry.path or "").strip().replace("\\", "/")
        if not path_raw:
            continue
        digest = str(entry.digest or "").strip()
        if not digest:
            continue
        sealed_count += 1
        resolved = resolve_manifest_member_path(root, path_raw, basename_fallback=True)
        if resolved and os.path.isfile(resolved):
            resolved_count += 1
            base = os.path.basename(resolved)
            if f"{base}.f33" not in names:
                return (
                    "ERR_VERIFY_BUNDLE_RENAME: A sealed file is missing its matching .f33 sidecar. "
                    "Restore original filenames from your sealed upload."
                )

    if non_portable_abs and resolved_count == 0:
        return (
            "ERR_VERIFY_MANIFEST_NOT_PORTABLE: This manifest lists seal-environment paths that "
            "do not match files in this folder. Use fors33-manifest.json from your storage prefix."
        )
    if sealed_count > 0 and resolved_count == 0:
        return (
            "ERR_VERIFY_BUNDLE_LAYOUT: No sealed files from the manifest were found in this folder. "
            "Check that filenames match your upload."
        )
    return None


def _resolve_verify_manifest_path(root_dir: str, hinted_manifest: str = "") -> tuple[str, str | None]:
    """Return (manifest_path, error_detail). error_detail is customer-safe when set."""
    root = os.path.abspath(root_dir)
    candidates: list[str] = []
    hint = os.path.abspath(str(hinted_manifest or "").strip()) if str(hinted_manifest or "").strip() else ""
    if hint and os.path.isfile(hint):
        candidates.append(hint)
    try:
        for name in sorted(os.listdir(root)):
            if not name.startswith("fors33-manifest"):
                continue
            if not name.endswith(".json") or name.endswith(".lock"):
                continue
            full = os.path.join(root, name)
            if os.path.isfile(full):
                candidates.append(os.path.abspath(full))
    except OSError:
        pass
    unique = sorted(set(candidates))
    if not unique:
        return "", None
    chosen = hint if hint and hint in unique else unique[0]
    preflight = verify_manifest_bundle_preflight(chosen, root)
    if preflight:
        return "", preflight
    return chosen, None


def _discover_checksum_manifest_at_root(root: str) -> str:
    """Return a standalone checksum manifest path at root (non-BagIt)."""
    root_abs = os.path.abspath(root)
    if discover_bagit_layout(root_abs):
        return ""
    try:
        names = set(os.listdir(root_abs))
    except OSError:
        return ""
    for candidate in _CHECKSUM_MANIFEST_FILENAMES:
        if candidate in names:
            full = os.path.join(root_abs, candidate)
            if os.path.isfile(full):
                return os.path.abspath(full)
    for name in sorted(names):
        if name.lower() in ("sha256sums", "md5sums"):
            full = os.path.join(root_abs, name)
            if os.path.isfile(full):
                return os.path.abspath(full)
    return ""


def _folder_has_verifiable_sidecars(root: str) -> bool:
    """True when the folder contains .f33 or checksum sidecars with sibling targets."""
    root_abs = os.path.abspath(root)
    try:
        for _dirpath, _dirnames, filenames in os.walk(root_abs):
            names = set(filenames)
            for name in filenames:
                lower = name.lower()
                if lower.endswith(".f33"):
                    return True
                for ext in (".sha256", ".sha512", ".md5"):
                    if lower.endswith(ext) and name[: -len(ext)] in names:
                        return True
    except OSError:
        return False
    return False


def discover_verify_strategy(
    root_dir: str, hinted_manifest: str = ""
) -> tuple[VerifyStrategyPlan | None, str | None]:
    """Pick verify strategy for root_dir. error_detail is customer-safe when set."""
    root = os.path.abspath(root_dir)
    if not os.path.isdir(path_for_kernel(root)):
        return None, f"Verify root must be a directory: {root}"

    resolved_manifest, resolve_detail = _resolve_verify_manifest_path(root, hinted_manifest)
    if resolve_detail:
        return None, resolve_detail
    if resolved_manifest:
        return VerifyStrategyPlan("fors33_manifest", root, resolved_manifest), None

    if discover_bagit_layout(root):
        return VerifyStrategyPlan("bagit", root), None

    checksum_manifest = _discover_checksum_manifest_at_root(root)
    if checksum_manifest:
        return VerifyStrategyPlan("checksum_manifest", root, checksum_manifest), None

    if _folder_has_verifiable_sidecars(root):
        return VerifyStrategyPlan("sidecars", root), None

    return None, None


def _verification_report_from_result(result: dict) -> VerificationReport:
    return VerificationReport(
        modified=result["modified"],
        created=result["created"],
        deleted=result["deleted"],
        skipped=result["skipped"],
        mutated=result.get("mutated_during_verification") or [],
        schema_version=result["schema_version"],
        baseline=result["baseline"],
        root=result["root"],
        roots=result.get("roots"),
        timing=result["timing"],
        files_scanned=int(result.get("files_scanned", 0)),
        lineage=result.get("lineage"),
        series_sha256=result.get("series_sha256") if isinstance(result.get("series_sha256"), dict) else None,
        series_reference=result.get("series_reference") if isinstance(result.get("series_reference"), dict) else None,
    )


def execute_verification_sidecars(
    root_dir: str,
    ignore_patterns: Sequence[str] | None = None,
    exclude_dirs: Sequence[str] | None = None,
    follow_symlinks: bool = False,
    verify_tsa: bool = False,
    progress_event_callback: Callable[[dict], None] | None = None,
    strip_mount_prefix: str = "",
    regulated_verify: bool = False,
    should_cancel: Callable[[], bool] | None = None,
) -> VerificationReport:
    """Library entry: verify directory via sidecar files (.f33, .sha256, etc.)."""
    void = progress_event_callback
    if void:
        void({"event": "verify_mode", "mode": "sidecars"})
    result = verify_directory_from_sidecars(
        root_dir=root_dir,
        ignore_patterns=ignore_patterns,
        exclude_dirs=exclude_dirs,
        follow_symlinks=follow_symlinks,
        verify_tsa=verify_tsa,
        strip_mount_prefix=strip_mount_prefix,
        regulated_verify=regulated_verify,
        should_cancel=should_cancel,
    )
    return _verification_report_from_result(result)


def execute_verification_bagit(
    bag_root: str,
    strip_mount_prefix: str = "",
    default_algo: str = "sha256",
    progress_event_callback: Callable[[dict], None] | None = None,
    should_cancel: Callable[[], bool] | None = None,
) -> VerificationReport:
    """Library entry: verify on-disk BagIt bag."""
    if progress_event_callback:
        progress_event_callback({"event": "verify_mode", "mode": "bagit"})
    result = verify_directory_from_bagit(
        bag_root=bag_root,
        strip_mount_prefix=strip_mount_prefix,
        default_algo=default_algo,
        should_cancel=should_cancel,
    )
    return _verification_report_from_result(result)


def execute_verification_checksum_manifest(
    manifest_path: str,
    root_dir: str,
    strip_mount_prefix: str = "",
    default_algo: str = "sha256",
    progress_event_callback: Callable[[dict], None] | None = None,
    should_cancel: Callable[[], bool] | None = None,
) -> VerificationReport:
    """Library entry: verify via standalone checksum manifest (GNU/BSD)."""
    if progress_event_callback:
        progress_event_callback({"event": "verify_mode", "mode": "checksum_manifest"})
    result = verify_directory_from_checksum_manifest(
        manifest_path=manifest_path,
        root_dir=root_dir,
        strip_mount_prefix=strip_mount_prefix,
        default_algo=default_algo,
        should_cancel=should_cancel,
    )
    return _verification_report_from_result(result)



def execute_verification(
    manifest_path: str,
    root_dir: str,
    default_algo: str = "sha256",
    ignore_patterns: Sequence[str] | None = None,
    exclude_dirs: Sequence[str] | None = None,
    follow_symlinks: bool = False,
    force_insecure: bool = False,
    progress_event_callback: Callable[[dict], None] | None = None,
    strip_mount_prefix: str = "",
    verify_tsa: bool = False,
    max_workers: Optional[int] = None,
    *,
    legacy_manifest_json: bool = False,
    manifest_compromise_action: Literal["fail_fast", "record_and_continue"] = "fail_fast",
    created_paths_format: Literal["extension", "stripped_filtered"] = "extension",
    manifest_modified_include_reason: bool = False,
    lineage_broken_maps_to_severe_exit: bool = True,
    should_cancel: Callable[[], bool] | None = None,
) -> VerificationReport:
    """
    Library entry point: verify directory against manifest.

    Returns VerificationReport with modified, created, deleted, skipped, mutated.
    When progress_event_callback is set, emits JSON progress events for headless streaming.

    Compatibility kwargs mirror ``verify_directory_from_manifest``; see that docstring.
    """
    result = verify_directory_from_manifest(
        manifest_path=manifest_path,
        root_dir=root_dir,
        default_algo=default_algo,
        ignore_patterns=ignore_patterns,
        exclude_dirs=exclude_dirs,
        follow_symlinks=follow_symlinks,
        force_insecure=force_insecure,
        progress_event_callback=progress_event_callback,
        strip_mount_prefix=strip_mount_prefix,
        verify_tsa=verify_tsa,
        max_workers=max_workers,
        legacy_manifest_json=legacy_manifest_json,
        manifest_compromise_action=manifest_compromise_action,
        created_paths_format=created_paths_format,
        manifest_modified_include_reason=manifest_modified_include_reason,
        lineage_broken_maps_to_severe_exit=lineage_broken_maps_to_severe_exit,
        should_cancel=should_cancel,
    )
    return VerificationReport(
        modified=result["modified"],
        created=result["created"],
        deleted=result["deleted"],
        skipped=result["skipped"],
        mutated=result["mutated_during_verification"],
        schema_version=result["schema_version"],
        baseline=result["baseline"],
        root=result["root"],
        roots=result.get("roots"),
        timing=result["timing"],
        files_scanned=int(result.get("files_scanned", 0)),
        lineage=result.get("lineage"),
        lineage_broken_maps_to_severe_exit=bool(
            result.get("lineage_broken_maps_to_severe_exit", True)
        ),
        series_sha256=result.get("series_sha256") if isinstance(result.get("series_sha256"), dict) else None,
        series_reference=result.get("series_reference") if isinstance(result.get("series_reference"), dict) else None,
    )


def execute_verification_single(
    target_name: str,
    computed: str,
    expected: str,
) -> int:
    """Standardized logic for comparing and logging the output in single mode."""
    computed_lower = computed.lower()
    expected_lower = expected.lower().strip()

    if computed_lower == expected_lower:
        _log_output(target_name, computed_lower, "VERIFIED")
        return 0

    _log_output(target_name, computed_lower, "MISMATCH")
    print(f"MISMATCH: expected {expected_lower}, got {computed_lower}", file=sys.stderr)
    return 1


def _verify_detached_signature_bytes(pdf_bytes: bytes, sig_bytes: bytes, pubkey_pem: bytes) -> None:
    """Verify Ed25519 detached signature on PDF bytes using public key."""
    from cryptography.hazmat.primitives import serialization
    
    public_key = serialization.load_pem_public_key(pubkey_pem)
    pdf_hash = hashlib.sha256(pdf_bytes).digest()
    public_key.verify(sig_bytes, pdf_hash)


def _extract_and_verify_zip(zip_path: str) -> dict:
    """Extract audit package files from ZIP in memory and verify signature (zero-copy, no disk I/O).
    
    Returns:
        dict: {'success': bool, 'error': str | None}
    """
    import zipfile
    
    pdf_bytes = None
    sig_bytes = None
    pubkey_pem = None
    
    try:
        with zipfile.ZipFile(path_for_kernel(zip_path), 'r') as z:
            for name in z.namelist():
                if name.lower().endswith('.pdf'):
                    pdf_bytes = z.read(name)
                elif name.lower().endswith('.sig'):
                    sig_bytes = z.read(name)
                elif name.lower().endswith('.pem'):
                    pubkey_pem = z.read(name)
    except Exception as e:
        return {'success': False, 'error': f"Failed to read ZIP archive: {e}"}
    
    if pdf_bytes is None:
        return {'success': False, 'error': "[FAILURE] No PDF file found in audit package ZIP"}
    if sig_bytes is None:
        return {'success': False, 'error': "[FAILURE] No signature file (.sig) found in audit package ZIP"}
    if pubkey_pem is None:
        return {'success': False, 'error': "[FAILURE] No public key file (.pem) found in audit package ZIP"}
    
    try:
        _verify_detached_signature_bytes(pdf_bytes, sig_bytes, pubkey_pem)
        return {'success': True, 'error': None}
    except Exception as e:
        return {'success': False, 'error': f"[FAILURE] Signature verification failed: {e}"}


def _discover_and_verify_pdf(pdf_path: str) -> dict:
    """Discover .sig and .pem files in same directory as PDF and verify signature.
    
    Returns:
        dict: {'success': bool, 'error': str | None}
    """
    pdf_dir = os.path.dirname(os.path.abspath(pdf_path))
    pdf_name = os.path.splitext(os.path.basename(pdf_path))[0]
    
    sig_path = os.path.join(pdf_dir, f"{pdf_name}.sig")
    pubkey_path = os.path.join(pdf_dir, f"{pdf_name}.pem")

    if not os.path.isfile(path_for_kernel(sig_path)):
        return {'success': False, 'error': "[FAILURE] Missing cryptographic signature. Ensure the .sig and .pem files reside in the same directory as the PDF."}
    if not os.path.isfile(path_for_kernel(pubkey_path)):
        fallback = os.path.join(pdf_dir, "public_key.pem")
        if os.path.isfile(path_for_kernel(fallback)):
            pubkey_path = fallback
        else:
            return {'success': False, 'error': "[FAILURE] Missing cryptographic signature. Ensure the .sig and .pem files reside in the same directory as the PDF."}
    
    try:
        with open(path_for_kernel(pdf_path), 'rb') as f:
            pdf_bytes = f.read()
        with open(path_for_kernel(sig_path), 'rb') as f:
            sig_bytes = f.read()
        with open(path_for_kernel(pubkey_path), 'rb') as f:
            pubkey_pem = f.read()
    except OSError as e:
        return {'success': False, 'error': f"[FAILURE] Failed to read files: {e}"}
    
    try:
        _verify_detached_signature_bytes(pdf_bytes, sig_bytes, pubkey_pem)
        return {'success': True, 'error': None}
    except Exception as e:
        return {'success': False, 'error': f"[FAILURE] Signature verification failed: {e}"}


def _verify_sealed_dataset(dataset_path: str) -> dict:
    """Verify a sealed dataset by finding and validating its receipt.
    
    Args:
        dataset_path: Path to directory containing manifest.json and .f33-receipt
    
    Returns:
        dict: {'success': bool, 'error': str | None}
    """
    try:
        from receipt_core import verify_receipt
    except ImportError:
        return {'success': False, 'error': "[FAILURE] receipt_core module not available"}
    
    # Look for .f33-receipt file in the directory
    receipt_path = None
    try:
        for file in os.listdir(path_for_kernel(dataset_path)):
            if file.endswith('.f33-receipt'):
                receipt_path = os.path.join(dataset_path, file)
                break
    except OSError as e:
        return {'success': False, 'error': f"[FAILURE] Failed to read directory: {e}"}
    
    if not receipt_path:
        return {'success': False, 'error': "[FAILURE] No receipt file (.f33-receipt) found in dataset directory"}
    
    try:
        success = verify_receipt(receipt_path, dataset_path)
        return {'success': success, 'error': None}
    except Exception as e:
        return {'success': False, 'error': f"[FAILURE] Receipt verification failed: {e}"}


def _verify_pdf_package(package: dict) -> dict:
    """Verify a PDF audit package for batch mode.
    
    Args:
        package: dict with 'path' key
    
    Returns:
        dict: {'success': bool, 'error': str | None}
    """
    return _discover_and_verify_pdf(package['path'])


def _verify_zip_package(package: dict) -> dict:
    """Verify a ZIP audit package for batch mode.
    
    Args:
        package: dict with 'path' key
    
    Returns:
        dict: {'success': bool, 'error': str | None}
    """
    return _extract_and_verify_zip(package['path'])


def _verify_sealed_package(package: dict, args) -> dict:
    """Verify a sealed dataset package for batch mode.
    
    Args:
        package: dict with 'path' key
        args: CLI arguments (unused but for consistency)
    
    Returns:
        dict: {'success': bool, 'error': str | None}
    """
    return _verify_sealed_dataset(package['path'])


def _verify_batch_directory(directory: str, args) -> int:
    """Verify all audit packages in a directory with concurrent processing.
    
    Args:
        directory: Path to directory containing audit packages
        args: CLI arguments
    
    Returns:
        int: Exit code (EXIT_OK if all pass, EXIT_DRIFT if any fail)
    """
    import concurrent.futures
    
    # Discover audit packages
    audit_packages = []
    for root, dirs, files in os.walk(directory):
        # Standalone PDF files
        for file in files:
            if file.lower().endswith('.pdf'):
                audit_packages.append({'type': 'pdf', 'path': os.path.join(root, file)})
            elif file.lower().endswith('.zip'):
                audit_packages.append({'type': 'zip', 'path': os.path.join(root, file)})
        # Directories with fors33-manifest.json or manifest.json (sealed datasets)
        if 'fors33-manifest.json' in files or 'manifest.json' in files:
            audit_packages.append({'type': 'sealed', 'path': root})
    
    with print_lock:
        print(f"[BATCH VERIFY] Scanning directory: {directory}")
        print(f"[BATCH VERIFY] Found {len(audit_packages)} audit packages")
    
    if not audit_packages:
        with print_lock:
            print("[BATCH VERIFY] No audit packages found")
        return EXIT_OK
    
    # Hardware-limited concurrency
    worker_count = resolve_manifest_worker_count(args.workers)
    with print_lock:
        print(f"[BATCH VERIFY] Using {worker_count} workers for concurrent processing")
    
    results = []
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        future_to_package = {}
        for package in audit_packages:
            if package['type'] == 'pdf':
                future = executor.submit(_verify_pdf_package, package)
            elif package['type'] == 'zip':
                future = executor.submit(_verify_zip_package, package)
            elif package['type'] == 'sealed':
                future = executor.submit(_verify_sealed_package, package, args)
            future_to_package[future] = package
        
        # Reap futures as they complete
        for future in concurrent.futures.as_completed(future_to_package):
            package = future_to_package[future]
            try:
                result_dict = future.result()
                results.append(BatchVerificationResult(
                    file_path=package['path'],
                    package_type=package['type'],
                    status='SUCCESS' if result_dict['success'] else 'ERROR',
                    error_message=result_dict.get('error')
                ))
                with print_lock:
                    if result_dict['success']:
                        print(f"[BATCH VERIFY] {os.path.basename(package['path'])}: PASS")
                    else:
                        print(f"[BATCH VERIFY] {os.path.basename(package['path'])}: FAIL - {result_dict.get('error', 'Unknown error')}")
            except Exception as exc:
                results.append(BatchVerificationResult(
                    file_path=package['path'],
                    package_type=package['type'],
                    status='ERROR',
                    error_message=str(exc)
                ))
                with print_lock:
                    print(f"[BATCH VERIFY] {os.path.basename(package['path'])}: ERROR - {str(exc)}")
    
    # Generate summary
    passed = sum(1 for r in results if r.status == 'SUCCESS')
    failed = sum(1 for r in results if r.status == 'ERROR')
    
    if args.json:
        # JSON output
        summary = {
            "total_packages": len(results),
            "passed": passed,
            "failed": failed,
            "results": [
                {
                    "path": r.file_path,
                    "type": r.package_type,
                    "status": r.status,
                    "error": r.error_message
                }
                for r in results
            ]
        }
        print(json.dumps(summary, indent=2))
    else:
        # Text output
        print()
        print("[BATCH VERIFY SUMMARY]")
        print(f"[BATCH VERIFY] Total packages: {len(results)}")
        print(f"[BATCH VERIFY] Passed: {passed}")
        print(f"[BATCH VERIFY] Failed: {failed}")
        
        if failed > 0:
            print()
            print("[BATCH VERIFY] Failed packages:")
            for r in results:
                if r.status == 'ERROR':
                    print(f"[BATCH VERIFY]   {os.path.basename(r.file_path)}: {r.error_message}")
    
    return EXIT_OK if failed == 0 else EXIT_DRIFT


def main() -> int:
    _print_compliance_notice()
    parser = argparse.ArgumentParser(
        description="Verify attested data (Fors33 Verifier)"
    )
    parser.add_argument(
        "--mode",
        choices=["single", "manifest", "sidecars", "bagit", "checksum_manifest", "auto"],
        default="single",
        help="Verification mode: single (default), manifest, sidecars, bagit, checksum_manifest, or auto.",
    )
    # Single-file / URL mode (backwards-compatible)
    parser.add_argument("--url", help="HTTPS presigned URL to download and verify")
    parser.add_argument("--file", help="Local file path")
    parser.add_argument("--expected-hash", help="Expected hex digest (algo inferred by length unless --algo is set)")
    parser.add_argument("--start", type=int, help="Starting byte offset (optional)")
    parser.add_argument("--end", type=int, help="Ending byte offset (optional)")
    parser.add_argument(
        "--record",
        help="Attestation record JSON (overrides --start/--end when provided)",
    )
    parser.add_argument(
        "--sidecar",
        help="Path to .f33 sidecar file (verifies SHA-256 + Ed25519) in single mode",
    )
    parser.add_argument(
        "--root",
        dest="root_dir",
        help="Target directory for verification (manifest/sidecars modes) or sidecar target dir.",
    )
    parser.add_argument(
        "--target-dir",
        dest="target_dir_deprecated",
        help=argparse.SUPPRESS,
    )

    # Shared options
    parser.add_argument(
        "--algo",
        help="Hash algorithm to use (sha256, sha512, blake3). Default inferred from digest length.",
    )
    parser.add_argument(
        "--force-insecure",
        action="store_true",
        help="Allow MD5/SHA-1 (deprecated). Without this, weak algorithms are rejected.",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format for structured modes (manifest/sidecars).",
    )
    parser.add_argument(
        "--follow-symlinks",
        action="store_true",
        help="Follow symbolic links when walking directories in manifest/sidecars modes.",
    )
    parser.add_argument(
        "--ignore-pattern",
        action="append",
        default=[],
        help="Glob pattern to ignore paths during directory or sidecar walks (can be specified multiple times).",
    )
    parser.add_argument(
        "--exclude-dir",
        action="append",
        default=[],
        help="Directory name to exclude from walks (can be specified multiple times).",
    )
    parser.add_argument(
        "--strip-mount-prefix",
        metavar="PREFIX",
        default="",
        help="Strip this prefix from roots and paths in stored/logged/JSON output (e.g. Docker host-mount).",
    )
    parser.add_argument(
        "--verify-manifest-sig",
        help="Path to detached Base64-encoded Ed25519 signature for the manifest (manifest mode).",
    )
    parser.add_argument(
        "--pubkey",
        help="Path to Ed25519 public key file for manifest signature verification.",
    )
    parser.add_argument(
        "--verify-tsa",
        action="store_true",
        help="Verify optional TSA signature block when present in JSON .f33 sidecars.",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=None,
        help="Thread pool size for --mode manifest (default: auto; capped at 64).",
    )
    parser.add_argument(
        "--legacy-manifest-json",
        action="store_true",
        help=(
            "OSS 0.8.x-style manifest output: record manifest compromise in modified and continue, "
            "strip created paths, include modified.reason, do not map broken lineage alone to exit 3 "
            "(same as FORS33_VERIFIER_LEGACY_MANIFEST_JSON=1)."
        ),
    )
    parser.add_argument(
        "--emit-report",
        action="store_true",
        help="Emit a one-line executive summary report.",
    )
    parser.add_argument(
        "--warn-only",
        action="store_true",
        help="Report all drift/tampering but always exit with code 0.",
    )
    parser.add_argument(
        "--verify-receipt",
        help=(
            "Path to .f33-receipt file for standalone verification "
            "(requires --root for the dataset directory containing fors33-manifest.json)."
        ),
    )
    parser.add_argument(
        "--audit-package",
        help="Path to PDF file for audit package verification (detached signature mode).",
    )
    parser.add_argument(
        "--sig",
        help="Path to detached signature file (.sig) for audit package verification.",
    )
    parser.add_argument(
        "--directory",
        help="Directory containing multiple audit packages for batch verification mode.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit batch verification summary in JSON format (separate from --format used by manifest/sidecars modes).",
    )
    args = parser.parse_args()

    # Environment overrides (FORS33_*)
    if os.environ.get("FORS33_ALGO"):
        args.algo = os.environ["FORS33_ALGO"].strip().lower()
    if os.environ.get("FORS33_ROOT") and not getattr(args, "root_dir", None) and not getattr(args, "target_dir_deprecated", None):
        args.root_dir = os.environ["FORS33_ROOT"].strip()
    if _env_bool("FORS33_FOLLOW_SYMLINKS"):
        args.follow_symlinks = True
    if os.environ.get("FORS33_IGNORE_PATTERN"):
        pats = [p.strip() for p in os.environ["FORS33_IGNORE_PATTERN"].split(",") if p.strip()]
        args.ignore_pattern = list(args.ignore_pattern or []) + pats
    if os.environ.get("FORS33_EXCLUDE_DIR"):
        dirs = [d.strip() for d in os.environ["FORS33_EXCLUDE_DIR"].split(",") if d.strip()]
        args.exclude_dir = list(args.exclude_dir or []) + dirs
    target_dir = getattr(args, "root_dir", None) or getattr(args, "target_dir_deprecated", None)

    if args.algo == "blake3":
        try:
            import blake3  # noqa: F401
        except ImportError:
            print("[ERROR] --algo blake3 requires the blake3 package. pip install blake3", file=sys.stderr)
            return EXIT_USAGE

    if not args.force_insecure and args.algo and args.algo.lower() in ("md5", "sha1"):
        print(
            "[ERROR] MD5 and SHA-1 are deprecated. Use sha256, sha512, or blake3. Override with --force-insecure for legacy.",
            file=sys.stderr,
        )
        return EXIT_USAGE

    reg_path = str(os.environ.get("F33_KEY_REGISTRY_PATH") or "").strip()
    if reg_path:
        kreg = path_for_kernel(reg_path)
        if not os.path.isfile(kreg):
            print("[ERROR] F33_KEY_REGISTRY_PATH is set but the file does not exist.", file=sys.stderr)
            return EXIT_USAGE
        try:
            with open(kreg, encoding="utf-8") as rf:
                rf.read(1)
        except OSError as e:
            print(f"[ERROR] F33_KEY_REGISTRY_PATH is not readable: {e}", file=sys.stderr)
            return EXIT_USAGE

    # Mutual exclusivity checks for batch mode
    if args.directory and args.file:
        print("[ERROR] --directory and --file cannot be used together", file=sys.stderr)
        return EXIT_USAGE
    if args.directory and args.mode in ("manifest", "sidecars", "bagit", "checksum_manifest"):
        print(
            "[ERROR] --directory cannot be used with --mode manifest, sidecars, bagit, checksum_manifest, or auto",
            file=sys.stderr,
        )
        return EXIT_USAGE

    # Handle standalone receipt verification
    if args.verify_receipt:
        if not target_dir:
            print("[ERROR] --root must be provided with --verify-receipt", file=sys.stderr)
            return EXIT_USAGE
        try:
            from receipt_core import verify_receipt
            ok = verify_receipt(args.verify_receipt, target_dir)
            return EXIT_OK if ok else EXIT_DRIFT
        except Exception as e:
            print(f"[ERROR] Receipt verification failed: {e}", file=sys.stderr)
            return EXIT_SEVERE

    # Handle audit package verification with explicit flags
    if args.audit_package:
        if not args.sig or not args.pubkey:
            print("[ERROR] --sig and --pubkey are required with --audit-package", file=sys.stderr)
            return EXIT_USAGE
        try:
            with open(path_for_kernel(args.audit_package), 'rb') as f:
                pdf_bytes = f.read()
            with open(path_for_kernel(args.sig), 'rb') as f:
                sig_bytes = f.read()
            with open(path_for_kernel(args.pubkey), 'rb') as f:
                pubkey_pem = f.read()
            _verify_detached_signature_bytes(pdf_bytes, sig_bytes, pubkey_pem)
            print("[SUCCESS] Audit package signature verified")
            return EXIT_OK
        except Exception as e:
            print(f"[ERROR] Audit package verification failed: {e}", file=sys.stderr)
            return EXIT_SEVERE

    # Smart routing: if --file ends in .zip or .pdf AND no expected hash is provided, route to audit package
    if args.file and not args.expected_hash and not args.record:
        if args.file.lower().endswith('.zip'):
            result = _extract_and_verify_zip(args.file)
            if result['success']:
                print("[SUCCESS] Audit package signature verified")
                return EXIT_OK
            else:
                print(f"[ERROR] Audit package verification failed: {result['error']}", file=sys.stderr)
                return EXIT_SEVERE
        elif args.file.lower().endswith('.pdf'):
            result = _discover_and_verify_pdf(args.file)
            if result['success']:
                print("[SUCCESS] Audit package signature verified")
                return EXIT_OK
            else:
                print(f"[ERROR] Audit package verification failed: {result['error']}", file=sys.stderr)
                return EXIT_SEVERE

    # Batch verification mode
    if args.directory:
        return _verify_batch_directory(args.directory, args)

    # Legacy single-file sidecar verification path (backwards compatible).
    if args.mode == "single" and args.sidecar:
        try:
            ok, msg = verify_sidecar_f33(args.sidecar, target_dir, verify_tsa=args.verify_tsa)
        except Exception as e:
            print(f"Sidecar verification error: {e}", file=sys.stderr)
            return EXIT_USAGE
        target_label = args.sidecar
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        print(f"[SYS.TIME]  : {ts}", file=sys.stderr)
        print(f"[SIDECAR]   : {target_label}", file=sys.stderr)
        print(f"[STATUS]    : {msg}", file=sys.stderr)
        print(f"[NOTICE]    : {_CTA}", file=sys.stderr)
        return EXIT_OK if (ok or args.warn_only) else EXIT_DRIFT

    if args.mode == "auto":
        root = os.path.abspath(target_dir or os.getcwd())
        hinted = str(args.file or "").strip()
        plan, detail = discover_verify_strategy(root, hinted_manifest=hinted)
        if detail:
            print(f"[ERROR] {detail}", file=sys.stderr)
            return EXIT_SEVERE
        if plan is None:
            print(
                "[ERROR] --mode auto: no fors33 manifest, BagIt layout, checksum manifest, or sidecars found.",
                file=sys.stderr,
            )
            return EXIT_USAGE
        if plan.strategy == "fors33_manifest":
            args.mode = "manifest"
            args.file = plan.manifest_path
            if not target_dir:
                args.root_dir = plan.root_dir
        elif plan.strategy == "bagit":
            args.mode = "bagit"
            if not target_dir:
                args.root_dir = plan.root_dir
        elif plan.strategy == "checksum_manifest":
            args.mode = "checksum_manifest"
            args.file = plan.manifest_path
            if not target_dir:
                args.root_dir = plan.root_dir
        elif plan.strategy == "sidecars":
            args.mode = "sidecars"
            if not target_dir:
                args.root_dir = plan.root_dir

    if args.mode == "manifest":
        if not args.file:
            print("[ERROR] --file must point to the manifest path in --mode manifest.", file=sys.stderr)
            return EXIT_USAGE
        manifest_path = args.file
        root_dir = target_dir or os.path.dirname(os.path.abspath(manifest_path)) or "."
        default_algo = args.algo or "sha256"

        signature_result = None
        if args.verify_manifest_sig or args.pubkey:
            if not (args.verify_manifest_sig and args.pubkey):
                print(
                    "Error: --verify-manifest-sig and --pubkey must both be provided for manifest signature verification.",
                    file=sys.stderr,
                )
                return EXIT_USAGE
            ok_sig, msg_sig = _verify_manifest_ed25519_signature(
                manifest_path, args.verify_manifest_sig, args.pubkey
            )
            signature_result = {"verified": ok_sig, "message": msg_sig}
            if not ok_sig:
                print(f"[WARNING] Manifest signature check failed: {msg_sig}", file=sys.stderr)

        ignore_list = list(args.ignore_pattern or []) + _load_f33ignore_patterns(root_dir)
        ignore_list.extend(["*.f33", "fors33-manifest.json", "**/fors33-manifest.json"])
        ignore_list.extend(
            [
                "metrics-template.json",
                "**/metrics-template.json",
                "integrity_provenance.json",
                "integrity_provenance_*.json",
                "epoch_attestation.json",
                "epoch_attestation.sig",
                "epoch_attestation_public.pem",
                "epoch_attestation_*.json",
                "epoch_attestation_*.sig",
                "epoch_attestation_*_public.pem",
            ]
        )
        try:
            worker_n = resolve_manifest_worker_count(args.workers)
        except ValueError as e:
            print(f"[ERROR] {e}", file=sys.stderr)
            return EXIT_USAGE
        try:
            report = execute_verification(
                manifest_path=manifest_path,
                root_dir=root_dir,
                default_algo=default_algo,
                ignore_patterns=ignore_list,
                exclude_dirs=args.exclude_dir,
                follow_symlinks=args.follow_symlinks,
                force_insecure=args.force_insecure,
                progress_event_callback=None,
                strip_mount_prefix=args.strip_mount_prefix or "",
                verify_tsa=args.verify_tsa,
                max_workers=worker_n,
                legacy_manifest_json=args.legacy_manifest_json,
            )
            result = {
                "schema_version": report.schema_version,
                "baseline": report.baseline,
                "root": report.root,
                "roots": report.roots,
                "modified": report.modified,
                "created": report.created,
                "deleted": report.deleted,
                "mutated_during_verification": report.mutated,
                "skipped": report.skipped,
                "timing": report.timing,
                "files_scanned": report.files_scanned,
                "lineage": report.lineage,
                "lineage_broken_maps_to_severe_exit": report.lineage_broken_maps_to_severe_exit,
            }
        except Exception as e:
            print(f"Manifest verification failed: {e}", file=sys.stderr)
            return EXIT_SEVERE

        if signature_result is not None:
            result["manifest_signature"] = signature_result

        modified = result.get("modified") or []
        created = result.get("created") or []
        deleted = result.get("deleted") or []
        mutated = result.get("mutated_during_verification") or []
        drift_detected = bool(modified or created or deleted or mutated)

        summary_line = (
            f"Baseline: {manifest_path} | Root: {root_dir} | "
            f"Modified: {len(modified)} | Created: {len(created)} | Deleted: {len(deleted)}"
        )

        if args.format == "json":
            if args.emit_report:
                result["summary"] = summary_line
                print(summary_line, file=sys.stderr)
            print(json.dumps(result))
        else:
            print(summary_line, file=sys.stderr)
            for m in result.get("modified") or []:
                p = m.get("path", "")
                print(f"  [MISMATCH] {p}" if not sys.stderr.isatty() else f"  \033[1;31m[MISMATCH]\033[0m {p}", file=sys.stderr)
            for m in result.get("mutated_during_verification") or []:
                p = m.get("path", "")
                status_line = f"  [TAMPERED] {p}" if not sys.stderr.isatty() else f"  \033[1;31m[TAMPERED]\033[0m {p}"
                print(status_line, file=sys.stderr)
                print("    (File changed during hash; may be active log. Verify manually if tampering suspected.)", file=sys.stderr)
            for c in result.get("created") or []:
                p = c.get("path", "")
                print(f"  [CREATED] {p}", file=sys.stderr)
            for d in result.get("deleted") or []:
                p = d.get("path", "")
                print(f"  [DELETED] {p}", file=sys.stderr)
            for s in result.get("skipped") or []:
                p = s.get("path", "")
                print(f"  [SKIPPED] {p}" if not sys.stderr.isatty() else f"  \033[90m[SKIPPED]\033[0m {p}", file=sys.stderr)

        exit_code = EXIT_DRIFT if drift_detected else EXIT_OK
        severe_statuses = {
            _ERR_BAD_SIGNATURE,
            _ERR_MANIFEST_COMPROMISED,
            _ERR_TSA_INVALID,
        }
        if any(str(m.get("status", "")) in severe_statuses for m in modified):
            exit_code = EXIT_SEVERE
        lin = result.get("lineage")
        if (
            result.get("lineage_broken_maps_to_severe_exit", True)
            and isinstance(lin, dict)
            and lin.get("status") == "broken"
        ):
            exit_code = EXIT_SEVERE
        if args.warn_only:
            return EXIT_OK
        return exit_code


    if args.mode == "bagit":
        root = os.path.abspath(target_dir or args.file or os.getcwd())
        try:
            report = execute_verification_bagit(
                root,
                strip_mount_prefix=args.strip_mount_prefix or "",
                default_algo=args.algo or "sha256",
            )
            result = {
                "schema_version": report.schema_version,
                "baseline": report.baseline,
                "root": report.root,
                "modified": report.modified,
                "created": report.created,
                "deleted": report.deleted,
                "mutated_during_verification": report.mutated,
                "skipped": report.skipped,
                "timing": report.timing,
                "files_scanned": report.files_scanned,
            }
        except Exception as e:
            print(f"BagIt verification failed: {e}", file=sys.stderr)
            return EXIT_SEVERE

        modified = result.get("modified") or []
        created = result.get("created") or []
        deleted = result.get("deleted") or []
        mutated = result.get("mutated_during_verification") or []
        drift_detected = bool(modified or created or deleted or mutated)
        summary_line = (
            f"Baseline: bagit | Root: {root} | "
            f"Modified: {len(modified)} | Created: {len(created)} | Deleted: {len(deleted)}"
        )
        if args.format == "json":
            if args.emit_report:
                result["summary"] = summary_line
                print(summary_line, file=sys.stderr)
            print(json.dumps(result))
        else:
            print(summary_line, file=sys.stderr)
        exit_code = EXIT_DRIFT if drift_detected else EXIT_OK
        if args.warn_only:
            return EXIT_OK
        return exit_code

    if args.mode == "checksum_manifest":
        if not args.file:
            print(
                "[ERROR] --file must point to the checksum manifest in --mode checksum_manifest.",
                file=sys.stderr,
            )
            return EXIT_USAGE
        manifest_path = args.file
        root_dir = target_dir or os.path.dirname(os.path.abspath(manifest_path)) or "."
        try:
            report = execute_verification_checksum_manifest(
                manifest_path=manifest_path,
                root_dir=root_dir,
                strip_mount_prefix=args.strip_mount_prefix or "",
                default_algo=args.algo or "sha256",
            )
            result = {
                "schema_version": report.schema_version,
                "baseline": report.baseline,
                "root": report.root,
                "modified": report.modified,
                "created": report.created,
                "deleted": report.deleted,
                "mutated_during_verification": report.mutated,
                "skipped": report.skipped,
                "timing": report.timing,
                "files_scanned": report.files_scanned,
            }
        except Exception as e:
            print(f"Checksum manifest verification failed: {e}", file=sys.stderr)
            return EXIT_SEVERE

        modified = result.get("modified") or []
        created = result.get("created") or []
        deleted = result.get("deleted") or []
        mutated = result.get("mutated_during_verification") or []
        drift_detected = bool(modified or created or deleted or mutated)
        summary_line = (
            f"Baseline: checksum_manifest | Manifest: {manifest_path} | Root: {root_dir} | "
            f"Modified: {len(modified)} | Created: {len(created)} | Deleted: {len(deleted)}"
        )
        if args.format == "json":
            if args.emit_report:
                result["summary"] = summary_line
                print(summary_line, file=sys.stderr)
            print(json.dumps(result))
        else:
            print(summary_line, file=sys.stderr)
        exit_code = EXIT_DRIFT if drift_detected else EXIT_OK
        if args.warn_only:
            return EXIT_OK
        return exit_code

    if args.mode == "sidecars":
        root = os.path.abspath(target_dir or args.file or os.getcwd())
        report = execute_verification_sidecars(
            root,
            ignore_patterns=args.ignore_pattern,
            exclude_dirs=args.exclude_dir,
            follow_symlinks=args.follow_symlinks,
            verify_tsa=args.verify_tsa,
            strip_mount_prefix=args.strip_mount_prefix or "",
        )
        failed = report.modified or []
        skipped = report.skipped or []
        files_scanned = int(report.files_scanned or 0)
        verified_count = max(0, files_scanned - len(failed))
        result = {
            "schema_version": report.schema_version,
            "root": report.root or root,
            "verified": [],
            "failed": failed,
            "skipped": skipped,
        }

        summary_line = (
            f"Root: {root} | Verified sidecars: {verified_count} | "
            f"Failed: {len(failed)} | Skipped: {len(skipped)}"
        )

        if args.emit_report:
            if args.format == "json":
                result["summary"] = summary_line
            print(summary_line, file=sys.stderr)

        if args.format == "json":
            print(json.dumps(result))
        else:
            print(summary_line, file=sys.stderr)

        exit_code = 1 if failed else 0
        if args.warn_only:
            return 0
        return exit_code

    # Default: single mode URL/file verification
    byte_start = args.start
    byte_end = args.end
    expected_hash = args.expected_hash

    if args.record:
        try:
            with open(path_for_kernel(args.record), encoding="utf-8") as f:
                record = json.load(f)
            byte_start = record.get("byte_start")
            byte_end = record.get("byte_end")
            expected_hash = record.get("hash")
        except Exception as e:
            print(f"Failed to load record: {e}", file=sys.stderr)
            return EXIT_USAGE

    if not expected_hash:
        print("[ERROR] --expected-hash or a valid --record is required in --mode single.", file=sys.stderr)
        return EXIT_USAGE

    algo = args.algo or infer_algo_from_digest(expected_hash) or "sha256"

    if args.url:
        if not args.url.startswith("https://"):
            print("[ERROR] --url must be HTTPS", file=sys.stderr)
            return EXIT_USAGE
        try:
            target_label = (
                args.url
                if byte_start is None
                else f"{args.url} [{byte_start}:{byte_end}]"
            )
            computed = download_and_hash(args.url, byte_start, byte_end, algo=algo)
            rc = execute_verification_single(target_label, computed, expected_hash)
            if args.warn_only and rc == 1:
                return EXIT_OK
            return rc
        except Exception as e:
            print(f"Remote fetch failed: {e}", file=sys.stderr)
            return EXIT_USAGE

    if args.file:
        try:
            target_label = (
                args.file
                if byte_start is None
                else f"{args.file} [{byte_start}:{byte_end}]"
            )
            b_start = byte_start if byte_start is not None else 0
            computed = hash_file(args.file, algo=algo, start=b_start, end=byte_end)
            rc = execute_verification_single(target_label, computed, expected_hash)
            if args.warn_only and rc == 1:
                return EXIT_OK
            return rc
        except Exception as e:
            print(f"Local read failed: {e}", file=sys.stderr)
            return EXIT_USAGE

    print("[ERROR] Must provide either --url or --file", file=sys.stderr)
    return EXIT_USAGE


def verify_epoch_attestation(
    attestation_path: str,
    sig_path: str,
    public_key_pem: bytes | str,
) -> tuple[bool, str]:
    """Verify DSSE-shaped epoch attestation JSON and detached Ed25519 signature."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        with open(path_for_kernel(attestation_path), "rb") as af:
            payload = af.read()
        with open(path_for_kernel(sig_path), "rb") as sf:
            sig = sf.read()
    except OSError as e:
        return False, f"read failed: {e}"
    try:
        doc = json.loads(payload.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        return False, f"invalid JSON: {e}"
    if doc.get("payloadType") != "application/vnd.in-toto+json":
        return False, "unexpected payloadType"
    if not isinstance(doc.get("payload"), str):
        return False, "missing payload"
    try:
        pem = public_key_pem if isinstance(public_key_pem, bytes) else public_key_pem.encode("utf-8")
        key = serialization.load_pem_public_key(pem)
        if not isinstance(key, Ed25519PublicKey):
            return False, "public key is not Ed25519"
        key.verify(sig, hashlib.sha256(payload).digest())
    except Exception as e:
        return False, f"signature invalid: {e}"
    return True, "epoch attestation signature valid"


if __name__ == "__main__":
    sys.exit(main())
