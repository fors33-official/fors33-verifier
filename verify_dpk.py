#!/usr/bin/env python3
"""
Verify attested data segment.

Standalone script for Data Provenance Kit. Supports:
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
from typing import Callable, Dict, List, Optional, Sequence

try:  # Support both package and flat-module imports
    from .hash_core import (  # type: ignore[import]
        default_dpk_worker_count,
        hash_file,
        hash_stream,
        infer_algo_from_digest,
        path_for_kernel,
    )
    from .manifest_core import ManifestEntry, load_manifest, verify_manifest_hash_chain  # type: ignore[import]
except ImportError:  # pragma: no cover - flat layout
    from hash_core import (  # type: ignore[import]
        default_dpk_worker_count,
        hash_file,
        hash_stream,
        infer_algo_from_digest,
        path_for_kernel,
    )
    from manifest_core import ManifestEntry, load_manifest, verify_manifest_hash_chain  # type: ignore[import]

try:
    import urllib.request
except ImportError:
    urllib = None

_CTA = "[TOOLCHAIN] : FORS33 Data Provenance Kit"
_ERR_INVALID_SEAL_FORMAT = "[ ERR_INVALID_SEAL_FORMAT ]"
_ERR_MISSING_SEAL = "[ ERR_MISSING_SEAL ]"
_ERR_MANIFEST_COMPROMISED = "[ ERR_MANIFEST_COMPROMISED: Root of trust invalid ]"
_ERR_BAD_SIGNATURE = "[ TAMPER DETECTED: BAD SIGNATURE ]"
_ERR_DATA_DRIFT = "[ SEAL BROKEN: DATA DRIFT ]"
_ERR_TSA_INVALID = "[ ERR_INVALID_TSA ]"

EXIT_OK = 0
EXIT_DRIFT = 1
EXIT_USAGE = 2
EXIT_SEVERE = 3

_COMPLIANCE_NOTICE_LINES = (
    "[NOTICE]  FORS33 Data Provenance Kit verifier",
    "[NOTICE]  Output describes integrity checks only; it is not legal advice.",
    "[NOTICE]  Validate results in your own compliance and audit workflow.",
    "[NOTICE]  Unauthorized use is prohibited.",
)


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
    return "\n".join(lines).encode("utf-8")


@dataclass
class VerificationReport:
    """Unified report for Data Latch UI: modified, created, deleted, skipped, mutated."""

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


class ManifestCompromisedError(RuntimeError):
    """Raised when a signed sidecar disagrees with manifest digest."""

    def __init__(self, rel: str, expected_digest: str, sidecar_digest: str) -> None:
        super().__init__(_ERR_MANIFEST_COMPROMISED)
        self.rel = rel
        self.expected_digest = expected_digest
        self.sidecar_digest = sidecar_digest


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

    # TSA token parsing: check new format (predicate.tsa.response_token) first, fallback to old format
    rfc3161_b64 = None
    tsa_obj = predicate.get("tsa")
    if isinstance(tsa_obj, dict):
        # New format: predicate.tsa.response_token
        nested = tsa_obj.get("response_token")
        if isinstance(nested, str) and nested.strip():
            rfc3161_b64 = nested.strip()
        # Fallback to old format: predicate.tsa.rfc3161_token_b64
        if not rfc3161_b64:
            nested_legacy = tsa_obj.get("rfc3161_token_b64")
            if isinstance(nested_legacy, str) and nested_legacy.strip():
                rfc3161_b64 = nested_legacy.strip()
    
    # Legacy top-level format: predicate.rfc3161_token_b64
    if not rfc3161_b64:
        rfc3161_raw = predicate.get("rfc3161_token_b64")
        rfc3161_b64 = rfc3161_raw.strip() if isinstance(rfc3161_raw, str) and rfc3161_raw.strip() else None

    if digest_algo == "sha512":
        if len(file_hash_l) != 128 or any(c not in "0123456789abcdef" for c in file_hash_l):
            raise ValueError(f"{_ERR_INVALID_SEAL_FORMAT} subject[0].digest.sha512 must be 128 hex chars")
    elif len(file_hash_l) != 64 or any(c not in "0123456789abcdef" for c in file_hash_l):
        raise ValueError(f"{_ERR_INVALID_SEAL_FORMAT} subject[0].digest.sha256 must be 64 hex chars")
    if len(public_key_hex_l) != 64 or any(c not in "0123456789abcdef" for c in public_key_hex_l):
        raise ValueError(f"{_ERR_INVALID_SEAL_FORMAT} predicate.public_key_hex must be 64 hex chars")
    if len(signature_hex_l) != 128 or any(c not in "0123456789abcdef" for c in signature_hex_l):
        raise ValueError(f"{_ERR_INVALID_SEAL_FORMAT} predicate.signature_hex must be 128 hex chars")

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
        "source_fingerprint": _pred_opt_str(predicate, "source_fingerprint"),
        "tsa_public_key_hex": tsa_public_key_hex_l,
        "tsa_signature_hex": tsa_signature_hex_l,
        "rfc3161_token_b64": rfc3161_b64,
        "tsa": predicate.get("tsa") if isinstance(predicate.get("tsa"), dict) else None,
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
    )


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


def _verify_rfc3161_token_b64(b64s: str, canonical_payload: bytes) -> None:
    """Decode RFC 3161 TimeStampResp; check status, imprint vs canonical payload, CMS signature."""
    import hashlib

    try:
        from asn1crypto import cms, tsp as tsp_mod
    except ImportError as e:
        raise ValueError(f"asn1crypto required for RFC 3161 TSA verification: {e}") from e

    raw = base64.standard_b64decode(b64s)
    resp = tsp_mod.TimeStampResp.load(raw)
    st = resp["status"]["status"].native
    if int(st) != 0:
        raise ValueError(f"TSA status not granted (status={int(st)})")

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

    signer_infos = signed_data["signer_infos"]
    if len(signer_infos) == 0:
        raise ValueError("no signer_infos in timestamp token")
    certs = _cms_certificates(signed_data)
    if not certs:
        raise ValueError("no certificates in timestamp token")
    signer_cert = _cms_match_signer_cert(signer_infos[0], certs)
    _cms_verify_signer_info(signer_infos[0], signer_cert, signed_data)


def _verify_tsa(parsed: dict, canonical_payload_bytes: bytes) -> tuple[bool, str]:
    """Verify TSA when --verify-tsa: RFC 3161 token or legacy Ed25519 predicate.tsa; fail-closed if neither."""
    rfc = parsed.get("rfc3161_token_b64")
    if isinstance(rfc, str) and rfc.strip():
        try:
            _verify_rfc3161_token_b64(rfc.strip(), canonical_payload_bytes)
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


def verify_sidecar_f33(sidecar_path: str, target_dir: str | None = None, verify_tsa: bool = False) -> tuple[bool, str]:
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
        payload = _verify_ed25519_pick_payload(parsed)
    except Exception as e:
        return False, f"{_ERR_BAD_SIGNATURE} {e}"
    if verify_tsa:
        tsa_ok, tsa_msg = _verify_tsa(parsed, payload)
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
) -> dict:
    """
    Verify a directory tree against a manifest.

    Returns a JSON-serializable dict with:
      - schema_version
      - modified, created, deleted, mutated_during_verification, skipped
      - algo_stats, timing
    """
    import fnmatch

    start_ts = datetime.now(timezone.utc)
    start_monotonic = start_ts.timestamp()

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
                if name.endswith(".f33") or name == "fors33-manifest.json":
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
            full_path = os.path.join(root_for_file, norm_rel)
            algo = entry.algo or default_algo
            work_key = f"{root_idx}:{norm_rel}" if len(roots_resolved) > 1 else norm_rel
            yield (work_key, norm_rel, full_path, algo, entry.digest)

    if sys.stderr.isatty():
        print("\r\033[K", end="", file=sys.stderr)

    _abort_event = threading.Event()

    def _hash_worker(item: tuple[str, str, str, str, str]):
        work_key, rel, path, algo, expected = item
        if _abort_event.is_set():
            return ("aborted", work_key, rel, algo, expected, None, "manifest_compromised_abort")
        kpath = path_for_kernel(path)
        sidecar_path = f"{path}.f33"
        try:
            if not os.path.isfile(kpath):
                return ("deleted", work_key, rel, algo, expected, None, None)
            if not os.path.isfile(path_for_kernel(sidecar_path)):
                return ("missing_seal", work_key, rel, algo, expected, None, _ERR_MISSING_SEAL)
            parsed = _parse_f33(sidecar_path)
            try:
                _validate_key_registry_window(parsed)
                payload = _verify_ed25519_pick_payload(parsed)
            except Exception as e:
                return ("bad_signature", work_key, rel, algo, expected, None, f"{_ERR_BAD_SIGNATURE} {e}")
            if verify_tsa:
                tsa_ok, tsa_msg = _verify_tsa(parsed, payload)
                if not tsa_ok:
                    return ("tsa_invalid", work_key, rel, algo, expected, None, tsa_msg)
            sidecar_digest = str(parsed["file_digest"]).lower()
            if sidecar_digest != expected.lower():
                _abort_event.set()
                raise ManifestCompromisedError(rel, expected, sidecar_digest)
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
            computed = hash_file(kpath, algo=algo, progress_callback=progress_cb)
            if progress_cb and sys.stderr.isatty():
                print(file=sys.stderr)
            st_after = os.stat(kpath)
            after_key: int | tuple[int, int] = (
                (st_after.st_dev, st_after.st_ino)
                if st_after.st_ino != 0
                else int(st_after.st_mtime)
            )
        except ManifestCompromisedError:
            raise
        except FileNotFoundError:
            return ("deleted", work_key, rel, algo, expected, None, None)
        except PermissionError:
            return ("skipped", work_key, rel, algo, expected, None, "access_denied")
        except OSError as e:
            return ("skipped", work_key, rel, algo, expected, None, str(e))
        except Exception as e:
            msg = f"Unhandled worker exception: {e}"
            print(f"[ERROR] {msg}", file=sys.stderr)
            return ("skipped", work_key, rel, algo, expected, None, msg)

        if before_key != after_key:
            return (
                "mutated",
                work_key,
                rel,
                algo,
                expected,
                None,
                "inode_or_mtime_changed_during_hash",
            )
        if computed.lower() != expected.lower():
            return ("seal_broken", work_key, rel, algo, expected, computed.lower(), _ERR_DATA_DRIFT)
        return ("ok", work_key, rel, algo, expected, None, None)

    executor = ThreadPoolExecutor(max_workers=resolve_manifest_worker_count(max_workers))
    try:
        for kind, wk, rel, algo, expected, computed, err in executor.map(
            _hash_worker, _work_generator()
        ):
            work_key = wk
            if kind == "seal_broken":
                modified.append(
                    {
                        "path": rel,
                        "digest": computed,
                        "expected_digest": expected,
                        "algo": algo,
                        "status": _ERR_DATA_DRIFT,
                        "reason": err,
                    }
                )
            elif kind == "missing_seal":
                modified.append(
                    {
                        "path": rel,
                        "algo": algo,
                        "expected_digest": expected,
                        "status": _ERR_MISSING_SEAL,
                        "reason": err or _ERR_MISSING_SEAL,
                    }
                )
            elif kind == "bad_signature":
                modified.append(
                    {
                        "path": rel,
                        "algo": algo,
                        "expected_digest": expected,
                        "status": _ERR_BAD_SIGNATURE,
                        "reason": err or _ERR_BAD_SIGNATURE,
                    }
                )
            elif kind == "tsa_invalid":
                modified.append(
                    {
                        "path": rel,
                        "algo": algo,
                        "expected_digest": expected,
                        "status": _ERR_TSA_INVALID,
                        "reason": err or _ERR_TSA_INVALID,
                    }
                )
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
            # Mark as seen for all non-deleted paths
            live_paths.pop(work_key, None)
    except ManifestCompromisedError as e:
        executor.shutdown(wait=False, cancel_futures=True)
        for k in list(live_paths.keys()):
            rel_only = k.split(":", 1)[1] if ":" in k and k[0].isdigit() else k
            if rel_only == e.rel:
                live_paths.pop(k, None)
        modified.append(
            {
                "path": e.rel,
                "expected_digest": e.expected_digest,
                "digest": e.sidecar_digest,
                "status": _ERR_MANIFEST_COMPROMISED,
                "reason": _ERR_MANIFEST_COMPROMISED,
            }
        )
    except KeyboardInterrupt:
        executor.shutdown(wait=False, cancel_futures=True)
        sys.exit(130)
    finally:
        executor.shutdown(wait=True)

    # Remaining live files that were not in manifest are "created"
    for norm_rel in sorted(live_paths.keys()):
        rel_only = norm_rel.split(":", 1)[1] if ":" in norm_rel and norm_rel[0].isdigit() else norm_rel
        rel_lower = rel_only.lower()
        if rel_lower.endswith(".f33") or rel_lower.endswith("/fors33-manifest.json") or rel_lower == "fors33-manifest.json":
            continue
        created.append({"path": rel_only, "status": "created"})

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
    }
    return result


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
) -> VerificationReport:
    """
    Library entry point: verify directory against manifest.

    Returns VerificationReport with modified, created, deleted, skipped, mutated.
    When progress_event_callback is set, emits JSON progress events for headless streaming.
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


def _extract_and_verify_zip(zip_path: str) -> None:
    """Extract audit package files from ZIP in memory and verify signature (zero-copy, no disk I/O)."""
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
        raise ValueError(f"Failed to read ZIP archive: {e}")
    
    if pdf_bytes is None:
        raise ValueError("[FAILURE] No PDF file found in audit package ZIP")
    if sig_bytes is None:
        raise ValueError("[FAILURE] No signature file (.sig) found in audit package ZIP")
    if pubkey_pem is None:
        raise ValueError("[FAILURE] No public key file (.pem) found in audit package ZIP")
    
    try:
        _verify_detached_signature_bytes(pdf_bytes, sig_bytes, pubkey_pem)
        print("[SUCCESS] Audit package signature verified")
    except Exception as e:
        raise ValueError(f"[FAILURE] Signature verification failed: {e}")


def _discover_and_verify_pdf(pdf_path: str) -> None:
    """Discover .sig and .pem files in same directory as PDF and verify signature."""
    pdf_dir = os.path.dirname(os.path.abspath(pdf_path))
    pdf_name = os.path.splitext(os.path.basename(pdf_path))[0]
    
    sig_path = os.path.join(pdf_dir, f"{pdf_name}.sig")
    pubkey_path = os.path.join(pdf_dir, f"{pdf_name}.pem")
    
    if not os.path.isfile(path_for_kernel(sig_path)):
        raise ValueError("[FAILURE] Missing cryptographic signature. Ensure the .sig and .pem files reside in the same directory as the PDF.")
    if not os.path.isfile(path_for_kernel(pubkey_path)):
        raise ValueError("[FAILURE] Missing cryptographic signature. Ensure the .sig and .pem files reside in the same directory as the PDF.")
    
    try:
        with open(path_for_kernel(pdf_path), 'rb') as f:
            pdf_bytes = f.read()
        with open(path_for_kernel(sig_path), 'rb') as f:
            sig_bytes = f.read()
        with open(path_for_kernel(pubkey_path), 'rb') as f:
            pubkey_pem = f.read()
    except OSError as e:
        raise ValueError(f"[FAILURE] Failed to read files: {e}")
    
    try:
        _verify_detached_signature_bytes(pdf_bytes, sig_bytes, pubkey_pem)
        print("[SUCCESS] Audit package signature verified")
    except Exception as e:
        raise ValueError(f"[FAILURE] Signature verification failed: {e}")


def main() -> int:
    _print_compliance_notice()
    parser = argparse.ArgumentParser(
        description="Verify attested data segment (Data Provenance Kit)"
    )
    parser.add_argument(
        "--mode",
        choices=["single", "manifest", "sidecars"],
        default="single",
        help="Verification mode: single (default), manifest, or sidecars.",
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
        help="Path to .f33-receipt file for standalone verification (requires --root for dataset directory).",
    )
    parser.add_argument(
        "--audit-package",
        help="Path to PDF file for audit package verification (detached signature mode).",
    )
    parser.add_argument(
        "--sig",
        help="Path to detached signature file (.sig) for audit package verification.",
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
            try:
                _extract_and_verify_zip(args.file)
                return EXIT_OK
            except Exception as e:
                print(f"[ERROR] Audit package verification failed: {e}", file=sys.stderr)
                return EXIT_SEVERE
        elif args.file.lower().endswith('.pdf'):
            try:
                _discover_and_verify_pdf(args.file)
                return EXIT_OK
            except Exception as e:
                print(f"[ERROR] Audit package verification failed: {e}", file=sys.stderr)
                return EXIT_SEVERE

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
        if args.warn_only:
            return EXIT_OK
        return exit_code

    if args.mode == "sidecars":
        # Directory-wide sidecar verification: .sha256/.sha512/.md5/.f33
        root = target_dir or args.file or os.getcwd()
        root = os.path.abspath(root)
        ignore_patterns = list(args.ignore_pattern or []) + _load_f33ignore_patterns(root)
        exclude_dirs = set(args.exclude_dir or [])

        import fnmatch

        verified = []
        failed = []
        skipped = []

        def _matches_ignore(path: str) -> bool:
            return any(fnmatch.fnmatch(path, pat) for pat in ignore_patterns)

        walk_root = path_for_kernel(os.path.abspath(root))
        visited_dirs: set[tuple[int, int]] = set()
        if args.follow_symlinks:
            try:
                st_root = os.stat(walk_root, follow_symlinks=False)
                visited_dirs.add((st_root.st_dev, st_root.st_ino))
            except OSError:
                pass
        for dirpath, dirnames, filenames in os.walk(
            walk_root, followlinks=args.follow_symlinks
        ):
            if args.follow_symlinks:
                keep = []
                for d in dirnames:
                    if d in exclude_dirs:
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
                dirnames[:] = [d for d in dirnames if d not in exclude_dirs]
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
                    try:
                        ok, msg = verify_sidecar_f33(full_path, verify_tsa=args.verify_tsa)
                    except Exception as e:
                        skipped.append({"sidecar": norm_rel, "error": str(e)})
                        continue
                    if ok:
                        verified.append({"sidecar": norm_rel, "type": "f33"})
                    else:
                        failed.append({"sidecar": norm_rel, "type": "f33", "reason": msg})
                    continue

                for ext, algo in ((".sha256", "sha256"), (".sha512", "sha512"), (".md5", "md5")):
                    if lower.endswith(ext):
                        target_rel = norm_rel[: -len(ext)]
                        target_full = os.path.join(dirpath, name[: -len(ext)])
                        if not os.path.isfile(path_for_kernel(target_full)):
                            failed.append(
                                {
                                    "sidecar": norm_rel,
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
                            skipped.append({"sidecar": norm_rel, "error": str(e)})
                            break
                        try:
                            computed = hash_file(target_full, algo=algo)
                        except Exception as e:
                            skipped.append({"sidecar": norm_rel, "error": str(e)})
                            break
                        if computed.lower() == expected.lower():
                            verified.append(
                                {
                                    "sidecar": norm_rel,
                                    "target": target_rel,
                                    "type": ext.lstrip("."),
                                }
                            )
                        else:
                            failed.append(
                                {
                                    "sidecar": norm_rel,
                                    "target": target_rel,
                                    "type": ext.lstrip("."),
                                    "expected": expected.lower(),
                                    "computed": computed.lower(),
                                }
                            )
                        break

        result = {
            "schema_version": "0.1",
            "root": root,
            "verified": verified,
            "failed": failed,
            "skipped": skipped,
        }

        summary_line = (
            f"Root: {root} | Verified sidecars: {len(verified)} | "
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

        exit_code = EXIT_DRIFT if failed else EXIT_OK
        if args.warn_only:
            return EXIT_OK
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


if __name__ == "__main__":
    sys.exit(main())
