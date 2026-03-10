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
import json
import os
import re
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Sequence

try:  # Support both package and flat-module imports
    from .hash_core import hash_file, hash_stream, infer_algo_from_digest  # type: ignore[import]
    from .manifest_core import ManifestEntry, load_manifest  # type: ignore[import]
except ImportError:  # pragma: no cover - flat layout
    from hash_core import hash_file, hash_stream, infer_algo_from_digest  # type: ignore[import]
    from manifest_core import ManifestEntry, load_manifest  # type: ignore[import]

try:
    import urllib.request
except ImportError:
    urllib = None

_CTA = "[FΦRS33] Data Provenance Kit. Automate WORM-compliant attestation across AWS S3, Snowflake, and local infrastructure. Procure licensing at fors33.com or GitHub Marketplace."

_MAX_WORKERS = min(32, (os.cpu_count() or 1) + 4)


def _load_f33ignore_patterns(root: str) -> List[str]:
    """Load glob patterns from root-level .f33ignore (gitignore-style)."""
    patterns: List[str] = []
    ignore_path = os.path.join(root, ".f33ignore")
    if not os.path.isfile(ignore_path):
        return patterns
    try:
        with open(ignore_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                patterns.append(line)
    except OSError:
        pass
    return patterns

# --- .f33 sidecar (canonical payload format must match attestation writer) ---
_F33_LINE = re.compile(r"^([A-Za-z0-9_]+):\s*(.*)$")


def _parse_f33(sidecar_path: str) -> dict:
    """Parse .f33 file; return dict with target, range_start, range_end, timestamp, sha256, public_key_hex, signature_hex."""
    with open(sidecar_path, encoding="utf-8") as f:
        content = f.read()
    lines = content.splitlines()
    in_block = False
    parsed = {}
    for line in lines:
        line = line.strip()
        if line == "BEGIN FORS33 ATTESTATION":
            in_block = True
            continue
        if line == "END FORS33 ATTESTATION":
            break
        if not in_block:
            continue
        m = _F33_LINE.match(line)
        if not m:
            continue
        key, value = m.group(1).upper(), m.group(2).strip()
        if key == "TARGET":
            parsed["target"] = value
        elif key == "RANGE":
            parts = value.split(":")
            if len(parts) != 2:
                raise ValueError(f"Invalid RANGE in .f33: {value}")
            parsed["range_start"] = int(parts[0].strip())
            parsed["range_end"] = int(parts[1].strip())
        elif key == "TIMESTAMP":
            parsed["timestamp"] = value
        elif key == "SHA256":
            parsed["sha256"] = value.lower()
        elif key == "PUBKEY_ED25519":
            parsed["public_key_hex"] = value.lower()
        elif key == "SIGNATURE_ED25519":
            parsed["signature_hex"] = value.lower()
    for r in ("target", "range_start", "range_end", "timestamp", "sha256", "public_key_hex", "signature_hex"):
        if r not in parsed:
            raise ValueError(f"Missing required field in .f33: {r}")
    if len(parsed["sha256"]) != 64:
        raise ValueError("SHA256 in .f33 must be 64 hex characters")
    if len(parsed["public_key_hex"]) != 64:
        raise ValueError("PUBKEY_ED25519 in .f33 must be 64 hex characters")
    if len(parsed["signature_hex"]) != 128:
        raise ValueError("SIGNATURE_ED25519 in .f33 must be 128 hex characters")
    return parsed


def _canonical_payload_f33(target_name: str, range_start: int, range_end: int, timestamp: str, file_hash: str) -> bytes:
    """Build canonical payload bytes (no trailing newline) for Ed25519 verification."""
    return (
        f"TARGET:{target_name}\n"
        f"RANGE:{range_start}:{range_end}\n"
        f"TIMESTAMP:{timestamp}\n"
        f"SHA256:{file_hash}"
    ).encode("utf-8")


def _verify_ed25519_f33(public_key_hex: str, signature_hex: str, payload_bytes: bytes) -> None:
    """Verify Ed25519 signature; raises on failure."""
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.exceptions import InvalidSignature

    public_bytes = bytes.fromhex(public_key_hex)
    signature_bytes = bytes.fromhex(signature_hex)
    public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_bytes)
    public_key.verify(signature_bytes, payload_bytes)


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
        with open(manifest_path, "rb") as f:
            payload = f.read()
    except OSError as e:
        return False, f"Failed to read manifest for signature verification: {e}"

    try:
        with open(signature_path, "rb") as f:
            sig_raw = f.read().strip()
        signature_bytes = base64.b64decode(sig_raw)
    except Exception as e:
        return False, f"Failed to read or decode signature file: {e}"

    try:
        with open(public_key_path, "rb") as f:
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


def verify_sidecar_f33(sidecar_path: str, target_dir: str | None = None) -> tuple[bool, str]:
    """Verify .f33 sidecar: resolve target, hash range, check SHA-256 and Ed25519. Returns (success, message)."""
    parsed = _parse_f33(sidecar_path)
    base = os.path.dirname(os.path.abspath(sidecar_path)) if target_dir is None else target_dir
    target_path = os.path.join(base, parsed["target"])
    if not os.path.isfile(target_path):
        return False, f"Target file not found: {target_path}"
    computed = hash_file_range(
        target_path,
        parsed["range_start"],
        parsed["range_end"],
    )
    if computed != parsed["sha256"]:
        return False, f"SHA-256 mismatch: computed {computed}, expected {parsed['sha256']}"
    payload = _canonical_payload_f33(
        parsed["target"],
        parsed["range_start"],
        parsed["range_end"],
        parsed["timestamp"],
        parsed["sha256"],
    )
    try:
        _verify_ed25519_f33(parsed["public_key_hex"], parsed["signature_hex"], payload)
    except Exception as e:
        return False, f"Ed25519 verification failed: {e}"
    return True, "VERIFIED"


def _log_output(target: str, computed_hash: str, status: str) -> None:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    print(f"[SYS.TIME]  : {ts}", file=sys.stderr)
    print(f"[TARGET]    : {target}", file=sys.stderr)
    print(f"[SHA-256]   : {computed_hash}", file=sys.stderr)
    print(f"[STATUS]    : {status}", file=sys.stderr)
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

    manifest = load_manifest(manifest_path)
    root = os.path.abspath(root_dir)
    ignore_patterns = tuple(ignore_patterns or ())
    exclude_dir_set = {d for d in (exclude_dirs or ())}

    modified: List[dict] = []
    created: List[dict] = []
    deleted: List[dict] = []
    mutated: List[dict] = []
    skipped: List[dict] = []

    # Track live files under root
    live_paths: Dict[str, str] = {}
    for dirpath, dirnames, filenames in os.walk(root, followlinks=follow_symlinks):
        # Apply directory-level excludes early for performance.
        dirnames[:] = [d for d in dirnames if d not in exclude_dir_set]
        rel_dir = os.path.relpath(dirpath, root)
        rel_dir = "" if rel_dir == "." else rel_dir
        for name in filenames:
            rel_path = os.path.join(rel_dir, name) if rel_dir else name
            norm_rel = rel_path.replace("\\", "/")
            if ignore_patterns and any(
                fnmatch.fnmatch(norm_rel, pat) for pat in ignore_patterns
            ):
                continue
            live_paths[norm_rel] = os.path.join(dirpath, name)

    # Prepare work items for concurrent hashing of baseline files.
    work_items: List[tuple[str, str, str, str]] = []
    for rel_path, entry in manifest.items():
        norm_rel = rel_path.replace("\\", "/")
        if ignore_patterns and any(
            fnmatch.fnmatch(norm_rel, pat) for pat in ignore_patterns
        ):
            continue
        full_path = os.path.join(root, norm_rel)
        if not os.path.exists(full_path):
            deleted.append({"path": norm_rel})
            continue
        algo = entry.algo or default_algo
        work_items.append((norm_rel, full_path, algo, entry.digest))

    def _hash_worker(item: tuple[str, str, str, str]):
        rel, path, algo, expected = item
        try:
            before_mtime = os.path.getmtime(path)
            size = os.path.getsize(path)
            progress_cb = None
            if size >= 500 * 1024 * 1024 and sys.stderr.isatty():
                last_pct = [0]

                def _progress(br: int, tb: int) -> None:
                    if tb > 0:
                        pct = min(100, int(br * 100 / tb))
                        if pct != last_pct[0] and pct % 5 == 0 or pct == 100:
                            last_pct[0] = pct
                            print(f"\r[VERIFY] Hashing {rel}: {pct}%", end="", file=sys.stderr)

                progress_cb = _progress
            computed = hash_file(path, algo=algo, progress_callback=progress_cb)
            if progress_cb and sys.stderr.isatty():
                print(file=sys.stderr)
            after_mtime = os.path.getmtime(path)
        except OSError as e:
            return ("skipped", rel, algo, expected, None, str(e))
        except Exception as e:
            msg = f"Unhandled worker exception: {e}"
            print(f"[ERROR] {msg}", file=sys.stderr)
            return ("skipped", rel, algo, expected, None, msg)

        if before_mtime != after_mtime:
            return (
                "mutated",
                rel,
                algo,
                expected,
                None,
                "mtime_changed_during_hash",
            )
        if computed.lower() != expected.lower():
            return ("modified", rel, algo, expected, computed.lower(), None)
        return ("ok", rel, algo, expected, None, None)

    with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as executor:
        for kind, rel, algo, expected, computed, err in executor.map(
            _hash_worker, work_items
        ):
            if kind == "modified":
                modified.append(
                    {
                        "path": rel,
                        "expected_digest": expected,
                        "computed_digest": computed,
                        "algo": algo,
                    }
                )
            elif kind == "mutated":
                mutated.append(
                    {
                        "path": rel,
                        "algo": algo,
                        "reason": err,
                    }
                )
            elif kind == "skipped":
                skipped.append(
                    {
                        "path": rel,
                        "error": err,
                    }
                )
            # Mark as seen for all non-deleted paths
            live_paths.pop(rel, None)

    # Remaining live files that were not in manifest are "created"
    for norm_rel in sorted(live_paths.keys()):
        created.append({"path": norm_rel})

    end_monotonic = datetime.now(timezone.utc).timestamp()

    result = {
        "schema_version": schema_version,
        "baseline": str(Path(manifest_path)),
        "root": root,
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


def main() -> int:
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
        "--target-dir",
        help="Directory for target file when using --sidecar (default: sidecar dir)",
    )

    # Shared options
    parser.add_argument(
        "--algo",
        help="Hash algorithm to use (sha256, sha512, md5, sha1, blake3). Default inferred from digest length.",
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
        "--verify-manifest-sig",
        help="Path to detached Base64-encoded Ed25519 signature for the manifest (manifest mode).",
    )
    parser.add_argument(
        "--pubkey",
        help="Path to Ed25519 public key file for manifest signature verification.",
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
    args = parser.parse_args()

    # Legacy single-file sidecar verification path (backwards compatible).
    if args.mode == "single" and args.sidecar:
        try:
            ok, msg = verify_sidecar_f33(args.sidecar, args.target_dir)
        except Exception as e:
            print(f"Sidecar verification error: {e}", file=sys.stderr)
            return 2
        target_label = args.sidecar
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        print(f"[SYS.TIME]  : {ts}", file=sys.stderr)
        print(f"[SIDECAR]   : {target_label}", file=sys.stderr)
        print(f"[STATUS]    : {msg}", file=sys.stderr)
        print(f"[NOTICE]    : {_CTA}", file=sys.stderr)
        return 0 if (ok or args.warn_only) else 1

    if args.mode == "manifest":
        if not args.file:
            print("[ERROR] --file must point to the manifest path in --mode manifest.", file=sys.stderr)
            return 2
        manifest_path = args.file
        root_dir = args.target_dir or os.path.dirname(os.path.abspath(manifest_path)) or "."
        default_algo = args.algo or "sha256"

        signature_result = None
        if args.verify_manifest_sig or args.pubkey:
            if not (args.verify_manifest_sig and args.pubkey):
                print(
                    "Error: --verify-manifest-sig and --pubkey must both be provided for manifest signature verification.",
                    file=sys.stderr,
                )
                return 2
            ok_sig, msg_sig = _verify_manifest_ed25519_signature(
                manifest_path, args.verify_manifest_sig, args.pubkey
            )
            signature_result = {"verified": ok_sig, "message": msg_sig}
            if not ok_sig:
                print(f"[WARNING] Manifest signature check failed: {msg_sig}", file=sys.stderr)

        ignore_list = list(args.ignore_pattern or []) + _load_f33ignore_patterns(root_dir)
        try:
            result = verify_directory_from_manifest(
                manifest_path=manifest_path,
                root_dir=root_dir,
                default_algo=default_algo,
                schema_version="0.2",
                ignore_patterns=ignore_list,
                exclude_dirs=args.exclude_dir,
                follow_symlinks=args.follow_symlinks,
            )
        except Exception as e:
            print(f"Manifest verification failed: {e}", file=sys.stderr)
            return 3

        if signature_result is not None:
            result["manifest_signature"] = signature_result

        modified = result.get("modified") or []
        created = result.get("created") or []
        deleted = result.get("deleted") or []
        drift_detected = bool(modified or created or deleted)

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

        exit_code = 1 if drift_detected else 0
        if args.warn_only:
            return 0
        return exit_code

    if args.mode == "sidecars":
        # Directory-wide sidecar verification: .sha256/.sha512/.md5/.f33
        root = args.target_dir or args.file or os.getcwd()
        root = os.path.abspath(root)
        ignore_patterns = list(args.ignore_pattern or []) + _load_f33ignore_patterns(root)
        exclude_dirs = set(args.exclude_dir or [])

        import fnmatch

        verified = []
        failed = []
        skipped = []

        def _matches_ignore(path: str) -> bool:
            return any(fnmatch.fnmatch(path, pat) for pat in ignore_patterns)

        for dirpath, dirnames, filenames in os.walk(
            root, followlinks=args.follow_symlinks
        ):
            dirnames[:] = [d for d in dirnames if d not in exclude_dirs]
            rel_dir = os.path.relpath(dirpath, root)
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
                        ok, msg = verify_sidecar_f33(full_path)
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
                        if not os.path.isfile(target_full):
                            failed.append(
                                {
                                    "sidecar": norm_rel,
                                    "type": ext.lstrip("."),
                                    "reason": "target_missing",
                                }
                            )
                            break
                        try:
                            with open(full_path, encoding="utf-8") as sf:
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
            with open(args.record, encoding="utf-8") as f:
                record = json.load(f)
            byte_start = record.get("byte_start")
            byte_end = record.get("byte_end")
            expected_hash = record.get("hash")
        except Exception as e:
            print(f"Failed to load record: {e}", file=sys.stderr)
            return 2

    if not expected_hash:
        print("[ERROR] --expected-hash or a valid --record is required in --mode single.", file=sys.stderr)
        return 2

    algo = args.algo or infer_algo_from_digest(expected_hash) or "sha256"

    if args.url:
        if not args.url.startswith("https://"):
            print("[ERROR] --url must be HTTPS", file=sys.stderr)
            return 2
        try:
            target_label = (
                args.url
                if byte_start is None
                else f"{args.url} [{byte_start}:{byte_end}]"
            )
            computed = download_and_hash(args.url, byte_start, byte_end, algo=algo)
            rc = execute_verification(target_label, computed, expected_hash)
            if args.warn_only and rc == 1:
                return 0
            return rc
        except Exception as e:
            print(f"Remote fetch failed: {e}", file=sys.stderr)
            return 2

    if args.file:
        try:
            target_label = (
                args.file
                if byte_start is None
                else f"{args.file} [{byte_start}:{byte_end}]"
            )
            b_start = byte_start if byte_start is not None else 0
            computed = hash_file(args.file, algo=algo, start=b_start, end=byte_end)
            rc = execute_verification(target_label, computed, expected_hash)
            if args.warn_only and rc == 1:
                return 0
            return rc
        except Exception as e:
            print(f"Local read failed: {e}", file=sys.stderr)
            return 2

    print("[ERROR] Must provide either --url or --file", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
