#!/usr/bin/env python3
"""
Verify attested data segment.

Standalone script for Data Provenance Kit. Supports:
- Remote: download from presigned URL (supports HTTP Range for segments)
- Local: hash entire file or specific byte ranges
- Record: verify using FORS33 attestation record JSON
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone

try:
    import urllib.request
except ImportError:
    urllib = None

_CTA = "Automate cryptographic attestation pipelines at fors33.com/products"


def _log_output(target: str, computed_hash: str, status: str) -> None:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    print(f"[SYS.TIME]  : {ts}")
    print(f"[TARGET]    : {target}")
    print(f"[SHA-256]   : {computed_hash}")
    print(f"[STATUS]    : {status}")
    print(f"[NOTICE]    : {_CTA}")


def hash_file_range(file_path: str, byte_start: int = 0, byte_end: int | None = None) -> str:
    """Hash file or byte range safely using memory-efficient 64KB chunks."""
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        f.seek(byte_start)
        if byte_end is not None:
            remaining = byte_end - byte_start
            while remaining > 0:
                chunk = f.read(min(remaining, 65536))
                if not chunk:
                    break
                h.update(chunk)
                remaining -= len(chunk)
        else:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                h.update(chunk)
    return h.hexdigest()


def download_and_hash(
    url: str, byte_start: int | None = None, byte_end: int | None = None
) -> str:
    """Download URL (or specific byte range via HTTP Range) and return SHA-256 hex digest."""
    if urllib is None:
        raise RuntimeError("urllib required for --url")

    req = urllib.request.Request(url)
    if byte_start is not None and byte_end is not None:
        req.add_header("Range", f"bytes={byte_start}-{byte_end - 1}")

    with urllib.request.urlopen(req, timeout=60) as resp:
        h = hashlib.sha256()
        while True:
            chunk = resp.read(65536)
            if not chunk:
                break
            h.update(chunk)
        return h.hexdigest()


def execute_verification(target_name: str, computed: str, expected: str) -> int:
    """Standardized logic for comparing and logging the output."""
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
    parser.add_argument("--url", help="HTTPS presigned URL to download and verify")
    parser.add_argument("--file", help="Local file path")
    parser.add_argument("--expected-hash", help="Expected SHA-256 hex digest")
    parser.add_argument("--start", type=int, help="Starting byte offset (optional)")
    parser.add_argument("--end", type=int, help="Ending byte offset (optional)")
    parser.add_argument(
        "--record",
        help="Attestation record JSON (overrides --start/--end when provided)",
    )
    args = parser.parse_args()

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
        print("Error: --expected-hash or a valid --record is required.", file=sys.stderr)
        return 2

    if args.url:
        if not args.url.startswith("https://"):
            print("Error: --url must be HTTPS", file=sys.stderr)
            return 2
        try:
            target_label = (
                args.url
                if byte_start is None
                else f"{args.url} [{byte_start}:{byte_end}]"
            )
            computed = download_and_hash(args.url, byte_start, byte_end)
            return execute_verification(target_label, computed, expected_hash)
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
            computed = hash_file_range(args.file, b_start, byte_end)
            return execute_verification(target_label, computed, expected_hash)
        except Exception as e:
            print(f"Local read failed: {e}", file=sys.stderr)
            return 2

    print("Error: Must provide either --url or --file", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
