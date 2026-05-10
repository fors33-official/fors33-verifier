#!/usr/bin/env python3
"""
FORS33 Verification Receipt Verification.

Verifies standalone verification receipts for third-party audits.
Receipts contain dataset digest, public key, and signature for independent
verification without installing full Fors33 software.
"""

import base64
import hashlib
import json
import os
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

try:  # Support both package and flat-module imports
    from .hash_core import path_for_kernel  # type: ignore[import]
    from .manifest_core import load_manifest  # type: ignore[import]
except ImportError:  # pragma: no cover - flat layout
    from hash_core import path_for_kernel  # type: ignore[import]
    from manifest_core import load_manifest  # type: ignore[import]


@dataclass
class VerificationReceipt:
    """Standalone verification receipt for dataset."""

    version: str
    dataset_digest: str
    public_key: str
    signature: str
    timestamp: str
    file_count: int
    total_bytes: int
    algorithm: str


def generate_verification_receipt(
    manifest_entries: Dict[str, Any],
    public_key_pem: str,
    private_key: ed25519.Ed25519PrivateKey,
    target_path: str,
) -> VerificationReceipt:
    """Produce a standalone receipt from manifest entry dicts (digest / hash keys)."""
    entry_digests: List[str] = []
    total_bytes = 0
    file_count = 0

    for entry in manifest_entries.values():
        digest = entry.get("digest") or entry.get("hash")
        if digest:
            entry_digests.append(str(digest))
        file_count += 1
        if "size" in entry:
            total_bytes += int(entry.get("size") or 0)
        else:
            entry_path = entry.get("path")
            if entry_path:
                full_path = os.path.join(target_path, str(entry_path))
                if os.path.isfile(path_for_kernel(full_path)):
                    try:
                        total_bytes += os.path.getsize(path_for_kernel(full_path))
                    except OSError:
                        pass

    entry_digests.sort()
    combined_digests = "".join(entry_digests).encode("utf-8")
    dataset_digest = hashlib.sha256(combined_digests).hexdigest()

    receipt_timestamp = datetime.now(timezone.utc).isoformat()
    receipt_payload = {
        "version": "1",
        "dataset_digest": f"sha256:{dataset_digest}",
        "timestamp": receipt_timestamp,
        "file_count": file_count,
        "total_bytes": total_bytes,
        "algorithm": "sha256",
    }

    payload_bytes = json.dumps(receipt_payload, sort_keys=True).encode("utf-8")
    signature = private_key.sign(payload_bytes)
    signature_b64 = base64.b64encode(signature).decode("utf-8")

    return VerificationReceipt(
        version="1",
        dataset_digest=f"sha256:{dataset_digest}",
        public_key=public_key_pem,
        signature=signature_b64,
        timestamp=receipt_timestamp,
        file_count=file_count,
        total_bytes=total_bytes,
        algorithm="sha256",
    )


def receipt_to_json(receipt: VerificationReceipt) -> str:
    return json.dumps(asdict(receipt), indent=2)


def receipt_to_base64(receipt: VerificationReceipt) -> str:
    return base64.b64encode(receipt_to_json(receipt).encode("utf-8")).decode("utf-8")


def verify_receipt(receipt_path: str, dataset_path: str) -> bool:
    """
    Verify a receipt against a dataset (standalone verification).

    Loads the canonical FORS33 manifest at ``<dataset_path>/fors33-manifest.json``
    using the same ``manifest_core.load_manifest`` loader as receipt generation.

    Args:
        receipt_path: Path to .f33-receipt file
        dataset_path: Path to dataset directory containing fors33-manifest.json

    Returns:
        True if receipt is valid, False otherwise
    """
    try:
        with open(path_for_kernel(receipt_path), "r", encoding="utf-8") as f:
            receipt_data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        print(f"[RECEIPT INVALID] Failed to load receipt: {e}")
        return False

    try:
        dataset_digest = receipt_data["dataset_digest"]
        public_key_pem = receipt_data["public_key"]
        signature_b64 = receipt_data["signature"]
        version = receipt_data["version"]
        timestamp = receipt_data["timestamp"]
        file_count = receipt_data["file_count"]
        total_bytes = receipt_data["total_bytes"]
        algorithm = receipt_data["algorithm"]
    except KeyError as e:
        print(f"[RECEIPT INVALID] Missing required field: {e}")
        return False

    if version != "1":
        print(f"[RECEIPT INVALID] Unsupported version: {version}")
        return False

    if algorithm != "sha256":
        print(f"[RECEIPT INVALID] Unsupported algorithm: {algorithm}")
        return False

    payload_for_verification = {
        "version": version,
        "dataset_digest": dataset_digest,
        "timestamp": timestamp,
        "file_count": file_count,
        "total_bytes": total_bytes,
        "algorithm": algorithm,
    }

    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
        payload_bytes = json.dumps(payload_for_verification, sort_keys=True).encode("utf-8")
        signature = base64.b64decode(signature_b64)
        public_key.verify(signature, payload_bytes)
    except Exception as e:
        print(f"[RECEIPT INVALID] Signature verification failed: {e}")
        return False

    print("[RECEIPT VERIFY] Computing dataset digest from target directory...")
    manifest_path = os.path.join(dataset_path, "fors33-manifest.json")
    if not os.path.exists(path_for_kernel(manifest_path)):
        print(f"[RECEIPT INVALID] Manifest not found at {manifest_path}")
        return False

    try:
        entries, _roots = load_manifest(manifest_path, dataset_path)
    except Exception as e:
        print(f"[RECEIPT INVALID] Error loading manifest: {e}")
        return False

    entry_digests: List[str] = []
    for entry in entries.values():
        if entry.digest:
            entry_digests.append(entry.digest)

    entry_digests.sort()
    combined_digests = "".join(entry_digests).encode("utf-8")
    computed_dataset_digest = hashlib.sha256(combined_digests).hexdigest()

    stored_digest = dataset_digest
    if stored_digest.startswith("sha256:"):
        stored_digest = stored_digest[7:]

    if computed_dataset_digest != stored_digest:
        print("[RECEIPT INVALID] Dataset digest mismatch!")
        print(f"[RECEIPT INVALID] Computed: sha256:{computed_dataset_digest}")
        print(f"[RECEIPT INVALID] Expected:  sha256:{stored_digest}")
        return False

    print(f"[RECEIPT VERIFIED] Dataset digest matches: sha256:{computed_dataset_digest}")
    print(f"[RECEIPT VERIFIED] Dataset: {dataset_digest}")
    print(f"[RECEIPT VERIFIED] Files: {file_count}, Total bytes: {total_bytes}")
    print(f"[RECEIPT VERIFIED] Timestamp: {timestamp}")
    return True
