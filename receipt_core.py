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
from typing import Dict, Optional

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

try:  # Support both package and flat-module imports
    from .hash_core import hash_file, path_for_kernel  # type: ignore[import]
    from .manifest_core import load_manifest  # type: ignore[import]
except ImportError:  # pragma: no cover - flat layout
    from hash_core import hash_file, path_for_kernel  # type: ignore[import]
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


def verify_receipt(receipt_path: str, dataset_path: str) -> bool:
    """
    Verify a receipt against a dataset (standalone verification).

    Args:
        receipt_path: Path to .f33-receipt file
        dataset_path: Path to dataset directory

    Returns:
        True if receipt is valid, False otherwise
    """
    # Load receipt
    try:
        with open(path_for_kernel(receipt_path), "r", encoding="utf-8") as f:
            receipt_data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        print(f"[RECEIPT INVALID] Failed to load receipt: {e}")
        return False

    # Extract receipt fields
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

    # Verify version
    if version != "1":
        print(f"[RECEIPT INVALID] Unsupported version: {version}")
        return False

    # Verify algorithm
    if algorithm != "sha256":
        print(f"[RECEIPT INVALID] Unsupported algorithm: {algorithm}")
        return False

    # Rebuild payload without signature for signature verification
    payload_for_verification = {
        "version": version,
        "dataset_digest": dataset_digest,
        "timestamp": timestamp,
        "file_count": file_count,
        "total_bytes": total_bytes,
        "algorithm": algorithm
    }

    # Verify signature
    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
        payload_bytes = json.dumps(payload_for_verification, sort_keys=True).encode("utf-8")
        signature = base64.b64decode(signature_b64)
        public_key.verify(signature, payload_bytes)
    except Exception as e:
        print(f"[RECEIPT INVALID] Signature verification failed: {e}")
        return False

    # Compute actual dataset digest from manifest
    try:
        manifest_path = os.path.join(dataset_path, "fors33-manifest.json")
        if not os.path.isfile(path_for_kernel(manifest_path)):
            print(f"[RECEIPT INVALID] Manifest not found at {manifest_path}")
            return False

        manifest = load_manifest(manifest_path)
        
        # Compute dataset digest by hashing all manifest entries
        entry_digests = []
        for entry in manifest.values():
            digest = entry.digest
            if digest:
                entry_digests.append(digest)
        
        entry_digests.sort()  # Deterministic ordering
        combined_digests = "".join(entry_digests).encode("utf-8")
        computed_digest = hashlib.sha256(combined_digests).hexdigest()
        computed_digest_with_prefix = f"sha256:{computed_digest}"
        
        # Compare computed digest with receipt digest
        if computed_digest_with_prefix != dataset_digest:
            print(f"[RECEIPT INVALID] Dataset digest mismatch")
            print(f"  Receipt: {dataset_digest}")
            print(f"  Computed: {computed_digest_with_prefix}")
            return False
        
    except Exception as e:
        print(f"[RECEIPT INVALID] Failed to compute dataset digest: {e}")
        return False

    print(f"[RECEIPT VERIFIED] Dataset: {dataset_digest}")
    print(f"[RECEIPT VERIFIED] Files: {file_count}, Total bytes: {total_bytes}")
    print(f"[RECEIPT VERIFIED] Timestamp: {timestamp}")
    return True
