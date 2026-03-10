#!/usr/bin/env python3
"""
Shared hashing utilities for fors33-verifier.

Supports SHA-256 (default), SHA-512, MD5, SHA-1, and optional BLAKE3 with
streaming, chunk-based hashing suitable for large files.
"""
from __future__ import annotations

import os
from typing import Callable, Iterable, Optional

import hashlib

try:
    import blake3  # type: ignore[attr-defined]
except Exception:  # pragma: no cover - optional
    blake3 = None  # type: ignore[assignment]


def _get_hasher(algo: str):
    algo_lower = algo.lower()
    if algo_lower == "sha256":
        return hashlib.sha256()
    if algo_lower == "sha512":
        return hashlib.sha512()
    if algo_lower == "md5":
        return hashlib.md5()
    if algo_lower in ("sha1", "sha-1"):
        return hashlib.sha1()
    if algo_lower == "blake3":
        if blake3 is None:
            raise RuntimeError("blake3 is not available in this environment")
        return blake3.blake3()
    raise ValueError(f"Unsupported hash algorithm: {algo}")


def infer_algo_from_digest(hex_str: str) -> Optional[str]:
    """Infer hash algorithm from hex digest length, when possible.

    32 -> md5, 40 -> sha1, 64 -> sha256, 128 -> sha512.
    BLAKE3 also emits 64 characters and cannot be inferred; callers must
    request it explicitly via algo='blake3' or manifest metadata.
    """
    length = len(hex_str)
    if length == 32:
        return "md5"
    if length == 40:
        return "sha1"
    if length == 64:
        return "sha256"
    if length == 128:
        return "sha512"
    return None


def hash_file(
    path: str,
    algo: str = "sha256",
    start: int = 0,
    end: Optional[int] = None,
    chunk_size: int = 4194304,
    progress_callback: Optional[Callable[[int, int], None]] = None,
) -> str:
    """Hash a file (or byte range) using streaming chunks.
    If progress_callback is set, it is called with (bytes_read, total_bytes) per chunk.
    total_bytes is -1 when unknown (streaming full file).
    """
    hasher = _get_hasher(algo)
    total_bytes = -1
    remaining: Optional[int] = None
    if end is not None:
        remaining = max(0, end - start)
        total_bytes = remaining
    else:
        try:
            total_bytes = os.path.getsize(path) - start
        except OSError:
            pass
    bytes_read = 0
    with open(path, "rb") as f:
        f.seek(start)
        if remaining is not None:
            while remaining > 0:
                chunk = f.read(min(remaining, chunk_size))
                if not chunk:
                    break
                hasher.update(chunk)
                remaining -= len(chunk)
                bytes_read += len(chunk)
                if progress_callback:
                    progress_callback(bytes_read, total_bytes)
        else:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                hasher.update(chunk)
                bytes_read += len(chunk)
                if progress_callback:
                    progress_callback(bytes_read, total_bytes if total_bytes >= 0 else -1)
    return hasher.hexdigest()


def hash_stream(
    chunks: Iterable[bytes],
    algo: str = "sha256",
) -> str:
    """Hash an arbitrary stream of byte chunks."""
    hasher = _get_hasher(algo)
    for chunk in chunks:
        if chunk:
            hasher.update(chunk)
    return hasher.hexdigest()

