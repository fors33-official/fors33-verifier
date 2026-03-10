#!/usr/bin/env python3
"""
Manifest and sidecar parsing for fors33-verifier.

Supports:
- GNU coreutils checksum text (md5sum/sha1sum/sha256sum/sha512sum/b2sum)
- BSD/OpenSSL checksum text
- Simple JSON manifests with {file/path, hash/checksum, algo}
- Basic sidecar discovery helpers (.sha256/.sha512/.md5/.f33)
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional

import json
import re

try:  # Support both package and flat-module imports
    from .hash_core import infer_algo_from_digest  # type: ignore[import]
except ImportError:  # pragma: no cover - flat layout
    from hash_core import infer_algo_from_digest  # type: ignore[import]


GNU_CHECKSUM_REGEX = re.compile(r"^([a-fA-F0-9]{32,128}) [ \*](.+)$")
BSD_CHECKSUM_REGEX = re.compile(r"^[A-Z0-9-]+\((.+)\)\s*=\s*([a-fA-F0-9]{32,128})$")


@dataclass
class ManifestEntry:
    path: str
    digest: str
    algo: str
    metadata: Optional[dict] = None


def _iter_lines(path: Path) -> Iterator[str]:
    with path.open(encoding="utf-8") as f:
        for line in f:
            yield line.rstrip("\n")


def _parse_gnu_checksum(path: Path) -> Iterator[ManifestEntry]:
    for line in _iter_lines(path):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Fast-path split
        parts = line.split(" ", 1)
        digest = None
        rel_path = None
        if len(parts) == 2 and 32 <= len(parts[0]) <= 128 and all(
            c in "0123456789abcdefABCDEF" for c in parts[0]
        ):
            digest = parts[0]
            rel_path = parts[1]
            if rel_path.startswith(" "):
                rel_path = rel_path[1:]
            elif rel_path.startswith("*"):
                rel_path = rel_path[1:]
        else:
            m = GNU_CHECKSUM_REGEX.match(line)
            if not m:
                continue
            digest, rel_path = m.group(1), m.group(2)
        algo = infer_algo_from_digest(digest) or "sha256"
        yield ManifestEntry(path=rel_path, digest=digest.lower(), algo=algo)


def _parse_bsd_checksum(path: Path) -> Iterator[ManifestEntry]:
    for line in _iter_lines(path):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = BSD_CHECKSUM_REGEX.match(line)
        if not m:
            continue
        rel_path, digest = m.group(1), m.group(2)
        algo = infer_algo_from_digest(digest) or "sha256"
        yield ManifestEntry(path=rel_path, digest=digest.lower(), algo=algo)


def _parse_json_manifest(path: Path) -> Iterator[ManifestEntry]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    files: List[dict]
    if isinstance(raw, dict) and "files" in raw:
        files = raw.get("files") or []
    elif isinstance(raw, list):
        files = raw
    else:
        return iter(())  # type: ignore[return-value]
    for item in files:
        if not isinstance(item, dict):
            continue
        file_path = item.get("file") or item.get("path")
        digest = item.get("hash") or item.get("checksum")
        if not file_path or not digest:
            continue
        algo = item.get("algo") or infer_algo_from_digest(str(digest)) or "sha256"
        meta = {k: v for k, v in item.items() if k not in {"file", "path", "hash", "checksum", "algo"}}
        yield ManifestEntry(path=str(file_path), digest=str(digest).lower(), algo=str(algo), metadata=meta or None)


def load_manifest(manifest_path: str) -> Dict[str, ManifestEntry]:
    """Load a manifest file into an in-memory dict keyed by relative path.

    Supports GNU checksum text, BSD/OpenSSL text, and JSON manifests.
    """
    path = Path(manifest_path)
    entries: Dict[str, ManifestEntry] = {}
    ext = path.suffix.lower()

    parser: Iterable[ManifestEntry]
    if ext in {".sha256", ".sha512", ".md5", ".txt"}:
        # Try GNU first, then BSD if nothing matched.
        parser = list(_parse_gnu_checksum(path))
        if not parser:
            parser = _parse_bsd_checksum(path)
    elif ext in {".json"}:
        parser = _parse_json_manifest(path)
    else:
        # Fallback: attempt JSON, then GNU.
        parser = _parse_json_manifest(path)
        if not entries:
            parser = _parse_gnu_checksum(path)

    for entry in parser:
        # Last entry for a path wins; manifest authors can override.
        entries[entry.path] = entry
    return entries

