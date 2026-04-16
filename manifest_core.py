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

import hashlib
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple

try:  # Support both package and flat-module imports
    from .hash_core import infer_algo_from_digest  # type: ignore[import]
except ImportError:  # pragma: no cover - flat layout
    from hash_core import infer_algo_from_digest  # type: ignore[import]

MANIFEST_CHAIN_VERSION = "1"
MANIFEST_GENESIS_PREVIOUS_HASH = hashlib.sha256(b"").hexdigest()

GNU_CHECKSUM_REGEX = re.compile(r"^([a-fA-F0-9]{32,128}) [ \*](.+)$")
BSD_CHECKSUM_REGEX = re.compile(r"^[A-Z0-9-]+\((.+)\)\s*=\s*([a-fA-F0-9]{32,128})$")


@dataclass
class ManifestEntry:
    path: str
    digest: str
    algo: str
    metadata: Optional[dict] = None
    root_index: int = 0


def _iter_lines(path: Path) -> Iterator[str]:
    with path.open(encoding="utf-8") as f:
        for line in f:
            yield line.rstrip("\n")


def _parse_gnu_checksum(path: Path) -> Iterator[ManifestEntry]:
    for line in _iter_lines(path):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
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


def _normalize_entry_path(file_path: str, fallback_root_dir: str | None) -> str:
    p = str(file_path)
    if fallback_root_dir and os.path.isabs(p):
        try:
            return os.path.relpath(p, os.path.abspath(fallback_root_dir)).replace("\\", "/")
        except Exception:
            return p.replace("\\", "/")
    return p.replace("\\", "/")


def _parse_json_manifest(
    path: Path, fallback_root_dir: str | None = None
) -> Iterator[tuple[ManifestEntry, Optional[List[str]]]]:
    """Yield (ManifestEntry, roots_or_none). roots_or_none is set once from the JSON; subsequent yields use None."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    files: List[dict]
    roots: Optional[List[str]] = None
    if isinstance(raw, dict):
        files = []
        if "entries" in raw and isinstance(raw.get("entries"), list):
            for item in raw.get("entries") or []:
                if not isinstance(item, dict):
                    continue
                fp = item.get("path")
                dg = (
                    item.get("sha256")
                    or item.get("sha512")
                    or item.get("digest")
                    or item.get("hash")
                )
                ha = item.get("hash_algo") or ("sha512" if item.get("sha512") else "sha256")
                if not fp or not dg:
                    continue
                files.append(
                    {
                        "path": _normalize_entry_path(str(fp), fallback_root_dir),
                        "digest": str(dg).lower(),
                        "algo": str(ha).lower(),
                    }
                )
        elif isinstance(raw.get("subject"), list):
            for sub in raw.get("subject") or []:
                if not isinstance(sub, dict):
                    continue
                fp = sub.get("name")
                digest_obj = sub.get("digest") if isinstance(sub.get("digest"), dict) else {}
                dg = digest_obj.get("sha256") or digest_obj.get("sha512")
                ha = "sha512" if digest_obj.get("sha512") else "sha256"
                if not fp or not dg:
                    continue
                files.append(
                    {
                        "path": _normalize_entry_path(str(fp), fallback_root_dir),
                        "digest": str(dg).lower(),
                        "algo": str(ha).lower(),
                    }
                )
        if "files" in raw and isinstance(raw.get("files"), list):
            files = raw.get("files") or []
        if "roots" in raw:
            roots = [str(r) for r in raw["roots"]]
        elif "root" in raw:
            roots = [str(raw["root"])]
    elif isinstance(raw, list):
        files = raw
    else:
        return iter(())  # type: ignore[return-value]
    for item in files:
        if not isinstance(item, dict):
            continue
        file_path = item.get("file") or item.get("path")
        digest = item.get("digest") or item.get("hash") or item.get("checksum")
        if not file_path or not digest:
            continue
        algo = item.get("algo") or infer_algo_from_digest(str(digest)) or "sha256"
        root_index = int(item.get("root_index", 0))
        meta = {
            k: v
            for k, v in item.items()
            if k not in {"file", "path", "digest", "hash", "checksum", "algo", "root_index"}
        }
        entry = ManifestEntry(
            path=_normalize_entry_path(str(file_path), fallback_root_dir),
            digest=str(digest).lower(),
            algo=str(algo),
            metadata=meta or None,
            root_index=root_index,
        )
        yield (entry, roots)


def load_manifest(
    manifest_path: str, fallback_root_dir: str | None = None
) -> tuple[Dict[str, ManifestEntry], List[str]]:
    """Load a manifest file into an in-memory dict and roots list.

    Returns (entries, roots). entries is keyed by 'root_index:path' for multi-root
    or 'path' for single-root. roots is from JSON (root/roots) or [fallback_root_dir]
    for GNU/BSD manifests.
    """
    path = Path(manifest_path)
    entries: Dict[str, ManifestEntry] = {}
    roots: List[str] = []
    ext = path.suffix.lower()

    if ext in {".json"}:
        for entry, roots_val in _parse_json_manifest(path, fallback_root_dir):
            if roots_val is not None:
                roots = roots_val
            key = f"{entry.root_index}:{entry.path}" if roots and len(roots) > 1 else entry.path
            entries[key] = entry
        if not roots and fallback_root_dir:
            roots = [os.path.abspath(fallback_root_dir)]
        return (entries, roots if roots else ([fallback_root_dir] if fallback_root_dir else []))

    gnu_iter = _parse_gnu_checksum(path)
    try:
        first = next(gnu_iter)
    except StopIteration:
        parser: Iterable[ManifestEntry] = _parse_bsd_checksum(path)
    else:
        def _chain_first() -> Iterator[ManifestEntry]:
            yield first
            for rest in gnu_iter:
                yield rest

        parser = _chain_first()

    for entry in parser:
        entries[entry.path] = entry
    roots = [os.path.abspath(fallback_root_dir)] if fallback_root_dir else []
    return (entries, roots)


def manifest_row_chain_digest(entry: dict[str, Any]) -> str:
    """SHA-256 of stable JSON for one manifest row; previous_entry_hash is excluded from the material."""
    slim = {k: v for k, v in sorted(entry.items()) if k != "previous_entry_hash"}
    blob = json.dumps(slim, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def verify_manifest_hash_chain(raw_manifest: dict[str, Any]) -> Tuple[bool, str]:
    """
    When chain_version matches MANIFEST_CHAIN_VERSION, verify previous_entry_hash links.
    Legacy manifests without chain_version skip successfully.
    """
    if str(raw_manifest.get("chain_version") or "") != MANIFEST_CHAIN_VERSION:
        return True, "chain not enabled"
    entries = raw_manifest.get("entries")
    if not isinstance(entries, list):
        return False, "manifest entries must be a list when chain_version is set"
    expected = MANIFEST_GENESIS_PREVIOUS_HASH
    for i, item in enumerate(entries):
        if not isinstance(item, dict):
            return False, f"manifest entry {i} must be an object"
        prev = str(item.get("previous_entry_hash") or "")
        if prev != expected:
            return False, f"manifest hash chain broken at index {i}"
        expected = manifest_row_chain_digest(item)
    return True, "ok"
