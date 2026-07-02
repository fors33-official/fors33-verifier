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

from hash_core import infer_algo_from_digest

# Linear hash chain over manifest rows (optional; see chain_version on manifest root).
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


def is_path_within_root(path: str, root: str) -> bool:
    """True when path resolves under root (commonpath guard)."""
    try:
        root_abs = os.path.abspath(root)
        path_abs = os.path.abspath(path)
        return os.path.commonpath([root_abs, path_abs]) == root_abs
    except Exception:
        return False


def _is_manifest_abs_path(file_path: str) -> bool:
    """True for OS abs paths and Unix-style absolutes from sealed manifests (e.g. /var/lib/...)."""
    p = str(file_path or "")
    if os.path.isabs(p):
        return True
    return len(p) > 1 and p[0] == "/" and not p.startswith("//")


def resolve_manifest_member_path(
    root_dir: str,
    candidate: str,
    *,
    basename_fallback: bool = False,
) -> str | None:
    """Join relative manifest member path under root_dir; reject paths outside root.

    When ``basename_fallback`` is True (manifest verify), try the entry basename if the
    full manifest path does not resolve (non-portable seal-environment paths).
    """
    raw = str(candidate or "").strip()
    if not raw:
        return None
    norm = raw.replace("\\", "/")

    def _resolve_one(member: str) -> str | None:
        if _is_manifest_abs_path(member):
            return None
        path = os.path.abspath(os.path.join(root_dir, member))
        if not is_path_within_root(path, root_dir):
            return None
        return path

    resolved = _resolve_one(norm)
    if resolved is not None:
        return resolved
    if basename_fallback:
        base = os.path.basename(norm)
        if base and base != norm:
            return _resolve_one(base)
    return None


def _normalize_entry_path(file_path: str, fallback_root_dir: str | None) -> str:
    p = str(file_path)
    if _is_manifest_abs_path(p):
        if fallback_root_dir:
            root_abs = os.path.abspath(fallback_root_dir)
            try:
                rel = os.path.relpath(p, root_abs).replace("\\", "/")
                if not rel.startswith(".."):
                    resolved = os.path.abspath(os.path.join(root_abs, rel))
                    if is_path_within_root(resolved, root_abs):
                        return rel
            except Exception:
                pass
        return os.path.basename(p.replace("\\", "/"))
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
        # Canonical L3dgr manifest format: {"version":"1.0","entries":[...]}
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
        # In-toto Statement style manifest with subject list.
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

    # GNU or BSD
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


def recompute_manifest_hash_chain(raw_manifest: dict[str, Any]) -> None:
    """Re-link previous_entry_hash after entry fields change (e.g. portable path rewrite)."""
    if str(raw_manifest.get("chain_version") or "") != MANIFEST_CHAIN_VERSION:
        return
    entries = raw_manifest.get("entries")
    if not isinstance(entries, list):
        return
    expected = MANIFEST_GENESIS_PREVIOUS_HASH
    for item in entries:
        if not isinstance(item, dict):
            continue
        item["previous_entry_hash"] = expected
        expected = manifest_row_chain_digest(item)


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


def manifest_chain_tip_from_manifest(raw_manifest: dict[str, Any]) -> str | None:
    """Return the ledger head digest (last row chain hash) or None when empty."""
    entries = raw_manifest.get("entries")
    if not isinstance(entries, list) or not entries:
        return None
    last = entries[-1]
    if not isinstance(last, dict):
        return None
    return manifest_row_chain_digest(last)


def manifest_chain_tip_from_path(manifest_path: str) -> str | None:
    """Load fors33-manifest.json and return chain tip hex, or None."""
    path = str(manifest_path or "").strip()
    if not path or not os.path.isfile(path):
        return None
    try:
        with open(path, encoding="utf-8") as fp:
            raw = json.load(fp)
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(raw, dict):
        return None
    return manifest_chain_tip_from_manifest(raw)


# --- BagIt (RFC 8493) discovery (verify-only; no fetch.txt retrieval) ---

BAGIT_PAYLOAD_DIRNAME = "data"
_BAGIT_MANIFEST_NAME_RE = re.compile(r"^manifest-([a-z0-9]+)\.txt$", re.IGNORECASE)
_BAGIT_SUPPORTED_VERSIONS = frozenset({"0.97", "1.0"})
BAGIT_TAG_BASENAMES = frozenset(
    {
        "bagit.txt",
        "bag-info.txt",
        "fetch.txt",
    }
)


@dataclass
class BagItLayout:
    bag_root: str
    payload_dir: str
    bagit_txt_path: str
    bagit_version: str
    payload_manifests: List[tuple[str, str]]
    has_fetch_txt: bool


def _parse_bagit_txt(path: str) -> dict[str, str]:
    """Parse bagit.txt key-value tag file (RFC 8493 §2.3)."""
    out: dict[str, str] = {}
    try:
        with open(path, encoding="utf-8") as fp:
            for raw_line in fp:
                line = raw_line.rstrip("\n\r")
                if not line or line.startswith("#"):
                    continue
                if ":" not in line:
                    continue
                key, val = line.split(":", 1)
                out[key.strip()] = val.strip()
    except OSError:
        return {}
    return out


def _bagit_manifest_algo_from_name(name: str) -> str | None:
    m = _BAGIT_MANIFEST_NAME_RE.match(name)
    if not m:
        return None
    algo = m.group(1).lower()
    if algo in ("md5", "sha1", "sha256", "sha512"):
        return algo
    return infer_algo_from_digest("a" * {"md5": 32, "sha1": 40, "sha256": 64, "sha512": 128}.get(algo, 64)) or algo


def discover_bagit_layout(root_dir: str) -> BagItLayout | None:
    """Return BagIt layout when root_dir is a bag root (bagit.txt + data/ + payload manifest)."""
    root = os.path.abspath(str(root_dir or "").strip())
    bagit_txt = os.path.join(root, "bagit.txt")
    if not os.path.isfile(bagit_txt):
        return None
    payload_dir = os.path.join(root, BAGIT_PAYLOAD_DIRNAME)
    if not os.path.isdir(payload_dir):
        return None
    tags = _parse_bagit_txt(bagit_txt)
    version = str(tags.get("BagIt-Version") or "1.0").strip()
    if version not in _BAGIT_SUPPORTED_VERSIONS:
        return None
    manifests: List[tuple[str, str]] = []
    try:
        for name in sorted(os.listdir(root)):
            algo = _bagit_manifest_algo_from_name(name)
            if not algo:
                continue
            full = os.path.join(root, name)
            if os.path.isfile(full):
                manifests.append((os.path.abspath(full), algo))
    except OSError:
        return None
    if not manifests:
        return None
    fetch_path = os.path.join(root, "fetch.txt")
    return BagItLayout(
        bag_root=root,
        payload_dir=os.path.abspath(payload_dir),
        bagit_txt_path=os.path.abspath(bagit_txt),
        bagit_version=version,
        payload_manifests=manifests,
        has_fetch_txt=os.path.isfile(fetch_path),
    )


def bagit_payload_relpaths(layout: BagItLayout) -> set[str]:
    """Union of payload member paths (``data/...``) listed in all payload manifests."""
    paths: set[str] = set()
    for manifest_path, _algo in layout.payload_manifests:
        entries, _roots = load_manifest(manifest_path, fallback_root_dir=layout.bag_root)
        for entry in entries.values():
            norm = str(entry.path or "").replace("\\", "/").lstrip("/")
            if not norm.startswith(f"{BAGIT_PAYLOAD_DIRNAME}/"):
                norm = f"{BAGIT_PAYLOAD_DIRNAME}/{norm}"
            paths.add(norm)
    return paths


def is_bagit_tag_basename(name: str) -> bool:
    """True for bag declaration/tag files that scan should skip as data candidates."""
    lower = str(name or "").lower()
    if lower in BAGIT_TAG_BASENAMES:
        return True
    if _BAGIT_MANIFEST_NAME_RE.match(name):
        return True
    if lower.startswith("tagmanifest-") and lower.endswith(".txt"):
        return True
    return False

