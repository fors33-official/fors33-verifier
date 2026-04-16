#!/usr/bin/env python3
"""
Shared hashing utilities for fors33-verifier.

Supports SHA-256 (default), SHA-512, MD5, SHA-1, and optional BLAKE3 with
streaming, chunk-based hashing suitable for large files.

Parity (0.6.0): cgroup/RAM mmap bounds, PSI gate, and default_dpk_worker_count match
fors33-scanner/hash_core.py; this tree additionally exposes set_global_read_bytes_per_second
and _throttle_before_read for extension/hosted use (chunked reads only).
"""
from __future__ import annotations

import hashlib
import mmap
import os
import re
import sys
import threading
import time
from typing import Callable, Iterable, Optional

# Global read-rate limit (bytes/sec) for chunked reads; None disables throttling.
_io_bucket_lock = threading.Lock()
_io_bps: Optional[float] = None
_tb_tokens: float = 0.0
_tb_last: float = 0.0


def set_global_read_bytes_per_second(bps: Optional[float]) -> None:
    """Configure daemon-wide disk read throttle (None = unlimited)."""
    global _io_bps, _tb_tokens, _tb_last
    with _io_bucket_lock:
        _io_bps = None if bps is None or bps <= 0 else float(bps)
        _tb_tokens = 0.0
        _tb_last = time.monotonic()


def _throttle_before_read(num_bytes: int) -> None:
    """Block until token bucket allows reading num_bytes (coarse global cap)."""
    global _tb_tokens, _tb_last
    if num_bytes <= 0:
        return
    while True:
        sleep_s = 0.0
        with _io_bucket_lock:
            bps = _io_bps
            if bps is None:
                return
            now = time.monotonic()
            elapsed = now - _tb_last
            _tb_last = now
            _tb_tokens = min(bps * 2.0, _tb_tokens + elapsed * bps)
            if _tb_tokens >= num_bytes:
                _tb_tokens -= float(num_bytes)
                return
            deficit = float(num_bytes) - _tb_tokens
            sleep_s = min(0.25, max(0.001, deficit / bps))
        time.sleep(sleep_s)


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


def path_for_kernel(path: str) -> str:
    """On Windows, normalize absolute path for kernel calls (stat, open)."""
    if os.name != "nt":
        return path
    if not os.path.isabs(path):
        return path
    path = path.replace("/", "\\")
    if path.startswith("\\\\") and not path.startswith("\\\\?\\"):
        return "\\\\?\\UNC\\" + path[2:]
    if len(path) >= 2 and path[1] == ":":
        return "\\\\?\\" + path
    return path


def path_from_kernel(path: str) -> str:
    """Strip Windows long-path prefix for relpath/comparison with non-prefixed paths."""
    if os.name != "nt":
        return path
    if path.startswith("\\\\?\\UNC\\"):
        return "\\\\" + path[7:]
    if path.startswith("\\\\?\\"):
        return path[4:]
    return path


def _read_first_line_int_bytes(path: str) -> Optional[int]:
    """Read a single cgroup limit file; return positive bytes or None if max/unlimited/unreadable."""
    try:
        with open(path, encoding="ascii", errors="replace") as f:
            raw = f.read().strip()
    except OSError:
        return None
    if not raw or raw.lower() == "max":
        return None
    try:
        v = int(raw, 10)
    except ValueError:
        return None
    return v if v > 0 else None


def _linux_cgroup_v2_rel_path() -> Optional[str]:
    if not sys.platform.startswith("linux"):
        return None
    try:
        with open("/proc/self/cgroup", encoding="ascii", errors="replace") as f:
            for line in f:
                line = line.strip()
                if line.startswith("0::"):
                    tail = line[3:].strip()
                    if not tail or tail == "/":
                        return "/"
                    return tail if tail.startswith("/") else "/" + tail
    except OSError:
        return None
    return None


def _cgroup_v2_dir() -> Optional[str]:
    rel = _linux_cgroup_v2_rel_path()
    if rel is None:
        return None
    base = "/sys/fs/cgroup"
    if rel in ("/", ""):
        return base
    return os.path.normpath(base + rel)


def _memory_ceiling_bytes_linux() -> Optional[int]:
    """
    Host/container memory ceiling (fallback chain):
    cgroup v2 memory.max, else cgroup v1 memory.limit_in_bytes, else visible RAM.
    """
    cg2 = _cgroup_v2_dir()
    if cg2:
        v = _read_first_line_int_bytes(os.path.join(cg2, "memory.max"))
        if v is not None:
            return v
    try:
        with open("/proc/self/cgroup", encoding="ascii", errors="replace") as f:
            lines = f.readlines()
    except OSError:
        lines = []
    mem_rel: Optional[str] = None
    for line in lines:
        parts = line.strip().split(":")
        if len(parts) >= 3 and "memory" in parts[1].split(","):
            mem_rel = parts[2]
            break
    if mem_rel:
        v1_path = os.path.normpath("/sys/fs/cgroup/memory" + (mem_rel if mem_rel.startswith("/") else "/" + mem_rel))
        lim = _read_first_line_int_bytes(os.path.join(v1_path, "memory.limit_in_bytes"))
        if lim is not None:
            huge = 1 << 60
            if lim < huge:
                return lim
    try:
        pages = int(os.sysconf("SC_PHYS_PAGES"))
        psize = int(os.sysconf("SC_PAGE_SIZE"))
        if pages > 0 and psize > 0:
            return pages * psize
    except (ValueError, OSError, AttributeError, TypeError):
        pass
    return None


def _memory_ceiling_bytes() -> Optional[int]:
    if sys.platform.startswith("linux"):
        return _memory_ceiling_bytes_linux()
    if os.name != "nt":
        try:
            pages = int(os.sysconf("SC_PHYS_PAGES"))
            psize = int(os.sysconf("SC_PAGE_SIZE"))
            if pages > 0 and psize > 0:
                return pages * psize
        except (ValueError, OSError, AttributeError, TypeError):
            pass
    return None


def _cgroup_v2_memory_pressure_some_avg10() -> Optional[float]:
    """Parse memory.pressure 'some' line avg10 for this process cgroup; None if missing or unusable."""
    cg2 = _cgroup_v2_dir()
    if not cg2:
        return None
    path = os.path.join(cg2, "memory.pressure")
    try:
        with open(path, encoding="ascii", errors="replace") as f:
            text = f.read()
    except OSError:
        return None
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("some"):
            continue
        m = re.search(r"avg10=([0-9.]+)", line)
        if not m:
            return None
        try:
            return float(m.group(1))
        except ValueError:
            return None
    return None


def _mmap_psi_disables_mmap() -> bool:
    raw = os.environ.get("FORS33_MMAP_PSI_SOME_AVG10_MAX", "").strip()
    if not raw:
        return False
    try:
        cap = float(raw)
    except ValueError:
        return False
    if cap < 0.0:
        return False
    avg10 = _cgroup_v2_memory_pressure_some_avg10()
    if avg10 is None:
        return False
    return avg10 > cap


def _effective_mmap_bounds_bytes() -> tuple[int, int]:
    """
    Return (mmap_min_bytes, mmap_max_bytes) after cgroup/RAM ceiling and env overrides.

    Order: cgroup v2 max, v1 limit, RAM for ceiling; then clamp user FORS33_MMAP_MAX_MB
    to ceiling; FORS33_MMAP_MIN_MB / defaults applied last.
    """
    mmap_min_mb = int(os.environ.get("FORS33_MMAP_MIN_MB", "500"))
    mmap_max_mb = int(os.environ.get("FORS33_MMAP_MAX_MB", "4000"))
    mmap_min_b = max(0, mmap_min_mb) * 1024 * 1024
    mmap_max_b = max(0, mmap_max_mb) * 1024 * 1024
    ceiling = _memory_ceiling_bytes()
    if ceiling is not None:
        reserve = 64 * 1024 * 1024
        cap_b = max(0, ceiling - reserve)
        if mmap_max_b > 0:
            mmap_max_b = min(mmap_max_b, cap_b)
        else:
            mmap_max_b = cap_b
    if mmap_max_b > 0 and mmap_min_b > mmap_max_b:
        mmap_min_b = mmap_max_b
    return mmap_min_b, mmap_max_b


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
    total_bytes is -1 when unknown.
    """
    hasher = _get_hasher(algo)
    total_bytes = -1
    remaining: Optional[int] = None
    if end is not None:
        remaining = max(0, end - start)
        total_bytes = remaining
    else:
        try:
            total_bytes = os.path.getsize(path_for_kernel(path)) - start
        except OSError:
            pass

    mmap_min, mmap_max = _effective_mmap_bounds_bytes()
    psi_mmap_off = _mmap_psi_disables_mmap()
    can_try_mmap = (
        not psi_mmap_off
        and remaining is None
        and end is None
        and start == 0
        and mmap_max > 0
        and total_bytes >= mmap_min
        and total_bytes <= mmap_max
    )
    bytes_read = 0
    buffer = bytearray(chunk_size)
    with open(path_for_kernel(path), "rb") as f:
        if can_try_mmap:
            try:
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                    hasher.update(mm)
                    if progress_callback:
                        progress_callback(total_bytes, total_bytes)
                return hasher.hexdigest()
            except Exception:
                pass
        f.seek(start)
        if remaining is not None:
            while remaining > 0:
                to_read = min(remaining, chunk_size)
                _throttle_before_read(to_read)
                n = f.readinto(memoryview(buffer)[:to_read])
                if n <= 0:
                    break
                hasher.update(memoryview(buffer)[:n])
                remaining -= n
                bytes_read += n
                if progress_callback:
                    progress_callback(bytes_read, total_bytes)
        else:
            while True:
                _throttle_before_read(chunk_size)
                n = f.readinto(buffer)
                if n <= 0:
                    break
                hasher.update(memoryview(buffer)[:n])
                bytes_read += n
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


def default_dpk_worker_count() -> int:
    """Shared worker cap for scan_dpk and verify_dpk (FORS33_DPK_MAX_WORKERS clamps cpu-based default)."""
    n = os.cpu_count() or 1
    w = min(32, max(1, n))
    cap = os.environ.get("FORS33_DPK_MAX_WORKERS", "").strip()
    if cap:
        try:
            c = int(cap, 10)
            if c >= 1:
                w = min(w, c)
        except ValueError:
            pass
    return w
