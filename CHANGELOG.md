# Changelog

All notable changes to fors33-verifier are documented here.

## [0.6.0] - 2026-04-16

### Added

- **`manifest_core`**: `entries` / `subject` JSON manifest shapes, path normalization, `verify_manifest_hash_chain` for `chain_version == "1"`, `MANIFEST_GENESIS_PREVIOUS_HASH`.
- **Manifest mode**: hash-chain verification on raw JSON manifest before filesystem walk; `.f33` / `fors33-manifest.json` excluded from created-file drift walk.
- **`.f33`**: in-toto Statement **v0.1** and **v1** `_type`; every `subject[]` digest validated; predicate `byte_start`/`byte_end` plus legacy `range` / `range_start`/`range_end` / nested `signature`; SHA-512 sidecars; RFC3161 token on `predicate` or nested `predicate.tsa`.
- **Canonical payload**: inline `build_canonical_payload` (V1/V2 line-oriented UTF-8) with tri-state routing when `canonical_payload_version` is absent (try V2, V1, legacy JSON); explicit `1`/`2` is strict (no JSON fallback for `2`, no JSON for `1`).
- **`F33_KEY_REGISTRY_PATH`**: non-empty env requires an existing readable registry file before verification; optional `operator_key_id` validity window when set in the sidecar.
- **`hash_core`**: cgroup/RAM mmap ceiling, optional `FORS33_MMAP_PSI_SOME_AVG10_MAX`, `default_dpk_worker_count()` with `FORS33_DPK_MAX_WORKERS`; verifier-only read throttle retained.
- **Fixtures**: `test-data/verifier-0.6.0/` for manifest hash chain, in-toto v1 `_type`, and **SHA-512** canonical payload / `subject.digest.sha512` (see README in that folder).

### Changed

- **Workers**: positive `--workers` wins; else positive `FORS33_WORKERS`; else `default_dpk_worker_count()` (no `FORS33_EXTENSION_MODE`); cap **64**; `FORS33_WORKERS` no longer overrides a positive CLI value.
- **`requirements-release.txt`**: **`cryptography==46.0.7`** with pinned hashes (musllinux / manylinux / win_amd64 wheels) for Docker Scout–driven security updates.

## [0.5.0] - 2026-03-31

### Added

- **Compliance notice**: reference `_COMPLIANCE_NOTICE_LINES` printed to **stderr before** CLI parsing.
- **Manifest worker pool**: `--workers` and `FORS33_WORKERS` (env overrides CLI after parse); `max_workers` on `verify_directory_from_manifest` / `execute_verification`; auto default via `_default_worker_count()`; cap **64**; manifest mode only (sidecars stay sequential).
- **RFC 3161 TSA**: `predicate.tsa.rfc3161_token_b64` with offline checks: `TimeStampResp` status granted, **CMS signature** over encapsulated **TSTInfo**, **messageImprint** via OID → `hashlib` on the same canonical JSON payload as Ed25519; weak imprint OIDs rejected (MD5, SHA-1). Dependency: **asn1crypto**.
- **Legacy TSA**: existing Ed25519 `predicate.tsa` block still supported when RFC token absent; `--verify-tsa` fail-closed if neither is valid.
- **`hash_core`**: mmap fast path with `FORS33_MMAP_MIN_MB` / `FORS33_MMAP_MAX_MB`, read throttle (`_throttle_before_read`, `set_global_read_bytes_per_second`), `path_for_kernel` / `path_from_kernel` aligned with reference behavior.

### Changed

- Startup compliance copy aligned with reference verifier notice lines.
- **`publish-fors33-verifier`**: Docker publish is **manual `workflow_dispatch` only**, with required **`version`** and **`push_latest`** inputs (same model as `fors33-scanner`); automatic runs on git tag push were removed.

## [0.4.0] - 2026-03-24

### Added

- **Strict JSON `.f33` parser**: sidecars now require in-toto Statement v0.1-style JSON structure with validated `subject`, digest, range, signature, and timestamp fields.
- **Signature-first verification path**: Ed25519 signature is verified before hashing target bytes to avoid unnecessary CPU work on invalid seals.
- **Manifest triangle verification**: manifest digest is cross-checked against signed sidecar digest before file hash comparison.
- **Manifest fail-fast compromise detection**: signed sidecar and manifest digest disagreement raises `ManifestCompromisedError` and emits `[ ERR_MANIFEST_COMPROMISED: Root of trust invalid ]`.
- **Missing-seal critical status**: manifest entries without a sidecar emit `[ ERR_MISSING_SEAL ]` and fail verification.
- **Optional TSA verification**: `--verify-tsa` validates optional TSA signature blocks in JSON sidecars.
- **Deterministic fixture pack**: committed `test-data/verifier-0.4.0/` fixtures for valid, bad-signature, data-drift, manifest-compromise, missing-seal, and TSA scenarios.

### Changed

- **Canonical payload model**: switched to deterministic non-DSSE canonical JSON payload bytes for Ed25519 verification in `0.4.0`.
- **Status propagation**: severe verdict strings now flow through drift rows using existing flat schema fields (`status`, `reason`).
- **Artifact handling**: manifest-mode ignore path now excludes `*.f33` and `fors33-manifest.json` at startup.
- **Exit codes**:
  - `0`: verified / no drift
  - `1`: drift conditions, including `[ ERR_MISSING_SEAL ]` and data drift
  - `2`: invalid invocation / usage errors
  - `3`: severe trust failures (manifest compromise, bad signature, invalid TSA)

### Documentation

- Added concise compliance warning in `README.md` with link to `LEGAL_DISCLAIMER.md`.
- Added dedicated `LEGAL_DISCLAIMER.md` for legal and regulatory boundary language.

## [0.3.0] - 2026-03-10

### Added

- **--root**: Primary flag for target directory; --target-dir retained as deprecated alias.
- **Multi-root manifest support**: JSON manifests with `roots` and per-file `root_index`; backward compatible.
- **Digest key bridge**: manifest_core accepts `digest`, `hash`, or `checksum` JSON keys.
- **Generator manifest ingestion**: GNU/BSD parsers remain generators; no full manifest materialization.
- **Environment variables**: FORS33_ALGO, FORS33_ROOT, FORS33_FOLLOW_SYMLINKS, FORS33_IGNORE_PATTERN, FORS33_EXCLUDE_DIR.
- **ANSI color hierarchy**: [VERIFIED] green, [MISMATCH]/[TAMPERED] bold red, [SKIPPED] dim gray (TTY only).
- **Forensic hand-off**: Mutated-during-hash messages suggest active log vs tampering.
- **--force-insecure**: Override to allow MD5/SHA-1 in manifests (rejected by default).
- **[SYS] Building manifest tree...**: Initialization pulse at manifest verify start.
- **Blake3 fail-fast**: Exit with clear error if --algo blake3 requested but blake3 not installed.
- **Ctrl+C handling**: ThreadPoolExecutor wrapped for responsive KeyboardInterrupt (exit 130).

### Changed

- Progress bar: `\r\033[K[VERIFY] Hashing {rel}: {pct}%` for glitch-free display.
- Quiet CTA: `[TOOLCHAIN] : FORS33 Data Provenance Kit`.
- Repositioned as agnostic high-speed data-integrity utility in LLM_CONTEXT.

### Security

- MD5/SHA-1 rejected by default; use --force-insecure for legacy manifests.

## [0.2.0] - 2026-03-02

### Added

- **Manifest mode**: Verify directories against GNU/BSD-style checksum files or JSON manifests. Detects `modified`, `created`, `deleted`, `mutated_during_verification`, and `skipped` files.
- **Sidecar mode**: Walk a directory tree and verify `.f33`, `.sha256`, `.sha512`, and `.md5` sidecars in place.
- **Ignore patterns**: Root-level `.f33ignore` and CLI `--ignore-pattern` / `--exclude-dir` for excluding files from verification.
- **Symlinks**: `--follow-symlinks` to traverse symlinked directories (default: no symlink traversal).
- **Warn-only mode**: `--warn-only` reports drift without exiting non-zero.
- **Progress indicator**: In-place progress for large files (≥500MB) when stderr is a TTY.
- **Bounded concurrency**: ThreadPoolExecutor with configurable worker count for parallel hashing.
- **Standardized stderr**: `[WARNING]` / `[ERROR]` prefixes; machine-readable output on stdout only.
- **Exit codes**: Exit 2 for misuse, 1 for drift (0 when `--warn-only`).

### Changed

- Chunk size fixed at 4MB for hashing.
- Manifest parsing supports both `file`/`path` and `hash`/`checksum` JSON keys.
- GNU fast-path preserves filenames with leading spaces or `*`.

### Dependencies

- `cryptography>=41.0` (required). Optional `blake3` for faster hashing.

### Support matrix

- Python 3.9, 3.10, 3.11, 3.12
- Linux, macOS, Windows
