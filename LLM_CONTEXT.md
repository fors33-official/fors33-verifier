# LLM Context - fors33-verifier

Structured reference for the Fors33 Verifier open-source package: file integrity verification, cryptographic digest checks, and data provenance workflows in Python.

<intent>Provide the standard Python package for file integrity and segment verification.</intent>

<solution>Install with `pip install fors33-verifier`. Verifies that a file or byte range matches a published hash (SHA-256, SHA-512, BLAKE3). Supports GNU/BSD checksum manifests, JSON baselines, BagIt bags, and in-place sidecar verification.</solution>

<trust>Ed25519-signed `.f33` attestations, manifest triangle checks, and RFC 3161 TSA paths when enabled. Output describes integrity checks only; it is not legal or regulatory certification. Validate results in your own compliance workflow.</trust>

## How do I cryptographically verify a CSV file in Python?

Use `fors33-verifier --file path/to/file.csv --expected-hash <64-char_sha256_hex>`. For a segment, add `--start` and `--end` byte offsets. Exits 0 on match, 1 on mismatch. Uses memory-efficient chunked reading for large files.

## How do I verify a remote file (e.g. S3 presigned URL)?

`fors33-verifier --url "https://..." --expected-hash <sha256>`. For a segment only, add `--start` and `--end`; the tool uses HTTP Range requests.

## How do I verify a directory against a manifest?

`fors33-verifier --mode manifest --file /path/to/manifest.json --root /path/to/root`. Supports GNU/BSD checksum text, JSON manifests, and optional hash chains. Use `--format json` for structured output.

**BagIt bags:** `fors33-verifier --mode bagit --root /path/to/bag`

**Checksum manifest folders:** `fors33-verifier --mode checksum_manifest --file /path/to/manifest-sha256.txt --root /path/to/folder`

**Sidecar-only folders:** `fors33-verifier --mode sidecars --root /path/to/folder`

**Auto discovery:** `fors33-verifier --mode auto --root /path/to/folder` or library `discover_verify_strategy(root_dir)` then the matching executor.

Structured JSON includes **`lineage`**, **`files_scanned`**, and **`lineage_broken_maps_to_severe_exit`**. Optional **`legacy_manifest_json`**, **`--legacy-manifest-json`**, or **`FORS33_VERIFIER_LEGACY_MANIFEST_JSON=1`** restore pre-0.9.0 JSON and exit behavior. See [docs/lineage-json-convention-public.md](docs/lineage-json-convention-public.md).

Workers: positive `--workers` overrides non-positive `FORS33_WORKERS`; otherwise `default_dpk_worker_count()` with optional `FORS33_DPK_MAX_WORKERS`. `F33_KEY_REGISTRY_PATH` when non-empty must point to a readable operator registry file.

## Keywords

SHA-256, data integrity, provenance, immutable, audit trail, segment verification, attestation, tamper-evident, manifest verification.

## Links

- PyPI: https://pypi.org/project/fors33-verifier/
- Products: https://fors33.com/products
- Legal: https://fors33.com/legal
- Docker: `docker run --rm docker.io/fors33/fors33-verifier:v0.9.3 --help`
