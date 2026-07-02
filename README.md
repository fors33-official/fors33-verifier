# fors33-verifier

[![CI](https://img.shields.io/github/actions/workflow/status/fors33-official/fors33-verifier/publish-fors33-verifier.yml?branch=main&style=flat-square)](https://github.com/fors33-official/fors33-verifier/actions)
[![Release](https://img.shields.io/badge/release-v0.9.3-blue?style=flat-square)](https://pypi.org/project/fors33-verifier/)
[![PyPI](https://img.shields.io/pypi/v/fors33-verifier?style=flat-square)](https://pypi.org/project/fors33-verifier/)
[![Docker Tag](https://img.shields.io/badge/docker-v0.9.3%20%7C%20latest-2496ED?style=flat-square&logo=docker&logoColor=white)](https://hub.docker.com/r/fors33/fors33-verifier)
[![Docker Pulls](https://img.shields.io/docker/pulls/fors33/fors33-verifier?style=flat-square)](https://hub.docker.com/r/fors33/fors33-verifier)
[![License](https://img.shields.io/github/license/fors33-official/fors33-verifier?style=flat-square)](https://github.com/fors33-official/fors33-verifier/blob/main/LICENSE)

Standalone verification for attested data segments and general-purpose file integrity baselines. For machine-readable context (LLMs, crawlers), see [LLM_CONTEXT.md](LLM_CONTEXT.md). Confirm that a data segment or directory tree matches published hashes.

> Warning: Fors33 Verifier provides cryptographic integrity checks only. It does not independently guarantee legal or regulatory compliance. See [LEGAL_DISCLAIMER.md](LEGAL_DISCLAIMER.md).

<details>
<summary><strong>Release notes &amp; version history</strong></summary>

### v0.9.3 (2026-07-02)

- **Auto verify mode:** `--mode auto` and `discover_verify_strategy(root_dir)` pick manifest, BagIt, checksum manifest, or sidecar verification from folder layout.
- **Manifest bundle preflight:** rename/layout/portability checks before hash walk (`ERR_VERIFY_BUNDLE_*`).
- **Sidecar CLI:** `--mode sidecars` delegates to `execute_verification_sidecars`.

### v0.9.2 (2026-07-02)

- **BagIt verify:** `--mode bagit` and `execute_verification_bagit` for on-disk RFC 8493 minimal subset (complete bags only; `fetch.txt` fails closed).
- **Checksum manifest verify:** `--mode checksum_manifest` and `execute_verification_checksum_manifest` for GNU/BSD manifests at folder root.
- **Sidecar verify:** `--mode sidecars` delegates to `execute_verification_sidecars`.
- **Epoch companions:** `is_epoch_upload_companion_basename` skips observability adjuncts from manifest created-drift noise.
- **TLS struct fingerprints:** `source_fingerprint_struct`-only predicates canonicalize like the L3dgr extension.
- **`verify_epoch_attestation`:** standalone DSSE epoch bundle signature check.
- **Registry revocation:** `revoked_at` honored in `F33_KEY_REGISTRY_PATH` window validation.
- **Unified release semver:** Git tags, PyPI, `workflow_dispatch` `version`, and Docker images use `vX.Y.Z`.

### v0.9.1 (2026-05-10)

- **Manifest JSON compatibility**: Keyword parameters on **`verify_directory_from_manifest`** / **`execute_verification`**, CLI **`--legacy-manifest-json`**, or env **`FORS33_VERIFIER_LEGACY_MANIFEST_JSON=1`** opt into pre-0.9.0-style output (record-and-continue on manifest compromise, stripped **`created[].path`**, **`modified[].reason`**, broken lineage does not force exit 3 alone). Defaults stay extension-parity.

### 0.9.0 (2026-05-10)

- **Manifest-mode extension parity**: Sidecar path **`dirname(target)/basename(target).f33`**, predicate byte-range hashing, triangle check order (data vs seal vs manifest), **`ManifestCompromisedError` fail-fast by default** after pool shutdown.
- **`lineage.json`**: After per-file verification, declares upstream digests checked against the same manifest `entries`; structured **`lineage`** object and **`files_scanned`** field in JSON (see [docs/lineage-json-convention-public.md](docs/lineage-json-convention-public.md)).
- **`created`** drift paths use multi-root keys verbatim (for example `0:relative/path`), matching extension output unless legacy compatibility is enabled (0.9.1).

### 0.8.1 (2026-05-10)

- **Wave 3 predicate parity**: Optional sidecar fields (`signature_intent`, `reason_for_change`, `sig_alg`, `nonce_hex`, `source_fingerprint`) use the same canonical payload rules as the L3dgr extension. Reserved X.509 `sig_alg` tags fail with stable `SIG_ALG_NOT_IMPLEMENTED` until chain validation ships.
- **Manifest HMAC**: `verify_manifest_hmac()` in `verify_dpk` validates an optional `fors33-manifest.hmac` sidecar when a pepper is supplied; missing sidecar is legacy-OK (`absent`).
- **TSA**: RFC 3161 path enforces TSA signer **id-kp-timeStamping** EKU; optional **nonce** check when `nonce_hex` is present in the predicate (`TSA_EKU_MISSING`, `TSA_NONCE_MISMATCH`).
- **Receipts**: `receipt_core` adds `generate_verification_receipt`, `receipt_to_json`, `receipt_to_base64`; `verify_receipt` loads `fors33-manifest.json` via `manifest_core.load_manifest(..., dataset_path)` like the extension.
- **Supply chain**: Docker images built by `publish-fors33-verifier` attach **SBOM** and **SLSA provenance** (`build-push-action` `sbom: true`, `provenance: mode=max`). Pin by digest in regulated CI.

### 0.8.0 (2026-05-01)

- Batch mode: `--directory` with concurrent verification of multiple PDF/ZIP/sealed datasets; `--json` summary; thread-safe output.

### 0.7.0 (2026-04-28)

- `--verify-receipt`, audit package / smart `--file` routing, `source_fingerprint` in predicates, enhanced TSA token formats, zero-copy ZIP reads.

### Earlier

- **0.6.0** and older: manifest hash chains, in-toto Statement v0.1/v1, canonical payload V1/V2, registry window, `hash_core` mmap workers. Full text: [CHANGELOG.md](CHANGELOG.md).

</details>

## Install

```bash
pip install fors33-verifier
```

Releases are published to PyPI manually using `python -m build` and `twine upload` with `vX.Y.Z` in `pyproject.toml`; the GitHub Actions workflow `publish-fors33-verifier` is responsible **only** for building and pushing Docker images. That workflow runs **only** when you trigger **`workflow_dispatch`** with **`version`** = `vX.Y.Z` (e.g. `v0.9.2`) and **`push_latest`** — bare `X.Y.Z` is **rejected**. It does **not** run automatically on git tags.

## Usage

**Remote (presigned URL, full file):**
```bash
fors33-verifier --url "https://..." --expected-hash <sha256_hex>
```

**Remote (HTTP Range, segment only):**
```bash
fors33-verifier --url "https://..." --start 0 --end 1048576 --expected-hash <sha256_hex>
```

**Local full file:**
```bash
fors33-verifier --file /path/to/segment.csv --expected-hash <sha256_hex>
```

**Local segment (direct byte range):**
```bash
fors33-verifier --file /path/to/data.csv --start 0 --end 4096 --expected-hash <sha256_hex>
```

**Local segment (using attestation record):**
```bash
fors33-verifier --file /path/to/data.csv --record /path/to/attestation_record.json
```

The attestation record JSON must contain `byte_start`, `byte_end`, and `hash`. Uses memory-efficient chunked reading so large files do not cause OOM.

**Directory verification (manifest mode):**
```bash
fors33-verifier --mode manifest --file ./baseline.sha256 --root ./root --format json
```
Use `--root` (or deprecated `--target-dir`) for the directory to verify. MD5/SHA-1 in manifests are rejected by default; use `--force-insecure` for legacy manifests.
Verify a directory against a checksum manifest (GNU/BSD-style text or JSON). Emits a structured drift report with `modified`, `created`, `deleted`, `mutated_during_verification`, `skipped`, **`files_scanned`** (extension-style residual live-path metric), and **`lineage`** when **`lineage.json`** rows are present (see [docs/lineage-json-convention-public.md](docs/lineage-json-convention-public.md)). **`--legacy-manifest-json`** or **`FORS33_VERIFIER_LEGACY_MANIFEST_JSON=1`** opts into pre-0.9.0 manifest JSON and exit behavior (see release **0.9.1**).

**Sidecar verification:**
```bash
fors33-verifier --mode sidecars --root ./root --format json
```
Walk the tree and verify `.f33`, `.sha256`, `.sha512`, and `.md5` sidecars in place.

**BagIt verification:**
```bash
fors33-verifier --mode bagit --root ./bag-folder --format json
```
Verify a complete on-disk BagIt bag (RFC 8493 minimal subset). Remote `fetch.txt` is unsupported and fails closed.

**Checksum manifest verification:**
```bash
fors33-verifier --mode checksum_manifest --file ./manifest-sha256.txt --root ./folder --format json
```
Verify files under `--root` against a standalone GNU/BSD checksum manifest (no `bagit.txt`).

**Auto discovery (auditor workflows):**
```bash
fors33-verifier --mode auto --root ./sealed-bundle-folder --format json
```
Inspects the folder for `fors33-manifest*.json`, BagIt layout, standalone checksum manifests, or verifiable sidecars and runs the matching mode. Explicit `--mode manifest|bagit|checksum_manifest|sidecars` remains the default integration path.

| Layout signal | Auto-selected mode |
|---|---|
| `fors33-manifest*.json` at root | `manifest` |
| `bagit.txt` + payload manifests | `bagit` |
| `manifest-sha256.txt` / `SHA256SUMS` (non-BagIt) | `checksum_manifest` |
| `.f33` or checksum sidecars with sibling targets | `sidecars` |

For sealed upload bundles exported from a Fors33 workbench, copy the storage prefix locally (manifest, data files, and matching `.f33` sidecars) then run `--mode auto` or pick the explicit mode above. Set `F33_KEY_REGISTRY_PATH` when verifying operator-registry-gated signatures. Use `--verify-tsa` for RFC 3161 timestamp blocks in JSON `.f33` sidecars (OSS path does not enforce regulated EUTL trust anchors).

Optional TSA verification for JSON `.f33` sidecars:
```bash
fors33-verifier --mode manifest --verify-tsa --file ./manifest.json --root ./root --format json
```

With `--verify-tsa`, the verifier accepts **`predicate.tsa.response_token`** (new enhanced format) or **`predicate.tsa.rfc3161_token_b64`** (legacy format) or top-level **`predicate.rfc3161_token_b64`** (RFC 3161 `TimeStampResp` DER, Base64) and/or the legacy **Ed25519** `predicate.tsa` block. RFC tokens are checked offline: PKI status granted, CMS signature on the timestamp token, **message imprint** (hash OID from the token) over the same **canonical attestation bytes** as the main Ed25519 signature (V1/V2 line-oriented payload, or legacy JSON when `canonical_payload_version` is absent), **TSA signer EKU** (`id-kp-timeStamping`), and optional **TSTInfo nonce** vs predicate **`nonce_hex`** when present. MD5/SHA-1 imprint algorithms are rejected.

**Receipt verification (standalone dataset verification):**
```bash
fors33-verifier --verify-receipt receipt.json --root ./dataset
```
Verifies a portable JSON receipt (dataset digest + Ed25519 signature) against **`fors33-manifest.json`** under `--root`. The Python module **`receipt_core`** also exposes `generate_verification_receipt`, `receipt_to_json`, `receipt_to_base64`, and `verify_receipt` for tooling and tests.

**Audit package verification (PDF with detached signature):**
```bash
# Explicit flags
fors33-verifier --audit-package report.pdf --sig report.sig --pubkey public_key.pem

# Smart routing (automatic detection)
fors33-verifier --file report.pdf
fors33-verifier --file audit_package.zip
```
Verifies detached Ed25519 signatures of PDF audit packages. Smart routing automatically detects ZIP archives and PDF files, discovering associated .sig and .pem files in the same directory.

**Batch verification (multiple audit packages):**
```bash
# Text output (default)
fors33-verifier --directory /path/to/audit/packages

# JSON output for CI/CD integration
fors33-verifier --directory /path/to/audit/packages --json

# With custom worker count
fors33-verifier --directory /path/to/audit/packages --workers 16
```
Verifies multiple audit packages (PDF, ZIP, sealed datasets) in a single command with hardware-limited concurrent processing. Automatically discovers PDF files, ZIP archives, and sealed datasets (directories with `fors33-manifest.json` or `manifest.json`). Returns exit code 0 if all packages pass, 1 if any fail. JSON output includes per-package results and summary statistics for automated pipelines.

## Legacy OpenPGP / GnuPG and fors33-verifier (separation of concerns)

This package deliberately keeps a **narrow execution path**: Ed25519-signed JSON `.f33` attestations, standard checksum sidecars (`.sha256`, `.sha512`, `.md5`), and manifest verification. It does **not** parse or verify **OpenPGP** (`.asc`, detached PGP signatures, keyrings).

For **legacy PGP / GnuPG** artifacts, use the tooling your organization already trusts—for example **`gpg --verify`** against the signer’s public key and the detached signature file—**alongside** fors33-verifier for **deterministic `.f33` supply-chain attestations** and **published hash baselines**. The two roles are complementary: GnuPG answers “was this blob signed by this PGP key?”; fors33-verifier answers “does this file or tree match the attested digest and seal metadata we ship in the kit?” without pulling OpenPGP into the verifier’s dependency or attack surface.

**Manifest hashing workers** (thread pool only):

```bash
fors33-verifier --mode manifest --workers 8 --file ./manifest.json --root ./root
```

Worker count: **positive `--workers`** wins; otherwise a **positive `FORS33_WORKERS`**; otherwise **`default_dpk_worker_count()`** (uses `cpu_count` and optional `FORS33_DPK_MAX_WORKERS`). Non-positive values mean auto. Hard cap **64**.

**Operator registry**: when **`F33_KEY_REGISTRY_PATH`** is set to a non-empty path, that file must exist and be readable before verification starts. When unset or empty, registry checks are skipped.

**Large-file hashing** (`hash_core`): mmap window uses `FORS33_MMAP_MIN_MB` / `FORS33_MMAP_MAX_MB` (defaults `500` / `4000`), clamped to cgroup/RAM ceiling on Linux; optional **`FORS33_MMAP_PSI_SOME_AVG10_MAX`** disables mmap when cgroup v2 memory pressure `some avg10` exceeds the threshold. Optional global read throttle: `set_global_read_bytes_per_second` (extension use; shipped CLI does not set it).

## Output

System-log format with timestamp, target, SHA-256, and status.

Exit codes:
- `0`: verified / no drift
- `1`: drift or missing seal (`[ ERR_MISSING_SEAL ]`)
- `2`: invocation or parameter misuse
- `3`: severe trust failures (e.g. bad signature, manifest compromise, invalid TSA)

Manifest/sidecars modes support `--format json` with `--warn-only` to report drift without failing.

## GitHub Action (CI/CD)

Use **Fors33 Data Provenance Check** in your workflow. The step fails (exit 1) on hash mismatch, blocking the pipeline.

The **`action.yml`** default `image:` tag is a **quickstart** only. For production or regulated CI, **pin** a **semver image tag** (for example `:0.9.1`) or an **immutable digest**—do **not** rely on `:latest` as your compliance baseline.

```yaml
- name: Verify data integrity
  uses: fors33-official/fors33-verifier@v1  # or your tag
  with:
    file: ./dist/artifact.bin
    expected-hash: 'abc123...'
```

For URL verification (presigned URLs only; no file uploads):

```yaml
- uses: fors33-official/fors33-verifier@v1
  with:
    url: 'https://example.com/presigned.csv'
    expected-hash: 'abc123...'
```

The Fors33 Data Provenance Kit runs on AWS S3, Snowflake, and local infrastructure. Procure licensing at [fors33.com](https://fors33.com) or [GitHub Marketplace](https://github.com/marketplace).

## Docker

```bash
docker run --rm ghcr.io/fors33/fors33-verifier:0.9.1 --url "https://..." --expected-hash <sha256>
# or
docker run --rm docker.io/fors33/fors33-verifier:0.9.1 --file /data/file.csv --expected-hash <sha256>
```

Published images include **SBOM** and **build provenance** metadata (expand **Release notes & version history** near the top of this README). `:latest` is convenient for exploration; pin a **version tag** or **immutable digest** in production pipelines so runs stay reproducible.

## URL-only API

For a hosted API that verifies **presigned URLs only** (no file uploads), run the image with the `serve` command. In-browser verification must use the **Web Crypto API** client-side; the file never leaves the user's machine.

## Requirements

Python 3.9–3.12. `cryptography` and `asn1crypto` (required). Optional `blake3` for faster hashing. Platforms: Linux, macOS, Windows.

## License

MIT License. See LICENSE file.
