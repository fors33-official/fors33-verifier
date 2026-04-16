# fors33-verifier

[![CI](https://img.shields.io/github/actions/workflow/status/fors33-official/fors33-verifier/publish-fors33-verifier.yml?branch=main&style=flat-square)](https://github.com/fors33-official/fors33-verifier/actions)
[![Release](https://img.shields.io/badge/release-0.6.0-blue?style=flat-square)](https://pypi.org/project/fors33-verifier/)
[![PyPI](https://img.shields.io/pypi/v/fors33-verifier?style=flat-square)](https://pypi.org/project/fors33-verifier/)
[![Docker Tag](https://img.shields.io/badge/docker-0.6.0%20%7C%20latest-2496ED?style=flat-square&logo=docker&logoColor=white)](https://hub.docker.com/r/fors33/fors33-verifier)
[![Docker Pulls](https://img.shields.io/docker/pulls/fors33/fors33-verifier?style=flat-square)](https://hub.docker.com/r/fors33/fors33-verifier)
[![License](https://img.shields.io/github/license/fors33-official/fors33-verifier?style=flat-square)](https://github.com/fors33-official/fors33-verifier/blob/main/LICENSE)

Standalone verification for attested data segments and general-purpose file integrity baselines. For machine-readable context (LLMs, crawlers), see [LLM_CONTEXT.md](LLM_CONTEXT.md). Confirm that a data segment or directory tree matches published hashes.

> Warning: FORS33 Verifier provides cryptographic integrity checks only. It does not independently guarantee legal or regulatory compliance. See [LEGAL_DISCLAIMER.md](LEGAL_DISCLAIMER.md).

## Install

```bash
pip install fors33-verifier
```

Releases are published to PyPI manually using `python -m build` and `twine upload`; the GitHub Actions workflow `publish-fors33-verifier` is responsible **only** for building and pushing Docker images. That workflow runs **only** when you trigger **`workflow_dispatch`** with explicit **`version`** (no leading `v`, e.g. `0.6.0`) and **`push_latest`**—it does **not** run automatically on git tags.

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
Verify a directory against a checksum manifest (GNU/BSD-style text or JSON). Emits a structured drift report with `modified`, `created`, `deleted`, `mutated_during_verification`, and `skipped`.

**Sidecar verification:**
```bash
fors33-verifier --mode sidecars --file ./root --format json
```
Walk the tree and verify `.f33`, `.sha256`, `.sha512`, and `.md5` sidecars in place.

Optional TSA verification for JSON `.f33` sidecars:
```bash
fors33-verifier --mode manifest --verify-tsa --file ./manifest.json --root ./root --format json
```

With `--verify-tsa`, the verifier accepts **`predicate.tsa.rfc3161_token_b64`** or top-level **`predicate.rfc3161_token_b64`** (RFC 3161 `TimeStampResp` DER, Base64) and/or the legacy **Ed25519** `predicate.tsa` block. RFC tokens are checked offline: PKI status granted, CMS signature on the timestamp token, and **message imprint** (hash OID from the token) over the same **canonical attestation bytes** used for the main Ed25519 signature (V1/V2 line-oriented payload, or legacy JSON when `canonical_payload_version` is absent). MD5/SHA-1 imprint algorithms are rejected.

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

Use **FORS33 Data Provenance Check** in your workflow. The step fails (exit 1) on hash mismatch, blocking the pipeline.

The **`action.yml`** default `image:` tag is a **quickstart** only. For production or regulated CI, **pin** a **semver image tag** (for example `:0.6.0`) or an **immutable digest**—do **not** rely on `:latest` as your compliance baseline.

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

The FORS33 Data Provenance Kit runs on AWS S3, Snowflake, and local infrastructure. Procure licensing at [fors33.com](https://fors33.com) or [GitHub Marketplace](https://github.com/marketplace).

## Docker

```bash
docker run --rm ghcr.io/fors33/fors33-verifier:0.6.0 --url "https://..." --expected-hash <sha256>
# or
docker run --rm docker.io/fors33/fors33-verifier:0.6.0 --file /data/file.csv --expected-hash <sha256>
```

`:latest` is convenient for exploration; pin a **version tag** or **digest** in production pipelines so runs stay reproducible.

## URL-only API

For a hosted API that verifies **presigned URLs only** (no file uploads), run the image with the `serve` command. In-browser verification must use the **Web Crypto API** client-side; the file never leaves the user's machine.

## Requirements

Python 3.9–3.12. `cryptography` and `asn1crypto` (required). Optional `blake3` for faster hashing. Platforms: Linux, macOS, Windows.

## License

MIT License. See LICENSE file.
