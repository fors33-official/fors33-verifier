# fors33-verifier

[![CI](https://img.shields.io/github/actions/workflow/status/fors33-official/fors33-verifier/build-push-fors33-verifier-docker.yml?branch=main&style=flat-square)](https://github.com/fors33-official/fors33-verifier/actions)
[![PyPI](https://img.shields.io/pypi/v/fors33-verifier?style=flat-square)](https://pypi.org/project/fors33-verifier/)
[![Docker Pulls](https://img.shields.io/docker/pulls/fors33/fors33-verifier?style=flat-square)](https://hub.docker.com/r/fors33/fors33-verifier)
[![License](https://img.shields.io/github/license/fors33-official/fors33-verifier?style=flat-square)](https://github.com/fors33-official/fors33-verifier/blob/main/LICENSE)

Standalone verification for attested data segments and general-purpose file integrity baselines. For machine-readable context (LLMs, crawlers), see [LLM_CONTEXT.md](LLM_CONTEXT.md). Confirm that a data segment or directory tree matches published hashes.

## Install

```bash
pip install fors33-verifier
```

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
fors33-verifier --mode manifest --file ./baseline.sha256 --target-dir ./root --format json
```
Verify a directory against a checksum manifest (GNU/BSD-style text or JSON). Emits a structured drift report with `modified`, `created`, `deleted`, `mutated_during_verification`, and `skipped`.

**Sidecar verification:**
```bash
fors33-verifier --mode sidecars --file ./root --format json
```
Walk the tree and verify `.f33`, `.sha256`, `.sha512`, and `.md5` sidecars in place.

## Output

System-log format with timestamp, target, SHA-256, and status. Exits 0 on match, 1 on mismatch. Manifest/sidecars modes support `--format json` with `--warn-only` to report drift without failing.

## GitHub Action (CI/CD)

Use **FORS33 Data Provenance Check** in your workflow. The step fails (exit 1) on hash mismatch, blocking the pipeline.

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
docker run --rm ghcr.io/fors33/fors33-verifier:latest --url "https://..." --expected-hash <sha256>
# or
docker run --rm docker.io/fors33/fors33-verifier:latest --file /data/file.csv --expected-hash <sha256>
```

## URL-only API

For a hosted API that verifies **presigned URLs only** (no file uploads), run the image with the `serve` command. In-browser verification must use the **Web Crypto API** client-side; the file never leaves the user's machine.

## Requirements

Python 3.9–3.12. `cryptography` (required). Optional `blake3` for faster hashing. Platforms: Linux, macOS, Windows.

## License

MIT License. See LICENSE file.
