# fors33-verifier

Standalone verification for attested data segments. Confirm that a data segment matches a published SHA-256 hash.

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

The attestation record JSON must contain `byte_start`, `byte_end`, and `hash`. Uses memory-efficient chunked reading (64KB) so large files do not cause OOM.

## Output

System-log format with timestamp, target, SHA-256, and status. Exits 0 on match, 1 on mismatch.

## Requirements

Python 3.9+. Uses only standard library (hashlib, json, argparse, urllib.request).

## License

MIT License. See LICENSE file.
