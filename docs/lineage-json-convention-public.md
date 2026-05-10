# lineage.json (schema 1.0) - public contract summary

This document is a **scrubbed**, user-facing summary of how `lineage.json` is interpreted by **`fors33-verifier`** in manifest mode. It omits internal product wiring; the normative behavior is the verifier implementation in `verify_dpk.py`.

## Purpose

Derived outputs in a sealed tree may ship a **`lineage.json`** next to those outputs. The file lists **upstream artifacts** (paths and digests) that the derivation consumed. The bytes of `lineage.json` are sealed like any other file (`.f33` sidecar and a row in `fors33-manifest.json`).

**Trust model:** Semantic claims in `lineage.json` are checked against the **same** `fors33-manifest.json` used for the verify run. Every declared input digest must match a **trusted manifest row** after path and algorithm normalization. Failures surface as **lineage broken** in the verify result and increment severe exit handling when appropriate.

## Placement

- **Filename:** `lineage.json` (exact, case-sensitive).
- **Location:** Any path under the verify root that appears as a row in the manifest.

## Schema 1.0 (top-level object)

| Field | Type | Required | Description |
|--------|------|----------|-------------|
| `schema_version` | string | yes | Must be `"1.0"`. |
| `derivation_id` | string | yes | Non-empty identifier, max 256 characters after trim; no ASCII control characters. |
| `inputs` | array | yes | Zero or more input objects (empty allowed). |

### `inputs[]` object

| Field | Type | Required | Description |
|--------|------|----------|-------------|
| `path` | string | yes | Relative path using `/`; no `..` segments; must not start with `/`. Matches manifest `entries[].path` after the same normalization rules. |
| `digest_alg` | string | yes | `sha256` or `sha512` (lowercase). |
| `digest_hex` | string | yes | Lowercase hex (64 chars for SHA-256, 128 for SHA-512). |
| `byte_start` | integer | no | Inclusive start when using byte ranges; use with `byte_end`. |
| `byte_end` | integer | no | Exclusive end; both must be set together or both omitted. |

## Verifier output

The manifest verify result includes a **`lineage`** object with `status` (`ok` \| `broken`), `files_checked`, and per-file `reports`. Broken lineage also appends rows to **`modified`** so JSON consumers see drift-style failure.

## Example

```json
{
  "schema_version": "1.0",
  "derivation_id": "pipeline-example-v1",
  "inputs": [
    {
      "path": "inputs/source.bin",
      "digest_alg": "sha256",
      "digest_hex": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    }
  ]
}
```

## Versioning

Unknown future `schema_version` values should be treated as unsupported until explicitly implemented; `1.0` is the initial interoperable version for the open-source verifier.
