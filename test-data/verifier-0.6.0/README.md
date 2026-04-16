# Verifier 0.6.0 fixture additions

Regression checks (run from `fors33-verifier/` root):

**Manifest hash chain (valid)**

```bash
python verify_dpk.py --mode manifest --file test-data/verifier-0.6.0/chain-valid/manifest.json --root test-data/verifier-0.6.0/chain-valid --ignore-pattern manifest.json --format json
```

Expect exit code `0` and no modified rows when `payload.txt` matches the manifest digest and `.f33` verifies.

**Manifest hash chain (invalid `entries` type)**

```bash
python verify_dpk.py --mode manifest --file test-data/verifier-0.6.0/chain-invalid-entries-type/manifest.json --root . --format json
```

Expect exit code `3` (severe) with `Manifest verification failed: manifest entries must be a list when chain_version is set`.

**in-toto Statement `_type` v1**

```bash
python verify_dpk.py --mode single --sidecar test-data/verifier-0.6.0/in-toto-v1-statement/payload.txt.f33
```

Expect exit code `0` and `VERIFIED` (same keys and Ed25519 material as the 0.4.0 valid fixture; only `_type` URI differs).

**SHA-512 digest + V2 canonical payload (`canonical_payload_version: 2`)**

The sidecar was produced with `reference/f33_sealer.py` **`write_f33_sidecar_with_manifest(..., hash_algo="sha512")`**: in-toto Statement v1, **`subject[0].digest.sha512`**, and line-oriented **`PAYLOAD_VERSION:2`** bytes for Ed25519.

```bash
python verify_dpk.py --mode single --sidecar test-data/verifier-0.6.0/sha512-canonical/payload512.txt.f33
```

Expect exit code `0` and `VERIFIED`. This exercises **`hash_file` with `algo=sha512`** and the **`SHA512:`** line in the signed canonical payload.

Existing **verifier-0.4.0** cases remain the primary CLI regression set; run each folder’s sidecar and (where present) manifest checks as documented in `test-data/verifier-0.4.0/README.md`.
