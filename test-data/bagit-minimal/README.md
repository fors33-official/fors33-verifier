# bagit-minimal

Hand-rolled RFC 8493 minimal bag for OSS CLI spot-check:

```bash
python -c "from verify_dpk import execute_verification_bagit; r=execute_verification_bagit('test-data/bagit-minimal'); print(len(r.modified))"
```

Expect `0` drift when digests match payload bytes (including trailing newline on `artifact.txt`).
