# Publishing fors33-verifier to PyPI

## Trusted Publishing (OIDC)

This package uses PyPI Trusted Publishing. No API tokens are stored in the repo.

### One-time setup on PyPI

1. Log in to [pypi.org](https://pypi.org) and go to Account Settings.
2. Under "Publishing" → "Add a new pending publisher".
3. Configure:
   - **PyPI Project Name:** `fors33-verifier`
   - **Owner:** your GitHub org or username
   - **Repository name:** your FORS33 repo name
   - **Workflow name:** `publish-fors33-verifier.yml`
   - **Environment name:** (leave blank)

4. Add the publisher. The workflow will authenticate via OIDC on the next run.

### Manual build and upload (first time only)

For the initial PyPI release, you may need to create the project first:

```bash
cd products/dpk/open_source
python -m pip install build twine
python -m build
twine upload dist/*
```

Use your PyPI API token when prompted. After the project exists, Trusted Publishing can take over.

### Release workflow

1. Update version in `pyproject.toml`.
2. Create a GitHub release (or run workflow manually via workflow_dispatch).
3. The workflow builds and publishes automatically.
