# Release process

## How to create a new release

The release process is fully automated via GitHub Actions. The workflow is triggered by tagging a commit with a version tag (`v*`).

### Manual steps

1. Bump the version in `pyproject.toml`:
```console
$ uv version --bump minor
```

2. Commit the version bump:
```console
$ git add pyproject.toml
$ git commit -m "release: $(uv version --short)"
```

3. Create a version tag (must match the version in `pyproject.toml`):
```console
$ git tag v$(uv version --short)
```

4. Push to GitHub (triggers the release workflow):
```console
$ git push github main --tags
```

### What happens next (automated)

The `.github/workflows/release.yml` workflow automatically:

1. **Validates** the tag matches the version in `pyproject.toml`
2. **Tests** across Python 3.12, 3.13, 3.14 (includes podman for container tests)
3. **Lints** the code (pyright, ruff, license check)
4. **Deploys docs** to the versioned docs site (via mike)
5. **Builds** the Python distribution (wheel + sdist)
6. **Publishes to PyPI** (via OIDC Trusted Publisher, no token needed)
7. **Builds the container image** as a squashfs for portablectl
8. **Creates a GitHub Release** with both the Python dist and the squashfs artifact
