# How to create a new release

Run all tests for all combinations of python versions we support
```console
$ uv run tox
```

Other checks
```console
$ uv run pyright
$ uv run ruff check
$ uv run ruff format
```

Check license compatibility
```console
$ uv run licensecheck
```

Update version number in pyproject.toml
```console
$ uv run version --bump minor
```

Build documentation for this VERSION, commit it to 
`gh-pages` branch, update the `latest` alias to point to
this version, and push the branch.
```console
uv run mike deploy --push -u $(uv version --short) latest
```

Build release
```console
$ uv build
```

Push release to pip
```console
$ uv publish --username __token__ --keyring-provider subprocess
```
