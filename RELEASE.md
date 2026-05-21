# Release process

## How to create a new release

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

Push release to pypi
```console
UV_PUBLISH_TOKEN=$(age -d -i  ~/.age-identity.yubikey ~/.pypi-pf-token.age) uv publish
```

Build pf-host image
```console
```

Push pf-host image to github
```console
```

## How to setup yubikey ?

```console
$ age-plugin-yubikey --generate
...
$ cat > ~/.age-identity.yubikey <<EOF
> AGE-PLUGIN-YUBIKEY-XXXX
> EOF
$ age -r RECIPIENT_KEY -o ~/.pypi-pf-token.age <<EOF
> PYPI_TOKEN
> EOF
```
