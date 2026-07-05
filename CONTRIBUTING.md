# Contribution Guide

## Community

Join our [public contributor channel](https://matrix.to/#/!TuOhYIkcNUOqWkqcqE:matrix.org?via=matrix.org)
to ask questions and coordinate with other contributors.

## Development environment

Install pre-commit hooks locally:
```console
$ uv run pre-commit install
```

## Coding style

Check any changes with:
```
uv run ruff check
uv run ruff format
uv run pyright
```

Most notably, all code is expected to use python type annotations for
method/function arguments and return values. "type: ignore" is considered
evil: avoid at all costs.

## Tests

We use python type hints extensively so, the first order of business is to
verify that your changes are still correct with regard to type hints:

```console
$ uv run pyright
```

Both unit tests and end-to-end tests can be run with pytest:
```console
$ uv run pytest
```

The pre-release test process requires a test across multiple python versions:
```console
$ uv run tox
```

We regularly track test code coverage. We aim for at least 85%:
```
$ make cov
...
$ make cov-report
...
TOTAL                                          5167    685    87%
```

## Submitting

Make sure any PR you submit and/or any commit that fixes an issue also creates a file in changelog.d/*.

## Debugging

Start the textual debugging console:
```
uv run --with textual-dev textual console
```

By default, the _dev_ textual app connects to the console:
```
./scripts/pfat
```

## Documentation

To rebuild the documentation and store the static html, js, and css to the `site/` directory:
```console
uv run zensical build
```

`zensical serve` is more convenient if you intend to work on the documentation content
itself:
```console
uv run zensical serve
```
