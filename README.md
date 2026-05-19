# NOT FOR PROD CONSUMPTION

Our ambition is to build a high-quality secure product that can be easily
self-hosted. The project, in its current state, does not meet our
security and quality bar to be deployed in production.

If you do so, be warned that you will hit both functional limitations and
major security issues.

# Documentation

All our [documentation](https://docs.provablyfine.net) lives in the `docs/` directory.

To rebuild it and store the static html, js, and css to the `site/` directory:
```console
uv run zensical build
```

`zensical serve` is more convenient if you intend to work on the documentation content
itself:
```console
uv run zensical serve
```

# Development environment

Install pre-commit hooks locally:
```console
$ uv run --with pre-commit pre-commit install
```

# Coding style

Check any changes with:
```
uv run ruff check
uv run ruff format
uv run pyright
```

Most notably, all code is expected to use python type anotations for
method/function arguments and return values. "type: ignore" is considered
evil: avoid at all costs.

# Tests

We use python type hints extensively so, the first order of business is to
verify that your changes are still correct with regard to type hints:

```console
$ uv run pyright
```

Both unit tests and end-to-end tests can be run with pytest:
```console
$ uv run pytest
```

We regularly track test code coverage. We aim for at least 85%:
```
$ make cov
...
$ make cov-report
...
TOTAL                                          5167    685    87%
```

# Debugging

Start the textual debugging console:
```
uv run --with textual-dev textual console
```

By default, the _dev_ textual app connects to the console:
```
./scripts/pfat
```

# Licence

`pf` is released under the open-source AGPLv3 licence. To summarize, it
allows you to deploy and run this code for any purpose, including to make money as
a business, provided you release any changes made to this project.

To clarify, contrary to the BPL that would require you to buy a licence to run this
code for a business, you do not have to buy anything here. The cost is that you must
release any change you make to this project to the users who access your deployment
of your modified version of this codebase.
