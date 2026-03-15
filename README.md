# NOT FOR PROD CONSUMPTION

Our ambition is to build a high-quality secure product that can be self-hosted
without too much pain. The project, in its current state, does not meet our
security and quality bar to be deployed in production.

If you do so, be warned that you will hit both functional limitations and
major security issues.

# Documentation

All our [user documentation](https://doc.proveblyfine.net) lives outside of this repository.
User documentation is often written before we implement the corresponding features
as a way to keep us on track towards building a tool that is usable.

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

We regularly track code coverage of these tests. We aim for at least 85% but the
objective is to reach 95% before we declare ourselves production ready:
```
$ make cov
...
$ make cov-report
...
TOTAL                                          5167    685    87%
```

# Licence

`pf` is released under the open-source AGPLv3 licence. To summarize, its spirit, it
allows you to deploy and run this code for any purpose, including to make money as
a business, provided you release any changes made to this project.

To clarify, contrary to the BPL that would require you to buy a licence to run this
code for a business, you do not have to buy anything here. The cost is that you must
release any change you make to this project to the users who access your deployment
of your modified version of this codebase.
