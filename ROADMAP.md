We want to complete the following items before we release 1.0:

## Security

- [ ] Security audit via Claude code + fix all issues uncovered
- [ ] Security audit via a real experienced human
- [ ] SECURITY.md on how to manage security reporting
- [ ] Documentation on security architecture, threat model, etc.

## Features

- [ ] Improve auditing capabilities:
  - support server-side filtering
  - support server-side pagination
  - client-side filtering+pagination in `pfa` and `pfat`
- [ ] Managed cloud-based free tier for demos
  - create tenant after user provides valid email
- [x] Prometheus metrics in pf-api
- [ ] Request id logging in pf-api and pf-bastion
- [x] Custom metrics in pf-bastion
- [ ] Make sure we can use encrypted account keys (ask for user password)

## Documentation

- [ ] Getting started
- [ ] Admin auth
- [ ] Admin permissions
- [ ] Basic self-hosting documentation
- [ ] Reference documentation for CLI tools
- [ ] Reference OpenAPI API description

## Developer workflow

- [x] Automated Tag-based Release workflow

## Look

- [ ] Custom UI theme for docs.provablyfine.net
