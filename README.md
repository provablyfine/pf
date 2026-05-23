# Your infrastructure, Provably Fine

## Centralized SSH Access Control

`pf` provides a collection of tools to implement centralized access control for your SSH servers to:

  - maintain a centralized database of users, hosts and access grants
  - check that each user is allowed to reach a host upon each connection attempt
  - provide access to SSH servers that do not have public IP addresses
  - review access logs
  - allow administrators to decide how users should authenticate, via private keys, or OIDC SSOs

If you want to learn how to use, manage, and deploy `pf`, head to our [Documentation](https://docs.provablyfine.net).

## NOT FOR PROD CONSUMPTION

Our ambition is to build a high-quality secure product that can be easily
self-hosted. The project, in its current state, does not meet our
security and quality bar to be deployed in production.

If you do so, be warned that you will hit both functional limitations and
major security issues.

We track our readiness status for 1.0 in our [Roadmap](./ROADMAP.md)

## Contributing

Contributions are welcome! If you want to set up a local development environment, 
run the test suite, or contribute code, please check out our 
[Development & Contributing Guide](CONTRIBUTING.md).

## Licence

`pf` is released under the open-source AGPLv3 licence. To summarize, it
allows you to deploy and run this code for any purpose, including to make money as
a business, provided you release any changes made to this project.

To clarify, contrary to the BPL that would require you to buy a licence to run this
code for a business, you do not have to buy anything here. The cost is that you must
release any change you make to this project to the users who access your deployment
of your modified version of this codebase.
