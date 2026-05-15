# SSH Access Control

`pf` provides a collection of tools to implement centralized access control for your SSH servers to:

  - maintain a centralized database of users, hosts and access grants
  - check that each user is allowed to reach a host upon each connection attempt
  - provide access to SSH servers that do not have public IP addresses
  - review access logs easily
  - allow administrators to decide how users should authenticate, via private keys, or OIDC SSOs

## Open Source

`pf` is open source, released under the [AGPL](https://www.gnu.org/licenses/agpl-3.0.en.html): 
this software is free to download and use, for both personal and commercial use, provided any 
changes you make are redistributed to your users.

## Goals

Our long-term objective is to build high-quality, production-ready, battle tested, 
software to manage infrastructure on-prem or on-cloud.

Our short-term objective is to start with SSH access control because existing solutions
often lack polish or robustness or are encumbered with licences that restrict their
for use in ways that we are not comfortable with.

## We are still young

Our long-term objective is ambitious. We are not quite there yet but we believe `pf` is 
already quite usable for small-scale lab-style deployments. Production deployments
on large-scale systems where the security stakes are high are not encouraged.

If you do use `pf`, we welcome feedback, discussions on features you feel are lacking,
bugs you found, or security issues you want to report.
