## 0.7.5 - 2026-08-31

### Fixed

- Detect the name of the ssh service to restart it ([#101](https://github.com/provablyfine/pf/issues/101))
- Remove hardcoded rule "not allowed to update self" for identities. ([#102](https://github.com/provablyfine/pf/issues/102))


## 0.7.4 - 2026-08-31

### Added

- Add per-grant max ttl session duration field and enforce it for every SSH session type. ([#75](https://github.com/provablyfine/pf/issues/75))
- New SSH Grant type which replaces the 3 previous ssh grant types. It allows the expression of policies that could not be expressed before. ([#81](https://github.com/provablyfine/pf/issues/81))
- Quick tour and extended tour screencast of TUI ([#98](https://github.com/provablyfine/pf/issues/98))

### Fixed

- Stop displaying frpc license in "pf license" since frpc binaries are not distributed ([#68](https://github.com/provablyfine/pf/issues/68))
- Add identity.unix_username used by {self} usernames in ssh grant's username_list ([#71](https://github.com/provablyfine/pf/issues/71))
- Return 401 Unauthorized instead of 403 Forbidden for expired, revoked, or missing session, account, and invitation credentials, so clients can tell "please re-authenticate" apart from "not permitted". ([#73](https://github.com/provablyfine/pf/issues/73))
- Enforce unique constraint on role and boundary names within each tenant ([#76](https://github.com/provablyfine/pf/issues/76))
- Enforce unique constraint on role and member identity pairs to prevent duplicate role memberships ([#77](https://github.com/provablyfine/pf/issues/77))
- Track coverage of "pf bastion connect" ([#78](https://github.com/provablyfine/pf/issues/78))
- Delete all references when deleting an identity. ([#79](https://github.com/provablyfine/pf/issues/79))
- Make sure the same tags aren't specified more than once and raise an error if it's the case when creating or updating an identity. ([#80](https://github.com/provablyfine/pf/issues/80))
- Introduce .containerignore to minimize the size of the podman context and resolve podman build failures during tests ([#83](https://github.com/provablyfine/pf/issues/83))
- Add sqlite_autoincrement to auth, identity_boundary, identity_tag, role_member, audit_log, role, boundary, and tenant so deleted ids can't be reused. Drop the unused `default` table, which was never read or written by any model or endpoint. ([#85](https://github.com/provablyfine/pf/issues/85))
- Use mutation testing to verify our unit test coverage for security critical code ([#90](https://github.com/provablyfine/pf/issues/90))
- Display a meaningful error message when bcrypt is not here and we need to encrypt or decrypt a key ([#91](https://github.com/provablyfine/pf/issues/91))
- Use an explicit path in tmp for ssh-agent sockets to avoid random e2e test failures ([#93](https://github.com/provablyfine/pf/issues/93))
- Allow an identity to set its own unix_username, and reject invalid or privileged unix_username values. ([#94](https://github.com/provablyfine/pf/issues/94))
- Make full testsuite pass on MACOS ([#95](https://github.com/provablyfine/pf/issues/95))
- Make TUI breadcrumb consistent across screens ([#99](https://github.com/provablyfine/pf/issues/99))


## 0.7.3 - 2026-07-27

### Fixed

- Add missing -r --role option from whoami ([#45](https://github.com/provablyfine/pf/issues/45))
- Avoid parallel test runs in CI ([#46](https://github.com/provablyfine/pf/issues/46))
- Add grants to active role is allowed ([#47](https://github.com/provablyfine/pf/issues/47))
- Increase client timeout to 30s for e2e tests ([#50](https://github.com/provablyfine/pf/issues/50))
- Avoid use of frpc binary: replace with a client-side frp pure-python implementation ([#52](https://github.com/provablyfine/pf/issues/52))
- Make sure we are not able to create the same identity twice. ([#54](https://github.com/provablyfine/pf/issues/54))
- Track session key expiration explicitly to renew it on time and reconnect successfully when a bastion connection dies. ([#55](https://github.com/provablyfine/pf/issues/55))
- Publish main branch documentation updates to "dev" documentation version ([#56](https://github.com/provablyfine/pf/issues/56))
- Validate tenant name on creation to only allow `[a-zA-Z0-9_-]`, preventing path traversal via slash characters. ([#57](https://github.com/provablyfine/pf/issues/57))
- Reduce HTTP signature freshness window to 5 minutes and reject replayed (key_id, nonce) pairs. ([#58](https://github.com/provablyfine/pf/issues/58))
- Enforce role-based access control on bastion create/read/update/delete endpoints, which were previously reachable by any authenticated identity. ([#59](https://github.com/provablyfine/pf/issues/59))
- Add audit-log grant type and enforce read permission on the audit log endpoint ([#61](https://github.com/provablyfine/pf/issues/61))
- Reject OIDC id_tokens whose `nbf` (not before) claim is in the future. ([#62](https://github.com/provablyfine/pf/issues/62))
- Reject OIDC id_tokens whose header is missing a `kid`, instead of validating against an arbitrary JWK from the provider's JWKS. ([#63](https://github.com/provablyfine/pf/issues/63))
- OIDC login now generates and verifies a nonce, preventing id_token replay attacks. ([#64](https://github.com/provablyfine/pf/issues/64))
- Bastion cram e2e tests are failing when run from within a sandbox ([#65](https://github.com/provablyfine/pf/issues/65))
- Speedup e2e tests ([#66](https://github.com/provablyfine/pf/issues/66))
- Rename files so they are picked by towncrier ([#67](https://github.com/provablyfine/pf/issues/67))


## 0.7.2 - 2026-07-27

### Added

- Send email on user email invite ([#48](https://github.com/provablyfine/pf/issues/48))


## 0.7.1 - 2026-07-17

### Added

- SQL versioning with alembic ([#7](https://github.com/provablyfine/pf/issues/7))
- `whoami` command for pf, pfa, and pfat ([#41](https://github.com/provablyfine/pf/issues/41))
- Bind sessions to roles ([#42](https://github.com/provablyfine/pf/issues/42))

### Fixed

- added were missing in change-logs ([#49](https://github.com/provablyfine/pf/issues/49))


## 0.7.0 - 2026-07-14

### Fixed

- Use python native logging configuration to make sure backtraces are sane(r) ([#22](https://github.com/provablyfine/pf/issues/22))
- Bundle frpc licence in release wheel ([#40](https://github.com/provablyfine/pf/issues/40))
- Add -r/--role option to `pf login`/`pfa login` ([#43](https://github.com/provablyfine/pf/issues/43))
- Avoid garbage on stdout/stderr upon webbrowser.open() ([#44](https://github.com/provablyfine/pf/issues/44))


## 0.6.0 - 2026-07-10

### Fixed

- Bundle frpc binary and licence in release wheels ([#39](https://github.com/provablyfine/pf/issues/39))


## 0.5.0 - 2026-07-10

### Fixed

- create pf-api-rotate binary on install ([#24](https://github.com/provablyfine/pf/issues/24))
- handle PF_API_KEK_FILENAME in pf-api-rotate ([#25](https://github.com/provablyfine/pf/issues/25))
- Use absolute paths for pf binaries ([#26](https://github.com/provablyfine/pf/issues/26))
- setup bastion register service in script generated by "openssh host-init" ([#27](https://github.com/provablyfine/pf/issues/27))
- Update pfat Bastion screens: connect/register urls are replaced with a single url field ([#28](https://github.com/provablyfine/pf/issues/28))
- auto-login for non-interactive headless authentication on "bastion register" ([#29](https://github.com/provablyfine/pf/issues/29))
- Use a single source of truth for changelog entries ([#30](https://github.com/provablyfine/pf/issues/30))
- add --version option ([#31](https://github.com/provablyfine/pf/issues/31))
- Make bastion HTTP CONNECT protocol RFC compliant ([#32](https://github.com/provablyfine/pf/issues/32))
- Allocate socat port number dynamically to avoid test failures due to port collisions ([#33](https://github.com/provablyfine/pf/issues/33))
- Subtenants are not allowed to have ssh-style permissions ([#34](https://github.com/provablyfine/pf/issues/34))
- Use frpc/frps instead of custom bastion protocol to improve robustness ([#36](https://github.com/provablyfine/pf/issues/36))
- Run pf-host-refresh automatically when the network comes back up via network manager dispatcher script ([#37](https://github.com/provablyfine/pf/issues/37))
- Use `auth.tokenSource.type=exec` to allow reconnections after the initial token expiration ([#38](https://github.com/provablyfine/pf/issues/38))


# Changelog

## 0.4.0 - 2026-06-28

### Added
- CHANGELOG.md
- Add "pfa initialize --transient-key" ([#9](https://github.com/provablyfine/pf/issues/9))
- Track client_type on a per-auth basis ([#12](https://github.com/provablyfine/pf/issues/12))
- Ask user to choose which authentication to use to accept an invitation if there is ambiguity
- Add a ping command to verify connectivity ([#20](https://github.com/provablyfine/pf/issues/20))
- Attempt to open automatically in user's browser device code flow url ([#21](https://github.com/provablyfine/pf/issues/21))

### Removed
- oauth2 GitHub support for auth.
- Auth tags ([#17](https://github.com/provablyfine/pf/issues/17))

### Fixed
- Sync client-side schema with server-side schema ([#10](https://github.com/provablyfine/pf/issues/10))
- Align key thumbprint calculation with RFC 6738 ([#16](https://github.com/provablyfine/pf/issues/16))
- Audit session duration ([#8](https://github.com/provablyfine/pf/issues/8))
- Allow login when we do not have a working ssh-agent ([#6](https://github.com/provablyfine/pf/issues/6))
- Handle multiple auths with the same name at the HTTP API layer ([#19](https://github.com/provablyfine/pf/issues/19))
- openssh host-init fails ([#23](https://github.com/provablyfine/pf/issues/23))

## 0.3.0 - 2026-06-05

### Added
- Rough documentation TOC
- Establish objective onboarding workflow in getting-started.md
- More automated CI checks
- Run CI checks across multiple all versions of python we support via tox
- Expose prometheus metrics in api and bastion servers
### Changed
- Split main package _provablyfine_ (AGPLv3) in two packages, _provablyfine_ (AGPLv3)
  and _provablyfine-client_ (MIT)

## 0.2.0 - 2026-05-23

### Added
- ROADMAP.md for 1.0.0
### Fixed
- Automated release process works
- All style and type checks pass

## 0.1.0 - 2026-05-23

### Added
- Automated release process to pypi
