# Changelog

## 0.4.0 - 2026-06-XX

### Added
- CHANGELOG.md
- Add "pfa initialize --transient-key" ([#9](https://github.com/provablyfine/pf/issues/9))
- Track client_type on a per-auth basis ([#12](https://github.com/provablyfine/pf/issues/12))
- Ask user to choose which authentication to use to accept an invitiation if there is ambiguity

### Removed
- oauth2 GitHub support for auth.
- Auth tags ([#17](https://github.com/provablyfine/pf/issues/17))

### Fixed
- Sync client-side schema with server-side schema ([#10](https://github.com/provablyfine/pf/issues/10))
- Align key thumbprint calculation with RFC 6738 ([#16](https://github.com/provablyfine/pf/issues/16))
- Audit session duration ([#8](https://github.com/provablyfine/pf/issues/8))
- Allow login when we do not have a working ssh-agent ([#6](https://github.com/provablyfine/pf/issues/6))
- Handle multiple auths with the same name at the HTTP API layer ([#19](https://github.com/provablyfine/pf/issues/19))

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
