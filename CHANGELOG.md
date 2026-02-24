# Changelog

## [0.6.0](https://github.com/TeamCadenceAI/cadence-cli/compare/v0.5.0...v0.6.0) (2026-02-24)


### Features

* add auth login/logout and rename hydrate to backfill ([ef187ea](https://github.com/TeamCadenceAI/cadence-cli/commit/ef187eaa798f9fe46f07715bba1caac30d4a18c9))
* **auth:** add CLI login/logout and hydrate onboarding sync ([eceadd9](https://github.com/TeamCadenceAI/cadence-cli/commit/eceadd94c70bfda907470528897b5a2ac05df4cb))
* **cli:** rename hydrate API contract to backfill ([672437a](https://github.com/TeamCadenceAI/cadence-cli/commit/672437aa3fc335006771af949b14e9e3d641c848))
* **cli:** rename hydrate command and remove install auto-run ([db678c5](https://github.com/TeamCadenceAI/cadence-cli/commit/db678c53d20b726b41d063ca97e15bdf9864b5b4))


### Performance Improvements

* **cli:** skip remote sync during backfill unless pushing ([6a32211](https://github.com/TeamCadenceAI/cadence-cli/commit/6a3221138036c3a33164da21a0448f63f08bc4ae))

## [0.4.1](https://github.com/TeamCadenceAI/cadence-cli/compare/v0.4.0...v0.4.1) (2026-02-20)


### Bug Fixes

* **update:** switch from GitHub API to HTTP redirect for release discovery ([4e9aafd](https://github.com/TeamCadenceAI/cadence-cli/commit/4e9aafd185922a32ac749af89b60c049aa2ccce8))
* **update:** switch from GitHub API to HTTP redirect for release discovery ([ee13e47](https://github.com/TeamCadenceAI/cadence-cli/commit/ee13e47659c472b71f9d73f1725c585687086584))

## [0.4.0](https://github.com/TeamCadenceAI/cadence-cli/compare/v0.3.0...v0.4.0) (2026-02-19)


### Features

* Add session_start timestamp to note frontmatter ([04a0704](https://github.com/TeamCadenceAI/cadence-cli/commit/04a0704527b034ec2a7821bd639eec95cadc95bc))
* Add session_start timestamp to note frontmatter ([f850bfd](https://github.com/TeamCadenceAI/cadence-cli/commit/f850bfd4a933f252aadf3024ed188dd5d3453b2b))

## [0.3.0](https://github.com/TeamCadenceAI/cadence-cli/compare/v0.2.1...v0.3.0) (2026-02-19)


### Features

* add release automation workflow and configuration files ([b363aca](https://github.com/TeamCadenceAI/cadence-cli/commit/b363acada35e93e179e64e133aad598fddb2997e))
* **build:** expose compile-time target triple for self-update artifact selection ([16bde3c](https://github.com/TeamCadenceAI/cadence-cli/commit/16bde3cc63faa058b73c120cd9a89d5159fc24ab))
* Simplified GPG (asymmetric keys) ([f3a15da](https://github.com/TeamCadenceAI/cadence-cli/commit/f3a15da6eea3c44a5df6e8ffa819fcc556ee2e10))
* **update:** add self-update system with checksum-verified binary replacement ([620addb](https://github.com/TeamCadenceAI/cadence-cli/commit/620addbc5351e6ccf0bb2e0e646fa78bc5beb99c))
* **update:** add self-update system with checksum-verified binary replacement ([e2d50f6](https://github.com/TeamCadenceAI/cadence-cli/commit/e2d50f655c47ea423671a49c82842235457d4a48))


### Bug Fixes

* Improve sync UX ([690d4bd](https://github.com/TeamCadenceAI/cadence-cli/commit/690d4bd8e8d52031c758144dff207cb3db1c29b8))
* Improvements to GPG setup ([c77acb8](https://github.com/TeamCadenceAI/cadence-cli/commit/c77acb872286e769eca368d78be5fd80a4a84460))
* Lean on RGPG more ([03ae12d](https://github.com/TeamCadenceAI/cadence-cli/commit/03ae12d4eb55a20055cbc9d4f7b95ffd2b21f47c))
* More sync TUI improvements ([d765b67](https://github.com/TeamCadenceAI/cadence-cli/commit/d765b6720324f56699252a654f388bb52fe095c0))
* **sync:** handle stale temp refs and non-fast-forward during notes sync ([23500e9](https://github.com/TeamCadenceAI/cadence-cli/commit/23500e906f9a77e54b7ddce9a21738d0c7cbcd53))
* **sync:** handle stale temp refs and non-fast-forward during notes sync ([a3a020f](https://github.com/TeamCadenceAI/cadence-cli/commit/a3a020fe26637ebc3c791d93ff5b909b68ebd67d))
* update key generation to use 2048-bit RSA for improved security ([30c23bd](https://github.com/TeamCadenceAI/cadence-cli/commit/30c23bd4530f4fde9ba1ea9483d7b168723017c9))
