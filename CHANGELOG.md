# Changelog

## [0.5.0](https://github.com/TeamCadenceAI/cadence-cli/compare/v0.4.1...v0.5.0) (2026-02-21)


### Features

* **gc:** add `cadence gc` command to clear and re-hydrate notes (Phase 4) ([0bd7984](https://github.com/TeamCadenceAI/cadence-cli/commit/0bd798454d60a892796dfbcd4012c3e1ea5fd812))
* **hydrate:** add progress bar during per-session processing ([eea5d5c](https://github.com/TeamCadenceAI/cadence-cli/commit/eea5d5c941ca1f913416056403e867d2b88cddec))
* **notes:** implement v2 pointer note format with payload dedup ([2a44a37](https://github.com/TeamCadenceAI/cadence-cli/commit/2a44a37933b1eaa5f42b23a68150e7e39eb05615))
* **push:** squash notes ref into orphan commit on push (Phase 2) ([748542e](https://github.com/TeamCadenceAI/cadence-cli/commit/748542e20fabb733ae2c12542052a6a32115b8b5))


### Bug Fixes

* **gc:** skip pre-push hook on ref delete and scope hydration to current repo ([b3d79ad](https://github.com/TeamCadenceAI/cadence-cli/commit/b3d79ad53f06cf1b0eb3b7443a4a5038da6078ad))
* **hydrate:** encrypt notes in time-window match path ([2c2b9d8](https://github.com/TeamCadenceAI/cadence-cli/commit/2c2b9d8e46617378c8470c12690daaf6a7a0096a))
* **install:** show version number in install script output ([9577f67](https://github.com/TeamCadenceAI/cadence-cli/commit/9577f6733a01db790af033e0eaced8489ab9436a))
* **notes:** keep v2 pointer notes as plaintext, encrypt only payload blob ([55ff7d7](https://github.com/TeamCadenceAI/cadence-cli/commit/55ff7d77934aa37d64a4604c9736b86e9ee3d78d))
* **push:** fetch-merge remote notes before pushing during hydrate ([2470bd9](https://github.com/TeamCadenceAI/cadence-cli/commit/2470bd9b3ad1a241d6b0d52ec64b12d408109835))
* **push:** preserve notes merge history instead of squashing into orphans ([0684801](https://github.com/TeamCadenceAI/cadence-cli/commit/068480179ab052ac4a4f6ccfaa0ef407bdb6e43b))
* **push:** skip merge in sync retry when remote has no notes ref ([d3fcd00](https://github.com/TeamCadenceAI/cadence-cli/commit/d3fcd00ac8fab1060c90188ee1074a834caf7403))
* **push:** skip push when no local notes ref exists ([0adab24](https://github.com/TeamCadenceAI/cadence-cli/commit/0adab2439def02d1dde2982030f051bf2e0287fa))
* **update:** switch from GitHub API to HTTP redirect for release discovery ([4e9aafd](https://github.com/TeamCadenceAI/cadence-cli/commit/4e9aafd185922a32ac749af89b60c049aa2ccce8))
* **update:** switch from GitHub API to HTTP redirect for release discovery ([ee13e47](https://github.com/TeamCadenceAI/cadence-cli/commit/ee13e47659c472b71f9d73f1725c585687086584))

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
