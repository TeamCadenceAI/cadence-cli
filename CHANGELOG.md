# Changelog

## [3.0.0](https://github.com/TeamCadenceAI/cadence-cli/compare/v2.6.2...v3.0.0) (2026-05-02)


### ⚠ BREAKING CHANGES

* removes the git-ref sync, pre-push hook, keys, sessions, and gc flows. Session ingestion now uses direct post-commit uploads with a local retry queue.

### Features

* add auth login/logout and rename hydrate to backfill ([ef187ea](https://github.com/TeamCadenceAI/cadence-cli/commit/ef187eaa798f9fe46f07715bba1caac30d4a18c9))
* add git identity fields to SessionRecord for server-side attribution ([0dce9b7](https://github.com/TeamCadenceAI/cadence-cli/commit/0dce9b775e69b524d9829c4e96b6843cff09ffff))
* add release automation workflow and configuration files ([b363aca](https://github.com/TeamCadenceAI/cadence-cli/commit/b363acada35e93e179e64e133aad598fddb2997e))
* Add session_start timestamp to note frontmatter ([04a0704](https://github.com/TeamCadenceAI/cadence-cli/commit/04a0704527b034ec2a7821bd639eec95cadc95bc))
* Add session_start timestamp to note frontmatter ([f850bfd](https://github.com/TeamCadenceAI/cadence-cli/commit/f850bfd4a933f252aadf3024ed188dd5d3453b2b))
* Add Warp support ([681f666](https://github.com/TeamCadenceAI/cadence-cli/commit/681f6665eb19049cb0e2385d7f40fd422e8364f1)), closes [#41](https://github.com/TeamCadenceAI/cadence-cli/issues/41)
* **agents:** add Cline, Roo Code, OpenCode, Kiro, and Amp Code session discovery ([ee310a4](https://github.com/TeamCadenceAI/cadence-cli/commit/ee310a4bf2ff196dd93e4190d697b37d53993f9a))
* **agents:** add Windows API discovery for windsurf and antigravity ([f56f315](https://github.com/TeamCadenceAI/cadence-cli/commit/f56f315ff4662687c2e9e8b8408ff67e623d7912))
* **agents:** add windsurf API session ingestion and backfill attachment support ([79e8282](https://github.com/TeamCadenceAI/cadence-cli/commit/79e8282d600e6853f2ba97f0ab4361d568f3d595))
* **api:** add HTTP client module for AI Barometer API key and auth endpoints ([0f8cd64](https://github.com/TeamCadenceAI/cadence-cli/commit/0f8cd64cb9047928ab8ac698150f4a2fadee7fb6))
* **api:** send CLI version header on Cadence requests ([0b1cc24](https://github.com/TeamCadenceAI/cadence-cli/commit/0b1cc24a26f4cddb5aad48b3bee2ff2f0342ba3a))
* **auth:** add CLI login/logout and hydrate onboarding sync ([eceadd9](https://github.com/TeamCadenceAI/cadence-cli/commit/eceadd94c70bfda907470528897b5a2ac05df4cb))
* **auth:** upgrade legacy CLI tokens automatically ([#143](https://github.com/TeamCadenceAI/cadence-cli/issues/143)) ([7b86672](https://github.com/TeamCadenceAI/cadence-cli/commit/7b866722aa554fc69560175472f79d59fdf2e790))
* **auto-update:** add phase 2 trust and control UX ([b63a1ed](https://github.com/TeamCadenceAI/cadence-cli/commit/b63a1ed8c192e937b52a7de31f99909824367ec6))
* **backfill:** migrate runtime to tokio and parallelize repository processing ([f8bcf48](https://github.com/TeamCadenceAI/cadence-cli/commit/f8bcf4842a8252c67ce9e1a6cf45745e76c9a26d))
* **bootstrap:** finish monitor bootstrap migration ([5af141c](https://github.com/TeamCadenceAI/cadence-cli/commit/5af141cbe0014d746e73f58ab09288af5c0d082f))
* **bootstrap:** unify install and version migration ([96d7b56](https://github.com/TeamCadenceAI/cadence-cli/commit/96d7b5679410432b3973e10c383bf85f862b5c9d))
* Branch/committer session storage ([7cdc164](https://github.com/TeamCadenceAI/cadence-cli/commit/7cdc16415579d68bdd65b6ab1331938d64d22494))
* **build:** expose compile-time target triple for self-update artifact selection ([16bde3c](https://github.com/TeamCadenceAI/cadence-cli/commit/16bde3cc63faa058b73c120cd9a89d5159fc24ab))
* **cli:** add `cadence uninstall` command ([0871d60](https://github.com/TeamCadenceAI/cadence-cli/commit/0871d608c09736b9730e7e2ffc1b5fad0b49dfc1))
* **cli:** add auth and encryption key management for Cadence API ([28f349e](https://github.com/TeamCadenceAI/cadence-cli/commit/28f349e3347efecb2306d68d88a271557c3169b0))
* **cli:** add auth and keys subcommands with stub handlers ([f289c92](https://github.com/TeamCadenceAI/cadence-cli/commit/f289c9292723ff7577df2853d87cef148afbe558))
* **cli:** add cadence uninstall command ([64fd9f9](https://github.com/TeamCadenceAI/cadence-cli/commit/64fd9f99abadcd04b1291dca2bd8210cd2132a8a))
* **cli:** implement auth logout and keys status handlers ([7137cf7](https://github.com/TeamCadenceAI/cadence-cli/commit/7137cf7d4bccbbe79523435f2656f2a015b46282))
* **cli:** implement auth status handler with local config display ([22ad56d](https://github.com/TeamCadenceAI/cadence-cli/commit/22ad56ddd43d4f7419eab3c7bf1fece5c31e2b44))
* **cli:** implement keys push command with GPG export and API upload ([618a778](https://github.com/TeamCadenceAI/cadence-cli/commit/618a7780c11dccf647758aee5cbef7b7a7584761))
* **cli:** implement keys test command with server-side decryption verification ([601f1b1](https://github.com/TeamCadenceAI/cadence-cli/commit/601f1b123957dc421c6a4c3eb997aa6426923b08))
* **cli:** implement OAuth browser login flow for auth login command ([b9b240d](https://github.com/TeamCadenceAI/cadence-cli/commit/b9b240dd97b186d793ac669b7d2455f57c66ed4e))
* Cline, RooCode, OpenCode, Kiro and Amp Code ([9902d5d](https://github.com/TeamCadenceAI/cadence-cli/commit/9902d5d1856f4aca53eeb287b572f90cf5ca89ce))
* **cli:** rename hydrate API contract to backfill ([672437a](https://github.com/TeamCadenceAI/cadence-cli/commit/672437aa3fc335006771af949b14e9e3d641c848))
* **cli:** rename hydrate command and remove install auto-run ([db678c5](https://github.com/TeamCadenceAI/cadence-cli/commit/db678c53d20b726b41d063ca97e15bdf9864b5b4))
* **config:** add local TOML config module for API credentials and settings ([00aa4a6](https://github.com/TeamCadenceAI/cadence-cli/commit/00aa4a6f916e24abc828c3615297c7a689189b4a))
* **discovery:** expand Cursor and Warp session recovery ([ec37e65](https://github.com/TeamCadenceAI/cadence-cli/commit/ec37e65c33d010128ccd3f6f2f55a3349dc0e589))
* **discovery:** expand Cursor and Warp session recovery ([0d5743f](https://github.com/TeamCadenceAI/cadence-cli/commit/0d5743f1f922acd856d35a78f8bebf1d4ffb7ee7))
* **encrypt:** switch git note encryption from gpg CLI to pure-Rust rpgp ([6334698](https://github.com/TeamCadenceAI/cadence-cli/commit/63346982e3ed1c7f2b456620437b3513e47d0300))
* **encrypt:** switch git note encryption from gpg CLI to pure-Rust rpgp ([0016625](https://github.com/TeamCadenceAI/cadence-cli/commit/001662535099940ecefc49dda37a93f2093ff0c2))
* **gc:** add `cadence gc` command to clear and re-hydrate notes (Phase 4) ([0bd7984](https://github.com/TeamCadenceAI/cadence-cli/commit/0bd798454d60a892796dfbcd4012c3e1ea5fd812))
* **gpg:** add GPG encryption support for session notes ([18e6788](https://github.com/TeamCadenceAI/cadence-cli/commit/18e6788f3cba0f629264836f5267cba7436f96b4))
* **gpg:** add GPG encryption support for session notes ([b2cf4bc](https://github.com/TeamCadenceAI/cadence-cli/commit/b2cf4bcf1191282e57492a954c991260b27e574d))
* **hooks:** show cadence spinner/check status for session sync ([f162591](https://github.com/TeamCadenceAI/cadence-cli/commit/f16259105ce626a2e0b3e8a21189291ed44d1e64))
* **hydrate:** add progress bar during per-session processing ([eea5d5c](https://github.com/TeamCadenceAI/cadence-cli/commit/eea5d5c941ca1f913416056403e867d2b88cddec))
* **install:** support org-scoped installation via curl ([398ade4](https://github.com/TeamCadenceAI/cadence-cli/commit/398ade4f4f7ccda47d007fe869dfa10d9679fec8))
* **install:** support org-scoped installation via curl ([137eaf8](https://github.com/TeamCadenceAI/cadence-cli/commit/137eaf8bc79eab567ccbf839b1472f45c41834ed))
* **login:** add Cadence branding to OAuth callback success/error screen ([c33b12f](https://github.com/TeamCadenceAI/cadence-cli/commit/c33b12fe6c0e67e599d56963ea2072a315c2825b))
* **matching:** unify commit/session matching across attach paths ([2a6a2db](https://github.com/TeamCadenceAI/cadence-cli/commit/2a6a2db256fcdce9c651d51a914c6086a1acbd9b))
* **monitor:** move live runtime off Git hooks ([c92ca66](https://github.com/TeamCadenceAI/cadence-cli/commit/c92ca66f6ec84413914043392ec5b591ae8ae464))
* move live ingestion to the background monitor runtime ([fdf5362](https://github.com/TeamCadenceAI/cadence-cli/commit/fdf5362aa5a23f836728f0030198b623943f67c4))
* **note:** add git_user_email and git_user_name, remove touched_paths ([e759e08](https://github.com/TeamCadenceAI/cadence-cli/commit/e759e08110888b21db0feb20fe9534444e8d743f))
* **notes:** implement v2 pointer note format with payload dedup ([2a44a37](https://github.com/TeamCadenceAI/cadence-cli/commit/2a44a37933b1eaa5f42b23a68150e7e39eb05615))
* **opencode:** stitch child sessions into root uploads ([965019e](https://github.com/TeamCadenceAI/cadence-cli/commit/965019e26b9095bb1567ba98ce73845ad957fde6))
* **opencode:** stitch child sessions into root uploads ([bc332d4](https://github.com/TeamCadenceAI/cadence-cli/commit/bc332d4327d20c5cc82c57738cea7e69ea26d5ef))
* **publication:** cut CLI uploads over to v2 session publications ([f6433e0](https://github.com/TeamCadenceAI/cadence-cli/commit/f6433e0d1325df9bfa05e4ac1d30e97797cfa933))
* **push:** speed up notes and payload ref synchronization ([1d61e39](https://github.com/TeamCadenceAI/cadence-cli/commit/1d61e3960e5a4c61e5ed86be68914da2b55055ba))
* **push:** squash notes ref into orphan commit on push (Phase 2) ([748542e](https://github.com/TeamCadenceAI/cadence-cli/commit/748542e20fabb733ae2c12542052a6a32115b8b5))
* refactor keychain operations to use async functions and update dependencies ([41a847a](https://github.com/TeamCadenceAI/cadence-cli/commit/41a847a2e4b5e1598bf761e6b6071dcf43a7d0a6))
* remove legacy session-ref pipeline leftovers ([37f03e5](https://github.com/TeamCadenceAI/cadence-cli/commit/37f03e583b5ce905486770e2654772dfa22d4680))
* **scanner:** add ranked multi-signal session-to-commit matching ([f1e5019](https://github.com/TeamCadenceAI/cadence-cli/commit/f1e50192535809c06df04146b5a31a900521faab))
* Simplified GPG (asymmetric keys) ([f3a15da](https://github.com/TeamCadenceAI/cadence-cli/commit/f3a15da6eea3c44a5df6e8ffa819fcc556ee2e10))
* **storage:** migrate legacy ai-session ref to canonical session ref ([68e8a97](https://github.com/TeamCadenceAI/cadence-cli/commit/68e8a97d5e8799f321f0e3fe285a9345f1d3720d))
* **sync-cursors:** implement persistent index-ingest cursors ([b21bf60](https://github.com/TeamCadenceAI/cadence-cli/commit/b21bf6070af3081f59e5ff23d7d37a50761d8fbb))
* **sync:** add deferred non-blocking cadence sync worker ([691fed1](https://github.com/TeamCadenceAI/cadence-cli/commit/691fed1f4ac44d8f7aebdde5663b0176daeb7a55))
* **sync:** add detailed per-ref deferred sync tracing ([1a07b60](https://github.com/TeamCadenceAI/cadence-cli/commit/1a07b6070825d1c6fbab53d056a4f63d056e1751))
* **sync:** notify Cadence API after deferred session-ref push ([1e0e74f](https://github.com/TeamCadenceAI/cadence-cli/commit/1e0e74f4d7f71aef5c4accf4bd82bc17af4a4adc))
* **sync:** notify session-ref pushes and require auth for server hook ([b035681](https://github.com/TeamCadenceAI/cadence-cli/commit/b035681359b47bdacdae3018a876574e2a7218a3))
* unattended auto-update with trust/control UX (Phase 1 + 2) ([f3cb63e](https://github.com/TeamCadenceAI/cadence-cli/commit/f3cb63e34770137c94b7ba1c3b582c859ad0c6d2))
* **update:** add detached updater helper and macOS signing ([2702319](https://github.com/TeamCadenceAI/cadence-cli/commit/2702319f46bdc90a0947514089117a698b9be762))
* **update:** add detached updater helper and macOS signing ([567de79](https://github.com/TeamCadenceAI/cadence-cli/commit/567de79c8526ac3b8b8f6c34c0a86c13b0bea938))
* **update:** add self-update system with checksum-verified binary replacement ([620addb](https://github.com/TeamCadenceAI/cadence-cli/commit/620addbc5351e6ccf0bb2e0e646fa78bc5beb99c))
* **update:** add self-update system with checksum-verified binary replacement ([e2d50f6](https://github.com/TeamCadenceAI/cadence-cli/commit/e2d50f655c47ea423671a49c82842235457d4a48))
* **update:** implement unattended hook-safe background auto-update v1 ([815fc22](https://github.com/TeamCadenceAI/cadence-cli/commit/815fc225f77ec39fc9350c668476eeee93c8acd7))
* **upload:** replace git-ref sync with direct session uploads ([997dc07](https://github.com/TeamCadenceAI/cadence-cli/commit/997dc07461e4089a8cc83ebe3d50d7efb2be7d83))
* **upload:** replace git-ref sync with direct session uploads ([e411236](https://github.com/TeamCadenceAI/cadence-cli/commit/e411236db50d33aa704bca314d1f5f3a204a80f5))
* V2 publishing ([312343b](https://github.com/TeamCadenceAI/cadence-cli/commit/312343b6b3ec38746a100febccb1edd3a5938116))
* Warp support ([f039ac0](https://github.com/TeamCadenceAI/cadence-cli/commit/f039ac005affffd4e2917ea8147153a973b9abaa))
* **warp:** preserve raw warp rows in uploaded sessions ([9c40565](https://github.com/TeamCadenceAI/cadence-cli/commit/9c405657cbea632ec6b55471c13b815364775995))
* **warp:** preserve raw warp rows in uploaded sessions ([f14be48](https://github.com/TeamCadenceAI/cadence-cli/commit/f14be488350cb5f44d74f1b5bc70916d8acde368))
* Windsurf support ([df4b338](https://github.com/TeamCadenceAI/cadence-cli/commit/df4b3383079305fa32bb4c2b3e5f6d41c5b9310c))


### Bug Fixes

* Add CLI version header + defer sync improvements ([0e5d1ad](https://github.com/TeamCadenceAI/cadence-cli/commit/0e5d1adab2d1fce722c2257d221ed6673da7b7b5))
* **agents:** harden windsurf and antigravity API discovery ([f1900c7](https://github.com/TeamCadenceAI/cadence-cli/commit/f1900c754de561e0fc0ae1f8d75321d2693a30df))
* **agents:** isolate app config paths from host env in rooted discovery ([45cce55](https://github.com/TeamCadenceAI/cadence-cli/commit/45cce558166508e70c1445845f97c3c8b9fb9542))
* **auth:** stop storing CLI tokens in OS keychain ([dd263f1](https://github.com/TeamCadenceAI/cadence-cli/commit/dd263f1ff775242e4edb25b456b26d1dc05bfd41))
* **auth:** stop storing CLI tokens in OS keychain ([8ea1eda](https://github.com/TeamCadenceAI/cadence-cli/commit/8ea1edad245fb944a57e5b2f655080180102f6d0))
* **backfill:** add boxed relogin guidance after update ([3b5a3ce](https://github.com/TeamCadenceAI/cadence-cli/commit/3b5a3cea9c435a8fd788812c52064af7ce4fef01))
* **backfill:** add boxed relogin guidance after update ([1476df9](https://github.com/TeamCadenceAI/cadence-cli/commit/1476df96c4a9a4c12d7e356893e16e7a01c94c83))
* **backfill:** add per-run diagnostic JSONL logs ([66884a0](https://github.com/TeamCadenceAI/cadence-cli/commit/66884a0fe24476168992322683b84b3ff80d94f4))
* **backfill:** improve upload diagnostics and recovery ([2e9c7d8](https://github.com/TeamCadenceAI/cadence-cli/commit/2e9c7d868a180ba8ee6c3f0b22c7f2f2505bae56))
* **backfill:** log repo_push_failed when session ref push errors ([3268234](https://github.com/TeamCadenceAI/cadence-cli/commit/3268234e1635eca85ba605fd10c7af38c539c4d3))
* **backfill:** log repo_push_failed when session ref push errors ([89ad10a](https://github.com/TeamCadenceAI/cadence-cli/commit/89ad10a49c368962d9ac72ce77aa50cae86e0b21))
* **backfill:** recover Claude metadata from log paths ([d512d09](https://github.com/TeamCadenceAI/cadence-cli/commit/d512d097e9847289d3f1d546e9cee4beeeeafc2a))
* **backfill:** recover codex/zed commits when session window is narrow ([3e48243](https://github.com/TeamCadenceAI/cadence-cli/commit/3e4824325a64cd831e808605bc23ac5794d00bae))
* **backfill:** skip auth-blocked recovery work ([8c6bb5f](https://github.com/TeamCadenceAI/cadence-cli/commit/8c6bb5f4b55d178f7624be007163e4abfc3502a1))
* **backfill:** streamline progress output and quiet push sync ([eea868b](https://github.com/TeamCadenceAI/cadence-cli/commit/eea868bff346822abd528352687ce45e531a0481))
* **backfill:** treat existing notes as skipped during backfill ([f30f2a5](https://github.com/TeamCadenceAI/cadence-cli/commit/f30f2a5dc9e1ce0ebdb998a081b5e685ec033a36))
* **bootstrap:** harden update handoff and fallback recovery ([3e8b170](https://github.com/TeamCadenceAI/cadence-cli/commit/3e8b170ed3dd2f3b68d94a22f3fa5bf867baed46))
* **bootstrap:** serialize install runtime bootstrap ([d9dfc76](https://github.com/TeamCadenceAI/cadence-cli/commit/d9dfc764d80c69f27f9134705a1bdab3b3478c60))
* **bootstrap:** serialize install runtime bootstrap ([53d6b8c](https://github.com/TeamCadenceAI/cadence-cli/commit/53d6b8c6e15d3973d4bbd58f3d80d1bdc5b1a0d5))
* **bootstrap:** widen recovery backfill window ([c2d1bec](https://github.com/TeamCadenceAI/cadence-cli/commit/c2d1bec2494ecd8f9885de44138eb3308376928f))
* **ci:** disable fail-fast test execution and stabilize windows scanner fixture ([ba83d69](https://github.com/TeamCadenceAI/cadence-cli/commit/ba83d69e2a6a6ff404ae3aef50c97102dad2d6ff))
* **claude:** align desktop manifest tests with platform paths ([cc5a3f4](https://github.com/TeamCadenceAI/cadence-cli/commit/cc5a3f481fcd9f50ad8274af31dc47df372a498f))
* **claude:** use desktop manifests to surface recent sessions ([d11eae6](https://github.com/TeamCadenceAI/cadence-cli/commit/d11eae6c959b377766c276c32b5a059e344c0f3a))
* **claude:** use desktop manifests to surface recent sessions ([6507528](https://github.com/TeamCadenceAI/cadence-cli/commit/65075288c8fa21460a1f26a667457f22ec1a8638))
* **clippy:** remove dead-code suppressions ([1c8b178](https://github.com/TeamCadenceAI/cadence-cli/commit/1c8b178a66eded78e883d3a0a032d70f8c6f838e))
* **compat:** move config path to ~/.cadence/cli and use pure-Rust pgp for challenge encryption ([08684a5](https://github.com/TeamCadenceAI/cadence-cli/commit/08684a515a89d632f645250c08cf6254f0623cf2))
* **cursor:** ignore MCP metadata in project scans ([60dc3fe](https://github.com/TeamCadenceAI/cadence-cli/commit/60dc3febb3b706b44100bbfdcce66440535c6f01))
* **cursor:** make workspace-key tests Windows-safe ([377f4d8](https://github.com/TeamCadenceAI/cadence-cli/commit/377f4d8e6e9a58407eb2ba3a4ea8cb16cc515ecc))
* **decrypt:** improve error context for private key parsing ([b14b68b](https://github.com/TeamCadenceAI/cadence-cli/commit/b14b68b55a3725abd0a1125bce764d79d20e2f7c))
* Deferred sync, performance improvements and discovery logging ([6a4e29c](https://github.com/TeamCadenceAI/cadence-cli/commit/6a4e29c80b6c532fbf464968a16f5650205783de))
* **deps:** use rustls-only TLS for cross-platform SSL compatibility ([8e33a5b](https://github.com/TeamCadenceAI/cadence-cli/commit/8e33a5b96785a5930966d8d870c71f3c42e92f8f))
* **deps:** use rustls-only TLS for cross-platform SSL compatibility ([76d4f36](https://github.com/TeamCadenceAI/cadence-cli/commit/76d4f36be87247845fe555ce0f181c711bb61725))
* **discovery:** address CI and review follow-ups ([18458d5](https://github.com/TeamCadenceAI/cadence-cli/commit/18458d573a1c6e3a56839f00bc13021d774886b5))
* **discovery:** resolve Claude desktop sessions with parent-directory CWD ([99f4fcd](https://github.com/TeamCadenceAI/cadence-cli/commit/99f4fcda5237b41b2812785ee0e8207fd5396ef2))
* **discovery:** resolve Claude desktop sessions with parent-directory CWD ([c03aae2](https://github.com/TeamCadenceAI/cadence-cli/commit/c03aae2b95f27b5d6b9abcf76d7af92c6c159916))
* **discovery:** respect windows and cursor turn order ([e3b9ce8](https://github.com/TeamCadenceAI/cadence-cli/commit/e3b9ce8b79c53d8d02e72b79d92a512eab219e8c))
* Fix GC not GCing all refs ([bbc337d](https://github.com/TeamCadenceAI/cadence-cli/commit/bbc337d3f348eb63620a5f08e4f35048cafd2435))
* Fix install script for new format ([72a3d0e](https://github.com/TeamCadenceAI/cadence-cli/commit/72a3d0e18ff335d2f5907fa8b5fcea2218f3cc71))
* Fixes for hook loop ([66d17cf](https://github.com/TeamCadenceAI/cadence-cli/commit/66d17cfc029dbc949285c9dfae96d7cd0e88dbdf))
* **gc:** skip pre-push hook on ref delete and scope hydration to current repo ([b3d79ad](https://github.com/TeamCadenceAI/cadence-cli/commit/b3d79ad53f06cf1b0eb3b7443a4a5038da6078ad))
* **git:** recover deleted worktree subdirectories ([718cc3e](https://github.com/TeamCadenceAI/cadence-cli/commit/718cc3e2f198a4ad113e35d72a4cb2db9cf26ffc))
* harden runtime bootstrap handoff for monitor migration ([2c5058e](https://github.com/TeamCadenceAI/cadence-cli/commit/2c5058e00ace9b9eb85aeeabfc19d043a6dac45c))
* **hook:** add newline for better readability in spinner output ([62d1e8c](https://github.com/TeamCadenceAI/cadence-cli/commit/62d1e8c7e80acc98b5c9af639187d5c52d389083))
* **hooks:** make post-commit compatibility path inert ([0fe8577](https://github.com/TeamCadenceAI/cadence-cli/commit/0fe8577ec3e1f735dc4851782249d197731b8b3a))
* **hydrate:** encrypt notes in time-window match path ([2c2b9d8](https://github.com/TeamCadenceAI/cadence-cli/commit/2c2b9d8e46617378c8470c12690daaf6a7a0096a))
* Improve sync UX ([690d4bd](https://github.com/TeamCadenceAI/cadence-cli/commit/690d4bd8e8d52031c758144dff207cb3db1c29b8))
* Improve verbosity of hooks ([bde25a3](https://github.com/TeamCadenceAI/cadence-cli/commit/bde25a3c6402b37643dc1f2d0cb9cdaf4a6c484a))
* Improvements to GPG setup ([c77acb8](https://github.com/TeamCadenceAI/cadence-cli/commit/c77acb872286e769eca368d78be5fd80a4a84460))
* **install:** default auto-update on during FTUE ([e79e877](https://github.com/TeamCadenceAI/cadence-cli/commit/e79e877b2c4a37728303a94120afc610b1649931))
* **install:** default auto-update on during FTUE ([d348d43](https://github.com/TeamCadenceAI/cadence-cli/commit/d348d4306d48943b3dc2cc5e00bcfdc4f3884449))
* **install:** show version number in install script output ([9577f67](https://github.com/TeamCadenceAI/cadence-cli/commit/9577f6733a01db790af033e0eaced8489ab9436a))
* Lean on RGPG more ([03ae12d](https://github.com/TeamCadenceAI/cadence-cli/commit/03ae12d4eb55a20055cbc9d4f7b95ffd2b21f47c))
* **locking:** report long waits for activity lock ([b23d46a](https://github.com/TeamCadenceAI/cadence-cli/commit/b23d46a99c7cef0f3e70f98683a8dc5140feb67f))
* **locking:** report long waits for activity lock ([39848df](https://github.com/TeamCadenceAI/cadence-cli/commit/39848dfed13a0a182d4622064df8f5ecfcfe1cf2))
* **login:** improve auth failure diagnostics ([a7ccbd2](https://github.com/TeamCadenceAI/cadence-cli/commit/a7ccbd23be974d4a26ff7cbcd81349a6ecdaa689))
* **login:** improve auth failure diagnostics ([89f5c99](https://github.com/TeamCadenceAI/cadence-cli/commit/89f5c999699bbcb11a93d48f32df977ec00c5c38))
* **merge:** resolve conflicts with main ([7c7e300](https://github.com/TeamCadenceAI/cadence-cli/commit/7c7e3008047f99fac73b0e27e8a21c26aca50631))
* **monitor:** freeze cursor after retryable skips ([d5a8784](https://github.com/TeamCadenceAI/cadence-cli/commit/d5a8784f2d04c1951341dd71092e5aeecd6a3540))
* **monitor:** gate macos-only scheduler helpers ([bc37a87](https://github.com/TeamCadenceAI/cadence-cli/commit/bc37a877621897d6ff19e0077e16a8c7e92db102))
* **monitor:** harden runtime bootstrap handoff ([d72c85e](https://github.com/TeamCadenceAI/cadence-cli/commit/d72c85e4ccc212c8a62607a373e858f2893051be))
* **monitor:** ignore irrelevant sessions when advancing cursor ([ea6b861](https://github.com/TeamCadenceAI/cadence-cli/commit/ea6b861d9cc96b438cb8aa75cbdb574e6efedcf4))
* **monitor:** keep compatibility ticks lightweight and resilient ([81c3de8](https://github.com/TeamCadenceAI/cadence-cli/commit/81c3de81af00d4b958fa527a2537f4351f1970a2))
* **monitor:** pause background publication when auth is invalid ([4431f4b](https://github.com/TeamCadenceAI/cadence-cli/commit/4431f4bc972d3039e1969afe4e0947314f8e9cc6))
* **monitor:** persist background diagnostics under cadence state ([2cb17ae](https://github.com/TeamCadenceAI/cadence-cli/commit/2cb17aee5c9b4663d9e387587a822efad949e128))
* **monitor:** recover sessions hidden behind the global cursor ([7d52321](https://github.com/TeamCadenceAI/cadence-cli/commit/7d523218776552666d60b0f75328b2fdb9360b17))
* **monitor:** recover sessions hidden behind the global cursor ([7208782](https://github.com/TeamCadenceAI/cadence-cli/commit/720878282c80028419881d9edbb1295aeb6d652c))
* **monitor:** remove global cursor blocking on retryable uploads ([2bd0182](https://github.com/TeamCadenceAI/cadence-cli/commit/2bd01823a6ef983f2cfd09e72774f3174bc64fff))
* **monitor:** scope scheduler failure helper ([f438578](https://github.com/TeamCadenceAI/cadence-cli/commit/f438578b2771ddfdd134c1c8d8fbcbbf7c3366cc))
* **monitor:** skip Warp discovery during background ticks ([b9d37c8](https://github.com/TeamCadenceAI/cadence-cli/commit/b9d37c811545e4bfba3e52b6477afb1f29b9b8b4))
* **monitor:** skip Warp discovery during background ticks ([4bc96e1](https://github.com/TeamCadenceAI/cadence-cli/commit/4bc96e17f599cad57d6d063a93aa2b1172a3add6))
* **monitor:** throttle repeated filtered session discovery ([35b8535](https://github.com/TeamCadenceAI/cadence-cli/commit/35b85355b54f0773c7a4154008645b78594c2d00))
* More sync TUI improvements ([d765b67](https://github.com/TeamCadenceAI/cadence-cli/commit/d765b6720324f56699252a654f388bb52fe095c0))
* **note:** remove misleading session envelope metadata ([62eda71](https://github.com/TeamCadenceAI/cadence-cli/commit/62eda713eff43a20868aa96dce87d66ae487fc9d))
* **note:** remove unused session matching metadata ([0b84901](https://github.com/TeamCadenceAI/cadence-cli/commit/0b849017b67260677730c12872bd6641b104bd71))
* **notes:** keep v2 pointer notes as plaintext, encrypt only payload blob ([55ff7d7](https://github.com/TeamCadenceAI/cadence-cli/commit/55ff7d77934aa37d64a4604c9736b86e9ee3d78d))
* **note:** stop writing misleading session fields ([567dcc6](https://github.com/TeamCadenceAI/cadence-cli/commit/567dcc639c20a6d95e51d82deed4115882ead80e))
* **opencode:** dedupe mixed records and scope SQLite queries ([009bbcd](https://github.com/TeamCadenceAI/cadence-cli/commit/009bbcdb428231c28061c76c710eb6a438a7e5a7))
* **opencode:** load parent file sessions outside cutoff ([36652cb](https://github.com/TeamCadenceAI/cadence-cli/commit/36652cb7688ff411bc610232efaf0c7377b304da))
* **opencode:** load SQLite-backed sessions across storage layouts ([1c41fbc](https://github.com/TeamCadenceAI/cadence-cli/commit/1c41fbc9942fa9745909bfbf516f9798d24eec4f))
* **opencode:** load SQLite-backed sessions across storage layouts ([781a29b](https://github.com/TeamCadenceAI/cadence-cli/commit/781a29b9f7cc95b593079c2cf0db39cee4ccbe8b))
* **opencode:** satisfy CI lint rules ([621f9c7](https://github.com/TeamCadenceAI/cadence-cli/commit/621f9c70c037bc616b805619381170050224cca5))
* **opencode:** use file mtime fallback for untimestamped sessions ([e367c9b](https://github.com/TeamCadenceAI/cadence-cli/commit/e367c9bf508216d053383d00da0ed1e638f0f4db))
* pause monitor publishing when auth is invalid ([c6fd8f5](https://github.com/TeamCadenceAI/cadence-cli/commit/c6fd8f55c1830e503a84770ad76406ada2bdf6b5))
* polish install and backfill CLI output formatting ([5906d96](https://github.com/TeamCadenceAI/cadence-cli/commit/5906d96e8fad742c0d792599cf9bf93740db3b75))
* polish install and backfill CLI output formatting ([d93a8cb](https://github.com/TeamCadenceAI/cadence-cli/commit/d93a8cbf39afa2c53fd6ecd40d4fda1340f2da8f))
* **publication:** refresh queued uploads and preserve cross-platform state writes ([580249d](https://github.com/TeamCadenceAI/cadence-cli/commit/580249dab25b97d88f18b803f2a4324a7408d8c4))
* **publication:** stop republishing sessions for head-only changes ([8686853](https://github.com/TeamCadenceAI/cadence-cli/commit/86868532bebfdf7fd9d55ec8308930972fb6adb4))
* **publication:** stop republishing sessions for head-only changes ([22975e2](https://github.com/TeamCadenceAI/cadence-cli/commit/22975e2cef131fb20c496a3b4aaaa3d85463142c))
* **push:** fetch-merge remote notes before pushing during hydrate ([2470bd9](https://github.com/TeamCadenceAI/cadence-cli/commit/2470bd9b3ad1a241d6b0d52ec64b12d408109835))
* **push:** preserve notes merge history instead of squashing into orphans ([0684801](https://github.com/TeamCadenceAI/cadence-cli/commit/068480179ab052ac4a4f6ccfaa0ef407bdb6e43b))
* **push:** skip merge in sync retry when remote has no notes ref ([d3fcd00](https://github.com/TeamCadenceAI/cadence-cli/commit/d3fcd00ac8fab1060c90188ee1074a834caf7403))
* **push:** skip push when no local notes ref exists ([0adab24](https://github.com/TeamCadenceAI/cadence-cli/commit/0adab2439def02d1dde2982030f051bf2e0287fa))
* **release:** pin release-please action to a newer SHA ([65beff3](https://github.com/TeamCadenceAI/cadence-cli/commit/65beff3d1fb6c64e077025b1377d03bbe88eb51e))
* **release:** pin release-please action to newer runtime ([9ca602c](https://github.com/TeamCadenceAI/cadence-cli/commit/9ca602ca74efeb82800684c687891b323edc15bd))
* **release:** publish assets for draft release-please releases ([7dcc222](https://github.com/TeamCadenceAI/cadence-cli/commit/7dcc222c7eb747183d956096c875d2f2d70ca78b))
* **release:** publish assets for draft release-please releases ([c86c273](https://github.com/TeamCadenceAI/cadence-cli/commit/c86c2739d4d8197d607aa7ebe6aa466bcf0a3dbf))
* **release:** remove macos notarization ([e000326](https://github.com/TeamCadenceAI/cadence-cli/commit/e000326d9dd102a071cfeb0a5eb4f72f8cd78d53))
* **release:** remove macos notarization from releases ([4b2a160](https://github.com/TeamCadenceAI/cadence-cli/commit/4b2a16015047734b685a8066774e9b448f6cee0c))
* **release:** stop checking notarization before submit ([2999c24](https://github.com/TeamCadenceAI/cadence-cli/commit/2999c24c6b98e643a9f511be9316f81ae5254dd7))
* **release:** stop checking notarization before submit ([eb27a76](https://github.com/TeamCadenceAI/cadence-cli/commit/eb27a76eb9a775d093542d40a7672073b228d92c))
* **retry:** prefix retry-attach log lines with cadence label ([a9acc97](https://github.com/TeamCadenceAI/cadence-cli/commit/a9acc972e3e44c7264dd2ed736ac25fed6e86957))
* **runtime:** avoid nested Tokio block_on panic during install ([1a7e491](https://github.com/TeamCadenceAI/cadence-cli/commit/1a7e4911155d7250af4d3050ce4018a38671209a))
* **runtime:** repair monitor state and hook ownership cleanup ([7134985](https://github.com/TeamCadenceAI/cadence-cli/commit/7134985ca80d350773e9143cef3564077dc79b1a))
* **scanner:** harden agent/cwd discovery and dedupe dir scans ([4048d23](https://github.com/TeamCadenceAI/cadence-cli/commit/4048d2331dfd2c646a575e1a3594949b82d48eb0))
* **scanner:** lower default match thresholds to favor overmatching ([0226146](https://github.com/TeamCadenceAI/cadence-cli/commit/0226146a4945164e341ecfe339514290651fcb3d))
* **scanner:** make Claude path recovery Windows-safe ([be70c3f](https://github.com/TeamCadenceAI/cadence-cli/commit/be70c3f658b115611e0ce69733bcf4bd74a93d00))
* **scanner:** support Windows-safe Claude project names ([546cafa](https://github.com/TeamCadenceAI/cadence-cli/commit/546cafae2790021730feb1e257a3c84c762e62cf))
* skip auth-blocked recovery backfills ([c7cbcbe](https://github.com/TeamCadenceAI/cadence-cli/commit/c7cbcbe603a7a1610189aa2a9f5ba77251abfe71))
* **sync:** avoid temp-file collisions in atomic queue writes ([9f2de13](https://github.com/TeamCadenceAI/cadence-cli/commit/9f2de13a6f6c70b41d83533e9d414f46f309a7d2))
* **sync:** bound deferred ingest to runnable pending jobs ([956b670](https://github.com/TeamCadenceAI/cadence-cli/commit/956b670a8a18e8dcf30fc626126f66bfe9432569))
* **sync:** capture full deferred-sync tracing in log files ([a2ba111](https://github.com/TeamCadenceAI/cadence-cli/commit/a2ba111ff8d903cd6a51810056097daace5620c7))
* **sync:** handle stale temp refs and non-fast-forward during notes sync ([23500e9](https://github.com/TeamCadenceAI/cadence-cli/commit/23500e906f9a77e54b7ddce9a21738d0c7cbcd53))
* **sync:** handle stale temp refs and non-fast-forward during notes sync ([a3a020f](https://github.com/TeamCadenceAI/cadence-cli/commit/a3a020fe26637ebc3c791d93ff5b909b68ebd67d))
* **sync:** harden cursor I/O and async traversal behavior ([b24834d](https://github.com/TeamCadenceAI/cadence-cli/commit/b24834d368065fe53a99956e463eae270f905322))
* **sync:** harden deferred sync execution and ref sync safety ([7e3373e](https://github.com/TeamCadenceAI/cadence-cli/commit/7e3373eb4315259b7efff0cb6e0ea6f7e0353d2e))
* **sync:** preserve index entries during ref merges and align post-commit branch indexing ([9fd3fe4](https://github.com/TeamCadenceAI/cadence-cli/commit/9fd3fe4d1c3e91be3233c24614561f3146d2cf21))
* **sync:** require auth token for session-ref push notification ([cc2250c](https://github.com/TeamCadenceAI/cadence-cli/commit/cc2250cdbb29f29ebc36b920dc1a887c98259591))
* **sync:** set deferred sync timeout to 120 seconds ([22b98b3](https://github.com/TeamCadenceAI/cadence-cli/commit/22b98b33aea57dd153915e5f0aa1e8f0c22195ab))
* **test:** accept Windows GPG passphrase error for unknown key export test ([b1663d1](https://github.com/TeamCadenceAI/cadence-cli/commit/b1663d1af57ed6360367daafdc7727cc2b1a5167))
* **transport:** support enterprise TLS roots ([1541eea](https://github.com/TeamCadenceAI/cadence-cli/commit/1541eeab0201ae40b3ad09fe9e8d02e40c58cdf0))
* **transport:** support enterprise TLS roots ([fa3e5a7](https://github.com/TeamCadenceAI/cadence-cli/commit/fa3e5a7377454ed59bf22a4fb713f5707a175eea))
* update key generation to use 2048-bit RSA for improved security ([30c23bd](https://github.com/TeamCadenceAI/cadence-cli/commit/30c23bd4530f4fde9ba1ea9483d7b168723017c9))
* **update:** address PR review feedback ([f39f41a](https://github.com/TeamCadenceAI/cadence-cli/commit/f39f41a70a7493289565c5237456f2a65cdd27aa))
* **update:** avoid nested Tokio runtime panic ([4b33d2d](https://github.com/TeamCadenceAI/cadence-cli/commit/4b33d2d470a48ae639752552ee13ba9b7071a5e9))
* **update:** avoid self-disabling monitor during self-update handoff ([98057c1](https://github.com/TeamCadenceAI/cadence-cli/commit/98057c17e0c7c005dd19e1eece492086deaf03d6))
* **update:** avoid self-disabling monitor during self-update handoff ([d031b36](https://github.com/TeamCadenceAI/cadence-cli/commit/d031b36c12799d6ab26cf811752ced92ba0c7b10))
* **update:** detach linux helper handoff ([073d643](https://github.com/TeamCadenceAI/cadence-cli/commit/073d643198137e665137ed1916ae1a1be3e4a28d))
* **update:** harden helper handoff semantics ([5fc3842](https://github.com/TeamCadenceAI/cadence-cli/commit/5fc38425f5d40ee7b43342b991b3ac7f229bd6fe))
* **update:** heal updater state after successful bootstrap ([7a73045](https://github.com/TeamCadenceAI/cadence-cli/commit/7a73045a4e92caf311556b118a766136920ee4e8))
* **update:** heal updater state after successful bootstrap ([47058b7](https://github.com/TeamCadenceAI/cadence-cli/commit/47058b75f516254cfbe5ba18907cd1b950a9bb9c))
* **update:** keep macOS auto-update scheduler persistent ([89ad0bd](https://github.com/TeamCadenceAI/cadence-cli/commit/89ad0bde06649cfbd28add401f0d73feb1074038))
* **update:** keep macOS auto-update scheduler persistent ([8190d4f](https://github.com/TeamCadenceAI/cadence-cli/commit/8190d4f162996f718cf3bc5af22716255916635a))
* **update:** recover sessions on first run of each version ([2e193ef](https://github.com/TeamCadenceAI/cadence-cli/commit/2e193ef19e06cfa888593c4c924320d3c6948530))
* **update:** recover sessions on first run of each version ([205432b](https://github.com/TeamCadenceAI/cadence-cli/commit/205432b75e459493c5e5d28a0e4e8d8003f78df1))
* **update:** recover worktree sessions and self-heal upgrades ([887f6ea](https://github.com/TeamCadenceAI/cadence-cli/commit/887f6ea4f67b8eeaa250e179a3180a956a5fc72c))
* **update:** recover worktree sessions and self-heal upgrades ([4682983](https://github.com/TeamCadenceAI/cadence-cli/commit/4682983c5eadca9f227fe74463666e479b353fbd))
* **update:** refresh git hooks after self-update ([fc79ce7](https://github.com/TeamCadenceAI/cadence-cli/commit/fc79ce78d045547aab690d090242e3326aea3064))
* **update:** repair windows activity-lock build ([9ac6c2c](https://github.com/TeamCadenceAI/cadence-cli/commit/9ac6c2c0937d967cf7e769b6f268f6a63419bdfa))
* **update:** report loaded macOS scheduler correctly ([83c84dc](https://github.com/TeamCadenceAI/cadence-cli/commit/83c84dca4fafaf05f00257bc2c83ac0b66a13823))
* **update:** report loaded macOS scheduler correctly ([daa3d78](https://github.com/TeamCadenceAI/cadence-cli/commit/daa3d783dfa0d539d1217c136326344924d57ba0))
* **update:** require reachable user systemd manager ([6085eb1](https://github.com/TeamCadenceAI/cadence-cli/commit/6085eb1a31d25ef8ce11b9dd40d75ce5a945d7e3))
* **update:** scope platform-specific clippy helpers ([1b92cf3](https://github.com/TeamCadenceAI/cadence-cli/commit/1b92cf39e678e56018e103b853697d53786890c4))
* **update:** support both macos release archive formats ([7b18b3e](https://github.com/TeamCadenceAI/cadence-cli/commit/7b18b3e977b47f7d0667b3a8522ad393e5732a64))
* **update:** support both macos release archive formats ([5ad817b](https://github.com/TeamCadenceAI/cadence-cli/commit/5ad817b71591041c3f811aed39ca48c6fa8ff573))
* **update:** switch from GitHub API to HTTP redirect for release discovery ([4e9aafd](https://github.com/TeamCadenceAI/cadence-cli/commit/4e9aafd185922a32ac749af89b60c049aa2ccce8))
* **update:** switch from GitHub API to HTTP redirect for release discovery ([ee13e47](https://github.com/TeamCadenceAI/cadence-cli/commit/ee13e47659c472b71f9d73f1725c585687086584))
* **update:** unblock monitor-driven auto-upgrades ([be07f49](https://github.com/TeamCadenceAI/cadence-cli/commit/be07f4930f2b6bf476fe7ab54f4af27c21b2f3e4))
* **update:** use portable windows sync access mask ([062f87b](https://github.com/TeamCadenceAI/cadence-cli/commit/062f87bab4e3d34d5afc8805a231efc3c6d18186))
* **upload:** address Copilot publication review findings ([77c837c](https://github.com/TeamCadenceAI/cadence-cli/commit/77c837c15ccf505595414d4d2172c3f80b5f51f0))
* **upload:** harden pending retry and hook throughput ([6cb948b](https://github.com/TeamCadenceAI/cadence-cli/commit/6cb948b6cc51da1c8db62202cc0d409a89a8131d))
* **upload:** increase presigned upload timeout from 60s to 5 minutes ([9e6dcc2](https://github.com/TeamCadenceAI/cadence-cli/commit/9e6dcc2c75404c108d6f4cdd70c6ddeaf717486a))
* **upload:** increase presigned upload timeout to 5 minutes ([68e3588](https://github.com/TeamCadenceAI/cadence-cli/commit/68e3588262a7c2cc2920a0e9e1b95374ed3c88ce))
* Uploading reliability + debugging improvements ([5344ad5](https://github.com/TeamCadenceAI/cadence-cli/commit/5344ad5e34545b6ed2707fc927f4fdcadbe852e2))
* **upload:** normalize Windows test worktree paths ([dbd7046](https://github.com/TeamCadenceAI/cadence-cli/commit/dbd70469e0bfae0906116234f494c897d648f321))
* **upload:** preserve direct-upload retries ([9475d17](https://github.com/TeamCadenceAI/cadence-cli/commit/9475d17c512247598f5d8b32c9c52fd1ed57fcda))
* **upload:** preserve pending replay across merge updates ([fc6b6f3](https://github.com/TeamCadenceAI/cadence-cli/commit/fc6b6f333c101b11ba9a298c0997800bf79ba37b))
* **upload:** scale presigned upload timeout for large payloads ([72b9fd0](https://github.com/TeamCadenceAI/cadence-cli/commit/72b9fd02117f80105adec8aad559659f4f2c4fab))
* **upload:** scale presigned upload timeout for large payloads ([baeba2c](https://github.com/TeamCadenceAI/cadence-cli/commit/baeba2cef700390a2d593b104333d04ddfa61fab))
* **warp:** include task-only sessions and preserve envelope meta events ([fe6314a](https://github.com/TeamCadenceAI/cadence-cli/commit/fe6314ade5399bef0f061e0e182569d642018d1f))
* **warp:** preserve block cwd in meta-only sessions ([6215d72](https://github.com/TeamCadenceAI/cadence-cli/commit/6215d72994e91f0749db6c3a71af3267d11df587))
* **windsurf:** preserve cached API logs and classify non-macOS paths ([a5d544a](https://github.com/TeamCadenceAI/cadence-cli/commit/a5d544a5ab5d58e5e132ed19138bd645c40ebca0))


### Performance Improvements

* **cli:** skip remote sync during backfill unless pushing ([6a32211](https://github.com/TeamCadenceAI/cadence-cli/commit/6a3221138036c3a33164da21a0448f63f08bc4ae))
* **hooks:** optimize ingest discovery and ref sync hot paths ([8334808](https://github.com/TeamCadenceAI/cadence-cli/commit/8334808959143b25d5f7ef6a1fae12e5d7fb0a44))
* Push performance, Tokio runtime ([236c707](https://github.com/TeamCadenceAI/cadence-cli/commit/236c70738e8e191023b7d6eca9f8ce14f1cf7f66))
* **scanner:** reduce matcher overhead in hook and hydrate ([4422def](https://github.com/TeamCadenceAI/cadence-cli/commit/4422def9b17ee502257785400585ebb0b95fbe07))

## [2.6.1](https://github.com/TeamCadenceAI/cadence-cli/compare/v2.6.0...v2.6.1) (2026-04-17)


### Bug Fixes

* **bootstrap:** widen recovery backfill window ([c2d1bec](https://github.com/TeamCadenceAI/cadence-cli/commit/c2d1bec2494ecd8f9885de44138eb3308376928f))
* **monitor:** ignore irrelevant sessions when advancing cursor ([ea6b861](https://github.com/TeamCadenceAI/cadence-cli/commit/ea6b861d9cc96b438cb8aa75cbdb574e6efedcf4))
* **monitor:** recover sessions hidden behind the global cursor ([7d52321](https://github.com/TeamCadenceAI/cadence-cli/commit/7d523218776552666d60b0f75328b2fdb9360b17))
* **monitor:** recover sessions hidden behind the global cursor ([7208782](https://github.com/TeamCadenceAI/cadence-cli/commit/720878282c80028419881d9edbb1295aeb6d652c))
* **monitor:** throttle repeated filtered session discovery ([35b8535](https://github.com/TeamCadenceAI/cadence-cli/commit/35b85355b54f0773c7a4154008645b78594c2d00))

## [2.6.0](https://github.com/TeamCadenceAI/cadence-cli/compare/v2.5.0...v2.6.0) (2026-04-09)


### Features

* **opencode:** stitch child sessions into root uploads ([965019e](https://github.com/TeamCadenceAI/cadence-cli/commit/965019e26b9095bb1567ba98ce73845ad957fde6))
* **opencode:** stitch child sessions into root uploads ([bc332d4](https://github.com/TeamCadenceAI/cadence-cli/commit/bc332d4327d20c5cc82c57738cea7e69ea26d5ef))


### Bug Fixes

* **opencode:** load parent file sessions outside cutoff ([36652cb](https://github.com/TeamCadenceAI/cadence-cli/commit/36652cb7688ff411bc610232efaf0c7377b304da))
* **opencode:** satisfy CI lint rules ([621f9c7](https://github.com/TeamCadenceAI/cadence-cli/commit/621f9c70c037bc616b805619381170050224cca5))

## [2.5.0](https://github.com/TeamCadenceAI/cadence-cli/compare/v2.4.1...v2.5.0) (2026-04-07)


### Features

* **warp:** preserve raw warp rows in uploaded sessions ([9c40565](https://github.com/TeamCadenceAI/cadence-cli/commit/9c405657cbea632ec6b55471c13b815364775995))
* **warp:** preserve raw warp rows in uploaded sessions ([f14be48](https://github.com/TeamCadenceAI/cadence-cli/commit/f14be488350cb5f44d74f1b5bc70916d8acde368))

## [2.4.1](https://github.com/TeamCadenceAI/cadence-cli/compare/v2.4.0...v2.4.1) (2026-04-02)


### Bug Fixes

* **discovery:** resolve Claude desktop sessions with parent-directory CWD ([99f4fcd](https://github.com/TeamCadenceAI/cadence-cli/commit/99f4fcda5237b41b2812785ee0e8207fd5396ef2))
* **discovery:** resolve Claude desktop sessions with parent-directory CWD ([c03aae2](https://github.com/TeamCadenceAI/cadence-cli/commit/c03aae2b95f27b5d6b9abcf76d7af92c6c159916))

## [2.4.0](https://github.com/TeamCadenceAI/cadence-cli/compare/v2.3.6...v2.4.0) (2026-04-02)


### Features

* **discovery:** expand Cursor and Warp session recovery ([ec37e65](https://github.com/TeamCadenceAI/cadence-cli/commit/ec37e65c33d010128ccd3f6f2f55a3349dc0e589))
* **discovery:** expand Cursor and Warp session recovery ([0d5743f](https://github.com/TeamCadenceAI/cadence-cli/commit/0d5743f1f922acd856d35a78f8bebf1d4ffb7ee7))


### Bug Fixes

* **cursor:** make workspace-key tests Windows-safe ([377f4d8](https://github.com/TeamCadenceAI/cadence-cli/commit/377f4d8e6e9a58407eb2ba3a4ea8cb16cc515ecc))
* **discovery:** address CI and review follow-ups ([18458d5](https://github.com/TeamCadenceAI/cadence-cli/commit/18458d573a1c6e3a56839f00bc13021d774886b5))
* **discovery:** respect windows and cursor turn order ([e3b9ce8](https://github.com/TeamCadenceAI/cadence-cli/commit/e3b9ce8b79c53d8d02e72b79d92a512eab219e8c))
* Fix install script for new format ([72a3d0e](https://github.com/TeamCadenceAI/cadence-cli/commit/72a3d0e18ff335d2f5907fa8b5fcea2218f3cc71))
* **warp:** preserve block cwd in meta-only sessions ([6215d72](https://github.com/TeamCadenceAI/cadence-cli/commit/6215d72994e91f0749db6c3a71af3267d11df587))

## [2.3.6](https://github.com/TeamCadenceAI/cadence-cli/compare/v2.3.5...v2.3.6) (2026-03-30)


### Bug Fixes

* **locking:** report long waits for activity lock ([b23d46a](https://github.com/TeamCadenceAI/cadence-cli/commit/b23d46a99c7cef0f3e70f98683a8dc5140feb67f))
* **locking:** report long waits for activity lock ([39848df](https://github.com/TeamCadenceAI/cadence-cli/commit/39848dfed13a0a182d4622064df8f5ecfcfe1cf2))
* **monitor:** skip Warp discovery during background ticks ([b9d37c8](https://github.com/TeamCadenceAI/cadence-cli/commit/b9d37c811545e4bfba3e52b6477afb1f29b9b8b4))
* **monitor:** skip Warp discovery during background ticks ([4bc96e1](https://github.com/TeamCadenceAI/cadence-cli/commit/4bc96e17f599cad57d6d063a93aa2b1172a3add6))

## [2.3.5](https://github.com/TeamCadenceAI/cadence-cli/compare/v2.3.4...v2.3.5) (2026-03-30)


### Bug Fixes

* **backfill:** add boxed relogin guidance after update ([3b5a3ce](https://github.com/TeamCadenceAI/cadence-cli/commit/3b5a3cea9c435a8fd788812c52064af7ce4fef01))
* **backfill:** add boxed relogin guidance after update ([1476df9](https://github.com/TeamCadenceAI/cadence-cli/commit/1476df96c4a9a4c12d7e356893e16e7a01c94c83))

## [2.3.4](https://github.com/TeamCadenceAI/cadence-cli/compare/v2.3.3...v2.3.4) (2026-03-30)


### Bug Fixes

* **update:** heal updater state after successful bootstrap ([7a73045](https://github.com/TeamCadenceAI/cadence-cli/commit/7a73045a4e92caf311556b118a766136920ee4e8))
* **update:** heal updater state after successful bootstrap ([47058b7](https://github.com/TeamCadenceAI/cadence-cli/commit/47058b75f516254cfbe5ba18907cd1b950a9bb9c))

## [2.3.3](https://github.com/TeamCadenceAI/cadence-cli/compare/v2.3.2...v2.3.3) (2026-03-30)


### Bug Fixes

* **update:** support both macos release archive formats ([7b18b3e](https://github.com/TeamCadenceAI/cadence-cli/commit/7b18b3e977b47f7d0667b3a8522ad393e5732a64))
* **update:** support both macos release archive formats ([5ad817b](https://github.com/TeamCadenceAI/cadence-cli/commit/5ad817b71591041c3f811aed39ca48c6fa8ff573))

## [2.3.2](https://github.com/TeamCadenceAI/cadence-cli/compare/v2.3.1...v2.3.2) (2026-03-29)


### Bug Fixes

* **release:** remove macos notarization ([e000326](https://github.com/TeamCadenceAI/cadence-cli/commit/e000326d9dd102a071cfeb0a5eb4f72f8cd78d53))
* **release:** remove macos notarization from releases ([4b2a160](https://github.com/TeamCadenceAI/cadence-cli/commit/4b2a16015047734b685a8066774e9b448f6cee0c))

## [2.3.1](https://github.com/TeamCadenceAI/cadence-cli/compare/v2.3.0...v2.3.1) (2026-03-29)


### Bug Fixes

* **release:** stop checking notarization before submit ([2999c24](https://github.com/TeamCadenceAI/cadence-cli/commit/2999c24c6b98e643a9f511be9316f81ae5254dd7))
* **release:** stop checking notarization before submit ([eb27a76](https://github.com/TeamCadenceAI/cadence-cli/commit/eb27a76eb9a775d093542d40a7672073b228d92c))

## [2.3.0](https://github.com/TeamCadenceAI/cadence-cli/compare/v2.2.6...v2.3.0) (2026-03-29)


### Features

* **update:** add detached updater helper and macOS signing ([2702319](https://github.com/TeamCadenceAI/cadence-cli/commit/2702319f46bdc90a0947514089117a698b9be762))
* **update:** add detached updater helper and macOS signing ([567de79](https://github.com/TeamCadenceAI/cadence-cli/commit/567de79c8526ac3b8b8f6c34c0a86c13b0bea938))


### Bug Fixes

* **update:** detach linux helper handoff ([073d643](https://github.com/TeamCadenceAI/cadence-cli/commit/073d643198137e665137ed1916ae1a1be3e4a28d))
* **update:** harden helper handoff semantics ([5fc3842](https://github.com/TeamCadenceAI/cadence-cli/commit/5fc38425f5d40ee7b43342b991b3ac7f229bd6fe))
* **update:** require reachable user systemd manager ([6085eb1](https://github.com/TeamCadenceAI/cadence-cli/commit/6085eb1a31d25ef8ce11b9dd40d75ce5a945d7e3))

## [2.2.6](https://github.com/TeamCadenceAI/cadence-cli/compare/v2.2.5...v2.2.6) (2026-03-29)


### Bug Fixes

* **update:** avoid self-disabling monitor during self-update handoff ([98057c1](https://github.com/TeamCadenceAI/cadence-cli/commit/98057c17e0c7c005dd19e1eece492086deaf03d6))
* **update:** avoid self-disabling monitor during self-update handoff ([d031b36](https://github.com/TeamCadenceAI/cadence-cli/commit/d031b36c12799d6ab26cf811752ced92ba0c7b10))

## [2.2.5](https://github.com/TeamCadenceAI/cadence-cli/compare/v2.2.4...v2.2.5) (2026-03-29)


### Bug Fixes

* **bootstrap:** serialize install runtime bootstrap ([d9dfc76](https://github.com/TeamCadenceAI/cadence-cli/commit/d9dfc764d80c69f27f9134705a1bdab3b3478c60))
* **bootstrap:** serialize install runtime bootstrap ([53d6b8c](https://github.com/TeamCadenceAI/cadence-cli/commit/53d6b8c6e15d3973d4bbd58f3d80d1bdc5b1a0d5))

## [2.2.4](https://github.com/TeamCadenceAI/cadence-cli/compare/v2.2.3...v2.2.4) (2026-03-29)


### Bug Fixes

* **update:** unblock monitor-driven auto-upgrades ([be07f49](https://github.com/TeamCadenceAI/cadence-cli/commit/be07f4930f2b6bf476fe7ab54f4af27c21b2f3e4))

## [2.2.3](https://github.com/TeamCadenceAI/cadence-cli/compare/v2.2.2...v2.2.3) (2026-03-29)


### Bug Fixes

* **backfill:** skip auth-blocked recovery work ([8c6bb5f](https://github.com/TeamCadenceAI/cadence-cli/commit/8c6bb5f4b55d178f7624be007163e4abfc3502a1))
* skip auth-blocked recovery backfills ([c7cbcbe](https://github.com/TeamCadenceAI/cadence-cli/commit/c7cbcbe603a7a1610189aa2a9f5ba77251abfe71))

## [2.2.2](https://github.com/TeamCadenceAI/cadence-cli/compare/v2.2.1...v2.2.2) (2026-03-29)


### Bug Fixes

* **monitor:** pause background publication when auth is invalid ([4431f4b](https://github.com/TeamCadenceAI/cadence-cli/commit/4431f4bc972d3039e1969afe4e0947314f8e9cc6))
* pause monitor publishing when auth is invalid ([c6fd8f5](https://github.com/TeamCadenceAI/cadence-cli/commit/c6fd8f55c1830e503a84770ad76406ada2bdf6b5))

## [2.2.1](https://github.com/TeamCadenceAI/cadence-cli/compare/v2.2.0...v2.2.1) (2026-03-29)


### Bug Fixes

* harden runtime bootstrap handoff for monitor migration ([2c5058e](https://github.com/TeamCadenceAI/cadence-cli/commit/2c5058e00ace9b9eb85aeeabfc19d043a6dac45c))
* **monitor:** harden runtime bootstrap handoff ([d72c85e](https://github.com/TeamCadenceAI/cadence-cli/commit/d72c85e4ccc212c8a62607a373e858f2893051be))

## [2.2.0](https://github.com/TeamCadenceAI/cadence-cli/compare/v2.1.7...v2.2.0) (2026-03-29)


### Features

* **bootstrap:** finish monitor bootstrap migration ([5af141c](https://github.com/TeamCadenceAI/cadence-cli/commit/5af141cbe0014d746e73f58ab09288af5c0d082f))
* **bootstrap:** unify install and version migration ([96d7b56](https://github.com/TeamCadenceAI/cadence-cli/commit/96d7b5679410432b3973e10c383bf85f862b5c9d))
* **monitor:** move live runtime off Git hooks ([c92ca66](https://github.com/TeamCadenceAI/cadence-cli/commit/c92ca66f6ec84413914043392ec5b591ae8ae464))
* move live ingestion to the background monitor runtime ([fdf5362](https://github.com/TeamCadenceAI/cadence-cli/commit/fdf5362aa5a23f836728f0030198b623943f67c4))


### Bug Fixes

* **bootstrap:** harden update handoff and fallback recovery ([3e8b170](https://github.com/TeamCadenceAI/cadence-cli/commit/3e8b170ed3dd2f3b68d94a22f3fa5bf867baed46))
* **claude:** align desktop manifest tests with platform paths ([cc5a3f4](https://github.com/TeamCadenceAI/cadence-cli/commit/cc5a3f481fcd9f50ad8274af31dc47df372a498f))
* **claude:** use desktop manifests to surface recent sessions ([d11eae6](https://github.com/TeamCadenceAI/cadence-cli/commit/d11eae6c959b377766c276c32b5a059e344c0f3a))
* **claude:** use desktop manifests to surface recent sessions ([6507528](https://github.com/TeamCadenceAI/cadence-cli/commit/65075288c8fa21460a1f26a667457f22ec1a8638))
* **hooks:** make post-commit compatibility path inert ([0fe8577](https://github.com/TeamCadenceAI/cadence-cli/commit/0fe8577ec3e1f735dc4851782249d197731b8b3a))
* **monitor:** freeze cursor after retryable skips ([d5a8784](https://github.com/TeamCadenceAI/cadence-cli/commit/d5a8784f2d04c1951341dd71092e5aeecd6a3540))
* **monitor:** keep compatibility ticks lightweight and resilient ([81c3de8](https://github.com/TeamCadenceAI/cadence-cli/commit/81c3de81af00d4b958fa527a2537f4351f1970a2))
* **monitor:** persist background diagnostics under cadence state ([2cb17ae](https://github.com/TeamCadenceAI/cadence-cli/commit/2cb17aee5c9b4663d9e387587a822efad949e128))
* **monitor:** remove global cursor blocking on retryable uploads ([2bd0182](https://github.com/TeamCadenceAI/cadence-cli/commit/2bd01823a6ef983f2cfd09e72774f3174bc64fff))
* **runtime:** repair monitor state and hook ownership cleanup ([7134985](https://github.com/TeamCadenceAI/cadence-cli/commit/7134985ca80d350773e9143cef3564077dc79b1a))

## [2.1.7](https://github.com/TeamCadenceAI/cadence-cli/compare/v2.1.6...v2.1.7) (2026-03-25)


### Bug Fixes

* **update:** keep macOS auto-update scheduler persistent ([89ad0bd](https://github.com/TeamCadenceAI/cadence-cli/commit/89ad0bde06649cfbd28add401f0d73feb1074038))
* **update:** keep macOS auto-update scheduler persistent ([8190d4f](https://github.com/TeamCadenceAI/cadence-cli/commit/8190d4f162996f718cf3bc5af22716255916635a))
* **update:** recover sessions on first run of each version ([2e193ef](https://github.com/TeamCadenceAI/cadence-cli/commit/2e193ef19e06cfa888593c4c924320d3c6948530))
* **update:** recover sessions on first run of each version ([205432b](https://github.com/TeamCadenceAI/cadence-cli/commit/205432b75e459493c5e5d28a0e4e8d8003f78df1))

## [2.1.6](https://github.com/TeamCadenceAI/cadence-cli/compare/v2.1.5...v2.1.6) (2026-03-24)


### Bug Fixes

* **release:** pin release-please action to newer runtime ([9ca602c](https://github.com/TeamCadenceAI/cadence-cli/commit/9ca602ca74efeb82800684c687891b323edc15bd))
* **update:** report loaded macOS scheduler correctly ([83c84dc](https://github.com/TeamCadenceAI/cadence-cli/commit/83c84dca4fafaf05f00257bc2c83ac0b66a13823))
* **update:** report loaded macOS scheduler correctly ([daa3d78](https://github.com/TeamCadenceAI/cadence-cli/commit/daa3d783dfa0d539d1217c136326344924d57ba0))

## [2.1.5](https://github.com/TeamCadenceAI/cadence-cli/compare/v2.1.4...v2.1.5) (2026-03-24)


### Bug Fixes

* **update:** recover worktree sessions and self-heal upgrades ([887f6ea](https://github.com/TeamCadenceAI/cadence-cli/commit/887f6ea4f67b8eeaa250e179a3180a956a5fc72c))
* **update:** recover worktree sessions and self-heal upgrades ([4682983](https://github.com/TeamCadenceAI/cadence-cli/commit/4682983c5eadca9f227fe74463666e479b353fbd))

## [2.1.4](https://github.com/TeamCadenceAI/cadence-cli/compare/v2.1.3...v2.1.4) (2026-03-24)


### Bug Fixes

* **opencode:** dedupe mixed records and scope SQLite queries ([009bbcd](https://github.com/TeamCadenceAI/cadence-cli/commit/009bbcdb428231c28061c76c710eb6a438a7e5a7))
* **opencode:** load SQLite-backed sessions across storage layouts ([1c41fbc](https://github.com/TeamCadenceAI/cadence-cli/commit/1c41fbc9942fa9745909bfbf516f9798d24eec4f))
* **opencode:** load SQLite-backed sessions across storage layouts ([781a29b](https://github.com/TeamCadenceAI/cadence-cli/commit/781a29b9f7cc95b593079c2cf0db39cee4ccbe8b))
* **release:** pin release-please action to a newer SHA ([65beff3](https://github.com/TeamCadenceAI/cadence-cli/commit/65beff3d1fb6c64e077025b1377d03bbe88eb51e))

## [2.1.3](https://github.com/TeamCadenceAI/cadence-cli/compare/v2.1.2...v2.1.3) (2026-03-24)


### Bug Fixes

* **release:** publish assets for draft release-please releases ([7dcc222](https://github.com/TeamCadenceAI/cadence-cli/commit/7dcc222c7eb747183d956096c875d2f2d70ca78b))
* **release:** publish assets for draft release-please releases ([c86c273](https://github.com/TeamCadenceAI/cadence-cli/commit/c86c2739d4d8197d607aa7ebe6aa466bcf0a3dbf))
* **transport:** support enterprise TLS roots ([1541eea](https://github.com/TeamCadenceAI/cadence-cli/commit/1541eeab0201ae40b3ad09fe9e8d02e40c58cdf0))
* **transport:** support enterprise TLS roots ([fa3e5a7](https://github.com/TeamCadenceAI/cadence-cli/commit/fa3e5a7377454ed59bf22a4fb713f5707a175eea))

## [2.1.2](https://github.com/TeamCadenceAI/cadence-cli/compare/v2.1.1...v2.1.2) (2026-03-24)


### Bug Fixes

* **publication:** stop republishing sessions for head-only changes ([8686853](https://github.com/TeamCadenceAI/cadence-cli/commit/86868532bebfdf7fd9d55ec8308930972fb6adb4))
* **publication:** stop republishing sessions for head-only changes ([22975e2](https://github.com/TeamCadenceAI/cadence-cli/commit/22975e2cef131fb20c496a3b4aaaa3d85463142c))

## [2.1.1](https://github.com/TeamCadenceAI/cadence-cli/compare/v2.1.0...v2.1.1) (2026-03-23)


### Bug Fixes

* **login:** improve auth failure diagnostics ([a7ccbd2](https://github.com/TeamCadenceAI/cadence-cli/commit/a7ccbd23be974d4a26ff7cbcd81349a6ecdaa689))
* **login:** improve auth failure diagnostics ([89f5c99](https://github.com/TeamCadenceAI/cadence-cli/commit/89f5c999699bbcb11a93d48f32df977ec00c5c38))

## [2.1.0](https://github.com/TeamCadenceAI/cadence-cli/compare/v2.0.6...v2.1.0) (2026-03-23)


### Features

* **cli:** add `cadence uninstall` command ([0871d60](https://github.com/TeamCadenceAI/cadence-cli/commit/0871d608c09736b9730e7e2ffc1b5fad0b49dfc1))
* **cli:** add cadence uninstall command ([64fd9f9](https://github.com/TeamCadenceAI/cadence-cli/commit/64fd9f99abadcd04b1291dca2bd8210cd2132a8a))
* **install:** support org-scoped installation via curl ([398ade4](https://github.com/TeamCadenceAI/cadence-cli/commit/398ade4f4f7ccda47d007fe869dfa10d9679fec8))
* **install:** support org-scoped installation via curl ([137eaf8](https://github.com/TeamCadenceAI/cadence-cli/commit/137eaf8bc79eab567ccbf839b1472f45c41834ed))
* **publication:** cut CLI uploads over to v2 session publications ([f6433e0](https://github.com/TeamCadenceAI/cadence-cli/commit/f6433e0d1325df9bfa05e4ac1d30e97797cfa933))
* V2 publishing ([312343b](https://github.com/TeamCadenceAI/cadence-cli/commit/312343b6b3ec38746a100febccb1edd3a5938116))


### Bug Fixes

* **publication:** refresh queued uploads and preserve cross-platform state writes ([580249d](https://github.com/TeamCadenceAI/cadence-cli/commit/580249dab25b97d88f18b803f2a4324a7408d8c4))
* **upload:** address Copilot publication review findings ([77c837c](https://github.com/TeamCadenceAI/cadence-cli/commit/77c837c15ccf505595414d4d2172c3f80b5f51f0))

## [2.0.6](https://github.com/TeamCadenceAI/cadence-cli/compare/v2.0.5...v2.0.6) (2026-03-18)


### Bug Fixes

* **backfill:** recover Claude metadata from log paths ([d512d09](https://github.com/TeamCadenceAI/cadence-cli/commit/d512d097e9847289d3f1d546e9cee4beeeeafc2a))
* **cursor:** ignore MCP metadata in project scans ([60dc3fe](https://github.com/TeamCadenceAI/cadence-cli/commit/60dc3febb3b706b44100bbfdcce66440535c6f01))
* **scanner:** make Claude path recovery Windows-safe ([be70c3f](https://github.com/TeamCadenceAI/cadence-cli/commit/be70c3f658b115611e0ce69733bcf4bd74a93d00))
* **scanner:** support Windows-safe Claude project names ([546cafa](https://github.com/TeamCadenceAI/cadence-cli/commit/546cafae2790021730feb1e257a3c84c762e62cf))

## [2.0.5](https://github.com/TeamCadenceAI/cadence-cli/compare/v2.0.4...v2.0.5) (2026-03-18)


### Bug Fixes

* Uploading reliability + debugging improvements ([5344ad5](https://github.com/TeamCadenceAI/cadence-cli/commit/5344ad5e34545b6ed2707fc927f4fdcadbe852e2))
* **upload:** normalize Windows test worktree paths ([dbd7046](https://github.com/TeamCadenceAI/cadence-cli/commit/dbd70469e0bfae0906116234f494c897d648f321))
* **upload:** preserve pending replay across merge updates ([fc6b6f3](https://github.com/TeamCadenceAI/cadence-cli/commit/fc6b6f333c101b11ba9a298c0997800bf79ba37b))

## [2.0.4](https://github.com/TeamCadenceAI/cadence-cli/compare/v2.0.3...v2.0.4) (2026-03-17)


### Bug Fixes

* **auth:** stop storing CLI tokens in OS keychain ([dd263f1](https://github.com/TeamCadenceAI/cadence-cli/commit/dd263f1ff775242e4edb25b456b26d1dc05bfd41))
* **auth:** stop storing CLI tokens in OS keychain ([8ea1eda](https://github.com/TeamCadenceAI/cadence-cli/commit/8ea1edad245fb944a57e5b2f655080180102f6d0))

## [2.0.3](https://github.com/TeamCadenceAI/cadence-cli/compare/v2.0.2...v2.0.3) (2026-03-17)


### Bug Fixes

* **upload:** scale presigned upload timeout for large payloads ([72b9fd0](https://github.com/TeamCadenceAI/cadence-cli/commit/72b9fd02117f80105adec8aad559659f4f2c4fab))
* **upload:** scale presigned upload timeout for large payloads ([baeba2c](https://github.com/TeamCadenceAI/cadence-cli/commit/baeba2cef700390a2d593b104333d04ddfa61fab))

## [2.0.2](https://github.com/TeamCadenceAI/cadence-cli/compare/v2.0.1...v2.0.2) (2026-03-17)


### Bug Fixes

* **upload:** increase presigned upload timeout from 60s to 5 minutes ([9e6dcc2](https://github.com/TeamCadenceAI/cadence-cli/commit/9e6dcc2c75404c108d6f4cdd70c6ddeaf717486a))
* **upload:** increase presigned upload timeout to 5 minutes ([68e3588](https://github.com/TeamCadenceAI/cadence-cli/commit/68e3588262a7c2cc2920a0e9e1b95374ed3c88ce))

## [2.0.1](https://github.com/TeamCadenceAI/cadence-cli/compare/v2.0.0...v2.0.1) (2026-03-17)


### Bug Fixes

* **update:** refresh git hooks after self-update ([fc79ce7](https://github.com/TeamCadenceAI/cadence-cli/commit/fc79ce78d045547aab690d090242e3326aea3064))

## [2.0.0](https://github.com/TeamCadenceAI/cadence-cli/compare/v1.3.0...v2.0.0) (2026-03-16)


### ⚠ BREAKING CHANGES

* removes the git-ref sync, pre-push hook, keys, sessions, and gc flows. Session ingestion now uses direct post-commit uploads with a local retry queue.

### Features

* **auto-update:** add phase 2 trust and control UX ([b63a1ed](https://github.com/TeamCadenceAI/cadence-cli/commit/b63a1ed8c192e937b52a7de31f99909824367ec6))
* remove legacy session-ref pipeline leftovers ([37f03e5](https://github.com/TeamCadenceAI/cadence-cli/commit/37f03e583b5ce905486770e2654772dfa22d4680))
* unattended auto-update with trust/control UX (Phase 1 + 2) ([f3cb63e](https://github.com/TeamCadenceAI/cadence-cli/commit/f3cb63e34770137c94b7ba1c3b582c859ad0c6d2))
* **update:** implement unattended hook-safe background auto-update v1 ([815fc22](https://github.com/TeamCadenceAI/cadence-cli/commit/815fc225f77ec39fc9350c668476eeee93c8acd7))
* **upload:** replace git-ref sync with direct session uploads ([997dc07](https://github.com/TeamCadenceAI/cadence-cli/commit/997dc07461e4089a8cc83ebe3d50d7efb2be7d83))
* **upload:** replace git-ref sync with direct session uploads ([e411236](https://github.com/TeamCadenceAI/cadence-cli/commit/e411236db50d33aa704bca314d1f5f3a204a80f5))


### Bug Fixes

* **install:** default auto-update on during FTUE ([e79e877](https://github.com/TeamCadenceAI/cadence-cli/commit/e79e877b2c4a37728303a94120afc610b1649931))
* **install:** default auto-update on during FTUE ([d348d43](https://github.com/TeamCadenceAI/cadence-cli/commit/d348d4306d48943b3dc2cc5e00bcfdc4f3884449))
* **note:** remove misleading session envelope metadata ([62eda71](https://github.com/TeamCadenceAI/cadence-cli/commit/62eda713eff43a20868aa96dce87d66ae487fc9d))
* **note:** remove unused session matching metadata ([0b84901](https://github.com/TeamCadenceAI/cadence-cli/commit/0b849017b67260677730c12872bd6641b104bd71))
* **note:** stop writing misleading session fields ([567dcc6](https://github.com/TeamCadenceAI/cadence-cli/commit/567dcc639c20a6d95e51d82deed4115882ead80e))
* **update:** address PR review feedback ([f39f41a](https://github.com/TeamCadenceAI/cadence-cli/commit/f39f41a70a7493289565c5237456f2a65cdd27aa))
* **update:** repair windows activity-lock build ([9ac6c2c](https://github.com/TeamCadenceAI/cadence-cli/commit/9ac6c2c0937d967cf7e769b6f268f6a63419bdfa))
* **update:** use portable windows sync access mask ([062f87b](https://github.com/TeamCadenceAI/cadence-cli/commit/062f87bab4e3d34d5afc8805a231efc3c6d18186))
* **upload:** harden pending retry and hook throughput ([6cb948b](https://github.com/TeamCadenceAI/cadence-cli/commit/6cb948b6cc51da1c8db62202cc0d409a89a8131d))
* **upload:** preserve direct-upload retries ([9475d17](https://github.com/TeamCadenceAI/cadence-cli/commit/9475d17c512247598f5d8b32c9c52fd1ed57fcda))

## [1.3.0](https://github.com/TeamCadenceAI/cadence-cli/compare/v1.2.0...v1.3.0) (2026-03-08)


### Features

* **sync:** notify Cadence API after deferred session-ref push ([1e0e74f](https://github.com/TeamCadenceAI/cadence-cli/commit/1e0e74f4d7f71aef5c4accf4bd82bc17af4a4adc))
* **sync:** notify session-ref pushes and require auth for server hook ([b035681](https://github.com/TeamCadenceAI/cadence-cli/commit/b035681359b47bdacdae3018a876574e2a7218a3))


### Bug Fixes

* **sync:** require auth token for session-ref push notification ([cc2250c](https://github.com/TeamCadenceAI/cadence-cli/commit/cc2250cdbb29f29ebc36b920dc1a887c98259591))

## [1.2.0](https://github.com/TeamCadenceAI/cadence-cli/compare/v1.1.1...v1.2.0) (2026-03-07)


### Features

* add git identity fields to SessionRecord for server-side attribution ([0dce9b7](https://github.com/TeamCadenceAI/cadence-cli/commit/0dce9b775e69b524d9829c4e96b6843cff09ffff))
* **note:** add git_user_email and git_user_name, remove touched_paths ([e759e08](https://github.com/TeamCadenceAI/cadence-cli/commit/e759e08110888b21db0feb20fe9534444e8d743f))

## [1.1.1](https://github.com/TeamCadenceAI/cadence-cli/compare/v1.1.0...v1.1.1) (2026-03-06)


### Bug Fixes

* **backfill:** log repo_push_failed when session ref push errors ([3268234](https://github.com/TeamCadenceAI/cadence-cli/commit/3268234e1635eca85ba605fd10c7af38c539c4d3))
* **backfill:** log repo_push_failed when session ref push errors ([89ad10a](https://github.com/TeamCadenceAI/cadence-cli/commit/89ad10a49c368962d9ac72ce77aa50cae86e0b21))

## [1.1.0](https://github.com/TeamCadenceAI/cadence-cli/compare/v1.0.0...v1.1.0) (2026-03-06)


### Features

* **agents:** add Cline, Roo Code, OpenCode, Kiro, and Amp Code session discovery ([ee310a4](https://github.com/TeamCadenceAI/cadence-cli/commit/ee310a4bf2ff196dd93e4190d697b37d53993f9a))
* **agents:** add Windows API discovery for windsurf and antigravity ([f56f315](https://github.com/TeamCadenceAI/cadence-cli/commit/f56f315ff4662687c2e9e8b8408ff67e623d7912))
* **agents:** add windsurf API session ingestion and backfill attachment support ([79e8282](https://github.com/TeamCadenceAI/cadence-cli/commit/79e8282d600e6853f2ba97f0ab4361d568f3d595))
* **api:** send CLI version header on Cadence requests ([0b1cc24](https://github.com/TeamCadenceAI/cadence-cli/commit/0b1cc24a26f4cddb5aad48b3bee2ff2f0342ba3a))
* Cline, RooCode, OpenCode, Kiro and Amp Code ([9902d5d](https://github.com/TeamCadenceAI/cadence-cli/commit/9902d5d1856f4aca53eeb287b572f90cf5ca89ce))
* Windsurf support ([df4b338](https://github.com/TeamCadenceAI/cadence-cli/commit/df4b3383079305fa32bb4c2b3e5f6d41c5b9310c))


### Bug Fixes

* Add CLI version header + defer sync improvements ([0e5d1ad](https://github.com/TeamCadenceAI/cadence-cli/commit/0e5d1adab2d1fce722c2257d221ed6673da7b7b5))
* **agents:** harden windsurf and antigravity API discovery ([f1900c7](https://github.com/TeamCadenceAI/cadence-cli/commit/f1900c754de561e0fc0ae1f8d75321d2693a30df))
* **agents:** isolate app config paths from host env in rooted discovery ([45cce55](https://github.com/TeamCadenceAI/cadence-cli/commit/45cce558166508e70c1445845f97c3c8b9fb9542))
* **opencode:** use file mtime fallback for untimestamped sessions ([e367c9b](https://github.com/TeamCadenceAI/cadence-cli/commit/e367c9bf508216d053383d00da0ed1e638f0f4db))
* **scanner:** harden agent/cwd discovery and dedupe dir scans ([4048d23](https://github.com/TeamCadenceAI/cadence-cli/commit/4048d2331dfd2c646a575e1a3594949b82d48eb0))
* **sync:** bound deferred ingest to runnable pending jobs ([956b670](https://github.com/TeamCadenceAI/cadence-cli/commit/956b670a8a18e8dcf30fc626126f66bfe9432569))
* **sync:** set deferred sync timeout to 120 seconds ([22b98b3](https://github.com/TeamCadenceAI/cadence-cli/commit/22b98b33aea57dd153915e5f0aa1e8f0c22195ab))
* **windsurf:** preserve cached API logs and classify non-macOS paths ([a5d544a](https://github.com/TeamCadenceAI/cadence-cli/commit/a5d544a5ab5d58e5e132ed19138bd645c40ebca0))

## [1.0.0](https://github.com/TeamCadenceAI/cadence-cli/compare/v0.10.0...v1.0.0) (2026-03-04)


## [0.10.0](https://github.com/TeamCadenceAI/cadence-cli/compare/v0.9.0...v0.10.0) (2026-03-04)


### Features

* Add Warp support ([681f666](https://github.com/TeamCadenceAI/cadence-cli/commit/681f6665eb19049cb0e2385d7f40fd422e8364f1)), closes [#41](https://github.com/TeamCadenceAI/cadence-cli/issues/41)
* **login:** add Cadence branding to OAuth callback success/error screen ([c33b12f](https://github.com/TeamCadenceAI/cadence-cli/commit/c33b12fe6c0e67e599d56963ea2072a315c2825b))
* **sync:** add deferred non-blocking cadence sync worker ([691fed1](https://github.com/TeamCadenceAI/cadence-cli/commit/691fed1f4ac44d8f7aebdde5663b0176daeb7a55))
* **sync:** add detailed per-ref deferred sync tracing ([1a07b60](https://github.com/TeamCadenceAI/cadence-cli/commit/1a07b6070825d1c6fbab53d056a4f63d056e1751))
* Warp support ([f039ac0](https://github.com/TeamCadenceAI/cadence-cli/commit/f039ac005affffd4e2917ea8147153a973b9abaa))


### Bug Fixes

* Deferred sync, performance improvements and discovery logging ([6a4e29c](https://github.com/TeamCadenceAI/cadence-cli/commit/6a4e29c80b6c532fbf464968a16f5650205783de))
* **merge:** resolve conflicts with main ([7c7e300](https://github.com/TeamCadenceAI/cadence-cli/commit/7c7e3008047f99fac73b0e27e8a21c26aca50631))
* **sync:** avoid temp-file collisions in atomic queue writes ([9f2de13](https://github.com/TeamCadenceAI/cadence-cli/commit/9f2de13a6f6c70b41d83533e9d414f46f309a7d2))
* **sync:** capture full deferred-sync tracing in log files ([a2ba111](https://github.com/TeamCadenceAI/cadence-cli/commit/a2ba111ff8d903cd6a51810056097daace5620c7))
* **sync:** harden deferred sync execution and ref sync safety ([7e3373e](https://github.com/TeamCadenceAI/cadence-cli/commit/7e3373eb4315259b7efff0cb6e0ea6f7e0353d2e))
* **warp:** include task-only sessions and preserve envelope meta events ([fe6314a](https://github.com/TeamCadenceAI/cadence-cli/commit/fe6314ade5399bef0f061e0e182569d642018d1f))


### Performance Improvements

* **hooks:** optimize ingest discovery and ref sync hot paths ([8334808](https://github.com/TeamCadenceAI/cadence-cli/commit/8334808959143b25d5f7ef6a1fae12e5d7fb0a44))

## [0.9.0](https://github.com/TeamCadenceAI/cadence-cli/compare/v0.8.1...v0.9.0) (2026-03-03)


### Features

* Branch/committer session storage ([7cdc164](https://github.com/TeamCadenceAI/cadence-cli/commit/7cdc16415579d68bdd65b6ab1331938d64d22494))
* **hooks:** show cadence spinner/check status for session sync ([f162591](https://github.com/TeamCadenceAI/cadence-cli/commit/f16259105ce626a2e0b3e8a21189291ed44d1e64))
* refactor keychain operations to use async functions and update dependencies ([41a847a](https://github.com/TeamCadenceAI/cadence-cli/commit/41a847a2e4b5e1598bf761e6b6071dcf43a7d0a6))
* **storage:** migrate legacy ai-session ref to canonical session ref ([68e8a97](https://github.com/TeamCadenceAI/cadence-cli/commit/68e8a97d5e8799f321f0e3fe285a9345f1d3720d))
* **sync-cursors:** implement persistent index-ingest cursors ([b21bf60](https://github.com/TeamCadenceAI/cadence-cli/commit/b21bf6070af3081f59e5ff23d7d37a50761d8fbb))


### Bug Fixes

* **backfill:** treat existing notes as skipped during backfill ([f30f2a5](https://github.com/TeamCadenceAI/cadence-cli/commit/f30f2a5dc9e1ce0ebdb998a081b5e685ec033a36))
* **decrypt:** improve error context for private key parsing ([b14b68b](https://github.com/TeamCadenceAI/cadence-cli/commit/b14b68b55a3725abd0a1125bce764d79d20e2f7c))
* Fix GC not GCing all refs ([bbc337d](https://github.com/TeamCadenceAI/cadence-cli/commit/bbc337d3f348eb63620a5f08e4f35048cafd2435))
* **hook:** add newline for better readability in spinner output ([62d1e8c](https://github.com/TeamCadenceAI/cadence-cli/commit/62d1e8c7e80acc98b5c9af639187d5c52d389083))
* **sync:** harden cursor I/O and async traversal behavior ([b24834d](https://github.com/TeamCadenceAI/cadence-cli/commit/b24834d368065fe53a99956e463eae270f905322))
* **sync:** preserve index entries during ref merges and align post-commit branch indexing ([9fd3fe4](https://github.com/TeamCadenceAI/cadence-cli/commit/9fd3fe4d1c3e91be3233c24614561f3146d2cf21))

## [0.8.1](https://github.com/TeamCadenceAI/cadence-cli/compare/v0.8.0...v0.8.1) (2026-03-01)


### Bug Fixes

* **backfill:** add per-run diagnostic JSONL logs ([66884a0](https://github.com/TeamCadenceAI/cadence-cli/commit/66884a0fe24476168992322683b84b3ff80d94f4))

## [0.8.0](https://github.com/TeamCadenceAI/cadence-cli/compare/v0.7.0...v0.8.0) (2026-02-27)


### Features

* **matching:** unify commit/session matching across attach paths ([2a6a2db](https://github.com/TeamCadenceAI/cadence-cli/commit/2a6a2db256fcdce9c651d51a914c6086a1acbd9b))


### Bug Fixes

* **backfill:** recover codex/zed commits when session window is narrow ([3e48243](https://github.com/TeamCadenceAI/cadence-cli/commit/3e4824325a64cd831e808605bc23ac5794d00bae))
* **retry:** prefix retry-attach log lines with cadence label ([a9acc97](https://github.com/TeamCadenceAI/cadence-cli/commit/a9acc972e3e44c7264dd2ed736ac25fed6e86957))
* **scanner:** lower default match thresholds to favor overmatching ([0226146](https://github.com/TeamCadenceAI/cadence-cli/commit/0226146a4945164e341ecfe339514290651fcb3d))
* **update:** avoid nested Tokio runtime panic ([4b33d2d](https://github.com/TeamCadenceAI/cadence-cli/commit/4b33d2d470a48ae639752552ee13ba9b7071a5e9))

## [0.7.0](https://github.com/TeamCadenceAI/cadence-cli/compare/v0.6.1...v0.7.0) (2026-02-27)


### Features

* **backfill:** migrate runtime to tokio and parallelize repository processing ([f8bcf48](https://github.com/TeamCadenceAI/cadence-cli/commit/f8bcf4842a8252c67ce9e1a6cf45745e76c9a26d))
* **push:** speed up notes and payload ref synchronization ([1d61e39](https://github.com/TeamCadenceAI/cadence-cli/commit/1d61e3960e5a4c61e5ed86be68914da2b55055ba))
* **scanner:** add ranked multi-signal session-to-commit matching ([f1e5019](https://github.com/TeamCadenceAI/cadence-cli/commit/f1e50192535809c06df04146b5a31a900521faab))


### Bug Fixes

* **backfill:** streamline progress output and quiet push sync ([eea868b](https://github.com/TeamCadenceAI/cadence-cli/commit/eea868bff346822abd528352687ce45e531a0481))
* **ci:** disable fail-fast test execution and stabilize windows scanner fixture ([ba83d69](https://github.com/TeamCadenceAI/cadence-cli/commit/ba83d69e2a6a6ff404ae3aef50c97102dad2d6ff))
* **runtime:** avoid nested Tokio block_on panic during install ([1a7e491](https://github.com/TeamCadenceAI/cadence-cli/commit/1a7e4911155d7250af4d3050ce4018a38671209a))


### Performance Improvements

* Push performance, Tokio runtime ([236c707](https://github.com/TeamCadenceAI/cadence-cli/commit/236c70738e8e191023b7d6eca9f8ce14f1cf7f66))
* **scanner:** reduce matcher overhead in hook and hydrate ([4422def](https://github.com/TeamCadenceAI/cadence-cli/commit/4422def9b17ee502257785400585ebb0b95fbe07))

## [0.6.1](https://github.com/TeamCadenceAI/cadence-cli/compare/v0.6.0...v0.6.1) (2026-02-25)


### Bug Fixes

* polish install and backfill CLI output formatting ([5906d96](https://github.com/TeamCadenceAI/cadence-cli/commit/5906d96e8fad742c0d792599cf9bf93740db3b75))
* polish install and backfill CLI output formatting ([d93a8cb](https://github.com/TeamCadenceAI/cadence-cli/commit/d93a8cbf39afa2c53fd6ecd40d4fda1340f2da8f))

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
