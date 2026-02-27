# Contributing

Thanks for contributing to Cadence CLI.

## Development Setup

Requirements:
- Rust (stable)
- Git

Common commands:
```sh
cargo build
cargo build --release
cargo test --no-fail-fast
cargo clippy -- -D warnings
cargo fmt -- --check
```

## Code Style

- Run `cargo fmt` and `cargo clippy` before submitting.
- Keep changes small and focused.
- Add tests for new behavior or bug fixes.

## Tests

Run the full suite:
```sh
cargo test --no-fail-fast
```

Run a single test:
```sh
cargo test <test_name>
```

## Pull Requests

- Describe the change and why it matters.
- Note any platform-specific behavior.
- Include test output if relevant.

## Release Process

Releases are cut from tagged commits (for example `v0.2.1`).
GitHub Actions builds platform artifacts and attaches them to the release.
