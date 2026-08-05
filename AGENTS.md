# Repository Guidelines

## Project Structure & Module Organization

This Rust 2024 crate builds the `mrk` CLI and library. `src/bin/mrk.rs` is the command-line entry point; `src/lib.rs` exports storage, cryptography, consensus, relay, and service modules. Keep domain behavior in `src/*.rs`, not CLI parsing code. Integration tests live in `tests/*.rs`, with relay certificates and keys in `tests/fixtures/`. Design notes belong in `docs/`, deployment examples in `deploy/`, and maintenance scripts in `scripts/`.

## Build, Test, and Development Commands

- `cargo build --release --offline` builds the optimized binary at `target/release/mrk` without network access.
- `cargo test --offline` runs unit and integration tests.
- `cargo test --offline --test relay_e2e` runs one integration-test target while iterating.
- `cargo clippy --offline --all-targets -- -D warnings` treats every Clippy warning as an error.
- `cargo fmt --all -- --check` verifies formatting; `cargo fmt --all` applies it.
- `./scripts/install.sh` builds with the lockfile and installs to `${PREFIX:-$HOME/.local}/bin`.

## Coding Style & Naming Conventions

Use rustfmt defaults (four-space indentation) and keep code Clippy-clean. Use `snake_case` for functions, modules, variables, and tests; `PascalCase` for types and traits; `SCREAMING_SNAKE_CASE` for constants. Prefer the crate's `Error` and `Result` aliases. Keep protocol transitions deterministic, and keep secrets out of arguments and logs.

## Testing Guidelines

Add focused unit tests beside small modules and cross-module or CLI scenarios under `tests/`. Name tests after behavior, for example `node_reward_transfer_and_private_network_flow`. Use unique temporary directories so tests do not touch `~/.mrk/` or share ledger state. No numeric coverage threshold is stated; cover success and relevant failure paths. Run the full offline test and Clippy suites before submitting.

## Commit & Pull Request Guidelines

Recent history follows Conventional Commit-style subjects: `feat: add relay registry discovery`, `fix: finalize epoch vesting through blocks`, and `refactor: group account and block CLI commands`. Use an imperative, scoped subject and keep each commit logically focused. Pull requests should explain the behavior change, identify protocol or persisted-state compatibility effects, link related issues, and list verification commands. Include CLI output for user-visible changes; screenshots are only useful when documentation or rendered output changes.

## Security & Configuration

Use `--data-dir` or `MRK_DATA_DIR` for isolated development state. `MRK_KEYSTORE_PASSWORD` is acceptable only for local tests; production automation should use an owner-only `MRK_KEYSTORE_PASSWORD_FILE`. Never commit real keys, credentials, ledger data, or deployment-specific certificate paths.
