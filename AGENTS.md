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

Use Conventional Commit subjects for all changes after the initial repository import:

```text
<type>(<optional-scope>): <imperative summary>
```

Use lowercase types such as `feat`, `fix`, `refactor`, `docs`, `test`, `chore`, `build`, `ci`, or `perf`. Omit the scope when the change spans the protocol or several modules. Keep the summary concise, start it with an imperative lowercase verb, and do not end it with a period; for example, `fix: finalize IP slot lifecycle through consensus` or `feat(relay): add registry discovery`. Keep each commit logically focused. Add a body only when the motivation, protocol behavior, or compatibility impact is not clear from the subject; separate it from the subject with a blank line. The historical `Initial commit` subject is the import exception, not a template for later changes.

Preserve the repository owner's identity as both Git Author and Committer: `rkonfj <rkonfj@gmail.com>`. When Codex contributes to a commit, add `Co-authored-by: Codex <codex@openai.com>` as the final trailer paragraph after a blank line. Do not use a Codex identity, `localhost` address, or noreply address for the Author or Committer fields.

Pull requests should explain the behavior change, identify protocol or persisted-state compatibility effects, link related issues, and list verification commands. Include CLI output for user-visible changes; screenshots are only useful when documentation or rendered output changes.

## Security & Configuration

Use `--data-dir` or `MRK_DATA_DIR` for isolated development state. `MRK_KEYSTORE_PASSWORD` is acceptable only for local tests; production automation should use an owner-only `MRK_KEYSTORE_PASSWORD_FILE`. Never commit real keys, credentials, ledger data, or deployment-specific certificate paths.
