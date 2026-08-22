## Local Conventions

- Formatting: run `just fmt`
- Tests: run `just test`
- PR title + description become the squashed commit message at merge time; use conventional commit format

## Cargo Dependency Safety

- Use `--locked` for Cargo commands that build, check, test, run, document, fetch, or read metadata.
- Do not run `cargo add`, `cargo update`, `cargo remove`, `cargo generate-lockfile`, or `cargo install` directly.
- Do not edit dependency declarations or `Cargo.lock` directly.
- Use `s2-deps` for dependency changes.
- Install Cargo tools through approved developer tooling, not from source with Cargo.
