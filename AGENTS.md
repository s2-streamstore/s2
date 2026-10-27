## Local Conventions

- Formatting: run `just fmt`
- Tests: run `just test`
- PR title + description become the squashed commit message at merge time; use conventional commit format

## Cargo Dependency Safety

- Use `--locked` for Cargo commands that build, check, test, run, document, fetch, or read metadata.
- The simulator is temporarily exempt until its separate lockfile is regenerated.
- Use `cargo +nightly add`, `cargo +nightly update`, `cargo +nightly remove`, or `cargo +nightly generate-lockfile` for dependency changes. The repository Cargo configuration applies the publication cooldown.
- Do not use the stable forms of these dependency commands.
- Do not edit dependency declarations or `Cargo.lock` directly.
- Do not install Cargo tools as part of a coding task.
