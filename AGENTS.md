## Local Conventions

- Formatting: run `just fmt`
- Tests: run `just test`
- PR title + description become the squashed commit message at merge time; use conventional commit format

## Cargo Dependency Safety

- Use `--locked` for Cargo commands that build, check, test, run, document, fetch, or read metadata.
- Use `cargo +nightly add`, `cargo +nightly update`, `cargo +nightly remove`, or `cargo +nightly generate-lockfile` for dependency changes. The repository Cargo configuration applies the publication cooldown.
- Do not use the stable forms of these dependency commands.
- Do not edit dependency declarations or `Cargo.lock` directly.
- Do not install Cargo tools as part of a coding task.

## API Evolution

A released client must keep parsing responses from a newer service.

- `s2-api`: a response field whose enum the service may extend is `MaybeKnown<T>`. The enum itself stays closed, and conversions into `s2_common` types reject `Unknown` with `MaybeKnown::known()`.
- `s2-sdk`: the matching enum has an `Unknown(String)` variant holding the wire name, and is `#[non_exhaustive]`.
- `s2-cli`: flag enums stay closed; output prints an unknown value by its wire name.
- Enums that are only ever sent by a client stay closed.
- Returning a new value in an existing field still breaks clients released before that field was tolerant, so check which released versions parse it as closed.
