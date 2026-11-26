## Local Conventions

- Formatting: run `just fmt`
- Tests: run `just test`
- PR title + description become the squashed commit message at merge time; use conventional commit format

## Cargo Dependency Safety

- Use `--locked` for Cargo commands that build, check, test, run, document, fetch, or read metadata.
- Use `cargo +nightly add`, `cargo +nightly update`, `cargo +nightly remove`, or `cargo +nightly generate-lockfile` for dependency changes. The repository Cargo configuration applies the publication cooldown.
- Do not use the stable forms of these dependency commands.
- Avoid editing dependency declarations or `Cargo.lock` directly; if you need to, ask for explicit permission first and flag the risk.
- Do not install Cargo tools as part of a coding task.

## API Evolution

A released client must keep parsing responses from a newer service.

- `s2-api`: a response field whose enum the service may extend is `MaybeKnown<T>`. The enum itself stays closed, and conversions into `s2_common` types reject `Unknown` with `MaybeKnown::known()`.
- `s2-sdk`: the matching enum has an `Unknown(String)` variant holding the wire name, and is `#[non_exhaustive]`.
- `s2-cli`: flag enums stay closed; output prints an unknown value by its wire name.
- Enums that are only ever sent by a client stay closed.
- Returning a new value in an existing field still breaks clients released before that field was tolerant, so check which released versions parse it as closed.

## SDK Specification

`s2-sdk` conforms to the unified SDK spec in `api/specs/sdk/` (`spec.md`, `rationale.md`, `vectors/`).

- Check the spec before changing `sdk/` APIs, errors, retries, sessions, or validation; do not silently diverge from spec rules.
- Keep conformance and shared vector tests (`sdk/tests/conformance.rs`, `sdk/tests/spec/`) passing, tagging spec-governed tests with `// spec: r1 <RULE_ID>`.
- When a change reveals a spec gap, ambiguity, or cross-SDK improvement, propose an update to `s2-specs` instead of working around it in Rust.
- Land spec changes in `s2-specs` first, then bump the `api/specs` submodule.
