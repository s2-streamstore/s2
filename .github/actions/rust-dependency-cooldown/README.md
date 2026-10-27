# Rust dependency cooldown

This action checks newly locked crates.io versions against the caller's
`registry.global-min-publish-age` setting. S2-owned crates listed in
`first-party-crates.txt` are exempt from the publication-age check.

## Security exceptions

`security-exceptions.toml` records reviewed exceptions for individual security
releases. Each entry requires an exact crate name and version, an advisory
identifier or URL, and a reason:

```toml
[[exception]]
crate = "rustls"
version = "0.23.45"
advisory = "RUSTSEC-2026-0285"
reason = "Fixes TLS 1.3 handshake messages accepted at the wrong encryption level"
```

Review the advisory and confirm that the exact release fixes it before adding an
entry. Ranges, wildcards, duplicate entries, and malformed configuration are
rejected. The action prints the crate, version, advisory, and reason whenever it
uses an exception. The exception waives only publication age; other dependency
checks, including `cargo deny`, continue to apply.

The exception file is distributed with this action. After merging an exception,
update consuming repositories' pinned action or reusable-workflow commit to pick
it up. Future releases of the same crate still have to satisfy the cooldown.

Entries need no expiry field: an approved release follows the normal age check
once it is old enough. Old entries may be removed in a later cleanup. An empty
file or `exception = []` means there are no security exceptions.

Cargo also enforces publication age during dependency resolution. To select an
approved release, override that resolver check for the targeted update command:

```sh
CARGO_RESOLVER_INCOMPATIBLE_PUBLISH_AGE=allow cargo +nightly update -p rustls --precise 0.23.45
```

Run the cooldown action on the resulting lockfile to check every newly selected
version against the exception list and normal age requirement.

## Tests

Run from the repository root:

```sh
python3 -m unittest discover -s .github/actions/rust-dependency-cooldown -p 'test_*.py' -v
```
