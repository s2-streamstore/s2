## Local Conventions

- Formatting: run `cargo +nightly fmt` or `just fmt`
- Tests: prefer `cargo nextest` or `just test`

## Release Process

1. Switch to main and pull latest:
   ```bash
   git checkout main && git pull
   ```

2. Bump version in root `Cargo.toml` (updates `workspace.package.version` and workspace deps):
   ```bash
   # Edit Cargo.toml: change version = "X.Y.Z" in all 3 places
   cargo generate-lockfile
   git add Cargo.toml Cargo.lock
   git commit -m "release: X.Y.Z"
   git push
   ```

3. Publish to crates.io:
   ```bash
   just publish
   ```

4. Tag and trigger release workflow:
   ```bash
   just tag X.Y.Z
   ```

This builds multi-arch Docker images and creates a GitHub release automatically.
