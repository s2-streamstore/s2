---
name: release
description: Release a new version of the project
---

# /release

Release a new version of the project.

## Usage

```
/release [version]
```

If version is not provided, prompt the user for it.

## Steps

1. **Validate version** - should be semver (X.Y.Z) and greater than current

2. **Run release**
   ```bash
   just release X.Y.Z
   ```

This handles: cargo credentials check, version bump in Cargo.toml (3 places), lockfile update, commit, push, crates.io publish, and git tag.

## Notes

- Must be on `main` branch with clean working directory
- Requires cargo credentials (`cargo login` or `CARGO_REGISTRY_TOKEN`)
- If any step fails, stop and report the error
- The git tag triggers GitHub Actions to build Docker images and create the GitHub release
