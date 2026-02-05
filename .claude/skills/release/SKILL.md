---
name: release
description: Release new versions of changed packages
---

# /release

Release new versions of changed packages.

## How releases work

This project uses [release-plz](https://release-plz.dev/) for automated releases. Version is determined by conventional commits (`fix:` → patch, `feat:` → minor, `feat!:` → major).

Each package has its own version and changelog. release-plz opens a PR only for packages with changes since their last release. `s2-cli` and `s2-lite` are in the same `version_group` (released together). `s2-api` and `s2-common` are library packages for internal use (published to crates.io but no GitHub releases).

Tags are per-package: `s2-cli-v{version}`, `s2-lite-v{version}`, `s2-api-v{version}`, `s2-common-v{version}`.

## Usage

```
/release
```

## Steps

1. **Find the release PR**
   ```bash
   gh pr list --label release --state open
   ```

2. **Identify which packages are being released**
   - Check which `Cargo.toml` files are modified in the PR:
     ```bash
     gh pr diff <PR_NUMBER> --name-only
     ```
   - Look for version bumps in `cli/Cargo.toml`, `lite/Cargo.toml`, `api/Cargo.toml`, `common/Cargo.toml`

3. **For each package being released, verify its changelog**
   - Get the PR diff and review the changelog sections:
     ```bash
     gh pr diff <PR_NUMBER>
     ```
   - Get commits since that package's last tag:
     ```bash
     git fetch --tags
     # Example for s2-cli (substitute the package name as needed):
     git log $(git tag -l 's2-cli-v*' --sort=-v:refname | head -1)..origin/main --oneline
     ```
   - Compare the changelog entries with the commit list
   - Conventional commits (`feat:`, `fix:`, `docs:`, etc.) should be included
   - Commits prefixed with `chore:` may be excluded (expected)

4. **If discrepancies found**
   - The release-plz action may not have run, trigger it:
     ```bash
     gh workflow run release-plz.yml
     ```
   - Or manually note the missing items for the user

5. **Dry run before merging** (only for packages being released)
   ```bash
   # Run only for packages with version bumps in the PR, e.g.:
   cargo publish -p <package-name> --dry-run
   ```

6. **If changelog is correct**: Merge the PR
   ```bash
   gh pr merge <PR_NUMBER> --squash
   ```

## If no release PR exists

```bash
gh workflow run release-plz.yml
```
Wait for the PR to be created, then verify and merge.

## Notes

- Check workflow status: `gh run list --workflow=release-plz.yml`
- After merge, `release-crates.yml` publishes to crates.io and creates per-package git tags
- Tags like `s2-cli-v*` or `s2-lite-v*` trigger `release-cli.yml` (builds binaries, Docker images, updates Homebrew)
- To override version: edit the relevant package's `Cargo.toml` in the PR before merging
