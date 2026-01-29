---
name: release
description: Release a new version of the project
---

# /release

Release a new version of the project.

## How releases work

This project uses [release-plz](https://release-plz.dev/) for automated releases. Version is determined by conventional commits (`fix:` → patch, `feat:` → minor, `feat!:` → major).

## Usage

```
/release
```

## Steps

1. **Find the release PR**
   ```bash
   gh pr list --label release --state open
   ```

2. **Get commits since last release**
   ```bash
   git fetch --tags
   git log $(git describe --tags --abbrev=0)..HEAD --oneline
   ```

3. **Verify changelog reflects all commits**
   - Fetch the PR diff to see the changelog updates:
     ```bash
     gh pr diff <PR_NUMBER> -- CHANGELOG.md
     ```
   - Compare with the commit list from step 2
   - Flag any missing commits that should be in the changelog
   - Conventional commits (`feat:`, `fix:`, `docs:`, etc.) should be included
   - Commits prefixed with `chore:` may be excluded (expected)

4. **If discrepancies found**
   - The release-plz action may not have run, trigger it:
     ```bash
     gh workflow run release-plz.yml
     ```
   - Or manually note the missing items for the user

5. **Dry run before merging**
   ```bash
   cargo publish -p s2-cli --dry-run
   cargo publish -p s2-lite --dry-run
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

- Check workflow status: `gh run list --workflow=release.yml`
- To override version: edit `Cargo.toml` in the PR before merging
