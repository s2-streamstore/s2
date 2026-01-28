# List available commands
default:
    @just --list

# Sync git submodules
sync:
    git submodule update --init --recursive

# Build the s2 CLI binary (includes lite subcommand)
build: sync
    cargo build --locked --release -p s2-cli

# Run clippy linter
clippy: sync
    cargo clippy --workspace --all-features --all-targets -- -D warnings --allow deprecated

# Ensure nightly toolchain is installed
_ensure-nightly:
    @rustup toolchain list | grep -q nightly || (echo "❌ Nightly toolchain required. Run: rustup toolchain install nightly" && exit 1)

# Format code with rustfmt
fmt: _ensure-nightly
    cargo +nightly fmt

# Ensure cargo-nextest is installed
_ensure-nextest:
    @cargo nextest --version > /dev/null 2>&1 || cargo install cargo-nextest

# Run tests with nextest (excludes CLI integration tests that need a server)
test: sync _ensure-nextest
    cargo nextest run --workspace --all-features -E 'not (package(s2-cli) & binary(integration))'

# Run CLI integration tests (requires s2 lite server running)
test-cli-integration: sync _ensure-nextest
    S2_ACCESS_TOKEN=test S2_ACCOUNT_ENDPOINT=http://localhost S2_BASIN_ENDPOINT=http://localhost \
    cargo nextest run -p s2-cli --test integration

# Verify Cargo.lock is up-to-date
check-locked:
    cargo metadata --locked --format-version 1 >/dev/null

# Clean build artifacts
clean:
    cargo clean

# Publish crates to crates.io (in dependency order)
publish:
    #!/usr/bin/env bash
    set -euo pipefail

    # Check for cargo credentials
    if [[ -z "${CARGO_REGISTRY_TOKEN:-}" ]] && [[ ! -f ~/.cargo/credentials.toml ]]; then
        echo "❌ No cargo credentials found. Run 'cargo login' or set CARGO_REGISTRY_TOKEN."
        exit 1
    fi

    # Verify clean working directory
    if ! git diff-index --quiet HEAD --; then
        echo "❌ Working directory not clean. Commit or stash changes first."
        exit 1
    fi

    # Verify on main branch
    if [[ "$(git rev-parse --abbrev-ref HEAD)" != "main" ]]; then
        echo "❌ Publish must be run from main branch."
        exit 1
    fi

    # Verify lockfile is up-to-date
    just check-locked

    echo "Publishing crates to crates.io..."

    echo "→ Publishing s2-common"
    cargo publish -p s2-common

    echo "Waiting for crates.io to index..."
    sleep 15

    echo "→ Publishing s2-api"
    cargo publish -p s2-api

    echo "Waiting for crates.io to index..."
    sleep 15

    echo "→ Publishing s2-lite"
    cargo publish -p s2-lite

    echo "Waiting for crates.io to index..."
    sleep 15

    echo "→ Publishing s2-cli"
    cargo publish -p s2-cli

    echo "✓ All crates published successfully"

# Run s2 lite server (in-memory)
serve:
    cargo run --release -p s2-cli -- lite

# Full release: bump version, commit, push, and trigger release workflow
# NOTE: Prefer using release-plz workflow (merge to main, then merge the release PR)
release VERSION:
    #!/usr/bin/env bash
    set -euo pipefail

    # Validate version format
    if ! [[ "{{VERSION}}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "❌ Invalid version format. Use semver: X.Y.Z"
        exit 1
    fi

    # Must be on main branch
    BRANCH=$(git rev-parse --abbrev-ref HEAD)
    if [[ "$BRANCH" != "main" ]]; then
        echo "❌ Must be on main branch (currently on: $BRANCH)"
        exit 1
    fi

    # Check for clean working directory
    if ! git diff --quiet || ! git diff --cached --quiet; then
        echo "❌ Working directory not clean. Commit or stash changes first."
        exit 1
    fi

    # Pull latest
    git pull --ff-only

    echo "📦 Releasing version {{VERSION}}..."

    # Bump version in workspace Cargo.toml
    sed -i '' 's/^version = "[^"]*"/version = "{{VERSION}}"/' Cargo.toml

    # Update Cargo.lock
    cargo generate-lockfile

    # Commit and push
    git add Cargo.toml Cargo.lock
    git commit -m "chore: release v{{VERSION}}"
    git push

    # Tag and trigger release workflow (handles crates.io, binaries, Docker, Homebrew)
    just tag {{VERSION}}

# Create and push a release tag, then trigger release workflow
tag TAG:
    #!/usr/bin/env bash
    set -euo pipefail

    # Validate version format
    if ! [[ "{{TAG}}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "❌ Invalid version format. Use semver: X.Y.Z"
        exit 1
    fi

    # Verify clean working directory
    if ! git diff-index --quiet HEAD --; then
        echo "❌ Working directory not clean. Commit or stash changes first."
        exit 1
    fi

    # Verify on main branch
    if [[ "$(git rev-parse --abbrev-ref HEAD)" != "main" ]]; then
        echo "❌ Releases must be tagged from main branch."
        exit 1
    fi

    # Verify lockfile is up-to-date
    just check-locked

    echo "Creating release tag: v{{TAG}}"
    git tag "v{{TAG}}"
    git push origin "v{{TAG}}"
    echo "✓ Tag v{{TAG}} created and pushed"

    echo "Triggering release workflow for binary builds, Docker, and Homebrew..."
    gh workflow run release.yml
    echo "✓ Release workflow triggered - monitor with: gh run list --workflow=release.yml"
