# List available commands
default:
    @just --list

# Sync git submodules
sync:
    git submodule update --init --recursive

# Build the s2-lite server binary
build: sync
    cargo build --locked --release -p s2-lite

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

# Run tests with nextest
test: sync _ensure-nextest
    cargo nextest run --workspace --all-features

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

    echo "✓ All crates published successfully"

# Full release: bump version, publish to crates.io, tag, push
release VERSION:
    #!/usr/bin/env bash
    set -euo pipefail

    # Validate version format
    if ! [[ "{{VERSION}}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "❌ Invalid version format. Use semver: X.Y.Z"
        exit 1
    fi

    # Check for cargo credentials early (fail fast)
    if [[ -z "${CARGO_REGISTRY_TOKEN:-}" ]] && [[ ! -f ~/.cargo/credentials.toml ]]; then
        echo "❌ No cargo credentials found. Run 'cargo login' or set CARGO_REGISTRY_TOKEN."
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

    # Bump version in all 3 places in Cargo.toml
    sed -i '' 's/^version = "[^"]*"/version = "{{VERSION}}"/' Cargo.toml
    sed -i '' 's/s2-api = { version = "[^"]*"/s2-api = { version = "{{VERSION}}"/' Cargo.toml
    sed -i '' 's/s2-common = { version = "[^"]*"/s2-common = { version = "{{VERSION}}"/' Cargo.toml

    # Update Cargo.lock
    cargo generate-lockfile

    # Commit and push
    git add Cargo.toml Cargo.lock
    git commit -m "release: {{VERSION}}"
    git push

    # Publish to crates.io
    just publish

    # Tag and trigger release workflow
    just tag {{VERSION}}

# Create and push a release tag
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

    echo "Creating release tag: {{TAG}}"
    git tag "{{TAG}}"
    git push origin "{{TAG}}"
    echo "✓ Tag {{TAG}} created and pushed - release workflow will start"
