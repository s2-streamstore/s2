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

# Run s2 lite server (in-memory)
serve:
    cargo run --release -p s2-cli -- lite
