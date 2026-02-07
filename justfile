# List available commands
default:
    @just --list

# Sync git submodules
sync:
    git submodule update --init --recursive

# Build the s2 CLI binary (includes lite subcommand)
build *args: sync
    cargo build --locked --release -p s2-cli {{args}}

# Run clippy linter
clippy *args: sync
    cargo clippy --workspace --all-features --all-targets {{args}} -- -D warnings --allow deprecated

# Ensure cargo-deny is installed
_ensure-deny:
    @cargo deny --version > /dev/null 2>&1 || cargo install cargo-deny

# Run cargo-deny checks
deny *args: _ensure-deny
    cargo deny check {{args}}

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
test *args: sync _ensure-nextest
    cargo nextest run --workspace --all-features -E 'not (package(s2-cli) & binary(integration))' {{args}}

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

# Run s2-lite
lite *args:
    cargo run --release -p s2-cli -- lite {{args}}
