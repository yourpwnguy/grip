# Grip — Development Tasks
# https://just.systems

# List available commands
default:
    @just --list

# ── Build ────────────────────────────────────────────────────────────────────

# Build in debug mode
build:
    cargo build

# Build optimized release binary
release:
    cargo build --release

# ── Quality ──────────────────────────────────────────────────────────────────

# Run all checks (tests, clippy, formatting)
check: test clippy fmt-check

# Run tests
test:
    cargo test

# Run tests with output
test-verbose:
    cargo test -- --nocapture

# Run clippy lints
clippy:
    cargo clippy --lib -- -D warnings

# Check formatting
fmt-check:
    cargo fmt --check

# Auto-format code
fmt:
    cargo fmt

# ── Clean ────────────────────────────────────────────────────────────────────

# Remove build artifacts
clean:
    cargo clean

# ── Benchmarks ───────────────────────────────────────────────────────────────

# Run benchmarks
bench:
    cargo bench

# ── Documentation ────────────────────────────────────────────────────────────

# Open documentation in browser
docs:
    cargo doc --open

# Build documentation (check for warnings)
docs-check:
    RUSTDOCFLAGS="-D warnings" cargo doc --no-deps

# ── Installation ─────────────────────────────────────────────────────────────

# Install locally
install:
    cargo install --path .

# Fingerprint a host
run:
    cargo run -- example.com

# Fingerprint with JSON output
run-json:
    cargo run -- --format json example.com

# Analyze a pcap file
run-pcap:
    cargo run -- --pcap capture.pcap

# ── Fingerprint DB ───────────────────────────────────────────────────────

# Refresh assets/fingerprints.csv from FoxIO's ja4plus-mapping (then rebuild)
update-db:
    python3 scripts/import_ja4_mapping.py

# ── Misc ─────────────────────────────────────────────────────────────────────

# Show project statistics
stats:
    @echo "Lines of code:"
    @find src -name '*.rs' -exec cat {} + | wc -l
    @echo ""
    @echo "File sizes:"
    @find src -name '*.rs' -exec wc -l {} + | sort -rn | head -10
    @echo ""
    @echo "Test count:"
    @cargo test 2>&1 | grep -E "^test result:" | head -1
