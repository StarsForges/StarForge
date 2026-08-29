#!/usr/bin/env bash
#
# StarForge End-to-End Smoke Test
#
# This script runs basic smoke tests to verify StarForge functionality.
# Network tests are gated behind STARFORGE_E2E=1 to allow skipping in CI.
#
# Usage:
#   ./scripts/e2e-smoke.sh              # Run without network tests
#   STARFORGE_E2E=1 ./scripts/e2e-smoke.sh  # Run with network tests
#

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Determine the starforge binary path
if [ -f "target/release/starforge" ]; then
    STARFORGE="./target/release/starforge"
elif [ -f "target/debug/starforge" ]; then
    STARFORGE="./target/debug/starforge"
elif command -v starforge &> /dev/null; then
    STARFORGE="starforge"
else
    echo -e "${RED}✗ StarForge binary not found${NC}"
    echo "  Build it with: cargo build --release"
    exit 1
fi

echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  StarForge E2E Smoke Test Suite${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
echo ""
echo "Using binary: $STARFORGE"
echo ""

# Helper function to run a test
run_test() {
    local test_name="$1"
    local test_command="$2"
    
    TESTS_RUN=$((TESTS_RUN + 1))
    echo -n "  Testing: $test_name... "
    
    if eval "$test_command" > /dev/null 2>&1; then
        echo -e "${GREEN}✓ PASS${NC}"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        echo -e "${RED}✗ FAIL${NC}"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

# Helper function to run a test with output check
run_test_with_output() {
    local test_name="$1"
    local test_command="$2"
    local expected_pattern="$3"
    
    TESTS_RUN=$((TESTS_RUN + 1))
    echo -n "  Testing: $test_name... "
    
    local output
    output=$(eval "$test_command" 2>&1)
    
    if echo "$output" | grep -q "$expected_pattern"; then
        echo -e "${GREEN}✓ PASS${NC}"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        echo -e "${RED}✗ FAIL${NC}"
        echo "    Expected pattern: $expected_pattern"
        echo "    Got: $output"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

# Cleanup function
cleanup() {
    if [ -n "$TEST_WALLET_NAME" ]; then
        echo ""
        echo -e "${YELLOW}Cleaning up test wallet...${NC}"
        # Note: Add wallet deletion command when implemented
        # $STARFORGE wallet delete "$TEST_WALLET_NAME" --yes 2>/dev/null || true
    fi
}

trap cleanup EXIT

echo -e "${BLUE}──────────────────────────────────────────────────────${NC}"
echo -e "${BLUE}1. Basic Command Tests${NC}"
echo -e "${BLUE}──────────────────────────────────────────────────────${NC}"
echo ""

# Test: starforge info
run_test "starforge info" "$STARFORGE info"

# Test: starforge --version
run_test "starforge --version" "$STARFORGE --version"

# Test: starforge --help
run_test "starforge --help" "$STARFORGE --help"

echo ""
echo -e "${BLUE}──────────────────────────────────────────────────────${NC}"
echo -e "${BLUE}2. Wallet Command Tests${NC}"
echo -e "${BLUE}──────────────────────────────────────────────────────${NC}"
echo ""

# Generate unique wallet name for testing
TEST_WALLET_NAME="smoke-test-$(date +%s)"

# Test: wallet create
run_test "wallet create" "$STARFORGE wallet create $TEST_WALLET_NAME"

# Test: wallet list
run_test_with_output "wallet list" "$STARFORGE wallet list" "$TEST_WALLET_NAME"

# Test: wallet show
run_test "wallet show" "$STARFORGE wallet show $TEST_WALLET_NAME"

echo ""
echo -e "${BLUE}──────────────────────────────────────────────────────${NC}"
echo -e "${BLUE}3. Network Command Tests${NC}"
echo -e "${BLUE}──────────────────────────────────────────────────────${NC}"
echo ""

# Test: network show
run_test "network show" "$STARFORGE network show"

# Network tests (gated behind STARFORGE_E2E=1)
if [ "$STARFORGE_E2E" = "1" ]; then
    echo ""
    echo -e "${YELLOW}Running network tests (STARFORGE_E2E=1)...${NC}"
    echo ""
    
    # Test: network test against testnet
    run_test "network test testnet" "$STARFORGE network test --network testnet"
    
    # Test: wallet fund (testnet only)
    echo -n "  Testing: wallet fund (testnet)... "
    if $STARFORGE wallet fund $TEST_WALLET_NAME --network testnet > /dev/null 2>&1; then
        echo -e "${GREEN}✓ PASS${NC}"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        TESTS_RUN=$((TESTS_RUN + 1))
        
        # Wait a moment for funding to complete
        sleep 2
        
        # Verify wallet has balance
        run_test_with_output "wallet show (funded)" "$STARFORGE wallet show $TEST_WALLET_NAME" "Balance"
    else
        echo -e "${YELLOW}⊘ SKIP (Friendbot may be unavailable)${NC}"
    fi
else
    echo -e "${YELLOW}⊘ Skipping network tests (set STARFORGE_E2E=1 to enable)${NC}"
fi

echo ""
echo -e "${BLUE}──────────────────────────────────────────────────────${NC}"
echo -e "${BLUE}4. Template Command Tests${NC}"
echo -e "${BLUE}──────────────────────────────────────────────────────${NC}"
echo ""

# Test: template list
run_test "template list" "$STARFORGE template list"

# Test: template search
run_test "template search" "$STARFORGE template search counter"

echo ""
echo -e "${BLUE}──────────────────────────────────────────────────────${NC}"
echo -e "${BLUE}5. Tutorial Command Tests${NC}"
echo -e "${BLUE}──────────────────────────────────────────────────────${NC}"
echo ""

# Test: tutorial list (no active tutorial required)
run_test "tutorial list" "$STARFORGE tutorial list"

echo ""
echo -e "${BLUE}──────────────────────────────────────────────────────${NC}"
echo -e "${BLUE}6. Other Command Tests${NC}"
echo -e "${BLUE}──────────────────────────────────────────────────────${NC}"
echo ""

# Test: completions generation
run_test "completions bash" "$STARFORGE completions bash"

echo ""
echo -e "${BLUE}──────────────────────────────────────────────────────${NC}"
echo -e "${BLUE}7. Release Command Tests${NC}"
echo -e "${BLUE}──────────────────────────────────────────────────────${NC}"
echo ""

# `starforge release` is exercised against a throwaway fixture "project"
# with a tiny placeholder binary — NOT a copy of this repo's own (100MB+
# debug) build output, which would make archiving/hashing needlessly slow.
# The fixture never touches the network — prepare/manifest/sbom/attest/verify
# are all local-file-only.
RELEASE_FIXTURE_DIR="$(mktemp -d)"
RELEASE_STAGING_DIR="$RELEASE_FIXTURE_DIR/staging"
mkdir -p "$RELEASE_FIXTURE_DIR/target/release"
echo "placeholder binary bytes for the release smoke test" > "$RELEASE_FIXTURE_DIR/target/release/fixture-app"
cat > "$RELEASE_FIXTURE_DIR/Cargo.toml" <<'EOF'
[package]
name = "fixture-app"
version = "0.0.1-smoke"
EOF
cat > "$RELEASE_FIXTURE_DIR/Cargo.lock" <<'EOF'
[[package]]
name = "fixture-app"
version = "0.0.1-smoke"
EOF
cat > "$RELEASE_FIXTURE_DIR/rust-toolchain.toml" <<'EOF'
[toolchain]
channel = "1.89.0"
EOF

RELEASE_ARGS="--repo-root $RELEASE_FIXTURE_DIR --version 0.0.1-smoke"

run_test "release prepare (--skip-build)" \
    "$STARFORGE release prepare $RELEASE_ARGS --binary-name fixture-app --target native --skip-build --out $RELEASE_STAGING_DIR --source-date-epoch 1700000000"

run_test "release manifest" \
    "$STARFORGE release manifest $RELEASE_ARGS --staging-root $RELEASE_STAGING_DIR --name fixture-app"

run_test "release sbom" \
    "$STARFORGE release sbom --repo-root $RELEASE_FIXTURE_DIR --name fixture-app --version 0.0.1-smoke --out $RELEASE_STAGING_DIR/0.0.1-smoke/sbom.json"

run_test "release attest" \
    "$STARFORGE release attest --dir $RELEASE_STAGING_DIR/0.0.1-smoke --signing-key $RELEASE_FIXTURE_DIR/signing.key --generate-key-if-missing"

run_test_with_output "release verify (passes)" \
    "$STARFORGE release verify --dir $RELEASE_STAGING_DIR/0.0.1-smoke --format json" \
    '"ok": true'

rm -rf "$RELEASE_FIXTURE_DIR"

echo ""
echo -e "${BLUE}──────────────────────────────────────────────────────${NC}"
echo -e "${BLUE}8. Notification Router Command Tests${NC}"
echo -e "${BLUE}──────────────────────────────────────────────────────${NC}"
echo ""

TEST_ROUTE_NAME="smoke-rule-$(date +%s)"

# Test: notify routes list
run_test "notify routes list" "$STARFORGE notify routes list"

# Test: notify routes add
run_test "notify routes add" \
    "$STARFORGE notify routes add --name $TEST_ROUTE_NAME --adapter stdout --event-type command_outcome --severity info --max-attempts 3"

# Test: notify routes list JSON contains added rule
run_test_with_output "notify routes list (json)" \
    "$STARFORGE notify routes list --json" \
    "$TEST_ROUTE_NAME"

# Test: notify routes test-rule
run_test "notify routes test-rule" \
    "$STARFORGE notify routes test-rule $TEST_ROUTE_NAME"

# Test: notify test matching
run_test_with_output "notify test" \
    "$STARFORGE notify test --event-type command_outcome --title 'Smoke Event' --severity info" \
    "$TEST_ROUTE_NAME"

# Test: notify events emit with process delivery
run_test_with_output "notify events emit" \
    "$STARFORGE notify events emit --event-type command_outcome --title 'Smoke Event' --severity info --process --json" \
    '"deliveries"'

# Test: notify events list
run_test "notify events list" "$STARFORGE notify events list"

# Test: notify stats
run_test "notify stats" "$STARFORGE notify stats"

# Test: notify dead-letter list
run_test "notify dead-letter list" "$STARFORGE notify dead-letter list"

# Test: notify routes remove
run_test "notify routes remove" "$STARFORGE notify routes remove $TEST_ROUTE_NAME"

echo ""
echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  Test Results${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
echo ""
echo "  Total tests run:    $TESTS_RUN"
echo -e "  ${GREEN}Tests passed:      $TESTS_PASSED${NC}"
if [ $TESTS_FAILED -gt 0 ]; then
    echo -e "  ${RED}Tests failed:      $TESTS_FAILED${NC}"
else
    echo -e "  ${GREEN}Tests failed:      $TESTS_FAILED${NC}"
fi
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ All smoke tests passed!${NC}"
    echo ""
    exit 0
else
    echo -e "${RED}✗ Some tests failed${NC}"
    echo ""
    exit 1
fi
