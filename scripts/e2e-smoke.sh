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
