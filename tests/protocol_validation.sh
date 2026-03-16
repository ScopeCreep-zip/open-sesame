#!/usr/bin/env bash
# tests/protocol_validation.sh — End-to-end protocol validation (V-001 through V-011)
#
# Prerequisites:
#   - sesame binary in PATH
#   - Open Sesame systemd user services running (open-sesame.target)
#   - No existing sesame state (or willingness to wipe it)
#
# Usage:
#   bash tests/protocol_validation.sh
#
# Exit code 0 = all tests pass, non-zero = at least one failure.
#
# Note on password prompts:
#   sesame init / sesame unlock use dialoguer::Password which reads from /dev/tty.
#   This script uses `expect` to automate interactive password entry. Install expect
#   if not present: apt install expect / nix-shell -p expect
#
# Test password: "testpassword123" (used for all init/unlock operations)

set -euo pipefail

PASS=0
FAIL=0
TEST_PASSWORD="testpassword123"
PROFILE="default"

# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

test_result() {
    local name="$1" expected="$2" actual="$3"
    if [[ "$actual" == *"$expected"* ]]; then
        echo "PASS: $name"
        ((PASS++))
    else
        echo "FAIL: $name"
        echo "  expected substring: $expected"
        echo "  actual output: $actual"
        ((FAIL++))
    fi
}

test_result_not_contains() {
    local name="$1" unexpected="$2" actual="$3"
    if [[ "$actual" != *"$unexpected"* ]]; then
        echo "PASS: $name"
        ((PASS++))
    else
        echo "FAIL: $name"
        echo "  unexpected substring found: $unexpected"
        echo "  actual output: $actual"
        ((FAIL++))
    fi
}

check_prerequisites() {
    if ! command -v sesame &>/dev/null; then
        echo "ERROR: sesame binary not found in PATH"
        echo "Build with: cargo build -p open-sesame"
        echo "Then add to PATH or run from target/debug/"
        exit 2
    fi

    if ! command -v expect &>/dev/null; then
        echo "ERROR: expect not found in PATH"
        echo "Install with: apt install expect / nix-shell -p expect"
        exit 2
    fi
}

# Use expect to drive interactive password prompts.
sesame_init() {
    expect -c "
        set timeout 30
        spawn sesame init
        expect {
            \"*assword*\" { send \"${TEST_PASSWORD}\r\" }
            \"*already*\" { }
            timeout { exit 1 }
        }
        expect {
            \"*onfirm*\" { send \"${TEST_PASSWORD}\r\" }
            eof { }
            timeout { }
        }
        expect eof
    " 2>&1
}

sesame_unlock() {
    expect -c "
        set timeout 30
        spawn sesame unlock
        expect {
            \"*assword*\" { send \"${TEST_PASSWORD}\r\" }
            \"*already*\" { }
            timeout { exit 1 }
        }
        expect eof
    " 2>&1
}

sesame_wipe() {
    expect -c "
        set timeout 30
        spawn sesame init --wipe-reset-destroy-all-data
        expect \"*destroy*\"
        send \"destroy all data\r\"
        expect {
            \"*assword*\" { send \"${TEST_PASSWORD}\r\" }
            eof { }
            timeout { }
        }
        expect {
            \"*onfirm*\" { send \"${TEST_PASSWORD}\r\" }
            eof { }
            timeout { }
        }
        expect eof
    " 2>&1
}

sesame_set_secret() {
    local profile="$1" key="$2" value="$3"
    echo "$value" | sesame secret set -p "$profile" "$key" 2>&1 || true
}

sesame_get_secret() {
    local profile="$1" key="$2"
    sesame secret get -p "$profile" "$key" 2>&1 || true
}

# --------------------------------------------------------------------------
# Full reset: wipe and re-init for a clean test environment
# --------------------------------------------------------------------------

full_reset() {
    sesame_wipe || true
    sleep 2
    sesame_init
    sleep 1
    # Activate the default profile
    sesame profile activate "$PROFILE" 2>&1 || true
    sleep 1
}

# --------------------------------------------------------------------------
# V-001: deactivate blocks secret access
# --------------------------------------------------------------------------
v001() {
    full_reset
    sesame_set_secret "$PROFILE" "v001-key" "v001-value"
    sesame profile deactivate "$PROFILE" 2>&1 || true
    sleep 1
    local result
    result=$(sesame_get_secret "$PROFILE" "v001-key")
    test_result "V-001: deactivate blocks secret access" "not active" "$result"
}

# --------------------------------------------------------------------------
# V-002: lock blocks secret access
# --------------------------------------------------------------------------
v002() {
    full_reset
    sesame_set_secret "$PROFILE" "v002-key" "v002-value"
    sesame lock 2>&1 || true
    sleep 1
    local result
    result=$(sesame_get_secret "$PROFILE" "v002-key")
    test_result "V-002: lock blocks secret access" "locked" "$result"
}

# --------------------------------------------------------------------------
# V-003: lock -> unlock -> get requires re-activation
# --------------------------------------------------------------------------
v003() {
    full_reset
    sesame_set_secret "$PROFILE" "v003-key" "v003-value"
    sesame lock 2>&1 || true
    sleep 1
    sesame_unlock
    sleep 1
    local result
    result=$(sesame_get_secret "$PROFILE" "v003-key")
    test_result "V-003: unlock without activate denies access" "not active" "$result"
}

# --------------------------------------------------------------------------
# V-004: lock -> unlock -> activate -> get succeeds
# --------------------------------------------------------------------------
v004() {
    full_reset
    sesame_set_secret "$PROFILE" "v004-key" "v004-value"
    sesame lock 2>&1 || true
    sleep 1
    sesame_unlock
    sleep 1
    sesame profile activate "$PROFILE" 2>&1 || true
    sleep 1
    local result
    result=$(sesame_get_secret "$PROFILE" "v004-key")
    test_result "V-004: lock -> unlock -> activate -> get succeeds" "v004-value" "$result"
}

# --------------------------------------------------------------------------
# V-005: deactivate -> activate -> get succeeds (vault re-opened)
# --------------------------------------------------------------------------
v005() {
    full_reset
    sesame_set_secret "$PROFILE" "v005-key" "v005-value"
    sesame profile deactivate "$PROFILE" 2>&1 || true
    sleep 1
    sesame profile activate "$PROFILE" 2>&1 || true
    sleep 1
    local result
    result=$(sesame_get_secret "$PROFILE" "v005-key")
    test_result "V-005: deactivate -> activate -> get succeeds" "v005-value" "$result"
}

# --------------------------------------------------------------------------
# V-006: status after lock reports locked
# --------------------------------------------------------------------------
v006() {
    full_reset
    sesame lock 2>&1 || true
    sleep 1
    local result
    result=$(sesame status 2>&1 || true)
    test_result "V-006: status after lock reports locked" "locked" "$result"
}

# --------------------------------------------------------------------------
# V-007: status after deactivate shows profile not active
# --------------------------------------------------------------------------
v007() {
    full_reset
    sesame profile deactivate "$PROFILE" 2>&1 || true
    sleep 1
    local result
    result=$(sesame status 2>&1 || true)
    test_result_not_contains "V-007: status after deactivate shows profile not in active list" "$PROFILE" "$result"
}

# --------------------------------------------------------------------------
# V-008: unlock when already unlocked is rejected
# --------------------------------------------------------------------------
v008() {
    full_reset
    local result
    result=$(sesame_unlock)
    test_result "V-008: unlock when already unlocked rejected" "already" "$result"
}

# --------------------------------------------------------------------------
# V-009: kill daemon-secrets -> status reports locked
# --------------------------------------------------------------------------
v009() {
    full_reset
    # Kill daemon-secrets
    pkill -f "daemon-secrets" 2>/dev/null || true
    sleep 5  # Wait for watchdog/restart detection
    local result
    result=$(sesame status 2>&1 || true)
    test_result "V-009: daemon-secrets kill -> status reports locked" "locked" "$result"
}

# --------------------------------------------------------------------------
# V-010: full round-trip: set -> deactivate -> activate -> get
# --------------------------------------------------------------------------
v010() {
    full_reset
    sesame_set_secret "$PROFILE" "v010-key" "v010-value"
    sesame profile deactivate "$PROFILE" 2>&1 || true
    sleep 1
    sesame profile activate "$PROFILE" 2>&1 || true
    sleep 1
    local result
    result=$(sesame_get_secret "$PROFILE" "v010-key")
    test_result "V-010: full round-trip succeeds" "v010-value" "$result"
}

# --------------------------------------------------------------------------
# V-011: sesame init re-run when already unlocked completes without error
# --------------------------------------------------------------------------
v011() {
    full_reset
    local result exit_code=0
    result=$(sesame_init) || exit_code=$?
    if [[ $exit_code -eq 0 ]]; then
        echo "PASS: V-011: sesame init re-run completes without error"
        ((PASS++))
    else
        echo "FAIL: V-011: sesame init re-run failed with exit code $exit_code"
        echo "  output: $result"
        ((FAIL++))
    fi
}

# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

check_prerequisites

echo "========================================"
echo " Open Sesame Protocol Validation Suite"
echo "========================================"
echo ""

v001
v002
v003
v004
v005
v006
v007
v008
v009
v010
v011

echo ""
echo "========================================"
echo " Results: PASS=$PASS  FAIL=$FAIL"
echo "========================================"

[[ $FAIL -eq 0 ]]
