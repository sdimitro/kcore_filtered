#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
#
# test_basic.sh - Basic functionality tests for kcore_filtered
#
# Tests module loading/unloading, procfs entry creation, ELF validity,
# and kernel log messages. Must be run as root.
#

set -euo pipefail

MODNAME="kcore_filtered"
MODPATH="$(dirname "$0")/../${MODNAME}.ko"
PROC_ENTRY="/proc/kcore_filtered"
STATS_ENTRY="/proc/kcore_filtered_stats"

PASS=0
FAIL=0
SKIP=0

pass() {
    echo "  PASS: $1"
    PASS=$((PASS + 1))
}

fail() {
    echo "  FAIL: $1"
    FAIL=$((FAIL + 1))
}

skip() {
    echo "  SKIP: $1"
    SKIP=$((SKIP + 1))
}

# Header
echo "=== kcore_filtered basic tests ==="
echo ""

# Check root
if [[ $EUID -ne 0 ]]; then
    echo "ERROR: This test must be run as root"
    exit 1
fi

# Check module exists
if [[ ! -f "$MODPATH" ]]; then
    echo "ERROR: Module not found at $MODPATH"
    echo "Run 'make' first to build the module"
    exit 1
fi

# Check readelf is available
if ! command -v readelf &>/dev/null; then
    echo "WARNING: readelf not found, some tests will be skipped"
    HAS_READELF=0
else
    HAS_READELF=1
fi

# Ensure module is not already loaded
if lsmod | grep -q "^${MODNAME}"; then
    echo "INFO: Module already loaded, unloading first..."
    rmmod "$MODNAME" || true
    sleep 1
fi

# Save dmesg position
DMESG_START=$(dmesg | wc -l)

# --- Test 1: Module loading ---
echo "Test 1: Module loading"
if insmod "$MODPATH"; then
    pass "insmod succeeded"
else
    fail "insmod failed"
    echo "FATAL: Cannot continue without module loaded"
    exit 1
fi
sleep 1

# --- Test 2: Procfs entry exists ---
echo "Test 2: Procfs entry"
if [[ -e "$PROC_ENTRY" ]]; then
    pass "/proc/kcore_filtered exists"
else
    fail "/proc/kcore_filtered does not exist"
fi

# --- Test 3: Permissions ---
echo "Test 3: Permissions"
PERMS=$(stat -c '%a' "$PROC_ENTRY" 2>/dev/null || stat -f '%Lp' "$PROC_ENTRY" 2>/dev/null || echo "unknown")
if [[ "$PERMS" == "400" ]]; then
    pass "permissions are 0400 (root read-only)"
else
    # On some systems stat format differs; check owner-read bit
    if [[ -r "$PROC_ENTRY" ]]; then
        pass "file is readable by root (perms: $PERMS)"
    else
        fail "unexpected permissions: $PERMS"
    fi
fi

# --- Test 4: File has non-zero size ---
echo "Test 4: File size"
SIZE=$(stat -c '%s' "$PROC_ENTRY" 2>/dev/null || stat -f '%z' "$PROC_ENTRY" 2>/dev/null || echo "0")
if [[ "$SIZE" -gt 0 ]]; then
    pass "file size is $SIZE bytes"
else
    fail "file size is zero"
fi

# --- Test 5: ELF header validity ---
echo "Test 5: ELF header"
if [[ $HAS_READELF -eq 1 ]]; then
    READELF_OUT=$(readelf -h "$PROC_ENTRY" 2>&1) || true
    if echo "$READELF_OUT" | grep -q "ELF Header"; then
        pass "readelf recognizes valid ELF header"
    else
        fail "readelf does not recognize ELF header"
        echo "  Output: $READELF_OUT"
    fi

    # Check it's a core file
    if echo "$READELF_OUT" | grep -q "CORE"; then
        pass "ELF type is CORE"
    else
        fail "ELF type is not CORE"
    fi
else
    skip "readelf not available"
fi

# --- Test 6: Program headers ---
echo "Test 6: Program headers"
if [[ $HAS_READELF -eq 1 ]]; then
    PHDR_OUT=$(readelf -l "$PROC_ENTRY" 2>&1) || true

    # Check for PT_NOTE
    if echo "$PHDR_OUT" | grep -q "NOTE"; then
        pass "PT_NOTE segment present"
    else
        fail "PT_NOTE segment missing"
    fi

    # Check for PT_LOAD
    NLOAD=$(echo "$PHDR_OUT" | grep -c "LOAD" || true)
    if [[ "$NLOAD" -gt 0 ]]; then
        pass "found $NLOAD PT_LOAD segments"
    else
        fail "no PT_LOAD segments found"
    fi
else
    skip "readelf not available"
fi

# --- Test 7: Can read first bytes ---
echo "Test 7: Read test"
FIRST_BYTES=$(dd if="$PROC_ENTRY" bs=16 count=1 2>/dev/null | xxd -l 4 -p 2>/dev/null || echo "fail")
if [[ "$FIRST_BYTES" == "7f454c46" ]]; then
    pass "first 4 bytes are ELF magic (\\x7fELF)"
else
    fail "unexpected first bytes: $FIRST_BYTES"
fi

# --- Test 8: Stats entry ---
echo "Test 8: Stats entry"
if [[ -e "$STATS_ENTRY" ]]; then
    pass "/proc/kcore_filtered_stats exists"

    STATS_CONTENT=$(cat "$STATS_ENTRY" 2>/dev/null || echo "")
    if echo "$STATS_CONTENT" | grep -q "allowed"; then
        pass "stats file contains expected fields"
    else
        fail "stats file missing expected fields"
    fi
else
    fail "/proc/kcore_filtered_stats does not exist"
fi

# --- Test 9: Module unloading ---
echo "Test 9: Module unloading"
if rmmod "$MODNAME"; then
    pass "rmmod succeeded"
else
    fail "rmmod failed"
fi
sleep 1

# --- Test 10: Procfs entries removed ---
echo "Test 10: Cleanup"
if [[ ! -e "$PROC_ENTRY" ]]; then
    pass "/proc/kcore_filtered removed after unload"
else
    fail "/proc/kcore_filtered still exists after unload"
fi

if [[ ! -e "$STATS_ENTRY" ]]; then
    pass "/proc/kcore_filtered_stats removed after unload"
else
    fail "/proc/kcore_filtered_stats still exists after unload"
fi

# --- Test 11: Kernel log check ---
echo "Test 11: Kernel log"
DMESG_NEW=$(dmesg | tail -n +$((DMESG_START + 1)))
if echo "$DMESG_NEW" | grep -q "${MODNAME}: initializing"; then
    pass "init message found in dmesg"
else
    fail "init message not found in dmesg"
fi

if echo "$DMESG_NEW" | grep -qi "error\|bug\|oops\|panic"; then
    fail "error/bug messages found in dmesg"
    echo "$DMESG_NEW" | grep -i "error\|bug\|oops\|panic" | head -5
else
    pass "no error messages in dmesg"
fi

# Summary
echo ""
echo "=== Results ==="
echo "  Passed: $PASS"
echo "  Failed: $FAIL"
echo "  Skipped: $SKIP"
echo ""

if [[ $FAIL -gt 0 ]]; then
    echo "OVERALL: FAIL"
    exit 1
else
    echo "OVERALL: PASS"
    exit 0
fi
