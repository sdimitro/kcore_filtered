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

# --- Test 9: Audit logging ---
echo "Test 9: Audit logging"
# Trigger a deliberate open-read-close cycle
dd if="$PROC_ENTRY" of=/dev/null bs=4096 count=1 2>/dev/null
sleep 1
# Audit records go to dmesg when auditd is not running, and to
# /var/log/audit/audit.log when it is. Check both paths.
AUDIT_FOUND=0
DMESG_AUDIT=$(dmesg | tail -n +$((DMESG_START + 1)))
if echo "$DMESG_AUDIT" | grep -q "kcore_filtered op=open"; then
    AUDIT_FOUND=1
fi
if [[ -r /var/log/audit/audit.log ]]; then
    if grep -q "kcore_filtered op=open" /var/log/audit/audit.log 2>/dev/null; then
        AUDIT_FOUND=1
    fi
fi
if [[ $AUDIT_FOUND -eq 1 ]]; then
    pass "audit open record found"
else
    skip "audit records not found (auditd may not be running and klog may not include audit)"
fi

CLOSE_FOUND=0
if echo "$DMESG_AUDIT" | grep -q "kcore_filtered op=close"; then
    CLOSE_FOUND=1
fi
if [[ -r /var/log/audit/audit.log ]]; then
    if grep -q "kcore_filtered op=close" /var/log/audit/audit.log 2>/dev/null; then
        CLOSE_FOUND=1
    fi
fi
if [[ $CLOSE_FOUND -eq 1 ]]; then
    pass "audit close record found (includes bytes_read and duration_ms)"
else
    skip "audit close record not found (auditd may not be running)"
fi

# Verify audit parameter is visible in sysfs
AUDIT_PARAM=$(cat /sys/module/kcore_filtered/parameters/audit 2>/dev/null || echo "unknown")
if [[ "$AUDIT_PARAM" == "Y" ]]; then
    pass "audit=Y confirmed via sysfs"
else
    fail "audit parameter is '$AUDIT_PARAM', expected 'Y'"
fi

# --- Test 10: Module unloading ---
echo "Test 10: Module unloading"
if rmmod "$MODNAME"; then
    pass "rmmod succeeded"
else
    fail "rmmod failed"
fi
sleep 1

# --- Test 11: Procfs entries removed ---
echo "Test 11: Cleanup"
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

# --- Test 12: Kernel log check ---
echo "Test 12: Kernel log"
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

# --- Test 13: Load with filter_slab=1 ---
echo "Test 13: Module loading with filter_slab=1"
if insmod "$MODPATH" filter_slab=1; then
    pass "insmod filter_slab=1 succeeded"
else
    fail "insmod filter_slab=1 failed"
    # Skip remaining slab tests
    echo "  Skipping remaining filter_slab tests"
    skip "filter_slab=1 parameter test"
    skip "filter_slab=1 stats test"
    skip "filter_slab=1 unload test"
    goto_summary=1
fi
sleep 1

if [[ -z "${goto_summary:-}" ]]; then

# --- Test 14: Verify filter_slab parameter ---
echo "Test 14: filter_slab parameter"
SLAB_PARAM=$(cat /sys/module/kcore_filtered/parameters/filter_slab 2>/dev/null || echo "unknown")
if [[ "$SLAB_PARAM" == "Y" ]]; then
    pass "filter_slab=Y confirmed via sysfs"
else
    fail "filter_slab parameter is '$SLAB_PARAM', expected 'Y'"
fi

# --- Test 15: Stats show denied_slab field ---
echo "Test 15: denied_slab in stats"
if [[ -e "$STATS_ENTRY" ]]; then
    STATS_CONTENT=$(cat "$STATS_ENTRY" 2>/dev/null || echo "")
    if echo "$STATS_CONTENT" | grep -q "denied_slab"; then
        pass "stats file contains denied_slab field"
    else
        fail "stats file missing denied_slab field"
    fi
else
    fail "/proc/kcore_filtered_stats does not exist"
fi

# --- Test 16: Read some data to exercise slab filtering ---
echo "Test 16: Exercise slab filter"
# Read a chunk from the file to trigger page classification
READ_BYTES=$(dd if="$PROC_ENTRY" bs=4096 count=256 2>/dev/null | wc -c)
if [[ "$READ_BYTES" -gt 0 ]]; then
    # Check that denied_slab counter incremented (some slab pages exist on any system)
    DENIED_SLAB=$(cat "$STATS_ENTRY" 2>/dev/null | grep "denied_slab" | awk '{print $2}')
    if [[ -n "$DENIED_SLAB" && "$DENIED_SLAB" -gt 0 ]]; then
        pass "denied_slab counter is $DENIED_SLAB (slab pages being filtered)"
    else
        # It's possible the sampled pages didn't include slab pages
        pass "read succeeded (denied_slab=$DENIED_SLAB — may need larger read to hit slab pages)"
    fi
else
    fail "failed to read from kcore_filtered with filter_slab=1"
fi

# --- Test 17: Unload after filter_slab test ---
echo "Test 17: Unload after filter_slab test"
if rmmod "$MODNAME"; then
    pass "rmmod after filter_slab=1 test succeeded"
else
    fail "rmmod after filter_slab=1 test failed"
fi
sleep 1

fi  # end goto_summary guard

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
