# kcore_filtered Test Suite

## Overview

This directory contains tests for the kcore_filtered kernel module.
All tests require **root privileges** and a running Linux system with
the module loaded (unless testing load/unload itself).

## Test Files

### test_basic.sh — Basic Functionality Tests

Shell-based smoke tests that verify:

1. **Module loading** — `insmod` succeeds, no kernel errors
2. **Procfs entry** — `/proc/kcore_filtered` exists with correct permissions
3. **ELF validity** — `readelf -h` recognizes the file as a valid ELF core
4. **Program headers** — `readelf -l` shows PT_NOTE + PT_LOAD segments
5. **Stats entry** — `/proc/kcore_filtered_stats` exists and is readable
6. **Module unloading** — `rmmod` succeeds, procfs entries removed
7. **Kernel log** — no errors or warnings in `dmesg`

**Requirements:** `readelf` (from binutils), root access.

```bash
sudo bash tests/test_basic.sh
```

### test_filter.py — Filter Verification Tests

Python script that validates the privacy filter is working correctly:

1. **Reads pages** from both `/proc/kcore` and `/proc/kcore_filtered`
   at the same file offsets
2. **Cross-references** with `/proc/kpageflags` to identify page types
3. **Verifies zeroing** — anonymous and free pages in kcore_filtered
   should be all zeroes
4. **Verifies pass-through** — kernel data pages should match between
   kcore and kcore_filtered
5. **Reports statistics** — breakdown of pages allowed vs. zeroed by
   category

**Requirements:** Python 3.6+, root access, both `/proc/kcore` and
`/proc/kcore_filtered` available.

```bash
sudo python3 tests/test_filter.py
```

### test_drgn.py — drgn Integration Tests

Tests that drgn can successfully use `/proc/kcore_filtered` as a
data source for kernel debugging:

1. **Open as program** — drgn opens kcore_filtered successfully
2. **Read init_task** — can read the initial task struct
3. **Walk task list** — can iterate all tasks via `for_each_task()`
4. **Read mount table** — can enumerate mounted filesystems
5. **Verify user page redaction** — attempts to read user process
   memory through drgn and verifies it returns zeroes

**Requirements:** Python 3.6+, drgn package, root access.

```bash
sudo python3 tests/test_drgn.py
```

## Running All Tests

From the project root:

```bash
make test
```

This runs all three test scripts in sequence. Any failure is reported
with a non-zero exit code.

## Test Environment Requirements

- Linux kernel 6.8+ (matching what the module was built against)
- Root access (for loading modules and reading /proc/kcore)
- `readelf` from binutils
- Python 3.6+
- drgn (for test_drgn.py only): `pip install drgn`
- The module must be built: `make` in the project root

## Writing New Tests

When adding tests:

1. All tests should be runnable independently
2. Tests should clean up after themselves (unload module if they loaded it)
3. Use clear PASS/FAIL output for each test case
4. Document any additional requirements in this file
5. Add the test to the `make test` target in the Makefile if appropriate
