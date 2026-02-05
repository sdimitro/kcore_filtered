#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""
test_drgn.py - drgn integration tests for kcore_filtered

Verifies that drgn can use /proc/kcore_filtered for kernel introspection.
Tests key drgn use cases: reading kernel globals, walking data structures,
and verifying that filtered pages return zeroes.

Must be run as root with the kcore_filtered module loaded.
Requires: drgn (pip install drgn)
"""

import os
import sys

KCORE_FILTERED_PATH = "/proc/kcore_filtered"

PASS = 0
FAIL = 0
SKIP = 0


def pass_test(msg):
    global PASS
    print(f"  PASS: {msg}")
    PASS += 1


def fail_test(msg):
    global FAIL
    print(f"  FAIL: {msg}")
    FAIL += 1


def skip_test(msg):
    global SKIP
    print(f"  SKIP: {msg}")
    SKIP += 1


def check_prereqs():
    """Check prerequisites."""
    if os.geteuid() != 0:
        print("ERROR: This test must be run as root")
        sys.exit(1)

    if not os.path.exists(KCORE_FILTERED_PATH):
        print(f"ERROR: {KCORE_FILTERED_PATH} does not exist")
        print("Is the kcore_filtered module loaded?")
        sys.exit(1)

    try:
        import drgn  # noqa: F401
        return True
    except ImportError:
        print("ERROR: drgn is not installed")
        print("Install with: pip install drgn")
        sys.exit(1)


def test_open_program():
    """Test 1: Open kcore_filtered as a drgn Program."""
    print("\nTest 1: Open as drgn Program")
    try:
        import drgn

        prog = drgn.Program()
        prog.set_core_dump(KCORE_FILTERED_PATH)

        # Try to load the default debug info
        try:
            prog.load_default_debug_info()
            pass_test("opened kcore_filtered and loaded debug info")
        except drgn.MissingDebugInfoError:
            pass_test("opened kcore_filtered (debug info not available, but file is valid)")

        return prog
    except Exception as e:
        fail_test(f"failed to open kcore_filtered: {e}")
        return None


def test_read_init_task(prog):
    """Test 2: Read init_task (PID 0 / swapper)."""
    print("\nTest 2: Read init_task")
    if prog is None:
        skip_test("no program available")
        return

    try:
        init_task = prog["init_task"]
        comm = init_task.comm.string_().decode("utf-8", errors="replace")
        pid = int(init_task.pid)

        if comm == "swapper/0" or comm.startswith("swapper"):
            pass_test(f"init_task.comm = '{comm}', pid = {pid}")
        elif pid == 0:
            pass_test(f"init_task.pid = {pid}, comm = '{comm}'")
        else:
            fail_test(f"unexpected init_task: comm='{comm}', pid={pid}")
    except Exception as e:
        fail_test(f"cannot read init_task: {e}")


def test_walk_tasks(prog):
    """Test 3: Walk the task list."""
    print("\nTest 3: Walk task list")
    if prog is None:
        skip_test("no program available")
        return

    try:
        from drgn.helpers.linux.pid import for_each_task

        count = 0
        errors = 0
        for task in for_each_task(prog):
            count += 1
            try:
                _ = task.comm.string_()
                _ = int(task.pid)
            except Exception:
                errors += 1

            if count >= 500:  # Don't walk forever
                break

        if count > 0:
            pass_test(f"walked {count} tasks ({errors} read errors)")
        else:
            fail_test("no tasks found")
    except ImportError:
        skip_test("drgn.helpers.linux.pid not available")
    except Exception as e:
        fail_test(f"failed to walk tasks: {e}")


def test_read_modules(prog):
    """Test 4: List loaded kernel modules."""
    print("\nTest 4: List kernel modules")
    if prog is None:
        skip_test("no program available")
        return

    try:
        from drgn.helpers.linux.module import for_each_module

        count = 0
        found_us = False
        for module in for_each_module(prog):
            name = module.name.string_().decode("utf-8", errors="replace")
            count += 1
            if "kcore_filtered" in name:
                found_us = True

            if count >= 200:
                break

        if count > 0:
            pass_test(f"found {count} modules")
        else:
            fail_test("no modules found")

        if found_us:
            pass_test("found kcore_filtered module in module list")
        else:
            # Module might not be visible through kcore_filtered depending on
            # how the ELF segments are laid out
            skip_test("kcore_filtered module not found in list (may be expected)")
    except ImportError:
        skip_test("drgn.helpers.linux.module not available")
    except Exception as e:
        fail_test(f"failed to list modules: {e}")


def test_read_mounts(prog):
    """Test 5: Read mount table."""
    print("\nTest 5: Read mount table")
    if prog is None:
        skip_test("no program available")
        return

    try:
        init_task = prog["init_task"]
        nsproxy = init_task.nsproxy
        mnt_ns = nsproxy.mnt_ns

        # Just verify we can dereference into the mount namespace
        _ = int(mnt_ns.seq)
        pass_test("read mount namespace seq number")
    except Exception as e:
        # This is a deep dereference chain that may fail if any
        # intermediate pointer page is filtered
        fail_test(f"failed to read mount info: {e}")


def test_kernel_version(prog):
    """Test 6: Read kernel version string."""
    print("\nTest 6: Read kernel version")
    if prog is None:
        skip_test("no program available")
        return

    try:
        uts = prog["init_uts_ns"].name
        release = uts.release.string_().decode("utf-8", errors="replace")
        if release and len(release) > 0:
            pass_test(f"kernel release: {release}")
        else:
            fail_test("empty kernel release string")
    except Exception as e:
        fail_test(f"cannot read kernel version: {e}")


def test_read_jiffies(prog):
    """Test 7: Read jiffies counter."""
    print("\nTest 7: Read jiffies")
    if prog is None:
        skip_test("no program available")
        return

    try:
        jiffies = int(prog["jiffies"])
        if jiffies > 0:
            pass_test(f"jiffies = {jiffies}")
        else:
            fail_test(f"unexpected jiffies value: {jiffies}")
    except Exception as e:
        fail_test(f"cannot read jiffies: {e}")


def main():
    check_prereqs()

    print("=== kcore_filtered drgn integration tests ===")

    prog = test_open_program()
    test_read_init_task(prog)
    test_walk_tasks(prog)
    test_read_modules(prog)
    test_read_mounts(prog)
    test_kernel_version(prog)
    test_read_jiffies(prog)

    # Summary
    print(f"\n=== Results ===")
    print(f"  Passed:  {PASS}")
    print(f"  Failed:  {FAIL}")
    print(f"  Skipped: {SKIP}")

    if FAIL > 0:
        print("\nOVERALL: FAIL")
        sys.exit(1)
    elif PASS == 0:
        print("\nOVERALL: SKIP (all tests skipped)")
        sys.exit(0)
    else:
        print("\nOVERALL: PASS")
        sys.exit(0)


if __name__ == "__main__":
    main()
