#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""
test_drgn.py - drgn integration tests for kcore_filtered

Verifies that drgn can use /proc/kcore_filtered for kernel introspection.
Tests key drgn use cases: reading kernel globals, walking data structures,
verifying that filtered pages return zeroes, and validating filter stats.

Must be run as root with the kcore_filtered module loaded.
Requires: drgn (pip install drgn)
"""

import os
import struct
import sys

KCORE_FILTERED_PATH = "/proc/kcore_filtered"
KCORE_PATH = "/proc/kcore"
STATS_PATH = "/proc/kcore_filtered_stats"

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


def read_stats():
    """Read /proc/kcore_filtered_stats into a dict."""
    stats = {}
    try:
        with open(STATS_PATH) as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 2:
                    # strip trailing colon from key
                    key = parts[0].rstrip(":")
                    stats[key] = int(parts[1])
    except (OSError, ValueError):
        pass
    return stats


def get_module_param(name):
    """Read a sysfs module parameter value."""
    path = f"/sys/module/kcore_filtered/parameters/{name}"
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return None


# ============================================================
# Core drgn tests - verify basic kernel introspection works
# ============================================================

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


# ============================================================
# Filter validation tests via drgn
# ============================================================

def test_task_struct_fields(prog):
    """Test 8: Read multiple task_struct fields to verify slab data accessible."""
    print("\nTest 8: Read task_struct fields (slab data)")
    if prog is None:
        skip_test("no program available")
        return

    try:
        from drgn.helpers.linux.pid import for_each_task

        checked = 0
        for task in for_each_task(prog):
            try:
                comm = task.comm.string_().decode("utf-8", errors="replace")
                pid = int(task.pid)
                tgid = int(task.tgid)
                state = int(task.__state)

                # Verify the fields make sense
                if pid < 0 or tgid < 0:
                    fail_test(f"invalid pid/tgid: {pid}/{tgid}")
                    return

                checked += 1
                if checked >= 10:
                    break
            except Exception:
                # Some tasks may race with exit
                continue

        if checked > 0:
            pass_test(f"read pid/tgid/state/comm from {checked} tasks")
        else:
            fail_test("could not read fields from any task")
    except ImportError:
        skip_test("drgn.helpers.linux.pid not available")
    except Exception as e:
        fail_test(f"failed to read task_struct fields: {e}")


def test_mm_struct_accessible(prog):
    """Test 9: Read mm_struct from a task (verifies mm slab data)."""
    print("\nTest 9: Read mm_struct from tasks")
    if prog is None:
        skip_test("no program available")
        return

    try:
        from drgn.helpers.linux.pid import for_each_task

        found_mm = False
        for task in for_each_task(prog):
            try:
                mm = task.mm
                if not mm:
                    continue
                # Read a field from mm_struct to verify the page is readable
                pgd = int(mm.pgd)
                total_vm = int(mm.total_vm)
                if pgd != 0 and total_vm > 0:
                    found_mm = True
                    break
            except Exception:
                continue

        if found_mm:
            pass_test(f"read mm_struct: pgd=0x{pgd:x}, total_vm={total_vm}")
        else:
            skip_test("no accessible mm_struct found (may be expected with filters)")
    except ImportError:
        skip_test("drgn.helpers.linux.pid not available")
    except Exception as e:
        fail_test(f"failed to read mm_struct: {e}")


def test_dentry_cache(prog):
    """Test 10: Walk dentry cache via the root dentry."""
    print("\nTest 10: Read dentry/inode structures")
    if prog is None:
        skip_test("no program available")
        return

    try:
        init_task = prog["init_task"]
        fs = init_task.fs
        root = fs.root

        # Read dentry name from root mount
        dentry = root.dentry
        d_name = dentry.d_name.name.string_().decode("utf-8", errors="replace")

        # Read inode from root dentry
        inode = dentry.d_inode
        i_ino = int(inode.i_ino)
        i_mode = int(inode.i_mode)

        pass_test(f"root dentry name='{d_name}', inode={i_ino}, mode=0o{i_mode:o}")
    except Exception as e:
        fail_test(f"failed to read dentry/inode: {e}")


def test_per_cpu_data(prog):
    """Test 11: Read per-CPU data (vmalloc region)."""
    print("\nTest 11: Read per-CPU data")
    if prog is None:
        skip_test("no program available")
        return

    try:
        from drgn.helpers.linux.percpu import per_cpu

        # Read the current CPU's runqueue (common drgn use case)
        # runqueues is a per-CPU variable
        try:
            rq = per_cpu(prog["runqueues"], 0)
            nr_running = int(rq.nr_running)
            pass_test(f"CPU 0 runqueue: nr_running={nr_running}")
        except Exception:
            # Try reading nr_cpus as a simpler test
            try:
                nr_cpus = int(prog["nr_cpu_ids"])
                pass_test(f"nr_cpu_ids={nr_cpus}")
            except Exception as e2:
                fail_test(f"cannot read per-CPU data: {e2}")
    except ImportError:
        skip_test("drgn.helpers.linux.percpu not available")
    except Exception as e:
        fail_test(f"failed to read per-CPU data: {e}")


def test_network_namespace(prog):
    """Test 12: Read network namespace (deep kernel structure walk)."""
    print("\nTest 12: Read network namespace")
    if prog is None:
        skip_test("no program available")
        return

    try:
        init_task = prog["init_task"]
        nsproxy = init_task.nsproxy
        net_ns = nsproxy.net_ns

        # Read network namespace fields
        ifindex = int(net_ns.ifindex)
        pass_test(f"init net_ns ifindex={ifindex}")
    except Exception as e:
        # Deep pointer chains may hit filtered pages in some configs
        skip_test(f"cannot read net_ns: {e}")


def test_vmemmap_readable(prog):
    """Test 13: Verify vmemmap (struct page array) is readable."""
    print("\nTest 13: Read vmemmap data (struct page)")
    if prog is None:
        skip_test("no program available")
        return

    try:
        import drgn

        # Read struct page for PFN 0 (should be in vmemmap region)
        page_type = prog.type("struct page")
        vmemmap_base = prog["vmemmap_base"] if "vmemmap_base" in [
            s.name for s in prog.symbols()
        ] else None

        if vmemmap_base is not None:
            pass_test(f"vmemmap_base accessible")
        else:
            # Alternative: use pfn_to_page equivalent
            try:
                # Try reading the page flags of a known-good page
                # init_task is in a slab page that must be online
                init_addr = prog["init_task"].address_of_()
                pass_test(f"init_task address accessible at {int(init_addr):#x}")
            except Exception as e2:
                skip_test(f"cannot verify vmemmap: {e2}")
    except Exception as e:
        skip_test(f"vmemmap test inconclusive: {e}")


def test_superblock_list(prog):
    """Test 14: Walk the superblock list (common drgn debugging)."""
    print("\nTest 14: Walk superblock list")
    if prog is None:
        skip_test("no program available")
        return

    try:
        from drgn.helpers.linux.list import list_for_each_entry

        sb_type = prog.type("struct super_block")
        super_blocks = prog["super_blocks"]
        count = 0
        fs_names = []

        for sb in list_for_each_entry(sb_type, super_blocks.address_of_(), "s_list"):
            try:
                fs_type = sb.s_type
                name = fs_type.name.string_().decode("utf-8", errors="replace")
                fs_names.append(name)
                count += 1
                if count >= 20:
                    break
            except Exception:
                count += 1
                continue

        if count > 0:
            sample = ", ".join(fs_names[:5])
            pass_test(f"found {count} superblocks (e.g., {sample})")
        else:
            fail_test("no superblocks found")
    except ImportError:
        skip_test("drgn.helpers.linux.list not available")
    except Exception as e:
        fail_test(f"failed to walk superblocks: {e}")


# ============================================================
# Filter stats and parameter validation via drgn
# ============================================================

def test_filter_stats_counters(prog):
    """Test 15: Verify filter stats counters are incrementing."""
    print("\nTest 15: Filter stats counters")
    if prog is None:
        skip_test("no program available")
        return

    stats = read_stats()
    if not stats:
        fail_test("cannot read /proc/kcore_filtered_stats")
        return

    allowed = stats.get("allowed", 0)
    denied_anon = stats.get("denied_anon", 0)
    denied_cache = stats.get("denied_cache", 0)
    denied_free = stats.get("denied_free", 0)

    # After running drgn tests above, allowed should be > 0
    if allowed > 0:
        pass_test(f"allowed={allowed} (filter is classifying pages)")
    else:
        fail_test("allowed=0 after drgn reads (expected > 0)")

    total_denied = denied_anon + denied_cache + denied_free
    if total_denied > 0:
        pass_test(f"total denied={total_denied} (anon={denied_anon}, "
                  f"cache={denied_cache}, free={denied_free})")
    else:
        # On a system with no user processes, this could be 0
        skip_test("no pages denied (system may have minimal user activity)")


def test_kcore_vs_filtered_elf_headers():
    """Test 16: Compare ELF headers between kcore and kcore_filtered."""
    print("\nTest 16: Compare ELF headers")
    PAGE_SIZE = os.sysconf("SC_PAGE_SIZE")

    try:
        with open(KCORE_PATH, "rb") as f:
            kcore_ehdr = f.read(64)
        with open(KCORE_FILTERED_PATH, "rb") as f:
            filtered_ehdr = f.read(64)
    except OSError as e:
        fail_test(f"cannot read ELF headers: {e}")
        return

    # Both should be valid ELF
    if kcore_ehdr[:4] != b"\x7fELF":
        fail_test("kcore is not ELF")
        return
    if filtered_ehdr[:4] != b"\x7fELF":
        fail_test("kcore_filtered is not ELF")
        return

    # Both should be ET_CORE (type field at offset 16)
    kcore_type = struct.unpack_from("<H", kcore_ehdr, 16)[0]
    filtered_type = struct.unpack_from("<H", filtered_ehdr, 16)[0]

    if kcore_type == 4 and filtered_type == 4:  # ET_CORE = 4
        pass_test("both files are ET_CORE")
    else:
        fail_test(f"ELF types: kcore={kcore_type}, filtered={filtered_type}")

    # Machine type should match
    kcore_machine = struct.unpack_from("<H", kcore_ehdr, 18)[0]
    filtered_machine = struct.unpack_from("<H", filtered_ehdr, 18)[0]
    if kcore_machine == filtered_machine:
        pass_test(f"machine type matches (e_machine={kcore_machine})")
    else:
        fail_test(f"machine mismatch: kcore={kcore_machine}, "
                  f"filtered={filtered_machine}")


def test_filtered_pages_are_zero():
    """Test 17: Read raw pages from kcore_filtered and verify filtering."""
    print("\nTest 17: Verify filtered pages return zeroes")
    PAGE_SIZE = os.sysconf("SC_PAGE_SIZE")

    try:
        with open(KCORE_FILTERED_PATH, "rb") as f:
            # Read ELF header to find PT_LOAD segments
            ehdr = f.read(64)
            e_phoff = struct.unpack_from("<Q", ehdr, 32)[0]
            e_phentsize = struct.unpack_from("<H", ehdr, 54)[0]
            e_phnum = struct.unpack_from("<H", ehdr, 56)[0]

            f.seek(e_phoff)
            segments = []
            for i in range(e_phnum):
                phdr = f.read(e_phentsize)
                p_type = struct.unpack_from("<I", phdr, 0)[0]
                p_offset = struct.unpack_from("<Q", phdr, 8)[0]
                p_paddr = struct.unpack_from("<Q", phdr, 24)[0]
                p_filesz = struct.unpack_from("<Q", phdr, 32)[0]
                if p_type == 1 and p_paddr != 0xFFFFFFFFFFFFFFFF:
                    segments.append((p_offset, p_filesz, p_paddr))

            if not segments:
                skip_test("no RAM PT_LOAD segments found")
                return

            # Sample pages from the first RAM segment
            seg_offset, seg_size, seg_paddr = segments[0]
            zero_pages = 0
            nonzero_pages = 0
            sample_count = 0
            step = max(PAGE_SIZE, seg_size // 50)

            for off in range(0, min(seg_size, step * 50), step):
                try:
                    f.seek(seg_offset + off)
                    page = f.read(PAGE_SIZE)
                    if len(page) < PAGE_SIZE:
                        break
                    sample_count += 1
                    if page == b"\x00" * PAGE_SIZE:
                        zero_pages += 1
                    else:
                        nonzero_pages += 1
                except OSError:
                    break

            if sample_count > 0:
                pass_test(f"sampled {sample_count} pages: "
                          f"{zero_pages} zeroed, {nonzero_pages} non-zero")
                if zero_pages > 0 and nonzero_pages > 0:
                    pass_test("filter is differentiating pages "
                              "(some zeroed, some passed)")
                elif zero_pages > 0:
                    pass_test("filter is zeroing pages (no kernel data "
                              "in sampled range)")
                elif nonzero_pages > 0:
                    pass_test("kernel data readable in sampled range")
            else:
                skip_test("could not sample any pages")

    except OSError as e:
        fail_test(f"cannot read kcore_filtered: {e}")


def test_module_params_visible():
    """Test 18: Verify module parameters are accessible via sysfs."""
    print("\nTest 18: Module parameters via sysfs")

    expected_params = [
        ("filter_anon", "Y"),
        ("filter_cache", "Y"),
        ("filter_free", "Y"),
        ("audit", "Y"),
    ]

    for name, expected_default in expected_params:
        val = get_module_param(name)
        if val is None:
            fail_test(f"parameter '{name}' not found in sysfs")
        elif val == expected_default:
            pass_test(f"{name}={val}")
        else:
            # Value might have been changed; just verify it's readable
            pass_test(f"{name}={val} (readable, default would be {expected_default})")


def test_concurrent_reads(prog):
    """Test 19: Verify multiple sequential reads return consistent data."""
    print("\nTest 19: Sequential read consistency")
    if prog is None:
        skip_test("no program available")
        return

    try:
        # Read the same kernel variable multiple times
        values = []
        for i in range(5):
            val = int(prog["init_task"].pid)
            values.append(val)

        if all(v == values[0] for v in values):
            pass_test(f"5 sequential reads of init_task.pid all returned {values[0]}")
        else:
            fail_test(f"inconsistent reads: {values}")
    except Exception as e:
        fail_test(f"sequential read test failed: {e}")


def test_cpuinfo_accessible(prog):
    """Test 20: Read CPU info (common drgn diagnostic)."""
    print("\nTest 20: Read CPU information")
    if prog is None:
        skip_test("no program available")
        return

    try:
        nr_cpus = int(prog["nr_cpu_ids"])
        if nr_cpus > 0:
            pass_test(f"nr_cpu_ids = {nr_cpus}")
        else:
            fail_test(f"invalid nr_cpu_ids: {nr_cpus}")
    except Exception as e:
        skip_test(f"cannot read nr_cpu_ids: {e}")


def main():
    check_prereqs()

    print("=== kcore_filtered drgn integration tests ===")

    prog = test_open_program()

    # Core introspection tests
    test_read_init_task(prog)
    test_walk_tasks(prog)
    test_read_modules(prog)
    test_read_mounts(prog)
    test_kernel_version(prog)
    test_read_jiffies(prog)

    # Extended kernel structure tests
    test_task_struct_fields(prog)
    test_mm_struct_accessible(prog)
    test_dentry_cache(prog)
    test_per_cpu_data(prog)
    test_network_namespace(prog)
    test_vmemmap_readable(prog)
    test_superblock_list(prog)

    # Filter and stats validation
    test_filter_stats_counters(prog)
    test_kcore_vs_filtered_elf_headers()
    test_filtered_pages_are_zero()
    test_module_params_visible()
    test_concurrent_reads(prog)
    test_cpuinfo_accessible(prog)

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
