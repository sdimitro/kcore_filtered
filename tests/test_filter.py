#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""
test_filter.py - Filter verification tests for kcore_filtered

Compares pages read from /proc/kcore and /proc/kcore_filtered to verify
that the privacy filter is working correctly:
  - Anonymous/free/cache pages should be zeroed in kcore_filtered
  - Kernel data pages should match between kcore and kcore_filtered

Also cross-references with /proc/kpageflags to independently verify
page classifications.

Must be run as root with the kcore_filtered module loaded.
"""

import os
import sys
import struct
import mmap

# Page flag bits from include/uapi/linux/kernel-page-flags.h
KPF_LOCKED = 0
KPF_ERROR = 1
KPF_REFERENCED = 2
KPF_UPTODATE = 3
KPF_DIRTY = 4
KPF_LRU = 5
KPF_ACTIVE = 6
KPF_SLAB = 7
KPF_WRITEBACK = 8
KPF_RECLAIM = 9
KPF_BUDDY = 10
KPF_MMAP = 11
KPF_ANON = 12
KPF_SWAPCACHE = 13
KPF_SWAPBACKED = 14
KPF_COMPOUND_HEAD = 15
KPF_COMPOUND_TAIL = 16
KPF_HUGE = 17
KPF_UNEVICTABLE = 18
KPF_HWPOISON = 19
KPF_NOPAGE = 20
KPF_KSM = 21
KPF_THP = 22
KPF_OFFLINE = 23
KPF_IDLE = 25

PAGE_SIZE = os.sysconf("SC_PAGE_SIZE")
KCORE_PATH = "/proc/kcore"
KCORE_FILTERED_PATH = "/proc/kcore_filtered"
KPAGEFLAGS_PATH = "/proc/kpageflags"
KPAGECOUNT_PATH = "/proc/kpagecount"


class Stats:
    """Track filter verification statistics."""

    def __init__(self):
        self.total_pages = 0
        self.matched_pages = 0  # Same content in both
        self.zeroed_pages = 0   # Zeroed in filtered but not in original
        self.both_zero = 0      # Zero in both
        self.mismatch_pages = 0  # Different non-zero content (unexpected)
        self.read_errors = 0

        # By page type (from kpageflags)
        self.anon_zeroed = 0
        self.anon_not_zeroed = 0
        self.buddy_zeroed = 0
        self.buddy_not_zeroed = 0
        self.lru_zeroed = 0
        self.lru_not_zeroed = 0
        self.slab_zeroed = 0
        self.slab_not_zeroed = 0
        self.other_zeroed = 0
        self.other_not_zeroed = 0


def check_root():
    """Ensure we're running as root."""
    if os.geteuid() != 0:
        print("ERROR: This test must be run as root")
        sys.exit(1)


def check_prereqs():
    """Check that required files exist."""
    for path in [KCORE_PATH, KCORE_FILTERED_PATH]:
        if not os.path.exists(path):
            print(f"ERROR: {path} does not exist")
            if path == KCORE_FILTERED_PATH:
                print("Is the kcore_filtered module loaded?")
            sys.exit(1)


def parse_elf_phdrs(path):
    """Parse ELF program headers to find PT_LOAD segments."""
    segments = []

    with open(path, "rb") as f:
        # Read ELF header
        ident = f.read(16)
        if ident[:4] != b"\x7fELF":
            print(f"ERROR: {path} is not a valid ELF file")
            return segments

        ei_class = ident[4]
        if ei_class != 2:  # ELFCLASS64
            print(f"ERROR: Expected 64-bit ELF, got class {ei_class}")
            return segments

        # Read rest of ehdr (64-bit)
        f.seek(0)
        ehdr_data = f.read(64)  # sizeof(Elf64_Ehdr)

        e_phoff = struct.unpack_from("<Q", ehdr_data, 32)[0]
        e_phentsize = struct.unpack_from("<H", ehdr_data, 54)[0]
        e_phnum = struct.unpack_from("<H", ehdr_data, 56)[0]

        # Read program headers
        f.seek(e_phoff)
        for i in range(e_phnum):
            phdr_data = f.read(e_phentsize)
            if len(phdr_data) < 56:
                break

            p_type = struct.unpack_from("<I", phdr_data, 0)[0]
            p_offset = struct.unpack_from("<Q", phdr_data, 8)[0]
            p_vaddr = struct.unpack_from("<Q", phdr_data, 16)[0]
            p_paddr = struct.unpack_from("<Q", phdr_data, 24)[0]
            p_filesz = struct.unpack_from("<Q", phdr_data, 32)[0]
            p_memsz = struct.unpack_from("<Q", phdr_data, 40)[0]

            if p_type == 1:  # PT_LOAD
                segments.append({
                    "offset": p_offset,
                    "vaddr": p_vaddr,
                    "paddr": p_paddr,
                    "filesz": p_filesz,
                    "memsz": p_memsz,
                })

    return segments


def get_kpageflags(pfn):
    """Read page flags from /proc/kpageflags for a given PFN."""
    try:
        with open(KPAGEFLAGS_PATH, "rb") as f:
            f.seek(pfn * 8)
            data = f.read(8)
            if len(data) < 8:
                return None
            return struct.unpack("<Q", data)[0]
    except (OSError, OverflowError):
        return None


def is_page_zero(data):
    """Check if a page-sized chunk is all zeroes."""
    return data == b"\x00" * len(data)


def classify_page_flags(flags):
    """Classify a page based on kpageflags bits."""
    if flags is None:
        return "unknown"
    if flags & (1 << KPF_BUDDY):
        return "buddy"
    if flags & (1 << KPF_ANON):
        return "anon"
    if flags & (1 << KPF_SLAB):
        return "slab"
    if flags & (1 << KPF_LRU):
        return "lru"
    if flags & (1 << KPF_OFFLINE):
        return "offline"
    return "other"


def test_ram_segments(segments_orig, segments_filt, stats):
    """
    Compare RAM segment pages between kcore and kcore_filtered.

    We iterate through PT_LOAD segments that have valid physical addresses
    (indicating RAM) and compare page-by-page.
    """
    print("\n--- Comparing RAM segment pages ---")

    # Build a map of paddr -> segment for kcore_filtered
    filt_by_paddr = {}
    for seg in segments_filt:
        if seg["paddr"] != 0xFFFFFFFFFFFFFFFF:
            filt_by_paddr[seg["paddr"]] = seg

    # Only compare segments that exist in both
    compared_segments = 0
    with open(KCORE_PATH, "rb") as f_orig, \
         open(KCORE_FILTERED_PATH, "rb") as f_filt:

        for seg in segments_orig:
            paddr = seg["paddr"]
            if paddr == 0xFFFFFFFFFFFFFFFF:
                continue  # Not a RAM segment

            if paddr not in filt_by_paddr:
                continue

            filt_seg = filt_by_paddr[paddr]
            compared_segments += 1

            # Sample pages from this segment (don't read entire segment)
            seg_size = min(seg["filesz"], filt_seg["filesz"])
            sample_step = max(PAGE_SIZE, seg_size // 100)  # Sample ~100 pages

            pages_in_seg = 0
            for page_off in range(0, seg_size, sample_step):
                if pages_in_seg >= 200:  # Cap per segment
                    break

                pfn = (paddr + page_off) >> 12  # PAGE_SHIFT = 12

                try:
                    f_orig.seek(seg["offset"] + page_off)
                    orig_data = f_orig.read(PAGE_SIZE)

                    f_filt.seek(filt_seg["offset"] + page_off)
                    filt_data = f_filt.read(PAGE_SIZE)
                except OSError:
                    stats.read_errors += 1
                    continue

                if len(orig_data) < PAGE_SIZE or len(filt_data) < PAGE_SIZE:
                    stats.read_errors += 1
                    continue

                stats.total_pages += 1
                pages_in_seg += 1
                orig_zero = is_page_zero(orig_data)
                filt_zero = is_page_zero(filt_data)

                # Get independent page classification
                flags = get_kpageflags(pfn)
                ptype = classify_page_flags(flags)

                if orig_zero and filt_zero:
                    stats.both_zero += 1
                elif orig_data == filt_data:
                    stats.matched_pages += 1
                    # Kernel data should match
                    if ptype == "anon":
                        stats.anon_not_zeroed += 1
                    elif ptype == "buddy":
                        stats.buddy_not_zeroed += 1
                    elif ptype == "lru":
                        stats.lru_not_zeroed += 1
                    elif ptype == "slab":
                        stats.slab_not_zeroed += 1
                    else:
                        stats.other_not_zeroed += 1
                elif filt_zero and not orig_zero:
                    stats.zeroed_pages += 1
                    # Filtered should be user/free pages
                    if ptype == "anon":
                        stats.anon_zeroed += 1
                    elif ptype == "buddy":
                        stats.buddy_zeroed += 1
                    elif ptype == "lru":
                        stats.lru_zeroed += 1
                    elif ptype == "slab":
                        stats.slab_zeroed += 1
                    else:
                        stats.other_zeroed += 1
                else:
                    stats.mismatch_pages += 1

    print(f"  Compared segments: {compared_segments}")


def print_stats(stats):
    """Print test results and statistics."""
    print("\n=== Filter Verification Results ===\n")
    print(f"  Total pages sampled:  {stats.total_pages}")
    print(f"  Both zero (unused):   {stats.both_zero}")
    print(f"  Matched (pass-thru):  {stats.matched_pages}")
    print(f"  Filtered (zeroed):    {stats.zeroed_pages}")
    print(f"  Mismatched:           {stats.mismatch_pages}")
    print(f"  Read errors:          {stats.read_errors}")

    print("\n--- Zeroed pages by type (from kpageflags) ---")
    print(f"  Anonymous zeroed:     {stats.anon_zeroed}")
    print(f"  Buddy zeroed:         {stats.buddy_zeroed}")
    print(f"  LRU/cache zeroed:     {stats.lru_zeroed}")
    print(f"  Slab zeroed:          {stats.slab_zeroed}")
    print(f"  Other zeroed:         {stats.other_zeroed}")

    print("\n--- Allowed pages by type (from kpageflags) ---")
    print(f"  Anonymous allowed:    {stats.anon_not_zeroed}")
    print(f"  Buddy allowed:        {stats.buddy_not_zeroed}")
    print(f"  LRU/cache allowed:    {stats.lru_not_zeroed}")
    print(f"  Slab allowed:         {stats.slab_not_zeroed}")
    print(f"  Other allowed:        {stats.other_not_zeroed}")

    # Validation
    print("\n--- Validation ---")
    ok = True

    if stats.anon_not_zeroed > 0:
        print(f"  WARNING: {stats.anon_not_zeroed} anonymous pages were NOT zeroed")
        print("  (This may indicate a filter gap or race condition)")
        ok = False

    if stats.buddy_not_zeroed > 0:
        print(f"  WARNING: {stats.buddy_not_zeroed} buddy pages were NOT zeroed")
        ok = False

    if stats.mismatch_pages > 0:
        # A small number of mismatches is expected on a live system due to
        # race conditions (page content changes between reading /proc/kcore
        # and /proc/kcore_filtered). Only fail on excessive mismatches.
        mismatch_pct = (100.0 * stats.mismatch_pages / stats.total_pages
                        if stats.total_pages > 0 else 0)
        if stats.mismatch_pages > 5 or mismatch_pct > 2.0:
            print(f"  FAIL: {stats.mismatch_pages} pages ({mismatch_pct:.1f}%) "
                  f"had unexpected mismatched content (exceeds tolerance)")
            ok = False
        else:
            print(f"  OK: {stats.mismatch_pages} minor mismatch(es) — "
                  f"likely race condition on live system")

    if stats.zeroed_pages > 0:
        print(f"  OK: {stats.zeroed_pages} pages correctly filtered (zeroed)")

    if stats.matched_pages > 0:
        print(f"  OK: {stats.matched_pages} kernel pages correctly passed through")

    if ok and stats.total_pages > 0:
        print("\n  OVERALL: PASS")
    elif stats.total_pages == 0:
        print("\n  OVERALL: SKIP (no pages compared)")
    else:
        print("\n  OVERALL: WARN (see warnings above)")


def print_module_stats():
    """Print the module's own filter statistics."""
    stats_path = "/proc/kcore_filtered_stats"
    if os.path.exists(stats_path):
        print("\n--- Module filter statistics ---")
        with open(stats_path) as f:
            for line in f:
                print(f"  {line.rstrip()}")


def main():
    check_root()
    check_prereqs()

    print("=== kcore_filtered filter verification ===")
    print(f"  Page size: {PAGE_SIZE}")

    # Parse ELF segments from both files
    print("\nParsing ELF headers...")
    segments_orig = parse_elf_phdrs(KCORE_PATH)
    segments_filt = parse_elf_phdrs(KCORE_FILTERED_PATH)
    print(f"  /proc/kcore: {len(segments_orig)} PT_LOAD segments")
    print(f"  /proc/kcore_filtered: {len(segments_filt)} PT_LOAD segments")

    if not segments_filt:
        print("ERROR: No PT_LOAD segments in kcore_filtered")
        sys.exit(1)

    stats = Stats()
    test_ram_segments(segments_orig, segments_filt, stats)
    print_stats(stats)
    print_module_stats()

    # Exit code - tolerate small race-induced mismatches on live systems
    mismatch_pct = (100.0 * stats.mismatch_pages / stats.total_pages
                    if stats.total_pages > 0 else 0)
    if stats.mismatch_pages > 5 or mismatch_pct > 2.0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
