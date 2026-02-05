# kcore_filtered: Original Design Document

## Problem Statement

At bare-metal cloud providers, kernel engineers need to inspect live
customer kernels for debugging, performance analysis, and fleet-wide
diagnostics. The standard tool for this is **drgn**, a Python-based
debugger that reads kernel memory through `/proc/kcore`.

The problem: `/proc/kcore` is a full ELF core file that exposes *all*
physical RAM — including user process memory. On a customer system this
means drgn can read:

- Process heap, stack, and anonymous memory (user data)
- Page cache (file contents recently accessed by user processes)
- Free pages (may contain residual user data)
- Kernel memory (the data we actually need)

From a privacy and compliance standpoint, reading user process memory
on a customer system is unacceptable, even if the operator's intent is
only to inspect kernel data structures. The mere capability to read
user data creates compliance exposure.

## Inspiration: makedumpfile

`makedumpfile` is a userspace utility that filters kernel crash dumps.
It classifies pages by examining `struct page` flags and the vmcoreinfo
metadata to determine which pages contain:

1. **Kernel pages** — keep these (they contain the crash data we need)
2. **User pages** — filter these out (reduce dump size and avoid
   exposing sensitive data)
3. **Free pages** — filter these out (no useful crash data, may contain
   residual sensitive data)
4. **Cache pages** — optionally filter (file contents, may be large)

makedumpfile uses dump levels (1-31) to control what gets filtered.
Level 31 produces the smallest dump containing only kernel pages.

## Design: /proc/kcore_filtered

We apply makedumpfile's classification logic *inside the kernel* to
create a new procfs entry, `/proc/kcore_filtered`, that is structurally
identical to `/proc/kcore` (same ELF format, same virtual address layout)
but returns **zeroes** for any page classified as user/sensitive data.

### Why In-Kernel?

Unlike makedumpfile which runs in userspace and parses vmcoreinfo to
understand page flags, our filter runs in-kernel with direct access to
`struct page` flags. This means:

- No vmcoreinfo parsing — we call `PageAnon()`, `PageSlab()` directly
- Lower overhead — no intermediate dump to filter
- Same tool compatibility — drgn sees a valid ELF core, just with
  some pages zeroed out
- Real-time — always reflects current kernel state

### Why a Module?

Building as a loadable kernel module (`.ko`) rather than patching
`/proc/kcore` directly provides:

- **Easier deployment** — `insmod` on existing kernels, no reboot
- **Faster iteration** — rebuild and reload without kernel compilation
- **Safer rollout** — can be loaded/unloaded without system disruption
- **Wider compatibility** — single module binary can work across
  minor kernel versions

## Architecture

### Memory Region Discovery

Since the internal `kclist_head` (the list of memory regions that
`/proc/kcore` exposes) is not exported, the module builds its own
region list:

- **System RAM** — discovered via `walk_iomem_res_desc()` iterating
  the iomem resource tree for `IORESOURCE_SYSTEM_RAM` ranges
- **Kernel text** — `_text` to `_end` symbols (arch-dependent)
- **vmalloc** — `VMALLOC_START` to `VMALLOC_END`
- **vmemmap** — computed from RAM ranges using `pfn_to_page()`
- **Module region** — `MODULES_VADDR` to `MODULES_END` if separate

### ELF Core Format

The output is a valid ELF64 core file:

```
┌──────────────────┐  offset 0
│ ELF Header       │  (ehdr)
├──────────────────┤  offset sizeof(ehdr)
│ Program Headers  │  PT_NOTE + N × PT_LOAD
├──────────────────┤
│ Note Segment     │  PRSTATUS + PRPSINFO + VMCOREINFO
├──────────────────┤  page-aligned
│ Data Segments    │  Memory contents (filtered)
└──────────────────┘
```

Each PT_LOAD segment maps a kernel virtual address range to a file
offset. When drgn (or readelf) reads data from a PT_LOAD segment, the
module's read handler serves the actual memory content — unless the
page is classified as sensitive, in which case zeroes are returned.

### Page Classification Taxonomy

For each page in a `KCORE_RAM` region, we examine the `struct page`
flags:

| Page Type | Detection | Action | Rationale |
|---|---|---|---|
| Anonymous user | `PageAnon(page)` | DENY → zeroes | User heap, stack, mmap |
| Free / buddy | `is_free_buddy_page(page)` | DENY → zeroes | May contain residual data |
| User page cache | `page_mapping()` + `PageLRU()` | DENY → zeroes | User file contents |
| Swap-backed | `PageSwapBacked(page)` | DENY → zeroes | User data headed to swap |
| Offline / hwpoison | `PageOffline()`, `is_page_hwpoison()` | DENY → zeroes | Unsafe to read |
| Slab | `PageSlab(page)` | **ALLOW** (default) | Kernel objects — needed by drgn |
| Kernel text | Region = TEXT | ALLOW | Kernel code |
| vmemmap | Region = VMEMMAP | ALLOW | struct page metadata |
| vmalloc | Region = VMALLOC | ALLOW | Module text, kernel buffers |
| Other kernel | Default | ALLOW | Kernel data structures |

### Module Parameters

Filter behavior is tunable at load time or runtime via sysfs:

- `filter_anon=1` — filter anonymous pages (default: on)
- `filter_cache=1` — filter user page cache (default: on)
- `filter_free=1` — filter free pages (default: on)
- `filter_slab=0` — filter slab pages (default: off)

These allow operators to adjust the privacy/utility tradeoff. For
example, setting `filter_slab=1` provides stronger privacy at the
cost of losing visibility into kernel slab objects.

## The Sub-Page Problem

There is an important limitation here! Page-level filtering
cannot catch user data that lives *within* kernel pages. For example:

- `copy_from_user()` data stored in slab objects
- User-provided strings (`strndup_user()`) in kernel allocations
- Network packet payloads in `sk_buff` slab caches
- Filesystem buffers with user file content

Fundamentally, a single slab page may contain dozens of `kmalloc`
allocations, some holding user data and some holding kernel
metadata. There is no page flag that distinguishes these.

### Our Position

We frame this project as **data-minimized kcore**, not **privacy-safe
kcore**. The goals are:

1. **Eliminate bulk user data exposure** — anonymous pages, page cache,
   and free pages represent the vast majority of user data in RAM.
   Filtering these removes 80-95% of sensitive data.

2. **Document residual risks** — acknowledge that slab-resident user
   data fragments exist and document them clearly.

3. **Layer additional mitigations** — see `future-mitigation-layers.md`
   for the roadmap of additional controls.

4. **Enable compliant operation** — the combination of data minimization,
   access controls (CAP_SYS_RAWIO), audit logging, and documented
   scope makes this usable under most compliance frameworks.

## Permission Model

- `/proc/kcore_filtered` is created with mode `0400` (root read-only)
- Opening requires `CAP_SYS_RAWIO` (same as `/proc/kcore`)
- Respects kernel lockdown mode

## Statistics and Observability

`/proc/kcore_filtered_stats` provides real-time counters:

- Pages allowed (served with real data)
- Pages denied by category (anon, cache, free, offline, swapbacked)
- Pages skipped (not online/valid)

This allows operators to verify the filter is working and understand
the data exposure profile of a given system.
