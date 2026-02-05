# AGENTS.md — Context for AI Coding Assistants

## Project Overview

**kcore_filtered** is a Linux kernel module that creates
`/proc/kcore_filtered` — a privacy-filtered alternative to
`/proc/kcore`. It exposes kernel memory in ELF core format (readable
by drgn, readelf, crash) but redacts user-space pages to zeroes.

**Use case:** Kernel engineers at bare-metal cloud providers who need
drgn-based live kernel introspection on customer systems without
exposing customer data.

## Target Kernel Version

**Linux 6.8 and newer.** All APIs used are stable across 6.5-6.8+.
The module uses `LINUX_VERSION_CODE` guards if any minor differences
surface.

## Build Instructions

```bash
# Build against running kernel
make

# Build against a specific kernel source tree
make KDIR=/path/to/kernel/source

# Run checkpatch.pl linting
make checkpatch

# Run sparse static analysis
make sparse

# Load/unload
sudo insmod kcore_filtered.ko
sudo rmmod kcore_filtered

# Module parameters (adjustable at load time or via sysfs)
sudo insmod kcore_filtered.ko filter_anon=1 filter_cache=1 filter_free=1 filter_slab=0
```

## Architecture

```
kcore_filtered_main.c  — Module init/exit, /proc entry, read_iter handler
page_filter.c/h        — Page classification (anon, cache, slab, free → allow/deny)
elf_core.c/h           — ELF ehdr/phdr/note generation
region.c/h             — RAM/vmalloc/text/vmemmap region discovery
```

### Key Design Decisions

1. **Out-of-tree module** — chosen for deployment speed. Cannot access
   unexported symbols like `kclist_head`, `vread_iter()`,
   `page_offline_freeze()`. See workarounds below.

2. **Page-level filtering** — filters at struct page granularity using
   `PageAnon()`, `PageSlab()`, `is_free_buddy_page()`, etc. This
   eliminates bulk user data but cannot catch user data fragments
   inside kernel slab objects (the "sub-page problem").

3. **Data-minimized, not privacy-safe** — we frame this as reducing
   data exposure by 80-95%, not guaranteeing zero user data leakage.
   See `doc/future-mitigation-layers.md` for the roadmap.

4. **GPL licensed** — required to use `EXPORT_SYMBOL_GPL` APIs and
   to avoid tainting the kernel.

### Unexported Symbol Workarounds

| Symbol | Workaround |
|---|---|
| `kclist_head` / `kclist_lock` | Build own region list in `region.c` |
| `walk_system_ram_range()` | Use `walk_iomem_res_desc(IORES_DESC_NONE, IORESOURCE_SYSTEM_RAM \| IORESOURCE_BUSY, ...)` |
| `vread_iter()` | Use `copy_from_kernel_nofault()` page-by-page for vmalloc |
| `page_offline_freeze/thaw()` | Skip; rely on `PageOffline()` + `copy_from_kernel_nofault()` fault tolerance |
| `vmcoreinfo_data/size` | Use `paddr_vmcoreinfo_note()` to locate physical note, then `phys_to_virt()` + `copy_from_kernel_nofault()` |
| `saved_command_line` | Use `boot_command_line` (exported) |

### Page Filter Policy (defaults)

| Page Type | Detection | Default Action |
|---|---|---|
| Anonymous user | `PageAnon(page)` | DENY (zeroes) |
| Free / buddy | `is_free_buddy_page(page)` | DENY (zeroes) |
| User page cache | `page_mapping()` + `PageLRU()` | DENY (zeroes) |
| Swap-backed | `PageSwapBacked(page)` | DENY (zeroes) |
| Offline / hwpoison | `PageOffline()`, `is_page_hwpoison()` | DENY (zeroes) |
| Slab | `PageSlab(page)` | ALLOW (configurable) |
| Kernel text / vmemmap / vmalloc | Region type | ALLOW |

## Known Limitations

1. **Sub-page problem:** User data copied into kernel slab objects
   (via `copy_from_user`, `memdup_user`, etc.) passes through the
   filter because slab pages are allowed by default. See
   `doc/future-mitigation-layers.md`.

2. **vmalloc read performance:** Without `vread_iter()`, vmalloc reads
   go through `copy_from_kernel_nofault()` page-by-page. Functional
   but slower than the in-tree kcore path.

3. **Race with page offlining:** Without `page_offline_freeze()`, there
   is a tiny window where a page could be offlined after our check.
   `copy_from_kernel_nofault()` handles this gracefully (returns error,
   we serve zeroes).

4. **Region list is static:** Built at module load time. If RAM is
   hot-added/removed after loading, the region list becomes stale.
   Reload the module to refresh.

## Testing

```bash
# Run all tests (requires root, module loaded)
make test

# Individual test scripts
sudo bash tests/test_basic.sh        # Load/unload, ELF validity
sudo python3 tests/test_filter.py    # Filter verification
sudo python3 tests/test_drgn.py      # drgn integration
```

See `tests/README.md` for detailed testing documentation.

## File Layout

```
kcore_filtered/
├── AGENTS.md                        ← you are here
├── LICENSE                          ← GPL-2.0-only
├── Makefile                         ← Kbuild + checkpatch + sparse + test
├── kcore_filtered_main.c            ← Module entry point
├── page_filter.c / page_filter.h    ← Privacy filter logic
├── elf_core.c / elf_core.h          ← ELF core generation
├── region.c / region.h              ← Region discovery
├── doc/
│   ├── original-design.md           ← Full design rationale
│   ├── future-mitigation-layers.md  ← Roadmap for additional controls
│   └── upstream-comparison.md       ← Module vs upstream patch tradeoffs
└── tests/
    ├── README.md                    ← Testing guide
    ├── test_basic.sh                ← Basic functionality tests
    ├── test_filter.py               ← Filter verification tests
    └── test_drgn.py                 ← drgn integration tests
```

## Common Development Tasks

- **Add a new filter rule:** Edit `kcf_classify_page()` in `page_filter.c`
- **Add a new region type:** Edit `region.c` and add a new `KCF_REGION_*` enum
- **Change ELF notes:** Edit `kcf_elf_write_notes()` in `elf_core.c`
- **Add module parameter:** Add `module_param_named()` in the relevant `.c` file
- **Debug filter behavior:** Check `/proc/kcore_filtered_stats` and `dmesg`
