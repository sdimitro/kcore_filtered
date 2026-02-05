# Upstream Patch vs. External Module: Comparison

This document compares implementing kcore_filtered as an external
out-of-tree kernel module (current approach) vs. as an upstreamable
patch to `fs/proc/kcore.c` (potential future approach).

## What Gets Easier as an Upstream Patch

### 1. Direct Access to kcore Internals

**Module (current):** Must rebuild the entire region list from scratch
using `walk_iomem_res_desc()`, `_text`/`_end` symbols, and
`VMALLOC_START`/`VMALLOC_END` macros.

**Upstream patch:** Direct access to `kclist_head` and `kclist_lock` —
the existing linked list of `kcore_list` entries that `/proc/kcore`
maintains. Could reuse the existing region list entirely instead of
building a parallel one.

**Effort saved:** ~200 lines of `region.c` become unnecessary.

### 2. vread_iter() for vmalloc

**Module (current):** Must use `copy_from_kernel_nofault()` page-by-page
for vmalloc regions because `vread_iter()` is static/unexported. This is
correct but less efficient — it doesn't understand vmalloc's internal
page table structure.

**Upstream patch:** Could call `vread_iter()` directly, which is the
optimized path that handles vmalloc guard pages, partially-mapped
regions, and other edge cases correctly and efficiently.

**Impact:** vmalloc reads become ~2-3x faster and handle edge cases
that `copy_from_kernel_nofault()` may return zeroes for unnecessarily.

### 3. page_offline_freeze/thaw()

**Module (current):** Cannot call `page_offline_freeze()` /
`page_offline_thaw()` because they're not exported. This means there's
a tiny race window where a page could be offlined between our
`PageOffline()` check and the actual read. We mitigate this with
`copy_from_kernel_nofault()` which handles the fault gracefully.

**Upstream patch:** Could use `page_offline_freeze()` to prevent any
page offlining during the read, eliminating the race entirely. This
is what the existing `/proc/kcore` read path does.

**Impact:** Eliminates a theoretical (but practically very unlikely)
race condition on systems with memory hotplug or balloon drivers.

### 4. vmcoreinfo Access

**Module (current):** Must use `paddr_vmcoreinfo_note()` to get the
physical address of the vmcoreinfo ELF note, then use `phys_to_virt()`
and `copy_from_kernel_nofault()` to read it. This is indirect and
fragile.

**Upstream patch:** Direct access to `vmcoreinfo_data` and
`vmcoreinfo_size` globals. Can memcpy the vmcoreinfo content directly.

**Impact:** Simpler, more robust vmcoreinfo handling. Currently ~40
lines of workaround code become ~5 lines.

### 5. ELF Header Generation

**Module (current):** Must implement ELF header, program header, and
note generation from scratch in `elf_core.c` (~250 lines).

**Upstream patch:** Could modify the existing `read_kcore_iter()`
function to add filtering, reusing all existing ELF generation code.
The patch would be a ~100-line addition to `kcore.c` rather than a
separate module.

**Impact:** Dramatically less code to write and maintain.

### 6. saved_command_line

**Module (current):** Uses `boot_command_line` (exported) as a fallback
for the prpsinfo note. This is close but not identical to
`saved_command_line`.

**Upstream patch:** Direct access to `saved_command_line` for accurate
prpsinfo.

**Impact:** Minor — `boot_command_line` is almost always identical.

## What Gets Harder as an Upstream Patch

### 1. Upstream Acceptance

Submitting to LKML requires:
- Justification for the feature in the commit message
- Review by fs/proc maintainers and mm maintainers
- Potentially contentious discussion about the "false sense of security"
  concern (see sub-page problem in design doc)
- Multiple revision cycles (typical: 3-5 revisions over weeks/months)
- Maintenance burden accepted by the subsystem maintainer

The sub-page limitation could be a significant objection from reviewers
who might argue the feature promises more than it delivers.

### 2. Deployment Timeline

**Module:** Build and deploy immediately on any 6.8+ kernel.
`insmod kcore_filtered.ko` and you're running.

**Upstream patch:** Even if accepted immediately, it wouldn't ship in
a distribution kernel for 6-12 months minimum (merge window → RC
cycle → distro adoption). For enterprise distributions (RHEL, Ubuntu
LTS), it could be 1-2 years.

### 3. Configurability

**Module:** Filter policy is easily adjustable via module parameters.
Different systems can run different policies. Operators can tune
`filter_slab=1` on high-sensitivity systems and `filter_slab=0`
on internal systems.

**Upstream patch:** Would need to use kernel boot parameters or sysctl
for configuration. The interface must be more carefully designed for
ABI stability. Reviewers may push back on too many tunables.

### 4. Iteration Speed

**Module:** Change code → `make` → `rmmod` → `insmod` → test.
Full cycle in seconds.

**Upstream patch:** Change code → full kernel build → reboot → test.
Even with ccache, this is minutes per iteration.

### 5. Testing on Customer Systems

**Module:** Can be loaded on a customer system for testing without any
system modification. Remove it and no trace remains.

**Upstream patch:** Requires either a custom kernel build or waiting
for the distro to ship it. Cannot easily A/B test.

## What Would Be Architecturally Different

### Approach A: Modify kcore.c Directly (Minimal Patch)

Add the filtering logic as a new mode within the existing
`read_kcore_iter()` function:

```c
/* In read_kcore_iter(), for KCORE_RAM pages: */
case KCORE_RAM:
    pfn = __pa(start) >> PAGE_SHIFT;
    page = pfn_to_online_page(pfn);

    if (!page || PageOffline(page) || is_page_hwpoison(page) ||
        !pfn_is_ram(pfn)) {
        /* existing zeroing logic */
        break;
    }

    /* NEW: privacy filter for kcore_filtered */
    if (is_filtered && should_filter_page(page)) {
        if (iov_iter_zero(tsz, iter) != tsz) { ... }
        break;
    }

    /* existing read-through logic */
    fallthrough;
```

This would require:
- A new `/proc/kcore_filtered` entry that sets a flag
- A `should_filter_page()` function (~50 lines)
- Sysctl or boot param for filter policy
- ~150 lines total added to `fs/proc/kcore.c`

### Approach B: New File (kcore_filtered.c in fs/proc/)

Create a separate file that imports from kcore.c:

- Export `kclist_head`, `kclist_lock` from kcore.c
- Create `fs/proc/kcore_filtered.c` with filtering read handler
- Share ELF generation code

This is cleaner but requires exporting currently-static symbols,
which maintainers may resist.

### Approach C: Factor Out Common Code

Refactor kcore.c to separate the ELF generation and memory reading
logic from the procfs entry management:

- `kcore_common.c` — ELF headers, region management, memory read
- `kcore.c` — unfiltered `/proc/kcore`
- `kcore_filtered.c` — filtered version

This is the cleanest architecture but the largest patch, making
upstream acceptance harder.

## Happy Case

**Short term (now):** Continue with the external module. It provides
immediate value, iterates fast, and can be deployed on existing systems.

**Medium term (6-12 months):** Once the module is proven in production
and the filter policy is stable, prepare an upstream patch using
Approach A (minimal modification to kcore.c). The production experience
strengthens the justification for upstream acceptance.

**Long term:** If upstream accepts the feature, the external module
continues to serve as a backport vehicle for older kernels that won't
receive the upstream change.

## Summary Table

| Aspect | External Module | Upstream Patch |
|---|---|---|
| Time to deploy | Minutes | 6-24 months |
| Code complexity | Higher (workarounds) | Lower (direct access) |
| Maintenance burden | On us | Shared with maintainers |
| vmalloc read path | Slower (page-by-page) | Faster (vread_iter) |
| Region discovery | Rebuilt from scratch | Reuses kclist |
| vmcoreinfo access | Indirect (phys addr) | Direct (global) |
| Configurability | Module params | Sysctl/boot params |
| Iteration speed | Fast (insmod) | Slow (reboot) |
| Customer testing | Easy (load/unload) | Hard (custom kernel) |
| Race conditions | Tiny window (no freeze) | None (page_offline_freeze) |
| Upstream acceptance | N/A | Uncertain |
