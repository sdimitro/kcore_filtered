# Dynamic Region List: Research and Approaches

## Problem

The `kcore_filtered` module builds its memory region list once at
`module_init` time in `kcf_regions_init()`. This list includes system
RAM ranges (discovered via `walk_iomem_res_desc()`), kernel text,
vmalloc, modules, and vmemmap regions. If physical RAM is hotplugged
(added or removed) after the module loads, the region list becomes
stale: new RAM is invisible to the filtered kcore, and removed RAM may
produce read errors.

The upstream `/proc/kcore` in `fs/proc/kcore.c` does not have this
problem because it has direct access to `kclist_head` (the
authoritative region list) and `kclist_lock` (the percpu rwsem
protecting it), neither of which is exported to modules. Upstream
also registers a memory hotplug notifier (`kcore_callback`) that sets
a `kcore_need_update` flag and lazily rebuilds the RAM portion of the
list on the next `open_kcore()` call.

## Approaches Evaluated

### 1. Memory Hotplug Notifier (`register_memory_notifier`)

**How it works:** The kernel provides a blocking notifier chain called
`memory_chain` in `mm/memory_hotplug.c`. A module registers a
`struct notifier_block` via `register_memory_notifier()` and receives
callbacks on `MEM_ONLINE` and `MEM_OFFLINE` events. The callback
includes a `struct memory_notify` with the affected `start_pfn` and
`nr_pages`. This is exactly the mechanism upstream `/proc/kcore` uses.

**API export status:** `register_memory_notifier()` and
`unregister_memory_notifier()` are both `EXPORT_SYMBOL_GPL`. When
`CONFIG_MEMORY_HOTPLUG` is disabled, they become static inline no-ops.
Fully available to our GPL module.

**Performance:** Negligible. The notifier callback only sets a flag.
Memory hotplug events are rare (seconds to minutes apart at most).

**Complexity:** Low. Mirrors the upstream pattern exactly.

**Verdict:** Best option. Solves the problem for RAM regions, which
are the only regions that change with hotplug (text, vmalloc, modules,
and vmemmap ranges are compile-time constants or boot-time setup).

### 2. Rebuild Region List on Every Open

**How it works:** Instead of maintaining a persistent global list, call
`kcf_regions_init()` inside `kcf_open()` and store the list in the
per-session `kcf_session` struct. Free it in `kcf_release()`.

**API export status:** All APIs already used. No new dependencies.

**Performance:** Moderate. `walk_iomem_res_desc()` acquires the
resource lock per iteration of the iomem tree. On large NUMA machines,
this can mean hundreds of lock cycles and `kmalloc()` calls per open.
For the typical drgn use case (one open per session), this is
negligible. The rate limiter (`max_opens_per_min`) already bounds
pathological patterns.

**Complexity:** Medium. The core problem is ELF inode size coherence:
`proc_set_size()` sets a single `i_size` on the inode, but with
per-session lists, concurrent opens with different region counts would
see inconsistent sizes. Upstream avoids this by maintaining a single
global list.

**Verdict:** Workable but fragile. The inode-size coherence issue makes
this an inferior choice compared to the lazy-rebuild approach.

### 3. Lazy iomem Re-walk on Open (Combined with Notifier)

**How it works:** Keep the global region list and ELF layout, but add
a dirty flag. When the memory notifier fires, set the flag. On the
next `kcf_open()`, check the flag and rebuild the list under the
write lock, then update the inode size atomically.

**API export status:** `walk_iomem_res_desc()` is `EXPORT_SYMBOL_GPL`.
Safe to call from the open path (process context, sleepable).

**Performance:** Excellent. Zero overhead when no hotplug has occurred
(just an `atomic_read`). The rebuild only happens once per hotplug
event, not on every open.

**Locking:** Build a new list into a local `LIST_HEAD`, then swap it
into the global `region_list` under `write_lock(&region_lock)`. The
`atomic_xchg()` pattern under the write lock prevents the
double-rebuild race where two CPUs both see the dirty flag and race
to rebuild.

**Complexity:** Low-medium. This is the exact upstream pattern adapted
for out-of-tree use.

**Verdict:** Recommended when combined with Approach 1.

### 4. Kallsyms / Kprobes to Access `kclist_head`

**How it works:** Use the kprobe trick to recover
`kallsyms_lookup_name()` (unexported since 5.7), then look up
`kclist_head` by name to read the upstream region list directly.

**API export status:** `register_kprobe()` is `EXPORT_SYMBOL_GPL`.
`kallsyms_lookup_name()` itself is NOT exported since kernel 5.7
(commit `0bd476e6c671`). The kprobe trick works because
`register_kprobe()` internally resolves symbols via kallsyms.

**Complexity:** Very high. Multiple problems:
- `kclist_head` is a static variable that may not appear in
  `/proc/kallsyms` depending on `CONFIG_KALLSYMS_ALL`.
- Even if found, you also need `kclist_lock` (a static percpu rwsem).
  You must find its address AND use the correct percpu_rwsem API.
- `struct kcore_list` is not part of any stable API; its layout could
  change without notice.
- This is explicitly the pattern the kernel community wanted to
  prevent when they unexported `kallsyms_lookup_name()`.
- Distributions may blacklist this technique.
- Every kernel version bump requires re-verification.

**Verdict:** Not recommended. Unacceptable maintenance burden and
stability risk for production code.

### 5. Upstream Integration

**How it works:** If kcore_filtered's privacy filtering were merged
into `fs/proc/kcore.c`, it would have direct access to `kclist_head`,
`kclist_lock`, `kcore_update_ram()`, and the existing hotplug
notifier. The filtering logic would be a modification to
`read_kcore_iter()` in the `KCORE_RAM` case.

**Pros:**
- No region discovery duplication
- No stale list bugs
- No API export concerns
- Benefits from upstream testing and maintenance

**Cons:**
- Requires upstream acceptance (kernel community review)
- Longer timeline tied to kernel release cycles
- Potentially more conservative filtering defaults

**Verdict:** The ideal long-term solution, but requires upstream
community engagement and a longer deployment timeline. The out-of-tree
module with the hotplug notifier approach is the right bridge.

### 6. Other Memory Topology Change Sources

The `memory_chain` notifier (Approach 1) is the primary mechanism.
Other related subsystems:

- **`get_online_mems()` / `put_online_mems()`**: Provide reader-side
  locking against hotplug, exported as GPL. Could be used in the read
  path to block hotplug during reads, but this is heavy-handed
  (blocks system-wide hotplug for the duration of a drgn session,
  which could be 5 minutes).

- **Virtio-mem, balloon drivers, etc.:** All go through the standard
  hotplug path and fire the `memory_chain` notifier. No separate
  handling needed.

- **iomem resource tree changes:** There is no general notifier for
  resource tree changes, but for System RAM specifically, resource
  tree updates happen as part of the hotplug path, so the memory
  notifier covers it.

**Verdict:** `register_memory_notifier()` alone covers all standard
memory hotplug scenarios. No supplementary mechanism is needed.

## Recommended Solution

Combine Approach 1 (memory hotplug notifier) with Approach 3 (lazy
rebuild on open), mirroring the upstream `/proc/kcore` pattern:

```c
static atomic_t kcf_need_update = ATOMIC_INIT(0);

static int kcf_memory_callback(struct notifier_block *self,
                               unsigned long action, void *arg)
{
    if (action == MEM_ONLINE || action == MEM_OFFLINE)
        atomic_set(&kcf_need_update, 1);
    return NOTIFY_OK;
}

static struct notifier_block kcf_mem_nb = {
    .notifier_call = kcf_memory_callback,
};
```

In `kcf_open()`, after permission and rate-limit checks:

```c
if (atomic_read(&kcf_need_update)) {
    write_lock(&region_lock);
    if (atomic_xchg(&kcf_need_update, 0)) {
        LIST_HEAD(new_list);
        int ret = kcf_regions_init(&new_list);
        if (ret == 0) {
            LIST_HEAD(old_list);
            list_splice_init(&region_list, &old_list);
            list_splice(&new_list, &region_list);
            int nr = kcf_regions_count(&region_list);
            elf_file_size = kcf_elf_compute_layout(
                &region_list, nr, &elf_layout);
            proc_set_size(proc_entry, elf_file_size);
            write_unlock(&region_lock);
            kcf_regions_free(&old_list);
        } else {
            /* Rebuild failed; re-arm so next open retries */
            atomic_set(&kcf_need_update, 1);
            write_unlock(&region_lock);
            kcf_regions_free(&new_list);
        }
    } else {
        write_unlock(&region_lock);
    }
}
```

Register in init, unregister in exit:

```c
register_memory_notifier(&kcf_mem_nb);   /* in kcf_init() */
unregister_memory_notifier(&kcf_mem_nb); /* in kcf_exit() */
```

### Properties

- **All APIs are GPL-exported** and officially supported.
- **Zero overhead** when no hotplug occurs (one `atomic_read` per
  open).
- **Correctness:** The `atomic_xchg` under the write lock prevents
  double-rebuild races.
- **Read path unchanged:** Continues to use `read_lock(&region_lock)`.
- **Graceful degradation:** When `CONFIG_MEMORY_HOTPLUG` is disabled,
  `register_memory_notifier()` is a no-op and the flag is never set.

## Summary

| Approach | Exported APIs? | Performance | Complexity | Fully Solves? | Recommended? |
|---|---|---|---|---|---|
| 1. Hotplug notifier | Yes (GPL) | Excellent | Low | Yes | **Yes** |
| 2. Rebuild on every open | Yes (GPL) | Good | Medium | Partially | No |
| 3. Lazy re-walk on open | Yes (GPL) | Excellent | Low-Med | Yes (with #1) | **Yes (with #1)** |
| 4. Kallsyms/kprobes | Partially | Excellent | Very High | Technically | **No** |
| 5. Upstream integration | N/A | Excellent | Low | Completely | Long-term goal |
| 6. Other notifier chains | Yes (GPL) | Varies | Low-Med | Same as #1 | #1 suffices |
