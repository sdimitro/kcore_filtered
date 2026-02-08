# Future Mitigation Layers

This document describes additional privacy controls that can be layered
on top of kcore_filtered's page-level filtering. These address residual
risks — particularly user data fragments inside slab allocations — and
move the system from "data-minimized" toward "privacy-hardened."

## Layer 0: Page-Level Filtering (Current Implementation)

**Status: Implemented**

The base layer. Filters out:
- Anonymous user pages (heap, stack, mmap)
- User file-backed page cache
- Free buddy pages (residual data)
- Swap-backed pages
- Offline/hwpoison pages

**Residual risk:** User data in slab objects, network buffers, and
kernel-allocated copies of user data.

## Layer 1: Slab Cache Allowlisting

**Status: Planned**

Instead of allowing all slab pages through (the current default), maintain
an allowlist of specific `kmem_cache` names that are known to contain
only kernel-internal data. Block all others.

### Approach

Each slab page belongs to a specific `kmem_cache`. The cache name
identifies what type of objects it holds (e.g., `task_struct`,
`dentry`, `inode_cache`, `sk_buff`).

An allowlist might include:
- `task_struct` — process descriptors (needed by drgn)
- `dentry` — directory entry cache
- `inode_cache` — filesystem inode cache
- `vm_area_struct` — VMA descriptors
- `mm_struct` — memory descriptors
- `signal_cache` — signal handling structures
- `files_cache` — file descriptor tables
- `radix_tree_node` — radix tree nodes
- `maple_node` — maple tree nodes (6.1+)
- `kmalloc-cg-*` — cgroup-tracked allocations (mixed, may need
  sub-filtering)

Caches to deny/filter:
- `sk_buff_head`, `skbuff_fclone_cache` — network packet data
- `biovec-*`, `bio-*` — block I/O vectors (may contain user data refs)
- `kmalloc-*` (generic) — mixed user and kernel data

### Implementation

```c
static bool is_allowed_slab_cache(struct page *page)
{
    struct slab *slab = page_slab(page);
    const char *name = slab->slab_cache->name;
    /* Check against allowlist */
}
```

**Challenge:** `page_slab()` / `slab_cache` access from a module requires
careful handling. The `struct slab` definition may not be fully exported.

### Trade-off

More restrictive filtering reduces drgn's ability to inspect some kernel
subsystems. The allowlist must be tuned per use case.

## Layer 2: Audit Logging

**Status: Implemented**

Logs every open and close of `/proc/kcore_filtered` to the kernel audit
subsystem using `AUDIT_KERNEL` (type 2000) records.

### What is logged

All records include full task identity via `audit_log_task_info()`:
- `ppid`, `pid` — parent and process PID
- `auid` — audit login UID (the original user who logged in, survives
  `sudo`/`su`)
- `uid`, `gid`, `euid`, `suid`, `fsuid`, `egid`, `sgid`, `fsgid` —
  full credential set
- `tty` — controlling terminal
- `ses` — audit session ID
- `comm` — process command name (e.g., `drgn`, `dd`, `cat`)
- `exe` — full path to the executable (e.g., `/usr/bin/drgn`)
- `subj` — LSM security context (if SELinux/AppArmor is active)

**On open (`op=open`):**
- Identity fields above, logged when a process successfully opens
  `/proc/kcore_filtered`

**On close (`op=close`):**
- Identity fields above, plus:
- `bytes_read` — total bytes read during the session
- `duration_ms` — how long the file was held open (milliseconds)

**On denied access (`op=denied`):**
- Identity fields above, logged when a process without `CAP_SYS_RAWIO`
  attempts to open the file

### Configuration

Controlled by the `audit` module parameter (default: on):

```bash
insmod kcore_filtered.ko audit=1    # default, emit audit records
insmod kcore_filtered.ko audit=0    # disable audit logging
echo 0 > /sys/module/kcore_filtered/parameters/audit  # runtime toggle
```

### Viewing audit records

When `auditd` is running, records appear in `/var/log/audit/audit.log`:

```bash
ausearch -m UNKNOWN[2000] -i | grep kcore_filtered
```

When `auditd` is not running, records go to the kernel log (dmesg):

```bash
dmesg | grep "kcore_filtered op="
```

### Value

Even if some data leaks through the filter, audit logging ensures
accountability. Combined with access controls, this creates a
compliance-friendly posture: "we minimize data exposure AND log all
access."

## Layer 3: Rate Limiting and Time-Limited Access

**Status: Planned**

Prevent sustained bulk reading of kernel memory:

- **Rate limit:** Cap the read rate (e.g., 100 MB/s) to prevent
  rapid bulk exfiltration
- **Time limit:** Auto-close the file descriptor after N seconds
  or minutes
- **Read budget:** Limit total bytes readable per session

### Implementation

Track bytes read and elapsed time in `struct file->private_data`.
Enforce limits in the `read_iter` handler.

### Value

Even with perfect filtering, limiting the total data exposure window
reduces risk. A drgn session typically needs to read a few MB of
specific kernel structures, not scan all of RAM.

## Layer 4: Targeted Read Mode (BPF-Based)

**Status: Research Phase**

Instead of exposing a full kcore-style interface, provide a targeted
read API where the caller specifies *what* kernel data structures they
want to read, and the module validates the request against a policy.

### Concept

```
write(fd, "read task_struct init_task", ...)  →  returns task_struct data
write(fd, "read mm_struct 0xffff...", ...)    →  validated, returns data
write(fd, "read arbitrary 0xdead...", ...)    →  DENIED
```

### Implementation Options

1. **BPF program** — attach a BPF program that validates read targets
   against a policy (type-aware filtering)
2. **BTF-aware filtering** — use BTF type information to understand
   what a pointer points to and only allow reads of known-safe types
3. **drgn backend plugin** — modify drgn to use a custom read backend
   that requests specific typed objects instead of raw memory ranges

### Value

This is the long-term vision. Instead of "filter out the bad pages,"
it becomes "only allow reads of known-good objects." This provides
much stronger guarantees but requires significant drgn modifications.

## Layer 5: Per-Slab-Object Tainting

**Status: Speculative / Requires Kernel Patches**

Tag individual slab objects that contain user-provided data (from
`copy_from_user`, `strncpy_from_user`, etc.) so the filter can
redact them even within an allowed slab cache.

### Concept

Instrument `copy_from_user()` and friends to mark the destination
slab object (or memory range) as "user-tainted." The kcore filter
would then check this taint before serving data.

### Challenges

- Requires in-tree kernel patches (not feasible as a module)
- Performance overhead of tainting every `copy_from_user` call
- Taint tracking across `memcpy` and other copies
- Memory overhead for per-object metadata

### Value

Addresses the sub-page problem completely, but at significant
complexity and performance cost. Likely only viable as an upstream
feature with careful design.

## Summary: Defense in Depth

| Layer | Control | Addresses |
|---|---|---|
| 0 | Page-level filtering (implemented) | Bulk user data (anon, cache, free) |
| 1 | Slab allowlisting | User data in denied slab caches |
| 2 | Audit logging (implemented) | Accountability and detection |
| 3 | Rate/time limits | Bulk exfiltration risk |
| 4 | Targeted reads (BPF) | Arbitrary kernel memory access |
| 5 | Object-level taint | User data in allowed slab objects |

Each layer independently reduces risk. Layers 0-3 are achievable as
an external module. Layer 4 requires drgn changes. Layer 5 requires
kernel patches.

The deployment path:
1. Start with Layer 0 (this module) — immediate value (**done**)
2. Add Layer 2 (audit logging) — low effort, high compliance value (**done**)
3. Add Layer 3 (rate limiting) — low effort, reduces blast radius
4. Investigate Layer 1 (slab allowlisting) — moderate effort
5. Research Layer 4 (targeted reads) — long-term goal
