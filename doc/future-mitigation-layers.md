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

## Layer 1: Slab Cache Allow/Deny List

**Status: Implemented**

Instead of an all-or-nothing `filter_slab=1`, operators can specify a
list of slab cache names and choose whether it acts as an allowlist
(only listed caches pass) or denylist (only listed caches are blocked).

### Configuration

Three modes, controlled by module parameters:

```bash
# Default: all slab pages allowed (no list, filter_slab=0)
insmod kcore_filtered.ko

# Catch-all: deny ALL slab pages (overrides any list)
insmod kcore_filtered.ko filter_slab=1

# Allowlist: only these caches pass, deny everything else
insmod kcore_filtered.ko slab_action=allow \
    slab_cache_list=task_struct,dentry,inode_cache,vm_area_struct,mm_struct,signal_cache,files_cache,radix_tree_node,maple_node

# Denylist: only these caches denied, allow everything else
insmod kcore_filtered.ko slab_action=deny \
    slab_cache_list=sk_buff_head,skbuff_fclone_cache
```

Priority hierarchy:
1. `filter_slab=1` — deny all slab (runtime-toggleable kill switch)
2. `slab_cache_list` non-empty — apply list with `slab_action` mode
3. Neither — allow all slab (current default)

`filter_slab` remains runtime-writable (0644) for emergency use.
`slab_action` and `slab_cache_list` are load-time only (0444) to
avoid re-parsing complexity.

### Recommended lists

Allowlist (kernel-internal, needed by drgn):
- `task_struct` — process descriptors
- `dentry` — directory entry cache
- `inode_cache` — filesystem inode cache
- `vm_area_struct` — VMA descriptors
- `mm_struct` — memory descriptors
- `signal_cache` — signal handling structures
- `files_cache` — file descriptor tables
- `radix_tree_node` — radix tree nodes
- `maple_node` — maple tree nodes (6.1+)

Denylist (may contain user data):
- `sk_buff_head`, `skbuff_fclone_cache` — network packet data
- `biovec-*`, `bio-*` — block I/O vectors
- `kmalloc-*` (generic) — mixed user and kernel data

### Implementation

Accesses the `slab_cache` pointer via a minimal two-word struct overlay
on `struct page`. `struct slab` (defined in `mm/slab.h`, not exported)
places `slab_cache` at word 2, stable since Linux 5.17.

The cache name is retrieved via a probed offset: at module init, a
temporary slab cache with a known name is created, the `struct
kmem_cache` is scanned for a pointer to that name, and the offset is
recorded. This avoids depending on `kmem_cache_name()` whose
declaration lives in the internal `mm/slab.h` header (modpost cannot
resolve it for out-of-tree modules). If the probe fails, the slab
list feature gracefully disables itself.

### Performance

When the list is inactive (default or `filter_slab=1`): zero overhead.
When active: ~100ns per slab page for a pointer dereference and linear
`strcmp()` scan. With typical lists of 10-30 entries, this is ~1-3%
of per-page read cost (dominated by `copy_from_kernel_nofault()`).

### Trade-off

More restrictive filtering reduces drgn's ability to inspect some kernel
subsystems. The list must be tuned per use case — the recommended
allowlist above covers the most common drgn debugging targets.

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

**Status: Implemented**

Prevent sustained bulk reading of kernel memory through two
complementary mechanisms: per-session limits and global rate limits.

### Per-Session Controls

- **Session byte budget** (`max_session_bytes`, default: 64 MB):
  Caps the total bytes a single open file descriptor can read.
  Once exhausted, subsequent reads return EOF (0 bytes). The read
  handler clamps each read request to the remaining budget so the
  session ends cleanly without an error.

- **Session time limit** (`max_session_secs`, default: 300s):
  Caps how long a file descriptor remains readable. After the
  deadline, reads return EOF. A normal drgn session typically
  finishes in seconds to a few minutes.

### Global Rate Controls (Cross-Session)

Per-session limits alone are insufficient against an attacker who
opens many short-lived sessions. For example, 100 drgn instances
each reading 5 MB would extract 500 MB without exceeding any
per-session budget. The global controls address this:

- **Open rate limit** (`max_opens_per_min`, default: 10):
  Limits how many times `/proc/kcore_filtered` can be successfully
  opened per 60-second window across all processes. Additional opens
  return `-EBUSY`. This directly throttles the "start many instances"
  pattern.

- **Global byte rate** (`max_global_bytes_per_min`, default: 128 MB):
  Caps the aggregate bytes read by all sessions within a 60-second
  window. When the budget is hit, active sessions receive `-EBUSY`
  on their next read. This limits total data extraction regardless
  of how it is spread across sessions.

Both global controls use a 60-second tumbling window protected by a
spinlock. The window resets (counters zeroed) once 60 seconds have
elapsed since the window start.

### Implementation

Per-session state (`bytes_read`, `open_time`) was already tracked in
`struct kcf_session` for audit logging. Layer 3 adds enforcement
checks at the top of `kcf_read_iter()` before any data is copied.

Global state uses module-level atomics and a spinlock-protected
tumbling window. The open rate check is in `kcf_open()`; the global
byte check is in `kcf_read_iter()`.

All four parameters are runtime-tunable via sysfs:
```bash
echo 0 > /sys/module/kcore_filtered/parameters/max_session_bytes  # disable
echo 33554432 > /sys/module/kcore_filtered/parameters/max_session_bytes  # 32M
```

Rate-limit events emit audit records (`op=rate_limited reason=...`)
and increment counters visible in `/proc/kcore_filtered_stats`:
- `rl_denied_opens` — opens blocked by open rate limit
- `rl_denied_reads` — reads blocked by global byte rate limit
- `rl_sess_expired` — sessions that hit the time limit
- `rl_sess_budget` — sessions that hit the byte budget

### Rapid-Restart Attack Analysis

**Attack:** An adversary with `CAP_SYS_RAWIO` spawns many drgn
processes in rapid succession, each reading a few MB before exiting.
Per-session limits are never triggered because each session stays
within budget.

**Mitigation:** The global open rate (`max_opens_per_min=10`) limits
throughput to 10 sessions/minute. Even if each reads the full 64 MB
budget, the global byte rate (`max_global_bytes_per_min=128M`) caps
aggregate extraction to 128 MB/minute. In practice the two limits
interact: 10 sessions x 64 MB = 640 MB theoretical, but the 128 MB
global byte cap triggers first, blocking further reads even within
active sessions. The attacker cannot extract more than 128 MB per
minute regardless of how many processes they use.

**Detection:** Every rate-limit event generates an audit record.
A spike in `rl_denied_opens` or `rl_denied_reads` counters is a
strong signal of attempted abuse. Monitoring systems can alert on
these counters or on the `op=rate_limited` audit messages.

### Value

Even with perfect page-level filtering, limiting total data exposure
reduces blast radius. A drgn session typically needs to read a few
MB of specific kernel structures, not scan all of RAM. The defaults
(64 MB/session, 128 MB/minute global) are generous enough for
legitimate drgn debugging while making bulk exfiltration impractical.

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
| 1 | Slab allow/deny list (implemented) | User data in denied slab caches |
| 2 | Audit logging (implemented) | Accountability and detection |
| 3 | Rate/time limits (implemented) | Bulk exfiltration risk |
| 4 | Targeted reads (BPF) | Arbitrary kernel memory access |
| 5 | Object-level taint | User data in allowed slab objects |

Each layer independently reduces risk. Layers 0-3 are achievable as
an external module. Layer 4 requires drgn changes. Layer 5 requires
kernel patches.

The deployment path:
1. Start with Layer 0 (this module) — immediate value (**done**)
2. Add Layer 2 (audit logging) — low effort, high compliance value (**done**)
3. Add Layer 3 (rate limiting) — low effort, reduces blast radius (**done**)
4. Add Layer 1 (slab allow/deny list) — moderate effort (**done**)
5. Research Layer 4 (targeted reads) — long-term goal
