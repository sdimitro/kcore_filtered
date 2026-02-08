// SPDX-License-Identifier: GPL-2.0-only
/*
 * Privacy-filtered /proc/kcore alternative
 *
 * Creates /proc/kcore_filtered, an ELF core file interface identical
 * in format to /proc/kcore but with page-level privacy filtering.
 * User process pages (anonymous, page cache, free) are redacted to
 * zeroes while kernel data structures remain readable.
 *
 * Designed for use with drgn and similar kernel introspection tools
 * on production systems where reading arbitrary user memory via
 * /proc/kcore is not acceptable from a privacy/compliance standpoint.
 *
 * Target: Linux v6.8+
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/uio.h>
#include <linux/capability.h>
#include <linux/security.h>
#include <linux/vmalloc.h>
#include <linux/audit.h>
#include <linux/ktime.h>
#include <linux/sched.h>
#include <asm/io.h>
#include <asm/page.h>

#include "region.h"
#include "elf_core.h"
#include "page_filter.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("kcore_filtered contributors");
MODULE_DESCRIPTION("Privacy-filtered /proc/kcore alternative for safe kernel introspection");
MODULE_VERSION("0.1.0");

static bool kcf_audit = true;
module_param_named(audit, kcf_audit, bool, 0644);
MODULE_PARM_DESC(audit, "Emit audit records on open/close (default: Y)");

/* Layer 3: Rate limiting and time-limited access */
static unsigned long kcf_max_session_bytes = 64UL * 1024 * 1024;
module_param_named(max_session_bytes, kcf_max_session_bytes, ulong, 0644);
MODULE_PARM_DESC(max_session_bytes,
	"Max bytes readable per session, 0=unlimited (default: 64M)");

static unsigned int kcf_max_session_secs = 300;
module_param_named(max_session_secs, kcf_max_session_secs, uint, 0644);
MODULE_PARM_DESC(max_session_secs,
	"Max session duration in seconds, 0=unlimited (default: 300)");

static unsigned int kcf_max_opens_per_min = 10;
module_param_named(max_opens_per_min, kcf_max_opens_per_min, uint, 0644);
MODULE_PARM_DESC(max_opens_per_min,
	"Max opens per minute globally, 0=unlimited (default: 10)");

static unsigned long kcf_max_global_bytes_per_min = 128UL * 1024 * 1024;
module_param_named(max_global_bytes_per_min, kcf_max_global_bytes_per_min,
	ulong, 0644);
MODULE_PARM_DESC(max_global_bytes_per_min,
	"Max bytes read per minute globally, 0=unlimited (default: 128M)");

/*
 * Global rate-limit window. Tracks opens and bytes read across all
 * sessions within a 60-second tumbling window. This is the cross-session
 * component of Layer 3 — it prevents an attacker from circumventing
 * per-session limits by rapidly opening many short-lived sessions.
 */
static DEFINE_SPINLOCK(rate_lock);
static ktime_t rate_window_start;
static unsigned int rate_window_opens;
static unsigned long rate_window_bytes;

/* Rate-limit statistics */
static atomic64_t kcf_rl_denied_opens = ATOMIC64_INIT(0);
static atomic64_t kcf_rl_denied_reads = ATOMIC64_INIT(0);
static atomic64_t kcf_rl_sessions_expired = ATOMIC64_INIT(0);
static atomic64_t kcf_rl_sessions_budget = ATOMIC64_INIT(0);

/* Forward declaration — defined after audit helpers */
static void kcf_audit_rate_limited(const char *reason);

/* Must be called with rate_lock held */
static void kcf_rate_check_window(void)
{
	s64 elapsed = ktime_ms_delta(ktime_get(), rate_window_start);

	if (elapsed >= 60000) {
		rate_window_start = ktime_get();
		rate_window_opens = 0;
		rate_window_bytes = 0;
	}
}

/*
 * Per-file session state. Tracks the bounce buffer, read metrics
 * for audit logging on close, and rate-limit state.
 */
struct kcf_session {
	char *bounce_buf;
	ktime_t open_time;
	size_t bytes_read;
	bool limit_logged;	/* avoids spamming audit on repeated reads */
};

/* Virtual address <-> file offset conversion, matching kcore.c */
#ifndef kc_vaddr_to_offset
#define kc_vaddr_to_offset(v) ((v) - PAGE_OFFSET)
#endif
#ifndef kc_offset_to_vaddr
#define kc_offset_to_vaddr(o) ((o) + PAGE_OFFSET)
#endif

/* Module state */
static struct proc_dir_entry *proc_entry;
static LIST_HEAD(region_list);
static DEFINE_RWLOCK(region_lock);
static struct kcf_elf_layout elf_layout;
static size_t elf_file_size;

/*
 * Read handler for /proc/kcore_filtered.
 *
 * This mirrors the structure of read_kcore_iter() from fs/proc/kcore.c
 * but adds per-page privacy filtering for KCORE_RAM regions and uses
 * only exported kernel APIs.
 */
static ssize_t kcf_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	struct file *file = iocb->ki_filp;
	struct kcf_session *sess = file->private_data;
	char *bounce_buf = sess->bounce_buf;
	loff_t *fpos = &iocb->ki_pos;
	size_t buflen = iov_iter_count(iter);
	size_t orig_buflen;
	struct kcf_region *m;
	unsigned long start;
	size_t tsz;
	size_t bytes_read;
	int ret = 0;

	/* Layer 3: session time limit */
	if (kcf_max_session_secs > 0) {
		s64 elapsed_ms = ktime_ms_delta(ktime_get(), sess->open_time);

		if (elapsed_ms > (s64)kcf_max_session_secs * 1000) {
			if (!sess->limit_logged) {
				sess->limit_logged = true;
				atomic64_inc(&kcf_rl_sessions_expired);
				kcf_audit_rate_limited("session_expired");
			}
			return 0;
		}
	}

	/* Layer 3: session byte budget — clamp read to remaining budget */
	if (kcf_max_session_bytes > 0) {
		if (sess->bytes_read >= kcf_max_session_bytes) {
			if (!sess->limit_logged) {
				sess->limit_logged = true;
				atomic64_inc(&kcf_rl_sessions_budget);
				kcf_audit_rate_limited("budget_exhausted");
			}
			return 0;
		}
		if (buflen > kcf_max_session_bytes - sess->bytes_read)
			buflen = kcf_max_session_bytes - sess->bytes_read;
	}

	/* Layer 3: global byte rate limit */
	if (kcf_max_global_bytes_per_min > 0) {
		spin_lock(&rate_lock);
		kcf_rate_check_window();
		if (rate_window_bytes >= kcf_max_global_bytes_per_min) {
			spin_unlock(&rate_lock);
			atomic64_inc(&kcf_rl_denied_reads);
			return -EBUSY;
		}
		spin_unlock(&rate_lock);
	}

	orig_buflen = buflen;

	read_lock(&region_lock);

	/* ELF file header */
	ret = kcf_elf_write_ehdr(iter, fpos, &buflen, &elf_layout);
	if (ret || !buflen)
		goto out;

	/* ELF program headers */
	ret = kcf_elf_write_phdrs(iter, fpos, &buflen, &elf_layout,
				  &region_list);
	if (ret || !buflen)
		goto out;

	/* ELF note segment */
	ret = kcf_elf_write_notes(iter, fpos, &buflen, &elf_layout);
	if (ret || !buflen)
		goto out;

	/*
	 * Data segment: serve memory contents for each PT_LOAD region.
	 * Convert file offset back to kernel virtual address and read
	 * page-by-page with filtering.
	 */
	start = kc_offset_to_vaddr(*fpos - elf_layout.data_offset);
	tsz = min_t(size_t, buflen, PAGE_SIZE - (start & ~PAGE_MASK));

	m = NULL;
	while (buflen) {
		unsigned long pfn;

		/*
		 * Find which region this address falls in.
		 * Optimization: check if we're still in the previous region.
		 */
		if (!m || start < m->addr || start >= m->addr + m->size) {
			struct kcf_region *r;

			m = NULL;
			list_for_each_entry(r, &region_list, list) {
				if (start >= r->addr &&
				    start < r->addr + r->size) {
					m = r;
					break;
				}
			}
		}

		/* Address not in any region: return zeroes */
		if (!m) {
			if (iov_iter_zero(tsz, iter) != tsz) {
				ret = -EFAULT;
				goto out;
			}
			goto skip;
		}

		switch (m->type) {
		case KCF_REGION_VMALLOC:
			/*
			 * vmalloc region: use copy_from_kernel_nofault()
			 * since vread_iter() is not exported.
			 * This is slightly less efficient but correct.
			 */
			if (copy_from_kernel_nofault(bounce_buf,
						     (void *)start, tsz)) {
				if (iov_iter_zero(tsz, iter) != tsz) {
					ret = -EFAULT;
					goto out;
				}
			} else if (_copy_to_iter(bounce_buf, tsz, iter) != tsz) {
				ret = -EFAULT;
				goto out;
			}
			break;

		case KCF_REGION_RAM:
			/*
			 * RAM region: this is where the privacy filter
			 * applies. Classify the page and either copy data
			 * or return zeroes.
			 */
			pfn = __pa(start) >> PAGE_SHIFT;

			switch (kcf_classify_page(pfn)) {
			case KCF_PAGE_ALLOW:
				/* Kernel data - read through bounce buffer */
				if (copy_from_kernel_nofault(bounce_buf,
							     (void *)start,
							     tsz)) {
					if (iov_iter_zero(tsz, iter) != tsz) {
						ret = -EFAULT;
						goto out;
					}
				} else if (_copy_to_iter(bounce_buf, tsz,
							 iter) != tsz) {
					ret = -EFAULT;
					goto out;
				}
				break;

			case KCF_PAGE_DENY:
			case KCF_PAGE_SKIP:
				/* Sensitive or invalid - return zeroes */
				if (iov_iter_zero(tsz, iter) != tsz) {
					ret = -EFAULT;
					goto out;
				}
				break;
			}
			break;

		case KCF_REGION_VMEMMAP:
		case KCF_REGION_TEXT:
			/*
			 * vmemmap and kernel text: always allow.
			 * These contain struct page metadata and kernel
			 * code respectively - essential for drgn and
			 * never contain user data.
			 */
			if (copy_from_kernel_nofault(bounce_buf,
						     (void *)start, tsz)) {
				if (iov_iter_zero(tsz, iter) != tsz) {
					ret = -EFAULT;
					goto out;
				}
			} else if (_copy_to_iter(bounce_buf, tsz, iter) != tsz) {
				ret = -EFAULT;
				goto out;
			}
			break;

		default:
			pr_warn_once("Unknown region type: %d\n", m->type);
			if (iov_iter_zero(tsz, iter) != tsz) {
				ret = -EFAULT;
				goto out;
			}
		}
skip:
		buflen -= tsz;
		*fpos += tsz;
		start += tsz;
		tsz = min_t(size_t, buflen, PAGE_SIZE);
	}

out:
	read_unlock(&region_lock);
	if (ret)
		return ret;
	bytes_read = orig_buflen - buflen;
	sess->bytes_read += bytes_read;

	/* Update global byte counter for cross-session rate limiting */
	if (kcf_max_global_bytes_per_min > 0 && bytes_read > 0) {
		spin_lock(&rate_lock);
		rate_window_bytes += bytes_read;
		spin_unlock(&rate_lock);
	}

	return bytes_read;
}

/*
 * Audit helpers. Use audit_log_task_info() (EXPORT_SYMBOL) to log
 * the full identity of current: pid, ppid, auid, uid, gid, euid,
 * suid, fsuid, egid, sgid, fsgid, tty, ses, comm, exe, and
 * subj (LSM context). This avoids audit_log_untrustedstring(),
 * audit_log_d_path(), and get_mm_exe_file() which are not exported.
 */
static void kcf_audit_open(void)
{
	struct audit_buffer *ab;

	if (!kcf_audit)
		return;

	ab = audit_log_start(NULL, GFP_ATOMIC, AUDIT_KERNEL);
	if (!ab)
		return;

	audit_log_format(ab, "kcore_filtered op=open");
	audit_log_task_info(ab);
	audit_log_end(ab);
}

static void kcf_audit_close(struct kcf_session *sess)
{
	struct audit_buffer *ab;
	s64 duration_ms;

	if (!kcf_audit)
		return;

	duration_ms = ktime_ms_delta(ktime_get(), sess->open_time);

	ab = audit_log_start(NULL, GFP_ATOMIC, AUDIT_KERNEL);
	if (!ab)
		return;

	audit_log_format(ab, "kcore_filtered op=close");
	audit_log_task_info(ab);
	audit_log_format(ab, " bytes_read=%zu duration_ms=%lld",
		sess->bytes_read, duration_ms);
	audit_log_end(ab);
}

static void kcf_audit_denied(void)
{
	struct audit_buffer *ab;

	if (!kcf_audit)
		return;

	ab = audit_log_start(NULL, GFP_ATOMIC, AUDIT_KERNEL);
	if (!ab)
		return;

	audit_log_format(ab, "kcore_filtered op=denied");
	audit_log_task_info(ab);
	audit_log_end(ab);
}

static void kcf_audit_rate_limited(const char *reason)
{
	struct audit_buffer *ab;

	if (!kcf_audit)
		return;

	ab = audit_log_start(NULL, GFP_ATOMIC, AUDIT_KERNEL);
	if (!ab)
		return;

	audit_log_format(ab, "kcore_filtered op=rate_limited reason=%s",
			 reason);
	audit_log_task_info(ab);
	audit_log_end(ab);
}

static int kcf_open(struct inode *inode, struct file *filp)
{
	struct kcf_session *sess;

	/*
	 * Same permission model as /proc/kcore:
	 * - Requires CAP_SYS_RAWIO
	 * - Respects kernel lockdown
	 */
	if (!capable(CAP_SYS_RAWIO)) {
		kcf_audit_denied();
		return -EPERM;
	}

	/* Layer 3: global open rate limit */
	if (kcf_max_opens_per_min > 0) {
		spin_lock(&rate_lock);
		kcf_rate_check_window();
		if (rate_window_opens >= kcf_max_opens_per_min) {
			spin_unlock(&rate_lock);
			atomic64_inc(&kcf_rl_denied_opens);
			kcf_audit_rate_limited("open_rate");
			return -EBUSY;
		}
		rate_window_opens++;
		spin_unlock(&rate_lock);
	}

	sess = kzalloc(sizeof(*sess), GFP_KERNEL);
	if (!sess)
		return -ENOMEM;

	sess->bounce_buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!sess->bounce_buf) {
		kfree(sess);
		return -ENOMEM;
	}

	sess->open_time = ktime_get();
	filp->private_data = sess;

	kcf_audit_open();
	return 0;
}

static int kcf_release(struct inode *inode, struct file *file)
{
	struct kcf_session *sess = file->private_data;

	kcf_audit_close(sess);
	kfree(sess->bounce_buf);
	kfree(sess);
	return 0;
}

static const struct proc_ops kcf_proc_ops = {
	.proc_read_iter	= kcf_read_iter,
	.proc_open	= kcf_open,
	.proc_release	= kcf_release,
	.proc_lseek	= default_llseek,
};

/*
 * /proc/kcore_filtered/stats - exposes filtering statistics
 */
static int kcf_stats_show(struct seq_file *m, void *v)
{
	seq_printf(m, "allowed:          %lld\n",
		   atomic64_read(&kcf_stats.allowed));
	seq_printf(m, "denied_anon:      %lld\n",
		   atomic64_read(&kcf_stats.denied_anon));
	seq_printf(m, "denied_cache:     %lld\n",
		   atomic64_read(&kcf_stats.denied_cache));
	seq_printf(m, "denied_free:      %lld\n",
		   atomic64_read(&kcf_stats.denied_free));
	seq_printf(m, "denied_slab:      %lld\n",
		   atomic64_read(&kcf_stats.denied_slab));
	seq_printf(m, "denied_offline:   %lld\n",
		   atomic64_read(&kcf_stats.denied_offline));
	seq_printf(m, "denied_swapbacked:%lld\n",
		   atomic64_read(&kcf_stats.denied_swapbacked));
	seq_printf(m, "skipped:          %lld\n",
		   atomic64_read(&kcf_stats.skipped));
	seq_printf(m, "rl_denied_opens:  %lld\n",
		   atomic64_read(&kcf_rl_denied_opens));
	seq_printf(m, "rl_denied_reads:  %lld\n",
		   atomic64_read(&kcf_rl_denied_reads));
	seq_printf(m, "rl_sessions_expired:%lld\n",
		   atomic64_read(&kcf_rl_sessions_expired));
	seq_printf(m, "rl_sessions_budget:%lld\n",
		   atomic64_read(&kcf_rl_sessions_budget));
	return 0;
}

static int kcf_stats_open(struct inode *inode, struct file *file)
{
	return single_open(file, kcf_stats_show, NULL);
}

static const struct proc_ops kcf_stats_proc_ops = {
	.proc_open	= kcf_stats_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
};

static struct proc_dir_entry *stats_entry;

static int __init kcf_init(void)
{
	int nregions;
	int ret;

	pr_info("initializing (filter_anon=%d filter_cache=%d filter_free=%d filter_slab=%d audit=%d)\n",
		kcf_filter_anon, kcf_filter_cache,
		kcf_filter_free, kcf_filter_slab, kcf_audit);
	pr_info("rate limits: max_session_bytes=%lu max_session_secs=%u max_opens_per_min=%u max_global_bytes_per_min=%lu\n",
		kcf_max_session_bytes, kcf_max_session_secs,
		kcf_max_opens_per_min, kcf_max_global_bytes_per_min);

	/* Initialize global rate-limit window */
	rate_window_start = ktime_get();

	/* Discover memory regions */
	ret = kcf_regions_init(&region_list);
	if (ret) {
		pr_err("failed to discover memory regions: %d\n", ret);
		return ret;
	}

	nregions = kcf_regions_count(&region_list);
	pr_info("discovered %d memory regions\n", nregions);

	/* Compute ELF layout */
	elf_file_size = kcf_elf_compute_layout(&region_list, nregions,
					       &elf_layout);

	/* Create /proc/kcore_filtered (root read-only, like /proc/kcore) */
	proc_entry = proc_create("kcore_filtered", 0400, NULL,
				 &kcf_proc_ops);
	if (!proc_entry) {
		pr_err("failed to create /proc/kcore_filtered\n");
		ret = -ENOMEM;
		goto fail_regions;
	}
	proc_set_size(proc_entry, elf_file_size);

	/* Create /proc/kcore_filtered_stats for observability */
	stats_entry = proc_create("kcore_filtered_stats", 0400, NULL,
				  &kcf_stats_proc_ops);

	pr_info("ready - /proc/kcore_filtered created (size=%zu)\n",
		elf_file_size);
	return 0;

fail_regions:
	kcf_regions_free(&region_list);
	return ret;
}

static void __exit kcf_exit(void)
{
	if (stats_entry)
		proc_remove(stats_entry);
	if (proc_entry)
		proc_remove(proc_entry);

	kcf_regions_free(&region_list);

	pr_info("unloaded - final stats: allowed=%lld denied_anon=%lld denied_cache=%lld denied_free=%lld denied_slab=%lld\n",
		atomic64_read(&kcf_stats.allowed),
		atomic64_read(&kcf_stats.denied_anon),
		atomic64_read(&kcf_stats.denied_cache),
		atomic64_read(&kcf_stats.denied_free),
		atomic64_read(&kcf_stats.denied_slab));
}

module_init(kcf_init);
module_exit(kcf_exit);
