// SPDX-License-Identifier: GPL-2.0-only
/*
 * Page classification and privacy filtering
 *
 * Core privacy logic for kcore_filtered. For each physical page in a
 * KCORE_RAM region, determines whether the page contains kernel data
 * (allow) or user/sensitive data (deny, return zeroes).
 *
 * Inspired by makedumpfile's page filtering categories, but running
 * in-kernel with direct access to struct page flags rather than
 * parsing vmcoreinfo from userspace.
 *
 * Classification hierarchy:
 *   1. Invalid/offline/hwpoison pages -> SKIP (zeroes)
 *   2. Free buddy pages              -> DENY (residual data)
 *   3. Anonymous user pages           -> DENY (heap, stack, mmap)
 *   4. Swap-backed pages              -> DENY (user data in swap)
 *   5. User file-backed page cache    -> DENY (file contents)
 *   6. Slab pages                     -> ALLOW (kernel objects) [configurable]
 *   7. Everything else                -> ALLOW (kernel data)
 */

#include <linux/mm.h>
#include <linux/page-flags.h>
#include <linux/pagemap.h>
#include <linux/module.h>
#include <linux/memory_hotplug.h>

#include "page_filter.h"

/* Module parameters controlling filter behavior */
bool kcf_filter_anon = true;
module_param_named(filter_anon, kcf_filter_anon, bool, 0644);
MODULE_PARM_DESC(filter_anon, "Filter anonymous user pages (default: Y)");

bool kcf_filter_cache = true;
module_param_named(filter_cache, kcf_filter_cache, bool, 0644);
MODULE_PARM_DESC(filter_cache, "Filter user file-backed page cache (default: Y)");

bool kcf_filter_free = true;
module_param_named(filter_free, kcf_filter_free, bool, 0644);
MODULE_PARM_DESC(filter_free, "Filter free buddy pages (default: Y)");

bool kcf_filter_slab;
module_param_named(filter_slab, kcf_filter_slab, bool, 0644);
MODULE_PARM_DESC(filter_slab, "Filter slab pages (default: N)");

/* Global statistics */
struct kcf_filter_stats kcf_stats;

/*
 * Check whether a page cache page belongs to a kernel-internal
 * address_space (e.g., shmem for tmpfs used by kernel) vs. a user
 * file's address_space.
 *
 * Returns true if the page is a user file-backed page that should
 * be filtered.
 */
static bool is_user_cache_page(struct page *page)
{
	struct folio *folio;
	struct address_space *mapping;

	folio = page_folio(page);
	mapping = folio_mapping(folio);
	if (!mapping)
		return false;

	/*
	 * Pages with a mapping but no host inode are kernel-internal
	 * (e.g., some special mappings). Allow them.
	 */
	if (!mapping->host)
		return false;

	/*
	 * If the inode belongs to a block device or has a non-zero
	 * i_ino, it's likely a user file. This is a heuristic -
	 * kernel-internal files (like sysfs, procfs) also have inodes,
	 * but their page cache pages are generally safe/small.
	 *
	 * For the initial implementation, we filter all file-backed
	 * page cache that's on the LRU (actively cached user file data).
	 */
	if (folio_test_lru(folio))
		return true;

	return false;
}

enum kcf_page_class kcf_classify_page(unsigned long pfn)
{
	struct page *page;

	/* Step 1: Check if the page is valid and online */
	page = pfn_to_online_page(pfn);
	if (!page) {
		atomic64_inc(&kcf_stats.skipped);
		return KCF_PAGE_SKIP;
	}

	/* Step 2: Offline or hwpoison pages are never safe to read */
	if (PageOffline(page) || is_page_hwpoison(page)) {
		atomic64_inc(&kcf_stats.denied_offline);
		return KCF_PAGE_DENY;
	}

	/* Step 3: Free buddy pages may contain residual data */
	if (kcf_filter_free && is_free_buddy_page(page)) {
		atomic64_inc(&kcf_stats.denied_free);
		return KCF_PAGE_DENY;
	}

	/*
	 * Step 4: Slab pages contain kernel objects. Allow by default,
	 * but can be filtered via module parameter for stricter policy.
	 * Checking slab before anon/cache because slab pages won't have
	 * those flags set.
	 */
	if (PageSlab(page)) {
		if (kcf_filter_slab) {
			atomic64_inc(&kcf_stats.denied_slab);
			return KCF_PAGE_DENY;
		}
		atomic64_inc(&kcf_stats.allowed);
		return KCF_PAGE_ALLOW;
	}

	/* Step 5: Anonymous pages are user process private memory */
	if (kcf_filter_anon && PageAnon(page)) {
		atomic64_inc(&kcf_stats.denied_anon);
		return KCF_PAGE_DENY;
	}

	/*
	 * Step 6: SwapBacked pages not caught by PageAnon above
	 * (e.g., shmem pages for shared anonymous mappings).
	 * PageSwapBacked() was removed in 6.12; use the folio API
	 * which is available on all kernels we target (6.8+).
	 */
	if (kcf_filter_anon && folio_test_swapbacked(page_folio(page))) {
		atomic64_inc(&kcf_stats.denied_swapbacked);
		return KCF_PAGE_DENY;
	}

	/* Step 7: User file-backed page cache */
	if (kcf_filter_cache && is_user_cache_page(page)) {
		atomic64_inc(&kcf_stats.denied_cache);
		return KCF_PAGE_DENY;
	}

	/* Step 8: Everything else is presumed kernel data - allow */
	atomic64_inc(&kcf_stats.allowed);
	return KCF_PAGE_ALLOW;
}
