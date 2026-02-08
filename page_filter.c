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
#include <linux/slab.h>
#include <linux/string.h>

#include "page_filter.h"

/*
 * kmem_cache_name() is EXPORT_SYMBOL_GPL in mm/slab_common.c but
 * declared in mm/slab.h (kernel-internal, not available to modules).
 * Provide our own declaration so the linker can resolve it.
 */
const char *kmem_cache_name(struct kmem_cache *s);

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

/*
 * Layer 1: Slab cache allow/deny list.
 *
 * When slab_cache_list is non-empty and filter_slab=0, individual slab
 * caches are filtered by name. slab_action controls interpretation:
 *   "allow" — only listed caches pass through (allowlist, deny rest)
 *   "deny"  — only listed caches are denied (denylist, allow rest)
 *
 * filter_slab=1 overrides the list (deny-all catch-all).
 * Both parameters are load-time only (0444) to avoid re-parsing races.
 */
static char slab_action_str[8] = "allow";
module_param_string(slab_action, slab_action_str,
		    sizeof(slab_action_str), 0444);
MODULE_PARM_DESC(slab_action,
	"Slab list mode: 'allow' or 'deny' (default: allow)");

static char slab_cache_list_buf[1024];
module_param_string(slab_cache_list, slab_cache_list_buf,
		    sizeof(slab_cache_list_buf), 0444);
MODULE_PARM_DESC(slab_cache_list,
	"Comma-separated slab cache names for allow/deny list");

#define KCF_SLAB_LIST_MAX	64

static char slab_list_parse_buf[sizeof(slab_cache_list_buf)];
static const char *slab_list_entries[KCF_SLAB_LIST_MAX];
static int slab_list_count;
static bool slab_list_active;
static bool slab_list_is_allowlist = true;

/*
 * Minimal view into struct slab to access the slab_cache pointer.
 * struct slab (mm/slab.h, not exported to modules) places slab_cache
 * as the second word, immediately after __page_flags. This layout has
 * been stable since struct slab was introduced in Linux 5.17, and the
 * kernel enforces it with BUILD_BUG_ON alignment checks in mm/slab.h.
 *
 * We only read the first two words — same fragility class as the
 * existing PageSlab() / page_folio() usage in this module.
 */
struct kcf_slab_view {
	unsigned long __page_flags;
	struct kmem_cache *slab_cache;
};

static inline struct kmem_cache *kcf_page_to_cache(struct page *page)
{
	return ((struct kcf_slab_view *)page)->slab_cache;
}

static bool kcf_slab_name_in_list(const char *name)
{
	int i;

	for (i = 0; i < slab_list_count; i++) {
		if (strcmp(name, slab_list_entries[i]) == 0)
			return true;
	}
	return false;
}

/*
 * Classify a slab page against the allow/deny list.
 * Returns true if the page should be allowed, false if denied.
 *
 * Called only when slab_list_active is true and filter_slab is false.
 */
static bool kcf_slab_list_allow(struct page *page)
{
	struct kmem_cache *cache;
	const char *name;
	bool in_list;

	cache = kcf_page_to_cache(page);
	if (!cache)
		return !slab_list_is_allowlist;

	name = kmem_cache_name(cache);
	if (!name)
		return !slab_list_is_allowlist;

	in_list = kcf_slab_name_in_list(name);

	if (slab_list_is_allowlist)
		return in_list;
	return !in_list;
}

int kcf_slab_list_init(void)
{
	char *buf, *tok;

	/* Validate slab_action */
	if (strcmp(slab_action_str, "allow") == 0) {
		slab_list_is_allowlist = true;
	} else if (strcmp(slab_action_str, "deny") == 0) {
		slab_list_is_allowlist = false;
	} else {
		pr_err("invalid slab_action='%s' (must be 'allow' or 'deny')\n",
		       slab_action_str);
		return -EINVAL;
	}

	/* Parse comma-separated cache name list */
	slab_list_count = 0;
	slab_list_active = false;

	if (!slab_cache_list_buf[0])
		return 0;

	/* Work on a copy so sysfs still shows the original string */
	strscpy(slab_list_parse_buf, slab_cache_list_buf,
		sizeof(slab_list_parse_buf));
	buf = slab_list_parse_buf;

	while ((tok = strsep(&buf, ",")) != NULL) {
		if (!*tok)
			continue;
		if (slab_list_count >= KCF_SLAB_LIST_MAX) {
			pr_warn("slab_cache_list truncated at %d entries\n",
				KCF_SLAB_LIST_MAX);
			break;
		}
		slab_list_entries[slab_list_count++] = tok;
	}

	if (slab_list_count > 0) {
		slab_list_active = true;
		pr_info("slab %s active with %d cache(s)\n",
			slab_list_is_allowlist ? "allowlist" : "denylist",
			slab_list_count);
	}

	return 0;
}

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
	 * Step 4: Slab pages contain kernel objects.
	 *   - filter_slab=1: deny all slab (catch-all kill switch)
	 *   - slab_cache_list set: check per-cache allow/deny list
	 *   - otherwise: allow all slab (default)
	 */
	if (PageSlab(page)) {
		if (kcf_filter_slab) {
			atomic64_inc(&kcf_stats.denied_slab);
			return KCF_PAGE_DENY;
		}
		if (slab_list_active && !kcf_slab_list_allow(page)) {
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
