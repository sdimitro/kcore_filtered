/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Page classification and privacy filtering for kcore_filtered
 *
 * Provides a per-page predicate that determines whether a given physical
 * page should be exposed (kernel data) or redacted (user/sensitive data).
 * Inspired by makedumpfile's page classification logic, but running
 * in-kernel with direct access to struct page flags.
 */
#ifndef KCORE_FILTERED_PAGE_FILTER_H
#define KCORE_FILTERED_PAGE_FILTER_H

#include <linux/mm.h>
#include <linux/types.h>

/**
 * enum kcf_page_class - Classification result for a physical page
 * @KCF_PAGE_ALLOW: Page contains kernel data, allow read
 * @KCF_PAGE_DENY:  Page contains user/sensitive data, return zeroes
 * @KCF_PAGE_SKIP:  Page is not valid/online, return zeroes
 */
enum kcf_page_class {
	KCF_PAGE_ALLOW,
	KCF_PAGE_DENY,
	KCF_PAGE_SKIP,
};

/**
 * kcf_classify_page - Determine if a RAM page should be exposed or redacted
 * @pfn: physical frame number to classify
 *
 * Examines struct page flags to classify the page. This is the core
 * privacy filter inspired by makedumpfile's page filtering.
 *
 * Returns a kcf_page_class value.
 */
enum kcf_page_class kcf_classify_page(unsigned long pfn);

/**
 * kcf_filter_stats - Per-class counters for observability
 */
struct kcf_filter_stats {
	atomic64_t allowed;
	atomic64_t denied_anon;
	atomic64_t denied_cache;
	atomic64_t denied_free;
	atomic64_t denied_offline;
	atomic64_t denied_swapbacked;
	atomic64_t skipped;
};

extern struct kcf_filter_stats kcf_stats;

/* Module parameters (declared in page_filter.c, used by main) */
extern bool kcf_filter_anon;
extern bool kcf_filter_cache;
extern bool kcf_filter_free;
extern bool kcf_filter_slab;

#endif /* KCORE_FILTERED_PAGE_FILTER_H */
