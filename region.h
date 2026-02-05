/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Memory region discovery and management for kcore_filtered
 *
 * Builds a list of kernel virtual address regions (text, vmalloc, RAM,
 * vmemmap) that mirrors what /proc/kcore exposes, but constructed
 * independently using exported kernel APIs.
 */
#ifndef KCORE_FILTERED_REGION_H
#define KCORE_FILTERED_REGION_H

#include <linux/list.h>
#include <linux/types.h>

enum kcf_region_type {
	KCF_REGION_TEXT,
	KCF_REGION_VMALLOC,
	KCF_REGION_RAM,
	KCF_REGION_VMEMMAP,
};

struct kcf_region {
	struct list_head	list;
	unsigned long		addr;	/* kernel virtual address */
	size_t			size;
	enum kcf_region_type	type;
};

/**
 * kcf_regions_init - Discover and populate the region list
 * @head: list_head to populate with kcf_region entries
 *
 * Walks system RAM, adds kernel text, vmalloc, and vmemmap regions.
 * Returns 0 on success, negative errno on failure.
 */
int kcf_regions_init(struct list_head *head);

/**
 * kcf_regions_free - Free all regions in the list
 * @head: list_head containing kcf_region entries
 */
void kcf_regions_free(struct list_head *head);

/**
 * kcf_regions_count - Count the number of regions
 * @head: list_head containing kcf_region entries
 */
int kcf_regions_count(struct list_head *head);

#endif /* KCORE_FILTERED_REGION_H */
