// SPDX-License-Identifier: GPL-2.0-only
/*
 * Memory region discovery for kcore_filtered
 *
 * Discovers system RAM ranges, kernel text, vmalloc, and vmemmap
 * regions using exported kernel APIs. This replaces the internal
 * kclist_head that /proc/kcore uses (which is not exported).
 *
 * RAM discovery uses walk_iomem_res_desc() which is exported as GPL.
 * Kernel text and vmalloc ranges come from well-known kernel symbols
 * and address range macros.
 */

#include <linux/ioport.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/sizes.h>
#include <linux/vmalloc.h>
#include <asm/io.h>

#ifdef CONFIG_SPARSEMEM_VMEMMAP
#include <asm/pgtable.h>
#endif

#include "region.h"

/*
 * Callback for walk_iomem_res_desc() - adds each system RAM range
 * as a KCF_REGION_RAM entry.
 */
static int add_ram_region(struct resource *res, void *arg)
{
	struct list_head *head = arg;
	struct kcf_region *ent;
	unsigned long start_pfn, end_pfn;
	unsigned long vaddr;
	size_t size;

	start_pfn = PFN_UP(res->start);
	end_pfn = PFN_DOWN(res->end + 1);

	if (start_pfn >= end_pfn)
		return 0;

	vaddr = (unsigned long)__va(PFN_PHYS(start_pfn));
	size = (end_pfn - start_pfn) << PAGE_SHIFT;

	/* Sanity: skip if virtual address is not valid */
	if (!virt_addr_valid((void *)vaddr))
		return 0;

	ent = kmalloc(sizeof(*ent), GFP_KERNEL);
	if (!ent)
		return -ENOMEM;

	ent->addr = vaddr;
	ent->size = size;
	ent->type = KCF_REGION_RAM;
	list_add_tail(&ent->list, head);

	return 0;
}

/*
 * Add the kernel text region.
 *
 * The linker symbols _text and _end are not exported to modules, so
 * we cannot reference them directly. On arm64, kimage_voffset is
 * exported and KIMAGE_VADDR is a header macro, so we can compute
 * the kernel image base address. We use a conservative estimate for
 * the kernel image size (256 MB) which is large enough to cover any
 * realistic kernel image.
 *
 * On other architectures where KIMAGE_VADDR is not defined, we skip
 * the text region — the kernel text physical pages are still accessible
 * through the RAM regions in the direct map.
 */
#define KCF_KERNEL_IMAGE_SIZE_MAX	SZ_256M

#if defined(CONFIG_ARCH_PROC_KCORE_TEXT) && defined(KIMAGE_VADDR)
extern u64 kimage_voffset;
#endif

static int add_text_region(struct list_head *head)
{
#if defined(CONFIG_ARCH_PROC_KCORE_TEXT) && defined(KIMAGE_VADDR)
	struct kcf_region *ent;
	unsigned long text_start;

	/*
	 * On arm64: kernel image VA = KIMAGE_VADDR + kaslr_offset.
	 * kimage_voffset = VA - PA of kernel image, and
	 * KIMAGE_VADDR is the base before KASLR.
	 * We include the full KIMAGE range up to a safe upper bound.
	 */
	text_start = KIMAGE_VADDR;

	ent = kmalloc(sizeof(*ent), GFP_KERNEL);
	if (!ent)
		return -ENOMEM;

	ent->addr = text_start;
	ent->size = KCF_KERNEL_IMAGE_SIZE_MAX;
	ent->type = KCF_REGION_TEXT;
	list_add_tail(&ent->list, head);
#endif
	return 0;
}

/*
 * Add the vmalloc region. Kernel vmalloc area covers module text,
 * vmalloc'd kernel buffers, vmap'd regions, etc.
 */
static int add_vmalloc_region(struct list_head *head)
{
	struct kcf_region *ent;

	ent = kmalloc(sizeof(*ent), GFP_KERNEL);
	if (!ent)
		return -ENOMEM;

	ent->addr = VMALLOC_START;
	ent->size = VMALLOC_END - VMALLOC_START;
	ent->type = KCF_REGION_VMALLOC;
	list_add_tail(&ent->list, head);

	return 0;
}

/*
 * Add vmemmap region covering struct page metadata for discovered
 * RAM ranges. Only relevant with CONFIG_SPARSEMEM_VMEMMAP.
 */
static int add_vmemmap_regions(struct list_head *head)
{
#ifdef CONFIG_SPARSEMEM_VMEMMAP
	struct kcf_region *r;
	struct kcf_region *vmm;
	unsigned long pfn, nr_pages;
	unsigned long start, end;

	list_for_each_entry(r, head, list) {
		if (r->type != KCF_REGION_RAM)
			continue;

		pfn = __pa(r->addr) >> PAGE_SHIFT;
		nr_pages = r->size >> PAGE_SHIFT;

		start = ((unsigned long)pfn_to_page(pfn)) & PAGE_MASK;
		end = (unsigned long)pfn_to_page(pfn + nr_pages);
		end = PAGE_ALIGN(end);

		if (start >= end)
			continue;

		vmm = kmalloc(sizeof(*vmm), GFP_KERNEL);
		if (!vmm)
			return -ENOMEM;

		vmm->addr = start;
		vmm->size = end - start;
		vmm->type = KCF_REGION_VMEMMAP;
		list_add_tail(&vmm->list, head);
	}
#endif
	return 0;
}

/*
 * Module-range support: on architectures where modules live outside
 * VMALLOC_START..VMALLOC_END, add them as a separate vmalloc-type region.
 */
static int add_modules_region(struct list_head *head)
{
#if defined(CONFIG_MODULES) && defined(MODULES_VADDR)
	struct kcf_region *ent;

	if (MODULES_VADDR == VMALLOC_START && MODULES_END == VMALLOC_END)
		return 0;

	ent = kmalloc(sizeof(*ent), GFP_KERNEL);
	if (!ent)
		return -ENOMEM;

	ent->addr = MODULES_VADDR;
	ent->size = MODULES_END - MODULES_VADDR;
	ent->type = KCF_REGION_VMALLOC;
	list_add_tail(&ent->list, head);
#endif
	return 0;
}

int kcf_regions_init(struct list_head *head)
{
	int ret;

	INIT_LIST_HEAD(head);

	/* Kernel text (architecture-dependent) */
	ret = add_text_region(head);
	if (ret)
		goto fail;

	/* vmalloc area */
	ret = add_vmalloc_region(head);
	if (ret)
		goto fail;

	/* Module area (if separate from vmalloc) */
	ret = add_modules_region(head);
	if (ret)
		goto fail;

	/* Walk system RAM via iomem resource tree */
	ret = walk_iomem_res_desc(IORES_DESC_NONE,
				  IORESOURCE_SYSTEM_RAM | IORESOURCE_BUSY,
				  0, -1UL, head, add_ram_region);
	if (ret)
		goto fail;

	/* vmemmap regions for the RAM we discovered */
	ret = add_vmemmap_regions(head);
	if (ret)
		goto fail;

	return 0;

fail:
	kcf_regions_free(head);
	return ret;
}

void kcf_regions_free(struct list_head *head)
{
	struct kcf_region *ent, *tmp;

	list_for_each_entry_safe(ent, tmp, head, list) {
		list_del(&ent->list);
		kfree(ent);
	}
}

int kcf_regions_count(struct list_head *head)
{
	struct kcf_region *ent;
	int count = 0;

	list_for_each_entry(ent, head, list)
		count++;

	return count;
}
