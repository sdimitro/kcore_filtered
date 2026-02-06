// SPDX-License-Identifier: GPL-2.0-only
/*
 * ELF core file header generation for kcore_filtered
 *
 * Generates the ELF file header, program headers (one PT_NOTE plus
 * one PT_LOAD per region), and note segment for /proc/kcore_filtered.
 *
 * The note segment includes:
 *   - NT_PRSTATUS (minimal, for ELF validity)
 *   - NT_PRPSINFO (minimal process info)
 *   - VMCOREINFO (critical for drgn - kernel structure layout info)
 *
 * The VMCOREINFO note is located via paddr_vmcoreinfo_note() which
 * is exported. We read the note content using copy_from_kernel_nofault().
 */

#include <linux/elf.h>
#include <linux/elfcore.h>
/*
 * paddr_vmcoreinfo_note() is exported by the kernel. The declaration
 * moved from crash_core.h to vmcore_info.h in 6.10, so we declare it
 * ourselves to avoid version-dependent includes.
 */
extern unsigned long long paddr_vmcoreinfo_note(void);
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/uio.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <asm/io.h>
#include <asm/page.h>

#include "elf_core.h"
#include "region.h"

#define CORE_STR "CORE"

/*
 * Matches the kernel's VMCOREINFO_NOTE_NAME. Defined here because
 * the declaration moved from crash_core.h to vmcore_info.h in 6.10.
 */
#define KCF_VMCOREINFO_NOTE_NAME "VMCOREINFO"

#ifndef ELF_CORE_EFLAGS
#define ELF_CORE_EFLAGS	0
#endif

/*
 * Virtual-address-to-file-offset conversion, matching kcore.c's scheme:
 * The file offset for a virtual address v is (v - PAGE_OFFSET).
 */
#ifndef kc_vaddr_to_offset
#define kc_vaddr_to_offset(v) ((v) - PAGE_OFFSET)
#endif

/*
 * Compute a single ELF note's padded size (name + desc, both 4-byte aligned).
 */
static size_t elf_note_size(const char *name, size_t descsz)
{
	size_t namesz = strlen(name) + 1;

	return sizeof(struct elf_note) +
	       ALIGN(namesz, 4) +
	       ALIGN(descsz, 4);
}

/*
 * Write a single ELF note into a buffer at position *i.
 */
static void append_note(char *buf, size_t *i, const char *name,
			unsigned int type, const void *desc, size_t descsz)
{
	struct elf_note *note = (struct elf_note *)&buf[*i];

	note->n_namesz = strlen(name) + 1;
	note->n_descsz = descsz;
	note->n_type = type;
	*i += sizeof(*note);
	memcpy(&buf[*i], name, note->n_namesz);
	*i = ALIGN(*i + note->n_namesz, 4);
	memcpy(&buf[*i], desc, descsz);
	*i = ALIGN(*i + descsz, 4);
}

/*
 * Compute how large the notes segment will be.
 * We include: prstatus, prpsinfo, and vmcoreinfo.
 */
static size_t compute_notes_len(void)
{
	size_t len = 0;

	/* NT_PRSTATUS */
	len += elf_note_size(CORE_STR, sizeof(struct elf_prstatus));

	/* NT_PRPSINFO */
	len += elf_note_size(CORE_STR, sizeof(struct elf_prpsinfo));

	/*
	 * VMCOREINFO - we reserve space for up to 4KB of vmcoreinfo.
	 * The actual size is determined at runtime from vmcoreinfo_size,
	 * but since that symbol isn't exported, we use a safe upper bound
	 * and pad with zeroes.
	 */
	len += elf_note_size(KCF_VMCOREINFO_NOTE_NAME, PAGE_SIZE);

	return len;
}

size_t kcf_elf_compute_layout(struct list_head *regions, int nregions,
			      struct kcf_elf_layout *layout)
{
	struct kcf_region *r;
	size_t size;

	/* 1 PT_NOTE + 1 PT_LOAD per region */
	layout->nphdr = 1 + nregions;

	layout->phdrs_offset = sizeof(struct elfhdr);
	layout->phdrs_len = layout->nphdr * sizeof(struct elf_phdr);

	layout->notes_offset = layout->phdrs_offset + layout->phdrs_len;
	layout->notes_len = compute_notes_len();

	layout->data_offset = PAGE_ALIGN(layout->notes_offset +
					 layout->notes_len);

	/*
	 * Total virtual file size: data_offset + the highest virtual
	 * address range we cover. This determines the inode size.
	 */
	size = layout->data_offset;
	list_for_each_entry(r, regions, list) {
		size_t region_end;

		region_end = kc_vaddr_to_offset(r->addr) +
			     layout->data_offset + r->size;
		if (region_end > size)
			size = region_end;
	}

	return size;
}

int kcf_elf_write_ehdr(struct iov_iter *iter, loff_t *fpos, size_t *buflen,
		       const struct kcf_elf_layout *layout)
{
	struct elfhdr ehdr = {
		.e_ident = {
			[EI_MAG0] = ELFMAG0,
			[EI_MAG1] = ELFMAG1,
			[EI_MAG2] = ELFMAG2,
			[EI_MAG3] = ELFMAG3,
			[EI_CLASS] = ELF_CLASS,
			[EI_DATA] = ELF_DATA,
			[EI_VERSION] = EV_CURRENT,
			[EI_OSABI] = ELF_OSABI,
		},
		.e_type = ET_CORE,
		.e_machine = ELF_ARCH,
		.e_version = EV_CURRENT,
		.e_phoff = sizeof(struct elfhdr),
		.e_flags = ELF_CORE_EFLAGS,
		.e_ehsize = sizeof(struct elfhdr),
		.e_phentsize = sizeof(struct elf_phdr),
		.e_phnum = layout->nphdr,
	};
	size_t tsz;

	if (!*buflen || *fpos >= sizeof(struct elfhdr))
		return 0;

	tsz = min_t(size_t, *buflen, sizeof(struct elfhdr) - *fpos);
	if (copy_to_iter((char *)&ehdr + *fpos, tsz, iter) != tsz)
		return -EFAULT;

	*buflen -= tsz;
	*fpos += tsz;
	return 0;
}

int kcf_elf_write_phdrs(struct iov_iter *iter, loff_t *fpos, size_t *buflen,
			const struct kcf_elf_layout *layout,
			struct list_head *regions)
{
	struct elf_phdr *phdrs, *phdr;
	struct kcf_region *r;
	size_t tsz;

	if (!*buflen || *fpos >= layout->phdrs_offset + layout->phdrs_len)
		return 0;

	if (*fpos < layout->phdrs_offset)
		return 0;

	phdrs = kzalloc(layout->phdrs_len, GFP_KERNEL);
	if (!phdrs)
		return -ENOMEM;

	/* First phdr: PT_NOTE */
	phdrs[0].p_type = PT_NOTE;
	phdrs[0].p_offset = layout->notes_offset;
	phdrs[0].p_filesz = layout->notes_len;

	/* One PT_LOAD per region */
	phdr = &phdrs[1];
	list_for_each_entry(r, regions, list) {
		phdr->p_type = PT_LOAD;
		phdr->p_flags = PF_R | PF_W | PF_X;
		phdr->p_offset = kc_vaddr_to_offset(r->addr) +
				 layout->data_offset;
		phdr->p_vaddr = (size_t)r->addr;

		if (r->type == KCF_REGION_RAM)
			phdr->p_paddr = __pa(r->addr);
		else if (r->type == KCF_REGION_TEXT)
			phdr->p_paddr = __pa_symbol(r->addr);
		else
			phdr->p_paddr = (elf_addr_t)-1;

		phdr->p_filesz = phdr->p_memsz = r->size;
		phdr->p_align = PAGE_SIZE;
		phdr++;
	}

	tsz = min_t(size_t, *buflen,
		    layout->phdrs_offset + layout->phdrs_len - *fpos);
	if (copy_to_iter((char *)phdrs + *fpos - layout->phdrs_offset,
			 tsz, iter) != tsz) {
		kfree(phdrs);
		return -EFAULT;
	}
	kfree(phdrs);

	*buflen -= tsz;
	*fpos += tsz;
	return 0;
}

int kcf_elf_write_notes(struct iov_iter *iter, loff_t *fpos, size_t *buflen,
			const struct kcf_elf_layout *layout)
{
	struct elf_prstatus prstatus = {};
	struct elf_prpsinfo prpsinfo = {
		.pr_sname = 'R',
		.pr_fname = "vmlinux",
	};
	char *notes;
	size_t i = 0;
	size_t tsz;
	unsigned char *vmcoreinfo_buf;
	size_t vmcoreinfo_actual_size = 0;

	if (!*buflen || *fpos >= layout->notes_offset + layout->notes_len)
		return 0;

	if (*fpos < layout->notes_offset)
		return 0;

	vmcoreinfo_buf = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!vmcoreinfo_buf)
		return -ENOMEM;

	notes = kzalloc(layout->notes_len, GFP_KERNEL);
	if (!notes) {
		kfree(vmcoreinfo_buf);
		return -ENOMEM;
	}

	/* NT_PRSTATUS */
	append_note(notes, &i, CORE_STR, NT_PRSTATUS,
		    &prstatus, sizeof(prstatus));

	/*
	 * NT_PRPSINFO - boot_command_line is not exported to modules,
	 * so we leave pr_psargs empty. drgn does not use this field.
	 */
	append_note(notes, &i, CORE_STR, NT_PRPSINFO,
		    &prpsinfo, sizeof(prpsinfo));

	/*
	 * VMCOREINFO note - critical for drgn.
	 *
	 * The vmcoreinfo_data/vmcoreinfo_size symbols are not exported,
	 * but paddr_vmcoreinfo_note() gives us the physical address of
	 * the full ELF note structure. We read the raw note content
	 * from there.
	 *
	 * The note at paddr_vmcoreinfo_note is a complete elf_note +
	 * name + data structure. We need just the data portion to
	 * re-wrap in our own note format.
	 *
	 * Fallback: if we can't read it, emit an empty vmcoreinfo note.
	 * drgn can still fall back to /sys/kernel/vmcoreinfo.
	 */
	if (paddr_vmcoreinfo_note()) {
		void *note_va;
		struct elf_note *vmci_note;

		note_va = phys_to_virt(paddr_vmcoreinfo_note());
		if (note_va &&
		    !copy_from_kernel_nofault(vmcoreinfo_buf, note_va,
					      sizeof(struct elf_note))) {
			vmci_note = (struct elf_note *)vmcoreinfo_buf;
			if (vmci_note->n_descsz > 0 &&
			    vmci_note->n_descsz < PAGE_SIZE) {
				size_t hdr_size;

				hdr_size = sizeof(struct elf_note) +
					   ALIGN(vmci_note->n_namesz, 4);
				vmcoreinfo_actual_size = vmci_note->n_descsz;

				/*
				 * Read just the data portion into our
				 * buffer for re-wrapping.
				 */
				memset(vmcoreinfo_buf, 0, PAGE_SIZE);
				copy_from_kernel_nofault(
					vmcoreinfo_buf,
					(char *)note_va + hdr_size,
					vmcoreinfo_actual_size);
			}
		}
	}

	append_note(notes, &i, KCF_VMCOREINFO_NOTE_NAME, 0,
		    vmcoreinfo_buf,
		    vmcoreinfo_actual_size ? vmcoreinfo_actual_size : 1);

	tsz = min_t(size_t, *buflen,
		    layout->notes_offset + layout->notes_len - *fpos);
	if (copy_to_iter(notes + *fpos - layout->notes_offset,
			 tsz, iter) != tsz) {
		kfree(notes);
		kfree(vmcoreinfo_buf);
		return -EFAULT;
	}
	kfree(notes);
	kfree(vmcoreinfo_buf);

	*buflen -= tsz;
	*fpos += tsz;
	return 0;
}
