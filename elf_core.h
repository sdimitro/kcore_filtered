/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * elf_core.h - ELF core file header generation for kcore_filtered
 *
 * Generates the ELF header, program headers (PT_LOAD segments), and
 * note segment that make /proc/kcore_filtered look like a valid ELF
 * core file to tools like drgn and readelf.
 */
#ifndef KCORE_FILTERED_ELF_CORE_H
#define KCORE_FILTERED_ELF_CORE_H

#include <linux/elf.h>
#include <linux/list.h>
#include <linux/types.h>
#include <linux/uio.h>

/**
 * struct kcf_elf_layout - Precomputed layout of the ELF core file
 * @nphdr:       number of program headers (1 PT_NOTE + N PT_LOAD)
 * @phdrs_offset: byte offset of program headers in the file
 * @phdrs_len:   total byte length of all program headers
 * @notes_offset: byte offset of the note segment
 * @notes_len:   byte length of the note segment
 * @data_offset: byte offset where the first PT_LOAD data begins
 */
struct kcf_elf_layout {
	int		nphdr;
	size_t		phdrs_offset;
	size_t		phdrs_len;
	size_t		notes_offset;
	size_t		notes_len;
	size_t		data_offset;
};

/**
 * kcf_elf_compute_layout - Calculate the ELF file layout
 * @regions: list of kcf_region entries
 * @nregions: number of regions
 * @layout: output layout structure
 *
 * Returns the total virtual size of the ELF file.
 */
size_t kcf_elf_compute_layout(struct list_head *regions, int nregions,
			      struct kcf_elf_layout *layout);

/**
 * kcf_elf_write_ehdr - Write the ELF file header into an iterator
 * @iter: output iterator
 * @fpos: current file position (in/out)
 * @buflen: remaining bytes to write (in/out)
 * @layout: precomputed layout
 *
 * Returns 0 on success, -EFAULT on copy failure.
 */
int kcf_elf_write_ehdr(struct iov_iter *iter, loff_t *fpos, size_t *buflen,
		       const struct kcf_elf_layout *layout);

/**
 * kcf_elf_write_phdrs - Write ELF program headers into an iterator
 * @iter: output iterator
 * @fpos: current file position (in/out)
 * @buflen: remaining bytes to write (in/out)
 * @layout: precomputed layout
 * @regions: list of kcf_region entries
 *
 * Returns 0 on success, negative errno on failure.
 */
int kcf_elf_write_phdrs(struct iov_iter *iter, loff_t *fpos, size_t *buflen,
			const struct kcf_elf_layout *layout,
			struct list_head *regions);

/**
 * kcf_elf_write_notes - Write the ELF note segment into an iterator
 * @iter: output iterator
 * @fpos: current file position (in/out)
 * @buflen: remaining bytes to write (in/out)
 * @layout: precomputed layout
 *
 * Returns 0 on success, negative errno on failure.
 */
int kcf_elf_write_notes(struct iov_iter *iter, loff_t *fpos, size_t *buflen,
			const struct kcf_elf_layout *layout);

#endif /* KCORE_FILTERED_ELF_CORE_H */
