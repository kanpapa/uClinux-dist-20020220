/*
 * include/asm-v850/pgalloc.h
 *
 *  Copyright (C) 2001  NEC Corporation
 *  Copyright (C) 2001  Miles Bader <miles@gnu.org>
 *
 * This file is subject to the terms and conditions of the GNU General
 * Public License.  See the file COPYING in the main directory of this
 * archive for more details.
 *
 * Written by Miles Bader <miles@gnu.org>
 */

#ifndef __V850_PGALLOC_H__
#define __V850_PGALLOC_H__

#include <asm/setup.h>

#include <asm/machdep.h>

/*
 * Cache handling functions
 */

#ifndef flush_cache_all
/* If there's no flush_cache_all macro defined by <asm/machdep.h>, then
   this processor has no cache, so just define these as nops.  */

#define flush_cache_all()			((void)0)
#define flush_cache_mm(mm)			((void)0)
#define flush_cache_range(mm, start, end)	((void)0)
#define flush_cache_page(vma, vmaddr)		((void)0)
#define flush_page_to_ram(page)			((void)0)
#define flush_dcache_page(page)			((void)0)
#define flush_icache_range(start, end)		((void)0)
#define flush_icache_page(vma,pg)		((void)0)
#define flush_icache()				((void)0)
#define flush_cache_sigtramp(vaddr)		((void)0)

#endif /* !flush_cache_all */

/*
 * flush all user-space atc entries.
 */
static inline void __flush_tlb(void)
{
	BUG();
}

static inline void __flush_tlb_one(unsigned long addr)
{
	BUG();
}

#define flush_tlb() __flush_tlb()

/*
 * flush all atc entries (both kernel and user-space entries).
 */
static inline void flush_tlb_all(void)
{
	BUG();
}

static inline void flush_tlb_mm(struct mm_struct *mm)
{
	BUG();
}

static inline void flush_tlb_page(struct vm_area_struct *vma, unsigned long addr)
{
	BUG();
}

static inline void flush_tlb_range(struct mm_struct *mm,
				   unsigned long start, unsigned long end)
{
	BUG();
}

extern inline void flush_tlb_kernel_page(unsigned long addr)
{
	BUG();
}

extern inline void flush_tlb_pgtables(struct mm_struct *mm,
				      unsigned long start, unsigned long end)
{
	BUG();
}

#endif /* _V850_PGALLOC_H */
