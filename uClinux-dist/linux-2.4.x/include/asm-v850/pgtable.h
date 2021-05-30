#ifndef __V850_PGTABLE_H__
#define __V850_PGTABLE_H__

#include <linux/config.h>
#include <asm/setup.h>

#define page_address(page)   ({ if (!(page)->virtual) BUG(); (page)->virtual;})
#define __page_address(page) (PAGE_OFFSET + (((page) - mem_map) << PAGE_SHIFT))
#define pgd_present(pgd)     (1)       /* pages are always present on NO_MM */
#define kern_addr_valid(addr) (1)

#define PAGE_NONE		__pgprot(0) /* these mean nothing to NO_MM */
#define PAGE_SHARED		__pgprot(0) /* these mean nothing to NO_MM */
#define PAGE_COPY		__pgprot(0) /* these mean nothing to NO_MM */
#define PAGE_READONLY		__pgprot(0) /* these mean nothing to NO_MM */
#define PAGE_KERNEL		__pgprot(0) /* these mean nothing to NO_MM */

extern void paging_init(void);

#define pgtable_cache_init()   ((void)0)

#endif /* __V850_PGTABLE_H__ */
