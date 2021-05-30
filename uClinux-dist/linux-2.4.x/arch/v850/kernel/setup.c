/*
 * arch/v850/kernel/setup.c -- Arch-dependent initialization functions
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

#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/bootmem.h>
#include <linux/irq.h>
#include <linux/reboot.h>
#include <linux/personality.h>

#include <asm/irq.h>

#ifdef CONFIG_TIME_BOOTUP
#include <asm/highres_timer.h>
#endif

#include "mach.h"

extern int _intv_start, _intv_end;
extern int _start, _stext, _etext, _sdata, _edata, _sbss, _ebss, _end;

char command_line[512];
char saved_command_line[512];

/* Memory not used by the kernel.  */
static unsigned long total_ram_pages;

/* System RAM.  */
static unsigned long ram_start = 0, ram_len = 0;

#define ADDR_TO_PAGE_UP(x)   ((((unsigned long)x) + PAGE_SIZE-1) >> PAGE_SHIFT)
#define ADDR_TO_PAGE(x)	     (((unsigned long)x) >> PAGE_SHIFT)
#define PAGE_TO_ADDR(x)	     (((unsigned long)x) << PAGE_SHIFT)

static void init_mem_alloc (unsigned long ram_start, unsigned long ram_len);

void __init setup_arch (char **cmdline)
{
	/* Keep a copy of command line */
	*cmdline = command_line;
	memcpy (saved_command_line, command_line, sizeof saved_command_line);
	saved_command_line[sizeof saved_command_line - 1] = '\0';

	console_verbose ();

	init_mm.start_code = (unsigned long) &_stext;
	init_mm.end_code = (unsigned long) &_etext;
	init_mm.end_data = (unsigned long) &_edata;
	init_mm.brk = (unsigned long) &_end;

	/* Find out what mem this machine has.  */
	mach_get_physical_ram (&ram_start, &ram_len);
	/* ... and tell the kernel about it.  */
	init_mem_alloc (ram_start, ram_len);

	/* do machine-specific setups.  */
	mach_setup (cmdline);
}

void __init trap_init (void)
{
}

static void irq_nop (unsigned irq) { }
static unsigned irq_zero (unsigned irq) { return 0; }

static void nmi_end (unsigned irq)
{
	if (irq > FIRST_NMI) {
		printk (KERN_CRIT "NMI %d is unrecoverable; restarting...",
			irq - FIRST_NMI);
		machine_restart (0);
	}
}

static struct hw_interrupt_type nmi_irq_type = {
	"NMI",
	irq_zero,		/* startup */
	irq_nop,		/* shutdown */
	irq_nop,		/* enable */
	irq_nop,		/* disable */
	irq_nop,		/* ack */
	nmi_end,		/* end */
};

void __init init_IRQ (void)
{
	init_irq_handlers (0, NUM_MACH_IRQS, 0);
	init_irq_handlers (FIRST_NMI, NUM_NMIS, &nmi_irq_type);
	mach_init_irqs ();
}

void __init mem_init (void)
{
	max_mapnr = MAP_NR (ram_start + ram_len);

	num_physpages = ADDR_TO_PAGE (ram_len);

	total_ram_pages = free_all_bootmem ();

	printk ("Memory: %luK/%luK available"
		" (%luK kernel code, %luK data)\n",
		PAGE_TO_ADDR (nr_free_pages()) / 1024,
		ram_len / 1024,
		((unsigned long)&_etext - (unsigned long)&_stext) / 1024,
		((unsigned long)&_ebss - (unsigned long)&_sdata) / 1024);
}

void free_initmem (void)
{
	extern char __init_begin, __init_end;
	unsigned long start = PAGE_ALIGN ((unsigned long)(&__init_begin));
	unsigned long end = PAGE_ALIGN ((unsigned long)(&__init_end));
	unsigned long addr;

	printk("Freeing unused kernel memory: %ldK freed\n",
	       (end - start) / 1024);

	for (addr = start; addr < end; addr += PAGE_SIZE) {
		mem_map_t *page = virt_to_page (addr);
		ClearPageReserved (page);
		set_page_count (page, 1);
		__free_page (page);
		total_ram_pages++;
	}
}

void si_meminfo (struct sysinfo *info)
{
	info->totalram = total_ram_pages;
	info->sharedram = 0;
	info->freeram = nr_free_pages ();
	info->bufferram = atomic_read (&buffermem_pages);
	info->totalhigh = 0;
	info->freehigh = 0;
	info->mem_unit = PAGE_SIZE;
}


/* Initialize the `bootmem allocator'.  RAM_START and RAM_LEN identify
   what RAM may be used.  */
static void __init
init_bootmem_alloc (unsigned long ram_start, unsigned long ram_len)
{
	/* Address range of the `kernel proper'.  */
	unsigned long kernel_start = (unsigned long)&_start;
	unsigned long kernel_end = (unsigned long)&_end;
	/* End of the managed RAM space.  */
	unsigned long ram_end = ram_start + ram_len;
	/* Address range of the interrupt vector table.  */
	unsigned long intv_start = (unsigned long)&_intv_start;
	unsigned long intv_end = (unsigned long)&_intv_end;
	/* How long we think the bootmem allocation bitmap will be.  */
	unsigned guess_bootmap_len = ram_end / PAGE_SIZE / 8;
	/* True if the kernel is in the managed RAM area.  */
	int kernel_in_ram = (kernel_end > ram_start && kernel_start < ram_end);
	/* True if the interrupt vectors are in the managed RAM area.  */
	int intv_in_ram = (intv_end > ram_start && intv_start < ram_end);
	/* True if the interrupt vectors are inside the kernel proper.  */
	int intv_in_kernel
		= (intv_end > kernel_start && intv_start < kernel_end);
	/* Address and length of the bootmem allocator's allocation bitmap.  */
	unsigned long bootmap, bootmap_len;

	/* Decide where to locate the bootmap.  */
	if (kernel_in_ram)
		/* Put it right after the kernel.  */
		bootmap = kernel_end;
	else if (ram_start < intv_end
		 && ram_start + guess_bootmap_len > intv_start)
		/* Put it at the beginning of RAM, but make sure to skip
		   the interrupt vectors.  */
		bootmap = intv_end;
	else
		/* Just put it at the start of RAM, since RAM doesn't
		   start at 0.  */
		bootmap = ram_start;

	/* Round bootmap location up to next page.  */
	bootmap = PAGE_TO_ADDR (ADDR_TO_PAGE_UP (bootmap));

	/* Initialize bootmem allocator.  */
	bootmap_len = init_bootmem_node (NODE_DATA (0),
					 ADDR_TO_PAGE (bootmap),
					 ADDR_TO_PAGE (PAGE_OFFSET),
					 ADDR_TO_PAGE (ram_end));

	/* Now make the RAM actually allocatable (it starts out `reserved'). */
	free_bootmem (ram_start, ram_len);

	if (kernel_in_ram)
		/* Reserve the kernel address space, so it doesn't get
		   allocated.  */
		reserve_bootmem (kernel_start, kernel_end - kernel_start);
	
	if (intv_in_ram && !intv_in_kernel)
		/* Reserve the interrupt vector space.  */
		reserve_bootmem (intv_start, intv_end - intv_start);

	/* Reserve the bootmap space.  */
	reserve_bootmem (bootmap, bootmap_len);

	/* Let the platform-dependent code reserve some too.  */
	if (mach_reserve_bootmem)
		mach_reserve_bootmem ();
}

/* Tell the kernel about what RAM it may use for memory allocation.  */
static void __init
init_mem_alloc (unsigned long ram_start, unsigned long ram_len)
{
	unsigned i;
	unsigned long zones_size[MAX_NR_ZONES];

	init_bootmem_alloc (ram_start, ram_len);

	for (i = 0; i < MAX_NR_ZONES; i++)
		zones_size[i] = 0;

	/* We stuff all the memory into one area, which includes the
	   initial gap from PAGE_OFFSET to ram_start.  */
	zones_size[ZONE_DMA]
		= ADDR_TO_PAGE (ram_len + (ram_start - PAGE_OFFSET));

	free_area_init_node (0, 0, 0, zones_size, PAGE_OFFSET, 0);
}
