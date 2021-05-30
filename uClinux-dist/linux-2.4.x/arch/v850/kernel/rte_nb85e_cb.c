/*
 * arch/v850/kernel/rte_nb85e_cb.c -- Midas labs RTE-V850E/NB85E-CB board
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

#include <linux/config.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/bootmem.h>
#include <linux/irq.h>

#include <asm/atomic.h>
#include <asm/page.h>
#include <asm/nb85e.h>
#include <asm/rte_nb85e_cb.h>

#include "mach.h"

void mach_get_physical_ram (unsigned long *ram_start, unsigned long *ram_len)
{
	/* Find memory used for root fs image.  */
	unsigned long blkmem_0_start = (unsigned long)&_blkmem_0_start;
	unsigned long blkmem_0_end = (unsigned long)&_blkmem_0_end;

	/* We just use SDRAM here; the kernel itself is in SRAM.  */
	*ram_start = SDRAM_ADDR;
	*ram_len = SDRAM_SIZE;

	/* See if the root fs image is in SDRAM (otherwise it doesn't
	   affect us).  */
	if (blkmem_0_end > blkmem_0_start
	    && blkmem_0_start < SDRAM_ADDR + SDRAM_SIZE
	    && blkmem_0_end >= SDRAM_ADDR)
	{
		if (blkmem_0_start == SDRAM_ADDR) {
			/* We only know how to deal with one case, where the
			   blkmem is exactly at the start of SDRAM.  */
			unsigned len = blkmem_0_end - blkmem_0_start;
			len = (len + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1);

			*ram_start += len;
			*ram_len -= len;
		} else
			printk ("Blkmem0 in strange place: 0lx%x - 0x%lx!\n",
				blkmem_0_start, blkmem_0_end);
	}
}

void mach_gettimeofday (struct timeval *tv)
{
	tv->tv_sec = 0;
	tv->tv_usec = 0;
}
