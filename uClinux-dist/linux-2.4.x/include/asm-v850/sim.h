/*
 * include/asm-v850/sim.h -- Machine-dependent defs for GDB v850e simulator
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

#ifndef __V850_SIM_H__
#define __V850_SIM_H__


/* For <asm/entry.h> */
#define ON_CHIP_RAM_ADDR	0xFFFFF000


/* For <asm/param.h> */
#ifndef HZ
#define HZ			24	/* Minimum supported frequency.  */
#endif

/* For <asm/irq.h> */
#define NUM_MACH_IRQS		6


#ifndef __ASSEMBLY__

/* For <asm/blkmem.h> */
/* This gives us a single arena.  */
#define CAT_ROMARRAY
/* These should be defined by sim startup.  */
extern unsigned long blkmem_0_addr, blkmem_0_len;
extern int blkmem_0_rw;
/* Make the single arena point use them.  */
#define FIXUP_ARENAS							      \
        arena[0].rw = blkmem_0_rw;					      \
	arena[0].address = blkmem_0_addr;				      \
	arena[0].length = blkmem_0_len;

#endif /* !__ASSEMBLY__ */


#endif /* __V850_SIM_H__ */
