/*
 * BK Id: SCCS/s.mcrfs.c 1.6 05/17/01 18:14:23 cort
 */
#include <linux/types.h>
#include <linux/errno.h>
#include <asm/uaccess.h>

#include "soft-fp.h"

int
mcrfs(u32 *ccr, u32 crfD, u32 crfS)
{
	u32 value, clear;

#ifdef DEBUG
	printk("%s: %p (%08x) %d %d\n", __FUNCTION__, ccr, *ccr, crfD, crfS);
#endif

	clear = 15 << ((7 - crfS) << 2);
	if (!crfS)
		clear = 0x90000000;

	value = (__FPU_FPSCR >> ((7 - crfS) << 2)) & 15;
	__FPU_FPSCR &= ~(clear);

	*ccr &= ~(15 << ((7 - crfD) << 2));
	*ccr |= (value << ((7 - crfD) << 2));

#ifdef DEBUG
	printk("CR: %08x\n", __FUNCTION__, *ccr);
#endif

	return 0;
}
