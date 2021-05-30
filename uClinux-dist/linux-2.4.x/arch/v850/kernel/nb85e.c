/*
 * arch/v850/kernel/nb85e.c -- Machine-specific code for NB85E cpu core
 *
 *  Copyright (C) 2001,2002  NEC Corporation
 *  Copyright (C) 2001,2002  Miles Bader <miles@gnu.org>
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
#include <asm/machdep.h>

#include "mach.h"

unsigned long cpu_clock_freq = CPU_CLOCK_FREQ;

#ifdef CONFIG_PROC_FS
int mach_print_cpu_info (struct seq_file *m, void *v)
{
	extern unsigned long loops_per_jiffy;
	return seq_printf (m,
			   "CPU-Family:	v850\n"
			   "CPU-Arch:	v850e\n"
			   "CPU-Model:	%s\n"
			   "BogoMips:	%lu.%02lu\n",
			   CHIP,
			   loops_per_jiffy/(500000/HZ),
			   (loops_per_jiffy/(5000/HZ)) % 100);
}
#endif /* CONFIG_PROC_FS */


/* Initialize hardware interrupt sources.  */

static void irq_nop (unsigned irq) { }

static unsigned nb85e_intc_irq_startup (unsigned irq)
{
	nb85e_intc_clear_pending_irq (irq);
	nb85e_intc_enable_irq (irq);
	return 0;
}

/* Initialize HW_IRQ_TYPES for INTC-controlled irqs described in array
   INITS (which is terminated by an entry with the name field == 0).  */
void __init nb85e_intc_init_irq_types (struct nb85e_intc_irq_init *inits,
				       struct hw_interrupt_type *hw_irq_types)
{
	struct nb85e_intc_irq_init *init;
	for (init = inits; init->name; init++) {
		int i;
		struct hw_interrupt_type *hwit = hw_irq_types++;

		hwit->typename = init->name;

		hwit->startup  = nb85e_intc_irq_startup;
		hwit->shutdown = nb85e_intc_disable_irq;
		hwit->enable   = nb85e_intc_enable_irq;
		hwit->disable  = nb85e_intc_disable_irq;
		hwit->ack      = irq_nop;
		hwit->end      = irq_nop;
		
		/* Initialize kernel IRQ infrastructure for this interrupt.  */
		init_irq_handlers (init->base, init->num, hwit);

		/* Set the interrupt priorities.  */
		for (i = 0; i < init->num; i++) {
			unsigned irq = init->base + i;

			/* If the interrupt is currently enabled (all
			   interrupts are initially disabled), then
			   assume whoever enabled it has set things up
			   properly, and avoid messing with it.  */
			if (! nb85e_intc_irq_enabled (irq))
				/* This write also (1) disables the
				   interrupt, and (2) clears any pending
				   interrupts.  */
				NB85E_INTC_IC (irq)
					= (NB85E_INTC_IC_PR (init->priority)
					   | NB85E_INTC_IC_MK);
		}
	}
}
