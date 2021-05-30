/*
 * include/asm-v850/irq.h -- Machine interrupt handling
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

#ifndef __V850_IRQ_H__
#define __V850_IRQ_H__

#include <asm/machdep.h>

/* v850 processors have 3 non-maskable interrupts.  */
#define NUM_NMIS	3

/* Includes both maskable and non-maskable irqs.  */
#define NR_IRQS		(NUM_MACH_IRQS + NUM_NMIS)
/* NMIs have IRQ numbers from FIRST_NMI to FIRST_NMI+NUM_NMIS-1.  */
#define FIRST_NMI	NUM_MACH_IRQS


#ifndef __ASSEMBLY__

struct pt_regs;
struct hw_interrupt_type;
struct irqaction;

/* Initialize irq handling for IRQs BASE to BASE+NUM-1 to IRQ_TYPE.
   An IRQ_TYPE of 0 means to use a generic interrupt type.  */
extern void init_irq_handlers (int base_irq, int num,
			       struct hw_interrupt_type *irq_type);

typedef void (*irq_handler_t)(int irq, void *data, struct pt_regs *regs);

/* Handle interrupt IRQ.  REGS are the registers at the time of ther
   interrupt.  */
extern unsigned int handle_irq (int irq, struct pt_regs *regs);

#endif /* !__ASSEMBLY__ */

#endif /* __V850_IRQ_H__ */
