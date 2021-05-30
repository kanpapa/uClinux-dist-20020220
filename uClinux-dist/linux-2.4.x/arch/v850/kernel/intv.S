/*
 * arch/v850/kernel/intv.S -- Interrupt vectors
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

#include <asm/clinkage.h>
#include <asm/irq.h>
#include <asm/machdep.h>
#include <asm/entry.h>

#ifdef CONFIG_HIGHRES_TIMER
#include <asm/highres_timer.h>
#endif

/* Jump to an interrupt/trap handler.  These handlers (defined in entry.S)
   expect the stack-pointer to be saved in ENTRY_SP, so we use sp to do an
   indirect jump (which avoids problems when the handler is more than a signed
   22-bit offset away).  */
#define JUMP_TO_HANDLER(name) 						      \
	st.w	sp, ENTRY_SP;						      \
	mov	hilo(name), sp;						      \
	jmp	[sp]


	/* Interrupt vectors.  */
	.section	.intv.common, "ax"
	
	/* This is used to align the section, in case the linker script needs
	   to use wierd tricks.  */
	.balign	0x10

	/*  Start out with reset vector.  */
	.org	0x0
	JUMP_TO_HANDLER (C_SYMBOL_NAME (start))

	/* Now come interrupt vectors.  */
	.org	0x10
	JUMP_TO_HANDLER (nmi)			// NMI0
	.org	0x20
	JUMP_TO_HANDLER (nmi)			// NMI1
	.org	0x30
	JUMP_TO_HANDLER (nmi)			// NMI2
	
	.org	0x40
	JUMP_TO_HANDLER (trap)			// TRAP0n
	.org	0x50
	JUMP_TO_HANDLER (trap)			// TRAP1n

	.org	0x60
	JUMP_TO_HANDLER (illegal_instruction)	// illegal insn trap

	.org	0x70
	JUMP_TO_HANDLER (dbtrap)		// DBTRAP insn


	/* Hardware interrupt vectors.  */
	.section	.intv.mach, "ax"
	.org	0x0

#if defined (CONFIG_HIGHRES_TIMER) && defined (IRQ_INTCMD)

	/* Interrupts before the highres timer interrupt.  */
	.rept	IRQ_INTCMD (HIGHRES_TIMER_TIMER_D_UNIT)
	.balign	0x10
	JUMP_TO_HANDLER (irq)
	.endr

	/* The highres timer interrupt.  */
	.balign	0x10
	JUMP_TO_HANDLER (C_SYMBOL_NAME (highres_timer_slow_tick_irq))

	/* Interrupts after the highres timer interrupt.  */
	.rept	NUM_MACH_IRQS - IRQ_INTCMD (HIGHRES_TIMER_TIMER_D_UNIT) - 1
	.balign	0x10
	JUMP_TO_HANDLER (irq)
	.endr

#else /* No highres timer */

	.rept	NUM_MACH_IRQS
	.balign	0x10
	JUMP_TO_HANDLER (irq)
	.endr

#endif /* Highres timer */
