/*
 * arch/v850/kernel/head.S -- Lowest-level startup code
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
#include <asm/current.h>
#include <asm/entry.h>
#include <asm/irq.h>


	.text

	// Define `mach_early_init' as a weak symbol
	.global	C_SYMBOL_NAME(mach_early_init)
	.weak	C_SYMBOL_NAME(mach_early_init)

C_ENTRY(start):
	// Make sure interrupts are turned off, just in case
	di

#ifdef CONFIG_RESET_GUARD
	// See if we got here via an unexpected reset
	ld.w	RESET_GUARD, r19	// Check current value of reset guard
	mov	RESET_GUARD_ACTIVE, r20
	cmp	r19, r20
	bne	1f			// Guard was not active

	// If we get here, the reset guard was active.  Load up some
	// interesting values as arguments, and jump to the handler.
	st.w	r0, RESET_GUARD		// Allow further resets to succeed
	mov	lp, r6			// Arg 0: return address
	ld.b	KM, r7			// Arg 1: kernel mode
	mov	sp, r9			// Arg 3: stack pointer
	ld.w	KSP, r19		// maybe switch to kernel stack
	cmp	r7, r0			// see if already in kernel mode
	cmov	z, r19, sp, sp		//  and switch to kernel stack if not
	GET_CURRENT_TASK(r8)		// Arg 2: task pointer
	jr	C_SYMBOL_NAME(unexpected_reset)

1:	st.w	r20, RESET_GUARD	// Turn on reset guard
#endif /* CONFIG_RESET_GUARD */

	// Load the current task pointer (in r20) and stack.
	mov	hilo(C_SYMBOL_NAME(init_task_union)), CURRENT_TASK
	movea	KERNEL_STACK_SIZE, CURRENT_TASK, sp

	// See if there's a platform-specific early-initialization routine
	// defined; it's a weak symbol, so it will have an address of zero if
	// there's not.
	mov	hilo(C_SYMBOL_NAME(mach_early_init)), r6
	cmp	r6, r0
	bz	3f

	// There is one, so call it.  If this function is written in C, it
	// should be very careful -- the stack pointer is valid, but very
	// little else is (e.g., bss is not zeroed yet).
	jarl	2f, lp			// first figure out return address
2:	add	3f - ., lp
	jmp	[r6]			// do call

3:

#ifdef CONFIG_TIME_BOOTUP
	/* This stuff must come after mach_early_init, because interrupts may
	   not work until after its been called.  */
	jarl	C_SYMBOL_NAME(highres_timer_reset), lp
	jarl	C_SYMBOL_NAME(highres_timer_start), lp
#endif

	// Kernel stack pointer save location
	st.w	sp, KSP

	// Assert that we're in `kernel mode'
	mov	1, r19
	st.w	r19, KM

	// Zero bss area, since we can't rely upon any loader to do so
	mov	hilo(C_SYMBOL_NAME(_sbss)), ep
	mov	hilo(C_SYMBOL_NAME(_ebss)), r10
4:	sst.w	r0, 0[ep]
	add	4, ep
	cmp	ep, r10
	bne	4b

	// Start Linux kernel.
	jarl	C_SYMBOL_NAME(start_kernel), lp
	// fall through
END(start)

C_ENTRY(exit):
	halt
	br	C_SYMBOL_NAME(exit)	/* Should never get here */
END(exit)
