/*
 * include/asm-v850/entry.h -- Definitions used by low-level trap handlers
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

#ifndef __V850_ENTRY_H__
#define __V850_ENTRY_H__


#include <asm/ptrace.h>
#include <asm/machdep.h>


/* If true, system calls save and restore all registers (except result
   registers, of course).  If false, then `call clobbered' registers
   will not be preserved, on the theory that system calls are basically
   function calls anyway, and the caller should be able to deal with it.
   This is a security risk, of course, as `internal' values may leak out
   after a system call, but that certainly doesn't matter very much for
   a processor with no MMU protection!  For a protected-mode kernel, it
   would be faster to just zero those registers before returning.  */
#define TRAPS_PRESERVE_CALL_CLOBBERED_REGS	0

/* If TRAPS_PRESERVE_CALL_CLOBBERED_REGS is false, then zero `call
   clobbered' registers before returning from a system call.  */
#define TRAPS_ZERO_CALL_CLOBBERED_REGS		0


/* These are special variables using by the kernel trap/interrupt code
   to save registers in, at a time when there are no spare registers we
   can use to do so, and we can't depend on the value of the stack
   pointer.  This means that they must be within a signed 16-bit
   displacement of 0x00000000.  */

#define KERNEL_VAR_SPACE_ADDR	ON_CHIP_RAM_ADDR

#ifdef __ASSEMBLY__
#define KERNEL_VAR(addr)	addr[r0]
#else
#define KERNEL_VAR(addr)	(*(volatile unsigned long *)(addr))
#endif

/* temporary storage for interrupt handlers, 4 bytes */
#define INT_SCRATCH_ADDR	KERNEL_VAR_SPACE_ADDR
#define INT_SCRATCH		KERNEL_VAR (INT_SCRATCH_ADDR)
/* where the stack-pointer is saved when jumping to interrupt handlers */
#define ENTRY_SP_ADDR		(KERNEL_VAR_SPACE_ADDR + 4)
#define ENTRY_SP		KERNEL_VAR (ENTRY_SP_ADDR)
/* kernel stack pointer, 4 bytes */
#define KSP_ADDR		(KERNEL_VAR_SPACE_ADDR + 8)
#define KSP			KERNEL_VAR (KSP_ADDR)
/* 1 if in kernel-mode, 0 if in user mode, 1 byte */
#define KM_ADDR 		(KERNEL_VAR_SPACE_ADDR + 12)
#define KM			KERNEL_VAR (KM_ADDR)

#ifdef CONFIG_RESET_GUARD
/* Used to detect unexpected resets (since the v850 has no MMU, any call
   through a null pointer will jump to the reset vector).  We detect
   such resets by checking for a magic value, RESET_GUARD_ACTIVE, in
   this location.  Properly resetting the machine stores zero there, so
   it shouldn't trigger the guard; the power-on value is uncertain, but
   it's unlikely to be RESET_GUARD_ACTIVE.  */
#define RESET_GUARD_ADDR	(KERNEL_VAR_SPACE_ADDR + 16)
#define RESET_GUARD		KERNEL_VAR (RESET_GUARD_ADDR)
#define RESET_GUARD_ACTIVE	0xFAB4BEEF
#endif /* CONFIG_RESET_GUARD */

#ifdef CONFIG_HIGHRES_TIMER
#define HIGHRES_TIMER_SLOW_TICKS_ADDR (KERNEL_VAR_SPACE_ADDR + 20)
#define HIGHRES_TIMER_SLOW_TICKS     KERNEL_VAR (HIGHRES_TIMER_SLOW_TICKS_ADDR)
#endif /* CONFIG_HIGHRES_TIMER */

#ifndef __ASSEMBLY__

#ifdef CONFIG_RESET_GUARD
/* Turn off reset guard, so that resetting the machine works normally.
   This should be called in the various machine_halt, etc., functions.  */
static inline void disable_reset_guard (void)
{
	RESET_GUARD = 0;
}
#endif /* CONFIG_RESET_GUARD */

#endif /* !__ASSEMBLY__ */


/* A `state save frame' is a struct pt_regs preceded by some extra space
   suitable for a function call stack frame.  */

/* Amount of room on the stack reserved for arguments and to satisfy the
   C calling conventions, in addition to the space used by the struct
   pt_regs that actually holds saved values.  */
#define STATE_SAVE_ARG_SPACE	(6*4) /* Up to six arguments.  */


#ifdef __ASSEMBLY__

/* The size of a state save frame.  */
#define STATE_SAVE_SIZE		(PT_SIZE + STATE_SAVE_ARG_SPACE)

#else /* !__ASSEMBLY__ */

/* The size of a state save frame.  */
#define STATE_SAVE_SIZE	       (sizeof (struct pt_regs) + STATE_SAVE_ARG_SPACE)

#endif /* __ASSEMBLY__ */


/* Offset of the struct pt_regs in a state save frame.  */
#define STATE_SAVE_PT_OFFSET	STATE_SAVE_ARG_SPACE


#endif /* __V850_ENTRY_H__ */
