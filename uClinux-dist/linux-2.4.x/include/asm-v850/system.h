/*
 * include/asm-v850/system.h -- Low-level interrupt/thread ops
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

#ifndef __V850_SYSTEM_H__
#define __V850_SYSTEM_H__

#include <linux/linkage.h>
#include <asm/ptrace.h>


#define prepare_to_switch()	do { } while (0)

/*
 * switch_to(n) should switch tasks to task ptr, first checking that
 * ptr isn't the current task, in which case it does nothing.
 */
struct thread_struct;
extern void *switch_thread (struct thread_struct *last,
			    struct thread_struct *next);
#define switch_to(prev,next,last)					      \
  do {									      \
        if (prev != next) {						      \
 		(last) = switch_thread (&prev->thread, &next->thread);	      \
	}								      \
  } while (0)


/* Enable/disable interrupts.  */
#define __sti() \
  __asm__ __volatile__ ("ei" ::: "memory")
#define __cli() \
  __asm__ __volatile__ ("di" ::: "memory")

#define __save_flags(flags) \
  __asm__ __volatile__ ("stsr %1, %0" : "=r" (flags) : "i" (SR_PSW))
#define __restore_flags(flags) \
  __asm__ __volatile__ ("ldsr %0, %1" :: "r" (flags), "i" (SR_PSW))
#define	__save_flags_cli(flags) \
  do { __save_flags (flags); __cli (); } while (0) 


/* For spinlocks etc */
#define local_irq_save(flags)	__save_flags_cli (flags)
#define local_irq_restore(flags) __restore_flags (flags)
#define local_irq_disable()	__cli ()
#define local_irq_enable()	__sti ()

#define cli()			__cli ()
#define sti()			__sti ()
#define save_flags(flags)	__save_flags (flags)
#define restore_flags(flags)	__restore_flags (flags)
#define save_flags_cli(flags)	__save_flags_cli (flags)

/*
 * Force strict CPU ordering.
 * Not really required on v850...
 */
#define nop()			__asm__ __volatile__ ("nop")
#define mb()			__asm__ __volatile__ ("" ::: "memory")
#define rmb()			mb ()
#define wmb()			mb ()
#define set_rmb(var, value)	do { xchg (&var, value); } while (0)
#define set_mb(var, value)	set_rmb (var, value)
#define set_wmb(var, value)	do { var = value; wmb (); } while (0)

#ifdef CONFIG_SMP
#define smp_mb()	mb ()
#define smp_rmb()	rmb ()
#define smp_wmb()	wmb ()
#else
#define smp_mb()	barrier ()
#define smp_rmb()	barrier ()
#define smp_wmb()	barrier ()
#endif

#define xchg(ptr, with) \
  ((__typeof__ (*(ptr)))__xchg ((unsigned long)(with), (ptr), sizeof (*(ptr))))
#define tas(ptr) (xchg ((ptr), 1))

extern inline unsigned long __xchg (unsigned long with,
				    __volatile__ void *ptr, int size)
{
	unsigned long tmp, flags;

	save_flags_cli (flags);

	switch (size) {
	case 1:
		tmp = *(unsigned char *)ptr;
		*(unsigned char *)ptr = with;
		break;
	case 2:
		tmp = *(unsigned short *)ptr;
		*(unsigned short *)ptr = with;
		break;
	case 4:
		tmp = *(unsigned long *)ptr;
		*(unsigned long *)ptr = with;
		break;
	}

	restore_flags (flags);

	return tmp;
}

#endif /* __V850_SYSTEM_H__ */
