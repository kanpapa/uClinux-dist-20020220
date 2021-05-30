/*
 * arch/v850/kernel/ptrace.c -- `ptrace' system call
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

#include <asm/errno.h>

/* Not implemented yet.  XXX  */
int sys_ptrace (long request, long pid, long addr, long data)
{
	return -ENOSYS;
}

void ptrace_disable (struct task_struct *child)
{
	/* There's no ptracing yet, so nothing to disable.  */
}
