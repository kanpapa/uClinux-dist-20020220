/*
 * include/asm-v850/blkmem.h -- `blkmem' device configuration
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

#ifndef __V850_BLKMEM_H__
#define __V850_BLKMEM_H__

/* Device specific memory array location.  */
#include <asm/machdep.h>

/* Used by the blkmem flash programming code.  */
#define HARD_RESET_NOW() __asm__ __volatile__ ("jmp r0")

#endif /* __V850_BLKMEM_H__ */
