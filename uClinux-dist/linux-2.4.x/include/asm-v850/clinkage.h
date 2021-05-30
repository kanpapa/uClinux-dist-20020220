/*
 * include/asm-v850/clinkage.h -- Macros to reflect C symbol-naming conventions
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

#include <asm/macrology.h>
#include <asm/asm.h>

#define C_SYMBOL_NAME(name) 	macrology_paste(_, name)
#define C_ENTRY(name)		G_ENTRY(C_SYMBOL_NAME(name))
#define C_END(name)		END(C_SYMBOL_NAME(name))
