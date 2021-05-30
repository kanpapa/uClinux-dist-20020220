/*
 * include/asm-v850/asm.h -- Macros for writing assembly code
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

#undef __ALIGN
#undef __ALIGN_STR
#define __ALIGN .align 4
#define __ALIGN_STR ".align 4"

#define G_ENTRY(name)							      \
   __ALIGN;								      \
   .globl name;								      \
   .type  name,@function;						      \
   name
#define END(name)							      \
   .size  name,.-name

#define L_ENTRY(name)							      \
   __ALIGN;								      \
   .type  name,@function;						      \
   name
