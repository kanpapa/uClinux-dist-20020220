/*
 * include/asm-v850/virtconvert.h -- conversion between virtual and
 * 	physical mappings
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

#ifndef __V850_VIRTCONVERT_H__
#define __V850_VIRTCONVERT_H__

#ifdef __KERNEL__

#include <asm/page.h>

#define mm_ptov(addr)		((void *)__phys_to_virt (addr))
#define mm_vtop(addr)		((unsigned long)__virt_to_phys (addr))
#define phys_to_virt(addr)	((void *)__phys_to_virt (addr))
#define virt_to_phys(addr)	((unsigned long)__virt_to_phys (addr))

#define virt_to_bus		virt_to_phys
#define bus_to_virt 		phys_to_virt

#endif /* __KERNEL__ */

#endif /* __V850_VIRTCONVERT_H__ */
