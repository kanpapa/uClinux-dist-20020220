/*
 * include/asm-v850/machdep.h -- Machine-dependent definitions
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

#ifndef __V850_MACHDEP_H__
#define __V850_MACHDEP_H__

#include <linux/config.h>

/* chips */
#ifdef CONFIG_V850E_MA1
#include <asm/ma1.h>
#endif
#ifdef CONFIG_V850E_TEG
#include <asm/teg.h>
#endif

/* platforms */
#ifdef CONFIG_RTE_MA1_CB
#include <asm/rte_ma1_cb.h>
#endif
#ifdef CONFIG_RTE_NB85E_CB
#include <asm/rte_nb85e_cb.h>
#endif
#ifdef CONFIG_SIM
#include <asm/sim.h>
#endif

#endif /* __V850_MACHDEP_H__ */
