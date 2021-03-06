/*
 * include/asm-v850/ma1.h -- V850E/MA1 cpu chip
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

#ifndef __V850_MA1_H__
#define __V850_MA1_H__

/* Inherit more generic details from MA series.  */
#include <asm/ma.h>

#define CHIP		"v850e/ma1"
#define CHIP_LONG	"NEC V850E/MA1"

/* Hardware-specific interrupt numbers (in the kernel IRQ namespace).  */
#define IRQ_INTOV(n)	(n)	/* 0-3 */
#define IRQ_INTOV_NUM	4
#define IRQ_INTP(n)	(0x4  + (n)) /* Pnnn (pin) interrupts */
#define IRQ_INTP_NUM	24
#define IRQ_INTCMD(n)	(0x1c + (n)) /* interval timer interrupts 0-3 */
#define IRQ_INTCMD_NUM	4
#define IRQ_INTDMA(n)	(0x20 + (n)) /* DMA interrupts 0-3 */
#define IRQ_INTDMA_NUM	4
#define IRQ_INTCSI(n)	(0x24 + (n)*4)/* CSI 0-2 transmit/receive completion */
#define IRQ_INTCSI_NUM	3
#define IRQ_INTSER(n)	(0x25 + (n)*4) /* UART 0-2 reception error */
#define IRQ_INTSER_NUM	3
#define IRQ_INTSR(n)	(0x26 + (n)*4) /* UART 0-2 reception completion */
#define IRQ_INTSR_NUM	3
#define IRQ_INTST(n)	(0x27 + (n)*4) /* UART 0-2 transmission completion */
#define IRQ_INTST_NUM	3

/* For <asm/irq.h> */
#define NUM_CHIP_IRQS	0x30
#define NUM_MACH_IRQS	NUM_CHIP_IRQS /* This is the default, but
					 platforms can override it. */

/* The MA1 has a UART with 3 channels.  */
#define NB85E_UART_NUM_CHANNELS	3


#endif /* __V850_MA1_H__ */
