/****************************************************************************/

/*
 *	coldfire.h -- Motorola ColdFire CPU sepecific defines
 *
 *	(C) Copyright 1999-2002, Greg Ungerer (gerg@snapgear.com)
 *	(C) Copyright 2000, Lineo (www.lineo.com)
 */

/****************************************************************************/
#ifndef	coldfire_h
#define	coldfire_h
/****************************************************************************/

#include <linux/config.h>

/*
 *	Define the processor support peripherals base address.
 *	This is generally setup by the boards start up code.
 */
#define	MCF_MBAR	0x10000000

/*
 *	Define master clock frequency.
 */
#if defined(CONFIG_CLOCK_16MHz)
#define	MCF_CLK		16000000
#elif defined(CONFIG_CLOCK_20MHz)
#define	MCF_CLK		20000000
#elif defined(CONFIG_CLOCK_25MHz)
#define	MCF_CLK		25000000
#elif defined(CONFIG_CLOCK_33MHz)
#define	MCF_CLK		33000000
#elif defined(CONFIG_CLOCK_40MHz)
#define	MCF_CLK		40000000
#elif defined(CONFIG_CLOCK_45MHz)
#define	MCF_CLK		45000000
#elif defined(CONFIG_CLOCK_50MHz)
#define	MCF_CLK		50000000
#elif defined(CONFIG_CLOCK_54MHz)
#define	MCF_CLK		54000000
#elif defined(CONFIG_CLOCK_60MHz)
#define	MCF_CLK		60000000
#elif defined(CONFIG_CLOCK_66MHz)
#define	MCF_CLK		66000000
#else
#error "Don't know what your ColdFire CPU clock frequency is??"
#endif

/****************************************************************************/
#endif	/* coldfire_h */
