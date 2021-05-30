/*
 * include/asm-v850/rte_cb.c -- Midas lab RTE-CB series of evaluation boards
 *
 *  Copyright (C) 2001,2002  NEC Corporation
 *  Copyright (C) 2001,2002  Miles Bader <miles@gnu.org>
 *
 * This file is subject to the terms and conditions of the GNU General
 * Public License.  See the file COPYING in the main directory of this
 * archive for more details.
 *
 * Written by Miles Bader <miles@gnu.org>
 */

#include <linux/config.h>
#include <linux/init.h>
#include <linux/irq.h>
#include <linux/fs.h>
#include <linux/major.h>

#include <asm/machdep.h>
#include <asm/nb85e_uart.h>

#include "mach.h"

static void led_tick (void);

#ifdef CONFIG_RTE_CB_MULTI
extern void multi_init (void);
#endif


#ifdef CONFIG_ROM_KERNEL
/* Initialization for kernel in ROM.  */
static inline rom_kernel_init (void)
{
	/* If the kernel is in ROM, we have to copy any initialized data
	   from ROM into RAM.  */
	extern unsigned long _data_load_start, _sdata, _edata;
	register unsigned long *src = &_data_load_start;
	register unsigned long *dst = &_sdata, *end = &_edata;

	while (dst != end)
		*dst++ = *src++;
}
#endif /* CONFIG_ROM_KERNEL */

void __init mach_early_init (void)
{
	nb85e_intc_disable_irqs ();

#if defined (CONFIG_ROM_KERNEL)
	rom_kernel_init ();
#elif defined (CONFIG_RTE_CB_MULTI)
	multi_init ();
#endif
}

void __init mach_setup (char **cmdline)
{
	printk ("CPU: %s\n"
		"Platform: %s%s\n",
		CHIP_LONG,
		PLATFORM_LONG,
#ifdef CONFIG_ROM_KERNEL
		""
#elif defined (CONFIG_RTE_CB_MULTI)
		" (with Multi ROM monitor)"
#else
		" (with ROM monitor)"
#endif		
		);

	/* Probe for Mother-A, and print a message if we find it.  */
	*(volatile long *)MB_A_SRAM_ADDR = 0xDEADBEEF;
	if (*(volatile long *)MB_A_SRAM_ADDR == 0xDEADBEEF) {
		*(volatile long *)MB_A_SRAM_ADDR = 0x12345678;
		if (*(volatile long *)MB_A_SRAM_ADDR == 0x12345678)
			printk ("          NEC SolutionGear/Midas lab"
				" RTE-MOTHER-A motherboard\n");
	}

#if defined (CONFIG_NB85E_UART) && !defined (CONFIG_TIME_BOOTUP)
	nb85e_uart_cons_init ();
#endif

	mach_tick = led_tick;

	ROOT_DEV = MKDEV (BLKMEM_MAJOR, 0);
}

#ifdef CONFIG_TIME_BOOTUP
void initial_boot_done (void)
{
#ifdef CONFIG_NB85E_UART
	nb85e_uart_cons_init ();
#endif
}
#endif

void machine_restart (char *__unused)
{
#ifdef CONFIG_RESET_GUARD
	disable_reset_guard ();
#endif
	__asm__ __volatile__ ("jmp r0"); /* Jump to the reset vector.  */
}

void machine_halt (void)
{
#ifdef CONFIG_RESET_GUARD
	disable_reset_guard ();
#endif
	for (;;)
		__asm__ __volatile__ ("halt");
}

void machine_power_off (void)
{
	machine_halt ();
}


/* Animated LED display for timer tick.  */

#define TICK_UPD_FREQ	6
static int tick_frames[][10] = {
	{ 0xfe, 0xfd, 0xfb, 0xf7, 0xef, 0xdf, -1 },
	{ 0x9c, 0xa3, -1 },
	{ 0xa3, 0xff, -1 },
	{ 0x9c, 0xff, -1 },
	{ -1 }
};

static void led_tick ()
{
	static unsigned counter = 0;

	if (++counter == (HZ / TICK_UPD_FREQ)) {
		static unsigned frame_nums[LED_NUM_DIGITS] = { 0 };
		int digit;

		for (digit = 0;
		     digit < LED_NUM_DIGITS && tick_frames[digit][0] >= 0;
		     digit++)
		{
			int frame = tick_frames[digit][frame_nums[digit]];
			if (frame < 0) {
				LED (digit) = tick_frames[digit][0];
				frame_nums[digit] = 1;
			} else {
				LED (digit) = frame;
				frame_nums[digit]++;
				break;
			}
		}
		
		counter = 0;
	}
}


/* Mother-A interrupts.  */

#ifdef CONFIG_GBUS_INT

#define L GBUS_INT_PRIORITY_LOW
#define M GBUS_INT_PRIORITY_MEDIUM
#define H GBUS_INT_PRIORITY_HIGH

static struct gbus_int_irq_init gbus_irq_inits[] = {
#ifdef CONFIG_RTE_MB_A_PCI
	{ "MB_A_LAN",	IRQ_MB_A_LAN,		1,			L },
	{ "MB_A_PCI1",	IRQ_MB_A_PCI1(0),	IRQ_MB_A_PCI1_NUM,	L },
	{ "MB_A_PCI2",	IRQ_MB_A_PCI2(0),	IRQ_MB_A_PCI2_NUM,	L },
	{ "MB_A_EXT",	IRQ_MB_A_EXT(0),	IRQ_MB_A_EXT_NUM,	L },
	{ "MB_A_USB_OC",IRQ_MB_A_USB_OC(0),	IRQ_MB_A_USB_OC_NUM,	L },
	{ "MB_A_PCMCIA_OC",IRQ_MB_A_PCMCIA_OC,	1,			L },
#endif
	{ 0 }
};
#define NUM_GBUS_IRQ_INITS  \
   ((sizeof gbus_irq_inits / sizeof gbus_irq_inits[0]) - 1)

static struct hw_interrupt_type gbus_hw_itypes[NUM_GBUS_IRQ_INITS];

#endif /* CONFIG_GBUS_INT */

void __init rte_cb_init_irqs (void)
{
#ifdef CONFIG_GBUS_INT
	gbus_int_init_irqs ();
	gbus_int_init_irq_types (gbus_irq_inits, gbus_hw_itypes);
#endif /* CONFIG_GBUS_INT */
}
