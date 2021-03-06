/***************************************************************************/

/*
 *	linux/arch/m68knommu/platform/5272/config.c
 *
 *	Copyright (C) 1999-2001, Greg Ungerer (gerg@snapgear.com)
 *	Copyright (C) 2001, SnapGear (www.snapgear.com)
 */

/***************************************************************************/

#include <linux/config.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/param.h>
#include <asm/irq.h>
#include <asm/dma.h>
#include <asm/delay.h>
#include <asm/traps.h>
#include <asm/machdep.h>
#include <asm/coldfire.h>
#include <asm/mcftimer.h>
#include <asm/mcfsim.h>
#include <asm/mcfdma.h>

#include <asm/mcfwdebug.h>

/***************************************************************************/

void	reset_setupbutton(void);

/***************************************************************************/

/*
 *	DMA channel base address table.
 */
unsigned int   dma_base_addr[MAX_DMA_CHANNELS] = {
        MCF_MBAR + MCFDMA_BASE0,
};

/***************************************************************************/

void coldfire_tick(void)
{
	volatile unsigned char	*timerp;

	/* Reset the ColdFire timer */
	timerp = (volatile unsigned char *) (MCF_MBAR + MCFTIMER_BASE1);
	timerp[MCFTIMER_TER] = MCFTIMER_TER_CAP | MCFTIMER_TER_REF;
}

/***************************************************************************/

void coldfire_timer_init(void (*handler)(int, void *, struct pt_regs *))
{
	volatile unsigned short	*timerp;
	volatile unsigned long	*icrp;

	/* Set up TIMER 1 as poll clock */
	timerp = (volatile unsigned short *) (MCF_MBAR + MCFTIMER_BASE1);
	timerp[MCFTIMER_TMR] = MCFTIMER_TMR_DISABLE;

	timerp[MCFTIMER_TRR] = (unsigned short) ((MCF_CLK / 16) / HZ);
	timerp[MCFTIMER_TMR] = MCFTIMER_TMR_ENORI | MCFTIMER_TMR_CLK16 |
		MCFTIMER_TMR_RESTART | MCFTIMER_TMR_ENABLE;

	icrp = (volatile unsigned long *) (MCF_MBAR + MCFSIM_ICR1);
	*icrp = 0x0000d000; /* TMR1 with priority 5 */
	request_irq(69, handler, SA_INTERRUPT, "ColdFire Timer", NULL);

#ifdef CONFIG_RESETSWITCH
	/* This is not really the right place to do this... */
	reset_setupbutton();
#endif
}

/***************************************************************************/

/*
 *	Program the vector to be an auto-vectored.
 */

void mcf_autovector(unsigned int vec)
{
	/* Everything is auto-vectored on the 5272 */
}

/***************************************************************************/

extern e_vector	*_ramvec;

void set_evector(int vecnum, void (*handler)(void))
{
	if (vecnum >= 0 && vecnum <= 255)
		_ramvec[vecnum] = handler;
}

/***************************************************************************/

/* assembler routines */
asmlinkage void buserr(void);
asmlinkage void trap(void);
asmlinkage void system_call(void);
asmlinkage void intrhandler(void);

void coldfire_trap_init(void)
{
	int i;
#ifdef MCF_MEMORY_PROTECT
	extern unsigned long _end;
	extern unsigned long memory_end;
#endif

#ifndef ENABLE_dBUG
	volatile unsigned long	*icrp;

	icrp = (volatile unsigned long *) (MCF_MBAR + MCFSIM_ICR1);
	icrp[0] = 0x88888888;
	icrp[1] = 0x88888888;
	icrp[2] = 0x88888888;
	icrp[3] = 0x88888888;
#endif

	/*
	 *	There is a common trap handler and common interrupt
	 *	handler that handle almost every vector. We treat
	 *	the system call and bus error special, they get their
	 *	own first level handlers.
	 */
#ifndef ENABLE_dBUG
	for (i = 3; (i <= 23); i++)
		_ramvec[i] = trap;
	for (i = 33; (i <= 63); i++)
		_ramvec[i] = trap;
#endif

	for (i = 24; (i <= 30); i++)
		_ramvec[i] = intrhandler;
#ifndef ENABLE_dBUG
	_ramvec[31] = intrhandler;  // Disables the IRQ7 button
#endif

	for (i = 64; (i < 255); i++)
		_ramvec[i] = intrhandler;
	_ramvec[255] = 0;

	_ramvec[2] = buserr;
	_ramvec[32] = system_call;

#ifdef MCF_MEMORY_PROTECT
	/* In order to protect memory, we set up an address range breakpoint
	 * that starts from address 0 and go until the end of the kernel image
	 * plus data.  This doens't protect the kernel stack, hardware devices
	 * or user processes from each other but it is better than nothing.
	 */
	wdebug(MCFDEBUG_ABLR, &_end);		/* Start of range */
	wdebug(MCFDEBUG_ABHR, memory_end);	/* End of range */
	
	/* Now set the trigger register:
	 * Ignore RW bit, ignore size field, only user mode accesses
	 */
	wdebug(MCFDEBUG_AATR, 0xe300);
	
	/* Activate the break point as a level one trigger outside address range */
	wdebug(MCFDEBUG_TDR,
			MCFDEBUG_TDR_TRC_INTR | MCFDEBUG_TDR_LXT1 |
			MCFDEBUG_TDR_EBL1 | MCFDEBUG_TDR_EAI1);
	printk("Protected memory outside %#x to %#x\n", (int)&_end, (int)memory_end);
#endif
}

/***************************************************************************/

/*
 *	Generic dumping code. Used for panic and debug.
 */

void dump(struct pt_regs *fp)
{
	extern unsigned int sw_usp, sw_ksp;
	unsigned long	*sp;
	unsigned char	*tp;
	int		i;

	printk("\nCURRENT PROCESS:\n\n");
	printk("COMM=%s PID=%d\n", current->comm, current->pid);
	printk("TEXT=%08x-%08x DATA=%08x-%08x BSS=%08x-%08x\n",
		(int) current->mm->start_code,
		(int) current->mm->end_code,
		(int) current->mm->start_data,
		(int) current->mm->end_data,
		(int) current->mm->end_data,
		(int) current->mm->brk);
	printk("USER-STACK=%08x  KERNEL-STACK=%08x\n\n",
		(int) current->mm->start_stack,
		(int) current->kernel_stack_page);

	printk("PC: %08lx\n", fp->pc);
	printk("SR: %08lx    SP: %08lx\n", (long) fp->sr, (long) fp);
	printk("d0: %08lx    d1: %08lx    d2: %08lx    d3: %08lx\n",
		fp->d0, fp->d1, fp->d2, fp->d3);
	printk("d4: %08lx    d5: %08lx    a0: %08lx    a1: %08lx\n",
		fp->d4, fp->d5, fp->a0, fp->a1);
	printk("\nUSP: %08x   KSP: %08x   TRAPFRAME: %08x\n",
		sw_usp, sw_ksp, (unsigned int) fp);

	printk("\nCODE:");
	tp = ((unsigned char *) fp->pc) - 0x20;
	for (sp = (unsigned long *) tp, i = 0; (i < 0x40);  i += 4) {
		if ((i % 0x10) == 0)
			printk("\n%08x: ", (int) (tp + i));
		printk("%08x ", (int) *sp++);
	}
	printk("\n");

	printk("\nKERNEL STACK:");
	tp = ((unsigned char *) fp) - 0x40;
	for (sp = (unsigned long *) tp, i = 0; (i < 0xc0); i += 4) {
		if ((i % 0x10) == 0)
			printk("\n%08x: ", (int) (tp + i));
		printk("%08x ", (int) *sp++);
	}
	printk("\n");
	if (STACK_MAGIC != *(unsigned long *)current->kernel_stack_page)
                printk("(Possibly corrupted stack page??)\n");
	printk("\n");

#if 1
	printk("\nUSER STACK:");
	tp = (unsigned char *) sw_usp;
	for (sp = (unsigned long *) tp, i = 0; (i < 0x80); i += 4) {
		if ((i % 0x10) == 0)
			printk("\n%08x: ", (int) (tp + i));
		printk("%08x ", (int) *sp++);
	}
	printk("\n\n");
#endif
}

/***************************************************************************/

#ifdef CONFIG_RESETSWITCH

/*
 *	Routines to support the NETtel software reset button.
 */
void reset_button(int irq, void *dev_id, struct pt_regs *regs)
{
	volatile unsigned long	*icrp, *isrp;
	extern void		flash_eraseconfig(void);
	static int		inbutton = 0;

	/*
	 *	IRQ7 is not maskable by the CPU core. It is possible
	 *	that switch bounce mey get us back here before we have
	 *	really serviced the interrupt.
	 */
	if (inbutton)
		return;
	inbutton = 1;

	/* Disable interrupt at SIM - best we can do... */
	icrp = (volatile unsigned long *) (MCF_MBAR + MCFSIM_ICR1);
	*icrp = (*icrp & 0x07777777) | 0x80000000;

	/* Try and de-bounce the switch a little... */
	udelay(10000);

	flash_eraseconfig();

	/* Don't leave here 'till button is no longer pushed! */
	isrp = (volatile unsigned long *) (MCF_MBAR + MCFSIM_ISR);
	for (;;) {
		if (*isrp & 0x80000000)
			break;
	}

	HARD_RESET_NOW();
	/* Should never get here... */

	inbutton = 0;
	/* Interrupt service done, acknowledge it */
	icrp = (volatile unsigned long *) (MCF_MBAR + MCFSIM_ICR1);
	*icrp = (*icrp & 0x07777777) | 0xf0000000;
}

/***************************************************************************/

void reset_setupbutton(void)
{
	volatile unsigned long	*icrp;

	icrp = (volatile unsigned long *) (MCF_MBAR + MCFSIM_ICR1);
	*icrp = (*icrp & 0x07777777) | 0xf0000000;
	request_irq(65, reset_button, (SA_INTERRUPT | IRQ_FLG_FAST),
		"Reset Button", NULL);
}

#endif /* CONFIG_RESETSWITCH */

/***************************************************************************/

void config_BSP(char *commandp, int size)
{
#ifdef CONFIG_FLASH_SNAPGEAR
	/* Copy command line from FLASH to local buffer... */
	memcpy(commandp, (char *) 0xf0004000, size);
	commandp[size-1] = 0;
	if (*commandp == (char) 0xff) /* erased flash */
		*commandp = '\0';
#else
	memset(commandp, 0, size);
#endif /* CONFIG_FLASH_SNAPGEAR */

	mach_sched_init = coldfire_timer_init;
	mach_tick = coldfire_tick;
	mach_trap_init = coldfire_trap_init;

#ifdef CONFIG_DS1302
{
	extern int ds1302_set_clock_mmss(unsigned long);
	extern void ds1302_gettod(int *, int *, int *, int *, int *, int *);
	mach_set_clock_mmss = ds1302_set_clock_mmss;
	mach_gettod = ds1302_gettod;
}
#endif
}

/***************************************************************************/
