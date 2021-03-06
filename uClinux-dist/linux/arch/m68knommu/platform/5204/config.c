/***************************************************************************/

/*
 *	linux/arch/coldfire/kernel/config.c
 *
 *	Copyright (C) 1999, Greg Ungerer (gerg@snapgea.com)
 *	Copyright (C) 2000, Lineo Inc. (www.lineo.com) 
 *	Copyright (C) 2001, Snapgear (www.snapgear.com) 
 */

/***************************************************************************/

#include <linux/config.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/param.h>
#include <asm/irq.h>
#include <asm/dma.h>
#include <asm/traps.h>
#include <asm/machdep.h>
#include <asm/coldfire.h>
#include <asm/mcftimer.h>
#include <asm/mcfsim.h>
#include <asm/mcfdma.h>

#include <asm/mcfwdebug.h>

/***************************************************************************/

extern void * _ramvec[];

/***************************************************************************/

#ifdef MCFDMA_BASE0
/*
 *	DMA channel base address table.
 */
unsigned int   dma_base_addr[MAX_DMA_CHANNELS] = {
        MCF_MBAR + MCFDMA_BASE0,
        MCF_MBAR + MCFDMA_BASE1,
        0
};
#endif /* MCFDMA_BASE0 */

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
	volatile unsigned char	*icrp;

	/* Set up TIMER 1 as poll clock */
	timerp = (volatile unsigned short *) (MCF_MBAR + MCFTIMER_BASE1);
	timerp[MCFTIMER_TMR] = MCFTIMER_TMR_DISABLE;

	timerp[MCFTIMER_TRR] = (unsigned short) ((MCF_CLK / 16) / HZ);
	timerp[MCFTIMER_TMR] = MCFTIMER_TMR_ENORI | MCFTIMER_TMR_CLK16 |
		MCFTIMER_TMR_RESTART | MCFTIMER_TMR_ENABLE;

	icrp = (volatile unsigned char *) (MCF_MBAR + MCFSIM_TIMER1ICR);

	*icrp = MCFSIM_ICR_AUTOVEC | MCFSIM_ICR_LEVEL5 | MCFSIM_ICR_PRI3;
	request_irq(29, handler, SA_INTERRUPT, "ColdFire Timer", NULL);
	mcf_setimr(mcf_getimr() & ~MCFSIM_IMR_TIMER1);
}

/***************************************************************************/

/*
 *	Program the vector to be an auto-vectored.
 */

void mcf_autovector(unsigned int vec)
{
	volatile unsigned char  *mbar;

	if ((vec >= 25) && (vec <= 31)) {
		mbar = (volatile unsigned char *) MCF_MBAR;
		vec = 0x1 << (vec - 24);
		*(mbar + MCFSIM_AVR) |= vec;
		mcf_setimr(mcf_getimr() & ~vec);
	}
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
	mcf_setimr(MCFSIM_IMR_MASKALL);
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
	printk("\nUSP: %08x   KSP: %08x\n", sw_usp, sw_ksp);

	printk("\nCODE:");
	tp = ((unsigned char *) fp->pc) - 0x20;
	for (sp = (unsigned long *) tp, i = 0; (i < 0x40);  i += 4) {
		if ((i % 0x10) == 0)
			printk("\n%08x: ", (int) (tp + i));
		printk("%08x ", (int) *sp++);
	}
	printk("\n");

	printk("\nKERNEL STACK:");
	tp = (unsigned char *) fp;
	for (sp = (unsigned long *) tp, i = 0; (i < 0x80); i += 4) {
		if ((i % 0x10) == 0)
			printk("\n%08x: ", (int) (tp + i));
		printk("%08x ", (int) *sp++);
	}
	printk("\n");
	if (STACK_MAGIC != *(unsigned long *)current->kernel_stack_page)
                printk("(Possibly corrupted stack page??)\n");
	printk("\n");
}

/***************************************************************************/

void tprint(const char *p)
{
        char c;
 
        while ((c = *(p++)) != 0) {
                if(c == '\n')
                        out_char('\r');
                out_char(c);
        }
        return;
}

/***************************************************************************/

void config_BSP(char *commandp, int size)
{
#if 0
	extern void rs_console_init(void);
	extern void rs_console_print(const char *b);
	rs_console_init();
	register_console(rs_console_print);
	memset(commandp, 0, size);
#else
	register_console(tprint);
#endif
	mach_sched_init = coldfire_timer_init;
	mach_tick = coldfire_tick;
#if 0
	mach_trap_init = coldfire_trap_init;
#endif
}

/***************************************************************************/
