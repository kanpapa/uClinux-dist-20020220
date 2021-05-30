/*
 * linux/arch/i960/kernel/ints.c
 *
 * Copyright (C) 1999	Keith Adams	<kma@cse.ogi.edu>
 * 			Oregon Graduate Institute
 *
 * Based on:
 *
 * linux/arch/i386/kernel/irq.c
 * 
 * Copyright (C) 1992 Linux Torvalds
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file COPYING in the main directory of this archive
 * for more details.
 *
 * N.B. that we treat "irq" as meaning, the high order four bits of the vector
 * number. Since there seems to be no way to set the low bits to something other
 * than 0010, this is good enough for us.
 */

#include <linux/types.h>
#include <linux/sched.h>
#include <linux/kernel_stat.h>
#include <linux/errno.h>
#include <linux/interrupt.h>
#include <linux/config.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#include <asm/atomic.h>
#include <asm/system.h>
#include <asm/irq.h>
#include <asm/traps.h>
#include <asm/page.h>
#include <asm/ptrace.h>
#include <asm/machdep.h>
#include <asm/i960.h>
#include <asm/unistd.h>

#if defined(CONFIG_I960JX) || defined(CONFIG_I960VH)
#include <asm/i960jx.h>
#endif

/*
 * device vectors; the *_HO macros are the corresponding indices into the
 * low-mem isr table
 */
#define NMI_VEC		248

#define LED	((unsigned char*)0xe0040000)
#define LED_THRESHOLD	(HZ/2)

#define TMR0_VEC_HO 0xd
#define TMR1_VEC_HO 0xe
#define XINT0_VEC_HO 1
#define XINT1_VEC_HO 2
#define XINT2_VEC_HO 3
#define XINT3_VEC_HO 4
#define XINT4_VEC_HO 5
#define XINT5_VEC_HO 6
#define XINT6_VEC_HO 7
#define XINT7_VEC_HO 8

static char* irq_names[] = {
	0,	/* 0 */
	"xint0",
	"xint1",
	"xint2",
	"xint3",	
	"serial",
	"xint5",
	"xint6",
	"xint7",
	0, 0, 0, 0,
	"timer0",
	"timer1",
	0,
};

#ifdef CONFIG_PROF_IRQ
static struct irqstat {
	unsigned long	min;
	unsigned long	avg;
	unsigned long	max;
} irqstat[16];
#endif

static void* pci_dev;
static const char* pci_name;
static void (*pci_isr)(int, void *, struct pt_regs *);

#define __VEC(ho)	(((ho) << 4) | 2)
#define TMR0_VEC __VEC(TMR0_VEC_HO)
#define TMR1_VEC __VEC(TMR1_VEC_HO)
#define XINT0_VEC __VEC(XINT0_VEC_HO)
#define XINT1_VEC __VEC(XINT1_VEC_HO)
#define XINT2_VEC __VEC(XINT2_VEC_HO)
#define XINT3_VEC __VEC(XINT3_VEC_HO)
#define XINT4_VEC __VEC(XINT4_VEC_HO)
#define SERIAL_VEC XINT4_VEC
#define PCI_VEC XINT1_VEC
#define XINT5_VEC __VEC(XINT5_VEC_HO)
#define XINT6_VEC __VEC(XINT6_VEC_HO)
#define XINT7_VEC __VEC(XINT7_VEC_HO)


void leave_kernel(struct pt_regs* regs);
static void nmi_intr(void);
static void bad_intr(unsigned char vec, struct pt_regs* regs);
static void xint(unsigned char ho, struct pt_regs* regs);
void stack_trace(void);

extern void intr(void);
static void program_clock(void);

#ifdef CONFIG_MON960
#include <asm/i960jx.h>
#include <asm/mon960.h>

static unsigned long get_mon960_serial_isr(void)
{
	prcb_t* prcb = (prcb_t*)get_prcbptr();
	unsigned long vec = (*(unsigned long*)IMAP1 & 0x0f00) >> 8;
	
	/* on cyclone, serial isr is XINT5 */
	return (unsigned long) prcb->pr_intr_tab->i_vectors[vec];
}

#endif

static void init_syscalls(void)
{
	unsigned long** prcb = (unsigned long**)get_prcbptr();
	unsigned long* syscall_tab = prcb[5];
	extern void syscall(void);
	/* we only use syscall 0, which is 12 words from the start of
	 * the syscall table. The entry type field of 0x2 indicates a call
	 * to supervisor mode.  */
	syscall_tab[12] = ((unsigned long) syscall) | 0x2;
	return;
}

/*
 * At entry here, we have a high ipl. We need to establish
 * our isr's, and enable the clock.
 */
void init_IRQ(void)
{
	unsigned long	*dram = 0;
	int	ii;

	/* set up the following layout in low RAM for our 15 vectors:
	 * 0:		NMI (we have no choice about this)
	 * 1-8: 	XINT0-7
	 * 9-12: 	Invalid
	 * 13:		Timer0. Note that Timer1 is disabled.
	 * 14-15:	Invalid.
	 * 
	 * This works out nicely, since the vector number-1 is the 
	 * corresponding bit in IMSK; see disable_irq below.
	 */
	atmod((void*)IMAP0, 0xffff, 0x4321);		/* xint 0-3 */
	atmod((void*)IMAP1, 0xffff, 0x8756);		/* xint 4-7 */
	atmod((void*)IMAP2, 0xff<<16, 0xed << 16);	/* Timer 0, Timer 1 */

	/* we vector all interrupts through intr */
	for (ii=0; ii < 16; ii++) 
		dram[ii] = (unsigned long)intr;
	
#ifdef CONFIG_MON960
	/* reset the XINT5 interrupt handler from software */
	dram[XINT5_VEC_HO] = get_mon960_serial_isr();
#endif
	
	program_clock();
	/* set 13th bit of ICON; enable vector caching */
	atmod((void*)ICON, 1<<13, 1<<13);
	/*
	 * XXX: what to mask is somewhat board dependent; we leave XINT4
	 * masked because Cyclone needs it to always be masked.
	 */
	atmod((void*)IPND, ~0, 0);
	atmod((void*)IMSK, 0x30ef, 0x30ef);
	
	/* Now set up syscalls */
	init_syscalls();
}

#define TRR0	(volatile unsigned long*)0xff000300
#define TCR0	(volatile unsigned long*)0xff000304
#define TMR0	(volatile unsigned long*)0xff000308

#define TRR1	(volatile unsigned long*)0xff000310
#define TCR1	(volatile unsigned long*)0xff000314
#define TMR1	(volatile unsigned long*)0xff000318
/* some helper macros for programming the mode register, TMR0 */

/* the clock may decrement once per cpu cycle, once every two cycles, ...
 * up to eight; set the appropriate bits in TMR0
 */
#define CLOCKSHIFT 4
#define CLOCKDIV(x)	(x << CLOCKSHIFT)
#define CLOCKDIV1 CLOCKDIV(0)
#define CLOCKDIV2 CLOCKDIV(1)
#define CLOCKDIV4 CLOCKDIV(2)
#define CLOCKDIV8 CLOCKDIV(3)

#define CLOCK_ENABLE		2	/* set for clock to work */
#define CLOCK_AUTO_RELOAD	4	/* reload from TRR0 when we reach 0 */
#define CLOCK_SUPER_ONLY	8	/* don't let users reprogram clocks */

/*
 * Set up timer 0 to interrupt us every so many clocks. Assumes
 * interrupts are disabled.
 */
static void
program_clock(void)
{
	/* 33Mhz PCI Bus assumed */
#define CYCLES_PER_HZ	(33 * 1000* 1000) / HZ
	*TRR0 = *TCR0 = CYCLES_PER_HZ;
	*TMR0 = CLOCKDIV1 | CLOCK_ENABLE | CLOCK_AUTO_RELOAD | CLOCK_SUPER_ONLY;
	
#ifdef CONFIG_PROF_IRQ
	disable_irq(TMR1_VEC_HO);
#endif
}

irq_node_t *new_irq_node(void)
{
	/* XXX: write me */
	return NULL;
}

int request_irq(unsigned int irq,
		void (*handler)(int, void *, struct pt_regs *),
                unsigned long flags, const char *devname, void *dev_id)
{
	/* XXX: this is a stopgap; we only can handle one pci device */
	if (pci_dev)
		return -1;

	pci_dev = dev_id;
	pci_name = devname;
	pci_isr = handler;
	return 0;
}

void free_irq(unsigned int irq, void *dev_id)
{
	pci_dev = 0;
}

/*
 * Do we need these probe functions on the i960?
 */
unsigned long probe_irq_on (void)
{
	return 0;
}

int probe_irq_off (unsigned long irqs)
{
	return 0;
}

void disable_irq(unsigned int irq)
{
	if (irq && irq < SYS_IRQS)
		atmod((void*)IMSK, 1<<(irq-1), 0);
}

void enable_irq(unsigned int irq)
{
	if (irq && irq < SYS_IRQS)
		atmod((void*)IMSK, 1<<(irq-1), 1<<(irq-1));
}

#ifdef CONFIG_PROF_IRQ
#define SAMPLE_BITS	7
static inline void
update_prof_timers(int vec, unsigned long ticks)
{
	struct irqstat* irq;
	vec = vec >> 4;
	irq = irqstat + vec;

	if (!irq->avg)  {
		irq->max = ticks;
		irq->min = ticks;
		irq->avg = ticks;
		return;
	}

	if (ticks < irq->min)
		irq->min = ticks;
	if (ticks > irq->max)
		irq->max = ticks;
	irq->avg -= irq->avg >> SAMPLE_BITS;
	irq->avg += ticks >> SAMPLE_BITS;
}
#endif

/*
 * Interrupt service routine. N.B. that XINT0, which is really a system call,
 * is never routed to cintr; it ends up in syscall instead.
 */
extern void do_signal(void);
asmlinkage void cintr(unsigned char vec, struct pt_regs* regs)
{
	extern void timer_interrupt(struct pt_regs* regs);
	static int ticks;
#ifdef CONFIG_PROF_IRQ
	unsigned long clocks;
	*TCR1 = CYCLES_PER_HZ * HZ;
	*TMR1 = CLOCKDIV1 | CLOCK_ENABLE;
#endif
	atomic_inc(&intr_count);
	
	kstat.interrupts[vec >> 4]++;
	switch(vec) {
		case	NMI_VEC:
			nmi_intr();
			break;

		case	XINT1_VEC:
		case	XINT0_VEC:
		case	XINT2_VEC:
		case	XINT3_VEC:
		case	XINT4_VEC:
		case	XINT5_VEC:
		case	XINT6_VEC:
		case	XINT7_VEC:
			xint(vec, regs);
			break;
			
		case	TMR0_VEC:
			if ((++ticks) >= LED_THRESHOLD) {
				static char nm = 0;
				*LED = ~ (1 << (nm++ % 8));
				ticks = 0;
			}
			timer_interrupt(regs);
			break;
			
		default:
			bad_intr(vec, regs);
			break;
	}
	atomic_dec(&intr_count);
	
	if (!intr_count)
		leave_kernel(regs);

#ifdef CONFIG_PROF_IRQ
	clocks = CYCLES_PER_HZ*HZ - *TCR1;
	update_prof_timers(vec, clocks);
#endif
	return;
}

/*
 * Common code to interrupt and syscall paths. When leaving the kernel, and not
 * returning to an interrupt context, do a whole bunch of processing.
 * 
 * Note that if we're called from cintr, we're running at high ipl.
 * 
 * Run the bottom half, check if scheduling is needed, and deliver signals to
 * the current process, just as in every other architecture.
 */
void leave_kernel(struct pt_regs* regs)
{
bh:
	if (bh_mask & bh_active) {
		atomic_inc(&intr_count);
		do_bottom_half();
		atomic_dec(&intr_count);
	}
	sti();
	
	if (user_mode(regs)) {
		if (need_resched) {
			schedule();
			goto bh;
		}


		if (current->signal & ~current->blocked) {
			do_signal();
		}
	}
}

static void nmi_intr(void)
{
	/* XXX: write me */
}

static void bad_intr(unsigned char vec, struct pt_regs* regs)
{
	/* XXX: write me */
	printk("whoah! bad intr: %x\n", vec);
}

static void xint(unsigned char vec, struct pt_regs* regs)
{
	/*
	 * This basically shouldn't happen
	 */
#ifdef CONFIG_MON960_CONSOLE
	if (vec == SERIAL_VEC) {
		extern void do_16552_intr(void);
		do_16552_intr();
		return;
	}
#endif
	
#ifdef CONFIG_PCI
	if (vec == PCI_VEC && pci_dev) {
		pci_isr(0, pci_dev, regs);
		return;
	}
#endif
	printk("EEP: xint %x\n", vec);
	stack_trace();
}

int get_irq_list(char *buf)
{
	int	len = 0;
	int	ii;
	
	for (ii=0; ii < 16; ii++) {
		if (irq_names[ii]) {
#ifdef CONFIG_PROF_IRQ
			len += sprintf(buf+len, "%d\t%s\t(%08x, %08x, %08x)\n",
				       kstat.interrupts[ii],
				       (ii==2 && pci_dev)
				       ? pci_name 
				       : irq_names[ii],
				       irqstat[ii].min, irqstat[ii].avg,
				       irqstat[ii].max);
#else
			len += sprintf(buf+len, "%d\t%s\n",
				       kstat.interrupts[ii], 
				       (ii==2 && pci_dev)
				       ? pci_name 
				       : irq_names[ii]);
#endif
		}
	}
	return len;
}

