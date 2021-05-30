/*
 * linux/arch/m68knommu/kernel/ints.c -- General interrupt handling code
 *
 * Copyright (C) 2000  Lineo, Inc.  (www.lineo.com) 
 * Copyright (C) 1998  D. Jeff Dionne <jeff@lineo.ca>,
 *                     Kenneth Albanowski <kjahds@kjahds.com>,
 *
 * Based on:
 *
 * linux/arch/m68k/kernel/ints.c -- Linux/m68k general interrupt handling code
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file COPYING in the main directory of this archive
 * for more details.
 *
 * 07/03/96: Timer initialization, and thus mach_sched_init(),
 *           removed from request_irq() and moved to init_time().
 *           We should therefore consider renaming our add_isr() and
 *           remove_isr() to request_irq() and free_irq()
 *           respectively, so they are compliant with the other
 *           architectures.                                     /Jes
 * 11/07/96: Changed all add_/remove_isr() to request_/free_irq() calls.
 *           Removed irq list support, if any machine needs an irq server
 *           it must implement this itself (as it's already done), instead
 *           only default handler are used with mach_default_handler.
 *           request_irq got some flags different from other architectures:
 *           - IRQ_FLG_REPLACE : Replace an existing handler (the default one
 *                               can be replaced without this flag)
 *           - IRQ_FLG_LOCK : handler can't be replaced
 *           There are other machine depending flags, see there
 *           If you want to replace a default handler you should know what
 *           you're doing, since it might handle different other irq sources
 *           which must be served                               /Roman Zippel
 */

#include <linux/types.h>
#include <linux/sched.h>
#include <linux/kernel_stat.h>
#include <linux/errno.h>
#include <linux/config.h>

#include <asm/system.h>
#include <asm/irq.h>
#include <asm/traps.h>
#include <asm/page.h>
#include <asm/machdep.h>

/* table for system interrupt handlers */
static irq_handler_t irq_list[SYS_IRQS];

static const char *default_names[SYS_IRQS] = {
	"spurious int", "int1 handler", "int2 handler", "int3 handler",
	"int4 handler", "int5 handler", "int6 handler", "int7 handler"
};

/* The number of spurious interrupts */
volatile unsigned int num_spurious;

#define NUM_IRQ_NODES 100
static irq_node_t nodes[NUM_IRQ_NODES];

#undef DUMP_TRACE

#ifdef DUMP_TRACE
#define INSNS 1024
static unsigned long pc_trace[INSNS];
static unsigned long usp_trace[INSNS];
static unsigned long ksp_trace[INSNS];
static int pc_trace_idx  = 0;

/*static unsigned long pc2_trace[512];
static unsigned long usp2_trace[512];
static int pc2_trace_idx  = 0;*/
#endif
static signed long last_usp = 0x7fffffff;

static void default_irq_handler(void) {
}

/*
 * void init_IRQ(void)
 *
 * Parameters:	None
 *
 * Returns:	Nothing
 *
 * This function should be called during kernel startup to initialize
 * the IRQ handling routines.
 */

void init_IRQ(void)
{
	int i;
	

	for (i = 0; i < SYS_IRQS; i++) {
		if (mach_default_handler)
			irq_list[i].handler = default_irq_handler; /*(*mach_default_handler)[i];*/
		irq_list[i].flags   = IRQ_FLG_STD;
		irq_list[i].dev_id  = NULL;
		irq_list[i].devname = default_names[i];
	}

	for (i = 0; i < NUM_IRQ_NODES; i++)
		nodes[i].handler = NULL;

	if (mach_init_IRQ)
		mach_init_IRQ ();
}

irq_node_t *new_irq_node(void)
{
	irq_node_t *node;
	short i;

	for (node = nodes, i = NUM_IRQ_NODES-1; i >= 0; node++, i--)
		if (!node->handler)
			return node;

	printk ("new_irq_node: out of nodes\n");
	return NULL;
}

int request_irq(unsigned int irq, void (*handler)(int, void *, struct pt_regs *),
                unsigned long flags, const char *devname, void *dev_id)
{
	if ((irq & IRQ_MACHSPEC) && mach_request_irq)
		return mach_request_irq(IRQ_IDX(irq), handler, flags, devname, dev_id);

	if (irq < IRQ1 || irq > IRQ7) {
		printk("%s: Incorrect IRQ %d from %s\n", __FUNCTION__, irq, devname);
		return -ENXIO;
	}

	if (!(irq_list[irq].flags & IRQ_FLG_STD)) {
		if (irq_list[irq].flags & IRQ_FLG_LOCK) {
			printk("%s: IRQ %d from %s is not replaceable\n",
			       __FUNCTION__, irq, irq_list[irq].devname);
			return -EBUSY;
		}
		if (flags & IRQ_FLG_REPLACE) {
			printk("%s: %s can't replace IRQ %d from %s\n",
			       __FUNCTION__, devname, irq, irq_list[irq].devname);
			return -EBUSY;
		}
	}
	irq_list[irq].handler = handler;
	irq_list[irq].flags   = flags;
	irq_list[irq].dev_id  = dev_id;
	irq_list[irq].devname = devname;
	return 0;
}

void free_irq(unsigned int irq, void *dev_id)
{
	if (irq & IRQ_MACHSPEC) {
		mach_free_irq(IRQ_IDX(irq), dev_id);
		return;
	}

	if (irq < IRQ1 || irq > IRQ7) {
		printk("%s: Incorrect IRQ %d\n", __FUNCTION__, irq);
		return;
	}

	if (irq_list[irq].dev_id != dev_id)
		printk("%s: Removing probably wrong IRQ %d from %s\n",
		       __FUNCTION__, irq, irq_list[irq].devname);

	irq_list[irq].handler = (*mach_default_handler)[irq];
	irq_list[irq].flags   = IRQ_FLG_STD;
	irq_list[irq].dev_id  = NULL;
	irq_list[irq].devname = default_names[irq];
}

/*
 * Do we need these probe functions on the m68k?
 */
unsigned long probe_irq_on (void)
{
	return 0;
}

int probe_irq_off (unsigned long irqs)
{
	return 0;
}

void enable_irq(unsigned int irq)
{
	if ((irq & IRQ_MACHSPEC) && mach_enable_irq)
		mach_enable_irq(IRQ_IDX(irq));
}

void disable_irq(unsigned int irq)
{
	if ((irq & IRQ_MACHSPEC) && mach_disable_irq)
		mach_disable_irq(IRQ_IDX(irq));
}

extern void timer_interrupt(int irq, void *dummy, struct pt_regs * regs);
#if defined(CONFIG_68328_SERIAL) || defined(CONFIG_68332_SERIAL)
extern void rs_interrupt(int irq, void *dev_id, struct pt_regs * regs);
#endif
#ifdef CONFIG_68328_DIGI
extern void digi_interrupt(int irq, void *dev_id, struct pt_regs * regs);
#endif

#ifdef CONFIG_PILOT
/*static int asleep = 0;*/

void pilot_button(int buttons)
{
	extern void hard_reset_now(void);
	
	if (buttons & 1) {
		hard_reset_now();
		
		/*if (asleep) {
			printk("I'm awake!\n");
			asleep = 0;
		} else {
			printk("Going to sleep\n");
			while (!((*(volatile unsigned short*)0xfffff202) & 0x8000))
				;
			*(volatile unsigned short*)0xfffff200 |= 8;
			asm("stop 0x2000");
			printk("Woke up\n");
		}*/
	}
}
#endif

extern void dump_stack(struct frame*);

int inwrap=0;

asmlinkage void process_int_wrap(unsigned long vec, struct pt_regs *fp)
{
	inwrap++;
	process_int(vec, fp);
	inwrap--;
}

asmlinkage void process_int(unsigned long vec, struct pt_regs *fp)
{
	int handled = 0;
	int i;
	
#ifdef CONFIG_M68332
	handled = 1;
	switch (vec) {
	case 3: /* alignment */
	case 4: /* address? */
	case 10: /* A-Line? */
	case 11: /* F-Line? */
		/* address error, Illegal instruction, A-Line or F-Line instruction */
		printk("Fatal exception %lu, trace [PC,USP,KSP]\n", vec);
#ifdef DUMP_TRACE
		for (i=0;i< (sizeof(pc_trace) / 4);i++) 
			printk("%p,%p,%p\n",
				(void*)pc_trace[(pc_trace_idx + i) & ((sizeof(pc_trace) / 4)-1)],
				(void*)usp_trace[(pc_trace_idx + i) & ((sizeof(pc_trace) / 4)-1)],
				(void*)ksp_trace[(pc_trace_idx + i) & ((sizeof(pc_trace) / 4)-1)]
				);
		/*printk("stack jump trace [PC,USP]:\n");
		for (i=0;i< (sizeof(pc2_trace) / 4);i++) 
			printk("%p,%p\n",
 				(void*)pc2_trace[(pc2_trace_idx + i) & ((sizeof(pc2_trace) / 4)-1)],
				(void*)usp2_trace[(pc2_trace_idx + i) & ((sizeof(pc2_trace) / 4)-1)]
				);*/
#endif
		printk("PC: %08lx\nSR: %04x  KSP: %p  USP: %p\n", fp->pc, fp->sr, fp, (void*)rdusp());
		printk("d0: %08lx    d1: %08lx    d2: %08lx    d3: %08lx\n",
			fp->d0, fp->d1, fp->d2, fp->d3);
		printk("d4: %08lx    d5: %08lx    a0: %08lx    a1: %08lx\n",
			fp->d4, fp->d5, fp->a0, fp->a1);
		if (STACK_MAGIC != *(unsigned long *)current->kernel_stack_page) printk("Corrupted stack page\n");
	        printk("Process %s (pid: %d, stackpage=%08lx)\n",
			current->comm, current->pid, current->kernel_stack_page);
		dump_stack((struct frame *)fp);
		HARD_RESET_NOW();
		while(1);
	case 9:
#ifdef DUMP_TRACE
		/* Trace.  Record in the trace buffer */
		pc_trace[pc_trace_idx] = fp->pc;
		usp_trace[pc_trace_idx] = rdusp();
		ksp_trace[pc_trace_idx] = (unsigned long)fp;
		pc_trace_idx = (++pc_trace_idx) & ((sizeof(pc_trace) / 4) - 1);
		
		/*if ((current->pid == 3) && ((last_usp - (signed long)rdusp()) > 64)) {
			pc2_trace[pc2_trace_idx] = fp->pc;
			usp2_trace[pc2_trace_idx] = last_usp = rdusp();
			pc2_trace_idx = (++pc2_trace_idx) & ((sizeof(pc2_trace) / 4) - 1);
		}*/
#endif
		break;
	case 14:
#ifdef DUMP_TRACE
		for (i=0;i< (sizeof(pc_trace) / 4);i++) 
			printk("%p,%p,%p\n",
				(void*)pc_trace[(pc_trace_idx + i) & ((sizeof(pc_trace) / 4)-1)],
				(void*)usp_trace[(pc_trace_idx + i) & ((sizeof(pc_trace) / 4)-1)],
				(void*)ksp_trace[(pc_trace_idx + i) & ((sizeof(pc_trace) / 4)-1)]
				);
		/*printk("stack jump trace [PC,USP]:\n");
		for (i=0;i< (sizeof(pc2_trace) / 4);i++) 
			printk("%p,%p\n",
 				(void*)pc2_trace[(pc2_trace_idx + i) & ((sizeof(pc2_trace) / 4)-1)],
				(void*)usp2_trace[(pc2_trace_idx + i) & ((sizeof(pc2_trace) / 4)-1)]
				);*/
#endif
		printk("PC: %08lx\nSR: %04x  KSP: %p  USP: %p\n", fp->pc, fp->sr, fp, (void*)rdusp());
		printk("d0: %08lx    d1: %08lx    d2: %08lx    d3: %08lx\n",
			fp->d0, fp->d1, fp->d2, fp->d3);
		printk("d4: %08lx    d5: %08lx    a0: %08lx    a1: %08lx\n",
			fp->d4, fp->d5, fp->a0, fp->a1);
		if (STACK_MAGIC != *(unsigned long *)current->kernel_stack_page) printk("Corrupted stack page\n");
	        printk("Process %s (pid: %d, stackpage=%08lx)\n",
			current->comm, current->pid, current->kernel_stack_page);
		dump_stack((struct frame *)fp);
		printk("Fatal execption 14: bad format (wrap=%d)\n", inwrap);
		HARD_RESET_NOW();
		break;
	case 15:
		printk("Spurious interrupt\n");
		break;
	case 0x40:
		timer_interrupt(vec, 0, fp);
		break;
#ifdef CONFIG_68332_SERIAL
	case 0x42:
		rs_interrupt(vec, 0, fp);
		break;
#endif
	default:
		handled = 0;
	}

/*	if (vec == 0x40) {
		timer_interrupt(vec, 0, fp);
		handled = 1;
	} else if (vec == 0x42) {
		rs_interrupt(vec, 0, fp);
		handled = 1;
	}*/
#endif
#ifdef CONFIG_M68328

	unsigned long pending =  (*(volatile unsigned long*)0xFFFFF30C);

	/*printk("Interrupt %d\n", vec);*/
	if (vec == VEC_INT4 || vec == VEC_INT6 || vec == VEC_INT5) {
		/*if (pending & 0x0000ff00) {
			pilot_button((pending >> 8) & 0xff);
			handled = 1;
		}*/
		if (pending & 0x00400002) { /* stupid, something broken */
			/*printk("Timer interrupt (jiffies %d)\n", jiffies);*/
			timer_interrupt(vec, 0, fp);
			handled = 1;
		}
#ifdef CONFIG_68328_SERIAL
		if (pending & 4) {
			/*printk("Serial interrupt\n");*/
			rs_interrupt(vec, 0, fp);
			handled = 1;
		}
#endif
#ifdef CONFIG_UCCS8900
		if (pending & 0x00100000) {
			cs8900_interrupt(vec, 0, fp);
			handled = 1;
		}
#endif
#ifdef CONFIG_68328_DIGI
	} else if (vec == VEC_INT5) {
		if (pending & (1<<20)) {
			printk("Digitizer interrupt\n");
			digi_interrupt(vec, 0, fp);
			handled = 1;
		}
#endif
	}
#endif
#if 0
	if (!handled) {
#ifdef CONFIG_M68328
		printk("Unhandled interrupt %lu (wrap %d)\nPending interrupts: %8X\n",
		        vec, inwrap, pending);
#else
		printk("Unhandled interrupt %lu (wrap %d)\n", vec, inwrap);
#endif
	}
#endif
	vec -= VEC_SPUR;
	/*kstat.interrupts[vec]++;*/
	
#if 0
#if 1
/*MC68000_NO_FRAME_VEC*/
	if (vec < VEC_INT1 || vec > VEC_INT7) {
		if (mach_process_int)
			mach_process_int(vec, fp);
		else
			panic("Can't process interrupt vector %ld\n", vec);
		return;
	}

	vec -= VEC_SPUR;
	kstat.interrupts[vec]++;
	irq_list[vec].handler(vec, irq_list[vec].dev_id, fp);
#else
	/* All we can do is the Jiffie clock, we can't get a vector on 68000 */
	/*jiffies++;*/
	do_timer(fp);

	(*((volatile unsigned long*)0xFFFFF304)) &= ~2;

	/*printk(".");*/
#endif
#endif
}

asmlinkage void process_int4(unsigned long vec, struct pt_regs *fp)
{
#ifdef MC68000_NO_FRAME_VEC
	if (vec < VEC_INT1 || vec > VEC_INT7) {
		if (mach_process_int)
			mach_process_int(vec, fp);
		else
			panic("Can't process interrupt vector %ld\n", vec);
		return;
	}

	vec -= VEC_SPUR;
	kstat.interrupts[vec]++;
	irq_list[vec].handler(vec, irq_list[vec].dev_id, fp);
#else
#ifdef CONFIG_68328_SERIAL
	rs_interrupt(0,0,fp);
#endif
#endif
}

int get_irq_list(char *buf)
{
	int i, len = 0;

	/* autovector interrupts */
	if (mach_default_handler) {
		for (i = 0; i < SYS_IRQS; i++) {
			len += sprintf(buf+len, "auto %2d: %10u ", i,
			               i ? kstat.interrupts[i] : num_spurious);
			if (irq_list[i].flags & IRQ_FLG_LOCK)
				len += sprintf(buf+len, "L ");
			else
				len += sprintf(buf+len, "  ");
			len += sprintf(buf+len, "%s\n", irq_list[i].devname);
		}
	}

	if (mach_get_irq_list)
		len += mach_get_irq_list(buf+len);
	return len;
}
