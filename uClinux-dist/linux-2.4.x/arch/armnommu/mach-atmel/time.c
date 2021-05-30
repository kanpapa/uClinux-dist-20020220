/*
 * time.c  Timer functions for Atmel AT91
 */

#include <linux/time.h>
#include <linux/timex.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <asm/io.h>
#include <asm/arch/hardware.h>

unsigned long atmel_gettimeoffset (void)
{
	struct at91_timers* tt = (struct trio_timers*) (AT91_TC_BASE);
	struct at91_timer_channel* tc = &tt->chans[KERNEL_TIMER].ch;
	return tc->cv * (1000*1000)/(ARM_CLK/128);
}

void atmel_timer_interrupt(int irq, void *dev_id, struct pt_regs *regs)
{
	struct at91_timers* tt = (struct trio_timers*) (AT91_TC_BASE);
	volatile struct  at91_timer_channel* tc = &tt->chans[KERNEL_TIMER].ch;
	unsigned long v = tc->sr;
        do_timer(regs);
}
