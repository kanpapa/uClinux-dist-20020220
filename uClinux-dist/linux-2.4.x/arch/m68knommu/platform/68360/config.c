/*
 *  linux/arch/$(ARCH)/platform/$(PLATFORM)/config.c
 *
 *  Copyright (c) 2000 Michael Leslie <mleslie@lineo.com>
 *  Copyright (C) 1993 Hamish Macdonald
 *  Copyright (C) 1999 D. Jeff Dionne <jeff@uclinux.org>
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file COPYING in the main directory of this archive
 * for more details.
 */

#include <stdarg.h>
#include <linux/config.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/tty.h>
#include <linux/console.h>

#include <asm/setup.h>
#include <asm/system.h>
#include <asm/pgtable.h>
#include <asm/irq.h>
#include <asm/machdep.h>

#ifdef CONFIG_UCQUICC
#include "uCquicc/bootstd.h"
#endif

#ifdef CONFIG_PILOT
#include "PalmV/romfs.h"
#endif

#include <asm/m68360.h>
void M68360_init_IRQ(void);

extern QUICC *pquicc;

/* TODO  DON"T Hard Code this */
/* calculate properly using the right PLL and prescaller */
// unsigned int system_clock = 33000000l;
extern unsigned long int system_clock; //In kernel setup.c


//extern void register_console(void (*proc)(const char *));

extern void config_M68360_irq(void);


void BSP_sched_init(void (*timer_routine)(int, void *, struct pt_regs *))
{
  unsigned char prescaler;
  unsigned short tgcr_save;
  int return_value;

#if 0
  /* Restart mode, Enable int, 32KHz, Enable timer */
  TCTL = TCTL_OM | TCTL_IRQEN | TCTL_CLKSOURCE_32KHZ | TCTL_TEN;
  /* Set prescaler (Divide 32KHz by 32)*/
  TPRER = 31;
  /* Set compare register  32Khz / 32 / 10 = 100 */
  TCMP = 10;                                                              

  request_irq(IRQ_MACHSPEC | 1, timer_routine, IRQ_FLG_LOCK, "timer", NULL);
#endif

  /* General purpose quicc timers: MC68360UM p7-20 */

  /* Set up timer 1 (in [1..4]) to do 100Hz */
  tgcr_save = pquicc->timer_tgcr & 0xfff0;
  pquicc->timer_tgcr  = tgcr_save; /* stop and reset timer 1 */
  /* pquicc->timer_tgcr |= 0x4444; */ /* halt timers when FREEZE (ie bdm freeze) */

  prescaler = 8;
  pquicc->timer_tmr1 = 0x001a | /* or=1, frr=1, iclk=01b */
                           (unsigned short)((prescaler - 1) << 8);
    
  pquicc->timer_tcn1 = 0x0000; /* initial count */
  /* calculate interval for 100Hz based on the _system_clock: */
  pquicc->timer_trr1 = (system_clock/ prescaler) / HZ; /* reference count */

  pquicc->timer_ter1 = 0x0003; /* clear timer events */

  /* enable timer 1 interrupt in CIMR */
//  request_irq(IRQ_MACHSPEC | CPMVEC_TIMER1, timer_routine, IRQ_FLG_LOCK, "timer", NULL);
  //return_value = request_irq( CPMVEC_TIMER1, timer_routine, IRQ_FLG_LOCK, "timer", NULL);
  return_value = request_irq(CPMVEC_TIMER1 , timer_routine, IRQ_FLG_LOCK,
          "Timer", NULL);

  /* Start timer 1: */
  tgcr_save = (pquicc->timer_tgcr & 0xfff0) | 0x0001;
  pquicc->timer_tgcr  = tgcr_save;
}


void BSP_tick(void)
{
  /* Reset Timer1 */
  /* TSTAT &= 0; */

  pquicc->timer_ter1 = 0x0002; /* clear timer event */  
}

unsigned long BSP_gettimeoffset (void)
{
  return 0;
}

void BSP_gettod (int *yearp, int *monp, int *dayp,
		   int *hourp, int *minp, int *secp)
{
}

int BSP_hwclk(int op, struct hwclk_time *t)
{
  if (!op) {
    /* read */
  } else {
    /* write */
  }
  return 0;
}

int BSP_set_clock_mmss (unsigned long nowtime)
{
#if 0
  short real_seconds = nowtime % 60, real_minutes = (nowtime / 60) % 60;

  tod->second1 = real_seconds / 10;
  tod->second2 = real_seconds % 10;
  tod->minute1 = real_minutes / 10;
  tod->minute2 = real_minutes % 10;
#endif
  return 0;
}

void BSP_reset (void)
{
  cli();
/*   asm volatile (" */
/*     moveal #0x10c00000, %a0; */
/*     moveb #0, 0xFFFFF300; */
/*     moveal 0(%a0), %sp; */
/*     moveal 4(%a0), %a0; */
/*     jmp (%a0); */
/*     "); */

  asm volatile ("
    moveal #_start, %a0;
    moveb #0, 0xFFFFF300;
    moveal 0(%a0), %sp;
    moveal 4(%a0), %a0;
    jmp (%a0);
    ");


}

unsigned char *scc1_hwaddr;
static int errno;

#if defined (CONFIG_UCQUICC)
_bsc0(char *, getserialnum)
_bsc1(unsigned char *, gethwaddr, int, a)
_bsc1(char *, getbenv, char *, a)
#endif


void config_BSP(char *command, int len)
{
  unsigned char *p;
/* #if defined (CONFIG_M68360_SMC_UART) */
/*   extern void console_print_68360(const char * b); */
/*   register_console(console_print_68360); */
/* #endif   */

  printk("\n68360 QUICC support (C) 2000 Lineo Inc.\n");

#if defined(CONFIG_UCQUICC) && 0
  printk("uCquicc serial string [%s]\n",getserialnum());
  p = scc1_hwaddr = gethwaddr(0);
  printk("uCquicc hwaddr %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
         p[0], p[1], p[2], p[3], p[4], p[5]);

  p = getbenv("APPEND");
  if (p)
    strcpy(p,command);
  else
    command[0] = 0;
#else
  scc1_hwaddr = "\00\01\02\03\04\05";
#endif
 
  mach_sched_init      = BSP_sched_init;
  mach_tick            = BSP_tick;
  mach_gettimeoffset   = BSP_gettimeoffset;
  mach_gettod          = BSP_gettod;
  mach_hwclk           = NULL;
  mach_set_clock_mmss  = NULL;
//  mach_mksound         = NULL;
  mach_reset           = BSP_reset;
  //Kendrick's Change
  mach_trap_init        = M68360_init_IRQ;
 // mach_debug_init      = NULL;

  config_M68360_irq();
}
