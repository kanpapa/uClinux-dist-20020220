/*
 *  linux/arch/h8300/kernel/setup.c
 *
 *  Yoshinori Sato <qzb04471@nifty.ne.jp>
 *
 *  Based on linux/arch/m68knommu/kernel/setup.c
 *
 *  Copyleft  ()) 2000       James D. Schettine {james@telos-systems.com}
 *  Copyright (C) 1999       Greg Ungerer (gerg@moreton.com.au)
 *  Copyright (C) 1998,1999  D. Jeff Dionne <jeff@rt-control.com>
 *  Copyright (C) 1998       Kenneth Albanowski <kjahds@kjahds.com>
 *  Copyright (C) 1995       Hamish Macdonald
 */

/*
 * This file handles the architecture-dependent parts of system setup
 */

#include <linux/config.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/delay.h>
#include <linux/interrupt.h>
#include <linux/fs.h>
#include <linux/fb.h>
#include <linux/console.h>
#include <linux/genhd.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/major.h>

#include <asm/setup.h>
#include <asm/irq.h>

#ifdef CONFIG_BLK_DEV_INITRD
#include <linux/blk.h>
#include <asm/pgtable.h>
#endif

extern void register_console(void (*proc)(const char *));
extern void gdb_output(const char *msg);
extern int console_loglevel;
extern void *_vector,*_erom;

/*  conswitchp               = &fb_con;*/
#ifdef CONFIG_CONSOLE
extern struct consw *conswitchp;
#endif

unsigned long rom_length;
unsigned long memory_start;
unsigned long memory_end;

extern char _command_line[512];
char saved_command_line[512];
char console_device[16];

char console_default[] = "CONSOLE=/dev/ttyS0";

void (*mach_sched_init) (void (*handler)(int, void *, struct pt_regs *)) = NULL;
void (*mach_tick)( void ) = NULL;
/* machine dependent keyboard functions */
int (*mach_keyb_init) (void) = NULL;
int (*mach_kbdrate) (struct kbd_repeat *) = NULL;
void (*mach_kbd_leds) (unsigned int) = NULL;
/* machine dependent irq functions */
void (*mach_init_IRQ) (void) = NULL;
void (*(*mach_default_handler)[]) (int, void *, struct pt_regs *) = NULL;
int (*mach_request_irq) (unsigned int, void (*)(int, void *, struct pt_regs *),
                         unsigned long, const char *, void *);
int (*mach_free_irq) (unsigned int, void *);
void (*mach_enable_irq) (unsigned int) = NULL;
void (*mach_disable_irq) (unsigned int) = NULL;
int (*mach_get_irq_list) (char *) = NULL;
int (*mach_process_int) (int, struct pt_regs *) = NULL;
void (*mach_trap_init) (void);
/* machine dependent timer functions */
unsigned long (*mach_gettimeoffset) (void) = NULL;
void (*mach_gettod) (int*, int*, int*, int*, int*, int*) = NULL;
int (*mach_hwclk) (int, struct hwclk_time*) = NULL;
int (*mach_set_clock_mmss) (unsigned long) = NULL;
void (*mach_mksound)( unsigned int count, unsigned int ticks ) = NULL;
void (*mach_reset)( void ) = NULL;
/* void (*waitbut)(void) = dummy_waitbut; */
void (*mach_debug_init)(void) = NULL;

void setup_arch(char **cmdline_p,
		unsigned long * memory_start_p, unsigned long * memory_end_p)
{
	extern int _stext, _etext;
	extern int _sdata, _edata;
	extern int _sbss, _ebss, _end;
	extern int _ramstart, _ramend;

	memory_start = &_end;
	memory_end = &_ramend - 4096; /* <- stack area */

	printk("\x0F\r\n\nuClinux for H8/300H\n");
	printk("Flat model support (C) 1998,1999 Kenneth Albanowski, D. Jeff Dionne\n");

/*
#ifdef DEBUG
	printk("KERNEL -> TEXT=0x%06x-0x%06x DATA=0x%06x-0x%06x "
		"BSS=0x%06x-0x%06x\n", (int) &_stext, (int) &_etext,
		(int) &_sdata, (int) &_edata,
		(int) &_sbss, (int) &_ebss);
	printk("KERNEL -> ROMFS=0x%06x-0x%06x MEM=0x%06x-0x%06x "
		"STACK=0x%06x-0x%06x\n",
	       (int) &_ebss, (int) memory_start,
		(int) memory_start, (int) memory_end,
		(int) memory_end, (int) &_ramend);
#endif
*/
	init_task.mm->start_code = (unsigned long) &_stext;
	init_task.mm->end_code = (unsigned long) &_etext;
	init_task.mm->end_data = (unsigned long) &_edata;
	init_task.mm->brk = (unsigned long) &_end;

	ROOT_DEV = MKDEV(BLKMEM_MAJOR,0);

	/* Keep a copy of command line */
	*cmdline_p = _command_line;

#ifdef DEBUG
	if (strlen(*cmdline_p)) 
		printk("Command line: '%s'\n", *cmdline_p);
	else
		printk("No Command line passed\n");
#endif
	*memory_start_p = memory_start;
	*memory_end_p = memory_end;
	rom_length = (unsigned long)&_erom - (unsigned long)&_vector;
	
#ifdef CONFIG_CONSOLE
	conswitchp = 0;
#endif
	/* register_console(gdb_output); */
  
#ifdef DEBUG
	printk("Done setup_arch\n");
#endif

}

int get_cpuinfo(char * buffer)
{
    char *cpu, *mmu, *fpu;

    cpu = "H8/300H";
    mmu = "none";
    fpu = "none";

    return(sprintf(buffer, "CPU:\t\t%s\n"
		   "MMU:\t\t%s\n"
		   "FPU:\t\t%s\n"
		   "BogoMips:\t%lu.%02lu\n"
		   "Calibration:\t%lu loops\n",
		   cpu, mmu, fpu,
		   loops_per_sec/500000,(loops_per_sec/5000)%100,
		   loops_per_sec));

}

void arch_gettod(int *year, int *mon, int *day, int *hour,
		 int *min, int *sec)
{
	if (mach_gettod)
		mach_gettod(year, mon, day, hour, min, sec);
	else
		*year = *mon = *day = *hour = *min = *sec = 0;
}

