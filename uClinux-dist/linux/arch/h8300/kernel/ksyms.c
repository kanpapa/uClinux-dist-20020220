#include <linux/config.h>
#include <linux/module.h>
#include <linux/linkage.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/user.h>
#include <linux/elfcore.h>

#include <asm/setup.h>
#include <asm/pgtable.h>
#include <asm/irq.h>
#include <asm/semaphore.h>

asmlinkage long long __ashrdi3 (long long, int);
extern char h8300_debug_device[];

extern void dump_thread(struct pt_regs *, struct user *);
extern int dump_fpu(elf_fpregset_t *);

static struct symbol_table arch_symbol_table = {
#include <linux/symtab_begin.h>
	/* platform dependent support */

	X(memcmp),
	X(request_irq),
	X(free_irq),
	X(dump_fpu),
	X(dump_thread),
	X(strnlen),
	X(strstr),

	/* The following are special because they're not called
	   explicitly (the C compiler generates them).  Fortunately,
	   their interface isn't gonna change any time soon now, so
	   it's OK to leave it out of version control.  */
	XNOVERS(__ashrdi3),
	XNOVERS(memcpy),
	XNOVERS(memset),

	XNOVERS(__down_failed),
	XNOVERS(__up_wakeup),

#include <linux/symtab_end.h>
};

void arch_syms_export(void)
{
	register_symtab(&arch_symbol_table);

	/*our_syms_export()*/
}
