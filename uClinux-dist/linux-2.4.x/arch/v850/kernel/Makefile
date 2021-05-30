#
# arch/v850/kernel/Makefile
#
#  Copyright (C) 2001,2002  NEC Corporation
#  Copyright (C) 2001,2002  Miles Bader <miles@gnu.org>
#
# Note! Dependencies are done automagically by 'make dep', which also
# removes any old dependencies. DON'T put your own dependencies here
# unless it's something special (ie not a .c file).
#

all: head.o kernel.o

USE_STANDARD_AS_RULE	:= true

O_TARGET := kernel.o
obj-y := intv.o entry.o process.o syscalls.o time.o semaphore.o setup.o \
	 signal.o irq.o mach.o ptrace.o v850_ksyms.o bug.o

# chip-specific code
obj-$(CONFIG_V850E_MA1)		+= ma.o	nb85e_utils.o nb85e_timer_d.o
obj-$(CONFIG_V850E_NB85E)	+= nb85e.o
# platform-specific code
obj-$(CONFIG_SIM)		+= sim.o simcons.o
obj-$(CONFIG_RTE_CB)		+= rte_cb.o
obj-$(CONFIG_RTE_MA1_CB)	+= rte_ma1_cb.o
obj-$(CONFIG_RTE_NB85E_CB)	+= rte_nb85e_cb.o
obj-$(CONFIG_RTE_CB_MULTI)	+= rte_cb_multi.o
obj-$(CONFIG_RTE_MB_A_PCI)	+= rte_mb_a_pci.o
obj-$(CONFIG_GBUS_INT)		+= gbus_int.o
# feature-specific code
obj-$(CONFIG_HIGHRES_TIMER)	+= highres_timer.o
obj-$(CONFIG_PROC_FS)		+= procfs.o

head.o: head.S v850_defs.h
entry.o: entry.S v850_defs.h

v850_defs.h: v850_defs.c v850_defs.head
	rm -f v850_defs.d
	SUNPRO_DEPENDENCIES="v850_defs.d v850_defs.h" \
	$(CC) $(filter-out -MD,$(CFLAGS)) -S v850_defs.c
	cp v850_defs.head v850_defs.h
	grep '^#define' v850_defs.s >> v850_defs.h
	rm v850_defs.s
-include v850_defs.d

include $(TOPDIR)/Rules.make
