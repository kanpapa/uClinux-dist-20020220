#
# arch/v850/Makefile
#
# This file is included by the global makefile so that you can add your own
# architecture-specific flags and dependencies. Remember to do have actions
# for "archclean" and "archdep" for cleaning up and making dependencies for
# this architecture
#
# This file is subject to the terms and conditions of the GNU General Public
# License.  See the file "COPYING" in the main directory of this archive
# for more details.
#

UTS_SYSNAME = -DUTS_SYSNAME=\"uClinux\"

# r16 is a fixed pointer to the current task
CFLAGS += -pipe -ffixed-r16 -mv850e -mno-prolog-function -fno-builtin -DNO_MM -DNO_FPU -D__ELF__ $(UTS_SYSNAME) -D__linux__


ARCH_DIR = arch/$(ARCH)


# linker scripts
ifdef CONFIG_SIM
LINKFLAGS = -T $(ARCH_DIR)/sim.ld
endif
ifdef CONFIG_RTE_MA1_CB
ifdef CONFIG_ROM_KERNEL
LINKFLAGS = -T $(ARCH_DIR)/rte_ma1_cb-rom.ld
else
ifdef CONFIG_RTE_MA1_CB_KSRAM
LINKFLAGS = -T $(ARCH_DIR)/rte_ma1_cb-ksram.ld
else
LINKFLAGS = -T $(ARCH_DIR)/rte_ma1_cb.ld
endif
endif
endif

HEAD := $(ARCH_DIR)/kernel/head.o

SUBDIRS += $(ARCH_DIR)/kernel $(ARCH_DIR)/lib
CORE_FILES := $(ARCH_DIR)/kernel/kernel.o $(CORE_FILES)
LIBS += $(ARCH_DIR)/lib/lib.a


# Deal with the initial contents of the blkmem device
ifdef BLKMEM0_IMAGE
ifndef CONFIG_SIM
# Embed it in the kernel

BLKMEM0_IMAGE_OBJ = blkmem0.o

CORE_FILES += $(BLKMEM0_IMAGE_OBJ)

$(LINUX) : $(BLKMEM0_IMAGE_OBJ)

# Note that we use the build-system's objcopy, as the v850 tools are fairly
# old, and don't have the --rename-section option.
$(BLKMEM0_IMAGE_OBJ): $(BLKMEM0_IMAGE)
	objcopy -I binary -O elf32-little -B i386 --rename-section .data=.blkmem0,alloc,load,readonly,data,contents $< $@

endif # !CONFIG_SIM
endif # BLKMEM0_IMAGE


#
# If you want the kernel build to build modules outside of the tree
# then define this and pass it to the main linux makefile
#
ifdef EXTRA_MODULE_DIRS
SUBDIRS += $(EXTRA_MODULE_DIRS)
endif

bootstrap:
	@$(MAKEBOOT) bootstrap

archmrproper:

archdep:

archclean:
	rm -f $(LINUX)
	rm -f $(ARCH_DIR)/kernel/v850_defs.h $(ARCH_DIR)/kernel/v850_defs.d

include $(TOPDIR)/Rules.make
