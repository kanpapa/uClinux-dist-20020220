#
# i960/Makefile
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
# Copyright (C) 1999	Keith Adams <kma@cse.ogi.edu>,
#			Erik Walthinsen <omega@cse.ogi.edu>,
#			Oregon Graduate Institute
#
# based on uClinux for the m68knommu (pilot/shglcore) by:
# Copyright (C) 1998,1999,2000  D. Jeff Dionne <jeff@.lineo.ca>,
#                          	Kenneth Albanowski <kjahds@kjahds.com>,
#
# Based on arch/m68k/Makefile:
# Copyright (C) 1994 by Hamish Macdonald
#

# test for cross compiling
COMPILE_ARCH = $(shell uname -m)
CROSS_COMPILE=y
XAS	=gas960
XLD	=gld960
XCC	=gcc960
XAR	=gar960
XNM	=gnm960
XSTRIP	=gstrip960

# even though i960 is COFF, don't define __COFF__; gcc960 still uses the 
# _ prefixes, so __COFF__ makes linkage.h do the wrong thing
CFLAGS += -pipe $(DBG_FLAGS) -DNO_MM -DNO_FPU -DNO_FORGET -DUTS_SYSNAME='"uClinux-i960"' -DMAGIC_ROM_PTR -mabi
AFLAGS += -pipe -DNO_MM -DNO_FPU -DUTS_SYSNAME='"uClinux-i960"'

ifeq ($(CONFIG_CYVH),y)
LINKFLAGS = -T arch/$(ARCH)/init_cyjx.ld
endif

ifeq ($(CONFIG_I960VH),y)
GCC960ARCH=-AJF
CFLAGS += $(GCC960ARCH)
AFLAGS += $(GCC960ARCH)
endif

HEAD := arch/$(ARCH)/kernel/head.o

SUBDIRS=arch/$(ARCH)/kernel arch/$(ARCH)/mm arch/$(ARCH)/lib
ARCHIVES=arch/$(ARCH)/kernel/kernel.o arch/$(ARCH)/mm/mm.o
LIBS=arch/$(ARCH)/lib/lib.a $(LIBGCC)

ifeq ($(CONFIG_ROMFS_FS),y)
ARCHIVES+=arch/$(ARCH)/romfs/romfs.o
endif

MAKEBOOT = $(MAKE) -C arch/$(ARCH)/boot

debug:
	$(MAKE) coff DBG_FLAGS="-DDEBUG"

coff: vmlinux
	cof960 -Fcoff -JS vmlinux

bootstrap:
	@$(MAKEBOOT) bootstrap

archclean:
	@$(MAKEBOOT) clean

archdep:
	$(MAKEBOOT) dep
