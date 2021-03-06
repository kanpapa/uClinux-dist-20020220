#
# 68360/Makefile
#
# This file is included by the global makefile so that you can add your own
# platform-specific flags and dependencies.
#
# This file is subject to the terms and conditions of the GNU General Public
# License.  See the file "COPYING" in the main directory of this archive
# for more details.
#
# Copyright (C) 2000       Michael Leslie <mleslie@lineo.com>,
# Copyright (C) 1998,1999  D. Jeff Dionne <jeff@uclinux.org>,
# Copyright (C) 1998       Kenneth Albanowski <kjahds@kjahds.com>
# Copyright (C) 1994 by Hamish Macdonald
#

GCC_DIR = $(shell $(CC) -v 2>&1 | grep specs | sed -e 's/.* \(.*\)specs/\1\./')

INCGCC = $(GCC_DIR)/include
LIBGCC = $(GCC_DIR)/m68000/libgcc.a

CFLAGS := -fno-builtin -DNO_CACHE $(CFLAGS) -pipe -DNO_MM -DNO_FPU -DNO_CACHE -m68332 -D__ELF__ -DMAGIC_ROM_PTR -DNO_FORGET -DUTS_SYSNAME='"uClinux"' -D__linux__
AFLAGS := $(AFLAGS) -pipe -DNO_MM -DNO_FPU -DNO_CACHE -m68332 -D__ELF__ -DMAGIC_ROM_PTR -DUTS_SYSNAME='"uClinux"' -Wa,--bitwise-or

LINKFLAGS = -T arch/$(ARCH)/platform/$(PLATFORM)/$(BOARD)/$(MODEL).ld



HEAD := arch/$(ARCH)/platform/$(PLATFORM)/$(BOARD)/crt0_$(MODEL).o

SUBDIRS := arch/$(ARCH)/kernel arch/$(ARCH)/mm arch/$(ARCH)/lib \
           arch/$(ARCH)/platform/$(PLATFORM) $(SUBDIRS)

CORE_FILES := arch/$(ARCH)/kernel/kernel.o arch/$(ARCH)/mm/mm.o \
              arch/$(ARCH)/platform/$(PLATFORM)/platform.o $(CORE_FILES)

LIBS += arch/$(ARCH)/lib/lib.a $(LIBGCC)

ifdef CONFIG_FRAMEBUFFER
SUBDIRS := $(SUBDIRS) arch/$(ARCH)/console
ARCHIVES := $(ARCHIVES) arch/$(ARCH)/console/console.a
endif

MAKEBOOT = $(MAKE) -C arch/$(ARCH)/boot

image.s19: romfs.img linux
	$(CROSS_COMPILE)objcopy --adjust-section-vma=.data=0x`$(CROSS_COMPILE)nm linux | awk '/__data_rom_start/ {printf $$1}'` linux image.s19
	ADDR=`$(CROSS_COMPILE)objdump --headers image.s19 | \
	grep .data | cut -d' ' -f 13,15 | xargs printf "0x%s 0x%s\n" | \
	xargs printf "%d + %d\n" |xargs expr |xargs printf "0x%x\n"`;\
	$(CROSS_COMPILE)objcopy --add-section=.romfs=romfs.img \
	--adjust-section-vma=.romfs=$${ADDR} --no-adjust-warnings \
	--set-section-flags=.romfs=alloc,load,data   \
	image.s19 image.s19 2> /dev/null
	$(CROSS_COMPILE)objcopy -O srec image.s19 image.s19

linux.data: linux
	$(CROSS_COMPILE)objcopy -O binary --remove-section=.romvec --remove-section=.text --remove-section=.ramvec --remove-section=.bss --remove-section=.eram linux linux.data

linux.text: linux
	$(CROSS_COMPILE)objcopy -O binary --remove-section=.ramvec --remove-section=.bss --remove-section=.data --remove-section=.eram --set-section-flags=.romvec=CONTENTS,ALLOC,LOAD,READONLY,CODE linux linux.text

linux.bin: linux.text linux.data romfs.img
	if [ -f romfs.img ]; then\
		cat linux.text linux.data romfs.img > linux.bin;\
	else\
		cat linux.text linux.data > linux.bin;\
	fi

flash.s19: linux.bin arch/$(ARCH)/empty.o
	$(CROSS_COMPILE)objcopy -v -R .text -R .data -R .bss --add-section=.fs=linux.bin --adjust-section-vma=.fs=$(FLASH_LOAD_ADDR) arch/$(ARCH)/empty.o flash.s19
	$(CROSS_COMPILE)objcopy -O srec flash.s19

flash.b: flash.s19
	$(STOB) flash.s19 > flash.b

linux.trg linux.rom: linux.bin
	perl arch/$(ARCH)/platform/$(PLATFORM)/tools/fixup.pl

linux.s19: linux
	$(CROSS_COMPILE)objcopy -O srec --adjust-section-vma=.data=0x`$(CROSS_COMPILE)nm linux | awk '/__data_rom_start/ {printf $$1}'` linux linux.s19
	
linux.b: linux.s19
	if [ -f $(INIT_B) ]; then\
		cp $(INIT_B) linux.b;\
	fi
	$(STOB) linux.s19 >> linux.b

archclean:
	@$(MAKEBOOT) clean
	rm -f linux.text linux.data linux.bin linux.rom linux.trg
	rm -f linux.s19 romfs.s19 flash.s19
	rm -f linux.img romdisk.img
	rm -f linux.b romfs.b flash.b
	rm -f romfs.o
