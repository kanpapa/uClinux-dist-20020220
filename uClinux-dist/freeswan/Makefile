# FreeS/WAN master makefile
# Copyright (C) 1998, 1999, 2000  Henry Spencer.
# 
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
# 
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
# for more details.
#
# RCSID $Id: Makefile,v 1.128 2001/05/30 06:18:44 henry Exp $

# install pathnames; DESTDIR can be used to supply a prefix to them all
# PUBDIR is where the "ipsec" command goes; beware, many things define PATH
# settings which are assumed to include it (or at least, to include *some*
# copy of the "ipsec" command).
PUBDIR=$(DESTDIR)/usr/local/sbin
# PRIVDIR is where commands get put, REALPRIVDIR is where they think they
# will be run from in the end (currently only used by utils/ipsec)
REALPRIVDIR=/usr/local/lib/ipsec
PRIVDIR=$(DESTDIR)$(REALPRIVDIR)
# where manpages go
MANTREE=$(DESTDIR)/usr/local/man
# all relevant manpage subdirectories
MANPLACES=man3 man5 man8
# where configuration files go
CONFDIR=$(DESTDIR)/etc
# RCDIR is where boot/shutdown scripts go (first RCDIRS that exists gets it);
# REALRCDIR is where they think they will ultimately be (for utils/Makefile)
RCDIRS=/etc/rc.d/init.d /etc/rc.d /etc/init.d /sbin/init.d
REALRCDIR=$(shell for d in $(RCDIRS) ; \
		do if test -d $$d ; \
		then echo $$d ; exit 0 ; \
		fi ; done ; echo /etc/rc.d/init.d )
RCDIR=$(DESTDIR)$(REALRCDIR)

# kernel location, and location of kernel patches in the distribution
KERNELSRC=/usr/src/linux
DIRIN22=$(KERNELSRC)/net/netlink
FILIN24=$(KERNELSRC)/net/khttpd/main.c
KERNELREL=$(shell { test -f $(FILIN24) && echo 2.3; } || { test -d $(DIRIN22) && echo 2.2; } )
KCFILE=$(KERNELSRC)/.config
VERFILE=$(KERNELSRC)/include/linux/version.h
PATCHES=klips/patches$(KERNELREL)
# note, some of the patches know the last part of this path
KERNELKLIPS=$(KERNELSRC)/net/ipsec

# kernel make name:  zImage for 2.0.xx, bzImage for 2.2.xx and later, and
# boot elsewhere (what ever happened to standards?)
B=$(shell test -d $(DIRIN22) && echo b)
KERNEL=$(shell if expr " `uname -m`" : ' i.86' >/dev/null ; then echo $(B)zImage ; else echo boot ; fi)

# pass pathnames etc. down
SETTINGS=BINDIR=$(PRIVDIR) PUBDIR=$(PUBDIR) PRIVDIR=$(PRIVDIR) \
	REALPRIVDIR=$(REALPRIVDIR) MANTREE=$(MANTREE) \
	DESTDIR=$(DESTDIR) INSTALL="$(INSTALL)"
FULLSET=$(SETTINGS) CONFDIR=$(CONFDIR) RCDIR=$(RCDIR) REALRCDIR=$(REALRCDIR)

# install stuff
INSTALL=install

SHELL=/bin/sh



def:
	@echo "Please read doc/intro.html or INSTALL before running make"
	@false

# everything that's necessary to put Klips into the kernel
insert:	patches klink klipsdefaults

klink:
	rm -rf $(KERNELKLIPS)
	mkdir -p $(KERNELKLIPS)/libdes/asm
	mkdir -p $(KERNELKLIPS)/libfreeswan
	mkdir -p $(KERNELKLIPS)/zlib
	ln -s `pwd`/klips/net/ipsec/Makefile $(KERNELKLIPS)
	ln -s `pwd`/klips/net/ipsec/Config.in $(KERNELKLIPS)
	ln -s `pwd`/klips/net/ipsec/defconfig $(KERNELKLIPS)
	ln -s `pwd`/klips/net/ipsec/*.[ch] $(KERNELKLIPS)
	ln -s `pwd`/lib/Makefile.kernel $(KERNELKLIPS)/libfreeswan/Makefile
	ln -s `pwd`/lib/*.[ch] $(KERNELKLIPS)/libfreeswan
	ln -s `pwd`/libdes/Makefile $(KERNELKLIPS)/libdes
	ln -s `pwd`/libdes/*.[ch] $(KERNELKLIPS)/libdes
	ln -s `pwd`/libdes/asm/*.pl $(KERNELKLIPS)/libdes/asm
	ln -s `pwd`/libdes/asm/perlasm $(KERNELKLIPS)/libdes/asm
	ln -s `pwd`/zlib/Makefile $(KERNELKLIPS)/zlib
	ln -s `pwd`/zlib/*.[chS] $(KERNELKLIPS)/zlib

PATCHER=utils/patcher
patches:
	echo "===============" >>out.kpatch
	echo "`date` `cd $(KERNELSRC) ; pwd`" >>out.kpatch
	$(MAKE) _patches$(KERNELREL) $(SETTINGS) >>out.kpatch

# Linux-2.0.x version
_patches:
	@$(PATCHER) -v $(KERNELSRC) Documentation/Configure.help \
		'CONFIG_IPSEC' $(PATCHES)/Documentation.Configure.help
	@$(PATCHER) -v $(KERNELSRC) include/linux/in.h \
		'IPPROTO_ESP' $(PATCHES)/include.linux.in.h
	@$(PATCHER) -v $(KERNELSRC) net/Config.in \
		'CONFIG_IPSEC' $(PATCHES)/net.Config.in
	@$(PATCHER) -v $(KERNELSRC) net/Makefile \
		'CONFIG_IPSEC' $(PATCHES)/net.Makefile
	@$(PATCHER) -v $(KERNELSRC) net/ipv4/af_inet.c \
		'CONFIG_IPSEC' $(PATCHES)/net.ipv4.af_inet.c
	@$(PATCHER) -v $(KERNELSRC) net/netsyms.c \
		'ip_fragment' $(PATCHES)/net.netsyms.c
	@$(PATCHER) -v $(KERNELSRC) include/linux/socket.h \
		'PF_KEY' $(PATCHES)/include.linux.socket.h
# Removed patches, will unpatch automatically.
	@$(PATCHER) -v $(KERNELSRC) include/linux/proc_fs.h
	@$(PATCHER) -v $(KERNELSRC) net/core/dev.c
	@$(PATCHER) -v $(KERNELSRC) net/ipv4/protocol.c
	@$(PATCHER) -v $(KERNELSRC) drivers/net/Space.c
	@$(PATCHER) -v $(KERNELSRC) net/netlink.c
	@$(PATCHER) -v $(KERNELSRC) drivers/isdn/isdn_net.c

# Linux-2.2.x version
PATCHES24=klips/patches2.3
_patches2.2:
	@$(PATCHER) -v $(KERNELSRC) Documentation/Configure.help \
		'CONFIG_IPSEC' $(PATCHES)/Documentation.Configure.help
	@$(PATCHER) -v $(KERNELSRC) include/linux/in.h \
		'IPPROTO_ESP' $(PATCHES)/include.linux.in.h
	@$(PATCHER) -v $(KERNELSRC) net/Config.in \
		'CONFIG_IPSEC' $(PATCHES24)/net.Config.in
	@$(PATCHER) -v $(KERNELSRC) net/Makefile \
		'CONFIG_IPSEC' $(PATCHES)/net.Makefile
	@$(PATCHER) -v $(KERNELSRC) net/ipv4/af_inet.c \
		'CONFIG_IPSEC' $(PATCHES)/net.ipv4.af_inet.c
	@$(PATCHER) -v $(KERNELSRC) net/netsyms.c \
		'neigh_compat_output' $(PATCHES)/net.netsyms.c.1 \
		'inet_addr_type' $(PATCHES)/net.netsyms.c.2
#	@$(PATCHER) -v $(KERNELSRC) include/linux/socket.h \
#		'define.AF_KEY' $(PATCHES)/include.linux.socket.h
# Removed patches, will unpatch automatically.
	@$(PATCHER) -v $(KERNELSRC) include/linux/proc_fs.h
	@$(PATCHER) -v $(KERNELSRC) net/core/dev.c
	@$(PATCHER) -v $(KERNELSRC) net/ipv4/protocol.c
	@$(PATCHER) -v $(KERNELSRC) drivers/net/Space.c
	@$(PATCHER) -v $(KERNELSRC) include/linux/netlink.h
	@$(PATCHER) -v $(KERNELSRC) net/netlink/af_netlink.c
	@$(PATCHER) -v $(KERNELSRC) net/netlink/netlink_dev.c
	@$(PATCHER) -v $(KERNELSRC) include/linux/socket.h
	@$(PATCHER) -v $(KERNELSRC) drivers/isdn/isdn_net.c

# Linux-2.4.0 version
PATCHES22=klips/patches2.2
_patches2.3:
	@$(PATCHER) -v $(KERNELSRC) Documentation/Configure.help \
		'CONFIG_IPSEC' $(PATCHES22)/Documentation.Configure.help
	@$(PATCHER) -v $(KERNELSRC) net/Config.in \
		'CONFIG_IPSEC' $(PATCHES)/net.Config.in
	@$(PATCHER) -v $(KERNELSRC) net/Makefile \
		'CONFIG_IPSEC' $(PATCHES)/net.Makefile
	@$(PATCHER) -v $(KERNELSRC) net/ipv4/af_inet.c \
		'CONFIG_IPSEC' $(PATCHES)/net.ipv4.af_inet.c
# Removed patches, will unpatch automatically.
	@$(PATCHER) -v $(KERNELSRC) include/linux/proc_fs.h
	@$(PATCHER) -v $(KERNELSRC) net/core/dev.c
	@$(PATCHER) -v $(KERNELSRC) net/ipv4/protocol.c
	@$(PATCHER) -v $(KERNELSRC) drivers/net/Space.c
	@$(PATCHER) -v $(KERNELSRC) include/linux/netlink.h
	@$(PATCHER) -v $(KERNELSRC) net/netlink/af_netlink.c
	@$(PATCHER) -v $(KERNELSRC) net/netlink/netlink_dev.c
	@$(PATCHER) -v $(KERNELSRC) drivers/isdn/isdn_net.c

ifeq ($(ARCH),)
ARCH := $(shell uname -m | sed -e s/i.86/i386/ -e s/sun4u/sparc64/ -e s/arm.*/arm/ -e s/sa110/arm/)
endif

klipsdefaults:
	@KERNELDEFCONFIG=$(KERNELSRC)/arch/$(ARCH)/defconfig ; \
	KERNELCONFIG=$(KCFILE) ; \
	if ! egrep -q 'CONFIG_IPSEC' $$KERNELDEFCONFIG ; \
	then \
		set -x ; \
		cp -a $$KERNELDEFCONFIG $$KERNELDEFCONFIG.orig ; \
		chmod u+w $$KERNELDEFCONFIG ; \
		cat $$KERNELDEFCONFIG $(KERNELKLIPS)/defconfig \
			>$$KERNELDEFCONFIG.tmp ; \
		rm -f $$KERNELDEFCONFIG ; \
		cp -a $$KERNELDEFCONFIG.tmp $$KERNELDEFCONFIG ; \
		rm -f $$KERNELDEFCONFIG.tmp ; \
	fi ; \
	if ! egrep -q 'CONFIG_IPSEC' $$KERNELCONFIG ; \
	then \
		set -x ; \
		cp -a $$KERNELCONFIG $$KERNELCONFIG.orig ; \
		chmod u+w $$KERNELCONFIG ; \
		cat $$KERNELCONFIG $(KERNELKLIPS)/defconfig \
			>$$KERNELCONFIG.tmp ; \
		rm -f $$KERNELCONFIG ; \
		cp -a $$KERNELCONFIG.tmp $$KERNELCONFIG ; \
		rm -f $$KERNELCONFIG.tmp ; \
	fi



# programs

programs:
	cd lib ; $(MAKE) $(SETTINGS)
	cd pluto ; $(MAKE) $(SETTINGS)
	cd klips/utils ; $(MAKE) $(SETTINGS)
	cd utils ; $(MAKE) $(SETTINGS)

install:
	mkdir -p $(PRIVDIR) $(PUBDIR)
	for m in $(MANPLACES) ; do mkdir -p $(MANTREE)/$$m ; done
	cd lib ; $(MAKE) install $(SETTINGS)
	cd klips/utils ; $(MAKE) install $(SETTINGS)
	cd pluto ; $(MAKE) install $(SETTINGS)
	cd utils ; $(MAKE) install $(FULLSET)

clean:
	cd lib ; $(MAKE) clean $(SETTINGS)	# looks after libdes too
	cd klips/utils ; $(MAKE) clean $(SETTINGS)
	cd pluto ; $(MAKE) clean $(SETTINGS)
	cd utils ; $(MAKE) clean $(SETTINGS)
	rm -f out.kbuild out.kinstall

# out.kpatch contents are usually worth retaining
spotless:	clean
	rm -f out.kpatch



# proxies for major kernel make operations

# do-everything entries
ogo:	precheck insert pcf confcheck programs install kernel
oldgo:	precheck insert ocf confcheck programs install kernel
menugo:	precheck insert mcf confcheck programs install kernel
xgo:	precheck insert xcf confcheck programs install kernel
omod:	precheck insert pcf confcheck programs install module
oldmod:	precheck insert ocf confcheck programs install module
menumod:	precheck insert mcf confcheck programs install module
xmod:	precheck insert xcf confcheck programs install module

# preliminaries
precheck:
	@if test ! -f $(KCFILE) ; \
	then \
		echo '*** kernel has never been configured!!' ; \
		echo '*** please do that first; the results are necessary.' ; \
		exit 1 ; \
	fi
	@if test ! -f $(VERFILE) ; \
	then \
		echo '*** kernel has never been compiled!!' ; \
		echo '*** please do that first; the results are necessary.' ; \
		exit 1 ; \
	fi

# configuring (exit statuses disregarded, something fishy here sometimes)
xcf:
	-cd $(KERNELSRC) ; $(MAKE) xconfig
mcf:
	-cd $(KERNELSRC) ; $(MAKE) menuconfig
pcf:
	-cd $(KERNELSRC) ; $(MAKE) config
ocf:
	-cd $(KERNELSRC) ; $(MAKE) oldconfig
confcheck:
	@if test ! -f $(KCFILE) ; \
	then echo '*** no kernel configuration file written!!' ; exit 1 ; \
	fi
	@if ! egrep -q '^CONFIG_IPSEC=[my]' $(KCFILE) ; \
	then echo '*** IPSEC not in kernel configuration!!' ; exit 1 ; \
	fi
	@if egrep -q '^CONFIG_IPSEC=m' $(KCFILE) && \
		! egrep -q '^CONFIG_MODULES=y' $(KCFILE) ; \
	then echo '*** IPSEC configured as module in kernel with no module support!!' ; exit 1 ; \
	fi

# kernel building, with error checks
kernel:
	rm -f out.kbuild out.kinstall
	( cd $(KERNELSRC) ; $(MAKE) dep clean $(KERNEL) ) 2>&1 | tee out.kbuild
	@if egrep -q '^CONFIG_MODULES=y' $(KCFILE) ; \
	then set -x ; \
		( cd $(KERNELSRC) ; \
		$(MAKE) modules 2>&1 ) | tee -a out.kbuild ; \
	fi
	utils/errcheck out.kbuild

# module-only building, with error checks
module:
	rm -f out.kbuild out.kinstall
	egrep -q '^CONFIG_MODULES=y' $(KCFILE)
	egrep -q '^CONFIG_IPSEC=m' $(KCFILE)
	( cd $(KERNELSRC) ; \
		$(MAKE) modules 2>&1 ) | tee out.kbuild
	utils/errcheck out.kbuild

# kernel install, with error checks
kinstall:
	rm -f out.kinstall
	( cd $(KERNELSRC) ; $(MAKE) install ) 2>&1 | tee out.kinstall
	@if egrep -q '^CONFIG_MODULES=y' $(KCFILE) ; \
	then set -x ; \
		( cd $(KERNELSRC) ; \
		$(MAKE) modules_install 2>&1 ) | tee -a out.kinstall ; \
	fi
	utils/errcheck out.kinstall

# module-only install, with error checks
minstall:
	rm -f out.kinstall
	egrep -q '^CONFIG_MODULES=y' $(KCFILE)
	egrep -q '^CONFIG_IPSEC=m' $(KCFILE)
	( cd $(KERNELSRC) ; \
		$(MAKE) modules_install 2>&1 ) | tee out.kinstall
	utils/errcheck out.kinstall



# backup of (almost) everything an install touches
TARNAME=$(shell date | awk '{print "backup-" $$6 "-" $$2 "-" $$3 ".tar.gz"}')
THEM=$(PUBDIR)/ipsec $(PRIVDIR)/* $(MANTREE)/*/ipsec* \
	$(CONFDIR)/ipsec.conf $(CONFDIR)/ipsec.secrets \
	$(RCDIR)/ipsec $(KCFILE) \
	$(KERNELSRC)/arch/$(ARCH)/defconfig \
	$(RCDIR)/../rc[0-6].d/[KS]??ipsec
backup:
	tar -cz --ignore-failed-read -f $(TARNAME) $(THEM)
	chmod -w $(TARNAME)

# take all the patches out of the kernel
# (Note, a couple of files are modified by non-patch means; they are
# included in "make backup".)
unpatch:
	for f in `find $(KERNELSRC)/. -name '*.preipsec' -print` ; \
	do \
		echo "restoring $$f:" ; \
		dir=`dirname $$f` ; \
		core=`basename $$f .preipsec` ; \
		cd $$dir ; \
		mv -f $$core.preipsec $$core ; \
		rm -f $$core.wipsec $$core.ipsecmd5 ; \
	done



# some oddities meant for the developers, probably of no use to users

# make tags and TAGS files from ctags and etags for vi and emacs, respectively.
tags TAGS: dummy
	etags `find lib pluto klips/utils klips/net/ipsec -name '*.[ch]'`
	ctags `find lib pluto klips/utils klips/net/ipsec -name '*.[ch]'`

dummy:
