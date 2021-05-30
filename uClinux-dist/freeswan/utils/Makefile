# utilities build and install
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
# RCSID $Id: Makefile,v 1.85 2001/06/14 13:20:14 henry Exp $

# pathnames, subject to overrides from main Makefile
PUBDIR=/usr/local/sbin
PRIVDIR=/usr/local/lib/ipsec
REALPRIVDIR=/usr/local/lib/ipsec
RCDIR=/etc/rc.d/init.d
REALRCDIR=/etc/rc.d/init.d
CONFDIR=/etc
MANTREE=/usr/local/man

FMANDIR=$(MANTREE)/man5
CMANDIR=$(MANTREE)/man8
PUBS=ipsec
BINS=ranbits rsasigkey
SCRIPTS=barf manual auto look showdefaults showhostkey
INTERNALS=_include _confread _keycensor _secretcensor _updown \
	_realsetup _startklips _plutorun _plutoload
PRIVS=$(PUBS) $(SCRIPTS) $(INTERNALS) $(BINS)
GENDFILES=secrets.eg conf.eg
GENDSCRIPTS=ipsec
LOCALS=
PLAIN_MANS=ipsec.8
IPSEC_CMANS=auto.8 barf.8 manual.8 ranbits.8 rsasigkey.8 setup.8 \
	showdefaults.8 showhostkey.8
MANS=$(PLAIN_MANS) $(IPSEC_CMANS)
CFLAGS=-I../lib
LIB=../lib/libfreeswan.a
INSTALL=install
PUB=--mode=644
PRIV=--mode=600
SECRETBITS=256
RSAKEYBITS=2048

ifdef CONFIG_COLDFIRE
CFLAGS += -DDEVICE='"/dev/urandom"'
endif

SHELL=/bin/sh

all:	$(PUBS) $(PRIVS) $(GENDFILES) $(LOCALS)

ranbits:	ranbits.o
	$(CC) $(CFLAGS) ranbits.o $(LIB) -o $@

rsasigkey:	rsasigkey.o
	$(CC) $(CFLAGS) rsasigkey.o $(LIB) -lgmp -o $@

man_xref:	man_xref.o
	$(CC) $(CFLAGS) man_xref.o $(LIB) -o $@

html2four:	html2four.o
	$(CC) $(CFLAGS) html2four.o $(LIB) -o $@

four2perm:	four2perm.o
	$(CC) $(CFLAGS) four2perm.o $(LIB) -o $@

ipsec:	ipsec.in
	VER=`sed -n '/"/s/^[^"]*"//p' ../version.c | sed 's/".*//'` ; \
	sed "s/xxx/$$VER/" ipsec.in | sed "s:@IPSEC_DIR@:$(REALPRIVDIR):" >$@
	chmod +x $@

# generate RSA private key... if, and only if, /etc/ipsec.secrets does
# not already exist
BLURB=-- not filled in because ipsec.secrets existed at build time --
secrets.eg:	secrets.proto ranbits rsasigkey
	rm -f $@
	umask 077 ; ( \
		sed '/yyy/,$$d' secrets.proto ; \
		if test ! -f $(CONFDIR)/ipsec.secrets ; \
		then ./rsasigkey --verbose $(RSAKEYBITS) ; \
		else echo "	# $(BLURB)" ; \
		fi ; \
		sed '1,/yyy/d' secrets.proto ; \
	) | egrep -v RCSID >$@

# force full secrets-file build
newsecrets:
	rm -f secrets.eg
	$(MAKE) secrets.eg CONFDIR=.

conf.eg:	conf.proto ranbits randomize
	rm -f $@
	./randomize conf.proto | egrep -v RCSI >$@

install:	$(PUBS) $(PRIVS) $(MANS) $(GENDFILES)
	mkdir -p $(PUBDIR) $(PRIVDIR) $(FMANDIR) $(CMANDIR) $(CONFDIR)
	$(INSTALL) $(PUBS) $(PUBDIR)
	$(INSTALL) $(PRIVS) $(PRIVDIR)
	$(INSTALL) $(PUB) ipsec.conf.5 $(FMANDIR)
	$(INSTALL) $(PUB) $(PLAIN_MANS) $(CMANDIR)
	for f in $(IPSEC_CMANS) ; \
	do \
		$(INSTALL) $(PUB) $$f $(CMANDIR)/ipsec_$$f || exit 1 ; \
		./manlink $(CMANDIR) ipsec_$$f ; \
	done
	test -f $(CONFDIR)/ipsec.secrets || \
		$(INSTALL) $(PRIV) secrets.eg $(CONFDIR)/ipsec.secrets
	test -f $(CONFDIR)/ipsec.conf || \
		$(INSTALL) $(PUB) conf.eg $(CONFDIR)/ipsec.conf
	# main copy must go in RCDIR, PRIVDIR may not be mounted at boot time
	mkdir -p $(RCDIR)
	$(INSTALL) setup $(RCDIR)/ipsec
	rm -f $(PRIVDIR)/setup
	ln -s $(REALRCDIR)/ipsec $(PRIVDIR)/setup
	PATH=/sbin:/usr/sbin:$$PATH ; export PATH ; \
	if test " $(DESTDIR)" != " " ; \
	then : do nothing ; \
	elif which chkconfig >/dev/null 2>&1 ; \
	then chkconfig --add ipsec ; \
	else $(MAKE) setup4 ; \
	fi

setup4:	$(RCDIR)/ipsec
	# fallback rc install -- on in run states 2345, off in 016, with
	# priorities matching those in setup's chkconfig line
	-cd $(RCDIR)/../rc0.d ; ln -s ../init.d/ipsec K68ipsec
	-cd $(RCDIR)/../rc1.d ; ln -s ../init.d/ipsec K68ipsec
	-cd $(RCDIR)/../rc2.d ; ln -s ../init.d/ipsec S47ipsec
	-cd $(RCDIR)/../rc3.d ; ln -s ../init.d/ipsec S47ipsec
	-cd $(RCDIR)/../rc4.d ; ln -s ../init.d/ipsec S47ipsec
	-cd $(RCDIR)/../rc5.d ; ln -s ../init.d/ipsec S47ipsec
	-cd $(RCDIR)/../rc6.d ; ln -s ../init.d/ipsec K68ipsec

clean:
	rm -f *.o $(BINS) $(GENDFILES) $(GENDSCRIPTS) $(LOCALS)
