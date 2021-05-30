# Makefile for the KLIPS interface utilities
# Copyright (C) 1998, 1999  Henry Spencer.
# Copyright (C) 1999, 2000, 2001  Richard Guy Briggs
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
# RCSID $Id: Makefile,v 1.17 2001/06/14 19:35:13 rgb Exp $

CC=gcc
CFLAGS=-O2 -I../net/ipsec -I../../lib -g

CFLAGS+= -Wall
#CFLAGS+= -Wconversion
#CFLAGS+= -Wmissing-prototypes
CFLAGS+= -Wpointer-arith
CFLAGS+= -Wcast-qual
#CFLAGS+= -Wmissing-declarations
CFLAGS+= -Wstrict-prototypes
#CFLAGS+= -pedantic
#CFLAGS+= -O3
#CFLAGS+= -W
#CFLAGS+= -Wwrite-strings
CFLAGS+= -Wbad-function-cast 

ALL=spi eroute spigrp tncfg klipsdebug
BINDIR=/usr/local/lib/ipsec
MANTREE=/usr/local/man
MANDIR8=$(MANTREE)/man8
MANDIR5=$(MANTREE)/man5
FREESWANLIB=../../lib/libfreeswan.a
INSTALL=install

all: $(ALL)

install: $(ALL)
	$(INSTALL) $(ALL) $(BINDIR)
	for f in $(addsuffix .8, $(ALL)) ; do \
		$(INSTALL) $$f $(MANDIR8)/ipsec_$$f || exit 1 ; done
	for f in $(addsuffix .5, $(ALL) version pf_key) ; do \
		$(INSTALL) $$f $(MANDIR5)/ipsec_$$f || exit 1 ; done

spi: spi.o
	$(CC) $(DFLAGS) -o $@ $? $(FREESWANLIB)

eroute: eroute.o
	$(CC) $(DFLAGS) -o $@ $? $(FREESWANLIB)

spigrp: spigrp.o
	$(CC) $(DFLAGS) -o $@ $? $(FREESWANLIB)

tncfg: tncfg.o
	$(CC) $(DFLAGS) -o $@ $? $(FREESWANLIB)

klipsdebug: klipsdebug.o
	$(CC) $(DFLAGS) -o $@ $? $(FREESWANLIB)

clean:
	rm -f *.o $(ALL)

#
# $Log: Makefile,v $
# Revision 1.17  2001/06/14 19:35:13  rgb
# Update copyright date.
#
# Revision 1.16  2000/06/30 06:20:25  rgb
# Add version.5 and pf_key.5 to the list of manpages to be installed.
#
# Revision 1.15  2000/06/28 05:51:23  rgb
# Install section 5 manpages.
#
# Revision 1.14  2000/01/21 09:44:29  rgb
# Added compiler switches to be a lot more fussy.
#
# Revision 1.13  1999/04/11 00:12:07  henry
# GPL boilerplate
#
# Revision 1.12  1999/04/06 04:54:37  rgb
# Fix/Add RCSID Id: and Log: bits to make PHMDs happy.  This includes
# patch shell fixes.
#
# Revision 1.11  1999/04/03 05:39:06  henry
# install -d doesn't do what I thought
#
# Revision 1.10  1999/04/03 05:23:23  henry
# use INSTALL
#
# Revision 1.9  1998/11/12 21:11:21  rgb
# Change default binary install directory from /usr/local/sbin to
# /usr/local/lib/ipsec.
#
# Revision 1.8  1998/11/07 05:38:54  henry
# changes for manpage ipsec_ prefix
#
# Revision 1.7  1998/07/28 00:08:07  rgb
# Add freeswan lib.
#
# Revision 1.6  1998/06/11 05:40:52  rgb
# Install manpages when binaries are installed.
#
# Revision 1.5  1998/05/12 02:28:07  rgb
# Utils can now be compiled before kernel install/config.
#
# Revision 1.4  1998/05/06 03:35:40  rgb
# Changed make install from an 'mv' to a 'cp'.
#
# Revision 1.3  1998/04/23 21:09:16  rgb
# Added a userspace util to change kernelspace debug switches.
#
# Revision 1.2  1998/04/14 14:07:01  rgb
# Permanently remove setsa.c and addrt.c from the distribution and fix the
# Makefile.
#
# Revision 1.1.1.1  1998/04/08 05:35:09  henry
# RGB's ipsec-0.8pre2.tar.gz ipsec-0.8
#
# Revision 0.5  1997/06/03 04:31:55  ji
# Added esp 3des-md5-96.
# Added transport mode configuration utility.
#
# Revision 0.4  1997/01/15 01:38:21  ji
# Changed to include setsa.c
#
# Revision 0.3  1996/11/20 14:51:32  ji
# Fixed problems with #include paths.
# Changed (incorrect) references to ipsp into ipsec.
#
#
