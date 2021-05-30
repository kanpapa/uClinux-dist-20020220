# FreeS/WAN library
# Copyright (C) 1998, 1999  Henry Spencer.
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
# RCSID $Id: Makefile,v 1.36 2000/10/25 23:58:57 henry Exp $

OBJS=addrtoa.o addrtot.o addrtypeof.o anyaddr.o atoaddr.o \
	atoasr.o atosa.o atosubnet.o atoul.o datatot.o \
	goodmask.o initaddr.o initsaid.o initsubnet.o \
	optionsfrom.o pfkey_v2_build.o pfkey_v2_ext_bits.o pfkey_v2_parse.o \
	portof.o rangetoa.o rangetosubnet.o sameaddr.o \
	satoa.o satot.o subnetof.o subnettoa.o subnettot.o \
	subnettypeof.o ttoaddr.o ttodata.o \
	ttosa.o ttosubnet.o ttoul.o ultoa.o ultot.o

HDRS=freeswan.h internal.h
LIB=libfreeswan.a
# Original flags
CFLAGS+=-O3 -I.
# Add debugging symbols
CFLAGS+= -g
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

ARFLAGS=crvs
EXTHDRS=des.h
EXTLIBS=libdes.a
MANTREE=/usr/local/man
MANDIR=$(MANTREE)/man3
MANS=anyaddr.3 atoaddr.3 atoasr.3 atosa.3 atoul.3 goodmask.3 \
	initaddr.3 initsubnet.3 optionsfrom.3 portof.3 rangetosubnet.3 \
	sameaddr.3 subnetof.3 ttoaddr.3 ttodata.3 ttosa.3 ttoul.3
INSTALL=install

SHELL=/bin/sh


all:	$(EXTHDRS) $(LIB) $(EXTLIBS)

install:
	mkdir -p $(MANDIR)
	for f in $(MANS) ; \
	do \
		$(INSTALL) $$f $(MANDIR)/ipsec_$$f || exit 1 ; \
		../utils/manlink $(MANDIR) ipsec_$$f ; \
	done

$(LIB):	$(OBJS)
	ar $(ARFLAGS) $(LIB) $(OBJS)

$(OBJS):	$(HDRS)

des.h:
	ln -s ../libdes/des.h

libdes.a:	../libdes/libdes.a
	ln -f -s ../libdes/libdes.a

# yes, that's CFLAG=, not CFLAGS=
../libdes/libdes.a:
	cd ../libdes ; \
	if test " `arch | sed 's/^i[3456]/x/'`" = " x86" ; \
	then $(MAKE) CC='$(CC)' CFLAG='$(CFLAGS)' TESTING='' x86-elf ; \
	else $(MAKE) CC='$(CC)' CFLAG='$(CFLAGS)' libdes.a ; \
	fi

clean:
	rm -f $(LIB) *.o try* core *.core $(EXTHDRS) $(EXTLIBS)
	cd ../libdes ; $(MAKE) clean



# developer-only stuff
l:
	$(MAKE) $(LIB) ARFLAGS=crv CFLAGS=-O
	ranlib $(LIB)

t:	$(LIB)
	cp atosubnet.c try.c
	cc -DATOSUBNET_MAIN try.c $(LIB) -o try
	./try -r
	cp ttosubnet.c try1a.c
	cc -DTTOSUBNET_MAIN try1a.c $(LIB) -o try1a
	./try1a -r
	cp ttodata.c try2.c
	cc -DTTODATA_MAIN try2.c $(LIB) -o try2
	./try2 -r
	cp atoasr.c try3.c
	cc -DATOASR_MAIN try3.c $(LIB) -o try3
	./try3 -r
	cp atosa.c try4.c
	cc -DATOSA_MAIN try4.c $(LIB) -o try4
	./try4 -r
	cp ttosa.c try4a.c
	cc -DTTOSA_MAIN try4a.c $(LIB) -o try4a
	./try4a -r
	cp rangetosubnet.c try6.c
	cc -DRANGETOSUBNET_MAIN try6.c $(LIB) -o try6
	./try6 -r

lt:	$(LIB)
	$(MAKE) t
	cp optionsfrom.c try5.c
	cc -DTEST try5.c $(LIB) -o try5
	echo --foo --bar >try5in1
	echo --optionsfrom >>try5in1
	echo try5in2 >>try5in1
	echo --foo >try5in2
	./try5 --foo --bar --optionsfrom try5in1 --bar something

tar:	clean
	tar -cvf /tmp/lib.tar Makefile [a-z]*
