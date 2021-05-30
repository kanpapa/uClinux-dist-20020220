
srcdir   = $(ROOTDIR)/freeswan
ipsecdir = $(srcdir)/klips/net/ipsec

vpath %.c $(srcdir)/klips/utils

CFLAGS	+= -I$(ipsecdir) -I$(srcdir)/lib -I$(srcdir)
CFLAGS	+= -Wall
#CFLAGS	+= -Wconversion
#CFLAGS	+= -Wmissing-prototypes
#CFLAGS	+= -Wpointer-arith
#CFLAGS	+= -Wcast-qual
#CFLAGS	+= -Wmissing-declarations
CFLAGS	+= -Wstrict-prototypes
#CFLAGS	+= -pedantic
#CFLAGS	+= -O3
#CFLAGS	+= -W
#CFLAGS	+= -Wwrite-strings
#CFLAGS	+= -Wbad-function-cast 

ALL=spi eroute spigrp tncfg klipsdebug

FREESWANLIB = ../lib/libfreeswan.a
INSTALL=install

all: $(ALL)

spi: spi.o
	$(CC) $(LDFLAGS) -o $@ $? $(FREESWANLIB) $(LDLIBS)

eroute: eroute.o
	$(CC) $(LDFLAGS) -o $@ $? $(FREESWANLIB) $(LDLIBS)

spigrp: spigrp.o
	$(CC) $(LDFLAGS) -o $@ $? $(FREESWANLIB) $(LDLIBS)

tncfg: tncfg.o
	$(CC) $(LDFLAGS) -o $@ $? $(FREESWANLIB) $(LDLIBS)

klipsdebug: klipsdebug.o
	$(CC) $(LDFLAGS) -o $@ $? $(FREESWANLIB) $(LDLIBS)

romfs:
	$(ROMFSINST) -e CONFIG_USER_FREESWAN_KLIPS_SPI /bin/spi
	$(ROMFSINST) -e CONFIG_USER_FREESWAN_KLIPS_EROUTE /bin/eroute
	$(ROMFSINST) -e CONFIG_USER_FREESWAN_KLIPS_SPIGRP /bin/spigrp
	$(ROMFSINST) -e CONFIG_USER_FREESWAN_KLIPS_TNCFG /bin/tncfg
	$(ROMFSINST) -e CONFIG_USER_FREESWAN_KLIPS_KLIPSDEBUG /bin/klipsdebug

clean:
	rm -f *.elf *.gdb *.o $(ALL)

