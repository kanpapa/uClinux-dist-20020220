#
#	Makefile -- Master makefile for small libc
#

.EXPORT_ALL_VARIABLES:

# CFLAGS += -I../include

DIRS  = headers error gtermcap misc stdio2 time getent regexp string termios \
        sysdeps malloc-simple net rpc $(MACHINE) serial
		# shm - doesn't work for 2.4 yet

all: libc.a

libc.a: $(DIRS)
	$(RANLIB) $@
	ln -f libc.a libcrypt.a
	ln -f libc.a libg.a

headers: dummy
	if [ ! -L "include/asm" ]; then ln -s ../../../$(LINUXDIR)/include/asm include/asm ; fi
	if [ ! -L "include/linux" ]; then ln -s ../../../$(LINUXDIR)/include/linux include/linux ; fi
	if [ ! -L "include/machine" ]; then ln -s $(MACHINE) include/machine ; fi
	if [ ! -L "stdio2/stdio.h" ]; then ln -s ../include/stdio.h stdio2/stdio.h ; fi
	if [ ! -L "include/netinet/in_system.h" ]; then ln -s in_systm.h include/netinet/in_system.h ; fi

error: dummy
	make -C error

gtermcap: dummy
	make -C gtermcap

misc: dummy
	make -C misc

stdio2: dummy
	make -C stdio2

time: dummy
	make -C time

getent: dummy
	make -C getent

regexp: dummy
	make -C regexp

string: dummy
	make -C string

termios: dummy
	make -C termios

sysdeps: dummy
	make -C sysdeps

malloc-simple: dummy
	make -C malloc-simple

net: dummy
	make -C net

rpc: dummy
	make -C rpc

serial: dummy
	make -C serial

shm: dummy
	make -C shm

$(MACHINE): dummy
	make -C $(MACHINE)

dummy:

romfs:

clean:
	-rm -f `find . -name \*.[oa] -o -name \*~` core
	-rm -f include/asm include/linux
	-rm -f include/machine stdio2/stdio.h include/netinet/in_system.h

