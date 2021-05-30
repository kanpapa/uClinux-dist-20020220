# $Header: /cvs/sw/new-wave/user/tpt/Makefile,v 1.1 2002/02/14 23:04:55 pauli Exp $

CFLAGS+=-Wall -Wshadow

OFILES = tpt.o util.o build.o dump.o massage.o

tpt: $(OFILES)

romfs:
	$(ROMFSINST) /bin/tpt

$(OFILES): tpt.h

clean:
	rm $(OFILES) tpt
