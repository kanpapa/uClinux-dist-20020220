# Copyright (C) 2000, Lineo
# This file is distributed under the GNU Library General Public License.
#
# Slow malloc for apps that do a lot of little allocs
#

LIBC=libsmalloc.a
MSRC=alloc.c
MOBJ=malloc.o free.o calloc.o realloc.o
# CFLAGS += -DEMBED=1 -I../libc/include
# CFLAGS += -DEMBED=1

OBJ=$(MOBJ)

all: $(LIBC) malloc-slow.o
	#@$(RM) $(OBJ)

$(LIBC): $(LIBC)($(OBJ))

#
# An object version to force inclusion of this malloc (libc clashes etc)
#
malloc-slow.o: $(MOBJ)
	$(LD) -r -o $@ $(MOBJ)

$(MOBJ): $(MSRC)
	$(CC) $(CFLAGS) -DL_$* $< -c -o $*.o

$(LIBC)($(MOBJ)): $(MOBJ)
	$(AR) $(ARFLAGS) $@ $*.o

romfs:

clean:
	rm -f *.o *.a

