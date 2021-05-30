# Generated automatically from Makefile.in by configure.
###############################################################################
# Makefile for the DMalloc library.
# $Id: Makefile,v 1.9 2001/12/12 00:46:44 philipc Exp $
###############################################################################

# default root installation directory
prefix = /usr/local
exec_prefix = ${prefix}

srcdir = .

bindir = $(exec_prefix)/bin
libdir = $(exec_prefix)/lib
shlibdir = $(exec_prefix)/shlib
incdir = $(prefix)/include
infodir = $(prefix)/info

# default c-compiler
# CC = gcc
# CXX = c++

DEFS	= -DHAVE_STDARG_H=1 \
	-DHAVE_STDLIB_H=1 \
	-DHAVE_STRING_H=1 \
	-DHAVE_UNISTD_H=1 \
	-DHAVE_SYS_MMAN_H=0 \
	-DHAVE_SYS_TYPES_H=1 \
	$(DEFINES)
INCS = -I. -I$(srcdir) $(INCLUDES)
LIBS = -L. -L../$(LIBCDIR) -L../$(LIBCDIR)/lib -lc

MODULE	= dmalloc

LIBRARY	= lib$(MODULE).a
SHLIBRARY = lib$(MODULE).so

# thread version of the library
LIB_TH	= lib$(MODULE)th.a
SHLIB_TH = lib$(MODULE)th.so
#BUILD_TH = $(LIB_TH)
#INSTALL_TH = installth

# C++ version of the library
LIB_CXX	= lib$(MODULE)xx.a
SHLIB_CXX = lib$(MODULE)xx.so
BUILD_CXX = $(LIB_CXX)
INSTALL_CXX = installcxx
BUILD_TH_CXX = $(LIB_TH_CXX)

# threads + C++
LIB_TH_CXX = lib$(MODULE)thcxx.a

# library with dmalloc disabled
LIB_DIS	= lib$(MODULE)lp.a
SHLIB_DIS = lib$(MODULE)lp.so

UTIL = $(MODULE)
INFOFILE = $(MODULE).info

#CCFLAGS += -g -O2 -m5200 -Wa,-m5200 -DCONFIG_COLDFIRE -Dlinux -D__linux__ -Dunix -DEMBED
#LDFLAGS += -g -Wl,-elf2flt -nostartfiles ../libc/crt0.o
LDFLAGS += -g -Wl,-elf2flt

INSTALL = /usr/bin/install -c
INSTALL_PROGRAM = ${INSTALL}
INSTALL_DATA = ${INSTALL} -m 644

###############################################################################
# End of system configuration section.
###############################################################################

SHELL = /bin/sh

HFLS = dmalloc.h
OBJS = arg_check.o compat.o dmalloc_lp.o dmalloc_tab.o env.o heap.o protect.o
NORMAL_OBJS = chunk.o error.o malloc.o
THREAD_OBJS = chunk_th.o error_th.o malloc_th.o
CXX_OBJS = dmallocc.o

CFLAGS += $(CCFLAGS) $(CPPFLAGS)
TEST = $(MODULE)_t

#all : dmalloc.h $(LIBRARY) tests

all : dmalloc.h $(LIBRARY)
#	@echo "To make the C++ version of the library type 'make cxx'"
	@echo "To make the thread version of the library type 'make threads'"

romfs :

clean :
	rm -f a.out core *.o *.t
	rm -f $(LIBRARY) $(LIB_TH) $(LIB_CXX) $(LIB_DIS) $(TEST) $(UTIL)
	rm -f dmalloc.h

realclean : clean

distclean : clean
	rm -f confdefs.h config.status config.log config.cache conf.h
	rm -f Makefile settings.h dmalloc.h.2
#	rm -f configure

installdirs :
	$(srcdir)/mkinstalldirs $(incdir) $(libdir) $(bindir)
# may want to add $(shlibdir) to this list

installincs : $(HFLS)
	$(srcdir)/mkinstalldirs $(incdir)
	$(INSTALL_DATA) $(HFLS) $(incdir)

installcxx : $(LIB_CXX)
	$(srcdir)/mkinstalldirs $(libdir)
	$(INSTALL_DATA) $(LIB_CXX) $(libdir)

installlib : installincs $(LIBRARY) $(LIB_DIS) $(INSTALL_CXX) $(INSTALL_TH)
	$(srcdir)/mkinstalldirs $(libdir)
	$(INSTALL_DATA) $(LIBRARY) $(libdir)
	ranlib $(libdir)/$(LIBRARY)
	$(INSTALL_DATA) $(LIB_DIS) $(libdir)
	ranlib $(libdir)/$(LIB_DIS)

install : installdirs installlib $(UTIL)
	$(srcdir)/mkinstalldirs $(bindir)
	$(INSTALL_PROGRAM) $(UTIL) $(bindir)
	@echo "Enter 'make installinfo' to install $(INFOFILE) in $(infodir)"
	@echo "Enter 'make installshlib' to install $(SHLIBRARY) in $(shlibdir)"
#	@echo "Enter 'make installcxx' to install the C++ library"
	@echo "Enter 'make installth' to install thread library"

installth : $(LIB_TH)
	$(srcdir)/mkinstalldirs $(libdir)
	$(INSTALL_DATA) $(LIB_TH) $(libdir)

installinfo : $(INFOFILE)
	$(srcdir)/mkinstalldirs $(infodir)
	$(INSTALL_DATA) $(srcdir)/$(INFOFILE) $(infodir)

installshlib : $(SHLIBRARY)
	$(srcdir)/mkinstalldirs $(shlibdir)
	$(INSTALL_DATA) $(srcdir)/$(SHLIBRARY) $(shlibdir)

dmalloc.h.2 : $(srcdir)/configure
	$(SHELL) $(srcdir)/configure

settings.h : $(srcdir)/settings.dist $(srcdir)/configure
	$(SHELL) $(srcdir)/configure

dmalloc.h : $(srcdir)/dmalloc.h.1 dmalloc.h.2 $(srcdir)/dmalloc.h.3
	rm -f $@ $@.t
	cat $(srcdir)/dmalloc.h.1 dmalloc.h.2 $(srcdir)/dmalloc.h.3 > $@.t
	mv $@.t $@

shlib : ${SHLIBRARY}

# NOTE: you may have to edit the following to have it work on your system
${SHLIBRARY} : $(LIBRARY)
	rm -f $@ $@.t
	ld -shared -o $@.t -all $(LIBRARY) -all -soname $@ -none -lc
	mv $@.t $@

$(LIBRARY) : $(OBJS) $(NORMAL_OBJS)
	$(AR) cr $@ $?
	$(RANLIB) $@

$(LIB_TH) : $(OBJS) $(THREAD_OBJS)
	$(AR) cr $@ $?
	$(RANLIB) $@

$(LIB_CXX) : $(OBJS) $(NORMAL_OBJS) $(CXX_OBJS)
	$(AR) cr $@ $?
	$(RANLIB) $@

$(LIB_TH_CXX) : $(OBJS) $(THREAD_OBJS) $(CXX_OBJS)
	$(AR) cr $@ $?
	$(RANLIB) $@

$(LIB_DIS) : dmalloc_lp.o
	$(AR) cr $@ $?
	$(RANLIB) $@

threads : $(LIB_TH) $(BUILD_TH_CXX)

cxx : $(LIB_CXX)

utils : $(UTIL)

$(UTIL) : $(UTIL).o dmalloc_argv.o compat.o env.o
	rm -f $@
	$(LD) -o a.out $(LDFLAGS) $(UTIL).o dmalloc_argv.o compat.o env.o $(LIBS)
	mv a.out $@

# special _th versions of objects with the LOCK_THREADS variable defined to 1
chunk_th.o : $(srcdir)/chunk.c
	rm -f $@
	$(CC) $(CFLAGS) $(CPPFLAGS) $(DEFS) $(INCS) -DLOCK_THREADS=1 \
		-c $(srcdir)/chunk.c -o ./$@

error_th.o : $(srcdir)/error.c
	rm -f $@
	$(CC) $(CFLAGS) $(CPPFLAGS) $(DEFS) $(INCS) -DLOCK_THREADS=1 \
		-c $(srcdir)/error.c -o ./$@

malloc_th.o : $(srcdir)/malloc.c
	rm -f $@
	$(CC) $(CFLAGS) $(CPPFLAGS) $(DEFS) $(INCS) -DLOCK_THREADS=1 \
		-c $(srcdir)/malloc.c -o ./$@

tests : $(TEST)

$(TEST) : $(TEST).o dmalloc_argv.o $(LIBRARY)
	rm -f $@
	$(CC) $(LDFLAGS) -o $@ $(TEST).o dmalloc_argv.o libdmalloc.a $(LIBS)

check light : $(TEST)
	./$(TEST) -s -t 10000
	./$(TEST) -s -t 10000
	./$(TEST) -s -t 10000
	./$(TEST) -s -t 10000
	./$(TEST) -s -t 10000

heavy : $(TEST) light
	./$(TEST) -s -t 100000
	./$(TEST) -s -t 100000
	./$(TEST) -s -t 100000

.c.o :
	rm -f $@
	$(CC) $(CFLAGS) $(CPPFLAGS) $(DEFS) $(INCS) -c $< -o ./$@

.cc.o :
	rm -f $@
	$(CXX) $(CFLAGS) $(CPPFLAGS) $(DEFS) $(INCS) -c $< -o ./$@

.texi.info :
	makeinfo --no-split $<

#
# auto configure settings - uncomment if you are doing configure
# development on the library
#

#Makefile : $(srcdir)/Makefile.in config.status
#	$(SHELL) config.status

#conf.h : $(srcdir)/conf.h.in config.status
#	$(SHELL) config.status

#config.status : $(srcdir)/configure
#	$(SHELL) config.status --recheck

# $(srcdir)/configure : $(srcdir)/configure.in
#	cd $(srcdir); autoconf

###############################################################################
#
# These dependencies are automatically generated.  Do not edit by hand.
#

arg_check.o: arg_check.c dmalloc.h conf.h settings.h chunk.h \
 debug_val.h dmalloc_loc.h error.h arg_check.h
chunk.o: chunk.c conf.h settings.h dmalloc.h chunk.h chunk_loc.h \
 dmalloc_loc.h compat.h debug_val.h dmalloc_tab.h error.h error_val.h \
 heap.h
compat.o: compat.c dmalloc.h conf.h settings.h compat.h dmalloc_loc.h
dmalloc.o: dmalloc.c dmalloc_argv.h conf.h settings.h dmalloc.h \
 compat.h debug_tok.h dmalloc_loc.h debug_val.h env.h error_str.h \
 error_val.h version.h
dmalloc_argv.o: dmalloc_argv.c conf.h settings.h dmalloc_argv.h \
 dmalloc_argv_loc.h compat.h
dmalloc_lp.o: dmalloc_lp.c dmalloc.h conf.h settings.h error_val.h \
 dmalloc_loc.h dmalloc_lp.h malloc.h error.h return.h
dmalloc_t.o: dmalloc_t.c conf.h settings.h dmalloc_argv.h dmalloc.h \
 debug_val.h dmalloc_loc.h error_val.h
dmalloc_tab.o: dmalloc_tab.c conf.h settings.h chunk.h compat.h \
 dmalloc.h dmalloc_loc.h error.h error_val.h dmalloc_tab.h \
 dmalloc_tab_loc.h
env.o: env.c conf.h settings.h dmalloc.h compat.h dmalloc_loc.h \
 debug_tok.h debug_val.h env.h error.h
error.o: error.c conf.h settings.h dmalloc.h compat.h debug_val.h \
 dmalloc_loc.h env.h error.h error_val.h version.h
heap.o: heap.c dmalloc.h conf.h settings.h chunk.h compat.h \
 debug_val.h dmalloc_loc.h error.h error_val.h heap.h
malloc.o: malloc.c conf.h settings.h dmalloc.h chunk.h compat.h \
 debug_val.h dmalloc_loc.h env.h error.h error_str.h error_val.h \
 heap.h dmalloc_lp.h malloc.h return.h
protect.o: protect.c conf.h settings.h dmalloc.h dmalloc_loc.h error.h \
 protect.h
chunk_th.o: chunk.c conf.h settings.h dmalloc.h chunk.h chunk_loc.h \
 dmalloc_loc.h compat.h debug_val.h dmalloc_tab.h error.h error_val.h \
 heap.h
error_th.o: error.c conf.h settings.h dmalloc.h compat.h debug_val.h \
 dmalloc_loc.h env.h error.h error_val.h version.h
malloc_th.o: malloc.c conf.h settings.h dmalloc.h chunk.h compat.h \
 debug_val.h dmalloc_loc.h env.h error.h error_str.h error_val.h \
 heap.h dmalloc_lp.h malloc.h return.h
