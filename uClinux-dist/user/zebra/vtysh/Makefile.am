## Process this file with Automake to create Makefile.in

INCLUDES = @INCLUDES@ -I.. -I$(top_srcdir) -I$(top_srcdir)/lib
DEFS = @DEFS@ -I. -I$(srcdir)

bin_PROGRAMS = vtysh

vtysh_SOURCES = vtysh.c
noinst_HEADERS = vtysh.h
vtysh_LDADD = ../lib/libzebra.a -lreadline -lncurses
