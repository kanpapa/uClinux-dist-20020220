
NMALLOC = $(ROOTDIR)/lib/libsmalloc/malloc-slow.o
INCLUDES = -I.. -I../lib

CFLAGS += -DHAVE_CONFIG_H -DSYSCONFDIR=\"/etc/config/\"

OBJS =  zserv.o main.o interface.o connected.o ioctl.o rib.o \
		redistribute.o debug.o rtadv.o zebra_snmp.o
OBJS += rt_ioctl.o
OBJS += if_ioctl.o
OBJS += if_proc.o
OBJS += rtread_proc.o
OBJS += ipforward_proc.o

all: zebra

zebra: $(OBJS) $(NMALLOC) ../lib/libzebra.a
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(NMALLOC) ../lib/libzebra.a $(LDLIBS)

romfs:
	$(ROMFSINST) /bin/zebra

client : client_main.o ../lib/libzebra.a
	$(CC) $(LDFLAGS) -o $@ client_main.o ../lib/libzebra.a $(LDLIBS)

.c.o:
	$(CC) $(INCLUDES) $(CFLAGS) -c $<

clean:
	rm -f *.gdb *.elf *.o client zebra

dummy_target:

nfs: dummy_target
	@$(MAKE) MAKE_NFS=1

