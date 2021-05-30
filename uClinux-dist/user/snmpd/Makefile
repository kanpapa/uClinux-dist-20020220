
EXEC = snmpd
OBJS = ap0.o aps.o asl.o asn.o asx.o avl.o host.o mis.o miv0.o ip_vars.o\
        miv1.o miv2.o miv3.o miv4.o miv5.o miv6.o miv7.o mix.o tcp_vars.o iface_vars.o\
        oid.o rdx.o smp.o smx.o udp.o vec.o systm.o udp_vars.o icmp_vars.o snmpd.o 
 
FLTFLAGS += -s 131072

ifdef BUILD_NETtel
CFLAGS += -DCONFIG_NETtel
endif
ifdef BUILD_NETtel1500
CFLAGS += -DCONFIG_NETtel
endif

all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

romfs:
	$(ROMFSINST) /bin/$(EXEC)

clean:
	-rm -f $(EXEC) *.elf *.gdb *.o

$(OBJS): 

