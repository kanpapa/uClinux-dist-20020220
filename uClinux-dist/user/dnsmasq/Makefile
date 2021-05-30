
EXEC = dnsmasq
OBJS = dnsmasq.o
CFLAGS += -D__USE_BSD=1 -DNO_FORK=1 -DDEFAULT_CACHE_SIZE=20

FLTFLAGS += -s 8192

all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

romfs:
	$(ROMFSINST) /bin/$(EXEC)

clean:
	-rm -f $(EXEC) *.gdb *.elf *.o

$(OBJS): 

