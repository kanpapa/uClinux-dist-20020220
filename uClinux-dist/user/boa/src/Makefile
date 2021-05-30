
EXEC = boa
OBJS = alias.o auth.o boa.o cgi.o cgi_header.o config.o get.o hash.o \
	log.o nls.o pipe.o queue.o read.o request.o response.o signals.o \
	timestamp.o util.o

FLTFLAGS += -s 8192

SSL_LIBS = 

ifdef CONFIG_USER_BOA_WITH_SSL
CFLAGS += $(INCSSL) -DSERVER_SSL=1
SSL_LIBS += $(LIBCRYPT) $(LIBSSL) $(LIBCRYPTO)
endif

ifdef CONFIG_USER_TINYLOGIN_SHADOWPASSWDS
CFLAGS += -DSHADOW_AUTH
endif

EXTRALIBS = $(LIBCRYPT)

all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(SSL_LIBS) $(EXTRALIBS) $(LDLIBS)

romfs:
	$(ROMFSINST) /bin/$(EXEC)

clean:
	-rm -f $(EXEC) *.gdb *.elf *.o


