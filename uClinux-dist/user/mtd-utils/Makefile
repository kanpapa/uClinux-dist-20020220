
# -*- sh -*-

# $Id: Makefile,v 1.20 2001/09/05 00:18:11 andersen Exp $

MY_CFLAGS = -I$(ROOTDIR)/$(LINUXDIR)/include
BUILD_CFLAGS += $(MY_CFLAGS)
CFLAGS += $(MY_CFLAGS)

BUILD_CC = gcc

ALL_TARGETS = ftl_format erase eraseall nftldump nanddump doc_loadbios \
nftl_format mkfs.jffs ftl_check nandtest nandwrite mkfs.jffs2 lock unlock \
einfo mtd_debug fcp jffs2reader
ALL_BUILD_TARGETS = $(patsubst %,build/%,$(ALL_TARGETS))

TARGETS = 
BUILD_TARGETS =

ifdef CONFIG_JFFS_FS
BUILD_TARGETS += build/mkfs.jffs
endif
ifdef CONFIG_JFFS2_FS
BUILD_TARGETS += build/mkfs.jffs2
endif

SYMLINKS = crc32.h crc32.c compr_rtime.c compr_rubin.c compr.c pushpull.h histo_mips.h compr_rubin.h compr_zlib.c

JFFS2_OBJS = crc32.o compr_rtime.o compr_rubin.o compr.o mkfs.jffs2.o compr_zlib.o
BUILD_JFFS2_OBJS = $(patsubst %,build/%,$(JFFS2_OBJS))

all: build $(TARGETS) $(BUILD_TARGETS)

.PHONY:
build:
	[ -d build ] || mkdir build

clean:
	rm -f *.o build/*.o $(ALL_TARGETS) $(ALL_BUILD_TARGETS) $(SYMLINKS)

romfs:

mkfs.jffs2.o crc32.o: crc32.h
build/mkfs.jffs2.o build/crc32.o: crc32.h
compr_rubin.o: pushpull.h
build/compr_rubin.o: pushpull.h
compr_rubin.o: histo_mips.h compr_rubin.h
build/compr_rubin.o: histo_mips.h compr_rubin.h

$(SYMLINKS):
	ln -sf $(ROOTDIR)/$(LINUXDIR)/fs/jffs2/$@ $@

mkfs.jffs2: $(JFFS2_OBJS)
	$(CC) -o $@ $^ $(LIBZ) $(LDLIBS)

build/mkfs.jffs2: $(BUILD_JFFS2_OBJS)
	$(BUILD_CC) -o $@ $^ $(LDPATH) -lz

compr.o: compr.c
	$(CC) $(CFLAGS) -Dprintk=printf -DKERN_NOTICE= -DKERN_WARNING= -c -o $@ $< $(LDLIBS)

build/compr.o: compr.c
	$(BUILD_CC) $(BUILD_CFLAGS) -Dprintk=printf -DKERN_NOTICE= -DKERN_WARNING= -c -o $@ $<

compr_zlib.o: compr_zlib.c
	$(CC) $(CFLAGS) $(INCZ) -c -o $@ $<

build/compr_zlib.o: compr_zlib.c
	$(BUILD_CC) $(BUILD_CFLAGS) -Dprintk=printf -DKERN_NOTICE= -DKERN_WARNING= $(INCZ) -c -o $@ $<

jffs2reader: jffs2reader.c
	$(CC) $(CFLAGS) jffs2reader.c -o jffs2reader $(LDPATH) -lz 

build/jffs2reader: jffs2reader.c
	$(BUILD_CC) $(BUILD_CFLAGS) -o $@ $< $(LDPATH) -lz

build/%.o: %.c
	$(BUILD_CC) $(BUILD_CFLAGS) -c -o $@ $<

build/%: %.c
	$(BUILD_CC) $(BUILD_CFLAGS) -o $@ $<

romfs:
