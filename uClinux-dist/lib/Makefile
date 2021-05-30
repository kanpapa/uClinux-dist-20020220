#
#	Makefile -- Master makefile for all libraries.
#

.EXPORT_ALL_VARIABLES:

#
# Include architecture specific build rules.
#

ifndef ROOTDIR
ROOTDIR=..
endif

UCLINUX_BUILD_LIB=1
include $(LINUX_CONFIG)
include $(CONFIG_CONFIG)
include $(ARCH_CONFIG)

#
# always build these dir_
#
dir_y  = $(LIBCDIR) libnet libsmalloc libdmalloc
dir_n  =
dir_   =

ifeq ($(LIBCDIR),libc)
dir_y += libm
endif

#
# and build these if someone needs them
#
dir_$(CONFIG_LIB_LIBDES)       += libdes
dir_$(CONFIG_LIB_LIBDES_FORCE) += libdes
dir_$(CONFIG_LIB_LIBSSL)       += libssl
dir_$(CONFIG_LIB_LIBSSL_FORCE) += libssl
dir_$(CONFIG_LIB_LIBGMP)       += libgmp
dir_$(CONFIG_LIB_LIBGMP_FORCE) += libgmp
dir_$(CONFIG_LIB_LIBG)         += libg
dir_$(CONFIG_LIB_LIBG_FORCE)   += libg
dir_$(CONFIG_LIB_LIBPAM)       += libpam
dir_$(CONFIG_LIB_LIBPAM_FORCE) += libpam
dir_$(CONFIG_LIB_LIBPCAP)      += libpcap
dir_$(CONFIG_LIB_LIBPCAP_FORCE)+= libpcap
dir_$(CONFIG_LIB_ZLIB)         += zlib
dir_$(CONFIG_LIB_ZLIB_FORCE)   += zlib

all:
ifeq ($(LIBCDIR),glibc/build)
	[ -d glibc/build ] || mkdir glibc/build
	if [ ! -f glibc/build/config.cache ]; then \
		cd glibc/build; \
		export CFLAGS="$(ARCH_CFLAGS)"; \
		unset LDFLAGS; \
		../configure  --prefix= \
			--build=i386-pc-linux --host=i386-redhat-linux \
			--with-headers=$(ROOTDIR)/$(LINUXDIR)/include \
			--without-cvs --without-gd \
			--disable-profile --disable-force-install \
			--enable-add-ons ; \
	fi
endif
	for i in $(dir_y) ; do [ ! -d $$i ] || make -C $$i || exit $? ; done

romfs:
	for i in $(dir_y) ; do \
		[ ! -d $$i ] || make -C $$i romfs || exit $$? ; \
	done
	-strip $(ROMFSDIR)/lib/*

clean:
	-for i in $(dir_y) $(dir_n) $(dir_); do \
		[ ! -d $$i ] || make -C $$i clean ; \
	done

