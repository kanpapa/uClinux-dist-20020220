#
# Makefile -- Build instructions for Midas lab RTE-V850E/MA1-CB eval board
#

ROMFSIMG = $(IMAGEDIR)/root.romfs
IMAGE    = $(IMAGEDIR)/linux

DIRS = 

ROMFS_DIRS = bin dev etc home lib mnt proc usr var \
             home/httpd home/httpd/cgi-bin

DEVICES =								      \
	tty,c,5,0      console,c,5,1   mem,c,1,1     kmem,c,1,2    null,c,1,3 \
									      \
	ttyS0,c,4,64   ttyS1,c,4,65					      \
									      \
	zero,c,1,5     random,c,1,8    urandom,c,1,9			      \
									      \
	ptyp0,c,2,0    ptyp1,c,2,1     ptyp2,c,2,2   ptyp3,c,2,3	      \
	ptyp4,c,2,4    ptyp5,c,2,5     ptyp6,c,2,6   ptyp7,c,2,7	      \
	ptyp8,c,2,8    ptyp9,c,2,9     ptypa,c,2,10  ptypb,c,2,11	      \
	ptypc,c,2,12   ptypd,c,2,13    ptype,c,2,14  ptypf,c,2,15	      \
									      \
	ttyp0,c,3,0    ttyp1,c,3,1     ttyp2,c,3,2   ttyp3,c,3,3	      \
	ttyp4,c,3,4    ttyp5,c,3,5     ttyp6,c,3,6   ttyp7,c,3,7	      \
	ttyp8,c,3,8    ttyp9,c,3,9     ttypa,c,3,10  ttypb,c,3,11	      \
	ttypc,c,3,12   ttypd,c,3,13    ttype,c,3,14  ttypf,c,3,15

all:
	dirs=$(DIRS) ; \
	for i in $$dirs ; do  $(MAKE) -C $$i || exit $? ; done

clean:
	-dirs=$(DIRS) ; \
	for i in $$dirs; do [ ! -d $$i ] || $(MAKE) -C $$i clean; done

romfs:
	[ -d $(ROMFSDIR)/$$i ] || mkdir -p $(ROMFSDIR)
	for i in $(ROMFS_DIRS); do \
		[ -d $(ROMFSDIR)/$$i ] || mkdir -p $(ROMFSDIR)/$$i; \
	done
	for i in $(DEVICES); do \
		touch $(ROMFSDIR)/dev/@$$i; \
	done
	dirs=$(DIRS) ; for i in $$dirs; do $(MAKE) -C $$i romfs || exit $? ; done
	$(ROMFSINST) -s /var/tmp /tmp
	$(ROMFSINST) -s /bin /sbin
	$(ROMFSINST) $(NEC_COMMON)/rc /etc/rc
	$(ROMFSINST) /etc/inittab
	$(ROMFSINST) ../../Generic/romfs/etc/services /etc/services
	$(ROMFSINST) $(NEC_COMMON)/v850e/motd /etc/motd
	$(ROMFSINST) $(NEC_COMMON)/passwd /etc/passwd
	$(ROMFSINST) ../../Generic/httpd /home/httpd
	echo "$(VERSIONSTR) -- " `date` > $(ROMFSDIR)/etc/version

image:
	[ -d $(IMAGEDIR) ] || mkdir -p $(IMAGEDIR)
	genromfs -v -x ramfs.img -V "ROMdisk" -f $(ROMFSIMG) -d $(ROMFSDIR)
	 # Relink the kernel with the root file system embedded in the image.
	$(MAKE) -C $(ROOTDIR)/$(LINUXDIR) LINUX=$(IMAGE) BLKMEM0_IMAGE=$(ROMFSIMG)
