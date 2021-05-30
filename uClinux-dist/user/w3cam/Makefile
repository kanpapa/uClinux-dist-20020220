# Generated automatically from Makefile.in by configure.
prefix=/usr/local
exec_prefix=${prefix}
sbindir=${exec_prefix}/sbin
cgibindir=$(prefix)/cgi-bin
bindir=${exec_prefix}/bin

VERSION=0.6.6
CFLAGS = -g -O2 -I/usr/local/include -I/usr/local/X11/include  -DHAVE_LIBM=1 -DHAVE_LIBZ=1 -DHAVE_LIBPNG=1 -DHAVE_LIBJPEG=1 -DHAVE_LIBTTF=1  -DVIDEO_DEV=\"/dev/video0\" -DVERSION=\"$(VERSION)\"
LDFLAGS =  -L/usr/local/lib -L/usr/local/X11/lib
LIBS = -lttf -ljpeg -lpng -lz -lm 

OBJ = w3cam.o cgi.o

default: w3cam.cgi vidcat README ppmtoascii w3camd/w3camd

w3cam.cgi: $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $(OBJ) $(LIBS)

vidcat: vidcat.o
	$(CC) $(LDFLAGS) -o $@ vidcat.o $(LIBS)

ppmtoascii: ppmtoascii.o
	$(CC) $(LDFLAGS) -o $@ ppmtoascii.o

w3camd/w3camd:
	cd w3camd && make

install: w3cam.cgi
	install w3cam.cgi $(cgibindir)/
	test -f $(cgibindir)/w3cam.cgi.scf || \
		install w3cam.cgi.scf $(cgibindir)/
	install vidcat $(bindir)/

clean:
	rm -f *.o w3cam.cgi vidcat ppmtoascii
	cd w3camd && make clean && rm -f w3camd

msproper: clean
	rm -f config.status config.log config.cache

index.html: index.in
	sed "s/@VERSION@/$(VERSION)/" < $< > $@

README: index.html
	lynx -dump http://www/~rasca/w3cam/index.html | \
		sed "s%/www/%/home.pages.de/%g" > README

tarball: clean
	rm -f config.status config.log config.cache Makefile
	cd .. && tar -czvf w3cam-$(VERSION).tar.gz w3cam/

