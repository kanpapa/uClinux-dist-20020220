# Makefile to generate various formats from HTML source
#
# Assumes the htmldoc utility is available.
# This can be downloaded from www.easysw.com
#
# Also needs lynx(1) for HTML-to-text conversion

# Set depth for table of contents generation
# L="--toclevel 4"

# source files in subdirectory
sections=src/intro.html src/install.html src/config.html src/manpages.html \
	src/firewall.html src/trouble.html src/kernel.html src/roadmap.html \
	src/compat.html src/interop.html src/politics.html src/ipsec.html \
	src/mail.html src/web.html src/glossary.html src/biblio.html \
	src/rfc.html src/faq.html src/performance.html

# separate HTML files built in current directory
separate=intro.html install.html config.html manpages.html \
	firewall.html trouble.html kernel.html roadmap.html \
	compat.html interop.html politics.html ipsec.html \
	mail.html performance.html web.html glossary.html biblio.html \
	rfc.html faq.html

# various one-big-file formats
howto=HowTo.html HowTo.ps HowTo.pdf HowTo.txt

# where are scripts
SCRIPTDIR=utils

# where do we put HTML manpages?
HMANDIR=manpage.d

# which sort of manpage conversion do we do?
MCT=$(test " `which man2html`" != " /usr/bin/man2html" && echo .old)

# default, build HTML only
# dependencies build most of it
# then we add index
index.html: toc.html HowTo.html manpages src/index.html
	cp src/index.html index.html

# separate files plus table of contents
toc.html : $(sections)
	htmldoc -t html -d .  $(sections)
	# remove HTML formatting added by htmldoc
	$(SCRIPTDIR)/cleanhtml.sh $(SCRIPTDIR)/cleanhtml.sed $(separate)

# one big HTML file
HowTo.html : $(sections)
	htmldoc -t html -f $@ $(sections)

# other HowTo formats
HowTo.txt: HowTo.html
	lynx -dump $< > $@

HowTo.ps : $(sections)
	htmldoc -f $@ $(sections)

HowTo.pdf : $(sections)
	htmldoc -f $@ $(sections)

manpages:	manp$(MCT)

manp:	$(SCRIPTDIR)/mkhtmlman
	$(SCRIPTDIR)/mkhtmlman $(HMANDIR) `find .. -type f -name '*.[1-8]'`

manp.old:	$(SCRIPTDIR)/man_xref
	$(SCRIPTDIR)/man2html.script /usr/local/man $(HMANDIR)

all: $(howto) $(manpages) index.html

clean:
	rm -f $(howto) $(separate) toc.html index.html
	rm -rf $(HMANDIR)
