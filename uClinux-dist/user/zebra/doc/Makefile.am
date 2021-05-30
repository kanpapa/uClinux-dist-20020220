## Process this file with automake to produce Makefile.in.

info_TEXINFOS = zebra.texi
EXTRA_DIST = BGP-TypeCode draft-zebra-00.txt bgpd.1 ospf6d.1 ospfd.1 \
	ripd.1 ripngd.1 zebra.1

draft-zebra-00.txt:
	groff -T ascii -ms draft-zebra-00.ms > draft-zebra-00.txt
