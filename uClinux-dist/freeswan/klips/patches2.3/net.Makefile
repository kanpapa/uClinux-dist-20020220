RCSID $Id: net.Makefile,v 1.4 2001/01/29 22:20:18 rgb Exp $
--- ./net/Makefile.preipsec	Tue Jun 20 17:32:27 2000
+++ ./net/Makefile	Fri Jun 30 14:44:38 2000
@@ -44,6 +44,7 @@
 subdir-$(CONFIG_ATM)		+= atm
 subdir-$(CONFIG_DECNET)		+= decnet
 subdir-$(CONFIG_ECONET)		+= econet
+subdir-$(CONFIG_IPSEC)		+= ipsec
 
 
 obj-y	:= socket.o $(join $(subdir-y), $(patsubst %,/%.o,$(notdir $(subdir-y)))) 
