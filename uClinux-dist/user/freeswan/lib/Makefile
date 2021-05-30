
OBJS=addrtoa.o addrtot.o addrtypeof.o anyaddr.o atoaddr.o \
	atoasr.o atosa.o atosubnet.o atoul.o datatot.o \
	goodmask.o initaddr.o initsaid.o initsubnet.o \
	optionsfrom.o pfkey_v2_build.o pfkey_v2_ext_bits.o pfkey_v2_parse.o \
	portof.o rangetoa.o rangetosubnet.o sameaddr.o \
	satoa.o satot.o subnetof.o subnettoa.o subnettot.o \
	subnettypeof.o ttoaddr.o ttodata.o \
	ttosa.o ttosubnet.o ttoul.o ultoa.o ultot.o
LIB=libfreeswan.a

CFLAGS+= -Wall
#CFLAGS+= -Wconversion
#CFLAGS+= -Wmissing-prototypes
#CFLAGS+= -Wpointer-arith
#CFLAGS+= -Wcast-qual
#CFLAGS+= -Wmissing-declarations
CFLAGS+= -Wstrict-prototypes
#CFLAGS+= -pedantic
#CFLAGS+= -O3
#CFLAGS+= -W
#CFLAGS+= -Wwrite-strings
#CFLAGS+= -Wbad-function-cast 

CFLAGS += -I$(ROOTDIR)/freeswan/lib
CFLAGS += -I$(ROOTDIR)/freeswan/libdes
CFLAGS += -I$(ROOTDIR)/lib/libgmp

vpath %.c $(ROOTDIR)/freeswan/lib

ARFLAGS=crvs

all: $(LIB)

$(LIB):	$(OBJS)
	ar $(ARFLAGS) $(LIB) $(OBJS)
	$(RANLIB) $(LIB)

$(OBJS): $(HDRS)

romfs:

clean:
	rm -f $(LIB) *.o try* core *.core

