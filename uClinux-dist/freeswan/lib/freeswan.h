#ifndef _FREESWAN_H
/*
 * header file for FreeS/WAN library functions
 * Copyright (C) 1998, 1999, 2000  Henry Spencer.
 * Copyright (C) 1999, 2000, 2001  Richard Guy Briggs
 * 
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Library General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/lgpl.txt>.
 * 
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Library General Public
 * License for more details.
 *
 * RCSID $Id: freeswan.h,v 1.53 2001/06/14 19:35:15 rgb Exp $
 */
#define	_FREESWAN_H	/* seen it, no need to see it again */



/*
 * First, assorted kernel-version-dependent trickery.
 */
#include <linux/version.h>
#ifndef KERNEL_VERSION
#define KERNEL_VERSION(x,y,z) (((x)<<16)+((y)<<8)+(z))
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,1,0)
#define HEADER_CACHE_BIND_21
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,1,0)
#define SPINLOCK
#  if LINUX_VERSION_CODE >= KERNEL_VERSION(2,3,0)
#  define SPINLOCK_23
#  endif
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,3,25)
#define PROC_FS_2325
#else
#  if LINUX_VERSION_CODE >= KERNEL_VERSION(2,1,0)
#  define PROC_FS_21
#  endif
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,3,0)
#define NETDEV_23
#  ifndef CONFIG_IP_ALIAS
#  define CONFIG_IP_ALIAS
#  endif
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,1,0)
#define NETLINK_SOCK
#define NET_21
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,3,30)
#define PROC_NO_DUMMY
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,3,35)
#define SKB_COPY_EXPAND
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,3,37)
#define IP_SELECT_IDENT
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,4)
#define IP_SELECT_IDENT_NEW
#define IPH_is_SKB_PULLED
#define SKB_COW_NEW
#else /* LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,4) */
#  ifdef REDHAT_BOGOSITY
#  define IP_SELECT_IDENT_NEW
#  define IPH_is_SKB_PULLED
#  define SKB_COW_NEW
#  endif /* REDHAT_BOGOSITY */
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,4) */

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,3,50)) && defined(CONFIG_NETFILTER)
#define SKB_RESET_NFCT
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,1,19)
#define net_device_stats enet_statistics
#endif                                                                         



/*
 * We've just got to have some datatypes defined...  And annoyingly, just
 * where we get them depends on whether we're in userland or not.
 */
#ifdef __KERNEL__

#  include <linux/types.h>
#  include <linux/in.h>

#  ifdef NET_21
#    include <linux/in6.h>
#  else
     /* old kernel in.h has some IPv6 stuff, but not quite enough */
#    define	s6_addr16	s6_addr
#    define	AF_INET6	10
#    define uint8_t __u8
#    define uint16_t __u16 
#    define uint32_t __u32 
#    define uint64_t __u64 
#  endif

#  ifndef SPINLOCK
#    include <linux/bios32.h>
     /* simulate spin locks and read/write locks */
     typedef struct {
       volatile char lock;
     } spinlock_t;

     typedef struct {
       volatile unsigned int lock;
     } rwlock_t;                                                                     

#    define spin_lock_init(x) { (x)->lock = 0;}
#    define rw_lock_init(x) { (x)->lock = 0; }

#    define spin_lock(x) { while ((x)->lock) barrier(); (x)->lock=1;}
#    define spin_lock_irq(x) { cli(); spin_lock(x);}
#    define spin_lock_irqsave(x,flags) { save_flags(flags); spin_lock_irq(x);}

#    define spin_unlock(x) { (x)->lock=0;}
#    define spin_unlock_irq(x) { spin_unlock(x); sti();}
#    define spin_unlock_irqrestore(x,flags) { spin_unlock(x); restore_flags(flags);}

#    define read_lock(x) spin_lock(x)
#    define read_lock_irq(x) spin_lock_irq(x)
#    define read_lock_irqsave(x,flags) spin_lock_irqsave(x,flags)

#    define read_unlock(x) spin_unlock(x)
#    define read_unlock_irq(x) spin_unlock_irq(x)
#    define read_unlock_irqrestore(x,flags) spin_unlock_irqrestore(x,flags)

#    define write_lock(x) spin_lock(x)
#    define write_lock_irq(x) spin_lock_irq(x)
#    define write_lock_irqsave(x,flags) spin_lock_irqsave(x,flags)

#    define write_unlock(x) spin_unlock(x)
#    define write_unlock_irq(x) spin_unlock_irq(x)
#    define write_unlock_irqrestore(x,flags) spin_unlock_irqrestore(x,flags)
#  endif /* !SPINLOCK */

#  ifndef SPINLOCK_23
#    define spin_lock_bh(x)  spin_lock_irq(x)
#    define spin_unlock_bh(x)  spin_unlock_irq(x)

#    define read_lock_bh(x)  read_lock_irq(x)
#    define read_unlock_bh(x)  read_unlock_irq(x)

#    define write_lock_bh(x)  write_lock_irq(x)
#    define write_unlock_bh(x)  write_unlock_irq(x)
#  endif /* !SPINLOCK_23 */

#ifndef IPPROTO_COMP
#define IPPROTO_COMP 108
#endif /* !IPPROTO_COMP */

#ifndef IPPROTO_INT
#define IPPROTO_INT 61
#endif /* !IPPROTO_INT */

#ifdef CONFIG_IPSEC_DEBUG
#define DEBUG_NO_STATIC
#else /* CONFIG_IPSEC_DEBUG */
#define DEBUG_NO_STATIC static
#endif /* CONFIG_IPSEC_DEBUG */

#else /* __KERNEL__ */

#  include <stdio.h>
#  include <netinet/in.h>

#  define uint8_t u_int8_t
#  define uint16_t u_int16_t 
#  define uint32_t u_int32_t 
#  define uint64_t u_int64_t 

#define DEBUG_NO_STATIC static

#endif /* __KERNEL__ */



/*
 * Basic data types for the address-handling functions.
 * ip_address and ip_subnet are supposed to be opaque types; do not
 * use their definitions directly, they are subject to change!
 */

/* first, some quick fakes in case we're on an old system with no IPv6 */
#ifndef __KERNEL__
#ifndef IN6ADDR_ANY_INIT
struct in6_addr {
	unsigned char s6_addr16[16];
};
#endif	/* !IN6ADDR_ANY_INIT */

#if !defined(IN6ADDR_ANY_INIT) && LINUX_VERSION_CODE >= KERNEL_VERSION(2,1,0)
struct sockaddr_in6 {
	unsigned short sin6_family;
	unsigned short sin6_port;
	unsigned long sin6_flowinfo;
	struct {
		unsigned char s6_addr16[16];
	} sin6_addr;
};
#endif	/* !IN6ADDR_ANY_INIT */

#ifndef AF_INET6
# define	AF_INET6	10 /* 2.0 systemdon't have this one */
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,1,0)
# define s6_addr16 s6_addr
# define gethostbyname2(x,y) ((y == AF_INET) ? gethostbyname(x) : 0)
#endif

#endif	/* !__KERNEL__ */

/* then the main types */
typedef struct {
	union {
		struct sockaddr_in v4;
		struct sockaddr_in6 v6;
	} u;
} ip_address;
typedef struct {
	ip_address addr;
	int maskbits;
} ip_subnet;

/* and the SA ID stuff */
#ifdef __KERNEL__
typedef __u32 ipsec_spi_t;
#else
typedef u_int32_t ipsec_spi_t;
#endif
typedef struct {		/* to identify an SA, we need: */
        ip_address dst;		/* A. destination host */
        ipsec_spi_t spi;	/* B. 32-bit SPI, assigned by dest. host */
#		define	SPI_PASS	256	/* magic values... */
#		define	SPI_DROP	257	/* ...for use... */
#		define	SPI_REJECT	258	/* ...with SA_INT */
#		define	SPI_HOLD	259
#		define	SPI_TRAP	260
	int proto;		/* C. protocol */
#		define	SA_ESP	50	/* IPPROTO_ESP */
#		define	SA_AH	51	/* IPPROTO_AH */
#		define	SA_IPIP	4	/* IPPROTO_IPIP */
#		define	SA_COMP	108	/* IPPROTO_COMP */
#		define	SA_INT	61	/* IANA reserved for internal use */
} ip_said;
struct sa_id {			/* old v4-only version */
        struct in_addr dst;
        ipsec_spi_t spi;
	int proto;
};

/* misc */
typedef const char *err_t;	/* error message, or NULL for success */



/*
 * new IPv6-compatible functions
 */

/* text conversions */
err_t ttoul(const char *src, size_t srclen, int format, unsigned long *dst);
size_t ultot(unsigned long src, int format, char *buf, size_t buflen);
#define	ULTOT_BUF	(22+1)	/* holds 64 bits in octal */
err_t ttoaddr(const char *src, size_t srclen, int af, ip_address *dst);
err_t tnatoaddr(const char *src, size_t srclen, int af, ip_address *dst);
size_t addrtot(const ip_address *src, int format, char *buf, size_t buflen);
/* RFC 1886 old IPv6 reverse-lookup format is the bulkiest */
#define	ADDRTOT_BUF	(32*2 + 3 + 1 + 3 + 1 + 1)
err_t ttosubnet(const char *src, size_t srclen, int af, ip_subnet *dst);
size_t subnettot(const ip_subnet *src, int format, char *buf, size_t buflen);
#define	SUBNETTOT_BUF	(ADDRTOT_BUF + 1 + 3)
err_t ttosa(const char *src, size_t srclen, ip_said *dst);
size_t satot(const ip_said *src, int format, char *bufptr, size_t buflen);
#define	SATOT_BUF	(5 + ULTOA_BUF + 1 + ADDRTOT_BUF)
err_t ttodata(const char *src, size_t srclen, int base, char *buf,
						size_t buflen, size_t *needed);
size_t datatot(const char *src, size_t srclen, int format, char *buf,
								size_t buflen);

/* initializations */
void initsaid(const ip_address *addr, ipsec_spi_t spi, int proto, ip_said *dst);
err_t loopbackaddr(int af, ip_address *dst);
err_t unspecaddr(int af, ip_address *dst);
err_t anyaddr(int af, ip_address *dst);
err_t initaddr(const unsigned char *src, size_t srclen, int af, ip_address *dst);
err_t initsubnet(const ip_address *addr, int maskbits, int clash, ip_subnet *dst);

/* misc. conversions and related */
err_t rangetosubnet(const ip_address *from, const ip_address *to, ip_subnet *dst);
int addrtypeof(const ip_address *src);
int subnettypeof(const ip_subnet *src);
size_t addrlenof(const ip_address *src);
size_t addrbytesptr(const ip_address *src, const unsigned char **dst);
size_t addrbytesof(const ip_address *src, unsigned char *dst, size_t dstlen);
int masktocount(const ip_address *src);
void networkof(const ip_subnet *src, ip_address *dst);
void maskof(const ip_subnet *src, ip_address *dst);

/* tests */
int sameaddr(const ip_address *a, const ip_address *b);
int addrcmp(const ip_address *a, const ip_address *b);
int samesubnet(const ip_subnet *a, const ip_subnet *b);
int addrinsubnet(const ip_address *a, const ip_subnet *s);
int subnetinsubnet(const ip_subnet *a, const ip_subnet *b);
int subnetishost(const ip_subnet *s);
int samesaid(const ip_said *a, const ip_said *b);
int sameaddrtype(const ip_address *a, const ip_address *b);
int samesubnettype(const ip_subnet *a, const ip_subnet *b);
int isanyaddr(const ip_address *src);
int isunspecaddr(const ip_address *src);
int isloopbackaddr(const ip_address *src);

/* low-level grot */
int portof(const ip_address *src);
void setportof(int port, ip_address *dst);
struct sockaddr *sockaddrof(ip_address *src);
size_t sockaddrlenof(const ip_address *src);



/*
 * old functions, to be deleted eventually
 */

/* unsigned long */
const char *			/* NULL for success, else string literal */
atoul(
	const char *src,
	size_t srclen,		/* 0 means strlen(src) */
	int base,		/* 0 means figure it out */
	unsigned long *resultp
);
size_t				/* space needed for full conversion */
ultoa(
	unsigned long n,
	int base,
	char *dst,
	size_t dstlen
);
#define	ULTOA_BUF	21	/* just large enough for largest result, */
				/* assuming 64-bit unsigned long! */

/* Internet addresses */
const char *			/* NULL for success, else string literal */
atoaddr(
	const char *src,
	size_t srclen,		/* 0 means strlen(src) */
	struct in_addr *addr
);
size_t				/* space needed for full conversion */
addrtoa(
	struct in_addr addr,
	int format,		/* character; 0 means default */
	char *dst,
	size_t dstlen
);
#define	ADDRTOA_BUF	16	/* just large enough for largest result */

/* subnets */
const char *			/* NULL for success, else string literal */
atosubnet(
	const char *src,
	size_t srclen,		/* 0 means strlen(src) */
	struct in_addr *addr,
	struct in_addr *mask
);
size_t				/* space needed for full conversion */
subnettoa(
	struct in_addr addr,
	struct in_addr mask,
	int format,		/* character; 0 means default */
	char *dst,
	size_t dstlen
);
#define	SUBNETTOA_BUF	32	/* large enough for worst case result */

/* ranges */
const char *			/* NULL for success, else string literal */
atoasr(
	const char *src,
	size_t srclen,		/* 0 means strlen(src) */
	char *type,		/* 'a', 's', 'r' */
	struct in_addr *addrs	/* two-element array */
);
size_t				/* space needed for full conversion */
rangetoa(
	struct in_addr *addrs,	/* two-element array */
	int format,		/* character; 0 means default */
	char *dst,
	size_t dstlen
);
#define	RANGETOA_BUF	34	/* large enough for worst case result */

/* data types for SA conversion functions */

/* SAs */
const char *			/* NULL for success, else string literal */
atosa(
	const char *src,
	size_t srclen,		/* 0 means strlen(src) */
	struct sa_id *sa
);
size_t				/* space needed for full conversion */
satoa(
	struct sa_id sa,
	int format,		/* character; 0 means default */
	char *dst,
	size_t dstlen
);
#define	SATOA_BUF	(3+ULTOA_BUF+ADDRTOA_BUF)

/* generic data, e.g. keys */
const char *			/* NULL for success, else string literal */
atobytes(
	const char *src,
	size_t srclen,		/* 0 means strlen(src) */
	char *dst,
	size_t dstlen,
	size_t *lenp		/* NULL means don't bother telling me */
);
size_t				/* 0 failure, else true size */
bytestoa(
	const char *src,
	size_t srclen,
	int format,		/* character; 0 means default */
	char *dst,
	size_t dstlen
);

/* old versions of generic-data functions; deprecated */
size_t				/* 0 failure, else true size */
atodata(
	const char *src,
	size_t srclen,		/* 0 means strlen(src) */
	char *dst,
	size_t dstlen
);
size_t				/* 0 failure, else true size */
datatoa(
	const char *src,
	size_t srclen,
	int format,		/* character; 0 means default */
	char *dst,
	size_t dstlen
);

/* part extraction and special addresses */
struct in_addr
subnetof(
	struct in_addr addr,
	struct in_addr mask
);
struct in_addr
hostof(
	struct in_addr addr,
	struct in_addr mask
);
struct in_addr
broadcastof(
	struct in_addr addr,
	struct in_addr mask
);

/* mask handling */
int
goodmask(
	struct in_addr mask
);
int
masktobits(
	struct in_addr mask
);
struct in_addr
bitstomask(
	int n
);



/*
 * general utilities
 */

#ifndef __KERNEL__
/* option pickup from files (userland only because of use of FILE) */
const char *optionsfrom(const char *filename, int *argcp, char ***argvp,
						int optind, FILE *errorreport);
#endif



#endif /* _FREESWAN_H */
