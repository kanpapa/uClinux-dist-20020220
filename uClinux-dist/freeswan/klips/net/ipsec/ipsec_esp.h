/*
 * Copyright (C) 1996, 1997  John Ioannidis.
 * Copyright (C) 1998, 1999, 2000, 2001  Richard Guy Briggs.
 * 
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 * 
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 * RCSID $Id: ipsec_esp.h,v 1.14 2001/06/14 19:35:08 rgb Exp $
 */

#include "ipsec_md5h.h"
#include "ipsec_sha1.h"

#ifndef IPPROTO_ESP
#define IPPROTO_ESP 50
#endif /* IPPROTO_ESP */

#define EMT_ESPDESCBC_ULEN	20	/* coming from user mode */
#define EMT_ESPDES_KMAX		64	/* 512 bit secret key enough? */
#define EMT_ESPDES_KEY_SZ	8	/* 56 bit secret key with parity = 64 bits */
#define EMT_ESP3DES_KEY_SZ	24	/* 168 bit secret key with parity = 192 bits */
#define EMT_ESPDES_IV_SZ	8	/* IV size */
#define ESP_DESCBC_BLKLEN       8       /* DES-CBC block size */

#define DB_ES_PKTRX	0x0001
#define DB_ES_PKTRX2	0x0002
#define DB_ES_TDB	0x0010
#define DB_ES_XF	0x0020
#define DB_ES_IPAD	0x0040
#define DB_ES_INAU	0x0080
#define DB_ES_OINFO	0x0100
#define DB_ES_OINFO2	0x0200
#define DB_ES_OH	0x0400
#define DB_ES_REPLAY	0x0800

struct espblkrply_edata
{
	__u16	eme_klen;		/* encryption key length */
	__u16	ame_klen;		/* authentication key length */
	__u16	eme_flags;		/* see below */
	__u16	eme_ooowin;		/* out-of-order window size */
#if 1
	__u16	eme_ivlen;		/* IV length */
	__u16	filler;
	union
	{
		__u8	Iv[8];		/* that's enough space */
		__u32	Ivl[2];
		__u64	Ivq;
	}Iu;
#define eme_iv	Iu.Iv
#define eme_ivl Iu.Ivl
#define eme_ivq Iu.Ivq
#endif
	__u8	eme_key[EMT_ESPDES_KMAX]; /* the encryption raw key */
	__u8	ame_key[AH_AMAX];	/* the authentication raw key */
};

#ifdef __KERNEL__
struct espdesmd5_xdata
{
        __u8    edmx_flags;             /* same as before */
        __u8    edmx_ooowin;            /* out-of-order window size */
        __u16   edmx_ivlen;             /* IV length */
        __u32   edmx_bitmap;            /* this&next should be 4 bytes each */
        __u32   edmx_lastseq;           /* in host order */
        __u32   edmx_eks[16][2];        /* the key schedule */
        __u32   edmx_iv[2];             /* constant IV */
        MD5_CTX edmx_ictx;              /* derived from HMAC_key */
        MD5_CTX edmx_octx;              /* ditto */
};

struct esp3desmd5_xdata
{
	__u8	edmx_flags;		/* same as before */
	__u8	edmx_ooowin;		/* out-of-order window size */
	__u16	edmx_ivlen;		/* IV length */
	__u32	edmx_bitmap;		/* this&next should be 4 bytes each */
	__u32	edmx_lastseq;		/* in host order */
	__u32	edmx_eks1[16][2];	/* the first key schedule */
	__u32	edmx_eks2[16][2];	/* the second key schedule */
	__u32	edmx_eks3[16][2];	/* the third key schedule */
	__u32	edmx_iv[2];		/* constant IV */
	MD5_CTX edmx_ictx;		/* derived from HMAC_key */
	MD5_CTX edmx_octx;		/* ditto */
};

struct espnullmd5_xdata
{
	__u8	edmx_flags;		/* same as before */
	__u8	edmx_ooowin;		/* out-of-order window size */
	__u32	edmx_bitmap;		/* this&next should be 4 bytes each */
	__u32	edmx_lastseq;		/* in host order */
	MD5_CTX edmx_ictx;		/* derived from HMAC_key */
	MD5_CTX edmx_octx;		/* ditto */
};

struct espdessha1_xdata
{
        __u8    edmx_flags;             /* same as before */
        __u8    edmx_ooowin;            /* out-of-order window size */
        __u16   edmx_ivlen;             /* IV length */
        __u32   edmx_bitmap;            /* this&next should be 4 bytes each */
        __u32   edmx_lastseq;           /* in host order */
        __u32   edmx_eks[16][2];        /* the key schedule */
        __u32   edmx_iv[2];             /* constant IV */
        SHA1_CTX edmx_ictx;             /* derived from HMAC_key */
        SHA1_CTX edmx_octx;             /* ditto */
};

struct esp3dessha1_xdata
{
	__u8	edmx_flags;		/* same as before */
	__u8	edmx_ooowin;		/* out-of-order window size */
	__u16	edmx_ivlen;		/* IV length */
	__u32	edmx_bitmap;		/* this&next should be 4 bytes each */
	__u32	edmx_lastseq;		/* in host order */
	__u32	edmx_eks1[16][2];	/* the first key schedule */
	__u32	edmx_eks2[16][2];	/* the second key schedule */
	__u32	edmx_eks3[16][2];	/* the third key schedule */
	__u32	edmx_iv[2];		/* constant IV */
	SHA1_CTX edmx_ictx;		/* derived from HMAC_key */
	SHA1_CTX edmx_octx;		/* ditto */
};

struct espnullsha1_xdata
{
	__u8	edmx_flags;		/* same as before */
	__u8	edmx_ooowin;		/* out-of-order window size */
	__u32	edmx_bitmap;		/* this&next should be 4 bytes each */
	__u32	edmx_lastseq;		/* in host order */
	SHA1_CTX edmx_ictx;		/* derived from HMAC_key */
	SHA1_CTX edmx_octx;		/* ditto */
};

struct espdes_xdata
{
        __u8    edmx_flags;             /* same as before */
        __u8    edmx_ooowin;            /* out-of-order window size */
        __u16   edmx_ivlen;             /* IV length */
        __u32   edmx_bitmap;            /* this&next should be 4 bytes each */
        __u32   edmx_lastseq;           /* in host order */
        __u32   edmx_eks[16][2];        /* the key schedule */
        __u32   edmx_iv[2];             /* constant IV */
};

struct esp3des_xdata
{
	__u8	edmx_flags;		/* same as before */
	__u8	edmx_ooowin;		/* out-of-order window size */
	__u16	edmx_ivlen;		/* IV length */
	__u32	edmx_bitmap;		/* this&next should be 4 bytes each */
	__u32	edmx_lastseq;		/* in host order */
	__u32	edmx_eks1[16][2];	/* the first key schedule */
	__u32	edmx_eks2[16][2];	/* the second key schedule */
	__u32	edmx_eks3[16][2];	/* the third key schedule */
	__u32	edmx_iv[2];		/* constant IV */
};

struct des_eks {
	__u32	eks[16][2];	/* the key schedule */
};

extern struct inet_protocol esp_protocol;

struct options;

extern int
esp_rcv(struct sk_buff *skb,
	struct device *dev,
	struct options *opt, 
	__u32 daddr,
	unsigned short len,
	__u32 saddr,
	int redo,
	struct inet_protocol *protocol);

struct esp
{
	__u32	esp_spi;		/* Security Parameters Index */
        __u32   esp_rpl;                /* Replay counter */
	__u8	esp_iv[8];		/* iv */
};

#ifdef CONFIG_IPSEC_DEBUG
extern int debug_esp;
#endif /* CONFIG_IPSEC_DEBUG */
#endif /* __KERNEL__ */

#ifdef CONFIG_IPSEC_DEBUG
#define ESPPRINTKEYS_
#endif /* CONFIG_IPSEC_DEBUG */

/*
 * $Log: ipsec_esp.h,v $
 * Revision 1.14  2001/06/14 19:35:08  rgb
 * Update copyright date.
 *
 * Revision 1.13  2000/09/08 19:12:56  rgb
 * Change references from DEBUG_IPSEC to CONFIG_IPSEC_DEBUG.
 *
 * Revision 1.12  2000/08/01 14:51:50  rgb
 * Removed _all_ remaining traces of DES.
 *
 * Revision 1.11  2000/01/10 16:36:20  rgb
 * Ditch last of EME option flags, including initiator.
 *
 * Revision 1.10  1999/12/07 18:16:22  rgb
 * Fixed comments at end of #endif lines.
 *
 * Revision 1.9  1999/04/11 00:28:57  henry
 * GPL boilerplate
 *
 * Revision 1.8  1999/04/06 04:54:25  rgb
 * Fix/Add RCSID Id: and Log: bits to make PHMDs happy.  This includes
 * patch shell fixes.
 *
 * Revision 1.7  1999/01/26 02:06:00  rgb
 * Removed CONFIG_IPSEC_ALGO_SWITCH macro.
 *
 * Revision 1.6  1999/01/22 15:22:05  rgb
 * Re-enable IV in the espblkrply_edata structure to avoid breaking pluto
 * until pluto can be fixed properly.
 *
 * Revision 1.5  1999/01/22 06:18:16  rgb
 * Updated macro comments.
 * Added key schedule types to support algorithm switch code.
 *
 * Revision 1.4  1998/08/12 00:07:32  rgb
 * Added data structures for new xforms: null, {,3}dessha1.
 *
 * Revision 1.3  1998/07/14 15:57:01  rgb
 * Add #ifdef __KERNEL__ to protect kernel-only structures.
 *
 * Revision 1.2  1998/06/25 19:33:46  rgb
 * Add prototype for protocol receive function.
 * Rearrange for more logical layout.
 *
 * Revision 1.1  1998/06/18 21:27:45  henry
 * move sources from klips/src to klips/net/ipsec, to keep stupid
 * kernel-build scripts happier in the presence of symlinks
 *
 * Revision 1.6  1998/06/05 02:28:08  rgb
 * Minor comment fix.
 *
 * Revision 1.5  1998/05/27 22:34:00  rgb
 * Changed structures to accomodate key separation.
 *
 * Revision 1.4  1998/05/18 22:28:43  rgb
 * Disable key printing facilities from /proc/net/ipsec_*.
 *
 * Revision 1.3  1998/04/21 21:29:07  rgb
 * Rearrange debug switches to change on the fly debug output from user
 * space.  Only kernel changes checked in at this time.  radij.c was also
 * changed to temporarily remove buggy debugging code in rj_delete causing
 * an OOPS and hence, netlink device open errors.
 *
 * Revision 1.2  1998/04/12 22:03:20  rgb
 * Updated ESP-3DES-HMAC-MD5-96,
 * 	ESP-DES-HMAC-MD5-96,
 * 	AH-HMAC-MD5-96,
 * 	AH-HMAC-SHA1-96 since Henry started freeswan cvs repository
 * from old standards (RFC182[5-9] to new (as of March 1998) drafts.
 *
 * Fixed eroute references in /proc/net/ipsec*.
 *
 * Started to patch module unloading memory leaks in ipsec_netlink and
 * radij tree unloading.
 *
 * Revision 1.1  1998/04/09 03:06:00  henry
 * sources moved up from linux/net/ipsec
 *
 * Revision 1.1.1.1  1998/04/08 05:35:02  henry
 * RGB's ipsec-0.8pre2.tar.gz ipsec-0.8
 *
 * Revision 0.5  1997/06/03 04:24:48  ji
 * Added ESP-3DES-MD5-96 transform.
 *
 * Revision 0.4  1997/01/15 01:28:15  ji
 * Added definitions for new ESP transforms.
 *
 * Revision 0.3  1996/11/20 14:35:48  ji
 * Minor Cleanup.
 * Rationalized debugging code.
 *
 * Revision 0.2  1996/11/02 00:18:33  ji
 * First limited release.
 *
 *
 */
