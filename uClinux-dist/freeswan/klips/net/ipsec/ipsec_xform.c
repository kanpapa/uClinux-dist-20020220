/*
 * Common routines for IPSEC transformations.
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
 * RCSID $Id: ipsec_xform.c,v 1.52 2001/06/14 19:35:11 rgb Exp $
 */

#include <linux/config.h>
#include <linux/version.h>

#include <linux/kernel.h> /* printk() */
#include <linux/malloc.h> /* kmalloc() */
#include <linux/errno.h>  /* error codes */
#include <linux/types.h>  /* size_t */
#include <linux/interrupt.h> /* mark_bh */

#include <linux/netdevice.h>   /* struct device, and other headers */
#include <linux/etherdevice.h> /* eth_type_trans */
#include <linux/ip.h>          /* struct iphdr */
#include <linux/skbuff.h>
#include <linux/random.h>	/* get_random_bytes() */
#include <freeswan.h>
#ifdef SPINLOCK
#ifdef SPINLOCK_23
#include <linux/spinlock.h> /* *lock* */
#else /* SPINLOCK_23 */
#include <asm/spinlock.h> /* *lock* */
#endif /* SPINLOCK_23 */
#endif /* SPINLOCK */
#ifdef NET_21
#include <asm/uaccess.h>
#include <linux/in6.h>
#endif
#include <asm/checksum.h>
#include <net/ip.h>

#include "radij.h"
#include "ipsec_encap.h"
#include "ipsec_radij.h"
#include "ipsec_netlink.h"
#include "ipsec_xform.h"
#include "ipsec_ipe4.h"
#include "ipsec_ah.h"
#include "ipsec_esp.h"

#include <pfkeyv2.h>
#include <pfkey.h>

#ifdef CONFIG_IPSEC_DEBUG
int debug_xform = 0;
#endif /* CONFIG_IPSEC_DEBUG */

#define SENDERR(_x) do { error = -(_x); goto errlab; } while (0)

extern int des_set_key(caddr_t, caddr_t);

struct xformsw xformsw[] = {
{ XF_IP4,		0,		"IPv4_Encapsulation"},
{ XF_AHHMACMD5,		XFT_AUTH,	"HMAC_MD5_Authentication"},
{ XF_AHHMACSHA1,	XFT_AUTH,	"HMAC_SHA-1_Authentication"},
{ XF_ESPDES,		XFT_CONF,	"DES_Encryption"},
{ XF_ESPDESMD596,	XFT_CONF,	"DES-MD5-96_Encryption"},
{ XF_ESPDESSHA196,	XFT_CONF,	"DES-SHA1-96_Encryption"},
{ XF_ESP3DES,		XFT_CONF,	"3DES_Encryption"},
{ XF_ESP3DESMD596,	XFT_CONF,	"3DES-MD5-96_Encryption"},
{ XF_ESP3DESSHA196,	XFT_CONF,	"3DES-SHA1-96_Encryption"},
{ XF_ESPNULLMD596,	XFT_CONF,	"NULL-MD5-96_ESP_*Plaintext*"},
{ XF_ESPNULLSHA196,	XFT_CONF,	"NULL-SHA1-96_ESP_*Plaintext*"},
};

struct tdb *tdbh[TDB_HASHMOD];
#ifdef SPINLOCK
spinlock_t tdb_lock = SPIN_LOCK_UNLOCKED;
#else /* SPINLOCK */
spinlock_t tdb_lock;
#endif /* SPINLOCK */
struct xformsw *xformswNXFORMSW = &xformsw[sizeof(xformsw)/sizeof(xformsw[0])];

int
ipsec_tdbinit(void)
{
	int i;

	for(i = 1; i < TDB_HASHMOD; i++) {
		tdbh[i] = NULL;
	}
	return 0;
}

struct tdb *
gettdb(struct sa_id *said)
{
	int hashval;
	struct tdb *tdbp;
        char sa[SATOA_BUF];
	size_t sa_len;

	if(!said) {
		KLIPS_PRINT(debug_xform,
			    "klips_error:gettdb: "
			    "null pointer passed in!\n");
		return NULL;
	}

	sa_len = satoa(*said, 0, sa, SATOA_BUF);

	hashval = (said->spi+said->dst.s_addr+said->proto) % TDB_HASHMOD;
	
	KLIPS_PRINT(debug_xform,
		    "klips_debug:gettdb: "
		    "linked entry in tdb table for hash=%d of SA:%s requested.\n",
		    hashval,
		    sa_len ? sa : " (error)");

	if(!(tdbp = tdbh[hashval])) {
		KLIPS_PRINT(debug_xform,
			    "klips_debug:gettdb: "
			    "no entries in tdb table for hash=%d of SA:%s.\n",
			    hashval,
			    sa_len ? sa : " (error)");
		return NULL;
	}

	for (; tdbp; tdbp = tdbp->tdb_hnext) {
		if ((tdbp->tdb_said.spi == said->spi) &&
		    (tdbp->tdb_said.dst.s_addr == said->dst.s_addr) &&
		    (tdbp->tdb_said.proto == said->proto)) {
			return tdbp;
		}
	}
	
	KLIPS_PRINT(debug_xform,
		    "klips_debug:gettdb: "
		    "no entry in linked list for hash=%d of SA:%s.\n",
		    hashval,
		    sa_len ? sa : " (error)");
	return NULL;
}

/*
  The tdb table better *NOT* be locked before it is handed in, or SMP locks will happen
*/
int
puttdb(struct tdb *tdbp)
{
	int error = 0;
	unsigned int hashval;

	if(!tdbp) {
		KLIPS_PRINT(debug_xform,
			    "klips_error:puttdb: "
			    "null pointer passed in!\n");
		return -ENODATA;
	}
	hashval = ((tdbp->tdb_said.spi + tdbp->tdb_said.dst.s_addr + tdbp->tdb_said.proto) % TDB_HASHMOD);

	spin_lock_bh(&tdb_lock);
	
	tdbp->tdb_hnext = tdbh[hashval];
	tdbh[hashval] = tdbp;
	
	spin_unlock_bh(&tdb_lock);

	return error;
}

/*
  The tdb table better be locked before it is handed in, or races might happen
*/
int
deltdb(struct tdb *tdbp)
{
	unsigned int hashval;
	struct tdb *tdbtp;
        char sa[SATOA_BUF];
	size_t sa_len;

	if(!tdbp) {
		KLIPS_PRINT(debug_xform,
			    "klips_error:deltdb: "
			    "null pointer passed in!\n");
		return -ENODATA;
	}
	
	sa_len = satoa(tdbp->tdb_said, 0, sa, SATOA_BUF);
	if(tdbp->tdb_inext || tdbp->tdb_onext) {
		KLIPS_PRINT(debug_xform,
			    "klips_error:deltdb: "
			    "SA:%s still linked!\n",
			    sa_len ? sa : " (error)");
		return -EMLINK;
	}
	
	hashval = ((tdbp->tdb_said.spi + tdbp->tdb_said.dst.s_addr + tdbp->tdb_said.proto) % TDB_HASHMOD);
	
	KLIPS_PRINT(debug_xform,
		    "klips_debug:deltdb: "
		    "deleting SA:%s, hashval=%d.\n",
		    sa_len ? sa : " (error)",
		    hashval);
	if(!tdbh[hashval]) {
		KLIPS_PRINT(debug_xform,
			    "klips_debug:deltdb: "
			    "no entries in tdb table for hash=%d of SA:%s.\n",
			    hashval,
			    sa_len ? sa : " (error)");
		return -ENOENT;
	}
	
	if (tdbp == tdbh[hashval]) {
		tdbh[hashval] = tdbh[hashval]->tdb_hnext;
		tdbp->tdb_hnext = NULL;
		KLIPS_PRINT(debug_xform,
			    "klips_debug:deltdb: "
			    "successfully deleted first tdb in chain.\n");
		return 0;
	} else {
		for (tdbtp = tdbh[hashval]; tdbtp; tdbtp = tdbtp->tdb_hnext) {
			if (tdbtp->tdb_hnext == tdbp) {
				tdbtp->tdb_hnext = tdbp->tdb_hnext;
				tdbp->tdb_hnext = NULL;
				KLIPS_PRINT(debug_xform,
					    "klips_debug:deltdb: "
					    "successfully deleted link in tdb chain.\n");
				return 0;
			}
		}
	}
	
	KLIPS_PRINT(debug_xform,
		    "klips_debug:deltdb: "
		    "no entries in linked list for hash=%d of SA:%s.\n",
		    hashval,
		    sa_len ? sa : " (error)");
	return -ENOENT;
}

/*
  The tdb table better be locked before it is handed in, or races might happen
*/
int
deltdbchain(struct tdb *tdbp)
{
	struct tdb *tdbdel;
	int error = 0;
        char sa[SATOA_BUF];
	size_t sa_len;

	if(!tdbp) {
		KLIPS_PRINT(debug_xform,
			    "klips_error:deltdbchain: "
			    "null pointer passed in!\n");
		return -ENODATA;
	}

	sa_len = satoa(tdbp->tdb_said, 0, sa, SATOA_BUF);
	KLIPS_PRINT(debug_xform,
		    "klips_debug:deltdbchain: "
		    "passed SA:%s\n",
		    sa_len ? sa : " (error)");
	while(tdbp->tdb_onext) {
		tdbp = tdbp->tdb_onext;
	}

	while(tdbp) {
		/* XXX send a pfkey message up to advise of deleted TDB */
		sa_len = satoa(tdbp->tdb_said, 0, sa, SATOA_BUF);
		KLIPS_PRINT(debug_xform,
			    "klips_debug:deltdbchain: "
			    "unlinking and delting SA:%s",
			    sa_len ? sa : " (error)");
		tdbdel = tdbp;
		tdbp = tdbp->tdb_inext;
		if(tdbp) {
			sa_len = satoa(tdbp->tdb_said, 0, sa, SATOA_BUF);
			KLIPS_PRINT(debug_xform,
				    ", inext=%s",
				    sa_len ? sa : " (error)");
			tdbdel->tdb_inext = NULL;
			tdbp->tdb_onext = NULL;
		}
		KLIPS_PRINT(debug_xform,
			    ".\n");
		if((error = deltdb(tdbdel))) {
			KLIPS_PRINT(debug_xform,
				    "klips_debug:deltdbchain: "
				    "deltdb returned error %d.\n", -error);
			return error;
		}
		if((error = ipsec_tdbwipe(tdbdel))) {
			KLIPS_PRINT(debug_xform,
				    "klips_debug:deltdbchain: "
				    "ipsec_tdbwipe returned error %d.\n", -error);
			return error;
		}
	}
	return error;
}

#if 0
int
tdb_init(struct tdb *tdbp, struct encap_msghdr *em)
{
	int alg;
	struct xformsw *xsp;
	int error = 0;
        int i;
#if defined(CONFIG_IPSEC_ENC_DES) || defined(CONFIG_IPSEC_ENC_3DES)
        int error;
#endif /* defined(CONFIG_IPSEC_ENC_DES) || defined(CONFIG_IPSEC_ENC_3DES) */

        char sa[SATOA_BUF];
        size_t sa_len;

	if(!tdbp || !em) {
		KLIPS_PRINT(debug_xform,
			    "klips_error:tdb_init: "
			    "null pointer passed in!\n");
		SENDERR(ENODATA);
	}

	sa_len = satoa(em->em_said, 0, sa, SATOA_BUF);

        KLIPS_PRINT(debug_esp,
		    "klips_debug:tdb_init: "
		    "(algo_switch defined) called for SA:%s\n",
		    sa_len ? sa : " (error)");
	alg = em->em_alg;
	
	for (xsp = xformsw; xsp < xformswNXFORMSW; xsp++) {
		if (xsp->xf_type == alg) {
			KLIPS_PRINT(debug_netlink,
				    "klips_debug:tdb_init: "
				    "called with tdbp=0x%p, xsp=0x%p, em=0x%p\n",
				    tdbp, xsp, em);
			KLIPS_PRINT(debug_netlink,
				    "klips_debug:tdb_init: "
				    "calling init routine of %s\n",
				    xsp->xf_name);
			tdbp->tdb_xform = xsp;
			tdbp->tdb_replaywin_lastseq = 0;
			tdbp->tdb_replaywin_bitmap = 0;
			/* check size of message here XXX */
			switch(alg) {
#ifdef CONFIG_IPSEC_IPIP
			case XF_IP4: {
				struct ipe4_xdata *xd;
				xd = (struct ipe4_xdata *)(em->em_dat);

				tdbp->tdb_authalg = AH_NONE;
				tdbp->tdb_encalg = ESP_NONE;
				
 				if((tdbp->tdb_addr_s = (struct sockaddr*)
				   kmalloc((tdbp->tdb_addr_s_size = sizeof(struct sockaddr_in)),
					   GFP_ATOMIC)) == NULL) {
					SENDERR(ENOMEM);
				}
				if((tdbp->tdb_addr_d = (struct sockaddr*)
				   kmalloc((tdbp->tdb_addr_d_size = sizeof(struct sockaddr_in)),
					   GFP_ATOMIC)) == NULL) {
					SENDERR(ENOMEM);
				}
				
				/* might want to use a different structure here, or set sin_family and sin_port */
				((struct sockaddr_in*)(tdbp->tdb_addr_s))->sin_addr = xd->i4_src;
				((struct sockaddr_in*)(tdbp->tdb_addr_d))->sin_addr = xd->i4_dst;
			}
				break;
#endif /* !CONFIG_IPSEC_IPIP */

#ifdef CONFIG_IPSEC_AH

# ifdef CONFIG_IPSEC_AUTH_HMAC_MD5
			case XF_AHHMACMD5: {
				struct ahhmacmd5_edata *ed;
				unsigned char kb[AHMD596_BLKLEN];
				MD5_CTX *ictx;
				MD5_CTX *octx;

				ed = (struct ahhmacmd5_edata *)em->em_dat;

				tdbp->tdb_authalg = AH_MD5;
				tdbp->tdb_encalg = ESP_NONE;
				
				if (em->em_msglen - EMT_SETSPI_FLEN > sizeof (struct ahhmacmd5_edata))
					SENDERR(EINVAL);
				
				if (ed->ame_klen != AHMD596_KLEN) {
					KLIPS_PRINT(debug_ah,
						    "klips_debug:tdb_init: "
						    "incorrect key size: %d -- must be %d octets (bytes)\n",
						    ed->ame_klen, AHMD596_KLEN);
					SENDERR(EINVAL);
				}
				
				if (ed->ame_alen != AHMD596_ALEN) {
					KLIPS_PRINT(debug_ah,
						    "klips_debug:tdb_init: "
						    "authenticator size: %d -- must be %d octets (bytes)\n",
						    ed->ame_alen, AHMD596_ALEN);
					SENDERR(EINVAL);
				}
				
				KLIPS_PRINT(debug_ah,
					    "klips_debug:tdb_init: "
					    "hmac md5-96 key is 0x%08x %08x %08x %08x\n",
					    (__u32)ntohl(*(((__u32 *)ed->ame_key)+0)),
					    (__u32)ntohl(*(((__u32 *)ed->ame_key)+1)),
					    (__u32)ntohl(*(((__u32 *)ed->ame_key)+2)),
					    (__u32)ntohl(*(((__u32 *)ed->ame_key)+3)));
				
				tdbp->tdb_key_bits_a = ed->ame_klen;
				tdbp->tdb_auth_bits = ed->ame_alen * 8;
				
				if(ed->ame_ooowin > 64) {
					KLIPS_PRINT(debug_ah,
						    "klips_debug:tdb_init: "
						    "replay window size: %d -- must be 0 <= size <= 64\n",
						    ed->ame_ooowin);
					SENDERR(EINVAL);
				}
				tdbp->tdb_replaywin = ed->ame_ooowin;
				tdbp->tdb_replaywin_lastseq = tdbp->tdb_replaywin_bitmap = 0;
				
				if((tdbp->tdb_key_a = (caddr_t)
				    kmalloc((tdbp->tdb_key_a_size = sizeof(struct md5_ctx)),
					    GFP_ATOMIC)) == NULL) {
					SENDERR(ENOMEM);
				}

				for (i = 0; i < ed->ame_klen; i++) {
					kb[i] = ed->ame_key[i] ^ HMAC_IPAD;
				}
				for (; i < AHMD596_BLKLEN; i++) {
					kb[i] = HMAC_IPAD;
				}

				ictx = &(((struct md5_ctx*)(tdbp->tdb_key_a))->ictx);
				MD5Init(ictx);
				MD5Update(ictx, kb, AHMD596_BLKLEN);

				for (i = 0; i < AHMD596_BLKLEN; i++)
					kb[i] ^= (HMAC_IPAD ^ HMAC_OPAD);

				octx = &(((struct md5_ctx*)(tdbp->tdb_key_a))->octx);
				MD5Init(octx);
				MD5Update(octx, kb, AHMD596_BLKLEN);
				
				KLIPS_PRINT(debug_ah,
					    "klips_debug:tdb_init: "
					    "MD5 ictx=0x%08x %08x %08x %08x octx=0x%08x %08x %08x %08x\n",
					    ((__u32*)ictx)[0],
					    ((__u32*)ictx)[1],
					    ((__u32*)ictx)[2],
					    ((__u32*)ictx)[3],
					    ((__u32*)octx)[0],
					    ((__u32*)octx)[1],
					    ((__u32*)octx)[2],
					    ((__u32*)octx)[3] );
				
				/* zero key buffer -- paranoid */
				memset(kb, 0, sizeof(kb));
				memset((caddr_t)&(ed->ame_key), 0, ed->ame_klen);
			}
				break;
# endif /* CONFIG_IPSEC_AUTH_HMAC_MD5 */
# ifdef CONFIG_IPSEC_AUTH_HMAC_SHA1
			case XF_AHHMACSHA1: {
				struct ahhmacsha1_edata *ed;
				unsigned char kb[AHSHA196_BLKLEN];
				SHA1_CTX *ictx;
				SHA1_CTX *octx;

				ed = (struct ahhmacsha1_edata *)em->em_dat;
				
				tdbp->tdb_authalg = AH_SHA;
				tdbp->tdb_encalg = ESP_NONE;
				
				if (em->em_msglen - EMT_SETSPI_FLEN > sizeof (struct ahhmacsha1_edata))
					SENDERR(EINVAL);
				
				if (ed->ame_klen != AHSHA196_KLEN) {
					KLIPS_PRINT(debug_ah,
						    "klips_debug:tdb_init: "
						    "incorrect key size: %d -- must be %d octets (bytes)\n",
						    ed->ame_klen, AHSHA196_KLEN);
					SENDERR(EINVAL);
				}
				
				if (ed->ame_alen != AHSHA196_ALEN) {
					KLIPS_PRINT(debug_ah,
						    "klips_debug:tdb_init: "
						    "authenticator size: %d -- must be %d octets (bytes)\n",
						    ed->ame_alen, AHSHA196_ALEN);
					SENDERR(EINVAL);
				}
				
				KLIPS_PRINT(debug_ah,
					    "klips_debug:tdb_init: "
					    "hmac sha1-96 key is 0x%08x %08x %08x %08x\n",
					    (__u32)ntohl(*(((__u32 *)ed->ame_key)+0)),
					    (__u32)ntohl(*(((__u32 *)ed->ame_key)+1)),
					    (__u32)ntohl(*(((__u32 *)ed->ame_key)+2)),
					    (__u32)ntohl(*(((__u32 *)ed->ame_key)+3)));
				
				tdbp->tdb_key_bits_a = ed->ame_klen;
				tdbp->tdb_auth_bits = ed->ame_alen * 8;
				
				if(ed->ame_ooowin > 64) {
					KLIPS_PRINT(debug_ah,
						    "klips_debug:tdb_init: "
						    "replay window size: %d -- must be 0 <= size <= 64\n",
						    ed->ame_ooowin);
					SENDERR(EINVAL);
				}
				tdbp->tdb_replaywin = ed->ame_ooowin;
				tdbp->tdb_replaywin_lastseq = tdbp->tdb_replaywin_bitmap = 0;
				
				if((tdbp->tdb_key_a = (caddr_t)
				    kmalloc((tdbp->tdb_key_a_size = (__u16)sizeof(struct sha1_ctx)),
					    GFP_ATOMIC)) == NULL) {
					SENDERR(ENOMEM);
				}

				for (i = 0; i < ed->ame_klen; i++)
					kb[i] = ed->ame_key[i] ^ HMAC_IPAD;
				for (; i < AHSHA196_BLKLEN; i++)
					kb[i] = HMAC_IPAD;

				ictx = &(((struct sha1_ctx*)(tdbp->tdb_key_a))->ictx);
				SHA1Init(ictx);
				SHA1Update(ictx, kb, AHSHA196_BLKLEN);
				
				for (i = 0; i < AHSHA196_BLKLEN; i++)
					kb[i] ^= (HMAC_IPAD ^ HMAC_OPAD);

				octx = &(((struct sha1_ctx*)(tdbp->tdb_key_a))->octx);
				SHA1Init(octx);
				SHA1Update(octx, kb, AHSHA196_BLKLEN);
				
				KLIPS_PRINT(debug_ah,
					    "klips_debug:tdb_init: "
					    "SHA1 ictx=0x%08x %08x %08x %08x octx=0x%08x %08x %08x %08x\n", 
					    ((__u32*)ictx)[0],
					    ((__u32*)ictx)[1],
					    ((__u32*)ictx)[2],
					    ((__u32*)ictx)[3],
					    ((__u32*)octx)[0],
					    ((__u32*)octx)[1],
					    ((__u32*)octx)[2],
					    ((__u32*)octx)[3] );
				
				/* zero key buffer -- paranoid */
				memset(kb, 0, sizeof(kb));
				memset((caddr_t)&(ed->ame_key), 0, ed->ame_klen);
			}
				break;
# endif /* CONFIG_IPSEC_AUTH_HMAC_SHA1 */

#endif /* CONFIG_IPSEC_AH */

#ifdef CONFIG_IPSEC_ESP
#ifdef CONFIG_IPSEC_ENC_DES
			case XF_ESPDES:
#ifdef CONFIG_IPSEC_AUTH_HMAC_MD5
			case XF_ESPDESMD596:
#endif /* CONFIG_IPSEC_AUTH_HMAC_MD5 */
#ifdef CONFIG_IPSEC_AUTH_HMAC_SHA1
			case XF_ESPDESSHA196:
#endif /* CONFIG_IPSEC_AUTH_HMAC_SHA1 */
#endif /* CONFIG_IPSEC_ENC_DES */
#ifdef CONFIG_IPSEC_ENC_3DES
			case XF_ESP3DES:
#ifdef CONFIG_IPSEC_AUTH_HMAC_MD5
			case XF_ESP3DESMD596:
#endif /* CONFIG_IPSEC_AUTH_HMAC_MD5 */
#ifdef CONFIG_IPSEC_AUTH_HMAC_SHA1
			case XF_ESP3DESSHA196:
#endif /* CONFIG_IPSEC_AUTH_HMAC_SHA1 */
#endif /* CONFIG_IPSEC_ENC_3DES */
			{
				struct espblkrply_edata *ed;
				unsigned char kb[AHMD596_BLKLEN];
				ed = (struct espblkrply_edata *)em->em_dat;

				KLIPS_PRINT(debug_esp,
					    "klips_debug:tdb_init: "
					    "netlink data:"
					    " eklen=%d"
					    " aklen=%d"
					    " flags=%d"
					    " ooowin=%d.\n",
					    ed->eme_klen,
					    ed->ame_klen,
					    ed->eme_flags,
					    ed->eme_ooowin);

				if(ed->eme_ooowin > 64) {
					KLIPS_PRINT(debug_esp,
						    "klips_debug:tdb_init: "
						    "replay window size: %d -- must be 0 <= size <= 64\n",
						    ed->eme_ooowin);
					SENDERR(EINVAL);
				}
				tdbp->tdb_replaywin = ed->eme_ooowin;

				switch(alg) {
				case XF_ESPDES:
				case XF_ESPDESMD596:
				case XF_ESPDESSHA196:
				case XF_ESP3DES:
				case XF_ESP3DESMD596:
				case XF_ESP3DESSHA196:
					if((tdbp->tdb_iv = (caddr_t)
					   kmalloc((tdbp->tdb_iv_size = EMT_ESPDES_IV_SZ), GFP_ATOMIC)) == NULL) {
						SENDERR(ENOMEM);
					}
					get_random_bytes((void *)tdbp->tdb_iv, EMT_ESPDES_IV_SZ);
					tdbp->tdb_iv_bits = tdbp->tdb_iv_size * 8;
					break;
				default:
				}

				switch(alg) {
#ifdef CONFIG_IPSEC_ENC_DES
				case XF_ESPDES:
				case XF_ESPDESMD596:
				case XF_ESPDESSHA196:
					tdbp->tdb_encalg = ESP_DES;

					if (ed->eme_klen != EMT_ESPDES_KEY_SZ) {
						KLIPS_PRINT(debug_esp,
							    "klips_debug:tdb_init: incorrect encryption "
							    "key size: %d -- must be %d octets (bytes)\n",
							    ed->eme_klen, EMT_ESPDES_KEY_SZ);
						SENDERR(EINVAL);
					}

					tdbp->tdb_key_bits_e = ed->eme_klen;

					if((tdbp->tdb_key_e = (caddr_t)
					   kmalloc((tdbp->tdb_key_e_size = sizeof(struct des_eks)),
						   GFP_ATOMIC)) == NULL) {
						   SENDERR(ENOMEM);
					}
#if 0
					KLIPS_PRINT(debug_esp,
						    "klips_debug:tdb_init: des key is 0x%08lx%08lx\n",
						    ntohl(*((__u32 *)ed->eme_key)),
						    ntohl(*((__u32 *)ed->eme_key + 1)));
#endif
					error = des_set_key((caddr_t)(ed->eme_key), (caddr_t)(tdbp->tdb_key_e));
					if (error == -1)
						printk("klips_debug:tdb_init: parity error in des key\n");
					else if (error == -2)
						printk("klips_debug:tdb_init: illegal weak des key\n");
					if (error) {
						memset(tdbp->tdb_key_e, 0, sizeof (struct des_eks));
						kfree_s(tdbp->tdb_key_e, sizeof(struct des_eks));
						SENDERR(EINVAL);
					}

					break;
#endif /* CONFIG_IPSEC_ENC_DES */
#ifdef CONFIG_IPSEC_ENC_3DES
				case XF_ESP3DES:
				case XF_ESP3DESMD596:
				case XF_ESP3DESSHA196:
					tdbp->tdb_encalg = ESP_3DES;
				
					if (ed->eme_klen != EMT_ESP3DES_KEY_SZ) {
						KLIPS_PRINT(debug_esp,
							    "klips_debug:tdb_init: "
							    "incorrect encryption key size: %d -- must be %d octets (bytes)\n",
							    ed->eme_klen, EMT_ESP3DES_KEY_SZ);
						SENDERR(EINVAL);
					}

					tdbp->tdb_key_bits_e = ed->eme_klen;

					if((tdbp->tdb_key_e = (caddr_t)
					   kmalloc((tdbp->tdb_key_e_size = 3 * sizeof(struct des_eks)),
						   GFP_ATOMIC)) == NULL) {
						SENDERR(ENOMEM);
					}

					for(i = 0; i < 3; i++) {
#if 0
						KLIPS_PRINT(debug_esp,
							    "klips_debug:tdb_init: "
							    "3des key %d/3 is 0x%08lx%08lx\n",
							    i + 1,
							    ntohl(*((__u32 *)ed->eme_key + i * 2)),
							    ntohl(*((__u32 *)ed->eme_key + i * 2 + 1)));
#endif
						error = des_set_key((caddr_t)(ed->eme_key) + EMT_ESPDES_KEY_SZ * i,
								    (caddr_t)&((struct des_eks*)(tdbp->tdb_key_e))[i]);
						if (error == -1)
							printk("klips_debug:tdb_init: "
							       "parity error in des key %d/3\n", i + 1);
						else if (error == -2)
							printk("klips_debug:tdb_init: "
							       "illegal weak des key %d/3\n", i + 1);
						if (error) {
							memset(tdbp->tdb_key_e, 0, 3 * sizeof(struct des_eks));
							kfree(tdbp->tdb_key_e);
							SENDERR(EINVAL);
						}
					}

					break;
#endif /* CONFIG_IPSEC_ENC_3DES */
				default:
					tdbp->tdb_encalg = ESP_NULL;
				}

				switch(alg) {
#ifdef CONFIG_IPSEC_AUTH_HMAC_MD5
				case XF_ESPDESMD596:
				case XF_ESP3DESMD596:
				case XF_ESPNULLMD596:
				{
					MD5_CTX *ictx;
					MD5_CTX *octx;

					tdbp->tdb_authalg = AH_MD5;
				
					if (ed->ame_klen != AHMD596_KLEN) {
						KLIPS_PRINT(debug_esp,
							    "klips_debug:tdb_init: "
							    "incorrect authorisation  key size: %d -- must be %d octets (bytes)\n",
							    ed->ame_klen, AHMD596_KLEN);
						SENDERR(EINVAL);
					}

					tdbp->tdb_key_bits_a = ed->ame_klen;
					tdbp->tdb_auth_bits = ed->ame_klen * 8;
			

					if((tdbp->tdb_key_a = (caddr_t)
					   kmalloc((tdbp->tdb_key_a_size = sizeof(struct md5_ctx)),
						   GFP_ATOMIC)) == NULL) {
						SENDERR(ENOMEM);
					}
					KLIPS_PRINT(debug_esp,
						    "klips_debug:tdb_init: "
						    "hmac md5-96 key is 0x%08x %08x %08x %08x\n",
						    (__u32)ntohl(*(((__u32 *)ed->ame_key)+0)),
						    (__u32)ntohl(*(((__u32 *)ed->ame_key)+1)),
						    (__u32)ntohl(*(((__u32 *)ed->ame_key)+2)),
						    (__u32)ntohl(*(((__u32 *)ed->ame_key)+3)));
					
					for (i=0; i< AHMD596_KLEN; i++)
						kb[i] = (*(((unsigned char *)(ed->ame_key)) + i)) ^ HMAC_IPAD;
					/*
					 * HMAC_key is now contained in the first 128 bits of kb.
					 * Pad with zeroes and XOR with HMAC_IPAD to create the inner context
					 */
					for (; i<AHMD596_BLKLEN; i++) {
						kb[i] = HMAC_IPAD;
					}

					ictx = &(((struct md5_ctx*)(tdbp->tdb_key_a))->ictx);
					MD5Init(ictx);
					MD5Update(ictx, kb, AHMD596_BLKLEN);
					
					for (i=0; i<AHMD596_BLKLEN; i++) {
						kb[i] ^= (HMAC_IPAD ^ HMAC_OPAD);
					}
					
					octx = &(((struct md5_ctx*)(tdbp->tdb_key_a))->octx);
					MD5Init(octx);
					MD5Update(octx, kb, AHMD596_BLKLEN);
					
					KLIPS_PRINT(debug_esp,
						    "klips_debug:tdb_init: "
						    "MD5 ictx=0x%08x %08x %08x %08x octx=0x%08x %08x %08x %08x\n",
						    ((__u32*)ictx)[0],
						    ((__u32*)ictx)[1],
						    ((__u32*)ictx)[2],
						    ((__u32*)ictx)[3],
						    ((__u32*)octx)[0],
						    ((__u32*)octx)[1],
						    ((__u32*)octx)[2],
						    ((__u32*)octx)[3] );

					memset(kb, 0, sizeof(kb)); /* paranoid */
					memset((caddr_t)&(ed->eme_key), 0, ed->eme_klen);
					memset((caddr_t)&(ed->ame_key), 0, ed->ame_klen);
					break;
				}
#endif /* CONFIG_IPSEC_AUTH_HMAC_MD5 */
#ifdef CONFIG_IPSEC_AUTH_HMAC_SHA1
				case XF_ESPNULLSHA196:
				case XF_ESPDESSHA196:
				case XF_ESP3DESSHA196:
				{
					SHA1_CTX *ictx;
					SHA1_CTX *octx;

					tdbp->tdb_authalg = AH_SHA;
				
					if (ed->ame_klen != AHSHA196_KLEN) {
						KLIPS_PRINT(debug_esp,
							    "klips_debug:tdb_init: "
							    "incorrect authorisation key size: %d -- must be %d octets (bytes)\n",
							    ed->ame_klen, AHSHA196_KLEN);
						SENDERR(EINVAL);
					}

					tdbp->tdb_key_bits_a = ed->ame_klen;
					tdbp->tdb_auth_bits = ed->ame_klen * 8;

					if((tdbp->tdb_key_a = (caddr_t)
					   kmalloc((tdbp->tdb_key_a_size = sizeof(struct sha1_ctx)),
						   GFP_ATOMIC)) == NULL) {
						SENDERR(ENOMEM);
					}
					KLIPS_PRINT(debug_esp,
						    "klips_debug:tdb_init: "
						    "hmac sha1-96 key is 0x%08x %08x %08x %08x\n",
						    (__u32)ntohl(*(((__u32 *)ed->ame_key)+0)),
						    (__u32)ntohl(*(((__u32 *)ed->ame_key)+1)),
						    (__u32)ntohl(*(((__u32 *)ed->ame_key)+2)),
						    (__u32)ntohl(*(((__u32 *)ed->ame_key)+3)));

					for (i=0; i< AHSHA196_KLEN; i++)
						kb[i] = (*(((unsigned char *)(ed->ame_key)) + i)) ^ HMAC_IPAD;
					/*
					 * HMAC_key is now contained in the first 128 bits of kb.
					 * Pad with zeroes and XOR with HMAC_IPAD to create the inner context
					 */
					for (; i<AHSHA196_BLKLEN; i++)
						kb[i] = HMAC_IPAD;
					
					ictx = &(((struct sha1_ctx*)(tdbp->tdb_key_a))->ictx);
					SHA1Init(ictx);
					SHA1Update(ictx, kb, AHSHA196_BLKLEN);
				
					for (i=0; i<AHSHA196_BLKLEN; i++)
						kb[i] ^= (HMAC_IPAD ^ HMAC_OPAD);
					
					octx = &(((struct sha1_ctx*)(tdbp->tdb_key_a))->octx);
					SHA1Init(octx);
					SHA1Update(octx, kb, AHSHA196_BLKLEN);
				
					KLIPS_PRINT(debug_esp,
						    "klips_debug:tdb_init: "
						    "SHA1 ictx=0x%08x %08x %08x %08x octx=0x%08x %08x %08x %08x\n",
						    ((__u32*)ictx)[0],
						    ((__u32*)ictx)[1],
						    ((__u32*)ictx)[2],
						    ((__u32*)ictx)[3],
						    ((__u32*)octx)[0],
						    ((__u32*)octx)[1],
						    ((__u32*)octx)[2],
						    ((__u32*)octx)[3] );
					
					memset(kb, 0, sizeof(kb)); /* paranoid */
					memset((caddr_t)&(ed->eme_key), 0, ed->eme_klen);
					memset((caddr_t)&(ed->ame_key), 0, ed->ame_klen);
					break;
				}
#endif /* CONFIG_IPSEC_AUTH_HMAC_SHA1 */
				case XF_ESPDES:
				case XF_ESP3DES:
					tdbp->tdb_authalg = AH_NONE;
					break;
				default:
				}
			}
				break;
#endif /* !CONFIG_IPSEC_ESP */
			default:
				KLIPS_PRINT(debug_xform,
					    "klips_debug:tdb_init: "
					    "alg=%d not configured\n",
					    alg);
				SENDERR(ESOCKTNOSUPPORT);
			}
			SENDERR(0);
		}
	}
	KLIPS_PRINT(debug_xform & DB_XF_INIT,
		    "klips_debug:tdb_init: "
		    "unregistered algorithm %d requested trying to setup SA:%s\n",
		    alg,
		    sa_len ? sa : " (error)");
	SENDERR(EINVAL);
errlab:
	return error;
}
#endif

int 
ipsec_tdbcleanup(__u8 proto)
{
	int i;
	int error = 0;
	struct tdb *tdbp, **tdbprev, *tdbdel;
        char sa[SATOA_BUF];
	size_t sa_len;

	KLIPS_PRINT(debug_xform,
		    "klips_debug:ipsec_tdbcleanup: "
		    "cleaning up proto=%d.\n",
		    proto);

	spin_lock_bh(&tdb_lock);

	for (i = 0; i < TDB_HASHMOD; i++) {
		tdbprev = &(tdbh[i]);
		tdbp = tdbh[i];
		for(; tdbp;) {
			sa_len = satoa(tdbp->tdb_said, 0, sa, SATOA_BUF);
			KLIPS_PRINT(debug_xform,
				    "klips_debug:ipsec_tdbcleanup: "
				    "checking SA:%s, hash=%d",
				    sa_len ? sa : " (error)",
				    i);
			tdbdel = tdbp;
			tdbp = tdbdel->tdb_hnext;
			if(tdbp) {
				sa_len = satoa(tdbp->tdb_said, 0, sa, SATOA_BUF);
				KLIPS_PRINT(debug_xform,
					    ", hnext=%s",
					    sa_len ? sa : " (error)");
			}
			if(*tdbprev) {
				sa_len = satoa((*tdbprev)->tdb_said, 0, sa, SATOA_BUF);
				KLIPS_PRINT(debug_xform,
					    ", *tdbprev=%s",
					    sa_len ? sa : " (error)");
				if((*tdbprev)->tdb_hnext) {
					sa_len = satoa((*tdbprev)->tdb_hnext->tdb_said, 0, sa, SATOA_BUF);
					KLIPS_PRINT(debug_xform,
						    ", *tdbprev->tdb_hnext=%s",
						    sa_len ? sa : " (error)");
				}
			}
			KLIPS_PRINT(debug_xform,
				    ".\n");
			if(!proto || (proto == tdbdel->tdb_said.proto)) {
				sa_len = satoa(tdbdel->tdb_said, 0, sa, SATOA_BUF);
				KLIPS_PRINT(debug_xform,
					    "klips_debug:ipsec_tdbcleanup: "
					    "deleting SA chain:%s.\n",
					    sa_len ? sa : " (error)");
				if((error = deltdbchain(tdbdel))) {
					SENDERR(-error);
				}
				tdbprev = &(tdbh[i]);
				tdbp = tdbh[i];

				KLIPS_PRINT(debug_xform,
					    "klips_debug:ipsec_tdbcleanup: "
					    "deleted SA chain:%s",
					    sa_len ? sa : " (error)");
				if(tdbp) {
					sa_len = satoa(tdbp->tdb_said, 0, sa, SATOA_BUF);
					KLIPS_PRINT(debug_xform,
						    ", tdbh[%d]=%s",
						    i,
						    sa_len ? sa : " (error)");
				}
				if(*tdbprev) {
					sa_len = satoa((*tdbprev)->tdb_said, 0, sa, SATOA_BUF);
					KLIPS_PRINT(debug_xform,
						    ", *tdbprev=%s",
						    sa_len ? sa : " (error)");
					if((*tdbprev)->tdb_hnext) {
						sa_len = satoa((*tdbprev)->tdb_hnext->tdb_said, 0, sa, SATOA_BUF);
						KLIPS_PRINT(debug_xform,
							    ", *tdbprev->tdb_hnext=%s",
							    sa_len ? sa : " (error)");
					}
				}
				KLIPS_PRINT(debug_xform,
					    ".\n");
			} else {
				tdbprev = &tdbdel;
			}
		}
	}
 errlab:

	spin_unlock_bh(&tdb_lock);

	return(error);
}

int
ipsec_tdbwipe(struct tdb *tdbp)
{
	if(!tdbp) {
		return -ENODATA;
	}

	if(tdbp->tdb_addr_s) {
		memset((caddr_t)(tdbp->tdb_addr_s), 0, tdbp->tdb_addr_s_size);
		kfree(tdbp->tdb_addr_s);
	}
	tdbp->tdb_addr_s = NULL;

	if(tdbp->tdb_addr_d) {
		memset((caddr_t)(tdbp->tdb_addr_d), 0, tdbp->tdb_addr_d_size);
		kfree(tdbp->tdb_addr_d);
	}
	tdbp->tdb_addr_d = NULL;

	if(tdbp->tdb_addr_p) {
		memset((caddr_t)(tdbp->tdb_addr_p), 0, tdbp->tdb_addr_p_size);
		kfree(tdbp->tdb_addr_p);
	}
	tdbp->tdb_addr_p = NULL;

	if(tdbp->tdb_key_a) {
		memset((caddr_t)(tdbp->tdb_key_a), 0, tdbp->tdb_key_a_size);
		kfree(tdbp->tdb_key_a);
	}
	tdbp->tdb_key_a = NULL;

	if(tdbp->tdb_key_e) {
		memset((caddr_t)(tdbp->tdb_key_e), 0, tdbp->tdb_key_e_size);
		kfree(tdbp->tdb_key_e);
	}
	tdbp->tdb_key_e = NULL;

	if(tdbp->tdb_iv) {
		memset((caddr_t)(tdbp->tdb_iv), 0, tdbp->tdb_iv_size);
		kfree(tdbp->tdb_iv);
	}
	tdbp->tdb_iv = NULL;

	if(tdbp->tdb_ident_data_s) {
		memset((caddr_t)(tdbp->tdb_ident_data_s),
		       0,
		       tdbp->tdb_ident_len_s * IPSEC_PFKEYv2_ALIGN);
		kfree(tdbp->tdb_ident_data_s);
	}
	tdbp->tdb_ident_data_s = NULL;

	if(tdbp->tdb_ident_data_d) {
		memset((caddr_t)(tdbp->tdb_ident_data_d),
		       0,
		       tdbp->tdb_ident_len_d * IPSEC_PFKEYv2_ALIGN);
		kfree(tdbp->tdb_ident_data_d);
	}
	tdbp->tdb_ident_data_d = NULL;

	memset((caddr_t)tdbp, 0, sizeof(*tdbp));
	kfree(tdbp);
	tdbp = NULL;

	return 0;
}

/*
 * $Log: ipsec_xform.c,v $
 * Revision 1.52  2001/06/14 19:35:11  rgb
 * Update copyright date.
 *
 * Revision 1.51  2001/05/30 08:14:03  rgb
 * Removed vestiges of esp-null transforms.
 *
 * Revision 1.50  2001/05/03 19:43:18  rgb
 * Initialise error return variable.
 * Update SENDERR macro.
 * Fix sign of error return code for ipsec_tdbcleanup().
 * Use more appropriate return code for ipsec_tdbwipe().
 *
 * Revision 1.49  2001/04/19 18:56:17  rgb
 * Fixed tdb table locking comments.
 *
 * Revision 1.48  2001/02/27 22:24:55  rgb
 * Re-formatting debug output (line-splitting, joining, 1arg/line).
 * Check for satoa() return codes.
 *
 * Revision 1.47  2000/11/06 04:32:08  rgb
 * Ditched spin_lock_irqsave in favour of spin_lock_bh.
 *
 * Revision 1.46  2000/09/20 16:21:57  rgb
 * Cleaned up ident string alloc/free.
 *
 * Revision 1.45  2000/09/08 19:16:51  rgb
 * Change references from DEBUG_IPSEC to CONFIG_IPSEC_DEBUG.
 * Removed all references to CONFIG_IPSEC_PFKEYv2.
 *
 * Revision 1.44  2000/08/30 05:29:04  rgb
 * Compiler-define out no longer used tdb_init() in ipsec_xform.c.
 *
 * Revision 1.43  2000/08/18 21:30:41  rgb
 * Purged all tdb_spi, tdb_proto and tdb_dst macros.  They are unclear.
 *
 * Revision 1.42  2000/08/01 14:51:51  rgb
 * Removed _all_ remaining traces of DES.
 *
 * Revision 1.41  2000/07/28 14:58:31  rgb
 * Changed kfree_s to kfree, eliminating extra arg to fix 2.4.0-test5.
 *
 * Revision 1.40  2000/06/28 05:50:11  rgb
 * Actually set iv_bits.
 *
 * Revision 1.39  2000/05/10 23:11:09  rgb
 * Added netlink debugging output.
 * Added a cast to quiet down the ntohl bug.
 *
 * Revision 1.38  2000/05/10 19:18:42  rgb
 * Cast output of ntohl so that the broken prototype doesn't make our
 * compile noisy.
 *
 * Revision 1.37  2000/03/16 14:04:59  rgb
 * Hardwired CONFIG_IPSEC_PFKEYv2 on.
 *
 * Revision 1.36  2000/01/26 10:11:28  rgb
 * Fixed spacing in error text causing run-in words.
 *
 * Revision 1.35  2000/01/21 06:17:16  rgb
 * Tidied up compiler directive indentation for readability.
 * Added ictx,octx vars for simplification.(kravietz)
 * Added macros for HMAC padding magic numbers.(kravietz)
 * Fixed missing key length reporting bug.
 * Fixed bug in tdbwipe to return immediately on NULL tdbp passed in.
 *
 * Revision 1.34  1999/12/08 00:04:19  rgb
 * Fixed SA direction overwriting bug for netlink users.
 *
 * Revision 1.33  1999/12/01 22:16:44  rgb
 * Minor formatting changes in ESP MD5 initialisation.
 *
 * Revision 1.32  1999/11/25 09:06:36  rgb
 * Fixed error return messages, should be returning negative numbers.
 * Implemented SENDERR macro for propagating error codes.
 * Added debug message and separate error code for algorithms not compiled
 * in.
 *
 * Revision 1.31  1999/11/23 23:06:26  rgb
 * Sort out pfkey and freeswan headers, putting them in a library path.
 *
 * Revision 1.30  1999/11/18 04:09:20  rgb
 * Replaced all kernel version macros to shorter, readable form.
 *
 * Revision 1.29  1999/11/17 15:53:40  rgb
 * Changed all occurrences of #include "../../../lib/freeswan.h"
 * to #include <freeswan.h> which works due to -Ilibfreeswan in the
 * klips/net/ipsec/Makefile.
 *
 * Revision 1.28  1999/10/18 20:04:01  rgb
 * Clean-out unused cruft.
 *
 * Revision 1.27  1999/10/03 19:01:03  rgb
 * Spinlock support for 2.3.xx and 2.0.xx kernels.
 *
 * Revision 1.26  1999/10/01 16:22:24  rgb
 * Switch from assignment init. to functional init. of spinlocks.
 *
 * Revision 1.25  1999/10/01 15:44:54  rgb
 * Move spinlock header include to 2.1> scope.
 *
 * Revision 1.24  1999/10/01 00:03:46  rgb
 * Added tdb structure locking.
 * Minor formatting changes.
 * Add function to initialize tdb hash table.
 *
 * Revision 1.23  1999/05/25 22:42:12  rgb
 * Add deltdbchain() debugging.
 *
 * Revision 1.22  1999/05/25 21:24:31  rgb
 * Add debugging statements to deltdbchain().
 *
 * Revision 1.21  1999/05/25 03:51:48  rgb
 * Refix error return code.
 *
 * Revision 1.20  1999/05/25 03:34:07  rgb
 * Fix error return for flush.
 *
 * Revision 1.19  1999/05/09 03:25:37  rgb
 * Fix bug introduced by 2.2 quick-and-dirty patch.
 *
 * Revision 1.18  1999/05/05 22:02:32  rgb
 * Add a quick and dirty port to 2.2 kernels by Marc Boucher <marc@mbsi.ca>.
 *
 * Revision 1.17  1999/04/29 15:20:16  rgb
 * Change gettdb parameter to a pointer to reduce stack loading and
 * facilitate parameter sanity checking.
 * Add sanity checking for null pointer arguments.
 * Add debugging instrumentation.
 * Add function deltdbchain() which will take care of unlinking,
 * zeroing and deleting a chain of tdbs.
 * Add a parameter to tdbcleanup to be able to delete a class of SAs.
 * tdbwipe now actually zeroes the tdb as well as any of its pointed
 * structures.
 *
 * Revision 1.16  1999/04/16 15:36:29  rgb
 * Fix cut-and-paste error causing a memory leak in IPIP TDB freeing.
 *
 * Revision 1.15  1999/04/11 00:29:01  henry
 * GPL boilerplate
 *
 * Revision 1.14  1999/04/06 04:54:28  rgb
 * Fix/Add RCSID Id: and Log: bits to make PHMDs happy.  This includes
 * patch shell fixes.
 *
 * Revision 1.13  1999/02/19 18:23:01  rgb
 * Nix debug off compile warning.
 *
 * Revision 1.12  1999/02/17 16:52:16  rgb
 * Consolidate satoa()s for space and speed efficiency.
 * Convert DEBUG_IPSEC to KLIPS_PRINT
 * Clean out unused cruft.
 * Ditch NET_IPIP dependancy.
 * Loop for 3des key setting.
 *
 * Revision 1.11  1999/01/26 02:09:05  rgb
 * Remove ah/esp/IPIP switching on include files.
 * Removed CONFIG_IPSEC_ALGO_SWITCH macro.
 * Removed dead code.
 * Clean up debug code when switched off.
 * Remove references to INET_GET_PROTOCOL.
 * Added code exclusion macros to reduce code from unused algorithms.
 *
 * Revision 1.10  1999/01/22 06:28:55  rgb
 * Cruft clean-out.
 * Put random IV generation in kernel.
 * Added algorithm switch code.
 * Enhanced debugging.
 * 64-bit clean-up.
 *
 * Revision 1.9  1998/11/30 13:22:55  rgb
 * Rationalised all the klips kernel file headers.  They are much shorter
 * now and won't conflict under RH5.2.
 *
 * Revision 1.8  1998/11/25 04:59:06  rgb
 * Add conditionals for no IPIP tunnel code.
 * Delete commented out code.
 *
 * Revision 1.7  1998/10/31 06:50:41  rgb
 * Convert xform ASCII names to no spaces.
 * Fixed up comments in #endif directives.
 *
 * Revision 1.6  1998/10/19 14:44:28  rgb
 * Added inclusion of freeswan.h.
 * sa_id structure implemented and used: now includes protocol.
 *
 * Revision 1.5  1998/10/09 04:32:19  rgb
 * Added 'klips_debug' prefix to all klips printk debug statements.
 *
 * Revision 1.4  1998/08/12 00:11:31  rgb
 * Added new xform functions to the xform table.
 * Fixed minor debug output spelling error.
 *
 * Revision 1.3  1998/07/09 17:45:31  rgb
 * Clarify algorithm not available message.
 *
 * Revision 1.2  1998/06/23 03:00:51  rgb
 * Check for presence of IPIP protocol if it is setup one way (we don't
 * know what has been set up the other way and can only assume it will be
 * symmetrical with the exception of keys).
 *
 * Revision 1.1  1998/06/18 21:27:51  henry
 * move sources from klips/src to klips/net/ipsec, to keep stupid
 * kernel-build scripts happier in the presence of symlinks
 *
 * Revision 1.3  1998/06/11 05:54:59  rgb
 * Added transform version string pointer to xformsw initialisations.
 *
 * Revision 1.2  1998/04/21 21:28:57  rgb
 * Rearrange debug switches to change on the fly debug output from user
 * space.  Only kernel changes checked in at this time.  radij.c was also
 * changed to temporarily remove buggy debugging code in rj_delete causing
 * an OOPS and hence, netlink device open errors.
 *
 * Revision 1.1  1998/04/09 03:06:13  henry
 * sources moved up from linux/net/ipsec
 *
 * Revision 1.1.1.1  1998/04/08 05:35:02  henry
 * RGB's ipsec-0.8pre2.tar.gz ipsec-0.8
 *
 * Revision 0.5  1997/06/03 04:24:48  ji
 * Added ESP-3DES-MD5-96
 *
 * Revision 0.4  1997/01/15 01:28:15  ji
 * Added new transforms.
 *
 * Revision 0.3  1996/11/20 14:39:04  ji
 * Minor cleanups.
 * Rationalized debugging code.
 *
 * Revision 0.2  1996/11/02 00:18:33  ji
 * First limited release.
 *
 *
 */
