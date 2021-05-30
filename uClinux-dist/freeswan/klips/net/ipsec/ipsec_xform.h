/*
 * Definitions relevant to IPSEC transformations
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
 * RCSID $Id: ipsec_xform.h,v 1.31 2001/06/14 19:35:11 rgb Exp $
 */

#include <freeswan.h>

#define XF_NONE			0	/* No transform set */
#define XF_IP4			1	/* IPv4 inside IPv4 */
#define XF_AHMD5		2	/* AH MD5 */
#define XF_AHSHA		3	/* AH SHA */
#define XF_ESPDES		4	/* ESP DES-CBC */
#define XF_ESP3DES		5	/* ESP DES3-CBC */
#define XF_AHHMACMD5		6	/* AH-HMAC-MD5 with opt replay prot */
#define XF_AHHMACSHA1		7	/* AH-HMAC-SHA1 with opt replay prot */
#define XF_ESPDESMD5		8	/* DES, HMAC-MD-5, 128-bits of authentication */
#define XF_ESPDESMD596		9	/* DES, HMAC-MD-5, 96-bits of authentication */
#define XF_ESP3DESMD5		10	/* triple DES, HMAC-MD-5, 128-bits of authentication */
#define	XF_ESP3DESMD596		11	/* triple DES, HMAC-MD-5, 96-bits of authentication */
#define	XF_ESPNULLMD596		12	/* NULL, HMAC-MD-5 with 96-bits of authentication */
#define	XF_ESPNULLSHA196	13	/* NULL, HMAC-SHA-1 with 96-bits of authentication */
#define	XF_ESPDESSHA196		14	/* DES, HMAC-SHA-1, 96-bits of authentication */
#define	XF_ESP3DESSHA196	15	/* triple DES, HMAC-SHA-1, 96-bits of authentication */
#define XF_IP6			16	/* IPv6 inside IPv6 */
#define XF_COMPDEFLATE		17	/* IPCOMP deflate */

#define XF_CLR			126	/* Clear SA table */
#define XF_DEL			127	/* Delete SA */

/* IPsec AH transform values
 * RFC 2407
 * draft-ietf-ipsec-doi-tc-mib-02.txt
 */

#define AH_NONE                  0
#define AH_MD5                   2
#define AH_SHA                   3

/* IPsec ESP transform values */

#define ESP_NONE		 0
#define ESP_DES			 2
#define ESP_3DES                 3
#define ESP_RC5                  4
#define ESP_IDEA                 5
#define ESP_CAST                 6
#define ESP_BLOWFISH             7
#define ESP_3IDEA                8
#define ESP_RC4                 10
#define ESP_NULL                11

/* IPCOMP transform values */

#define IPCOMP_NONE              0
#define IPCOMP_OUI               1
#define IPCOMP_DEFLAT            2
#define IPCOMP_LZS               3
#define IPCOMP_V42BIS            4

#define XFT_AUTH	0x0001
#define XFT_CONF	0x0100

#ifdef CONFIG_IPSEC_DEBUG
#define DB_XF_INIT	0x0001
#endif /* CONFIG_IPSEC_DEBUG */

#ifdef __KERNEL__
/* 'struct tdb' should really be 64bit aligned... XXX */
struct tdb				/* tunnel descriptor block */
{
	struct tdb	*tdb_hnext;	/* next in hash chain */
	struct tdb	*tdb_onext;	/* next in output */
	struct tdb	*tdb_inext;	/* next in input (prev!) */
	struct ifnet	*tdb_rcvif;	/* related rcv encap interface */
	struct sa_id	tdb_said;	/* SA ID */
	__u32	tdb_seq;	/* seq num of msg that initiated this SA */
	__u32	tdb_pid;	/* PID of process that initiated this SA */
	__u8		tdb_authalg;	/* auth algorithm for this SA */
	__u8		tdb_encalg;	/* enc algorithm for this SA */

	__u32		tdb_alg_errs;	/* number of algorithm errors */
	__u32	tdb_auth_errs;	/* number of authentication errors */
	__u32	tdb_encsize_errs;	/* number of encryption size errors */
	__u32	tdb_encpad_errs;	/* number of encryption size errors */
	__u32	tdb_replaywin_errs;	/* number of pkt sequence errors */

	__u8		tdb_replaywin;	/* replay window size */
	__u8		tdb_state;	/* state of SA */
	__u32	tdb_replaywin_lastseq;	/* last pkt sequence num */
	__u64	tdb_replaywin_bitmap;	/* bitmap of received pkts */
	__u32	tdb_replaywin_maxdiff;	/* maximum pkt sequence difference */

	__u32	tdb_flags;	/* generic xform flags */

	__u32	tdb_lifetime_allocations_c;	/* see rfc2367 */
	__u32	tdb_lifetime_allocations_s;
	__u32	tdb_lifetime_allocations_h;
	__u64	tdb_lifetime_bytes_c;
	__u64	tdb_lifetime_bytes_s;
	__u64	tdb_lifetime_bytes_h;
	__u64	tdb_lifetime_addtime_c;
	__u64	tdb_lifetime_addtime_s;
	__u64	tdb_lifetime_addtime_h;
	__u64	tdb_lifetime_usetime_c;
	__u64	tdb_lifetime_usetime_s;
	__u64	tdb_lifetime_usetime_h;
	__u64	tdb_lifetime_packets_c;
	__u64	tdb_lifetime_packets_s;
	__u64	tdb_lifetime_packets_h;
	__u64	tdb_lifetime_usetime_l;	/* last time transform was used */
	struct sockaddr	*tdb_addr_s;	/* src sockaddr */
	struct sockaddr	*tdb_addr_d;	/* dst sockaddr */
       	struct sockaddr	*tdb_addr_p;	/* proxy sockaddr */
	__u16	tdb_addr_s_size;
	__u16	tdb_addr_d_size;
	__u16	tdb_addr_p_size;
	__u16	tdb_key_bits_a;	/* size of authkey in bits */
	__u16	tdb_auth_bits;	/* size of authenticator in bits */
	__u16	tdb_key_bits_e;	/* size of enckey in bits */
	__u16	tdb_iv_bits;	/* size of IV in bits */

	__u8	tdb_iv_size;
	__u16	tdb_key_a_size;
	__u16	tdb_key_e_size;
	caddr_t	tdb_key_a;	/* authentication key */
	caddr_t	tdb_key_e;	/* encryption key */
	caddr_t	tdb_iv;		/* Initialisation Vector */
	__u16	tdb_ident_type_s;	/* src identity type */
	__u16	tdb_ident_type_d;	/* dst identity type */
	__u64	tdb_ident_id_s;	/* src identity id */
	__u64	tdb_ident_id_d;	/* dst identity id */
	__u8	tdb_ident_len_s;	/* src identity type */
	__u8	tdb_ident_len_d;	/* dst identity type */
	caddr_t	tdb_ident_data_s;	/* src identity data */
	caddr_t	tdb_ident_data_d;	/* dst identity data */
#ifdef CONFIG_IPSEC_IPCOMP
	__u16	tdb_comp_adapt_tries;   /* ipcomp self-adaption tries */
	__u16	tdb_comp_adapt_skip;    /* ipcomp self-adaption to-skip */
	__u64	tdb_comp_ratio_cbytes;	/* compressed bytes */
	__u64	tdb_comp_ratio_dbytes;	/* decompressed (or uncompressed) bytes */
#endif /* CONFIG_IPSEC_IPCOMP */
#if 0
	__u32	tdb_sens_dpd;
	__u8	tdb_sens_sens_level;
	__u8	tdb_sens_sens_len;
	__u64*	tdb_sens_sens_bitmap;
	__u8	tdb_sens_integ_level;
	__u8	tdb_sens_integ_len;
	__u64*	tdb_sens_integ_bitmap;
#endif
};

#define PROTO2TXT(x) \
	(x) == IPPROTO_AH ? "AH" : \
	(x) == IPPROTO_ESP ? "ESP" : \
	(x) == IPPROTO_IPIP ? "IPIP" : \
	(x) == IPPROTO_COMP ? "COMP" : \
	"UNKNOWN_proto"

#if 0
	(x)->tdb_said.proto == IPPROTO_AH ? "AH" : \
	(x)->tdb_said.proto == IPPROTO_ESP ? "ESP" : \
	(x)->tdb_said.proto == IPPROTO_IPIP ? "IPIP" : \
	(x)->tdb_said.proto == IPPROTO_COMP ? "COMP" : \
	"UNKNOWN_proto", \

#endif
#define TDB_XFORM_NAME(x) \
	PROTO2TXT((x)->tdb_said.proto), \
	(x)->tdb_said.proto == IPPROTO_COMP ? \
		((x)->tdb_encalg == SADB_X_CALG_DEFLATE ? \
		 "_DEFLATE" : "_UNKNOWN_comp") : \
	(x)->tdb_encalg == ESP_NONE ? "" : \
	(x)->tdb_encalg == ESP_DES ? "_DES" : \
	(x)->tdb_encalg == ESP_3DES ? "_3DES" : \
	"_UNKNOWN_encr", \
	(x)->tdb_authalg == AH_NONE ? "" : \
	(x)->tdb_authalg == AH_MD5 ? "_HMAC_MD5" : \
	(x)->tdb_authalg == AH_SHA ? "_HMAC_SHA1" : \
	"_UNKNOWN_auth" \

#define TDB_HASHMOD	257

struct xformsw
{
	u_short		xf_type;	/* Unique ID of xform */
	u_short		xf_flags;	/* secondary type reall) */
	char		*xf_name;	/* human-readable name */
};

extern struct tdb *tdbh[TDB_HASHMOD];
extern spinlock_t tdb_lock;
extern struct xformsw xformsw[], *xformswNXFORMSW;

extern int ipsec_tdbinit(void);
extern struct tdb *gettdb(struct sa_id*);
extern /* void */ int deltdb(struct tdb *);
extern /* void */ int deltdbchain(struct tdb *);
extern /* void */ int puttdb(struct tdb *);
extern int tdb_init(struct tdb *, struct encap_msghdr *);
extern int ipsec_tdbcleanup(__u8);
extern int ipsec_tdbwipe(struct tdb *);

#ifdef CONFIG_IPSEC_DEBUG
extern int debug_xform;
#endif /* CONFIG_IPSEC_DEBUG */
#endif /* __KERNEL__ */

/*
 * $Log: ipsec_xform.h,v $
 * Revision 1.31  2001/06/14 19:35:11  rgb
 * Update copyright date.
 *
 * Revision 1.30  2001/05/30 08:14:03  rgb
 * Removed vestiges of esp-null transforms.
 *
 * Revision 1.29  2001/01/30 23:42:47  rgb
 * Allow pfkey msgs from pid other than user context required for ACQUIRE
 * and subsequent ADD or UDATE.
 *
 * Revision 1.28  2000/11/06 04:30:40  rgb
 * Add Svenning's adaptive content compression.
 *
 * Revision 1.27  2000/09/19 00:38:25  rgb
 * Fixed algorithm name bugs introduced for ipcomp.
 *
 * Revision 1.26  2000/09/17 21:36:48  rgb
 * Added proto2txt macro.
 *
 * Revision 1.25  2000/09/17 18:56:47  rgb
 * Added IPCOMP support.
 *
 * Revision 1.24  2000/09/12 19:34:12  rgb
 * Defined XF_IP6 from Gerhard for ipv6 tunnel support.
 *
 * Revision 1.23  2000/09/12 03:23:14  rgb
 * Cleaned out now unused tdb_xform and tdb_xdata members of struct tdb.
 *
 * Revision 1.22  2000/09/08 19:12:56  rgb
 * Change references from DEBUG_IPSEC to CONFIG_IPSEC_DEBUG.
 *
 * Revision 1.21  2000/09/01 18:32:43  rgb
 * Added (disabled) sensitivity members to tdb struct.
 *
 * Revision 1.20  2000/08/30 05:31:01  rgb
 * Removed all the rest of the references to tdb_spi, tdb_proto, tdb_dst.
 * Kill remainder of tdb_xform, tdb_xdata, xformsw.
 *
 * Revision 1.19  2000/08/01 14:51:52  rgb
 * Removed _all_ remaining traces of DES.
 *
 * Revision 1.18  2000/01/21 06:17:45  rgb
 * Tidied up spacing.
 *
 * Revision 1.17  1999/11/17 15:53:40  rgb
 * Changed all occurrences of #include "../../../lib/freeswan.h"
 * to #include <freeswan.h> which works due to -Ilibfreeswan in the
 * klips/net/ipsec/Makefile.
 *
 * Revision 1.16  1999/10/16 04:23:07  rgb
 * Add stats for replaywin_errs, replaywin_max_sequence_difference,
 * authentication errors, encryption size errors, encryption padding
 * errors, and time since last packet.
 *
 * Revision 1.15  1999/10/16 00:29:11  rgb
 * Added SA lifetime packet counting variables.
 *
 * Revision 1.14  1999/10/01 00:04:14  rgb
 * Added tdb structure locking.
 * Add function to initialize tdb hash table.
 *
 * Revision 1.13  1999/04/29 15:20:57  rgb
 * dd return values to init and cleanup functions.
 * Eliminate unnessessary usage of tdb_xform member to further switch
 * away from the transform switch to the algorithm switch.
 * Change gettdb parameter to a pointer to reduce stack loading and
 * facilitate parameter sanity checking.
 * Add a parameter to tdbcleanup to be able to delete a class of SAs.
 *
 * Revision 1.12  1999/04/15 15:37:25  rgb
 * Forward check changes from POST1_00 branch.
 *
 * Revision 1.9.2.2  1999/04/13 20:35:57  rgb
 * Fix spelling mistake in comment.
 *
 * Revision 1.9.2.1  1999/03/30 17:13:52  rgb
 * Extend struct tdb to support pfkey.
 *
 * Revision 1.11  1999/04/11 00:29:01  henry
 * GPL boilerplate
 *
 * Revision 1.10  1999/04/06 04:54:28  rgb
 * Fix/Add RCSID Id: and Log: bits to make PHMDs happy.  This includes
 * patch shell fixes.
 *
 * Revision 1.9  1999/01/26 02:09:31  rgb
 * Removed CONFIG_IPSEC_ALGO_SWITCH macro.
 * Removed dead code.
 *
 * Revision 1.8  1999/01/22 06:29:35  rgb
 * Added algorithm switch code.
 * Cruft clean-out.
 *
 * Revision 1.7  1998/11/10 05:37:35  rgb
 * Add support for SA direction flag.
 *
 * Revision 1.6  1998/10/19 14:44:29  rgb
 * Added inclusion of freeswan.h.
 * sa_id structure implemented and used: now includes protocol.
 *
 * Revision 1.5  1998/08/12 00:12:30  rgb
 * Added macros for new xforms.  Added prototypes for new xforms.
 *
 * Revision 1.4  1998/07/28 00:04:20  rgb
 * Add macro for clearing the SA table.
 *
 * Revision 1.3  1998/07/14 18:06:46  rgb
 * Added #ifdef __KERNEL__ directives to restrict scope of header.
 *
 * Revision 1.2  1998/06/23 03:02:19  rgb
 * Created a prototype for ipsec_tdbcleanup when it was moved from
 * ipsec_init.c.
 *
 * Revision 1.1  1998/06/18 21:27:51  henry
 * move sources from klips/src to klips/net/ipsec, to keep stupid
 * kernel-build scripts happier in the presence of symlinks
 *
 * Revision 1.4  1998/06/11 05:55:31  rgb
 * Added transform version string pointer to xformsw structure definition.
 * Added extern declarations for transform version strings.
 *
 * Revision 1.3  1998/05/18 22:02:54  rgb
 * Modify the *_zeroize function prototypes to include one parameter.
 *
 * Revision 1.2  1998/04/21 21:29:08  rgb
 * Rearrange debug switches to change on the fly debug output from user
 * space.  Only kernel changes checked in at this time.  radij.c was also
 * changed to temporarily remove buggy debugging code in rj_delete causing
 * an OOPS and hence, netlink device open errors.
 *
 * Revision 1.1  1998/04/09 03:06:14  henry
 * sources moved up from linux/net/ipsec
 *
 * Revision 1.1.1.1  1998/04/08 05:35:06  henry
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
