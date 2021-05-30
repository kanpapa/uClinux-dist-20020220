/*
 * declarations relevant to encapsulation-like operations
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
 * RCSID $Id: ipsec_encap.h,v 1.13 2001/06/14 19:35:08 rgb Exp $
 */

#define SENT_IP4	0x0008	/* data is two struct in_addr */
			/* (2 * sizeof(struct in_addr)) */
			/* sizeof(struct sockaddr_encap)
			   - offsetof(struct sockaddr_encap, Sen.Sip4.Src) */

#define SEN_HDRLEN	(2*sizeof(__u8)+sizeof(__u16))
			/* offsetof(struct sockaddr_encap, Sen.Sip4.Src) */

#define SEN_IP4_SRCOFF	(0)
#define SEN_IP4_DSTOFF (sizeof (struct in_addr))
			/* offsetof(struct sockaddr_encap, Sen.Sip4.Dst)
			   - offsetof(struct sockaddr_encap, Sen.Sip4.Src) */
#define SEN_IP4_OPTOFF	(2 * sizeof (struct in_addr))
			/* sizeof(struct sockaddr_encap)
			   - offsetof(struct sockaddr_encap, Sen.Sip4.Src) */

#define SEN_IP4_LEN	(SENT_HDRLEN + SENT_IP4_OPTOFF)
			/* sizeof(struct sockaddr_encap) */

#ifdef CONFIG_IPSEC_DEBUG
#define DB_ER_PROCFS	0x0001
#define DB_SP_PROCFS	0x0001
#endif /* CONFIG_IPSEC_DEBUG */

struct sockaddr_encap
{
	__u8	sen_len;		/* length */
	__u8	sen_family;		/* AF_ENCAP */
	__u16	sen_type;		/* see SENT_* */
	union
	{
		struct			/* SENT_IP4 */
		{
			struct in_addr Src;
			struct in_addr Dst;
		} Sip4;
	} Sen;
};

#define sen_ip_src	Sen.Sip4.Src
#define sen_ip_dst	Sen.Sip4.Dst

#ifndef AF_ENCAP
#define AF_ENCAP 26
#endif /* AF_ENCAP */

/*
 * The "type" is really part of the address as far as the routing
 * system is concerned. By using only one bit in the type field
 * for each type, we sort-of make sure that different types of
 * encapsulation addresses won't be matched against the wrong type.
 */

#ifdef __KERNEL__
/*
 * An entry in the radix tree 
 */

struct rjtentry
{
	struct	radij_node rd_nodes[2];	/* tree glue, and other values */
#define	rd_key(r)	((struct sockaddr_encap *)((r)->rd_nodes->rj_key))
#define	rd_mask(r)	((struct sockaddr_encap *)((r)->rd_nodes->rj_mask))
	short	rd_flags;
	short	rd_count;
};

/*
 * An encapsulation route consists of a pointer to a 
 * radix tree entry and a SAID (a destination_address/SPI/protocol triple).
 */

struct eroute
{
	struct rjtentry er_rjt;
	struct sa_id er_said;
	uint32_t er_pid;
	uint32_t er_count;
	uint64_t er_lasttime;
	struct sockaddr_encap er_eaddr;
	struct sockaddr_encap er_emask;
};

#define er_dst er_said.dst
#define er_spi er_said.spi
#define er_proto er_said.proto
#ifdef CONFIG_IPSEC_DEBUG
extern int debug_eroute;
extern int debug_spi;
#endif /* CONFIG_IPSEC_DEBUG */

#ifdef NETDEV_23
#define device net_device
#define ipsec_dev_get __dev_get_by_name
#else
#define ipsec_dev_get dev_get
#endif /* NETDEV_23 */
#endif /* __KERNEL__ */

/*
 * $Log: ipsec_encap.h,v $
 * Revision 1.13  2001/06/14 19:35:08  rgb
 * Update copyright date.
 *
 * Revision 1.12  2001/05/27 06:12:10  rgb
 * Added structures for pid, packet count and last access time to eroute.
 * Added packet count to beginning of /proc/net/ipsec_eroute.
 *
 * Revision 1.11  2000/09/08 19:12:56  rgb
 * Change references from DEBUG_IPSEC to CONFIG_IPSEC_DEBUG.
 *
 * Revision 1.10  2000/03/22 16:15:36  rgb
 * Fixed renaming of dev_get (MB).
 *
 * Revision 1.9  2000/01/21 06:13:26  rgb
 * Added a macro for AF_ENCAP
 *
 * Revision 1.8  1999/12/31 14:56:55  rgb
 * MB fix for 2.3 dev-use-count.
 *
 * Revision 1.7  1999/11/18 04:09:18  rgb
 * Replaced all kernel version macros to shorter, readable form.
 *
 * Revision 1.6  1999/09/24 00:34:13  rgb
 * Add Marc Boucher's support for 2.3.xx+.
 *
 * Revision 1.5  1999/04/11 00:28:57  henry
 * GPL boilerplate
 *
 * Revision 1.4  1999/04/06 04:54:25  rgb
 * Fix/Add RCSID Id: and Log: bits to make PHMDs happy.  This includes
 * patch shell fixes.
 *
 * Revision 1.3  1998/10/19 14:44:28  rgb
 * Added inclusion of freeswan.h.
 * sa_id structure implemented and used: now includes protocol.
 *
 * Revision 1.2  1998/07/14 18:19:33  rgb
 * Added #ifdef __KERNEL__ directives to restrict scope of header.
 *
 * Revision 1.1  1998/06/18 21:27:44  henry
 * move sources from klips/src to klips/net/ipsec, to keep stupid
 * kernel-build scripts happier in the presence of symlinks
 *
 * Revision 1.2  1998/04/21 21:29:10  rgb
 * Rearrange debug switches to change on the fly debug output from user
 * space.  Only kernel changes checked in at this time.  radij.c was also
 * changed to temporarily remove buggy debugging code in rj_delete causing
 * an OOPS and hence, netlink device open errors.
 *
 * Revision 1.1  1998/04/09 03:05:58  henry
 * sources moved up from linux/net/ipsec
 *
 * Revision 1.1.1.1  1998/04/08 05:35:02  henry
 * RGB's ipsec-0.8pre2.tar.gz ipsec-0.8
 *
 * Revision 0.4  1997/01/15 01:28:15  ji
 * Minor cosmetic changes.
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
