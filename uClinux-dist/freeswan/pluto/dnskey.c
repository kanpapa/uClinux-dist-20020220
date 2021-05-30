/* Find public key in DNS
 * Copyright (C) 2000  D. Hugh Redelmeier.
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
 * RCSID $Id: dnskey.c,v 1.24 2001/04/09 19:48:40 dhr Exp $
 */

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <netdb.h>	/* ??? for h_errno */

#include <freeswan.h>

#include "constants.h"
#include "defs.h"
#include "id.h"
#include "log.h"
#include "connections.h"	/* needs id.h */
#include "preshared.h"	    /* needs connections.h */
#include "dnskey.h"
#include "packet.h"
#include "timer.h"

/* The interface in RHL6.x and BIND distribution 8.2.2 are different,
 * so we build some of our own :-(
 */

static err_t do_dns_query(const struct id *id, const struct id *peerid
    , int type, const char *typename);	/* forward */

/* Support deprecated interface to allow for older releases of the resolver.
 * Fake new interface!
 * See resolver(3) bind distribution (should be in RHL6.1, but isn't).
 * __RES was 19960801 in RHL6.2, an old resolver.
 */

#if (__RES) <= 19960801
# define OLD_RESOLVER	1
#endif

#ifdef OLD_RESOLVER

# ifndef NS_MAXDNAME
#   define NS_MAXDNAME MAXDNAME /* I hope this is long enough for IPv6 */
# endif
# ifndef NS_PACKETSZ
#   define NS_PACKETSZ PACKETSZ
# endif

# define res_ninit(statp) res_init()
# define res_nquery(statp, dname, class, type, answer, anslen) \
    res_query(dname, class, type, answer, anslen)
# define res_nclose(statp) res_close()

#ifndef EMBED
static struct __res_state *statp = &_res;
#endif

#else /* !OLD_RESOLVER */

static struct __res_state my_res_state /* = { 0 } */;
static res_state statp = &my_res_state;

#endif /* !OLD_RESOLVER */




/* structure of Query Reply (RFC 1035 4.1.1):
 *
 *  +---------------------+
 *  |        Header       |
 *  +---------------------+
 *  |       Question      | the question for the name server
 *  +---------------------+
 *  |        Answer       | RRs answering the question
 *  +---------------------+
 *  |      Authority      | RRs pointing toward an authority
 *  +---------------------+
 *  |      Additional     | RRs holding additional information
 *  +---------------------+
 */

/* Header section format (as modified by RFC 2535 6.1):
 *                                  1  1  1  1  1  1
 *    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                      ID                       |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |QR|   Opcode  |AA|TC|RD|RA| Z|AD|CD|   RCODE   |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                    QDCOUNT                    |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                    ANCOUNT                    |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                    NSCOUNT                    |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                    ARCOUNT                    |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */
struct qr_header {
    u_int16_t	id;	/* 16-bit identifier to match query */

    u_int16_t	stuff;	/* packed crud: */

#define QRS_QR	0x8000	/* QR: on if this is a response */

#define QRS_OPCODE_SHIFT	11  /* OPCODE field */
#define QRS_OPCODE_MASK	0xF
#define QRSO_QUERY	0   /* standard query */
#define QRSO_IQUERY	1   /* inverse query */
#define QRSO_STATUS	2   /* server status request query */

#define QRS_AA 0x0400	/* AA: on if Authoritativ Answer */
#define QRS_TC 0x0200	/* TC: on if truncation happened */
#define QRS_RD 0x0100	/* RD: on if recursion desired */
#define QRS_RA 0x0080	/* RA: on if recursion available */
#define QRS_Z  0x0040	/* Z: reserved; must be zero */
#define QRS_AD 0x0020	/* AD: on if authentic data (RFC 2535) */
#define QRS_CD 0x0010	/* AD: on if checking disabled (RFC 2535) */

#define QRS_RCODE_SHIFT	0 /* RCODE field: response code */
#define QRS_RCODE_MASK	0xF
#define QRSR_OK	    0


    u_int16_t qdcount;	    /* number of entries in question section */
    u_int16_t ancount;	    /* number of resource records in answer section */
    u_int16_t nscount;	    /* number of name server resource records in authority section */
    u_int16_t arcount;	    /* number of resource records in additional records section */
};

static field_desc qr_header_fields[] = {
    { ft_nat, 16/BITS_PER_BYTE, "ID", NULL },
    { ft_nat, 16/BITS_PER_BYTE, "stuff", NULL },
    { ft_nat, 16/BITS_PER_BYTE, "QD Count", NULL },
    { ft_nat, 16/BITS_PER_BYTE, "Answer Count", NULL },
    { ft_nat, 16/BITS_PER_BYTE, "Authority Count", NULL },
    { ft_nat, 16/BITS_PER_BYTE, "Additional Count", NULL },
    { ft_end, 0, NULL, NULL }
};

static struct_desc qr_header_desc = {
    "Query Response Header",
    qr_header_fields,
    sizeof(struct qr_header)
};

/* Messages for codes in RCODE (see RFC 1035 4.1.1) */
static const err_t rcode_text[QRS_RCODE_MASK + 1] = {
    NULL,   /* not an error */
    "Format error - The name server was unable to interpret the query",
    "Server failure - The name server was unable to process this query"
	" due to a problem with the name server",
    "Name Error - Meaningful only for responses from an authoritative name"
	" server, this code signifies that the domain name referenced in"
	" the query does not exist",
    "Not Implemented - The name server does not support the requested"
	" kind of query",
    "Refused - The name server refuses to perform the specified operation"
	" for policy reasons",
    /* the rest are reserved for future use */
    };

/* throw away a possibly compressed domain name */

static err_t
eat_name(pb_stream *pbs)
{
    u_char name_buf[NS_MAXDNAME + 2];
    u_char *ip = pbs->cur;
    unsigned oi = 0;
    unsigned jump_count = 0;

    for (;;)
    {
	u_int8_t b;

	if (ip >= pbs->roof)
	    return "ran out of message while skipping domain name";

	b = *ip++;
	if (jump_count == 0)
	    pbs->cur = ip;

	if (b == 0)
	    break;

	switch (b & 0xC0)
	{
	    case 0x00:
		/* we grab the next b characters */
		if (oi + b > NS_MAXDNAME)
		    return "domain name too long";

		if (pbs->roof - ip <= b)
		    return "domain name falls off end of message";

		if (oi != 0)
		    name_buf[oi++] = '.';

		memcpy(name_buf + oi, ip, b);
		oi += b;
		ip += b;
		if (jump_count == 0)
		    pbs->cur = ip;
		break;

	    case 0xC0:
		{
		    unsigned ix;

		    if (ip >= pbs->roof)
			return "ran out of message in middle of compressed domain name";

		    ix = ((b & ~0xC0u) << 8) | *ip++;
		    if (jump_count == 0)
			pbs->cur = ip;

		    if (ix >= pbs_room(pbs))
			return "impossible compressed domain name";

		    /* Avoid infinite loop.
		     * There can be no more jumps than there are bytes
		     * in the packet.  Not a tight limit, but good enough.
		     */
		    jump_count++;
		    if (jump_count > pbs_room(pbs))
			return "loop in compressed domain name";

		    ip = pbs->start + ix;
		}
		break;

	    default:
		return "invalid code in label";
	}
    }

    name_buf[oi++] = '\0';

    DBG(DBG_PARSING, DBG_log("skipping name %s", name_buf));

    return NULL;
}

static err_t
eat_name_helpfully(pb_stream *pbs, const char *context)
{
    err_t ugh = eat_name(pbs);

    return ugh == NULL? ugh
	: builddiag("malformed name within DNS record of %s: %s", context, ugh);
}

/* non-variable part of 4.1.2 Question Section entry:
 *                                 1  1  1  1  1  1
 *   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                                               |
 * /                     QNAME                     /
 * /                                               /
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                     QTYPE                     |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                     QCLASS                    |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */

struct qs_fixed {
    u_int16_t qtype;
    u_int16_t qclass;
};

static field_desc qs_fixed_fields[] = {
    { ft_loose_enum, 16/BITS_PER_BYTE, "QTYPE", &rr_qtype_names },
    { ft_loose_enum, 16/BITS_PER_BYTE, "QCLASS", &rr_class_names },
    { ft_end, 0, NULL, NULL }
};

static struct_desc qs_fixed_desc = {
    "Question Section entry fixed part",
    qs_fixed_fields,
    sizeof(struct qs_fixed)
};

/* 4.1.3. Resource record format:
 *                                 1  1  1  1  1  1
 *   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                                               |
 * /                                               /
 * /                      NAME                     /
 * |                                               |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                      TYPE                     |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                     CLASS                     |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                      TTL                      |
 * |                                               |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                   RDLENGTH                    |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
 * /                     RDATA                     /
 * /                                               /
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */

struct rr_fixed {
    u_int16_t type;
    u_int16_t class;
    u_int32_t ttl;	/* actually signed */
    u_int16_t rdlength;
};


static field_desc rr_fixed_fields[] = {
    { ft_loose_enum, 16/BITS_PER_BYTE, "type", &rr_type_names },
    { ft_loose_enum, 16/BITS_PER_BYTE, "class", &rr_class_names },
    { ft_nat, 32/BITS_PER_BYTE, "TTL", NULL },
    { ft_nat, 16/BITS_PER_BYTE, "RD length", NULL },
    { ft_end, 0, NULL, NULL }
};

static struct_desc rr_fixed_desc = {
    "Resource Record fixed part",
    rr_fixed_fields,
    /* note: following is tricky: avoids padding problems */
    offsetof(struct rr_fixed, rdlength) + sizeof(u_int16_t)
};

/* RFC 1035 3.3.14: TXT RRs have text in the RDATA field.
 * It is in the form of a sequence of <character-string>s as described in 3.3.
 * unpack_txt_rdata() deals with this peculiar representation.
 */

/* RFC 2535 3.1 KEY RDATA format:
 *
 *                      1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |             flags             |    protocol   |   algorithm   |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               /
 * /                          public key                           /
 * /                                                               /
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
 */

struct key_rdata {
    u_int16_t flags;
    u_int8_t protocol;
    u_int8_t algorithm;
};

static field_desc key_rdata_fields[] = {
    { ft_nat, 16/BITS_PER_BYTE, "flags", NULL },
    { ft_nat, 8/BITS_PER_BYTE, "protocol", NULL },
    { ft_nat, 8/BITS_PER_BYTE, "algorithm", NULL },
    { ft_end, 0, NULL, NULL }
};

static struct_desc key_rdata_desc = {
    "KEY RR RData fixed part",
    key_rdata_fields,
    sizeof(struct key_rdata)
};

/****************************************************************/

static err_t
init_dns(void)
{
    static bool inited = FALSE;

    if (!inited)
    {
	int r = res_ninit(statp);

	if (r != 0)
	    return "undocumented failure of res_ninit";

	inited = TRUE;
#ifndef OLD_RESOLVER
	statp->options |= RES_ROTATE;
#ifdef RES_DEBUG
	statp->options |= RES_DEBUG;
#endif
#endif
    }
    return NULL;
}

static err_t
build_dns_name(u_char name_buf[NS_MAXDNAME + 2], const struct id *id
, const char *typename)
{
    /* note: all end in "." to suppress relative searches */
    switch (id->kind)
    {
    case ID_IPV4_ADDR:
    {
	/* XXX: this is really ugly and only temporary until addrtot can
	 *      generate the correct format
	 */
	const unsigned char *b;
	size_t bl = addrbytesptr(&id->ip_addr, &b);

	passert(bl == 4);
	snprintf(name_buf, NS_MAXDNAME + 2, "%d.%d.%d.%d.in-addr.arpa."
	    , b[3], b[2], b[1], b[0]);
	break;
    }

    case ID_IPV6_ADDR:
    {
	/* ??? is this correct? */
	const unsigned char *b;
	size_t bl;
	u_char *op = name_buf;
	static const char suffix[] = "IP6.INT.";

	for (bl = addrbytesptr(&id->ip_addr, &b); bl-- != 0; )
	{
	    if (op + 4 + sizeof(suffix) >= name_buf + NS_MAXDNAME + 1)
		return "IPv6 reverse name too long";
	    op += sprintf(op, "%x.%x.", b[bl] & 0xF, b[bl] >> 4);
	}
	strcpy(op, suffix);
	break;
    }

    case ID_FQDN:
	if (id->name.len > NS_MAXDNAME)
	    return "FQDN too long for domain name";

	memcpy(name_buf, id->name.ptr, id->name.len);
	strcpy(name_buf + id->name.len, ".");
	break;

    default:
	return "can only query DNS for key for ID that is a FQDN, IPV4_ADDR, or IPV6_ADDR";
    }

    DBG(DBG_CONTROL, DBG_log("Querying DNS for %s for %s"
	, typename, name_buf));
    return NULL;
}

static err_t
process_key_rr(u_char *ptr, size_t len, chunk_t *k)
{
    pb_stream pbs;
    struct key_rdata kr;

    if (len < sizeof(struct key_rdata))
	return "KEY Resource Record's RD Length is too small";

    init_pbs(&pbs, ptr, len, "KEY RR");

    if (!in_struct(&kr, &key_rdata_desc, &pbs, NULL))
	return "failed to get fixed part or KEY Resource Record RDATA";

    if (kr.protocol == 4	/* IPSEC (RFC 2535 3.1.3) */
    && kr.algorithm == 1	/* RSA/MD5 (RFC 2535 3.2) */
    && (kr.flags & 0x8000) == 0	/* use for authentication (3.1.2) */
    && (kr.flags & 0x2CF0) == 0)	/* must be zero */
    {
	/* we have what seems to be a tasty key */
	if (k->ptr != NULL)
	    return "too many keys found: only one allowed";

	k->len = pbs_left(&pbs);
	k->ptr = pbs.cur;
    }
    return NULL;
}

/* unpack TXT rr RDATA into C string.
 * A sequence of <character-string>s as described in RFC 1035 3.3.
 * We concatenate them.  If a count is less than 255, we add a space
 * because that looks more like the "source" version of the record.
 */
static err_t
unpack_txt_rdata(u_char *d, size_t dlen, const u_char *s, size_t slen)
{
    size_t i = 0
	, o = 0;

    while (i < slen)
    {
	size_t cl = s[i++];
	int add_sp = cl < 255 && i + cl != slen;	/* reconstitute whitespace? */

	if (i + cl > slen)
	    return "TXT rr RDATA representation malformed";

	if (o + cl + add_sp >= dlen)
	    return "TXT rr RDATA too large";

	memcpy(d + o, s + i, cl);
	i += cl;
	o += cl;
	if (add_sp)
	    d[o++] = ' ';
    }
    d[o] = '\0';
    if (strlen(d) != o)
	return "TXT rr RDATA contains a NUL";

    return NULL;
}

/* info relevant for T_TXT X-IPsec-Server */

#define our_TXT_attr_string "X-IPsec-Server"
static const char our_TXT_attr[] = our_TXT_attr_string;

struct rr_index {
    const u_char *rdata;
    size_t rdlen;
    size_t offset;
};

struct txt_tbl {
    int count;
    unsigned long pref;	/* NB: meaningful only if txt isn't empty */
    struct rr_index rr[10];	/* arbitrary limit: ignore after first 10 */
};

static err_t
decode_iii(u_char **pp, const struct id *client_id, struct id *gw_id)
{
    u_char *p = *pp + strspn(*pp, " \t");
    u_char *e = p + strcspn(p, " \t");
    u_char under = *e;

    if (p == e)
	return "TXT " our_TXT_attr_string " badly formed (no gateway specified)";

    *e = '\0';
    if (*p == '@')
    {
	/* gateway specification in this record is @FQDN */
	err_t ugh = atoid(p, gw_id);

	if (ugh != NULL)
	    return builddiag("malformed FQDN in TXT " our_TXT_attr_string ": %s"
		, ugh);
    }
    else
    {
	/* gateway specification is numeric */
	ip_address ip;
	err_t ugh = tnatoaddr(p, e-p
	    , strchr(p, ':') == NULL? AF_INET : AF_INET6
	    , &ip);

	if (ugh != NULL)
	    return builddiag("malformed IP address in TXT " our_TXT_attr_string ": %s"
		, ugh);

	if (isanyaddr(&ip))
	    return "gateway address must not be 0.0.0.0 or 0::0";

	iptoid(&ip, gw_id);
    }

    *e = under;
    *pp = e + strspn(e, " \t");

    DBG(DBG_CONTROL,
	{
	    char cidb[IDTOA_BUF];
	    char pidb[IDTOA_BUF];

	    idtoa(client_id, cidb, sizeof(cidb));
	    idtoa(gw_id, pidb, sizeof(cidb));
	    DBG_log("decoding TXT %s record for %s: security gateway %s"
		, our_TXT_attr, cidb, pidb);
	});
    return NULL;
}

static err_t
accumulate_txt_rr(u_char *rdata, size_t rdlen, struct txt_tbl *tt
, const struct id *client_id, const struct id *peer_id)
{
    u_char str[2049];	/* space for unpacked RDATA */
    u_char *p = str;
    unsigned long pref = 0;
    struct id sgw_id;

    {
	err_t ugh = unpack_txt_rdata(str, sizeof(str), rdata, rdlen);

	if (ugh != NULL)
	    return ugh;
    }

    p += strspn(p, " \t");	/* ignore leading whitespace */

    /* is this for us? */
    if (strncasecmp(p, our_TXT_attr, sizeof(our_TXT_attr)-1) != 0)
	return NULL;	/* neither interesting nor bad */

    p += sizeof(our_TXT_attr) - 1;	/* ignore our attribute name */
    p += strspn(p, " \t");	/* ignore leading whitespace */

    /* decode '(' pref ')' */
    if (*p != '(')
	return "X-IPsec-Server missing '('";

    {
	char *e;

	p++;
	pref = strtoul(p, &e, 0);
	if ((u_char *)e == p)
	    return "malformed X-IPsec-Server priority";

	p = e + strspn(e, " \t");

	if (*p != ')')
	    return "X-IPsec-Server priority missing ')'";

	p++;
	p += strspn(p, " \t");

	if (pref > 0xFFFF)
	    return "X-IPsec-Server priority larger than 0xFFFF";
    }

    /* time for '=' */

    if (*p != '=')
	return "X-IPsec-Server priority missing '='";

    p++;
    p += strspn(p, " \t");

    /* Decode iii (Security Gateway ID).
     * For simplicity, we don't save the decoded ID because
     * we'd have to allocate memory for the strings in the id.
     * (There are ways to excuse ourselves, but they are too tricky
     * by half: the only time the ID would get used, it would only
     * be an IP address.)
     */
    {
	u_char *q = p;	/* so p isn't updated */
	err_t ugh = decode_iii(&q, client_id, &sgw_id);

	if (ugh != NULL)
	    return ugh;

	if (peer_id == NULL)
	{
	    /* we're looking for a gateway spec with an IP address */
	    if (!id_is_ipaddr(&sgw_id))
		return NULL;	/* we cannot use this record, but it isn't wrong */
	}
	else
	{
	    /* we're looking for a gatway spec that confirms what we were told */
	    if (!same_id(peer_id, &sgw_id))
		return NULL;	/* we cannot use this record, but it isn't wrong */
	}
    }

    if (tt->count == 0)
	tt->pref = pref;

    if (tt->pref > pref)
    {
	/* earlier accumulation trumped by this one */
	tt->count = 0;
	tt->pref = pref;
    }

    if (tt->pref == pref
    && tt->count < (int)elemsof(tt->rr))
    {
	/* accumulate this rr */
	struct rr_index *i = &tt->rr[tt->count++];

	i->rdata = rdata;
	i->rdlen = rdlen;
	i->offset = p - str;
    }

    return NULL;
}

/* list of gateways for Opportunistic initiation.
 * Found by reverse lookup of client.
 * One entry for each (non-local) client we've looked up.
 * There could be sharing of peer info, but commonality is likely low.
 * Besides, a supposed client could lie about peer, and we don't want that
 * to prevent other clients from using that peer.
 * Entries must not be freed without first clearing out references
 * from struct connection objects.
 */
static struct gw_info *gateways = NULL;

/* process TXT X-IPsec-Server record of remote client to discover its
 * Security Gatway.
 * Format of body (the part we get): iii kkk
 * where iii is @FQDN or dotted-decimal IPv4 address or colon-hex IPv6 address
 * and kkk is an optional RSA public signing key in base 64.
 * Side effect: result is added at front of gateways list.
 * NOTE: we've got to be very wary of anything we find -- bad guys
 * might have prepared it.
 */
static err_t
process_ipsec_server_rr(const struct id *id, const struct rr_index *rri)
{
    struct gw_info gi;
    unsigned char str[2049];	/* plenty of space for copy of rdata */
    u_char kb[2048];	/* plenty of space for binary form of public key */
    chunk_t kbc;
    u_char *p;
    err_t ugh;

    zero(&gi);

    gi.client_id = *id;	/* will need to unshare_id_content */

    ugh = unpack_txt_rdata(str, sizeof(str), rri->rdata, rri->rdlen);
    if (ugh != NULL)
	return ugh;

    p = str + rri->offset;

    /* decode iii */

    ugh = decode_iii(&p, id, &gi.gw_id);
    if (ugh != NULL)
	return ugh;

    if (!id_is_ipaddr(&gi.gw_id))
	return "IP address for security gateway not specified in TXT record";

    /* decode optional key */

    if (*p == '\0')
    {
	/* kkk is missing: go for gateway's KEY record (Gateway id is iii).
	 * Beware: this is recursive!
	 */
	const struct RSA_public_key *pk = get_RSA_public_key(&gi.gw_id);

	if (pk == NULL)
	    return "no RSA public key found";

	/* copy result */
	gi.gw_key.k = pk->k;
	mpz_init_set(&gi.gw_key.n, &pk->n);
	mpz_init_set(&gi.gw_key.e, &pk->e);
    }
    else
    {
	/* kkk is base 64 encoding of key */
	ugh = ttodata(p, 0, 64, kb, sizeof(kb), &kbc.len);

	if (ugh != NULL)
	    return builddiag("malformed key data: %s", ugh);

	passert(kbc.len < sizeof(kb));

	kbc.ptr = kb;
	ugh = unpack_RSA_public_key(&gi.gw_key, &kbc);
	if (ugh != NULL)
	    return builddiag("invalid key data: %s", ugh);
    }

    /* we're home free!  Allocate everything and add to gateways list. */
    gi.created_time = now();
    gi.last_tried_time = gi.last_worked_time = NO_TIME;
    unshare_id_content(&gi.client_id);
    gi.next = gateways;
    gateways = clone_thing(gi, "gateway info");

    return NULL;
}

static err_t
process_dns_answer(const struct id *id, const struct id *sgw_id
, u_char ans[], int anslen, int type)
{
    int r;	/* all-purpose return value holder */
    u_int16_t c;	/* number of current RR in current answer section */
    err_t ugh = NULL;
    pb_stream pbs;
    struct qr_header qr_header;
    chunk_t key;	/* info relevant to T_KEY */
    struct txt_tbl txt_tbl;	/* info relevant to T_TXT X-IPsec-Server */

    setchunk(key, NULL, 0);	/* empty */
    txt_tbl.count = 0;	/* empty */

    init_pbs(&pbs, ans, anslen, "Query Response Message");

    /* decode and check header */

    if (!in_struct(&qr_header, &qr_header_desc, &pbs, NULL))
	return "malformed header";

    /* ID: nothing to do with us */

    /* stuff -- lots of things */
    if ((qr_header.stuff & QRS_QR) == 0)
	return "not a response?!?";

    if (((qr_header.stuff >> QRS_OPCODE_SHIFT) & QRS_OPCODE_MASK) != QRSO_QUERY)
	return "unexpected opcode";

    /* I don't think we care about AA */

    if (qr_header.stuff & QRS_TC)
	return "response truncated";

    /* I don't think we care about RD, RA, AD (yet?), or CD */

    if (qr_header.stuff & QRS_Z)
	return "Z bit is not zero";

    r = (qr_header.stuff >> QRS_RCODE_SHIFT) & QRS_RCODE_MASK;
    if (r != 0)
	return r < (int)elemsof(rcode_text)? rcode_text[r] : "unknown rcode";

    if (qr_header.ancount == 0)
	return "no KEY RR found by DNS";

    /* end of header checking */

    /* Question Section processing */

    /* 4.1.2. Question section format:
     *                                 1  1  1  1  1  1
     *   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
     * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
     * |                                               |
     * /                     QNAME                     /
     * /                                               /
     * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
     * |                     QTYPE                     |
     * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
     * |                     QCLASS                    |
     * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
     */

    for (c = 0; c != qr_header.qdcount; c++)
    {
	struct qs_fixed qsf;

	ugh = eat_name_helpfully(&pbs, "Query Section");
	if (ugh != NULL)
	    return ugh;

	if (!in_struct(&qsf, &qs_fixed_desc, &pbs, NULL))
	    return "failed to get fixed part of Question Section";

	if (qsf.qtype != type)
	    return "unexpected QTYPE in Question Section";

	if (qsf.qclass != C_IN)
	    return "unexpected QCLASS in Question Section";
    }

    /* rest of sections are made up of Resource Records */

    /* Answer Section processing */

    for (c = 0; c != qr_header.ancount; c++)
    {
	struct rr_fixed rrf;
	size_t tail;

	/* ??? do we need to match the name? */

	ugh = eat_name_helpfully(&pbs, "Answer Section");
	if (ugh != NULL)
	    return ugh;

	if (!in_struct(&rrf, &rr_fixed_desc, &pbs, NULL))
	    return "failed to get fixed part of Answer Section Resource Record";

	if (rrf.rdlength > pbs_left(&pbs))
	    return "RD Length extends beyond end of message";

	/* ??? should we care about ttl? */

	tail = rrf.rdlength;

	if (rrf.type == type && rrf.class == C_IN)
	{
	    switch (type)
	    {
	    case T_KEY:
		ugh = process_key_rr(pbs.cur, tail, &key);
		break;
	    case T_TXT:
		ugh = accumulate_txt_rr(pbs.cur, tail, &txt_tbl, id, sgw_id);
		break;
	    default:
		passert(FALSE);
	    }
	    if (ugh != NULL)
		return ugh;
	}
	in_raw(NULL, tail, &pbs, "RR RDATA");
    }

    /* Authority Section processing (just sanity checking) */

    for (c = 0; c != qr_header.nscount; c++)
    {
	struct rr_fixed rrf;
	size_t tail;

	ugh = eat_name_helpfully(&pbs, "Authority Section");
	if (ugh != NULL)
	    return ugh;

	if (!in_struct(&rrf, &rr_fixed_desc, &pbs, NULL))
	    return "failed to get fixed part of Authority Section Resource Record";

	if (rrf.rdlength > pbs_left(&pbs))
	    return "RD Length extends beyond end of message";

	/* ??? should we care about ttl? */

	tail = rrf.rdlength;

	in_raw(NULL, tail, &pbs, "RR RDATA");
    }

    /* Additional Section processing (just sanity checking) */

    for (c = 0; c != qr_header.arcount; c++)
    {
	struct rr_fixed rrf;
	size_t tail;

	ugh = eat_name_helpfully(&pbs, "Additional Section");
	if (ugh != NULL)
	    return ugh;

	if (!in_struct(&rrf, &rr_fixed_desc, &pbs, NULL))
	    return "failed to get fixed part of Authority Section Resource Record";

	if (rrf.rdlength > pbs_left(&pbs))
	    return "RD Length extends beyond end of message";

	/* ??? should we care about ttl? */

	tail = rrf.rdlength;

	in_raw(NULL, tail, &pbs, "RR RDATA");
    }

    /* done all sections */

    /* ??? is padding legal, or can we complain if more left in record? */

    switch (type)
    {
    case T_KEY:
	if (key.ptr == NULL)
	    return "no suitable key found in DNS";

	add_public_key(id, PUBKEY_ALG_RSA, &key);
	break;

    case T_TXT:
	if (txt_tbl.count == 0)
	    return "no suitable TXT " our_TXT_attr_string " found in DNS";

	/* Note: quality of rand() matters hardly at all in this case */
	return process_ipsec_server_rr(id, &txt_tbl.rr[rand() % txt_tbl.count]);
	break;

    default:
	passert(FALSE);
    }
    return NULL;
}

/* Look up a TXT X-IPsec-Server or KEY record.
 * Three kinds of queries are supported:
 * For KEY record, the result is a new entry in the public key table.
 * For TXT records, the result is a new gateway entry.
 * If sgw_id is null, only pay attention to TXT records that specify an
 * IP address for the gatway: we need this in the initiation case.
 * If sgw_id is non-null, only pay attention to TXT records that specify
 * this id as the security gatway; this is useful to the Responder
 * for confirming claims of gateways.
 * Beware: this can be recursive.
 */
static err_t
do_dns_query(const struct id *id	/* domain to query */
, const struct id *sgw_id	/* if non-null, any accepted gw_info must match */
, int type	/* T_TXT or T_KEY, selecting rr type of interest */
, const char *typename)	/* string for type */
{
    err_t ugh;
    u_char name_buf[NS_MAXDNAME + 1];
    u_char ans[NS_PACKETSZ * 10];	/* very probably bigger than necessary */
    int anslen;

    ugh = init_dns();
    if (ugh != NULL)
	return ugh;

    ugh = build_dns_name(name_buf, id, typename);
    if (ugh != NULL)
	return ugh;

    anslen = res_nquery(statp, name_buf, C_IN, type, ans, sizeof(ans));
    if (anslen == -1)
    {
	/* newer resolvers support statp->res_h_errno as well as h_errno.
	 * That might be better, but older resolvers don't.
	 * See resolver(3), if you have it.
	 */
	return builddiag("failure querying DNS for %s of %s: %s"
	    , typename, name_buf, hstrerror(h_errno));
    }

    if (anslen > (int) sizeof(ans))
	return "(INTERNAL ERROR) answer too long for buffer";

    ugh = process_dns_answer(id, sgw_id, ans, anslen, type);
    if (ugh != NULL)
	return builddiag("failure processing %s record of DNS answer for %s: %s"
	    , typename, name_buf, ugh);

    return NULL;
}

/* look up DNS KEY RR, if any, for id to find a suitable RSA key */
err_t
fetch_public_key(const struct id *id)
{
    return do_dns_query(id, (struct id *)NULL, T_KEY, "KEY");
}

/* look up TXT X-IPsec-Server record, if any.
 * Will tell us GW IP address and public RSA key.
 * On success, the result will be assigned to *gwp.
 * Note: the key is being ascribed to the gateway by the client.
 *   The gateway may not agree!  So we cannot trust it in other
 *   contexts.
 */
err_t
discover_gateway(const ip_address *peer_client
, const struct id *putative_sgw
, struct gw_info **gwp)
{
    struct id id;
    struct gw_info **pp
	, *p;
    err_t ugh = NULL;

    iptoid(peer_client, &id);

    for (pp = &gateways; ; pp = &p->next)
    {
	p = *pp;
	if (p == NULL)
	{
	    /* not in table: do a DNS query.
	     * On success, will leave result at front of gateways.
	     */
	    ugh = do_dns_query(&id, putative_sgw, T_TXT, "TXT");
	    break;
	}
	if (same_id(&id, &p->client_id)
	&& (putative_sgw == NULL? id_is_ipaddr(&p->gw_id) : same_id(putative_sgw, &p->gw_id)))
	{
	    /* We found one from a previous attempt.
	     * Move it to front of gateways list.
	     */
	    *pp = p->next;
	    p->next = gateways;
	    gateways = p;
	    break;
	}
    }

    /* if successful and requested, set *gwp from front of gateways */
    if (ugh == NULL && gwp != NULL)
	*gwp = gateways;

    return ugh;
}
