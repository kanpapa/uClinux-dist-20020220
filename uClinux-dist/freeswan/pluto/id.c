/* identity representation, as in IKE ID Payloads (RFC 2407 DOI 4.6.2.1)
 * Copyright (C) 1999  D. Hugh Redelmeier
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
 * RCSID $Id: id.c,v 1.15 2001/04/12 23:34:14 dhr Exp $
 */

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <freeswan.h>

#include "constants.h"
#include "defs.h"
#include "id.h"
#include "connections.h"	/* needs id.h */
#include "packet.h"

const struct id empty_id;	/* all zeros and NULLs */

/* Convert textual form of id into a (temporary) struct id.
 * Note that if the id is to be kept, unshare_id_content will be necessary.
 */
err_t
atoid(char *src, struct id *id)
{
    err_t ugh = NULL;

    *id = empty_id;

    if (*src == '=')
    {
	id->kind = ID_KEY_ID;
	id->name.ptr = src+1;		/* discard = */
	id->name.len = strlen(id->name.ptr);
    }
    else if (strchr(src, '@') == NULL)
    {
	/* !!! this test is not sufficient for distinguishing address families.
	 * We need a notation to specify that a FQDN is to be resolved to IPv6.
	 */
	const struct af_info *afi = strchr(src, ':') == NULL
	    ? &af_inet4_info: &af_inet6_info;

	id->kind = afi->id_addr;
	ugh = ttoaddr(src, 0, afi->af, &id->ip_addr);
    }
    else
    {
	if (*src == '@')
	{
	    id->kind = ID_FQDN;
	    id->name.ptr = src+1;	/* discard @ */
	}
	else
	{
	    /* We leave in @, as per DOI 4.6.2.4
	     * (but DNS wants . instead).
	     */
	    id->kind = ID_USER_FQDN;
	    id->name.ptr = src;
	}
	id->name.len = strlen(id->name.ptr);
#ifdef INTEROP_CHECKPOINT_FW_4_1
	/* why couldn't they have used ID_KEY_ID? (violates RFC2407 4.6.2.4) */
	if (id->kind == ID_USER_FQDN && id->name.len > 0)
	{
	    if (src[id->name.len-1] == '@')
		id->name.len--;
	}
#endif
    }
    return ugh;
}

void
iptoid(const ip_address *ip, struct id *id)
{
    *id = empty_id;

    switch (addrtypeof(ip))
    {
    case AF_INET:
	id->kind = ID_IPV4_ADDR;
	break;
    case AF_INET6:
	id->kind = ID_IPV6_ADDR;
	break;
    default:
	passert(FALSE);
    }
    id->ip_addr = *ip;
}

int
idtoa(const struct id *id, char *dst, size_t dstlen)
{
    int n;

    switch (id->kind)
    {
    case ID_NONE:
	n = snprintf(dst, dstlen, "(none)");
	break;
    case ID_IPV4_ADDR:
    case ID_IPV6_ADDR:
	n = (int)addrtot(&id->ip_addr, 0, dst, dstlen) - 1;
	break;
    case ID_FQDN:
	n = snprintf(dst, dstlen, "@%.*s", (int)id->name.len, id->name.ptr);
	break;
    case ID_KEY_ID:
        n = snprintf(dst, dstlen, "=%.*s", (int)id->name.len, id->name.ptr);
        break;
    case ID_USER_FQDN:
#ifdef INTEROP_CHECKPOINT_FW_4_1
 	n = snprintf(dst, dstlen, "%.*s%s", (int)id->name.len, id->name.ptr,
	    strchr(id->name.ptr, '@') ? "" : "@");
#else
	n = snprintf(dst, dstlen, "%.*s", (int)id->name.len, id->name.ptr);
	break;
#endif
    default:
	n = snprintf(dst, dstlen, "unknown id kind %d", id->kind);
	break;
    }

    /* "Sanitize" string so that log isn't endangered:
     * replace unprintable characters with '?'.
     */
    if (n > 0)
    {
	for ( ; *dst != '\0'; dst++)
	    if (!isprint(*dst))
		*dst = '?';
    }

    return n;
}

/* Make private copy of string in struct id.
 * This is needed if the result of atoid is to be kept.
 */
void
unshare_id_content(struct id *id)
{
    switch (id->kind)
    {
    case ID_FQDN:
    case ID_USER_FQDN:
    case ID_KEY_ID:
	id->name.ptr = clone_bytes(id->name.ptr, id->name.len, "keep id name");
	break;
    case ID_NONE:
    case ID_IPV4_ADDR:
    case ID_IPV6_ADDR:
	break;
    default:
	passert(FALSE);
    }
}

void
free_id_content(struct id *id)
{
    switch (id->kind)
    {
    case ID_FQDN:
    case ID_KEY_ID:
    case ID_USER_FQDN:
	pfree(id->name.ptr);
	break;
    case ID_NONE:
    case ID_IPV4_ADDR:
    case ID_IPV6_ADDR:
	break;
    default:
	passert(FALSE);
    }
}

/* compare two struct id values */
bool
same_id(const struct id *a, const struct id *b)
{
    if (a->kind != b->kind)
	return FALSE;
    switch (a->kind)
    {
    case ID_NONE:
	return TRUE;	/* kind of vacuous */

    case ID_IPV4_ADDR:
    case ID_IPV6_ADDR:
	return sameaddr(&a->ip_addr, &b->ip_addr);

    case ID_FQDN:
    case ID_USER_FQDN:
	/* assumption: case should be ignored */
	return a->name.len == b->name.len
	    && strncasecmp(a->name.ptr, b->name.ptr, a->name.len) == 0;

    case ID_KEY_ID:
	/* pretend that it's binary */
	return a->name.len == b->name.len
	    && memcmp(a->name.ptr, b->name.ptr, a->name.len) == 0;

    default:
	passert(FALSE);
    }
}

/* build an ID payload
 * Note: no memory is allocated for the body of the payload (tl->ptr).
 * We assume it will end up being a pointer into a sufficiently
 * stable datastructure.  It only needs to last a short time.
 */
void
build_id_payload(struct isakmp_ipsec_id *hd, chunk_t *tl, struct end *end)
{
    zero(hd);
    hd->isaiid_idtype = end->id.kind;
    switch (end->id.kind)
    {
    case ID_NONE:
	hd->isaiid_idtype = aftoinfo(addrtypeof(&end->host_addr))->id_addr;
	tl->len = addrbytesptr(&end->host_addr
	    , (const unsigned char **)&tl->ptr);
	break;
    case ID_FQDN:
    case ID_USER_FQDN:
    case ID_KEY_ID:
	*tl = end->id.name;
	break;
    case ID_IPV4_ADDR:
    case ID_IPV6_ADDR:
	tl->len = addrbytesptr(&end->host_addr
	    , (const unsigned char **)&tl->ptr);
	break;
    default:
	passert(FALSE);
    }
}
