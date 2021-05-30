/* mechanisms for preshared keys (public, private, and preshared secrets)
 * Copyright (C) 1998, 1999  D. Hugh Redelmeier.
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
 * RCSID $Id: preshared.c,v 1.50 2001/04/09 19:48:42 dhr Exp $
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <glob.h>
#ifndef GLOB_ABORTED
# define GLOB_ABORTED    GLOB_ABEND	/* fix for old versions */
#endif

#include <freeswan.h>

#include "constants.h"
#include "defs.h"
#include "id.h"
#include "connections.h"	/* needs id.h */
#include "state.h"
#include "preshared.h"
#include "dnskey.h"
#include "log.h"
#include "whack.h"	/* for RC_LOG_SERIOUS */

struct fld {
    const char *name;
    size_t offset;
};

static const struct fld RSA_private_field[] =
{
    { "Modulus", offsetof(struct RSA_private_key, pub.n) },
    { "PublicExponent", offsetof(struct RSA_private_key, pub.e) },
    { "PrivateExponent", offsetof(struct RSA_private_key, d) },
    { "Prime1", offsetof(struct RSA_private_key, p) },
    { "Prime2", offsetof(struct RSA_private_key, q) },
    { "Exponent1", offsetof(struct RSA_private_key, dP) },
    { "Exponent2", offsetof(struct RSA_private_key, dQ) },
    { "Coefficient", offsetof(struct RSA_private_key, qInv) },
};

#ifdef DEBUG
static void
RSA_show_key_fields(struct RSA_private_key *k, int fieldcnt)
{
    const struct fld *p;

    for (p = RSA_private_field; p < &RSA_private_field[fieldcnt]; p++)
    {
	MP_INT *n = (MP_INT *) ((char *)k + p->offset);
	size_t sz = mpz_sizeinbase(n, 16);
	char buf[2048/4 + 2];	/* ought to be big enough */

	passert(sz <= sizeof(buf));
	mpz_get_str(buf, 16, n);

	DBG_log(" %s: %s", p->name, buf);
    }
}

/* debugging info that compromises security! */
static void
RSA_show_private_key(struct RSA_private_key *k)
{
    RSA_show_key_fields(k, elemsof(RSA_private_field));
}

static void
RSA_show_public_key(struct RSA_public_key *k)
{
    /* Kludge: pretend that it is a private key, but only display the
     * first two fields (which are the public key).
     */
    passert(offsetof(struct RSA_private_key, pub) == 0);
    RSA_show_key_fields((struct RSA_private_key *)k, 2);
}
#endif

static const char *
RSA_private_key_sanity(struct RSA_private_key *k)
{
    /* note that the *last* error found is reported */
    err_t ugh = NULL;
    mpz_t t, u, q1;

#ifdef DEBUG	/* debugging info that compromises security */
    DBG(DBG_PRIVATE, RSA_show_private_key(k));
#endif

    /* PKCS#1 1.5 section 6 requires modulus to have at least 12 octets.
     * We actually require more (for security).
     */
    if (k->pub.k < RSA_MIN_OCTETS)
	return RSA_MIN_OCTETS_UGH;

    /* we picked a max modulus size to simplify buffer allocation */
    if (k->pub.k > RSA_MAX_OCTETS)
	return RSA_MAX_OCTETS_UGH;

    mpz_init(t);
    mpz_init(u);
    mpz_init(q1);

    /* check that n == p * q */
    mpz_mul(u, &k->p, &k->q);
    if (mpz_cmp(u, &k->pub.n) != 0)
	ugh = "n != p * q";

    /* check that e divides neither p-1 nor q-1 */
    mpz_sub_ui(t, &k->p, 1);
    mpz_mod(t, t, &k->pub.e);
    if (mpz_cmp_ui(t, 0) == 0)
	ugh = "e divides p-1";

    mpz_sub_ui(t, &k->q, 1);
    mpz_mod(t, t, &k->pub.e);
    if (mpz_cmp_ui(t, 0) == 0)
	ugh = "e divides q-1";

    /* check that d is e^-1 (mod lcm(p-1, q-1)) */
    /* see PKCS#1v2, aka RFC 2437, for the "lcm" */
    mpz_sub_ui(q1, &k->q, 1);
    mpz_sub_ui(u, &k->p, 1);
    mpz_gcd(t, u, q1);		/* t := gcd(p-1, q-1) */
    mpz_mul(u, u, q1);		/* u := (p-1) * (q-1) */
    mpz_divexact(u, u, t);	/* u := lcm(p-1, q-1) */

    mpz_mul(t, &k->d, &k->pub.e);
    mpz_mod(t, t, u);
    if (mpz_cmp_ui(t, 1) != 0)
	ugh = "(d * e) mod (lcm(p-1, q-1)) != 1";

    /* check that dP is d mod (p-1) */
    mpz_sub_ui(u, &k->p, 1);
    mpz_mod(t, &k->d, u);
    if (mpz_cmp(t, &k->dP) != 0)
	ugh = "dP is not congruent to d mod (p-1)";

    /* check that dQ is d mod (q-1) */
    mpz_sub_ui(u, &k->q, 1);
    mpz_mod(t, &k->d, u);
    if (mpz_cmp(t, &k->dQ) != 0)
	ugh = "dQ is not congruent to d mod (q-1)";

    /* check that qInv is (q^-1) mod p */
    mpz_mul(t, &k->qInv, &k->q);
    mpz_mod(t, t, &k->p);
    if (mpz_cmp_ui(t, 1) != 0)
	ugh = "qInv is not conguent ot (q^-1) mod p";

    mpz_clear(t);
    mpz_clear(u);
    mpz_clear(q1);
    return ugh;
}

const char *shared_secrets_file = SHARED_SECRETS_FILE;

struct id_list {
    struct id id;
    struct id_list *next;
};

struct secret {
    struct id_list *ids;
    enum PrivateKeyKind kind;
    union {
	chunk_t preshared_secret;
	struct RSA_private_key RSA_private_key;
    } u;
    struct secret *next;
};

struct secret *secrets = NULL;

/* find the struct secret associated with the combination of
 * me and the peer.  We match the Id (if none, the IP address).
 * Failure is indicated by a NULL.
 */
static const struct secret *
get_secret(struct connection *c, enum PrivateKeyKind kind, bool asym)
{
    enum {
	match_default = 01,
	match_him = 02,
	match_me = 04
    };
    int i = 0;
    unsigned int best_match = 0;
    struct secret *best = NULL;
    struct secret *s;
    struct id *my_id = &c->this.id
	, rw_id, my_rw_id
	, *his_id = &c->that.id;

    if (his_id_was_instantiated(c))
    {
	/* roadwarrior: replace him with 0.0.0.0 */
	rw_id.kind = c->that.id.kind;
	(void)anyaddr(addrtypeof(&c->that.host_addr), &rw_id.ip_addr);
	his_id = &rw_id;
    }
	
    for (i = 0; i < 2; i++) { 
	for (s = secrets; s != NULL; s = s->next)
	{
	    if (s->kind == kind)
	    {
		unsigned int match = 0;

		if (s->ids == NULL)
		{
		    /* a default (signified by lack of ids):
		     * accept if no more specific match found
		     */
		    match = match_default;
		}
		else
		{
		    /* check if both ends match ids */
		    struct id_list *i;

		    for (i = s->ids; i != NULL; i = i->next)
		    {
			if (same_id(my_id, &i->id))
			    match |= match_me;

			if (same_id(his_id, &i->id))
			    match |= match_him;
		    }

		    /* If our end matched the only id in the list,
		     * default to matching any peer.
		     * A more specific match will trump this.
		     */
		    if (match == match_me
		    && s->ids->next == NULL)
			match |= match_default;
		}

		switch (match)
		{
		case match_me:
		    /* if this is an asymmetric (eg. public key) system,
		     * allow this-side-only match to count, even if
		     * there are other ids in the list.
		     */
		    if(!asym)
			break;
		    /* FALLTHROUGH */
		case match_default:	/* default all */
		case match_me | match_default:	/* default peer */
		case match_me | match_him:	/* explicit */
		    if (match == best_match)
		    {
			/* two good matches are equally good:
			 * do they agree?
			 */
			bool same;

			switch (kind)
			{
			case PPK_PSK:
			    same = s->u.preshared_secret.len == best->u.preshared_secret.len
				&& memcmp(s->u.preshared_secret.ptr, best->u.preshared_secret.ptr, s->u.preshared_secret.len) == 0;
			    break;
			case PPK_RSA:
			    /* Dirty trick: since we have code to compare
			     * RSA public keys, but not private keys, we
			     * make the assumption that equal public keys
			     * mean equal private keys.  This ought to work.
			     */
			    same = same_RSA_public_key(&s->u.RSA_private_key.pub
				, &best->u.RSA_private_key.pub);
			    break;
			default:
			    passert(FALSE);
			}
			if (!same)
			{
			    loglog(RC_LOG_SERIOUS, "multiple ipsec.secrets entries with distinct secrets match endpoints:"
				" first secret used");
			    best = s;	/* list is backwards: take latest in list */
			}
		    }
		    else if (match > best_match)
		    {
			/* this is the best match so far */
			best_match = match;
			best = s;
		    }
		}
	    }
	}
	if (best != NULL) {
	    break;
	} else {
	    /* replace him with 0.0.0.0 */
	    my_rw_id.kind = c->this.id.kind;
	    (void)anyaddr(addrtypeof(&c->this.host_addr), &my_rw_id.ip_addr);
	    my_id = &my_rw_id;
	}
    }
    return best;
}

/* find the appropriate preshared key (see get_secret).
 * Failure is indicated by a NULL pointer.
 * Note: the result is not to be freed by the caller.
 */
const chunk_t *
get_preshared_secret(struct connection *c)
{
    const struct secret *s = get_secret(c, PPK_PSK, FALSE);

#ifdef DEBUG
    DBG(DBG_PRIVATE,
	if (s == NULL)
	    DBG_log("no Preshared Key Found");
	else
	    DBG_dump_chunk("Preshared Key", s->u.preshared_secret);
	);
#endif
    return s == NULL? NULL : &s->u.preshared_secret;
}

/* find the appropriate RSA private key (see get_secret).
 * Failure is indicated by a NULL pointer.
 */
const struct RSA_private_key *
get_RSA_private_key(struct connection *c)
{
    const struct secret *s = get_secret(c, PPK_RSA, TRUE);

    return s == NULL? NULL : &s->u.RSA_private_key;
}

/* digest a secrets file
 *
 * The file is a sequence of records.  A record is a maximal sequence of
 * tokens such that the first, and only the first, is in the first column
 * of a line.
 *
 * Tokens are generally separated by whitespace and are key words, ids,
 * strings, or data suitable for atobytes(3).  As a nod to convention,
 * a trailing ":" on what would otherwise be a token is taken as a
 * separate token.  If preceded by whitespace, a "#" is taken as starting
 * a comment: it and the rest of the line are ignored.
 *
 * One kind of record is an include directive.  It starts with "include".
 * The filename is the only other token in the record.
 * If the filename does not start with /, it is taken to
 * be relative to the directory containing the current file.
 *
 * The other kind of record describes a key.  It starts with a
 * sequence of ids and ends with key information.  Each id
 * is an IP address, a Fully Qualified Domain Name (which will immediately
 * be resolved), or @FQDN which will be left as a name.
 *
 * The key part can be in several forms.
 *
 * The old form of the key is still supported: a simple
 * quoted strings (with no escapes) is taken as a preshred key.
 *
 * The new form starts the key part with a ":".
 *
 * For Preshared Key, use the "PSK" keyword, and follow it by a string
 * or a data token suitable for atobytes(3).
 *
 * For RSA Private Key, use the "RSA" keyword, followed by a
 * brace-enclosed list of key field keywords and data values.
 * The data values are large integers to be decoded by atobytes(3).
 * The fields are a subset of those used by BIND 8.2 and have the
 * same names.
 */

struct secrets_file_position
{
    int depth;	/* how deeply we are nested */
    char *filename;
    FILE *fp;
    enum { B_none, B_record, B_file } bdry;	/* current boundary */
    int lino;	/* line number in file */
    char buffer[2049];    /* note: one extra char for our use (jamming '"') */
    char *cur;	/* cursor */
    char under;	/* except in shift(): character orignally at *cur */
    struct secrets_file_position *previous;
};

static struct secrets_file_position *sfp = NULL;

/* Token decoding: shift() loads the next token into tok.
 * Iff a token starts at the left margin, it is considered
 * to be the first in a record.  We create a special condition,
 * Record Boundary (analogous to EOF), just before such a token.
 * We are unwilling to shift through a record boundary:
 * it must be overridden first.
 * Returns FALSE iff Record Boundary or EOF (i.e. no token);
 * tok will then be NULL.
 */

static void process_secrets_file(const char *file_pat);

static char *tok;
#define tokeq(s) (streq(tok, (s)))
#define tokeqword(s) (strcasecmp(tok, (s)) == 0)

static bool
shift(void)
{
    char *p = sfp->cur;
    char *sor = NULL;	/* start of record for any new lines */

    passert(sfp->bdry == B_none);

    *p = sfp->under;
    sfp->under = '\0';

    for (;;)
    {
	switch (*p)
	{
	case '\0':	/* end of line */
	case '#':	/* comment to end of line: treat as end of line */
	    /* get the next line */
	    if (fgets(sfp->buffer, sizeof(sfp->buffer)-1, sfp->fp) == NULL)
	    {
		sfp->bdry = B_file;
		tok = sfp->cur = NULL;
		return FALSE;
	    }
	    else
	    {
		/* strip trailing whitespace, including \n */

		for (p = sfp->buffer+strlen(sfp->buffer)-1
		; p>sfp->buffer && isspace(p[-1]); p--)
		    ;
		*p = '\0';

		sfp->lino++;
		sor = p = sfp->buffer;
	    }
	    break;	/* try again for a token */

	case ' ':	/* whitespace */
	case '\t':
	    p++;
	    break;	/* try again for a token */

	case '"':	/* quoted token */
	case '\'':
	    if (p != sor)
	    {
		/* we have a quoted token: note and advance to its end */
		tok = p;
		p = strchr(p+1, *p);
		if (p == NULL)
		{
		    loglog(RC_LOG_SERIOUS, "\"%s\" line %d: unterminated string"
			, sfp->filename, sfp->lino);
		    p = tok + strlen(tok);
		}
		else
		{
		    p++;	/* include delimiter in token */
		}

		/* remember token delimiter and replace with '\0' */
		sfp->under = *p;
		*p = '\0';
		sfp->cur = p;
		return TRUE;
	    }
	    /* FALL THROUGH */
	default:
	    if (p != sor)
	    {
		/* we seem to have a token: note and advance to its end */
		tok = p;

		if (p[0] == '0' && p[1] == 't')
		{
		    /* 0t... token goes to end of line */
		    p += strlen(p);
		}
		else
		{
		    /* "ordinary" token: up to whitespace or end of line */
		    do {
			p++;
		    } while (*p != '\0' && !isspace(*p))
			;

		    /* fudge to separate ':' from a preceding adjacent token */
		    if (p-1 > tok && p[-1] == ':')
			p--;
		}

		/* remember token delimiter and replace with '\0' */
		sfp->under = *p;
		*p = '\0';
		sfp->cur = p;
		return TRUE;
	    }

	    /* we have a start-of-record: return it, deferring "real" token */
	    sfp->bdry = B_record;
	    tok = NULL;
	    sfp->under = *p;
	    sfp->cur = p;
	    return FALSE;
	}
    }
}

/* ensures we are at a Record (or File) boundary, optionally warning if not */

static bool
flushline(const char *m)
{
    if (sfp->bdry != B_none)
    {
	return TRUE;
    }
    else
    {
	if (m != NULL)
	    loglog(RC_LOG_SERIOUS, "\"%s\" line %d: %s", sfp->filename, sfp->lino, m);
	do ; while (shift());
	return FALSE;
    }
}

static void
process_key(struct secret *s)
{
    char buf[2048];	/* limit on size of binary representation of key */
    err_t ugh = NULL;
    
    if (*tok == '"' || *tok == '\'')
    {
	/* old PSK format: just a string */
	clonetochunk(s->u.preshared_secret, tok+1, sfp->cur - tok  - 2, "PSK");
	(void) shift();
    }
    else if (tokeqword("psk"))
    {
	/* preshared key: quoted string or atobytes format */
	if (!shift())
	{
	    ugh = "unexpected end of record in PSK";
	}
	else if (*tok == '"' || *tok == '\'')
	{
	    clonetochunk(s->u.preshared_secret, tok+1, sfp->cur - tok  - 2, "PSK");
	    (void) shift();
	}
	else
	{
	    size_t sz;

	    ugh = atobytes(tok, sfp->cur - tok, buf, sizeof(buf), &sz);
	    if (ugh != NULL)
	    {
		/* atobytes didn't like PSK data */
		ugh = builddiag("PSK data malformed (%s): %s", ugh, tok);
	    }
	    else
	    {
		clonetochunk(s->u.preshared_secret, buf, sz, "PSK");
		(void) shift();
	    }
	}
    }
    else if (tokeqword("rsa"))
    {
	/* RSA key: the fun begins.
	 * A braced list of keyword and value pairs.
	 */
	s->kind = PPK_RSA;
	if (!(shift() && tokeq("{")))
	{
	    ugh = "bad RSA key syntax";
	}
	else
	{
	    /* handle fields of RSA public key
	     * At the moment, each field is required, in order.
	     * The fields come from BIND 8.2's representation
	     */
	    const struct fld *p;

	    for (p = RSA_private_field; ugh == NULL && p < &RSA_private_field[elemsof(RSA_private_field)]; p++)
	    {
		size_t sz;

		if (!shift())
		{
		    ugh = "premature end of RSA key";
		}
		else if (!tokeqword(p->name))
		{
		    ugh = builddiag("%s keyword not found where expected in RSA key"
			, p->name);
		}
		else if (!(shift()
		&& (!tokeq(":") || shift())))	/* ignore optional ":" */
		{
		    ugh = "premature end of RSA key";
		}
		else if (NULL != (ugh = atobytes(tok, sfp->cur - tok, buf, sizeof(buf), &sz)))
		{
		    /* in RSA key, atobytes didn't like */
		    ugh = builddiag("RSA data malformed (%s): %s", ugh, tok);
		}
		else
		{
		    MP_INT *n = (MP_INT *) ((char *)&s->u.RSA_private_key + p->offset);

		    n_to_mpz(n, buf, sz);
#if 0	/* debugging info that compromises security */
		    {
			size_t sz = mpz_sizeinbase(n, 16);
			char buf[2048/4 + 2];	/* ought to be big enough */

			passert(sz <= sizeof(buf));
			mpz_get_str(buf, 16, n);

			loglog(RC_LOG_SERIOUS, "%s: %s", p->name, buf);
		    }
#endif
		}
	    }

	    if (ugh == NULL)
	    {
		/* note: the following requires a boundary after "}" */
		if (!(shift() && tokeq("}") && !shift()))
		{
		    ugh = "malformed end of RSA private key";
		}
		else
		{
		    unsigned bits = mpz_sizeinbase(&s->u.RSA_private_key.pub.n, 2);

		    s->u.RSA_private_key.pub.k = (bits + BITS_PER_BYTE - 1) / BITS_PER_BYTE;
		    ugh = RSA_private_key_sanity(&s->u.RSA_private_key);
		}
	    }
	}
    }
    else
    {
	ugh = builddiag("unrecognized key format: %s", tok);
    }

    if (ugh != NULL)
    {
	loglog(RC_LOG_SERIOUS, "\"%s\" line %d: %s"
	    , sfp->filename, sfp->lino, ugh);
    }
    else if (flushline("expected record boundary in key"))
    {
	/* gauntlet has been run: install new secret */
	s->next = secrets;
	secrets = s;
    }
}

static void
process_secret_records(void)
{
    /* read records from ipsec.secrets and load them into our table */
    for (;;)
    {
	(void)flushline(NULL);	/* silently ditch leftovers, if any */
	if (sfp->bdry == B_file)
	    break;

	sfp->bdry = B_none;	/* eat the Record Boundary */
	(void)shift();	/* get real first token */

	if (tokeqword("include"))
	{
	    /* an include directive */
	    char fn[2048];	/* space for filename (I hope) */
	    char *p = fn;
	    char *end_prefix = strrchr(sfp->filename, '/');

	    if (!shift())
	    {
		loglog(RC_LOG_SERIOUS, "\"%s\" line %d: unexpected end of include directive"
		    , sfp->filename, sfp->lino);
		continue;   /* abandon this record */
	    }

	    /* if path is relative and including file's pathname has
	     * a non-empty dirname, prefix this path with that dirname.
	     */
	    if (tok[0] != '/' && end_prefix != NULL)
	    {
		size_t pl = end_prefix - sfp->filename + 1;

		/* "clamp" length to prevent problems now;
		 * will be rediscovered and reported later.
		 */
		if (pl > sizeof(fn))
		    pl = sizeof(fn);
		memcpy(fn, sfp->filename, pl);
		p += pl;
	    }
	    if (sfp->cur - tok >= &fn[sizeof(fn)] - p)
	    {
		loglog(RC_LOG_SERIOUS, "\"%s\" line %d: include pathname too long"
		    , sfp->filename, sfp->lino);
		continue;   /* abandon this record */
	    }
	    strcpy(p, tok);
	    (void) shift();	/* move to Record Boundary, we hope */
	    if (flushline("ignoring malformed INCLUDE -- expected Record Boundary after filename"))
	    {
		process_secrets_file(fn);
		tok = NULL;	/* correct, but probably redundant */
	    }
	}
	else
	{
	    /* expecting a list of indices and then the key info */
	    struct secret *s = alloc_thing(struct secret, "secret");

	    s->ids = NULL;
	    s->kind = PPK_PSK;	/* default */
	    setchunk(s->u.preshared_secret, NULL, 0);
	    s->next = NULL;

	    for (;;)
	    {
		if (tok[0] == '"' || tok[0] == '\'')
		{
		    /* found key part */
		    process_key(s);
		    break;
		}
		else if (tokeq(":"))
		{
		    /* found key part */
		    shift();	/* discard explicit separator */
		    process_key(s);
		    break;
		}
		else
		{
		    /* an id
		     * See RFC2407 IPsec Domain of Interpretation 4.6.2
		     */
		    struct id id;
		    err_t ugh;

		    if (tokeq("%any"))
		    {
			id = empty_id;
			id.kind = ID_IPV4_ADDR;
			ugh = anyaddr(AF_INET, &id.ip_addr);
		    }
		    else if (tokeq("%any6"))
		    {
			id = empty_id;
			id.kind = ID_IPV6_ADDR;
			ugh = anyaddr(AF_INET6, &id.ip_addr);
		    }
		    else
		    {
			ugh = atoid(tok, &id);
		    }

		    if (ugh != NULL)
		    {
			loglog(RC_LOG_SERIOUS, "\"%s\" line %d: %s \"%s\""
			    , sfp->filename, sfp->lino, ugh, tok);
		    }
		    else
		    {
			struct id_list *i = alloc_thing(struct id_list
			    , "id_list");
			i->id = id;
			unshare_id_content(&i->id);
			i->next = s->ids;
			s->ids = i;
			/* DBG_log("id type %d: %s %.*s", i->kind, ip_str(&i->ip_addr), (int)i->name.len, i->name.ptr); */
		    }
		    if (!shift())
		    {
			/* unexpected Record Boundary or EOF */
			loglog(RC_LOG_SERIOUS, "\"%s\" line %d: unexpected end of id list"
			    , sfp->filename, sfp->lino);
			break;
		    }
		}
	    }
	}
    }
}

static int
globugh(const char *epath, int eerrno)
{
    log_errno_routine(eerrno, "problem with secrets file \"%s\"", epath);
    return 1;	/* stop glob */
}

static void
process_secrets_file(const char *file_pat)
{
    struct secrets_file_position pos;
    char **fnp;
    glob_t globbuf;

    pos.depth = sfp == NULL? 0 : sfp->depth + 1;

    if (pos.depth > 10)
    {
	loglog(RC_LOG_SERIOUS, "preshared secrets file \"%s\" nested too deeply", file_pat);
	return;
    }

    /* do globbing */
    {
	int r = glob(file_pat, GLOB_ERR, globugh, &globbuf);

	if (r != 0)
	{
	    switch (r)
	    {
	    case GLOB_NOSPACE:
		loglog(RC_LOG_SERIOUS, "out of space processing secrets filename \"%s\"", file_pat);
		break;
	    case GLOB_ABORTED:
		break;	/* already logged */
	    case GLOB_NOMATCH:
		loglog(RC_LOG_SERIOUS, "no secrets filename matched \"%s\"", file_pat);
		break;
	    default:
		loglog(RC_LOG_SERIOUS, "unknown glob error %d", r);
		break;
	    }
	    globfree(&globbuf);
	    return;
	}
    }

    pos.previous = sfp;
    sfp = &pos;

    /* for each file... */
    for (fnp = globbuf.gl_pathv; *fnp != NULL; fnp++)
    {
	pos.filename = *fnp;
	pos.fp = fopen(pos.filename, "r");
	if (pos.fp == NULL)
	{
	    log_errno((e, "could not open \"%s\"", pos.filename));
	    continue;	/* try the next one */
	}

	log("loading secrets from \"%s\"", pos.filename);

	pos.lino = 0;
	pos.bdry = B_none;

	pos.cur = pos.buffer;	/* nothing loaded yet */
	pos.under = *pos.cur = '\0';

	(void) shift();	/* prime tok */
	(void) flushline("file starts with indentation (continuation notation)");
	process_secret_records();
	fclose(pos.fp);
    }

    sfp = pos.previous;	/* restore old state */
}

void
free_preshared_secrets(void)
{
    if (secrets != NULL)
    {
	struct secret *s, *ns;

	log("forgetting secrets");

	for (s = secrets; s != NULL; s = ns)
	{
	    struct id_list *i, *ni;

	    ns = s->next;	/* grab before freeing s */
	    for (i = s->ids; i != NULL; i = ni)
	    {
		ni = i->next;	/* grab before freeing i */
		free_id_content(&i->id);
		pfree(i);
	    }
	    switch (s->kind)
	    {
	    case PPK_PSK:
		pfree(s->u.preshared_secret.ptr);
		break;
	    case PPK_RSA:
		mpz_clear(&s->u.RSA_private_key.pub.n);
		mpz_clear(&s->u.RSA_private_key.pub.e);
		mpz_clear(&s->u.RSA_private_key.d);
		mpz_clear(&s->u.RSA_private_key.p);
		mpz_clear(&s->u.RSA_private_key.q);
		mpz_clear(&s->u.RSA_private_key.dP);
		mpz_clear(&s->u.RSA_private_key.dQ);
		mpz_clear(&s->u.RSA_private_key.qInv);
		break;
	    default:
		passert(FALSE);
	    }
	    pfree(s);
	}
	secrets = NULL;
    }
}

void
load_preshared_secrets(void)
{
    free_preshared_secrets();
    (void) process_secrets_file(shared_secrets_file);
}

/* public key machinery */

struct pubkeyrec {
    struct id id;
    enum pubkey_alg alg;
    union {
	struct RSA_public_key rsa;
    } u;
    struct pubkeyrec *next;
};

static struct pubkeyrec *pubkeys = NULL;

static void
free_first_public_key(void)
{
    struct pubkeyrec *p = pubkeys;

    pubkeys = p->next;

    free_id_content(&p->id);

    /* algorithm-specific freeing */
    switch (p->alg)
    {
    case PUBKEY_ALG_RSA:
	mpz_clear(&p->u.rsa.n);
	mpz_clear(&p->u.rsa.e);
	break;
    default:
	passert(FALSE);
    }

    pfree(p);
}


void
free_public_keys(void)
{
    while (pubkeys != NULL)
	free_first_public_key();
}

/* decode of RSA pubkey chunk
 * - format specified in RFC 2537 RSA/MD5 Keys and SIGs in the DNS
 * - exponent length in bytes (1 or 3 octets)
 *   + 1 byte if in [1, 255]
 *   + otherwise 0x00 followed by 2 bytes of length
 * - exponent
 * - modulus
 */
err_t
unpack_RSA_public_key(struct RSA_public_key *rsa, chunk_t *pubkey)
{
    chunk_t exp;
    chunk_t mod;

    if (pubkey->len < 3)
	return "RSA public key blob way to short";	/* not even room for length! */

    if (pubkey->ptr[0] != 0x00)
    {
	setchunk(exp, pubkey->ptr + 1, pubkey->ptr[0]);
    }
    else
    {
	setchunk(exp, pubkey->ptr + 3
	    , (pubkey->ptr[1] << BITS_PER_BYTE) + pubkey->ptr[2]);
    }

    if (pubkey->len - (exp.ptr - pubkey->ptr) < exp.len + RSA_MIN_OCTETS_RFC)
	return "RSA public key blob too short";

    mod.ptr = exp.ptr + exp.len;
    mod.len = &pubkey->ptr[pubkey->len] - mod.ptr;

    if (mod.len < RSA_MIN_OCTETS)
	return RSA_MIN_OCTETS_UGH;

    if (mod.len > RSA_MAX_OCTETS)
	return RSA_MAX_OCTETS_UGH;

    n_to_mpz(&rsa->e, exp.ptr, exp.len);
    n_to_mpz(&rsa->n, mod.ptr, mod.len);

#ifdef DEBUG
    DBG(DBG_PRIVATE, RSA_show_public_key(rsa));
#endif


    rsa->k = mpz_sizeinbase(&rsa->n, 2);	/* size in bits, for a start */
    rsa->k = (rsa->k + BITS_PER_BYTE - 1) / BITS_PER_BYTE;	/* now octets */

    if (rsa->k != mod.len)
    {
	mpz_clear(&rsa->e);
	mpz_clear(&rsa->n);
	return "RSA modulus shorter than specified";
    }

    return NULL;
}

bool
same_RSA_public_key(const struct RSA_public_key *a
    , const struct RSA_public_key *b)
{
    return a == b
    || (a->k == b->k && mpz_cmp(&a->n, &b->n) == 0 && mpz_cmp(&a->e, &b->e) == 0);
}

static struct pubkeyrec *
get_public_key(const struct id *id, enum pubkey_alg alg)
{
    struct pubkeyrec *p, **pp;

    for (pp = &pubkeys; (p = *pp) != NULL; pp = &p->next)
    {
	if (same_id(id, &p->id) && p->alg == alg)
	{
	    /* we have a winner: bring it to front, return key */

	    *pp = p->next;	/* remove p from list */
	    p->next = pubkeys;	/* add p to front of list */
	    pubkeys = p;
	    return p;
	}
    }
    return NULL;	/* failure */
}

/* find the RSA public key.
 * Either in our cache, or from DNS.
 */
const struct RSA_public_key *
get_RSA_public_key(const struct id *id)
{
    struct pubkeyrec *p = get_public_key(id, PUBKEY_ALG_RSA);

    if (p == NULL && opportunism_possible())
    {
	err_t ugh = fetch_public_key(id);

	if (ugh != NULL)
	{
	    char ib[100];	/* arbitrary limit on width of ID reported */

	    (void)idtoa(id, ib, sizeof(ib));
	    loglog(RC_NOKEY, "unable to fetch public key for %s: %s", ib, ugh);
	}
	else
	{
	    /* try search again -- should be successful */
	    p = get_public_key(id, PUBKEY_ALG_RSA);
	    passert(p != NULL);
	}
    }

    return p == NULL? NULL : &p->u.rsa;
}

const struct RSA_public_key *
get_his_RSA_public_key(struct connection *c)
{
    return c->gw_info != NULL
	? &c->gw_info->gw_key
	: get_RSA_public_key(&c->that.id);
}

void
add_public_key(const struct id *id, enum pubkey_alg alg, chunk_t *key)
{
    struct pubkeyrec *p = alloc_thing(struct pubkeyrec, "pubkeyrec");

    /* first: algorithm-specific decoding of key chunk */
    switch (alg)
    {
    case PUBKEY_ALG_RSA:
	{
	    err_t ugh = unpack_RSA_public_key(&p->u.rsa, key);

	    if (ugh != NULL)
	    {
		loglog(RC_LOG_SERIOUS, "%s", ugh);
		pfree(p);
		return;
	    }
	}
	break;
    default:
	passert(FALSE);
    }

    p->id = *id;
    unshare_id_content(&p->id);

    p->alg = alg;

    /* just before installing, delete any previous key of this type
     * for this id.
     */
    {
	struct pubkeyrec *q = get_public_key(id, alg);

	if (q != NULL)
	{
	    passert(q == pubkeys);
	    free_first_public_key();
	}
    }

    p->next = pubkeys;
    pubkeys = p;
}
