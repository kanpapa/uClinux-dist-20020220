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
 * RCSID $Id: preshared.h,v 1.17 2000/08/18 05:20:18 dhr Exp $
 */

#include <gmp.h>    /* GNU MP library */

#ifndef SHARED_SECRETS_FILE
# define SHARED_SECRETS_FILE  "/etc/ipsec.secrets"
#endif

const char *shared_secrets_file;

extern void load_preshared_secrets(void);
extern void free_preshared_secrets(void);

struct state;	/* forward declaration */

enum PrivateKeyKind {
    PPK_PSK,
    /* PPK_DSS, */	/* not implemented */
    PPK_RSA
};

extern const chunk_t *get_preshared_secret(struct connection *c);

struct RSA_public_key
{
    /* length of modulus n in octets: [RSA_MIN_OCTETS, RSA_MAX_OCTETS] */
    unsigned k;

    /* public: */
    MP_INT
	n,	/* modulus: p * q */
	e;	/* exponent: relatively prime to (p-1) * (q-1) [probably small] */
};

struct RSA_private_key {
    struct RSA_public_key pub;	/* must be at start for RSA_show_public_key */

    MP_INT
	d,	/* private exponent: (e^-1) mod ((p-1) * (q-1)) */
	/* help for Chinese Remainder Theorem speedup: */
	p,	/* first secret prime */
	q,	/* second secret prime */
	dP,	/* first factor's exponent: (e^-1) mod (p-1) == d mod (p-1) */
	dQ,	/* second factor's exponent: (e^-1) mod (q-1) == d mod (q-1) */
	qInv;	/* (q^-1) mod p */
};

extern err_t unpack_RSA_public_key(struct RSA_public_key *rsa, chunk_t *pubkey);

extern const struct RSA_private_key *get_RSA_private_key(struct connection *c);

/* public key machinery  */

extern void free_public_keys(void);
extern void add_public_key(const struct id *id, enum pubkey_alg alg, chunk_t *key);

extern const struct RSA_public_key *get_RSA_public_key(const struct id *id)
    , *get_his_RSA_public_key(struct connection *c);

extern bool same_RSA_public_key(const struct RSA_public_key *a
    , const struct RSA_public_key *b);
