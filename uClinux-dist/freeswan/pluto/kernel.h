/* declarations of routines that interface with the kernel's IPsec mechanism
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
 * RCSID $Id: kernel.h,v 1.24 2001/06/05 03:14:28 dhr Exp $
 */

extern bool no_klips;	/* don't actually use KLIPS */
extern bool can_do_IPcomp;  /* can system actually perform IPCOMP? */

#ifdef KLIPS
extern int pfkeyfd;
extern void pfkey_dequeue(void);
extern void pfkey_event(void);
#endif

extern void init_kernel(void);

extern void scan_proc_shunts(void);

extern void pfkey_event(void);

struct connection;	/* forward declaration of tag */
extern bool trap_connection(struct connection *c);
extern void unroute_connection(struct connection *c);

extern bool replace_bare_shunt(const ip_address *src, const ip_address *dst
    , ipsec_spi_t shunt_spi	/* in host order! */
    , bool repl, const char *opname);

extern bool assign_hold(struct connection *c
    , const ip_address *src, const ip_address *dst);

struct state;	/* forward declaration of tag */
extern ipsec_spi_t get_ipsec_spi(ipsec_spi_t avoid);
extern ipsec_spi_t get_my_cpi(void);

extern bool install_inbound_ipsec_sa(struct state *st);
extern bool install_ipsec_sa(struct state *st, bool inbound_also);
extern void delete_ipsec_sa(struct state *st, bool inbound_only);
