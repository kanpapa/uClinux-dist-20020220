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
 * RCSID $Id: dnskey.h,v 1.12 2001/02/26 23:21:30 dhr Exp $
 */

extern err_t fetch_public_key(const struct id *id);

/* Gateway info gleaned from reverse DNS of client */
struct gw_info {
    time_t created_time
	, last_tried_time
	, last_worked_time;
#define NO_TIME ((time_t) -2)	/* time_t value meaning "not_yet" */
    struct id client_id;	/* id of client of peer */
    struct id gw_id;	/* id of peer (if id_is_ipaddr, .ip_addr is address) */
    struct RSA_public_key gw_key;
    struct gw_info *next;
};

/* find a new gateway */
extern err_t
    discover_gateway(const ip_address *peer_client
	, const struct id *putative_sgw
	, struct gw_info **gwp);
