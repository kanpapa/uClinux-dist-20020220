/* Structure of messages from whack to Pluto proper.
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
 * RCSID $Id: whack.h,v 1.35 2001/01/28 21:03:05 dhr Exp $
 */

#include <freeswan.h>

/*
 * Since the message remains on one host, native representation is used.
 * Think of this as horizontal microcode: all selected operations are
 * to be done (in the order declared here).
 *
 * MAGIC is used to help detect verion mismatches between whack and Pluto.
 * Whenever the interface (i.e. this struct) changes in form or
 * meaning, change this value (probably by changing the last number).
 */
#define WHACK_MAGIC (('w' << 24) + ('a' << 16) + ('k' << 8) + 10)

/* struct whack_end is a lot like connection.h's struct end
 * It differs because it is going to be shipped down a socket
 * and because whack is a separate program from pluto.
 */
struct whack_end {
    char *id;	/* id string (if any) -- decoded by pluto */

    ip_address
	host_addr,
	host_nexthop;
    ip_subnet client;

    bool has_client;
    char *updown;	/* string */
    u_int16_t host_port;	/* host order */
};

struct whack_message {
    unsigned int magic;

    /* name is used in connection and initiate */
    size_t name_len;	/* string 1 */
    char *name;

    /* for WHACK_OPTIONS: */

    bool whack_options;

    unsigned int debugging;

    /* for WHACK_CONNECTION */

    bool whack_connection;
    bool whack_async;

    lset_t policy;
    time_t sa_ike_life_seconds;
    time_t sa_ipsec_life_seconds;
    time_t sa_rekey_margin;
    unsigned long sa_rekey_fuzz;
    unsigned long sa_keying_tries;

    /* note that each end contains string 2/4.id and string 3/5 updown */
    struct whack_end left;
    struct whack_end right;

    /* note: if the client is the gateway, the following must be equal */
    sa_family_t addr_family;	/* between gateways */
    sa_family_t tunnel_addr_family;	/* between clients */

    /* for WHACK_KEY: */
    bool whack_key;
    char *keyid;	/* string 6 */
    enum pubkey_alg pubkey_alg;
    chunk_t keyval;	/* chunk */

    /* for WHACK_ROUTE: */
    bool whack_route;

    /* for WHACK_UNROUTE: */
    bool whack_unroute;

    /* for WHACK_INITIATE: */
    bool whack_initiate;

    /* for WHACK_OPINITIATE */
    bool whack_oppo_initiate;
    ip_address oppo_my_client, oppo_peer_client;

    /* for WHACK_TERMINATE: */
    bool whack_terminate;

    /* for WHACK_DELETE: */
    bool whack_delete;

    /* for WHACK_LISTEN: */
    bool whack_listen, whack_unlisten;

    /* for WHACK_STATUS: */
    bool whack_status;

    /* for WHACK_SHUTDOWN */
    bool whack_shutdown;

    /* space for strings (hope there is enough room):
     * Note that pointers don't travel on wire.
     * 1 connection name [name_len]
     * 2 left's name [left.host.name.len]
     * 3 left's routescipt
     * 4 right's name [left.host.name.len]
     * 5 right's updown
     * 6 keyid
     * plus keyval (limit: 8K bits + overhead), a chunk.
     */
    size_t str_size;
    char string[2048];
};

/* Codes for status messages returned to whack.
 * These are 3 digit decimal numerals.  The structure
 * is inspired by section 4.2 of RFC959 (FTP).
 * Since these will end up as the exit status of whack, they
 * must be less than 256.
 * NOTE: ipsec_auto(8) knows about some of these numbers -- change carefully.
 */
enum rc_type {
    RC_COMMENT,		/* non-commital utterance (does not affect exit status) */
    RC_WHACK_PROBLEM,	/* whack-detected problem */
    RC_LOG,		/* message aimed at log (does not affect exit status) */
    RC_LOG_SERIOUS,	/* serious message aimed at log (does not affect exit status) */
    RC_SUCCESS,		/* success (exit status 0) */

    /* failure, but not definitive */

    RC_RETRANSMISSION = 10,

    /* improper request */

    RC_DUPNAME = 20,	/* attempt to reuse a connection name */
    RC_UNKNOWN_NAME,	/* connection name unknown */
    RC_ORIENT,	/* cannot orient connection: neither end is us */
    RC_CLASH,	/* clash between two Road Warrior connections */
    RC_DEAF,	/* need --listen before --initiate */
    RC_ROUTE,	/* cannot route */
    RC_RTBUSY,	/* cannot unroute: route busy */
    RC_BADID,	/* malformed --id */
    RC_NOKEY,	/* no key found through DNS */
    RC_NOPEERIP,	/* cannot initiate when peer IP is unknown */

    /* permanent failure */

    RC_BADWHACKMESSAGE = 30,
    RC_NORETRANSMISSION,
    RC_INTERNALERR,
    RC_OPPOFAILURE,	/* Opportunism failed */

    /* progress: start of range for successful state transition.
     * Actual value is RC_NEW_STATE plus the new state code.
     */
    RC_NEW_STATE = 100,

    /* start of range for notification.
     * Actual value is RC_NOTIFICATION plus code for notification
     * that should be generated by this Pluto.
     */
    RC_NOTIFICATION = 200	/* as per IKE notification messages */
};
