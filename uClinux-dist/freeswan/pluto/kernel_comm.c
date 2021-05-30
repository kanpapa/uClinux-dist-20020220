/* whack communicating routines
 * Copyright (C) 1997 Angelos D. Keromytis.
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
 * RCSID $Id: kernel_comm.c,v 1.61 2001/05/29 18:39:57 dhr Exp $
 */

#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <freeswan.h>

#include "constants.h"
#include "defs.h"
#include "id.h"
#include "connections.h"	/* needs id.h */
#include "whack.h"	/* needs connections.h */
#include "packet.h"
#include "demux.h"	/* needs packet.h */
#include "state.h"
#include "ipsec_doi.h"	/* needs demux.h and state.h */
#include "kernel.h"
#include "kernel_comm.h"
#include "log.h"
#include "preshared.h"
#include "dnskey.h"
#include "server.h"

/* helper variables and function to decode strings from whack message */

static char *next_str
    , *str_roof;

static bool
unpack_str(char **p)
{
    char *end = memchr(next_str, '\0', str_roof - next_str);

    if (end == NULL)
    {
	return FALSE;	/* fishy: no end found */
    }
    else
    {
	*p = next_str == end? NULL : next_str;
	next_str = end + 1;
	return TRUE;
    }
}

/* Handle a kernel request. Supposedly, there's a message in
 * the kernelsock socket.
 */
void
whack_handle(int whackctlfd)
{
    struct whack_message msg;
    struct sockaddr_un whackaddr;
    int whackaddrlen = sizeof(whackaddr);
    int whackfd = accept(whackctlfd, (struct sockaddr *)&whackaddr, &whackaddrlen);
    ssize_t n;

    if (whackfd < 0)
    {
	log_errno((e, "accept() failed in whack_handle()"));
	return;
    }
    n = read(whackfd, &msg, sizeof(msg));
    if (n == -1)
    {
	log_errno((e, "read() failed in whack_handle()"));
	close(whackfd);
	return;
    }

    whack_log_fd = whackfd;

    /* sanity check message */
    {
	err_t ugh = NULL;

	next_str = msg.string;
	str_roof = (char *)&msg + n;

	if (next_str > str_roof)
	{
	    ugh = builddiag("truncated message from whack: got %d bytes; expected %d.  Message ignored."
		, n, (int) sizeof(msg));
	}
	else if (msg.magic != WHACK_MAGIC)
	{
	    ugh = builddiag("message from whack has bad magic %d; should be %d; probably wrong version.  Message ignored"
		, msg.magic, WHACK_MAGIC);
	}
	else if (!unpack_str(&msg.name)	/* string 1 */
	|| !unpack_str(&msg.left.id)	/* string 2 */
	|| !unpack_str(&msg.left.updown)	/* string 3 */
	|| !unpack_str(&msg.right.id)	/* string 4 */
	|| !unpack_str(&msg.right.updown)	/* string 5 */
	|| !unpack_str(&msg.keyid)	/* string 6 */
	|| str_roof - next_str != (ptrdiff_t)msg.keyval.len)	/* check chunk */
	{
	    ugh = "message from whack contains bad string";
	}
	else
	{
	    msg.keyval.ptr = next_str;	/* grab chunk */
	}

	if (ugh != NULL)
	{
	    loglog(RC_BADWHACKMESSAGE, "%s", ugh);
	    whack_log_fd = NULL_FD;
	    close(whackfd);
	    return;
	}
    }

    if (msg.whack_options)
    {
#ifdef DEBUG
	if (msg.name == NULL)
	{
	    /* we do a two-step so that if either old or new would
	     * cause the message to print, it will be printed.
	     */
	    cur_debugging |= msg.debugging;
	    DBG(DBG_CONTROL
		, DBG_log("base debugging = %s"
		    , bitnamesof(debug_bit_names, msg.debugging)));
	    cur_debugging = base_debugging = msg.debugging;
	}
	else if (!msg.whack_connection)
	{
	    struct connection *c = con_by_name(msg.name, TRUE);

	    if (c != NULL)
	    {
		c->extra_debugging = msg.debugging;
		DBG(DBG_CONTROL
		    , DBG_log("\"%s\" extra_debugging = %s"
			, c->name
			, bitnamesof(debug_bit_names, c->extra_debugging)));
	    }
	}
#endif
    }

    /* Deleting combined with adding a connection works as replace.
     * To make this more useful, in only this combination,
     * delete will silently ignore the lack of the connection.
     */
    if (msg.whack_delete)
    {
	struct connection *c = con_by_name(msg.name, !msg.whack_connection);

	/* note: this is a "while" because road warrior
	 * leads to multiple connections with the same name.
	 */
	for (; c != NULL; c = con_by_name(msg.name, FALSE))
	    delete_connection(c);
    }

    if (msg.whack_connection)
	add_connection(&msg);

    /* process "listen" before any operation that could require it */
    if (msg.whack_listen)
    {
	log("listening for IKE messages");
	listening = TRUE;
	find_ifaces();
	load_preshared_secrets();
    }
    if (msg.whack_unlisten)
    {
	log("no longer listening for IKE messages");
	listening = FALSE;
    }

    if (msg.whack_key)
    {
	/* add a public key */
	struct id keyid;
	err_t ugh = atoid(msg.keyid, &keyid);

	if (ugh != NULL)
	{
	    loglog(RC_BADID, "bad --keyid: %s", ugh);
	}
	else
	{
	    if (msg.keyval.len == 0)
	    {
		ugh = fetch_public_key(&keyid);
		if (ugh != NULL)
		{
		    char name[100];	/* longer IDs will be truncated in message */

		    (void)idtoa(&keyid, name, sizeof(name));
		    loglog(RC_NOKEY
			, "failure to fetch key for %s from DNS: %s", name, ugh);
		}
	    }
	    else
	    {
		add_public_key(&keyid, msg.pubkey_alg, &msg.keyval);
	    }
	}
    }

    if (msg.whack_route)
    {
	if (!listening)
	    whack_log(RC_DEAF, "need --listen before --route");
	else
	{
	    struct connection *c = con_by_name(msg.name, TRUE);

	    if (c != NULL)
	    {
		SET_CUR_CONNECTION(c);
		if (!oriented(*c))
		    whack_log(RC_ORIENT
			, "we have no ipsecN interface for either end of this connection");
		else if (!trap_connection(c))
		    whack_log(RC_ROUTE, "could not route");
		UNSET_CUR_CONNECTION();
	    }
	}
    }

    if (msg.whack_unroute)
    {
	struct connection *c = con_by_name(msg.name, TRUE);

	if (c != NULL)
	{
	    SET_CUR_CONNECTION(c);
	    if (c->routing >= RT_ROUTED_TUNNEL)
		whack_log(RC_RTBUSY, "cannot unroute: route busy");
	    else
		unroute_connection(c);
	    UNSET_CUR_CONNECTION();
	}
    }

    if (msg.whack_initiate)
    {
	if (!listening)
	    whack_log(RC_DEAF, "need --listen before --initiate");
	else
	    initiate_connection(msg.name
		, msg.whack_async? NULL_FD : dup_any(whackfd));
    }

    if (msg.whack_oppo_initiate)
    {
	if (!listening)
	    whack_log(RC_DEAF, "need --listen before opportunistic initiation");
	else
	    initiate_opportunistic(&msg.oppo_my_client, &msg.oppo_peer_client
		, FALSE
		, msg.whack_async? NULL_FD : dup_any(whackfd));
    }

    if (msg.whack_terminate)
	terminate_connection(msg.name);

    if (msg.whack_status)
    {
	show_ifaces_status();
	whack_log(RC_COMMENT, BLANK_FORMAT);	/* spacer */
	show_connections_status();
	whack_log(RC_COMMENT, BLANK_FORMAT);	/* spacer */
	show_states_status();
    }

    if (msg.whack_shutdown)
    {
	log("shutting down");
	exit_pluto(0);	/* delete lock and leave, with 0 status */
    }

    whack_log_fd = NULL_FD;
    close(whackfd);
}
