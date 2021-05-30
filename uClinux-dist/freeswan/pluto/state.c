/* routines for state objects
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
 * RCSID $Id: state.c,v 1.82 2001/06/05 03:14:28 dhr Exp $
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>

#include <freeswan.h>

#include "constants.h"
#include "defs.h"
#include "id.h"
#include "connections.h"	/* needs id.h */
#include "state.h"
#include "kernel.h"
#include "log.h"
#include "rnd.h"
#include "timer.h"
#include "whack.h"

#include "sha1.h"
#include "md5.h"
#include "crypto.h" /* requires sha1.h and md5.h */

/*
 * Global variables: had to go somewhere, might as well be this file.
 */

u_int16_t pluto_port = IKE_UDP_PORT;	/* Pluto's port */

/*
 * This file has the functions that handle the
 * state hash table and the Message ID list.
 */

/* Message-IDs
 *
 * A Message ID is contained in each IKE message header.
 * For Phase 1 exchanges (Main and Aggressive), it will be zero.
 * For other exchanges, which must be under the protection of an
 * ISAKMP SA, the Message ID must be unique within that ISAKMP SA.
 * Effectively, this labels the message as belonging to a particular
 * exchange.
 * BTW, we feel this uniqueness allows rekeying to be somewhat simpler
 * than specified by draft-jenkins-ipsec-rekeying-06.txt.
 *
 * A MessageID is a 32 bit unsigned number.  We represent the value
 * internally in network order -- they are just blobs to us.
 * They are unsigned numbers to make hashing and comparing easy.
 *
 * The following mechanism is used to allocate message IDs.  This
 * requires that we keep track of which numbers have already been used
 * so that we don't allocate one in use.
 */

struct msgid_list
{
    msgid_t               msgid; /* network order */
    struct msgid_list     *next;
};

bool
reserve_msgid(struct state *isakmp_sa, msgid_t msgid)
{
    struct msgid_list *p;

    passert(IS_ISAKMP_SA_ESTABLISHED(isakmp_sa->st_state));

    for (p = isakmp_sa->st_used_msgids; p != NULL; p = p->next)
	if (p->msgid == msgid)
	    return FALSE;

    p = alloc_thing(struct msgid_list, "msgid");
    p->msgid = msgid;
    p->next = isakmp_sa->st_used_msgids;
    isakmp_sa->st_used_msgids = p;
    return TRUE;
}

msgid_t
generate_msgid(struct state *isakmp_sa)
{
    int timeout = 100;	/* only try so hard for unique msgid */
    msgid_t msgid;

    passert(IS_ISAKMP_SA_ESTABLISHED(isakmp_sa->st_state));

    for (;;)
    {
	get_rnd_bytes((void *) &msgid, sizeof(msgid));
	if (msgid != 0 && reserve_msgid(isakmp_sa, msgid))
	    break;

	if (--timeout == 0)
	{
	    log("gave up looking for unique msgid; using 0x%08lx",
		(unsigned long) msgid);
	    break;
	}
    }
    return msgid;
}


/* state table functions */

#define STATE_TABLE_SIZE 32

static struct state *statetable[STATE_TABLE_SIZE];

static struct state **
state_hash(const u_char *icookie, const u_char *rcookie, const ip_address *peer)
{
    u_int i = 0, j;
    const unsigned char *byte_ptr;
    size_t length = addrbytesptr(peer, &byte_ptr);

    DBG(DBG_RAW | DBG_CONTROL,
	DBG_dump("ICOOKIE:", icookie, COOKIE_SIZE);
	DBG_dump("RCOOKIE:", rcookie, COOKIE_SIZE);
	DBG_dump("peer:", byte_ptr, length));

    /* XXX the following hash is pretty pathetic */

    for (j = 0; j < COOKIE_SIZE; j++)
	i = i * 407 + icookie[j] + rcookie[j];

    for (j = 0; j < length; j++)
	i = i * 613 + byte_ptr[j];

    i = i % STATE_TABLE_SIZE;

    DBG(DBG_CONTROL, DBG_log("state hash entry %d", i));

    return &statetable[i];
}

/* Get a state object.
 * Caller must schedule an event for this object so that it doesn't leak.
 * Caller must insert_state().
 */
struct state *
new_state(void)
{
    static const struct state blank_state;	/* initialized all to zero & NULL */
    static so_serial_t next_so = SOS_FIRST;
    struct state *st;

    st = clone_thing(blank_state, "struct state in new_state()");
    st->st_serialno = next_so++;
    passert(next_so > SOS_FIRST);	/* overflow can't happen! */
    st->st_whack_sock = NULL_FD;
    DBG(DBG_CONTROL, DBG_log("creating state object #%lu at %p",
	st->st_serialno, (void *) st));
    return st;
}

/*
 * Initialize the state table (and mask*).
 */
void
init_states(void)
{
    int i;

    for (i = 0; i < STATE_TABLE_SIZE; i++)
	statetable[i] = (struct state *) NULL;
}

/* Find the state object with this serial number.
 * This allows state object references that don't turn into dangerous
 * dangling pointers: reference a state by its serial number.
 * Returns NULL if there is no such state.
 * If this turns out to be a significant CPU hog, it could be
 * improved to use a hash table rather than sequential seartch.
 */
struct state *
state_with_serialno(so_serial_t sn)
{
    if (sn >= SOS_FIRST)
    {
	struct state *st;
	int i;

	for (i = 0; i < STATE_TABLE_SIZE; i++)
	    for (st = statetable[i]; st != NULL; st = st->st_hashchain_next)
		if (st->st_serialno == sn)
		    return st;
    }
    return NULL;
}

/* Insert a state object in the hash table. The object is inserted
 * at the begining of list.
 * Needs cookies, connection, and msgid.
 */
void
insert_state(struct state *st)
{
    struct state **p = state_hash(st->st_icookie, st->st_rcookie
	, &st->st_connection->that.host_addr);

    passert(st->st_hashchain_prev == NULL && st->st_hashchain_next == NULL);

    if (*p != NULL)
    {
	passert((*p)->st_hashchain_prev == NULL);
	(*p)->st_hashchain_prev = st;
    }
    st->st_hashchain_next = *p;
    *p = st;

    /* Ensure that somebody is in charge of killing this state:
     * if no event is scheduled for it, schedule one to discard the state.
     * If nothing goes wrong, this event will be replaced by
     * a more appropriate one.
     */
    if (st->st_event == NULL) {
	event_schedule(EVENT_SO_DISCARD, 0, st);
    }
}

/* unlink a state object from the hash table, but don't free it
 */
void
unhash_state(struct state *st)
{
    /* unlink from forward chain */
    struct state **p = st->st_hashchain_prev == NULL
	? state_hash(st->st_icookie, st->st_rcookie, &st->st_connection->that.host_addr)
	: &st->st_hashchain_prev->st_hashchain_next;

    /* unlink from forward chain */
    passert(*p == st);
    *p = st->st_hashchain_next;

    /* unlink from backward chain */
    if (st->st_hashchain_next != NULL)
    {
	passert(st->st_hashchain_next->st_hashchain_prev == st);
	st->st_hashchain_next->st_hashchain_prev = st->st_hashchain_prev;
    }

    st->st_hashchain_next = st->st_hashchain_prev = NULL;
}

/* Free the Whack socket file descriptor.
 * This has the side effect of telling Whack that we're done.
 */
void
release_whack(struct state *st)
{
    if (st->st_whack_sock != NULL_FD)
    {
	close(st->st_whack_sock);
	st->st_whack_sock = NULL_FD;
    }
}

/*
 * delete a state object
 */
void
delete_state(struct state *st)
{
    /* Check that no timer event is left dangling.
     * We could actually delete it here, but in most
     * cases this is a "can't happen".
     */
    struct connection *const c = st->st_connection;
    struct state *old_cur_state = cur_state == st? NULL : cur_state;

    cur_state = st;
#ifdef DEBUG
    extra_debugging(c);
#endif
    passert(st->st_event == NULL);

    /* Ditch anything pending on ISAKMP SA being established.
     * Note: this must be done before the unhash_state to prevent
     * flush_pending_by_state inadvertently and prematurely
     * deleting our connection.
     */
    flush_pending_by_state(st);

    /* effectively, this deletes any ISAKMP SA that this state represents */
    unhash_state(st);

    /* tell kernel to delete any IPSEC SA
     * ??? we ought to tell peer to delete IPSEC SAs
     */
    if (IS_IPSEC_SA_ESTABLISHED(st->st_state))
	delete_ipsec_sa(st, FALSE);
    else if (IS_ONLY_INBOUND_IPSEC_SA_ESTABLISHED(st->st_state))
	delete_ipsec_sa(st, TRUE);

    if (c->newest_ipsec_sa == st->st_serialno)
	c->newest_ipsec_sa = SOS_NOBODY;

    if (c->newest_isakmp_sa == st->st_serialno)
	c->newest_isakmp_sa = SOS_NOBODY;

    st->st_connection = NULL;	/* we might be about to free it */
    cur_state = old_cur_state;	/* without st_connection, st isn't complete */
    connection_discard(c);

    release_whack(st);

    /* from here on we are just freeing RAM */

    {
	struct msgid_list *p = st->st_used_msgids;

	while (p != NULL)
	{
	    struct msgid_list *q = p;
	    p = p->next;
	    pfree(q);
	}
    }

    if (st->st_sec_in_use)
	mpz_clear(&(st->st_sec));

    pfreeany(st->st_tpacket.ptr);
    pfreeany(st->st_rpacket.ptr);
    pfreeany(st->st_p1isa.ptr);
    pfreeany(st->st_gi.ptr);
    pfreeany(st->st_gr.ptr);
    pfreeany(st->st_shared.ptr);
    pfreeany(st->st_ni.ptr);
    pfreeany(st->st_nr.ptr);
    pfreeany(st->st_skeyid.ptr);
    pfreeany(st->st_skeyid_d.ptr);
    pfreeany(st->st_skeyid_a.ptr);
    pfreeany(st->st_skeyid_e.ptr);
    pfreeany(st->st_enc_key.ptr);
    pfreeany(st->st_ah.our_keymat);
    pfreeany(st->st_ah.peer_keymat);
    pfreeany(st->st_esp.our_keymat);
    pfreeany(st->st_esp.peer_keymat);

    pfree(st);
}

/* Is a connection in use by some state? */
bool
states_use_connection(struct connection *c)
{
    /* are there any states still using it? */
    struct state *st = NULL;
    int i;

    for (i = 0; st == NULL && i < STATE_TABLE_SIZE; i++)
	for (st = statetable[i]; st != NULL; st = st->st_hashchain_next)
	    if (st->st_connection == c)
		return TRUE;

    return FALSE;
}

/* If a connection will no longer be used, and it is temporary, delete it.
 * We must be careful to avoid circularity:
 * we don't touch it if it is rwcs_going_away.
 */
void
rw_connection_discard(struct connection *c)
{
    if (c->rw_state == rwcs_instance)
    {
	/* are there any states still using it? */
	struct state *st = NULL;
	int i;

	DBG(DBG_CONTROL, DBG_log("rw_connection_discard"));
	for (i = 0; st == NULL && i < STATE_TABLE_SIZE; i++)
	    for (st = statetable[i]
	    ; st != NULL && st->st_connection != c
	    ; st = st->st_hashchain_next)
		;
	if (st == NULL)
	    delete_connection(c);
    }
}


void
delete_states_by_connection(struct connection *c)
{
    int i;

    /* this kludge avoids an n^2 algorithm */
    enum connection_kind ck = c->kind;

    if (ck == CK_INSTANCE)
	c->kind = CK_GOING_AWAY;

    for (i = 0; i < STATE_TABLE_SIZE; i++)
    {
	struct state *st;

	for (st = statetable[i]; st != NULL; )
	{
	    struct state *this = st;

	    st = st->st_hashchain_next;	/* before this is deleted */

	    if (this->st_connection == c)
	    {
		struct state *old_cur_state
		    = cur_state == this? NULL : cur_state;
#ifdef DEBUG
		unsigned int old_cur_debugging = cur_debugging;
#endif

		cur_state = this;
#ifdef DEBUG
		extra_debugging(this->st_connection);
#endif
		log("deleting state (%s)"
		    , enum_show(&state_names, this->st_state));
		passert(this->st_event != NULL);
		delete_event(this);
		delete_state(this);
		cur_state = old_cur_state;
#ifdef DEBUG
		cur_debugging = old_cur_debugging;
#endif
	    }
	}
    }

    passert(c->newest_ipsec_sa == SOS_NOBODY
	&& c->newest_isakmp_sa == SOS_NOBODY
	&& c->eroute_owner == SOS_NOBODY
	&& c->routing != RT_ROUTED_TUNNEL);

    if (ck == CK_INSTANCE)
    {
	c->kind = ck;
	delete_connection(c);
    }
}

/* Duplicate a Phase 1 state object, to create a Phase 2 object.
 * Caller must schedule an event for this object so that it doesn't leak.
 * Caller must insert_state().
 */
struct state *
duplicate_state(const struct state *st)
{
    struct state *nst;

    DBG(DBG_CONTROL, DBG_log("duplicating state object #%lu",
	st->st_serialno));

    nst = new_state();

    memcpy(nst->st_icookie, st->st_icookie, COOKIE_SIZE);
    memcpy(nst->st_rcookie, st->st_rcookie, COOKIE_SIZE);
    nst->st_connection = st->st_connection;

    nst->st_doi = st->st_doi;
    nst->st_situation = st->st_situation;

#   define clone_chunk(ch, name) \
	clonetochunk(nst->ch, st->ch.ptr, st->ch.len, name)

    clone_chunk(st_skeyid_d, "st_skeyid_d in duplicate_state");
    clone_chunk(st_skeyid_a, "st_skeyid_a in duplicate_state");
    clone_chunk(st_skeyid_e, "st_skeyid_e in duplicate_state");
    clone_chunk(st_enc_key, "st_enc_key in duplicate_state");

#   undef clone_chunk

    /* no obvious reason to copy st_peeridentity_protocol and st_peeridentity_port */

    nst->st_oakley = st->st_oakley;

    return nst;
}

/*
 * Find a state object.
 */
struct state *
find_state(const u_char *icookie, const u_char *rcookie,
		const ip_address *peer, msgid_t /*network order*/  msgid)
{
    struct state *st = *state_hash(icookie, rcookie, peer);

    while (st != (struct state *) NULL)
	if (sameaddr(peer, &st->st_connection->that.host_addr)
	&& memcmp(icookie, st->st_icookie, COOKIE_SIZE) == 0
	&& memcmp(rcookie, st->st_rcookie, COOKIE_SIZE) == 0
	&& msgid == st->st_msgid)
	    break;
	else
	    st = st->st_hashchain_next;

    DBG(DBG_CONTROL,
	if (st == NULL)
	    DBG_log("state object not found");
	else
	    DBG_log("state object #%lu found, in %s",
		st->st_serialno,
		enum_show(&state_names, st->st_state)));

    return st;
}

/* Find newest Phase 1 negotiation state object for suitable for connection c
 */
struct state *
find_phase1_state(const struct connection *c)
{
    struct state
	*st,
	*best = NULL;
    int i;

    for (i = 0; i < STATE_TABLE_SIZE; i++)
	for (st = statetable[i]; st != NULL; st = st->st_hashchain_next)
	    if (IS_PHASE1(st->st_state)
	    && c->host_pair == st->st_connection->host_pair
	    && same_peer_ids(c, st->st_connection, NULL)
	    && (best == NULL || best->st_serialno < st->st_serialno))
		best = st;

    return best;
}

void
show_states_status(void)
{
    time_t n = now();
    int i;

    for (i = 0; i < STATE_TABLE_SIZE; i++)
    {
	struct state *st;

	for (st = statetable[i]; st != NULL; st = st->st_hashchain_next)
	{
	    /* what the heck is interesting about a state? */
	    const struct connection *c = st->st_connection;
	    long delta = st->st_event->ev_time >= n
		? (long)(st->st_event->ev_time - n)
		: -(long)(n - st->st_event->ev_time);
	    char him[ADDRTOT_BUF+1];	/* for RW */
	    const char *np1 = c->newest_isakmp_sa == st->st_serialno
		? "; newest ISAKMP" : "";
	    const char *np2 = c->newest_ipsec_sa == st->st_serialno
		? "; newest IPSEC" : "";
	    const char *eo = c->eroute_owner == st->st_serialno
		? "; eroute owner" : "";

	    passert(st->st_event != 0);

	    him[0] = '\0';
	    if (c->kind == CK_INSTANCE)
	    {
		him[0] = ':';
		addrtot(&c->that.host_addr, 0, him+1, sizeof(him)-1);
	    }

	    whack_log(RC_COMMENT
		, "#%lu: \"%s\"%s %s (%s); %s in %lds%s%s%s"
		, st->st_serialno
		, c->name
		, him
		, enum_name(&state_names, st->st_state)
		, state_story[st->st_state - STATE_MAIN_R0]
		, enum_name(&timer_event_names, st->st_event->ev_type)
		, delta
		, np1, np2, eo);

	    /* print out SPIs if SAs are established */
	    if (IS_IPSEC_SA_ESTABLISHED(st->st_state))
	    {
		char buf[SATOT_BUF*6 + 1];
		char *p = buf;

#		define add_said(adst, aspi, aproto) { \
		    ip_said s; \
		    \
		    initsaid(adst, aspi, aproto, &s); \
		    if (p < &buf[sizeof(buf)-1]) \
		    { \
			*p++ = ' '; \
			p += satot(&s, 0, p, &buf[sizeof(buf)] - p) - 1; \
		    } \
		}


		*p = '\0';
		if (st->st_ah.present)
		{
		    add_said(&c->that.host_addr, st->st_ah.attrs.spi, SA_AH);
		    add_said(&c->this.host_addr, st->st_ah.our_spi, SA_AH);
		}
		if (st->st_esp.present)
		{
		    add_said(&c->that.host_addr, st->st_esp.attrs.spi, SA_ESP);
		    add_said(&c->this.host_addr, st->st_esp.our_spi, SA_ESP);
		}
		if (st->st_ipcomp.present)
		{
		    add_said(&c->that.host_addr, st->st_ipcomp.attrs.spi, SA_COMP);
		    add_said(&c->this.host_addr, st->st_ipcomp.our_spi, SA_COMP);
		}
#ifdef KLIPS
		if (st->st_ah.attrs.encapsulation == ENCAPSULATION_MODE_TUNNEL
		|| st->st_esp.attrs.encapsulation == ENCAPSULATION_MODE_TUNNEL
		|| st->st_ipcomp.attrs.encapsulation == ENCAPSULATION_MODE_TUNNEL)
		{
		    add_said(&c->that.host_addr, st->st_tunnel_out_spi, SA_IPIP);
		    add_said(&c->this.host_addr, st->st_tunnel_in_spi, SA_IPIP);
		}
#endif
		whack_log(RC_COMMENT
		    , "#%lu: \"%s\"%s%s"
		    , st->st_serialno
		    , c->name
		    , him
		    , buf);

#		undef add_said
	    }
	}
    }
}

/* Given that we've used up a range of unused CPI's,
 * search for a new range of currently unused ones.
 * Note: this is very expensive when not trivial!
 * If we can't find one easily, choose 0 (a bad SPI,
 * no matter what order) indicating failure.
 */
void
find_my_cpi_gap(cpi_t *latest_cpi, cpi_t *first_busy_cpi)
{
    int tries = 0;
    cpi_t base = *latest_cpi;
    cpi_t closest;
    int i;

startover:
    closest = ~0;	/* not close at all */
    for (i = 0; i < STATE_TABLE_SIZE; i++)
    {
	struct state *st;

	for (st = statetable[i]; st != NULL; st = st->st_hashchain_next)
	{
	    if (st->st_ipcomp.present)
	    {
		cpi_t c = ntohl(st->st_ipcomp.our_spi) - base;

		if (c < closest)
		{
		    if (c == 0)
		    {
			/* oops: next spot is occupied; start over */
			if (++tries == 20)
			{
			    /* FAILURE */
			    *latest_cpi = *first_busy_cpi = 0;
			    return;
			}
			base++;
			if (base > IPCOMP_LAST_NEGOTIATED)
			    base = IPCOMP_FIRST_NEGOTIATED;
			goto startover;	/* really a tail call */
		    }
		    closest = c;
		}
	    }
	}
    }
    *latest_cpi = base;	/* base is first in next free range */
    *first_busy_cpi = closest + base;	/* and this is the roof */
}

/* Muck with high-order 16 bits of this SPI in order to make
 * the corresponding SAID unique.
 * Its low-order 16 bits hold a well-known IPCOMP CPI.
 * Oh, and remember that SPIs are stored in network order.
 * Kludge!!!  So I name it with the non-English word "uniquify".
 * If we can't find one easily, return 0 (a bad SPI,
 * no matter what order) indicating failure.
 */
ipsec_spi_t
uniquify_his_cpi(ipsec_spi_t cpi, struct state *st)
{
    int tries = 0;
    int i;

startover:

    /* network order makes first two bytes our target */
    get_rnd_bytes((u_char *)&cpi, 2);

    /* Make sure that the result is unique.
     * Hard work.  If there is no unique value, we'll loop forever!
     */
    for (i = 0; i < STATE_TABLE_SIZE; i++)
    {
	struct state *s;

	for (s = statetable[i]; s != NULL; s = s->st_hashchain_next)
	{
	    if (s->st_ipcomp.present
	    && sameaddr(&s->st_connection->that.host_addr
	      , &st->st_connection->that.host_addr)
	    && cpi == s->st_ipcomp.attrs.spi)
	    {
		if (++tries == 20)
		    return 0;	/* FAILURE */
		goto startover;
	    }
	}
    }
    return cpi;
}
