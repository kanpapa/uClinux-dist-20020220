/* IPsec DOI and Oakley resolution routines
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
 * RCSID $Id: ipsec_doi.c,v 1.134 2001/06/01 07:38:32 dhr Exp $
 */

#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <freeswan.h>

#include "constants.h"
#include "defs.h"
#include "state.h"
#include "id.h"
#include "connections.h"	/* needs id.h */
#include "preshared.h"
#include "packet.h"
#include "demux.h"	/* needs packet.h */
#include "dnskey.h"
#include "kernel.h"
#include "log.h"
#include "cookie.h"
#include "server.h"
#include "spdb.h"
#include "timer.h"
#include "rnd.h"
#include "ipsec_doi.h"	/* needs demux.h and state.h */
#include "whack.h"

#include "sha1.h"
#include "md5.h"
#include "crypto.h" /* requires sha1.h and md5.h */

typedef stf_status initiator_function(
    int whack_sock,
    struct connection *c,
    struct state *predecessor,
    lset_t policy,
    unsigned long try);


/* MAGIC: perform f, a function that returns notification_t
 * and return from the ENCLOSING stf_status returning function if it fails.
 */
#define RETURN_STF_FAILURE(f) \
    { int r = (f); if (r != NOTHING_WRONG) return STF_FAIL + r; }

/* Compute DH shared secret from our local secret and the peer's public value.
 * We make the leap that the length should be that of the group
 * (see quoted passage at start of ACCEPT_KE).
 */
static void
compute_dh_shared(struct state *st, const chunk_t g
, const struct oakley_group_desc *group)
{
    MP_INT mp_g, mp_shared;

    passert(st->st_sec_in_use);
    n_to_mpz(&mp_g, g.ptr, g.len);
    mpz_init(&mp_shared);
    mpz_powm(&mp_shared, &mp_g, &st->st_sec, group->modulus);
    mpz_clear(&mp_g);
    freeanychunk(st->st_shared);	/* happens in odd error cases */
    st->st_shared = mpz_to_n(&mp_shared, group->bytes);
    mpz_clear(&mp_shared);
#ifdef DODGE_DH_MISSING_ZERO_BUG
    if (st->st_shared.ptr[0] == 0)
	loglog(RC_LOG_SERIOUS, "shared DH secret has leading zero -- triggers Pluto 1.0 bug");
#endif
    DBG_cond_dump_chunk(DBG_CRYPT, "DH shared secret:\n", st->st_shared);
}

/* if we haven't already done so, compute a local DH secret (st->st_sec) and
 * the corresponding public value (g).  This is emitted as a KE payload.
 * KLUDGE: if DODGE_DH_MISSING_ZERO_BUG and we're the responder,
 * this routine computes the shared secret to see if it would
 * have a leading zero.  If so, we try again.
 */
static bool
build_and_ship_KE(struct state *st, chunk_t *g
, const struct oakley_group_desc *group, pb_stream *outs, u_int8_t np)
{
    if (!st->st_sec_in_use)
    {
	u_char tmp[LOCALSECRETSIZE];
	MP_INT mp_g;

	get_rnd_bytes(tmp, LOCALSECRETSIZE);
	st->st_sec_in_use = TRUE;
	n_to_mpz(&st->st_sec, tmp, LOCALSECRETSIZE);

	mpz_init(&mp_g);
	mpz_powm(&mp_g, &groupgenerator, &st->st_sec, group->modulus);
	freeanychunk(*g);	/* happens in odd error cases */
	*g = mpz_to_n(&mp_g, group->bytes);
	mpz_clear(&mp_g);
#ifdef DODGE_DH_MISSING_ZERO_BUG
	if (g->ptr[0] == 0)
	{
	    /* generate a new secret to avoid this situation */
	    loglog(RC_LOG_SERIOUS, "regenerating DH private secret to avoid Pluto 1.0 bug"
		" handling public value with leading zero");
	    mpz_clear(&st->st_sec);
	    st->st_sec_in_use = FALSE;
	    return build_and_ship_KE(st, g, group, outs, np);
	}
	/* if we're the responder, we can compute the shared secret
	 * to see if it would turn out OK.
	 */
	if (g == &st->st_gr)
	{
	    compute_dh_shared(st, st->st_gi
		, IS_PHASE1(st->st_state)
		    ? st->st_oakley.group : st->st_pfs_group);
	    if (st->st_shared.ptr[0] == 0)
	    {
		/* generate a new secret to avoid this situation */
		loglog(RC_LOG_SERIOUS, "regenerating DH private secret to avoid Pluto 1.0 bug"
		    " handling shared secret with leading zero");
		freeanychunk(st->st_shared);
		mpz_clear(&st->st_sec);
		st->st_sec_in_use = FALSE;
		return build_and_ship_KE(st, g, group, outs, np);
	    }
	}
#endif

	DBG(DBG_CRYPT,
	    DBG_dump("Local DH secret:\n", tmp, LOCALSECRETSIZE);
	    DBG_dump_chunk("Public DH value sent:\n", *g));
    }
    return out_generic_chunk(np, &isakmp_keyex_desc, outs, *g, "keyex value");
}

/* accept_ke
 *
 * Check and accept DH public value (Gi or Gr) from peer's message.
 * According to RFC2409 "The Internet key exchange (IKE)" 5:
 *  The Diffie-Hellman public value passed in a KE payload, in either
 *  a phase 1 or phase 2 exchange, MUST be the length of the negotiated
 *  Diffie-Hellman group enforced, if necessary, by pre-pending the
 *  value with zeros.
 * ??? For now, if DODGE_DH_MISSING_ZERO_BUG is defined, we accept shorter
 *     values to interoperate with old Plutos.  This should change some day.
 */
static notification_t
accept_KE(chunk_t *dest, const char *val_name
, const struct oakley_group_desc *gr
, pb_stream *pbs)
{
    if (pbs_left(pbs) != gr->bytes)
    {
	loglog(RC_LOG_SERIOUS, "KE has %u byte DH public value; %u required"
	    , (unsigned) pbs_left(pbs), (unsigned) gr->bytes);
	/* XXX Could send notification back */
#ifdef DODGE_DH_MISSING_ZERO_BUG
	if (pbs_left(pbs) > gr->bytes)
#endif
	    return INVALID_KEY_INFORMATION;
    }
    clonereplacechunk(*dest, pbs->cur, pbs_left(pbs), val_name);
    DBG_cond_dump_chunk(DBG_CRYPT, "DH public value received:\n", *dest);
    return NOTHING_WRONG;
}

/* accept_PFS_KE
 *
 * Check and accept optional Quick Mode KE payload for PFS.
 * Extends ACCEPT_PFS to check whether KE is allowed or required.
 */
static notification_t
accept_PFS_KE(struct msg_digest *md, chunk_t *dest
, const char *val_name, const char *msg_name)
{
    struct state *st = md->st;
    struct payload_digest *const ke_pd = md->chain[ISAKMP_NEXT_KE];

    if (ke_pd == NULL)
    {
	if (st->st_pfs_group != NULL)
	{
	    loglog(RC_LOG_SERIOUS, "missing KE payload in %s message", msg_name);
	    return INVALID_KEY_INFORMATION;
	}
    }
    else
    {
	if (st->st_pfs_group == NULL)
	{
	    loglog(RC_LOG_SERIOUS, "%s message KE payload requires a GROUP_DESCRIPTION attribute in SA"
		, msg_name);
	    return INVALID_KEY_INFORMATION;
	}
	if (ke_pd->next != NULL)
	{
	    loglog(RC_LOG_SERIOUS, "%s message contains several KE payloads; we accept at most one", msg_name);
	    return INVALID_KEY_INFORMATION;	/* ??? */
	}
	return accept_KE(dest, val_name, st->st_pfs_group, &ke_pd->pbs);
    }
    return NOTHING_WRONG;
}

static bool
build_and_ship_nonce(chunk_t *n, pb_stream *outs, u_int8_t np
, const char *name)
{
    setchunk(*n, alloc_bytes(DEFAULT_NONCE_SIZE, name), DEFAULT_NONCE_SIZE);
    get_rnd_bytes(n->ptr, DEFAULT_NONCE_SIZE);
    return out_generic_chunk(np, &isakmp_nonce_desc, outs, *n, name);
}

/*
 * Send a notification to the peer. We could make a decision on
 * whether to send the notification, based on the type and the
 * destination, if we care to.
 * XXX It doesn't handle DELETE notifications (which are also
 * XXX informational exchanges).
 * XXX Not modified to support ip_address and related (IPv4+IPv6) functions.
 */
#if 0 /* not currently used */
//static void
//send_notification(int sock,
//    u_int16_t type,
//    u_char *spi,
//    u_char spilen,
//    u_char protoid,
//    u_char *icookie,
//    u_char *rcookie,
//    msgid_t /*network order*/ msgid,
//    struct sockaddr sa)
//{
//    u_char buffer[sizeof(struct isakmp_hdr) +
//		 sizeof(struct isakmp_notification)];
//    struct isakmp_hdr *isa = (struct isakmp_hdr *) buffer;
//    struct isakmp_notification *isan = (struct isakmp_notification *)
//				       (buffer + sizeof(struct isakmp_hdr));
//
//    memset(buffer, '\0', sizeof(struct isakmp_hdr) +
//	  sizeof(struct isakmp_notification));
//
//    if (icookie != (u_char *) NULL)
//	memcpy(isa->isa_icookie, icookie, COOKIE_SIZE);
//
//    if (rcookie != (u_char *) NULL)
//	memcpy(isa->isa_rcookie, rcookie, COOKIE_SIZE);
//
//    /* Standard header */
//    isa->isa_np = ISAKMP_NEXT_N;
//    isa->isa_version = ISAKMP_MAJOR_VERSION << ISA_MAJ_SHIFT | ISAKMP_MINOR_VERSION;
//    isa->isa_xchg = ISAKMP_XCHG_INFO;
//    isa->isa_msgid = msgid;
//    isa->isa_length = htonl(sizeof(struct isakmp_hdr) +
//			    sizeof(struct isakmp_notification) +
//			    spilen);
//
//    /* Notification header */
//    isan->isan_type = htons(type);
//    isan->isan_doi = htonl(ISAKMP_DOI_IPSEC);
//    isan->isan_length = htons(sizeof(struct isakmp_notification) + spilen);
//    isan->isan_spisize = spilen;
//    memcpy((u_char *)isan + sizeof(struct isakmp_notification), spi, spilen);
//    isan->isan_protoid = protoid;
//
//    DBG(DBG_CONTROL, DBG_log("sending INFO type %s to %s",
//	enum_show(&notification_names, type),
//	show_sa(&sa)));
//
//    if (sendto(sock, buffer, ntohl(isa->isa_length), 0, &sa,
//	       sizeof(sa)) != ntohl(isa->isa_length))
//	log_errno((e, "sendto() failed in send_notification() to %s",
//	    show_sa(&sa)));
//    else
//    {
//	DBG(DBG_CONTROL, DBG_log("transmitted %d bytes", ntohl(isa->isa_length)));
//    }
//}
#endif /* not currently used */

/* The whole message must be a multiple of 4 octets.
 * I'm not sure where this is spelled out, but look at
 * rfc2408 3.6 Transform Payload.
 * Note: it talks about 4 BYTE boundaries!
 */
static void
close_message(pb_stream *pbs)
{
    size_t padding =  pad_up(pbs_offset(pbs), 4);

    if (padding != 0)
	(void) out_zero(padding, pbs, "message padding");
    close_output_pbs(pbs);
}

/* Initiate an Oakley Main Mode exchange.
 * --> HDR;SA
 */
static stf_status
main_outI1(int whack_sock
, struct connection *c
, struct state *predecessor
, lset_t policy
, unsigned long try)
{
    u_char space[8192];	/* NOTE: we assume 8192 is big enough to build the packet */
    pb_stream reply;	/* not actually a reply, but you know what I mean */
    pb_stream rbody;

    struct state *st;

    /* set up new state */
    cur_state = st = new_state();
    st->st_connection = c;
#ifdef DEBUG
    extra_debugging(c);
#endif
    st->st_policy = policy & ~POLICY_IPSEC_MASK;
    st->st_whack_sock = whack_sock;
    st->st_try = try;
    st->st_state = STATE_MAIN_I1;

    get_cookie(ISAKMP_INITIATOR, st->st_icookie, COOKIE_SIZE, &c->that.host_addr);

    insert_state(st);	/* needs cookies, connection, and msgid (0) */

    if (HAS_IPSEC_POLICY(policy))
	add_pending(dup_any(whack_sock), st, c, policy, 1);

    log("initiating Main Mode");

    /* set up reply */
    init_pbs(&reply, space, sizeof(space), "reply packet");

    /* HDR out */
    {
	struct isakmp_hdr hdr;

	zero(&hdr);	/* default to 0 */
	hdr.isa_version = ISAKMP_MAJOR_VERSION << ISA_MAJ_SHIFT | ISAKMP_MINOR_VERSION;
	hdr.isa_np = ISAKMP_NEXT_SA;
	hdr.isa_xchg = ISAKMP_XCHG_IDPROT;
	memcpy(hdr.isa_icookie, st->st_icookie, COOKIE_SIZE);
	/* R-cookie, flags and MessageID are left zero */

	if (!out_struct(&hdr, &isakmp_hdr_desc, &reply, &rbody))
	{
	    cur_state = NULL;
	    return STF_INTERNAL_ERROR;
	}
    }

    /* SA out */
    {
	u_char *sa_start = rbody.cur;
	lset_t auth_policy = policy & POLICY_ID_AUTH_MASK;

	if (auth_policy == LEMPTY)
	{
	    /* unspecified: figure out what we can manage */
	    if (get_preshared_secret(c) != NULL)
		auth_policy |= POLICY_PSK;

	    if (get_RSA_private_key(c) != NULL
	    && get_his_RSA_public_key(c) != NULL)
		auth_policy |= POLICY_RSASIG;
	    /* Not clear what we should do if neither is possible.
	     * Perhaps we should not have entered negotiations at all.
	     */
	    if (auth_policy == LEMPTY)
	    {
		loglog(RC_LOG_SERIOUS, "we don't know how to authenticate this connection");
		cur_state = NULL;
		return STF_INTERNAL_ERROR;
	    }
	}
	if (!out_sa(&rbody
	, &oakley_sadb[auth_policy >> POLICY_ISAKMP_SHIFT]
	, st, TRUE, ISAKMP_NEXT_NONE))
	{
	    cur_state = NULL;
	    return STF_INTERNAL_ERROR;
	}

	/* save initiator SA for later HASH */
	passert(st->st_p1isa.ptr == NULL);	/* no leak!  (MUST be first time) */
	clonetochunk(st->st_p1isa, sa_start, rbody.cur - sa_start
	    , "sa in main_outI1");
    }

    close_message(&rbody);
    close_output_pbs(&reply);

    clonetochunk(st->st_tpacket, reply.start, pbs_offset(&reply)
	, "reply packet for main_outI1");

    /* Transmit */

    send_packet(st, "main_outI1");

    /* Set up a retransmission event, half a minute henceforth */
    delete_event(st);
    event_schedule(EVENT_RETRANSMIT, EVENT_RETRANSMIT_DELAY_0, st);

    if (predecessor != NULL)
    {
	update_pending(predecessor, st);
	whack_log(RC_NEW_STATE + STATE_MAIN_I1
	    , "%s: initiate, replacing #%lu"
	    , enum_name(&state_names, st->st_state)
	    , predecessor->st_serialno);
    }
    else
    {
	whack_log(RC_NEW_STATE + STATE_MAIN_I1
	    , "%s: initiate", enum_name(&state_names, st->st_state));
    }
    cur_state = NULL;
    return STF_NO_REPLY;
}


/* Initiate an Oakley Aggressive Mode exchange.
 * --> HDR, SA, KE, Ni, IDii
 */
static stf_status
aggr_outI1(
	int whack_sock,
	struct connection *c,
	struct state *predecessor,
	lset_t policy,
	unsigned long try)
{
    u_char space[8192];	/* NOTE: we assume 8192 is big enough to build the packet */
    pb_stream reply;	/* not actually a reply, but you know what I mean */
    pb_stream rbody;

    struct state *st;

    /* set up new state */
    cur_state = st = new_state();
    st->st_connection = c;
#ifdef DEBUG
    extra_debugging(c);
#endif
    st->st_policy = policy & ~POLICY_IPSEC_MASK;;
    st->st_whack_sock = whack_sock;
    st->st_try = try;
    st->st_state = STATE_AGGR_I1;

    get_cookie(ISAKMP_INITIATOR, st->st_icookie, COOKIE_SIZE, &c->that.host_addr);

    insert_state(st);	/* needs cookies, connection, and msgid (0) */
    
    if (HAS_IPSEC_POLICY(policy))
	add_pending(dup_any(whack_sock), st, c, policy, 1);
    
    log("initiating Aggressive Mode, state #%lu, connection \"%s\""
	, st->st_serialno, st->st_connection->name);

    /* set up reply */
    init_pbs(&reply, space, sizeof(space), "reply packet");

    /* HDR out */
    {
	struct isakmp_hdr hdr;

	zero(&hdr);	/* default to 0 */
	hdr.isa_version = ISAKMP_MAJOR_VERSION << ISA_MAJ_SHIFT | ISAKMP_MINOR_VERSION;
	hdr.isa_np = ISAKMP_NEXT_SA;
	hdr.isa_xchg = ISAKMP_XCHG_AGGR;
	memcpy(hdr.isa_icookie, st->st_icookie, COOKIE_SIZE);
	/* R-cookie, flags and MessageID are left zero */

	if (!out_struct(&hdr, &isakmp_hdr_desc, &reply, &rbody))
	{
	    cur_state = NULL;
	    return STF_INTERNAL_ERROR;
	}
    }

    /* SA out */
    {
	u_char *sa_start = rbody.cur;
	lset_t auth_policy = policy & POLICY_ID_AUTH_MASK;

	if (auth_policy == LEMPTY)
	{
	    /* unspecified: figure out what we can manage */
	    if (get_preshared_secret(c) != NULL)
		auth_policy |= POLICY_PSK;

	    if (get_RSA_private_key(c) != NULL
	    && get_RSA_public_key(&c->that.id) != NULL)
		auth_policy |= POLICY_RSASIG;
	    /* Not clear what we should do if neither is possible.
	     * Perhaps we should not have entered negotiations at all.
	     */
	    if (auth_policy == LEMPTY)
	    {
		loglog(RC_LOG_SERIOUS, "we don't know how to Authenticate this connection");
		cur_state = NULL;
		return STF_INTERNAL_ERROR;
	    }
	}
	init_st_oakley(st, auth_policy);

	if (!out_sa(&rbody, &oakley_sadb_am, st, TRUE, ISAKMP_NEXT_KE))
	{
	    return STF_INTERNAL_ERROR;
	    cur_state = NULL;
	}

	/* save initiator SA for later HASH */
	passert(st->st_p1isa.ptr == NULL);	/* no leak! */
	clonetochunk(st->st_p1isa, sa_start, rbody.cur - sa_start,
		     "sa in aggr_outI1");
    }

    /* KE out */
    if (!build_and_ship_KE(st, &st->st_gi, st->st_oakley.group,
			   &rbody, ISAKMP_NEXT_NONCE))
	return STF_INTERNAL_ERROR;

    /* Ni out */
    if (!build_and_ship_nonce(&st->st_ni, &rbody, ISAKMP_NEXT_ID, "Ni"))
	return STF_INTERNAL_ERROR;

    /* IDii out */
    {
	struct isakmp_ipsec_id id_hd;
	chunk_t id_b;
	pb_stream id_pbs;

	build_id_payload(&id_hd, &id_b, &st->st_connection->this);
	id_hd.isaiid_np = ISAKMP_NEXT_NONE;
	if (!out_struct(&id_hd, &isakmp_ipsec_identification_desc, &rbody, &id_pbs)
	|| !out_chunk(id_b, &id_pbs, "my identity"))
	    return STF_INTERNAL_ERROR;
	close_output_pbs(&id_pbs);
    }

    /* finish message */

    close_message(&rbody);
    close_output_pbs(&reply);

    clonetochunk(st->st_tpacket, reply.start, pbs_offset(&reply),
		 "reply packet from aggr_outI1");

    /* Transmit */

    DBG_cond_dump(DBG_RAW, "sending:\n",
		  st->st_tpacket.ptr, st->st_tpacket.len);

    send_packet(st, "aggr_outI1");

    /* Set up a retransmission event, half a minute henceforth */
    delete_event(st);
    event_schedule(EVENT_RETRANSMIT, EVENT_RETRANSMIT_DELAY_0, st);

    whack_log(RC_NEW_STATE + STATE_AGGR_I1,
	      "%s: initiate", enum_name(&state_names, st->st_state));
    cur_state = NULL;
    return STF_NO_REPLY;
}


void

ipsecdoi_initiate(int whack_sock
, struct connection *c
, lset_t policy
, unsigned long try)
{
    /* If there's already an ISAKMP SA established, use that and
     * go directly to Quick Mode.
     * Note: there is no way to initiate with a Road Warrior.
     */
    struct state *st = find_phase1_state(c);

    DBG(DBG_CONTROL, DBG_log("ipsecdoi_initiate 1"));
    if (st == NULL)
    {
	initiator_function *initiator = (LALLIN(c->policy, POLICY_AGGRESSIVE)
					 ? aggr_outI1 : main_outI1);
	DBG(DBG_CONTROL, DBG_log("ipsecdoi_initiate 2"));
 	(void) initiator(whack_sock, c, NULL, policy, try);
    }
    else if (HAS_IPSEC_POLICY(policy))
    {
    	DBG(DBG_CONTROL, DBG_log("ipsecdoi_initiate 3"));
	if (!IS_ISAKMP_SA_ESTABLISHED(st->st_state))
	{
	    /* leave our Phase 2 negotiation pending */
	    add_pending(whack_sock, st, c, policy, try);
	}
	else
	{
	    DBG(DBG_CONTROL, DBG_log("ipsecdoi_initiate 4"));
	    /* ??? we assume that peer_nexthop_sin isn't important:
	     * we already have it from when we negotiated the ISAKMP SA!
	     * It isn't clear what to do with the error return.
	     */
	    (void) quick_outI1(whack_sock, st, c, policy, try);
	}
    }
    else if (whack_sock != NULL_FD)
    {
	close(whack_sock);
    }
}

/* Replace SA with a fresh one that is similar
 *
 * Shares some logic with ipsecdoi_initiate, but not the same!
 * - we must not reuse the ISAKMP SA if we are trying to replace it!
 * - if trying to replace IPSEC SA, use ipsecdoi_initiate to build
 *   ISAKMP SA if needed.
 * - duplicate whack fd, if live.
 * Does not delete the old state -- someone else will do that.
 */
void
ipsecdoi_replace(struct state *st, unsigned long try)
{
    int whack_sock = dup_any(st->st_whack_sock);
    lset_t policy = st->st_policy;
    struct connection *c = st->st_connection;

    if (IS_PHASE1(st->st_state))
    {
    	initiator_function *initiator;
	passert(!HAS_IPSEC_POLICY(policy));
	initiator = (LALLIN(c->policy, POLICY_AGGRESSIVE)
 					 ? aggr_outI1 : main_outI1);
 	(void) initiator(whack_sock, c, st, policy, try);
    }
    else
    {
	/* Add features of actual old state to policy.  This ensures
	 * that rekeying doesn't downgrade security.  I admit that
	 * this doesn't capture everything.
	 */
	if (st->st_pfs_group != NULL)
	    policy |= POLICY_PFS;
	if (st->st_ah.present)
	{
	    policy |= POLICY_AUTHENTICATE;
	    if (st->st_ah.attrs.encapsulation == ENCAPSULATION_MODE_TUNNEL)
		policy |= POLICY_TUNNEL;
	}
	if (st->st_esp.present && st->st_esp.attrs.transid != ESP_NULL)
	{
	    policy |= POLICY_ENCRYPT;
	    if (st->st_esp.attrs.encapsulation == ENCAPSULATION_MODE_TUNNEL)
		policy |= POLICY_TUNNEL;
	}
	if (st->st_ipcomp.present)
	{
	    policy |= POLICY_COMPRESS;
	    if (st->st_ipcomp.attrs.encapsulation == ENCAPSULATION_MODE_TUNNEL)
		policy |= POLICY_TUNNEL;
	}
	passert(HAS_IPSEC_POLICY(policy));
	ipsecdoi_initiate(whack_sock, st->st_connection, policy, try);
    }
}

/* SKEYID for preshared keys.
 * See draft-ietf-ipsec-ike-01.txt 4.1
 */
static bool
skeyid_preshared(struct state *st)
{
    const chunk_t *pss = get_preshared_secret(st->st_connection);

    if (pss == NULL)
    {
	loglog(RC_LOG_SERIOUS, "preshared secret disappeared!");
	return FALSE;
    }
    else
    {
	struct hmac_ctx ctx;

	hmac_init_chunk(&ctx, st->st_oakley.hasher, *pss);
	hmac_update_chunk(&ctx, st->st_ni);
	hmac_update_chunk(&ctx, st->st_nr);
	hmac_final_chunk(st->st_skeyid, "st_skeyid in skeyid_preshared()", &ctx);
	return TRUE;
    }
}

static bool
skeyid_digisig(struct state *st)
{
    struct hmac_ctx ctx;
    chunk_t nir;

    /* We need to hmac_init with the concatenation of Ni_b and Nr_b,
     * so we have to build a temporary concatentation.
     */
    nir.len = st->st_ni.len + st->st_nr.len;
    nir.ptr = alloc_bytes(nir.len, "Ni + Nr in skeyid_digisig");
    memcpy(nir.ptr, st->st_ni.ptr, st->st_ni.len);
    memcpy(nir.ptr+st->st_ni.len, st->st_nr.ptr, st->st_nr.len);
    hmac_init_chunk(&ctx, st->st_oakley.hasher, nir);
    pfree(nir.ptr);

    hmac_update_chunk(&ctx, st->st_shared);
    hmac_final_chunk(st->st_skeyid, "st_skeyid in skeyid_digisig()", &ctx);
    return TRUE;
}

/* Generate the SKEYID_* and new IV
 * See draft-ietf-ipsec-ike-01.txt 4.1
 */
static bool
generate_skeyids_iv(struct state *st)
{
    /* Generate the SKEYID */
    switch (st->st_oakley.auth)
    {
	case OAKLEY_PRESHARED_KEY:
	    if (!skeyid_preshared(st))
		return FALSE;
	    break;

	case OAKLEY_RSA_SIG:
	    if (!skeyid_digisig(st))
		return FALSE;
	    break;

	case OAKLEY_DSS_SIG:
	    /* XXX */

	case OAKLEY_RSA_ENC:
	case OAKLEY_RSA_ENC_REV:
	case OAKLEY_ELGAMAL_ENC:
	case OAKLEY_ELGAMAL_ENC_REV:
	    /* XXX */

	default:
	    exit_log("generate_skeyids_iv(): unsupported authentication method %s",
		enum_show(&oakley_auth_names, st->st_oakley.auth));
    }

    /* generate SKEYID_* from SKEYID */
    {
	struct hmac_ctx ctx;

	hmac_init_chunk(&ctx, st->st_oakley.hasher, st->st_skeyid);

	/* SKEYID_D */
	hmac_update_chunk(&ctx, st->st_shared);
	hmac_update(&ctx, st->st_icookie, COOKIE_SIZE);
	hmac_update(&ctx, st->st_rcookie, COOKIE_SIZE);
	hmac_update(&ctx, "\0", 1);
	hmac_final_chunk(st->st_skeyid_d, "st_skeyid_d in generate_skeyids_iv()", &ctx);

	/* SKEYID_A */
	hmac_reinit(&ctx);
	hmac_update_chunk(&ctx, st->st_skeyid_d);
	hmac_update_chunk(&ctx, st->st_shared);
	hmac_update(&ctx, st->st_icookie, COOKIE_SIZE);
	hmac_update(&ctx, st->st_rcookie, COOKIE_SIZE);
	hmac_update(&ctx, "\1", 1);
	hmac_final_chunk(st->st_skeyid_a, "st_skeyid_a in generate_skeyids_iv()", &ctx);

	/* SKEYID_E */
	hmac_reinit(&ctx);
	hmac_update_chunk(&ctx, st->st_skeyid_a);
	hmac_update_chunk(&ctx, st->st_shared);
	hmac_update(&ctx, st->st_icookie, COOKIE_SIZE);
	hmac_update(&ctx, st->st_rcookie, COOKIE_SIZE);
	hmac_update(&ctx, "\2", 1);
	hmac_final_chunk(st->st_skeyid_e, "st_skeyid_e in generate_skeyids_iv()", &ctx);
    }

    /* generate IV */
    {
	union hash_ctx hash_ctx;
	const struct hash_desc *h = st->st_oakley.hasher;

	st->st_new_iv_len = h->hash_digest_len;
	passert(st->st_new_iv_len <= sizeof(st->st_new_iv));

	h->hash_init(&hash_ctx);
	h->hash_update(&hash_ctx, st->st_gi.ptr, st->st_gi.len);
	h->hash_update(&hash_ctx, st->st_gr.ptr, st->st_gr.len);
	h->hash_final(st->st_new_iv, &hash_ctx);
    }

    /* Oakley Keying Material
     * Derived from Skeyid_e: if it is not big enough, generate more
     * using the PRF.
     * See draft-ietf-ipsec-isakmp-oakley-07.txt Appendix B
     */
    {
	const size_t keysize = st->st_oakley.encrypter->keysize;
	u_char keytemp[MAX_OAKLEY_KEY_LEN + MAX_DIGEST_LEN];
	u_char *k = st->st_skeyid_e.ptr;

	if (keysize > st->st_skeyid_e.len)
	{
	    struct hmac_ctx ctx;
	    size_t i = 0;

	    hmac_init_chunk(&ctx, st->st_oakley.hasher, st->st_skeyid_e);
	    hmac_update(&ctx, "\0", 1);
	    for (;;)
	    {
		hmac_final(&keytemp[i], &ctx);
		i += ctx.hmac_digest_len;
		if (i >= keysize)
		    break;
		hmac_reinit(&ctx);
		hmac_update(&ctx, &keytemp[i - ctx.hmac_digest_len], ctx.hmac_digest_len);
	    }
	    k = keytemp;
	}
	clonereplacechunk(st->st_enc_key, k, keysize, "st_enc_key");
    }

    DBG(DBG_CRYPT,
	DBG_dump_chunk("Skeyid:  ", st->st_skeyid);
	DBG_dump_chunk("Skeyid_d:", st->st_skeyid_d);
	DBG_dump_chunk("Skeyid_a:", st->st_skeyid_a);
	DBG_dump_chunk("Skeyid_e:", st->st_skeyid_e);
	DBG_dump_chunk("enc key:", st->st_enc_key);
	DBG_dump("IV:", st->st_new_iv, st->st_new_iv_len));
    return TRUE;
}

/* Generate HASH_I or HASH_R for ISAKMP Phase I.
 * This will *not* generate other hash payloads (eg. Phase II or Quick Mode,
 * New Group Mode, or ISAKMP Informational Exchanges).
 * If the hashi argument is TRUE, generate HASH_I; if FALSE generate HASH_R.
 * If hashus argument is TRUE, we're generating a hash for our end.
 * See RFC2409 IKE 5.
 *
 * Generating the SIG_I and SIG_R for DSS is an odd perversion of this:
 * Most of the logic is the same, but SHA-1 is used in place of HMAC-whatever.
 * The extensive common logic is embodied in main_mode_hash_body().
 * See draft-ietf-ipsec-ike-01.txt 4.1 and 6.1.1.2
 */

static void
main_mode_hash_body(struct state *st, bool hashi, bool hashus
, union hash_ctx *ctx
, void (*hash_update)(union hash_ctx *, const u_char *input, unsigned int len))
{
#if 0	/* if desperate to debug hashing */
#   define hash_update(ctx, input, len) { \
	DBG_cond_dump(DBG_CRYPT, "hash input", input, len); \
	(hash_update)(ctx, input, len); \
	}
#endif

#   define hash_update_chunk(ctx, ch) hash_update((ctx), (ch).ptr, (ch).len)
    if (hashi)
    {
	hash_update_chunk(ctx, st->st_gi);
	hash_update_chunk(ctx, st->st_gr);
	hash_update(ctx, st->st_icookie, COOKIE_SIZE);
	hash_update(ctx, st->st_rcookie, COOKIE_SIZE);
    }
    else
    {
	hash_update_chunk(ctx, st->st_gr);
	hash_update_chunk(ctx, st->st_gi);
	hash_update(ctx, st->st_rcookie, COOKIE_SIZE);
	hash_update(ctx, st->st_icookie, COOKIE_SIZE);
    }

    DBG(DBG_CRYPT, DBG_log("hashing %d bytes of SA"
	, st->st_p1isa.len - sizeof(struct isakmp_generic)));

    /* SA_b */
    hash_update(ctx, st->st_p1isa.ptr + sizeof(struct isakmp_generic)
	, st->st_p1isa.len - sizeof(struct isakmp_generic));

    /* IDio_b (o stands for originator: i or r) */
    {
	/* Hash identification payload, without generic payload header.
	 * Note: the part of header and body used must be in network order!
	 */
	struct connection *c = st->st_connection;
	struct isakmp_ipsec_id id_hd;
	chunk_t id_b;

	build_id_payload(&id_hd, &id_b, hashus? &c->this : &c->that);
	if (!hashus)
	{
	    /* ugly feature *we* don't use */
	    id_hd.isaiid_protoid = st->st_peeridentity_protocol;
	    id_hd.isaiid_port = htons(st->st_peeridentity_port);
	}
	DBG(DBG_CRYPT,
	    DBG_log("Hashing %s ID: Type %s, Protocol %d, Port %d"
		, hashus? "my" : "his"
		, enum_show(&ident_names, id_hd.isaiid_idtype)
		, id_hd.isaiid_protoid, htons(id_hd.isaiid_port)));

	/* NOTE: hash does NOT include the generic payload part of
	 * Identity Payload
	 */
	hash_update(ctx
	    , (u_char *)&id_hd + sizeof(struct isakmp_generic)
	    , sizeof(id_hd) - sizeof(struct isakmp_generic));

	hash_update_chunk(ctx, id_b);
    }
#   undef hash_update_chunk
#   undef hash_update
}

static size_t
main_mode_hash(struct state *st, u_char *hash_val
, bool hashi, bool hashus)
{
    struct hmac_ctx ctx;

    hmac_init_chunk(&ctx, st->st_oakley.hasher, st->st_skeyid);
    main_mode_hash_body(st, hashi, hashus, &ctx.hash_ctx, ctx.h->hash_update);
    hmac_final(hash_val, &ctx);
    return ctx.hmac_digest_len;
}

#if 0	/* only needed for DSS */
static void
main_mode_sha1(struct state *st, u_char *hash_val, size_t *hash_len
, bool hashi, bool hashus)
{
    union hash_ctx ctx;

    SHA1Init(&ctx.ctx_sha1);
    SHA1Update(&ctx.ctx_sha1, st->st_skeyid.ptr, st->st_skeyid.len);
    *hash_len = SHA1_DIGEST_SIZE;
    main_mode_hash_body(st, hashi, hashus, &ctx
	, (void (*)(union hash_ctx *, const u_char *, unsigned int))&SHA1Update);
    SHA1Final(hash_val, &ctx.ctx_sha1);
}
#endif

/* Create an RSA signature of a hash.
 * Poorly specified in draft-ietf-ipsec-ike-01.txt 6.1.1.2.
 * Use PKCS#1 version 1.5 encryption of hash (called
 * RSAES-PKCS1-V1_5) in PKCS#2.
 */
static size_t
RSA_sign_hash(struct connection *c
, u_char sig_val[RSA_MAX_OCTETS]
, const u_char *hash_val, size_t hash_len)
{
    const struct RSA_private_key *k = get_RSA_private_key(c);
    size_t sz;
    u_char *p = sig_val;
    size_t padlen;
    mpz_t t1, t2;
    chunk_t ch;

    if (k == NULL)
	return 0;	/* failure: no key to use */
    sz = k->pub.k;
    passert(RSA_MIN_OCTETS <= sz && 4 + hash_len < sz && sz <= RSA_MAX_OCTETS);

    /* PKCS#1 v1.5 8.1 encryption-block formatting */
    *p++ = 0x00;
    *p++ = 0x01;	/* BT (block type) 01 */
    padlen = sz - 3 - hash_len;
    memset(p, 0xFF, padlen);
    p += padlen;
    *p++ = 0x00;
    memcpy(p, hash_val, hash_len);
    passert(p + hash_len - sig_val == (ptrdiff_t)sz);

    /* PKCS#1 v1.5 8.2 octet-string-to-integer conversion */
    n_to_mpz(t1, sig_val, sz);	/* (could skip leading 0x00) */

    /* PKCS#1 v1.5 8.3 RSA computation y = x^c mod n
     * Better described in PKCS#1 v2.0 5.1 RSADP.
     * There are two methods, depending on the form of the private key.
     * We use the one based on the Chinese Remainder Theorem.
     */
    mpz_init(t2);

    mpz_powm(t2, t1, &k->dP, &k->p);	/* m1 = c^dP mod p */

    mpz_powm(t1, t1, &k->dQ, &k->q);	/* m2 = c^dQ mod Q */

    mpz_sub(t2, t2, t1);	/* h = qInv (m1 - m2) mod p */
    mpz_mod(t2, t2, &k->p);
    mpz_mul(t2, t2, &k->qInv);
    mpz_mod(t2, t2, &k->p);

    mpz_mul(t2, t2, &k->q);	/* m = m2 + h q */
    mpz_add(t1, t1, t2);

    /* PKCS#1 v1.5 8.4 integer-to-octet-string conversion */
    ch = mpz_to_n(t1, sz);
    memcpy(sig_val, ch.ptr, sz);
    pfree(ch.ptr);

    mpz_clear(t1);
    mpz_clear(t2);
    return sz;
}

/* Check a Main Mode RSA Signature
 * Although the math should be the same for generating and checking signatures,
 * it is not: the knowledge of the private key allows more efficient (i.e.
 * different) computation for encryption.
 */
static notification_t
RSA_check_signature(struct state *st
, u_char hash_val[MAX_DIGEST_LEN], size_t hash_len
, const pb_stream *sig_pbs)
{
    const u_char *sig_val = sig_pbs->cur;
    size_t sig_len = pbs_left(sig_pbs);
    const struct RSA_public_key *k;
    u_char s[RSA_MAX_OCTETS];	/* for decrypted sig_val */
    u_char *hash_in_s = &s[sig_len - hash_len];

    /* find the public key for peer id */
    k = get_his_RSA_public_key(st->st_connection);
    if (k == NULL)
    {
	char buf[200];	/* arbitrary limit on length of ID reported */

	(void) idtoa(&st->st_connection->that.id, buf, sizeof(buf));
	loglog(RC_LOG_SERIOUS, "no RSA public key known for '%s'", buf);
	/* ??? is this the best code there is? */
	return INVALID_KEY_INFORMATION;
    }

    /* decrypt the signature -- reversing RSA_sign_hash */
    if (sig_len != k->k)
    {
	loglog(RC_LOG_SERIOUS, "SIG length does not match public key length");
	return INVALID_KEY_INFORMATION;
    }

    /* actual exponentiation; see PKCS#1 v2.0 5.1 */
    {
	chunk_t temp_s;
	mpz_t c;

	n_to_mpz(c, sig_val, sig_len);
	mpz_powm(c, c, &k->e, &k->n);

	temp_s = mpz_to_n(c, sig_len);	/* back to octets */
	memcpy(s, temp_s.ptr, sig_len);
	pfree(temp_s.ptr);
	mpz_clear(c);
    }

    /* sanity check on signature: see if it matches
     * PKCS#1 v1.5 8.1 encryption-block formatting
     */
    {
	err_t ugh = NULL;

	if (s[0] != 0x00)
	    ugh = "no leading 00";
	else if (hash_in_s[-1] != 0x00)
	    ugh = "00 separator not present";
	else if (s[1] == 0x01)
	{
	    const u_char *p;

	    for (p = &s[2]; p != hash_in_s - 1; p++)
	    {
		if (*p != 0xFF)
		{
		    ugh = "invalid Padding String";
		    break;
		}
	    }
	}
	else if (s[1] == 0x02)
	{
	    const u_char *p;

	    for (p = &s[2]; p != hash_in_s - 1; p++)
	    {
		if (*p == 0x00)
		{
		    ugh = "invalid Padding String";
		    break;
		}
	    }
	}
	else
	    ugh = "Block Type not 01 or 02";

	if (ugh != NULL)
	{
	    /* note: it might be a good idea to make sure that
	     * an observer cannot tell what kind of failure happened.
	     * I don't know what this means in practice.
	     */
	    loglog(RC_LOG_SERIOUS, "SIG did not decrypt into good ECB: %s. Bad key?", ugh);
	    return INVALID_KEY_INFORMATION;
	}
    }

    /* We have the decoded hash: see if it matches. */
    if (memcmp(hash_val, hash_in_s, hash_len))
    {
	/* good: header, hash, signature, and other payloads well-formed
	 * good: we could find an RSA Sig key for the peer.
	 * bad: hash doesn't match
	 * Guess: sides disagree about key to be used.
	 */
	DBG_cond_dump(DBG_CRYPT, "decrypted SIG", s, sig_len);
	DBG_cond_dump(DBG_CRYPT, "computed HASH", hash_val, hash_len);
	loglog(RC_LOG_SERIOUS, "authentication failure: received SIG does not match computed HASH, but message is well-formed; perhaps we disagree about which RSA Sig key applies");
	/* XXX Could send notification back */
	return INVALID_HASH_INFORMATION;
    }

    return NOTHING_WRONG;
}

/* check Main Mode authenticator (Hash or Signature Payload) */
static notification_t
check_main_authenticator(struct msg_digest *md, bool hashi)
{
    struct state *st = md->st;
    u_char hash_val[MAX_DIGEST_LEN];
    size_t hash_len = main_mode_hash(st, hash_val, hashi, FALSE);

    switch (st->st_oakley.auth)
    {
    case OAKLEY_PRESHARED_KEY:
	{
	    pb_stream *const hash_pbs = &md->chain[ISAKMP_NEXT_HASH]->pbs;

	    if (pbs_left(hash_pbs) != hash_len
	    || memcmp(hash_pbs->cur, hash_val, hash_len) != 0)
	    {
		DBG_cond_dump(DBG_CRYPT, "received HASH:"
		    , hash_pbs->cur, pbs_left(hash_pbs));
		loglog(RC_LOG_SERIOUS, "received Hash Payload does not match computed value");
		/* XXX Could send notification back */
		return INVALID_HASH_INFORMATION;
	    }
	    return NOTHING_WRONG;
	}
	break;
    case OAKLEY_RSA_SIG:
	return RSA_check_signature(st, hash_val, hash_len
	    , &md->chain[ISAKMP_NEXT_SIG]->pbs);
    default:
	passert(FALSE);
    }
}

/* CHECK_QUICK_HASH
 *
 * This macro is magic -- it cannot be expressed as a function.
 * - it causes the caller to return!
 * - it declares local variables and expects the "do_hash" argument
 *   expression to reference them (hash_val, hash_pbs)
 */
#define CHECK_QUICK_HASH(md, do_hash, hash_name, msg_name) { \
	pb_stream *const hash_pbs = &md->chain[ISAKMP_NEXT_HASH]->pbs; \
	u_char hash_val[MAX_DIGEST_LEN]; \
	size_t hash_len = do_hash; \
	if (pbs_left(hash_pbs) != hash_len \
	|| memcmp(hash_pbs->cur, hash_val, hash_len) != 0) \
	{ \
	    DBG_cond_dump(DBG_CRYPT, "received " hash_name ":", hash_pbs->cur, pbs_left(hash_pbs)); \
	    loglog(RC_LOG_SERIOUS, "received " hash_name " does not match computed value in " msg_name); \
	    /* XXX Could send notification back */ \
	    return STF_FAIL + INVALID_HASH_INFORMATION; \
	} \
    }

static notification_t
accept_nonce(struct msg_digest *md, chunk_t *dest, const char *name)
{
    pb_stream *nonce_pbs = &md->chain[ISAKMP_NEXT_NONCE]->pbs;
    size_t len = pbs_left(nonce_pbs);

    if (len < MINIMUM_NONCE_SIZE || MAXIMUM_NONCE_SIZE < len)
    {
	loglog(RC_LOG_SERIOUS, "%s length not between %d and %d"
	    , name , MINIMUM_NONCE_SIZE, MAXIMUM_NONCE_SIZE);
	return PAYLOAD_MALFORMED;	/* ??? */
    }
    clonereplacechunk(*dest, nonce_pbs->cur, len, "nonce");
    return NOTHING_WRONG;
}

/* START_HASH_PAYLOAD
 *
 * Emit a to-be-filled-in hash payload, noting the field start (r_hashval)
 * and the start of the part of the message to be hashed (r_hash_start).
 * This macro is magic.
 * - it can cause the caller to return
 * - it references variables local to the caller (r_hashval, r_hash_start, st)
 */
#define START_HASH_PAYLOAD(rbody, np) { \
    pb_stream hash_pbs; \
    if (!out_generic(np, &isakmp_hash_desc, &(rbody), &hash_pbs)) \
	return STF_INTERNAL_ERROR; \
    r_hashval = hash_pbs.cur;	/* remember where to plant value */ \
    if (!out_zero(st->st_oakley.hasher->hash_digest_len, &hash_pbs, "HASH")) \
	return STF_INTERNAL_ERROR; \
    close_output_pbs(&hash_pbs); \
    r_hash_start = (rbody).cur;	/* hash from after HASH payload */ \
}

/* encrypt message, sans fixed part of header
 * IV is fetched from st->st_new_iv and stored into st->st_iv.
 * The theory is that there will be no "backing out", so we commit to IV.
 * We also close the pbs.
 */
static bool
encrypt_message(pb_stream *pbs, struct state *st)
{
    const struct encrypt_desc *e = st->st_oakley.encrypter;
    u_int8_t *enc_start = pbs->start + sizeof(struct isakmp_hdr);
    size_t enc_len = pbs_offset(pbs) - sizeof(struct isakmp_hdr);

    DBG_cond_dump(DBG_CRYPT | DBG_RAW, "encrypting:\n", enc_start, enc_len);

    /* Pad up to multiple of encryption blocksize.
     * See the description associated with the definition of
     * struct isakmp_hdr in packet.h.
     */
    {
	size_t padding = pad_up(enc_len, e->blocksize);

	if (padding != 0)
	{
	    if (!out_zero(padding, pbs, "encryption padding"))
		return FALSE;
	    enc_len += padding;
	}
    }

    DBG(DBG_CRYPT, DBG_log("encrypting using %s", enum_show(&oakley_enc_names, st->st_oakley.encrypt)));

    e->crypt(TRUE, enc_start, enc_len, st);

    update_iv(st);
    DBG_cond_dump(DBG_CRYPT, "next IV:", st->st_iv, st->st_iv_len);
    close_message(pbs);
    return TRUE;
}

/* Compute HASH(1), HASH(2) of Quick Mode.
 * HASH(1) is part of Quick I1 message.
 * HASH(2) is part of Quick R1 message.
 * Used by: quick_outI1, quick_inI1_outR1 (twice), quick_inR1_outI2
 * (see draft-ietf-ipsec-isakmp-oakley-07.txt 5.5)
 */
static size_t
quick_mode_hash12(u_char *dest, const u_char *start, const u_char *roof
, const struct state *st, bool hash2)
{
    struct hmac_ctx ctx;

    hmac_init_chunk(&ctx, st->st_oakley.hasher, st->st_skeyid_a);
    hmac_update(&ctx, (const u_char *) &st->st_msgid, sizeof(st->st_msgid));
    if (hash2)
	hmac_update_chunk(&ctx, st->st_ni);	/* include Ni_b in the hash */
    hmac_update(&ctx, start, roof-start);
    hmac_final(dest, &ctx);

    DBG(DBG_CRYPT,
	DBG_log("HASH(%d) computed:", hash2 + 1);
	DBG_dump("", dest, ctx.hmac_digest_len));
    return ctx.hmac_digest_len;
}

/* Compute HASH(3) in Quick Mode (part of Quick I2 message).
 * Used by: quick_inR1_outI2, quick_inI2
 * See RFC2409 "The Internet Key Exchange (IKE)" 5.5.
 * NOTE: this hash (unlike HASH(1) and HASH(2)) ONLY covers the
 * Message ID and Nonces.  This is a mistake.
 */
static size_t
quick_mode_hash3(u_char *dest, struct state *st)
{
    struct hmac_ctx ctx;

    hmac_init_chunk(&ctx, st->st_oakley.hasher, st->st_skeyid_a);
    hmac_update(&ctx, "\0", 1);
    hmac_update(&ctx, (u_char *) &st->st_msgid, sizeof(st->st_msgid));
    hmac_update_chunk(&ctx, st->st_ni);
    hmac_update_chunk(&ctx, st->st_nr);
    hmac_final(dest, &ctx);
    DBG_cond_dump(DBG_CRYPT, "HASH(3) computed:", dest, ctx.hmac_digest_len);
    return ctx.hmac_digest_len;
}

/* Compute Phase 2 IV.
 * Uses Phase 1 IV from st_iv; puts result in st_new_iv.
 */
void
init_phase2_iv(struct state *st, const msgid_t *msgid)
{
    const struct hash_desc *h = st->st_oakley.hasher;
    union hash_ctx ctx;

    st->st_new_iv_len = h->hash_digest_len;
    passert(st->st_new_iv_len <= sizeof(st->st_new_iv));

    h->hash_init(&ctx);
    h->hash_update(&ctx, st->st_iv, st->st_iv_len);
    passert(*msgid != 0);
    h->hash_update(&ctx, (const u_char *)msgid, sizeof(*msgid));
    h->hash_final(st->st_new_iv, &ctx);

    DBG_cond_dump(DBG_CRYPT, "computed Phase 2 IV:"
	, st->st_new_iv, st->st_new_iv_len);
}

/* Initiate quick mode.
 * --> HDR*, HASH(1), SA, Nr [, KE ] [, IDci, IDcr ]
 * (see draft-ietf-ipsec-isakmp-oakley-07.txt 5.5)
 */

static bool
emit_subnet_id(ip_subnet *net
, u_int8_t np, u_int8_t protoid, u_int16_t port, pb_stream *outs)
{
    struct isakmp_ipsec_id id;
    pb_stream id_pbs;
    ip_address ta;
    const unsigned char *tbp;
    size_t tal;

    id.isaiid_np = np;
    id.isaiid_idtype = aftoinfo(subnettypeof(net))->id_subnet;
    id.isaiid_protoid = protoid;
    id.isaiid_port = port;

    if (!out_struct(&id, &isakmp_ipsec_identification_desc, outs, &id_pbs))
	return FALSE;

    networkof(net, &ta);
    tal = addrbytesptr(&ta, &tbp);
    if (!out_raw(tbp, tal, &id_pbs, "client network"))
	return FALSE;

    maskof(net, &ta);
    tal = addrbytesptr(&ta, &tbp);
    if (!out_raw(tbp, tal, &id_pbs, "client mask"))
	return FALSE;

    close_output_pbs(&id_pbs);
    return TRUE;
}

stf_status
quick_outI1(int whack_sock
, struct state *isakmp_sa
, struct connection *c
, lset_t policy
, unsigned long try)
{
    struct state *st = duplicate_state(isakmp_sa);
    u_char space[8192];	/* NOTE: we assume 8192 is big enough to build the packet */
    pb_stream reply;	/* not really a reply */
    pb_stream rbody;
    u_char
	*r_hashval,	/* where in reply to jam hash value */
	*r_hash_start;	/* start of what is to be hashed */
    bool has_client = c->this.has_client ||  c->that.has_client;

    cur_state = st;
    st->st_whack_sock = whack_sock;
    st->st_connection = c;
#ifdef DEBUG
    extra_debugging(c);
#endif
    st->st_policy = policy;
    st->st_try = try;

    st->st_myuserprotoid = st->st_peeruserprotoid = 0;
    st->st_myuserport = st->st_peeruserport = 0;

    st->st_msgid = generate_msgid(isakmp_sa);
    st->st_state = STATE_QUICK_I1;

    insert_state(st);	/* needs cookies, connection, and msgid */

    log("initiating Quick Mode %s", bitnamesof(sa_policy_bit_names, policy));

    /* set up reply */
    init_pbs(&reply, space, sizeof(space), "reply packet");

    /* HDR* out */
    {
	struct isakmp_hdr hdr;

	hdr.isa_version = ISAKMP_MAJOR_VERSION << ISA_MAJ_SHIFT | ISAKMP_MINOR_VERSION;
	hdr.isa_np = ISAKMP_NEXT_HASH;
	hdr.isa_xchg = ISAKMP_XCHG_QUICK;
	hdr.isa_msgid = st->st_msgid;
	hdr.isa_flags = ISAKMP_FLAG_ENCRYPTION;
	memcpy(hdr.isa_icookie, st->st_icookie, COOKIE_SIZE);
	memcpy(hdr.isa_rcookie, st->st_rcookie, COOKIE_SIZE);
	if (!out_struct(&hdr, &isakmp_hdr_desc, &reply, &rbody))
	    return STF_INTERNAL_ERROR;
    }

    /* HASH(1) -- create and note space to be filled later */
    START_HASH_PAYLOAD(rbody, ISAKMP_NEXT_SA);

    /* SA out */

    /* If PFS specified, use the same group as during Phase 1:
     * since no negotiation is possible, we pick one that is
     * very likely supported.
     */
    st->st_pfs_group = policy & POLICY_PFS? isakmp_sa->st_oakley.group : NULL;

    /* Emit SA payload based on a subset of the policy bits.
     * POLICY_COMPRESS is considered iff we can do IPcomp.
     */
    {
	lset_t pm = POLICY_ENCRYPT | POLICY_AUTHENTICATE;

	if (can_do_IPcomp)
	    pm |= POLICY_COMPRESS;

	if (!out_sa(&rbody
	, &ipsec_sadb[(st->st_policy & pm) >> POLICY_IPSEC_SHIFT]
	, st, FALSE, ISAKMP_NEXT_NONCE))
	    return STF_INTERNAL_ERROR;
    }

    /* Ni out */
    if (!build_and_ship_nonce(&st->st_ni, &rbody
    , policy & POLICY_PFS? ISAKMP_NEXT_KE : has_client? ISAKMP_NEXT_ID : ISAKMP_NEXT_NONE
    , "Ni"))
	return STF_INTERNAL_ERROR;

    /* [ KE ] out (for PFS) */

    if (st->st_pfs_group != NULL)
    {
	if (!build_and_ship_KE(st, &st->st_gi, st->st_pfs_group
	, &rbody, has_client? ISAKMP_NEXT_ID : ISAKMP_NEXT_NONE))
	    return STF_INTERNAL_ERROR;
    }

    /* [ IDci, IDcr ] out */
    if (has_client)
    {
	/* IDci (we are initiator), then IDcr (peer is responder) */
	if (!emit_subnet_id(&c->this.client
	  , ISAKMP_NEXT_ID, st->st_myuserprotoid, st->st_myuserport, &rbody)
	|| !emit_subnet_id(&c->that.client
	  , ISAKMP_NEXT_NONE, st->st_peeruserprotoid, st->st_peeruserport, &rbody))
	    return STF_INTERNAL_ERROR;
    }

    /* finish computing  HASH(1), inserting it in output */
    (void) quick_mode_hash12(r_hashval, r_hash_start, rbody.cur, st, FALSE);

    /* encrypt message, except for fixed part of header */

    init_phase2_iv(isakmp_sa, &st->st_msgid);
    st->st_new_iv_len = isakmp_sa->st_new_iv_len;
    memcpy(st->st_new_iv, isakmp_sa->st_new_iv, st->st_new_iv_len);

    if (!encrypt_message(&rbody, st))
	return STF_INTERNAL_ERROR;

    /* save packet, now that we know its size */
    clonetochunk(st->st_tpacket, reply.start, pbs_offset(&reply)
	, "reply packet from quick_outI1");

    /* send the packet */

    send_packet(st, "quick_outI1");

    delete_event(st);
    event_schedule(EVENT_RETRANSMIT, EVENT_RETRANSMIT_DELAY_0, st);

    whack_log(RC_NEW_STATE + STATE_QUICK_I1
	, "%s: initiate", enum_name(&state_names, st->st_state));
    cur_state = NULL;
    return STF_NO_REPLY;
}

/* Decode the ID payload of Phase 1 (main_inI3_outR3 and main_inR3)
 * Note: we may change connections as a result.
 * We must be called before SIG or HASH are decoded since we
 * may change the peer's RSA key or ID.
 */
static bool
decode_peer_id(struct msg_digest *md, bool initiator, bool aggrmode)
{
    struct state *const st = md->st;
    struct payload_digest *const id_pld = md->chain[ISAKMP_NEXT_ID];
    pb_stream *const id_pbs = &id_pld->pbs;
    struct isakmp_id *const id = &id_pld->payload.id;
    struct id peer;

    /* I think that RFC2407 (IPSEC DOI) 4.6.2 is confused.
     * It talks about the protocol ID and Port fields of the ID
     * Payload, but they don't exist as such in Phase 1.
     * We use more appropriate names.
     * isaid_doi_specific_a is in place of Protocol ID.
     * isaid_doi_specific_b is in place of Port.
     * Besides, there is no good reason for allowing these to be
     * other than 0 in Phase 1.
     */
    if (!(id->isaid_doi_specific_a == 0 && id->isaid_doi_specific_b == 0)
    && !(id->isaid_doi_specific_a == IPPROTO_UDP && id->isaid_doi_specific_b == IKE_UDP_PORT))
    {
	loglog(RC_LOG_SERIOUS, "protocol/port in Phase 1 ID Payload must be 0/0 or %d/%d"
	    " but are %d/%d"
	    , IPPROTO_UDP, IKE_UDP_PORT
	    , id->isaid_doi_specific_a, id->isaid_doi_specific_b);
	return FALSE;
    }

    /* XXX Check for valid ID types? */
    peer.kind = id->isaid_idtype;

    switch (peer.kind)
    {
    case ID_IPV4_ADDR:
    case ID_IPV6_ADDR:
	/* failure mode for initaddr is probably inappropriate address length */
	{
	    err_t ugh = initaddr(id_pbs->cur, pbs_left(id_pbs)
		, peer.kind == ID_IPV4_ADDR? AF_INET : AF_INET6
		, &peer.ip_addr);

	    if (ugh != NULL)
	    {
		loglog(RC_LOG_SERIOUS, "improper %s identification payload: %s"
		    , enum_show(&ident_names, peer.kind), ugh);
		/* XXX Could send notification back */
		return FALSE;
	    }
	}
	break;

    case ID_USER_FQDN:
#ifndef INTEROP_CHECKPOINT_FW_4_1
	if (memchr(id_pbs->cur, '@', pbs_left(id_pbs)) == NULL)
	{
	    loglog(RC_LOG_SERIOUS, "peer's ID_USER_FQDN contains no @");
	    return FALSE;
	}
#endif
	/* FALLTHROUGH */
    case ID_FQDN:
	if (memchr(id_pbs->cur, '\0', pbs_left(id_pbs)) != NULL)
	{
	    loglog(RC_LOG_SERIOUS, "Phase 1 ID Payload of type %s contains a NUL"
		, enum_show(&ident_names, peer.kind));
	    return FALSE;
	}
     /* FALLTHROUGH */
    case ID_KEY_ID:	/* can be anything */
	/* ??? ought to do some more sanity check, but what? */

	setchunk(peer.name, id_pbs->cur, pbs_left(id_pbs));
	break;

    default:
	/* XXX Could send notification back */
	loglog(RC_LOG_SERIOUS, "Unacceptable identity type (%s) in Phase 1 ID Payload"
	    " from %s"
	    , enum_show(&ident_names, peer.kind)
	    , inet_ntoa(md->sin.sin_addr));
	return FALSE;
    }

    /* crazy stuff, must be kept for hash */
    st->st_peeridentity_protocol = id->isaid_doi_specific_a;
    st->st_peeridentity_port = id->isaid_doi_specific_b;

    DBG(DBG_PARSING,
	{
	    char buf[IDTOA_BUF];

	    idtoa(&peer, buf, sizeof(buf));
	    DBG_log("%s Mode peer's ID is %s: '%s'",
		aggrmode ? "Aggressive" : "Main",
		enum_show(&ident_names, id->isaid_idtype),
		buf);
	});

    /* Now that we've decoded the ID payload, let's see if we
     * need to switch connections.
     * We must not switch horses if we initiated:
     * - if the initiation was explicit, we'd be ignoring user's intent
     * - if opportunistic, we'll lose our HOLD info
     */
    if (initiator)
    {
	if (!same_id(&st->st_connection->that.id, &peer))
	{
	    char expect[IDTOA_BUF]
		, found[IDTOA_BUF];

	    idtoa(&st->st_connection->that.id, expect, sizeof(expect));
	    idtoa(&peer, found, sizeof(found));
	    loglog(RC_LOG_SERIOUS
		, "we require peer to have ID '%s', but peer declares '%s'"
		, expect, found);
	    return FALSE;
	}
    }
    else
    {
	struct connection *c = st->st_connection;
	struct connection *r = refine_host_connection(st, &peer, initiator, aggrmode);

	if (r == NULL)
	{
	    char buf[IDTOA_BUF];

	    idtoa(&peer, buf, sizeof(buf));
	    loglog(RC_LOG_SERIOUS, "no suitable connection for peer '%s'", buf);
	    return FALSE;
	}
	else if (r != c)
	{
	    /* apparently, r is an improvement on c -- replace */

	    DBG(DBG_CONTROL
		, DBG_log("switched from \"%s\" to \"%s\"", c->name, r->name));
	    if (r->kind == CK_TEMPLATE)
	    {
		/* instantiate it, filling in peer's ID */
		r = rw_instantiate(r, &c->that.host_addr, &peer);
	    }

	    st->st_connection = r;	/* kill reference to c */
	    SET_CUR_CONNECTION(r);
	    connection_discard(c);
	}
    }

    return TRUE;
}

/* Decode the variable part of an ID packet (during Quick Mode).
 * This is designed for packets that identify clients, not peers.
 */
static bool
decode_net_id(struct isakmp_ipsec_id *id
, pb_stream *id_pbs
, ip_subnet *net
, const char *which)
{
    const struct af_info *afi = NULL;

    /* Note: the following may be a pointer into static memory
     * that may be recycled, but only if the type is not known.
     * That case is disposed of very early -- in the first switch.
     */
    const char *idtypename = enum_show(&ident_names, id->isaiid_idtype);

    switch (id->isaiid_idtype)
    {
	case ID_IPV4_ADDR:
	case ID_IPV4_ADDR_SUBNET:
	case ID_IPV4_ADDR_RANGE:
	    afi = &af_inet4_info;
	    break;
	case ID_IPV6_ADDR:
	case ID_IPV6_ADDR_SUBNET:
	case ID_IPV6_ADDR_RANGE:
	    afi = &af_inet6_info;
	    break;

	default:
	    /* XXX support more */
	    loglog(RC_LOG_SERIOUS, "unsupported ID type %s"
		, idtypename);
	    /* XXX Could send notification back */
	    return FALSE;
    }

    if (id->isaiid_protoid != 0)
    {
	loglog(RC_LOG_SERIOUS
	    , "%s ID payload %s specifies protocol %u; we only support 0"
	    , which, idtypename, id->isaiid_protoid);
	/* XXX Could send notification back */
	return FALSE;
    }

    if (id->isaiid_port != htons(0))
    {
	loglog(RC_LOG_SERIOUS
	    , "%s ID payload %s specifies port %u; we only support 0"
	    , which, idtypename, ntohs(id->isaiid_port));
	/* XXX Could send notification back */
	return FALSE;
    }

    switch (id->isaiid_idtype)
    {
	case ID_IPV4_ADDR:
	case ID_IPV6_ADDR:
	{
	    ip_address temp_address;
	    err_t ugh;

	    ugh = initaddr(id_pbs->cur, pbs_left(id_pbs), afi->af, &temp_address);

	    if (ugh != NULL)
	    {
		loglog(RC_LOG_SERIOUS, "%s ID payload %s has wrong length in Quick I1 (%s)"
		    , which, idtypename, ugh);
		/* XXX Could send notification back */
		return FALSE;
	    }
	    ugh = initsubnet(&temp_address, afi->mask_cnt, '0', net);
	    passert(ugh == NULL);
	    DBG(DBG_PARSING | DBG_CONTROL,
		{
		    char temp_buff[SUBNETTOT_BUF];

		    subnettot(net, 0, temp_buff, sizeof(temp_buff));
		    DBG_log("%s is %s", which, temp_buff);
		});
	    break;
	}

	case ID_IPV4_ADDR_SUBNET:
	case ID_IPV6_ADDR_SUBNET:
	{
	    ip_address temp_address, temp_mask;
	    err_t ugh;

	    if (pbs_left(id_pbs) != 2 * afi->ia_sz)
	    {
		loglog(RC_LOG_SERIOUS, "%s ID payload %s wrong length in Quick I1"
		    , which, idtypename);
		/* XXX Could send notification back */
		return FALSE;
	    }
	    ugh = initaddr(id_pbs->cur
		, afi->ia_sz, afi->af, &temp_address);
	    if (ugh == NULL)
		ugh = initaddr(id_pbs->cur + afi->ia_sz
		    , afi->ia_sz, afi->af, &temp_mask);
	    if (ugh == NULL)
		ugh = initsubnet(&temp_address, masktocount(&temp_mask)
		    , '0', net);
	    if (ugh != NULL)
	    {
		loglog(RC_LOG_SERIOUS, "%s ID payload %s bad subnet in Quick I1 (%s)"
		    , which, idtypename, ugh);
		/* XXX Could send notification back */
		return FALSE;
	    }
	    DBG(DBG_PARSING | DBG_CONTROL,
		{
		    char temp_buff[SUBNETTOT_BUF];

		    subnettot(net, 0, temp_buff, sizeof(temp_buff));
		    DBG_log("%s is subnet %s", which, temp_buff);
		});
	    break;
	}

	case ID_IPV4_ADDR_RANGE:
	case ID_IPV6_ADDR_RANGE:
	{
	    ip_address temp_address_from, temp_address_to;
	    err_t ugh;

	    if (pbs_left(id_pbs) != 2 * afi->ia_sz)
	    {
		loglog(RC_LOG_SERIOUS, "%s ID payload %s wrong length in Quick I1"
		    , which, idtypename);
		/* XXX Could send notification back */
		return FALSE;
	    }
	    ugh = initaddr(id_pbs->cur, afi->ia_sz, afi->af, &temp_address_from);
	    if (ugh == NULL)
		ugh = initaddr(id_pbs->cur + afi->ia_sz
		    , afi->ia_sz, afi->af, &temp_address_to);
	    if (ugh != NULL)
	    {
		loglog(RC_LOG_SERIOUS, "%s ID payload %s malformed (%s) in Quick I1"
		    , which, idtypename, ugh);
		/* XXX Could send notification back */
		return FALSE;
	    }

	    ugh = rangetosubnet(&temp_address_from, &temp_address_to, net);
	    if (ugh != NULL)
	    {
		char temp_buff1[ADDRTOT_BUF], temp_buff2[ADDRTOT_BUF];

		addrtot(&temp_address_from, 0, temp_buff1, sizeof(temp_buff1));
		addrtot(&temp_address_to, 0, temp_buff2, sizeof(temp_buff2));
		loglog(RC_LOG_SERIOUS, "%s ID payload in Quick I1, %s"
		    " %s - %s unacceptable: %s"
		    , which, idtypename, temp_buff1, temp_buff2, ugh);
		return FALSE;
	    }
	    DBG(DBG_PARSING | DBG_CONTROL,
		{
		    char temp_buff[SUBNETTOT_BUF];

		    subnettot(net, 0, temp_buff, sizeof(temp_buff));
		    DBG_log("%s is subnet %s (received as range)"
			, which, temp_buff);
		});
	    break;
	}
    }

    return TRUE;
}

/* like decode, but checks that what is received matches what was sent */
static bool

check_net_id(struct isakmp_ipsec_id *id
, pb_stream *id_pbs
, u_int8_t *protoid
, u_int16_t *port
, ip_subnet *net
, const char *which)
{
    ip_subnet net_temp;

    if (!decode_net_id(id, id_pbs, &net_temp, which))
	return FALSE;

    if (!samesubnet(net, &net_temp)
    || *protoid != id->isaiid_protoid || *port != id->isaiid_port)
    {
	loglog(RC_LOG_SERIOUS, "%s ID returned doesn't match my proposal", which);
	return FALSE;
    }
    return TRUE;
}

/*
 * Produce the new key material of Quick Mode.
 * draft-ietf-ipsec-isakmp-oakley-06.txt section 5.5
 * specifies how this is to be done.
 */
static void
compute_proto_keymat(struct state *st
, u_int8_t protoid
, struct ipsec_proto_info *pi)
{
    size_t needed_len; /* bytes of keying material needed */

    /* Add up the requirements for keying material
     * (It probably doesn't matter if we produce too much!)
     */
    switch (protoid)
    {
    case PROTO_IPSEC_ESP:
	    switch (pi->attrs.transid)
	    {
	    case ESP_NULL:
		needed_len = 0;
		break;
	    case ESP_DES:
		needed_len = DES_CBC_BLOCK_SIZE;
		break;
	    case ESP_3DES:
		needed_len = DES_CBC_BLOCK_SIZE * 3;
		break;
	    default:
		exit_log("transform %s not implemented yet",
		    enum_show(&esp_transformid_names, pi->attrs.transid));
	    }

	    switch (pi->attrs.auth)
	    {
	    case AUTH_ALGORITHM_NONE:
		break;
	    case AUTH_ALGORITHM_HMAC_MD5:
		needed_len += HMAC_MD5_KEY_LEN;
		break;
	    case AUTH_ALGORITHM_HMAC_SHA1:
		needed_len += HMAC_SHA1_KEY_LEN;
		break;
	    case AUTH_ALGORITHM_DES_MAC:
	    default:
		exit_log("AUTH algorithm %s not implemented yet",
		    enum_show(&auth_alg_names, pi->attrs.auth));
	    }
	    break;

    case PROTO_IPSEC_AH:
	    switch (pi->attrs.transid)
	    {
	    case AH_MD5:
		needed_len = HMAC_MD5_KEY_LEN;
		break;
	    case AH_SHA:
		needed_len = HMAC_SHA1_KEY_LEN;
		break;
	    default:
		exit_log("transform %s not implemented yet",
		    enum_show(&ah_transformid_names, pi->attrs.transid));
	    }
	    break;

    default:
	exit_log("protocol %s not implemented yet",
	    enum_show(&protocol_names, protoid));
	break;
    }

    pi->keymat_len = needed_len;

    /* Allocate space for the keying material.
     * Although only needed_len bytes are desired, we
     * must round up to a multiple of ctx.hmac_digest_len
     * so that our buffer isn't overrun.
     */
    {
	struct hmac_ctx ctx_me, ctx_peer;
	size_t needed_space;	/* space needed for keying material (rounded up) */
	size_t i;

	hmac_init_chunk(&ctx_me, st->st_oakley.hasher, st->st_skeyid_d);
	ctx_peer = ctx_me;	/* duplicate initial conditions */

	needed_space = needed_len + pad_up(needed_len, ctx_me.hmac_digest_len);
	replace(pi->our_keymat, alloc_bytes(needed_space, "keymat in compute_keymat()"));
	replace(pi->peer_keymat, alloc_bytes(needed_space, "peer_keymat in quick_inI1_outR1()"));

	for (i = 0;; )
	{
	    if (st->st_shared.ptr != NULL)
	    {
		/* PFS: include the g^xy */
		hmac_update_chunk(&ctx_me, st->st_shared);
		hmac_update_chunk(&ctx_peer, st->st_shared);
	    }
	    hmac_update(&ctx_me, &protoid, sizeof(protoid));
	    hmac_update(&ctx_peer, &protoid, sizeof(protoid));

	    hmac_update(&ctx_me, (u_char *)&pi->our_spi, sizeof(pi->our_spi));
	    hmac_update(&ctx_peer, (u_char *)&pi->attrs.spi, sizeof(pi->attrs.spi));

	    hmac_update_chunk(&ctx_me, st->st_ni);
	    hmac_update_chunk(&ctx_peer, st->st_ni);

	    hmac_update_chunk(&ctx_me, st->st_nr);
	    hmac_update_chunk(&ctx_peer, st->st_nr);

	    hmac_final(pi->our_keymat + i, &ctx_me);
	    hmac_final(pi->peer_keymat + i, &ctx_peer);

	    i += ctx_me.hmac_digest_len;
	    if (i >= needed_space)
		break;

	    /* more keying material needed: prepare to go around again */

	    hmac_reinit(&ctx_me);
	    hmac_reinit(&ctx_peer);

	    hmac_update(&ctx_me, pi->our_keymat + i - ctx_me.hmac_digest_len,
		ctx_me.hmac_digest_len);
	    hmac_update(&ctx_peer, pi->peer_keymat + i - ctx_peer.hmac_digest_len,
		ctx_peer.hmac_digest_len);
	}
    }

    DBG(DBG_CRYPT,
	DBG_dump("KEYMAT computed:\n", pi->our_keymat, pi->keymat_len);
	DBG_dump("Peer KEYMAT computed:\n", pi->peer_keymat, pi->keymat_len));
}

static void
compute_keymats(struct state *st)
{
    if (st->st_ah.present)
	compute_proto_keymat(st, PROTO_IPSEC_AH, &st->st_ah);
    if (st->st_esp.present)
	compute_proto_keymat(st, PROTO_IPSEC_ESP, &st->st_esp);
}

/* State Transition Functions.
 * - Called from comm_handle;
 * - state_check[state].processor points to these
 * - these routines are in state-order
 * - these routines must be restartable from any point of error return.
 * - output HDR is handled by comm_handle().
 * Hint: the definition of state_check in demux.c is a good
 * overview of these routines.
 */

/* Handle a Main Mode Oakley first packet (responder side).
 * HDR;SA --> HDR;SA
 */
stf_status
main_inI1_outR1(struct msg_digest *md)
{
    struct payload_digest *const sa_pd = md->chain[ISAKMP_NEXT_SA];
    struct state *st;
    struct connection *c = find_host_connection(&md->iface->addr, pluto_port
	, &md->sender, md->sender_port);

    pb_stream r_sa_pbs;

    if (c == NULL)
    {
	/* see if a wildcarded connection can be found */
	c = find_host_connection(&md->iface->addr, pluto_port
	    , (ip_address*)NULL, md->sender_port);
	if (c != NULL)
	{
	    /* Create a temporary connection that is a copy of this one.
	     * His ID isn't declared yet.
	     */
	    c = rw_instantiate(c, &md->sender, NULL);
	}
	else
	{
	    loglog(RC_LOG_SERIOUS, "initial Main Mode message received on %s:%u"
		" but no connection has been authorized"
		, ip_str(&md->iface->addr), pluto_port);
	    /* XXX notification is in order! */
	    return STF_IGNORE;
	}
    }

    /* Set up state */
    cur_state = md->st = st = new_state();	/* (caller will reset cur_state) */
    st->st_connection = c;
#ifdef DEBUG
    extra_debugging(c);
#endif
    st->st_try = 0;	/* not our job to try again from start */
    st->st_policy = c->policy & ~POLICY_IPSEC_MASK;	/* only as accurate as connection */

    memcpy(st->st_icookie, md->hdr.isa_icookie, COOKIE_SIZE);
    get_cookie(ISAKMP_RESPONDER, st->st_rcookie, COOKIE_SIZE, &md->sender);

    insert_state(st);	/* needs cookies, connection, and msgid (0) */

    st->st_doi = ISAKMP_DOI_IPSEC;
    st->st_situation = SIT_IDENTITY_ONLY; /* We only support this */
    st->st_state = STATE_MAIN_R1;

    if (c->kind == CK_INSTANCE)
    {
	log("responding to Main Mode from unknown peer %s"
	    , ip_str(&c->that.host_addr));
    }
    else
    {
	log("responding to Main Mode");
    }

    /* parse_isakmp_sa also spits out a winning SA into our reply,
     * so we have to build our md->reply and emit HDR before calling it.
     */

    /* HDR out.
     * We can't leave this to comm_handle() because we must
     * fill in the cookie.
     */
    {
	struct isakmp_hdr r_hdr = md->hdr;

	memcpy(r_hdr.isa_rcookie, st->st_rcookie, COOKIE_SIZE);
	r_hdr.isa_np = ISAKMP_NEXT_SA;
	if (!out_struct(&r_hdr, &isakmp_hdr_desc, &md->reply, &md->rbody))
	    return STF_INTERNAL_ERROR;
    }

    /* start of SA out */
    {
	struct isakmp_sa r_sa = sa_pd->payload.sa;

	r_sa.isasa_np = ISAKMP_NEXT_NONE;
	if (!out_struct(&r_sa, &isakmp_sa_desc, &md->rbody, &r_sa_pbs))
	    return STF_INTERNAL_ERROR;
    }

    /* SA body in and out */
    RETURN_STF_FAILURE(parse_isakmp_sa_body(&sa_pd->pbs, &sa_pd->payload.sa, &r_sa_pbs
	    , FALSE, st));
    close_message(&md->rbody);

    /* save initiator SA for HASH */
    clonereplacechunk(st->st_p1isa, sa_pd->pbs.start, pbs_room(&sa_pd->pbs), "sa in main_inI1_outR1()");

    return STF_REPLY;
}

/* STATE_MAIN_I1: HDR, SA --> auth dependent
 * PSK_AUTH, DS_AUTH: --> HDR, KE, Ni
 *
 * The following are not yet implemented:
 * PKE_AUTH: --> HDR, KE, [ HASH(1), ] <IDi1_b>PubKey_r, <Ni_b>PubKey_r
 * RPKE_AUTH: --> HDR, [ HASH(1), ] <Ni_b>Pubkey_r, <KE_b>Ke_i,
 *                <IDi1_b>Ke_i [,<<Cert-I_b>Ke_i]
 *
 * We must verify that the proposal received matches one we sent.
 */
stf_status
main_inR1_outI2(struct msg_digest *md)
{
    struct state *const st = md->st;

    /* verify echoed SA */
    {
	struct payload_digest *const sapd = md->chain[ISAKMP_NEXT_SA];

	RETURN_STF_FAILURE(parse_isakmp_sa_body(&sapd->pbs
	    , &sapd->payload.sa, NULL, TRUE, st));
    }

    /**************** build output packet HDR;KE;Ni ****************/

    /* HDR out.
     * We can't leave this to comm_handle() because the isa_np
     * depends on the type of Auth (eventually).
     */
    {
	struct isakmp_hdr r_hdr = md->hdr;

	r_hdr.isa_np = ISAKMP_NEXT_KE;
	if (!out_struct(&r_hdr, &isakmp_hdr_desc, &md->reply, &md->rbody))
	    return STF_INTERNAL_ERROR;
    }

    /* KE out */
    if (!build_and_ship_KE(st, &st->st_gi, st->st_oakley.group
    , &md->rbody, ISAKMP_NEXT_NONCE))
	return STF_INTERNAL_ERROR;

    /* Ni out */
    if (!build_and_ship_nonce(&st->st_ni, &md->rbody, ISAKMP_NEXT_NONE, "Ni"))
	return STF_INTERNAL_ERROR;

    /* finish message */
    close_message(&md->rbody);

    /* Reinsert the state, using the responder cookie we just received */
    unhash_state(st);
    memcpy(st->st_rcookie, md->hdr.isa_rcookie, COOKIE_SIZE);
    insert_state(st);	/* needs cookies, connection, and msgid (0) */

    st->st_state = STATE_MAIN_I2;

    return STF_REPLY;
}

/* STATE_MAIN_R1:
 * PSK_AUTH, DS_AUTH: HDR, KE, Ni --> HDR, KE, Nr
 *
 * The following are not yet implemented:
 * PKE_AUTH: HDR, KE, [ HASH(1), ] <IDi1_b>PubKey_r, <Ni_b>PubKey_r
 *	    --> HDR, KE, <IDr1_b>PubKey_i, <Nr_b>PubKey_i
 * RPKE_AUTH:
 *	    HDR, [ HASH(1), ] <Ni_b>Pubkey_r, <KE_b>Ke_i, <IDi1_b>Ke_i [,<<Cert-I_b>Ke_i]
 *	    --> HDR, <Nr_b>PubKey_i, <KE_b>Ke_r, <IDr1_b>Ke_r
 */
stf_status
main_inI2_outR2(struct msg_digest *md)
{
    struct state *const st = md->st;
    pb_stream *keyex_pbs = &md->chain[ISAKMP_NEXT_KE]->pbs;

    /* KE in */
    RETURN_STF_FAILURE(accept_KE(&st->st_gi, "Gi", st->st_oakley.group, keyex_pbs));

    /* Ni in */
    RETURN_STF_FAILURE(accept_nonce(md, &st->st_ni, "Ni"));


    /**************** build output packet HDR;KE;Nr ****************/

    /* HDR out done */

    /* KE out */
    if (!build_and_ship_KE(st, &st->st_gr, st->st_oakley.group
    , &md->rbody, ISAKMP_NEXT_NONCE))
	return STF_INTERNAL_ERROR;

    /* Nr out */
    if (!build_and_ship_nonce(&st->st_nr, &md->rbody, ISAKMP_NEXT_NONE, "Nr"))
	return STF_INTERNAL_ERROR;

    /* finish message */
    close_message(&md->rbody);

    /* next message will be encrypted, but not this one.
     * We could defer this calculation.
     */
#ifndef DODGE_DH_MISSING_ZERO_BUG
    compute_dh_shared(st, st->st_gi, st->st_oakley.group);
#endif
    if (!generate_skeyids_iv(st))
	return STF_FAIL + AUTHENTICATION_FAILED;
    update_iv(st);

    /* Advance state */
    st->st_state = STATE_MAIN_R2;

    return STF_REPLY;
}

/* STATE_MAIN_I2:
 * SMF_PSK_AUTH: HDR, KE, Nr --> HDR*, IDi1, HASH_I
 * SMF_DS_AUTH: HDR, KE, Nr --> HDR*, IDi1, [ CERT, ] SIG_I
 *
 * The following are not yet implemented.
 * SMF_PKE_AUTH: HDR, KE, <IDr1_b>PubKey_i, <Nr_b>PubKey_i
 *	    --> HDR*, HASH_I
 * SMF_RPKE_AUTH: HDR, <Nr_b>PubKey_i, <KE_b>Ke_r, <IDr1_b>Ke_r
 *	    --> HDR*, HASH_I
 */
stf_status
main_inR2_outI3(struct msg_digest *md)
{
    struct state *const st = md->st;
    pb_stream *const keyex_pbs = &md->chain[ISAKMP_NEXT_KE]->pbs;
    int auth_payload = st->st_oakley.auth == OAKLEY_PRESHARED_KEY
	? ISAKMP_NEXT_HASH : ISAKMP_NEXT_SIG;

    /* KE in */
    RETURN_STF_FAILURE(accept_KE(&st->st_gr, "Gr", st->st_oakley.group, keyex_pbs));

    /* Nr in */
    RETURN_STF_FAILURE(accept_nonce(md, &st->st_nr, "Nr"));

    /* done parsing; initialize crypto  */

    compute_dh_shared(st, st->st_gr, st->st_oakley.group);
#ifdef DODGE_DH_MISSING_ZERO_BUG
    if (st->st_shared.ptr[0] == 0)
	return STF_REPLACE_DOOMED_EXCHANGE;
#endif
    if (!generate_skeyids_iv(st))
	return STF_FAIL + AUTHENTICATION_FAILED;

    /*************** build output packet HDR*;IDii;HASH/SIG_I ***************/
    /* ??? NOTE: this is almost the same as main_inI3_outR3's code */

    /* HDR* out done */

    /* IDii out */
    {
	struct isakmp_ipsec_id id_hd;
	chunk_t id_b;
	pb_stream id_pbs;

	build_id_payload(&id_hd, &id_b, &st->st_connection->this);
	id_hd.isaiid_np = auth_payload;
	if (!out_struct(&id_hd, &isakmp_ipsec_identification_desc, &md->rbody, &id_pbs)
	|| !out_chunk(id_b, &id_pbs, "my identity"))
	    return STF_INTERNAL_ERROR;
	close_output_pbs(&id_pbs);
    }

    /* HASH_I or SIG_I out */
    {
	u_char hash_val[MAX_DIGEST_LEN];
	size_t hash_len = main_mode_hash(st, hash_val, TRUE, TRUE);

	if (auth_payload == ISAKMP_NEXT_HASH)
	{
	    /* HASH_I out */
	    if (!out_generic_raw(ISAKMP_NEXT_NONE, &isakmp_hash_desc, &md->rbody
	    , hash_val, hash_len, "HASH_I"))
		return STF_INTERNAL_ERROR;
	}
	else
	{
	    /* SIG_I out */
	    u_char sig_val[RSA_MAX_OCTETS];
	    size_t sig_len = RSA_sign_hash(st->st_connection
		, sig_val, hash_val, hash_len);

	    if (sig_len == 0)
	    {
		loglog(RC_LOG_SERIOUS, "unable to locate my private key for RSA Signature");
		return STF_FAIL + AUTHENTICATION_FAILED;
	    }

	    if (!out_generic_raw(ISAKMP_NEXT_NONE, &isakmp_signature_desc
	    , &md->rbody, sig_val, sig_len, "SIG_I"))
		return STF_INTERNAL_ERROR;
	}
    }

    /* encrypt message, except for fixed part of header */

    /* st_new_iv was computed by generate_skeyids_iv */
    if (!encrypt_message(&md->rbody, st))
	return STF_INTERNAL_ERROR;	/* ??? we may be partly committed */

    /* Advance state */
    st->st_state = STATE_MAIN_I3;

    return STF_REPLY;
}

/* STATE_MAIN_R2:
 * PSK_AUTH: HDR*, IDi1, HASH_I --> HDR*, IDr1, HASH_R
 * DS_AUTH: HDR*, IDi1, [ CERT, ] SIG_I --> HDR*, IDr1, [ CERT, ] SIG_R
 * PKE_AUTH, RPKE_AUTH: HDR*, HASH_I --> HDR*, HASH_R
 */
stf_status
main_inI3_outR3(struct msg_digest *md)
{
    struct state *const st = md->st;
    int auth_payload = st->st_oakley.auth == OAKLEY_PRESHARED_KEY
	? ISAKMP_NEXT_HASH : ISAKMP_NEXT_SIG;

    /* input code similar to main_inR3 -- should be factored */

    /* IDii in */
    if (!decode_peer_id(md, FALSE, FALSE))
	return STF_FAIL + INVALID_ID_INFORMATION;

    /* HASH_I or SIG_I in */
    RETURN_STF_FAILURE(check_main_authenticator(md, TRUE));

    /*************** build output packet HDR*;IDir;HASH/SIG_R ***************/
    /* ??? NOTE: this is almost the same as main_inR2_outI3's code */

    /* IDir out */
    {
	struct isakmp_ipsec_id id_hd;
	chunk_t id_b;
	pb_stream r_id_pbs;

	build_id_payload(&id_hd, &id_b, &st->st_connection->this);
	id_hd.isaiid_np = auth_payload;
	if (!out_struct(&id_hd, &isakmp_ipsec_identification_desc, &md->rbody, &r_id_pbs)
	|| !out_chunk(id_b, &r_id_pbs, "my identity"))
	    return STF_INTERNAL_ERROR;
	close_output_pbs(&r_id_pbs);
    }

    /* HASH_R or SIG_R out */
    {
	u_char hash_val[MAX_DIGEST_LEN];
	size_t hash_len = main_mode_hash(st, hash_val, FALSE, TRUE);

	if (auth_payload == ISAKMP_NEXT_HASH)
	{
	    /* HASH_R out */
	    if (!out_generic_raw(ISAKMP_NEXT_NONE, &isakmp_hash_desc, &md->rbody
	    , hash_val, hash_len, "HASH_R"))
		return STF_INTERNAL_ERROR;
	}
	else
	{
	    /* SIG_R out */
	    u_char sig_val[RSA_MAX_OCTETS];
	    size_t sig_len = RSA_sign_hash(st->st_connection
		, sig_val, hash_val, hash_len);

	    if (sig_len == 0)
	    {
		loglog(RC_LOG_SERIOUS, "unable to locate my private key for RSA Signature");
		return STF_FAIL + AUTHENTICATION_FAILED;
	    }

	    if (!out_generic_raw(ISAKMP_NEXT_NONE, &isakmp_signature_desc
	    , &md->rbody, sig_val, sig_len, "SIG_R"))
		return STF_INTERNAL_ERROR;
	}
    }

    /* encrypt message, sans fixed part of header */

    if (!encrypt_message(&md->rbody, st))
	return STF_INTERNAL_ERROR;	/* ??? we may be partly committed */

    /* Last block of Phase 1 (R3), kept for Phase 2 IV generation */
    DBG_cond_dump(DBG_CRYPT, "last encrypted block of Phase 1:"
	, st->st_new_iv, st->st_new_iv_len);

    /* Advance state */
    st->st_state = STATE_MAIN_R3;
    ISAKMP_SA_established(st->st_connection, st->st_serialno);

    /* ??? If st->st_connectionc->gw_info != NULL,
     * we should keep the public key -- it tested out.
     */

    return STF_REPLY_UNPEND_QUICK;
}

/* STATE_MAIN_I3:
 * Handle HDR*;IDir;HASH/SIG_R from responder.
 */
stf_status
main_inR3(struct msg_digest *md)
{
    struct state *const st = md->st;
    struct connection *c = st->st_connection;

    /* input code similar to main_inI3_outR3 -- should be factored */

    /* IDir in */
    if (!decode_peer_id(md, TRUE, FALSE))
	return STF_FAIL + INVALID_ID_INFORMATION;

    /* HASH_R or SIG_R in */
    RETURN_STF_FAILURE(check_main_authenticator(md, FALSE));

    /**************** done input ****************/

    /* Advance state */
    st->st_state = STATE_MAIN_I4;
    ISAKMP_SA_established(c, st->st_serialno);

    /* ??? If c->gw_info != NULL,
     * we should keep the public key -- it tested out.
     */

    update_iv(st);	/* finalize our Phase 1 IV */

    return STF_UNPEND_QUICK;
}


/* STATE_AGGR_R0: HDR, SA, KE, Ni, IDii 
 *           --> HDR, SA, KE, Nr, IDir, HASH_R/SIG_R
 */
stf_status
aggr_inI1_outR1(struct msg_digest *md)
{
    /* With Aggressive Mode, we get an ID payload in this, the first
     * message, so we can use it to index the preshared-secrets
     * when the IP address would not be meaningful (i.e. Road
     * Warrior).  So our first task is to unravel the ID payload.
     */
    struct state *st;
    struct payload_digest *const sa_pd = md->chain[ISAKMP_NEXT_SA];
    pb_stream *keyex_pbs = &md->chain[ISAKMP_NEXT_KE]->pbs;
    struct connection *c = find_host_connection(&md->iface->addr, pluto_port
	, &md->sender, md->sender_port);
    pb_stream r_sa_pbs;
    int auth_payload;
	
    DBG(DBG_CONTROL, DBG_log("aggr_inI1_outR1, md->iface->addr.u.v4: %x,"
    	" pluto_port: %x,"
	" md->sender: %x,"
	" md->sender_port: %x,", md->iface->addr.u.v4, pluto_port,
				md->sender, md->sender_port));
    if (c == NULL)
    {
	/* see if a wildcarded connection can be found */
	c = find_host_connection(&md->iface->addr, pluto_port
	    , (const ip_address *)NULL, md->sender_port);
	DBG(DBG_CONTROL, DBG_log("aggr_inI1_outR1 2"));
	if (c != NULL)
	{
	    /* create a temporary connection that is a copy of this one */
	    c = rw_connection(c, &md->sender);
	    DBG(DBG_CONTROL, DBG_log("aggr_inI1_outR1 3"));
	}
	else
	{
	    loglog(RC_LOG_SERIOUS, "initial Aggressive Mode message from %s"
		" but no (wildcard) connection has been configured"
		, md->sender);
	    /* XXX notification is in order! */
	    return STF_IGNORE;
	}
    }
    
    DBG(DBG_CONTROL, DBG_log("aggr_inI1_outR1 4"));
    /* Set up state */
    cur_state = md->st = st = new_state();	/* (caller will reset cur_state) */
    st->st_connection = c;

    st->st_policy |= POLICY_AGGRESSIVE;

    /* KLUDGE: st_oakley determined by SA parse which wants the pre-
       shared secret already determinable by decode_peer_id! */
    /* we really need to peek into the SA to see if it is RSASIG
       or something else. */
    st->st_oakley.auth = OAKLEY_PRESHARED_KEY;  /* FIXME! */
    if (!decode_peer_id(md, FALSE, TRUE))
    {
	char buf[200];

	DBG(DBG_CONTROL, DBG_log("aggr_inI1_outR1 5, md->iface->addr.u.v4: %x,"
    	" pluto_port: %x,"
	" md->sender: %x,"
	" md->sender_port: %x,", md->iface->addr.u.v4, pluto_port,
				md->sender, md->sender_port));
	(void) idtoa(&st->st_connection->that.id, buf, sizeof(buf));
	loglog(RC_LOG_SERIOUS,
	     "initial Aggressive Mode packet claiming to be from %s"
	     " on %s but no connection has been authorized",
	    buf, inet_ntoa(md->sin.sin_addr));
	/* XXX notification is in order! */
	return STF_FAIL + INVALID_ID_INFORMATION;
    }

#ifdef DEBUG
    extra_debugging(c);
#endif
    st->st_try = 0;	/* Not our job to try again from start */
    st->st_policy = c->policy & ~POLICY_IPSEC_MASK;  /* only as accurate as connection */

#if 0
    /* Copy identity from temporary state object */
    st->st_peeridentity = tempstate.st_peeridentity;
    st->st_peeridentity_type = tempstate.st_peeridentity_type;
    st->st_peeruserprotoid = tempstate.st_peeruserprotoid;
    st->st_peeruserport = tempstate.st_peeruserport;
#endif

    memcpy(st->st_icookie, md->hdr.isa_icookie, COOKIE_SIZE);
    get_cookie(ISAKMP_RESPONDER, st->st_rcookie, COOKIE_SIZE, &md->sender);

    insert_state(st);	/* needs cookies, connection, and msgid (0) */

    st->st_doi = ISAKMP_DOI_IPSEC;
    st->st_situation = SIT_IDENTITY_ONLY; /* We only support this */
    st->st_state = STATE_AGGR_R1;

    log("responding to Aggressive Mode, state #%lu, connection \"%s\""
	" %s from %s"
	, st->st_serialno, st->st_connection->name
	, (c->rw_state == rwcs_instance) ? "(Road Warrior)" : ""
	, inet_ntoa(c->that.host_addr.u.v4.sin_addr));
    
    /* save initiator SA for HASH */
    clonereplacechunk(st->st_p1isa, sa_pd->pbs.start, pbs_room(&sa_pd->pbs),
		      "sa in aggr_inI1_outR1()");

    /* parse_isakmp_sa also spits out a winning SA into our reply,
     * so we have to build our md->reply and emit HDR before calling it.
     */

    /* HDR out */
    {
	struct isakmp_hdr r_hdr = md->hdr;

	memcpy(r_hdr.isa_rcookie, st->st_rcookie, COOKIE_SIZE);
	r_hdr.isa_np = ISAKMP_NEXT_SA;
	if (!out_struct(&r_hdr, &isakmp_hdr_desc, &md->reply, &md->rbody))
	    return STF_INTERNAL_ERROR;
    }

    /* start of SA out */
    {
	struct isakmp_sa r_sa = sa_pd->payload.sa;
	notification_t r;

	r_sa.isasa_np = ISAKMP_NEXT_KE;
	if (!out_struct(&r_sa, &isakmp_sa_desc, &md->rbody, &r_sa_pbs))
	    return STF_INTERNAL_ERROR;

	/* SA body in and out */
	r = parse_isakmp_sa_body(&sa_pd->pbs, &sa_pd->payload.sa,
				 &r_sa_pbs, FALSE, st);
	if (r != NOTHING_WRONG)
	    return STF_FAIL + r;
    }

    /* don't know until after SA body has been parsed */
    auth_payload = st->st_oakley.auth == OAKLEY_PRESHARED_KEY
	? ISAKMP_NEXT_HASH : ISAKMP_NEXT_SIG;


    /* KE in */
    RETURN_STF_FAILURE(accept_KE(&st->st_gi, "Gi", st->st_oakley.group, keyex_pbs));

    /* Ni in */
    RETURN_STF_FAILURE(accept_nonce(md, &st->st_ni, "Ni"));


    /************** build rest of output: KE, Nr, IDir, HASH_R/SIG_R ********/

    /* KE */
    if (!build_and_ship_KE(st, &st->st_gr, st->st_oakley.group,
			   &md->rbody, ISAKMP_NEXT_NONCE))
	return STF_INTERNAL_ERROR;

    /* Nr */
    if (!build_and_ship_nonce(&st->st_nr, &md->rbody, ISAKMP_NEXT_ID, "Nr"))
	return STF_INTERNAL_ERROR;

    /* IDir out */
    {
	struct isakmp_ipsec_id id_hd;
	chunk_t id_b;
	pb_stream r_id_pbs;

	build_id_payload(&id_hd, &id_b, &st->st_connection->this);
	id_hd.isaiid_np = auth_payload;
	if (!out_struct(&id_hd, &isakmp_ipsec_identification_desc, &md->rbody, &r_id_pbs)
	|| !out_chunk(id_b, &r_id_pbs, "my identity"))
	    return STF_INTERNAL_ERROR;
	close_output_pbs(&r_id_pbs);
    }

    compute_dh_shared(st, st->st_gi, st->st_oakley.group);
#ifdef DODGE_DH_MISSING_ZERO_BUG
    if (st->st_shared.ptr[0] == 0)
	return STF_DROP_DOOMED_EXCHANGE;
#endif
    if (!generate_skeyids_iv(st))
	return STF_FAIL + AUTHENTICATION_FAILED;
    update_iv(st);

    /* HASH_R or SIG_R out */
    {
	u_char hash_val[MAX_DIGEST_LEN];
	size_t hash_len = main_mode_hash(st, hash_val, FALSE, TRUE);

	if (auth_payload == ISAKMP_NEXT_HASH)
	{
	    /* HASH_R out */
	    if (!out_generic_raw(ISAKMP_NEXT_NONE, &isakmp_hash_desc, &md->rbody
	    , hash_val, hash_len, "HASH_R"))
		return STF_INTERNAL_ERROR;
	}
	else
	{
	    /* SIG_R out */
	    u_char sig_val[RSA_MAX_OCTETS];
	    size_t sig_len = RSA_sign_hash(st->st_connection
		, sig_val, hash_val, hash_len);

	    if (sig_len == 0)
	    {
		loglog(RC_LOG_SERIOUS, "unable to locate my private key for RSA Signature");
		return STF_FAIL + AUTHENTICATION_FAILED;
	    }

	    if (!out_generic_raw(ISAKMP_NEXT_NONE, &isakmp_signature_desc
	    , &md->rbody, sig_val, sig_len, "SIG_R"))
		return STF_INTERNAL_ERROR;
	}
    }

    /* finish message */
    close_message(&md->rbody);

    /* Advance state */
    st->st_state = STATE_AGGR_R1;

    return STF_REPLY;
}

/* STATE_AGGR_I1: HDR, SA, KE, Nr, IDir, HASH_R/SIG_R
 *           --> HDR*, HASH_I/SIG_I
 */
stf_status
aggr_inR1_outI2(struct msg_digest *md)
{
    /* With Aggressive Mode, we get an ID payload in this, the second
     * message, so we can use it to index the preshared-secrets
     * when the IP address would not be meaningful (i.e. Road
     * Warrior).  So our first task is to unravel the ID payload.
     */
    struct state *st = md->st;
    pb_stream *keyex_pbs = &md->chain[ISAKMP_NEXT_KE]->pbs;
    struct connection *c = st->st_connection;
    int auth_payload;

    st->st_policy |= POLICY_AGGRESSIVE;

    DBG(DBG_CONTROL, DBG_log("aggr_inR1_outI2 - 1"));
    if (!decode_peer_id(md, FALSE, TRUE))
    {
	char buf[200];

	(void) idtoa(&st->st_connection->that.id, buf, sizeof(buf));
	loglog(RC_LOG_SERIOUS,
	     "initial Aggressive Mode packet claiming to be from %s"
	     " on %s but no connection has been authorized",
	    buf, md->sender);
	/* XXX notification is in order! */
	return STF_FAIL + INVALID_ID_INFORMATION;
    }
    DBG(DBG_CONTROL, DBG_log("aggr_inR1_outI2 - 2"));
    auth_payload = st->st_oakley.auth == OAKLEY_PRESHARED_KEY
	? ISAKMP_NEXT_HASH : ISAKMP_NEXT_SIG;

    DBG(DBG_CONTROL, DBG_log("aggr_inR1_outI2 - 3"));
    /* verify echoed SA */
    {
	struct payload_digest *const sapd = md->chain[ISAKMP_NEXT_SA];
	notification_t r = \
	    parse_isakmp_sa_body(&sapd->pbs, &sapd->payload.sa,
				 NULL, TRUE, st);

	if (r != NOTHING_WRONG)
	    return STF_FAIL + r;
    }

    /* KE in */
    RETURN_STF_FAILURE(accept_KE(&st->st_gr, "Gr", st->st_oakley.group, keyex_pbs));

    /* Ni in */
    RETURN_STF_FAILURE(accept_nonce(md, &st->st_nr, "Nr"));

    /* moved the following up as we need Rcookie for hash, skeyids */
    /* Reinsert the state, using the responder cookie we just received */
    unhash_state(st);
    memcpy(st->st_rcookie, md->hdr.isa_rcookie, COOKIE_SIZE);
    insert_state(st);	/* needs cookies, connection, and msgid (0) */

    DBG(DBG_CONTROL, DBG_log("aggr_inR1_outI2 - 4"));
    /* Generate SKEYID, SKEYID_A, SKEYID_D, SKEYID_E */
    compute_dh_shared(st, st->st_gr, st->st_oakley.group);
#ifdef DODGE_DH_MISSING_ZERO_BUG
    if (st->st_shared.ptr[0] == 0)
	return STF_REPLACE_DOOMED_EXCHANGE;
#endif
    if (!generate_skeyids_iv(st))
	return STF_FAIL + AUTHENTICATION_FAILED;
    update_iv(st);

    /* HASH_R or SIG_R in */
    RETURN_STF_FAILURE(check_main_authenticator(md, FALSE));

    /**************** build output packet: HDR, HASH_I/SIG_I **************/

    /* HDR out */
    {
	struct isakmp_hdr r_hdr = md->hdr;

	memcpy(r_hdr.isa_rcookie, st->st_rcookie, COOKIE_SIZE);
	/* outputting should back-patch previous struct/hdr with payload type */
	r_hdr.isa_np = auth_payload;
	r_hdr.isa_flags |= ISAKMP_FLAG_ENCRYPTION;  /* KLUDGE */
	if (!out_struct(&r_hdr, &isakmp_hdr_desc, &md->reply, &md->rbody))
	    return STF_INTERNAL_ERROR;
    }

    /* HASH_I or SIG_I out */
    {
	u_char hash_val[MAX_DIGEST_LEN];
	size_t hash_len = main_mode_hash(st, hash_val, TRUE, TRUE);

	if (auth_payload == ISAKMP_NEXT_HASH)
	{
	    /* HASH_I out */
	    if (!out_generic_raw(ISAKMP_NEXT_NONE, &isakmp_hash_desc, &md->rbody
	    , hash_val, hash_len, "HASH_I"))
		return STF_INTERNAL_ERROR;
	}
	else
	{
	    /* SIG_I out */
	    u_char sig_val[RSA_MAX_OCTETS];
	    size_t sig_len = RSA_sign_hash(st->st_connection
		, sig_val, hash_val, hash_len);

	    if (sig_len == 0)
	    {
		loglog(RC_LOG_SERIOUS, "unable to locate my private key for RSA Signature");
		return STF_FAIL + AUTHENTICATION_FAILED;
	    }

	    if (!out_generic_raw(ISAKMP_NEXT_NONE, &isakmp_signature_desc
	    , &md->rbody, sig_val, sig_len, "SIG_I"))
		return STF_INTERNAL_ERROR;
	}
    }

    /* RFC2408 says we must encrypt at this point */

    /* st_new_iv was computed by generate_skeyids_iv */
    if (!encrypt_message(&md->rbody, st))
	return STF_INTERNAL_ERROR;	/* ??? we may be partly committed */

    st->st_state = STATE_AGGR_I2;
    c->newest_isakmp_sa = st->st_serialno;
    
    DBG(DBG_CONTROL, DBG_log("aggr_inR1_outI2 - 5"));
    return STF_REPLY_UNPEND_QUICK;
}

/* STATE_AGGR_R1: HDR*, HASH_I --> done
 */
stf_status
aggr_inI2(struct msg_digest *md)
{
    struct state *const st = md->st;
    struct connection *c = st->st_connection;

    /* HASH_I or SIG_I in */
    RETURN_STF_FAILURE(check_main_authenticator(md, TRUE));

    /**************** done input ****************/

    /* Advance state */
    DBG(DBG_CONTROL, DBG_log("aggr_inI2"));
    st->st_state = STATE_AGGR_R2;
    c->newest_isakmp_sa = st->st_serialno;

    update_iv(st);	/* Finalize our Phase 1 IV */

    return STF_NO_REPLY;
}



/* Handle first message of Phase 2 -- Quick Mode.
 * HDR*, HASH(1), SA, Ni [, KE ] [, IDci, IDcr ] -->
 * HDR*, HASH(2), SA, Nr [, KE ] [, IDci, IDcr ]
 * (see draft-ietf-ipsec-isakmp-oakley-07.txt 5.5)
 * Installs inbound IPsec SAs.
 * Although this seems early, we know enough to do so, and
 * this way we know that it is soon enough to catch all
 * packets that other side could send using this IPsec SA.
 */
stf_status
quick_inI1_outR1(struct msg_digest *md)
{
    /* we build reply packet as we parse the message since
     * the parse_ipsec_sa_body emits the reply SA
     */

    struct state *st = duplicate_state(md->st);
    struct connection *c = st->st_connection;
    struct payload_digest *const id_pd = md->chain[ISAKMP_NEXT_ID];
    ip_subnet our_net, peer_net;

    u_char
	*r_hashval,	/* where in reply to jam hash value */
	*r_hash_start;	/* from where to start hashing */

    /* first: fill in missing bits of our new state object */

    st->st_try = 0;	/* not our job to try again from start */

    st->st_msgid = md->hdr.isa_msgid;

    st->st_new_iv_len = md->st->st_new_iv_len;
    memcpy(st->st_new_iv, md->st->st_new_iv, st->st_new_iv_len);

    cur_state = st;	/* (caller will reset) */
#ifdef DEBUG
    extra_debugging(c);
#endif
    md->st = st;	/* feed back new state */

    st->st_policy = c->policy;	/* somebody has got to do it */

    insert_state(st);	/* needs cookies, connection, and msgid */

    /* HASH(1) in */
    CHECK_QUICK_HASH(md, quick_mode_hash12(hash_val, hash_pbs->roof, md->message_pbs.roof, st, FALSE)
	, "HASH(1)", "Quick I1");

    /* HDR* out done */

    /* HASH(2) out -- first pass */
    START_HASH_PAYLOAD(md->rbody, ISAKMP_NEXT_SA);

    /* [ IDci, IDcr ] in
     * We do this now (probably out of physical order) because
     * we wish to select the correct connection before we consult
     * it for policy.
     */

    if (id_pd != NULL)
    {
	/* ??? we are assuming IPSEC_DOI */

	/* IDci (initiator is peer) */

	if (!decode_net_id(&id_pd->payload.ipsec_id, &id_pd->pbs
	, &peer_net, "peer client"))
	    return STF_FAIL + INVALID_ID_INFORMATION;

	st->st_peeruserprotoid = id_pd->payload.ipsec_id.isaiid_protoid;
	st->st_peeruserport = id_pd->payload.ipsec_id.isaiid_port;

	/* IDcr (we are responder) */

	if (!decode_net_id(&id_pd->next->payload.ipsec_id, &id_pd->next->pbs
	, &our_net, "our client"))
	    return STF_FAIL + INVALID_ID_INFORMATION;

	st->st_myuserprotoid = id_pd->next->payload.ipsec_id.isaiid_protoid;
	st->st_myuserport = id_pd->next->payload.ipsec_id.isaiid_port;
    }
    else
    {
	/* implicit IDci and IDcr: peer and self */
	err_t ugh;

	if (!sameaddrtype(&c->this.host_addr, &c->that.host_addr))
	    return STF_FAIL;

	ugh = rangetosubnet(&c->this.host_addr, &c->this.host_addr, &our_net);
	passert(ugh == NULL);
	ugh = rangetosubnet(&c->that.host_addr, &c->that.host_addr, &peer_net);
	passert(ugh == NULL);
    }

    /* Now that we have identities of client subnets, we must look for
     * a suitable connection (our current one only matches for hosts).
     */
    {
	struct connection *p = find_client_connection(c
	    , &our_net, &peer_net);

#ifdef ALLOW_PHASE2_REFINE_SUBNETS
 	/* MAYBE DON'T NEED THIS MOD, BUT JUST MULTIPLE CONNECTION DESCRS. */
 	/* After completing phase 2 IKE with a CheckPoint FW-1/VPN-1,
 	 any packet we send through the tunnel causes the VPN-1 to
 	 attempt to negotiate a separate SA between the host endpoints.
 	 Therefore we have to instantiate another connection.
 	 This code has some similarities to the RW code (but not quite). */
 	if (p == NULL)
 	{
 	    if (inside_subnets(c, our_net, our_mask, peer_net, peer_mask))
 	    {
 		p = subnet_connection(c, our_net, our_mask, peer_net, peer_mask);
 		st->st_connection = p;
 		SET_CUR_CONNECTION(p);
 		rw_connection_discard(c);
 		c = p;
 	    }
 	}
#endif  /* ALLOW_PHASE2_REFINE_SUBNETS */

	if (p == NULL)
	{
	    /* This message occurs in very puzzling circumstances
	     * so we must add as much information and beauty as we can.
	     */
	    struct end
		me = c->this,
		he = c->that;
	    char buf[2*SUBNETTOT_BUF + 2*ADDRTOT_BUF + 2*IDTOA_BUF + 2*ADDRTOT_BUF + 12]; /* + 12 for separating */
	    size_t l;

	    me.client = our_net;
	    me.has_client = !subnetishost(&our_net)
		|| !addrinsubnet(&me.host_addr, &our_net);

	    he.client = peer_net;
	    he.has_client = !subnetishost(&peer_net)
		|| !addrinsubnet(&he.host_addr, &peer_net);

	    l = format_end(buf, sizeof(buf), &me, NULL, TRUE);
	    l += snprintf(buf + l, sizeof(buf) - l, "...");
	    (void)format_end(buf + l, sizeof(buf) - l, &he, NULL, FALSE);
	    log("cannot respond to IPsec SA request"
		" because no connection is known for %s"
		, buf);
	    return STF_FAIL + INVALID_ID_INFORMATION;
	}
	else if (p != c)
	{
	    /* We've got a better connection: it can support the
	     * specified clients.  But it may need instantiation.
	     */
	    if (p->kind == CK_TEMPLATE)
	    {
		/* Yup, it needs instantiation.  How much?
		 * Is it a Road Warrior connection (simple)
		 * or is it an Opportunistic connection (needing gw validation)?
		 */
		if (HasWildcardClient(p))
		{
		    /* Opportunistic.
		     * We need to determine if this peer is authorized
		     * to negotiate for this client!  If the peer's
		     * client is the peer, we assume that it is authorized.
		     * Since p isn't yet instantiated, we need to look
		     * in c for description of peer.
		     */
		    struct gw_info *gw = c->gw_info;
		    ip_address our_client
			, peer_client;

		    passert(subnetishost(&our_net) && subnetishost(&peer_net));

		    networkof(&our_net, &our_client);
		    networkof(&peer_net, &peer_client);

		    if (!sameaddr(&c->that.host_addr, &peer_client))
		    {
			err_t ugh = discover_gateway(&peer_client
			    , &c->that.id, &gw);

			if (ugh != NULL)
			{
			    char fgwb[ADDRTOT_BUF]
				, cb[ADDRTOT_BUF];

			    addrtot(&c->that.host_addr, 0, fgwb, sizeof(fgwb));
			    addrtot(&peer_client, 0, cb, sizeof(cb));
			    loglog(RC_OPPOFAILURE
				, "gateway %s claims client %s, but DNS for client fails to confirm: %s"
				, fgwb, cb, ugh);
			    return STF_FAIL + INVALID_ID_INFORMATION;
			}

			if (!same_RSA_public_key(get_his_RSA_public_key(c), &gw->gw_key))
			{
			    loglog(RC_OPPOFAILURE, "peer and client disagree about public key");
			    return STF_FAIL + INVALID_ID_INFORMATION;
			}
		    }

		    /* Instantiate inbound Opportunism, carrying over his ID
		     * and filling in a few more details.
		     */
		    p = oppo_instantiate(p, &c->that.host_addr, &p->that.id
			, gw, &our_client, &peer_client);
		}
		else
		{
		    /* Plain Road Warrior: instantiate, carrying over his ID */
		    p = rw_instantiate(p, &c->that.host_addr, &p->that.id);
		}
	    }
#ifdef DEBUG
	    /* temporarily bump up cur_debugging to get "using..." message
	     * printed if we'd want it with new connection.
	     */
	    {
		unsigned int old_cur_debugging = cur_debugging;

		cur_debugging |= p->extra_debugging;
		DBG(DBG_CONTROL, DBG_log("using connection \"%s\"", p->name));
		cur_debugging = old_cur_debugging;
	    }
#endif
	    st->st_connection = p;
	    SET_CUR_CONNECTION(p);
	    connection_discard(c);
	    c = p;
	}
    }

    /* now that we are sure of our connection, copy the connection's
     * IPSEC policy into our state.  The ISAKMP policy is water under
     * the bridge, I think.  It will reflect the ISAKMP SA that we
     * are using.
     */
    st->st_policy = (st->st_policy & POLICY_ISAKMP_MASK)
	| (c->policy & ~POLICY_ISAKMP_MASK);

    /* process SA (in and out) */
    {
	struct payload_digest *const sapd = md->chain[ISAKMP_NEXT_SA];
	pb_stream r_sa_pbs;
	struct isakmp_sa sa = sapd->payload.sa;

	/* sa header is unchanged -- except for np */
	sa.isasa_np = ISAKMP_NEXT_NONCE;
	if (!out_struct(&sa, &isakmp_sa_desc, &md->rbody, &r_sa_pbs))
	    return STF_INTERNAL_ERROR;

	/* parse and accept body */
	st->st_pfs_group = &unset_group;
	RETURN_STF_FAILURE(parse_ipsec_sa_body(&sapd->pbs
		, &sapd->payload.sa, &r_sa_pbs, FALSE, st));
    }

    passert(st->st_pfs_group != &unset_group);

    if ((st->st_policy & POLICY_PFS) && st->st_pfs_group == NULL)
    {
	loglog(RC_LOG_SERIOUS, "we require PFS but Quick I1 SA specifies no GROUP_DESCRIPTION");
	return STF_FAIL + NO_PROPOSAL_CHOSEN;	/* ??? */
    }

    /* Ni in */
    RETURN_STF_FAILURE(accept_nonce(md, &st->st_ni, "Ni"));

    /* [ KE ] in (for PFS) */
    RETURN_STF_FAILURE(accept_PFS_KE(md, &st->st_gi, "Gi", "Quick Mode I1"));

    log("responding to Quick Mode");

    /**** finish reply packet: Nr [, KE ] [, IDci, IDcr ] ****/

    /* Nr out */
    if (!build_and_ship_nonce(&st->st_nr, &md->rbody
    , st->st_pfs_group != NULL? ISAKMP_NEXT_KE : id_pd != NULL? ISAKMP_NEXT_ID : ISAKMP_NEXT_NONE
    , "Nr"))
	return STF_INTERNAL_ERROR;

    /* [ KE ] out (for PFS) */

    if (st->st_pfs_group != NULL)
    {
	if (!build_and_ship_KE(st, &st->st_gr, st->st_pfs_group
	, &md->rbody, id_pd != NULL? ISAKMP_NEXT_ID : ISAKMP_NEXT_NONE))
		return STF_INTERNAL_ERROR;

	/* MPZ-Operations might be done after sending the packet... */

#ifndef DODGE_DH_MISSING_ZERO_BUG
	compute_dh_shared(st, st->st_gi, st->st_pfs_group);
#endif
    }

    /* [ IDci, IDcr ] out */
    if  (id_pd != NULL)
    {
	struct isakmp_ipsec_id *p = (void *)md->rbody.cur;	/* UGH! */

	if (!out_raw(id_pd->pbs.start, pbs_room(&id_pd->pbs), &md->rbody, "IDci"))
	    return STF_INTERNAL_ERROR;
	p->isaiid_np = ISAKMP_NEXT_ID;

	p = (void *)md->rbody.cur;	/* UGH! */

	if (!out_raw(id_pd->next->pbs.start, pbs_room(&id_pd->next->pbs), &md->rbody, "IDcr"))
	    return STF_INTERNAL_ERROR;
	p->isaiid_np = ISAKMP_NEXT_NONE;
    }

    /* Compute reply HASH(2) and insert in output */
    (void)quick_mode_hash12(r_hashval, r_hash_start, md->rbody.cur, st, TRUE);

    /* Derive new keying material */
    compute_keymats(st);

    /* Tell the kernel to establish the new inbound SA
     * (unless the commit bit is set -- which we don't support).
     * We do this before any state updating so that
     * failure won't look like success.
     */
    if (!install_inbound_ipsec_sa(st))
	return STF_INTERNAL_ERROR;	/* ??? we may be partly committed */

    /* encrypt message, except for fixed part of header */

    if (!encrypt_message(&md->rbody, st))
	return STF_INTERNAL_ERROR;	/* ??? we may be partly committed */

    /* Update state of exchange */
    st->st_state = STATE_QUICK_R1;

    return STF_REPLY;
}

/* Handle (the single) message from Responder in Quick Mode.
 * HDR*, HASH(2), SA, Nr [, KE ] [, IDci, IDcr ] -->
 * HDR*, HASH(3)
 * (see draft-ietf-ipsec-isakmp-oakley-07.txt 5.5)
 * Installs inbound and outbound IPsec SAs, routing, etc.
 */
stf_status
quick_inR1_outI2(struct msg_digest *md)
{
    struct state *const st = md->st;
    const struct connection *c = st->st_connection;

    /* HASH(2) in */
    CHECK_QUICK_HASH(md, quick_mode_hash12(hash_val, hash_pbs->roof, md->message_pbs.roof, st, TRUE)
	, "HASH(2)", "Quick R1");

    /* SA in */
    {
	struct payload_digest *const sa_pd = md->chain[ISAKMP_NEXT_SA];

	RETURN_STF_FAILURE(parse_ipsec_sa_body(&sa_pd->pbs
	    , &sa_pd->payload.sa, NULL, TRUE, st));
    }

    /* Nr in */
    RETURN_STF_FAILURE(accept_nonce(md, &st->st_nr, "Nr"));

    /* [ KE ] in (for PFS) */
    RETURN_STF_FAILURE(accept_PFS_KE(md, &st->st_gr, "Gr", "Quick Mode R1"));

    if (st->st_pfs_group != NULL)
    {
	compute_dh_shared(st, st->st_gr, st->st_pfs_group);
#ifdef DODGE_DH_MISSING_ZERO_BUG
	if (st->st_shared.ptr[0] == 0)
	    return STF_REPLACE_DOOMED_EXCHANGE;
#endif
    }

    /* [ IDci, IDcr ] in; these must match what we sent */

    {
	struct payload_digest *const id_pd = md->chain[ISAKMP_NEXT_ID];

	if (id_pd != NULL)
	{
	    /* ??? we are assuming IPSEC_DOI */

	    /* IDci (we are initiator) */

	    if (!check_net_id(&id_pd->payload.ipsec_id, &id_pd->pbs
	    , &st->st_myuserprotoid, &st->st_myuserport
	    , &st->st_connection->this.client
	    , "our client"))
		return STF_FAIL + INVALID_ID_INFORMATION;

	    /* IDcr (responder is peer) */

	    if (!check_net_id(&id_pd->next->payload.ipsec_id, &id_pd->next->pbs
	    , &st->st_peeruserprotoid, &st->st_peeruserport
	    , &st->st_connection->that.client
	    , "peer client"))
		return STF_FAIL + INVALID_ID_INFORMATION;
	}
	else
	{
	    /* No IDci, IDcr: we must check that the defaults match our proposal.
	     * Parallels a sequence of assignments in quick_outI1.
	     */
	    if (!subnetishost(&c->this.client) || !subnetishost(&c->that.client))
	    {
		loglog(RC_LOG_SERIOUS, "IDci, IDcr payloads missing in message"
		    " but default does not match proposal");
		return STF_FAIL + INVALID_ID_INFORMATION;
	    }
	}
    }

    /* ??? We used to copy the accepted proposal into the state, but it was
     * never used.  From sa_pd->pbs.start, length pbs_room(&sa_pd->pbs).
     */

    /**************** build reply packet HDR*, HASH(3) ****************/

    /* HDR* out done */

    /* HASH(3) out -- since this is the only content, no passes needed */
    {
	u_char
	    *r_hashval,	/* where in reply to jam hash value */
	    *r_hash_start;	/* start of what is to be hashed */

	START_HASH_PAYLOAD(md->rbody, ISAKMP_NEXT_NONE);
	(void)quick_mode_hash3(r_hashval, st);
    }

    /* Derive new keying material */
    compute_keymats(st);

    /* Tell the kernel to establish the inbound, outbound, and routing part
     * of the new SA (unless the commit bit is set -- which we don't support).
     * We do this before any state updating so that
     * failure won't look like success.
     */
    if (!install_ipsec_sa(st, TRUE))
	return STF_INTERNAL_ERROR;

    /* encrypt message, except for fixed part of header */

    if (!encrypt_message(&md->rbody, st))
	return STF_INTERNAL_ERROR;	/* ??? we may be partly committed */

    /* Update state of exchange */
    st->st_state = STATE_QUICK_I2;
    st->st_connection->newest_ipsec_sa = st->st_serialno;

    /* note (presumed) success */
    if (c->gw_info != NULL)
	c->gw_info->last_worked_time = now();

    return STF_REPLY;
}

/* Handle last message of Quick Mode.
 * HDR*, HASH(3) -> done
 * (see draft-ietf-ipsec-isakmp-oakley-07.txt 5.5)
 * Installs outbound IPsec SAs, routing, etc.
 */
stf_status
quick_inI2(struct msg_digest *md)
{
    struct state *const st = md->st;

    /* HASH(3) in */
    CHECK_QUICK_HASH(md, quick_mode_hash3(hash_val, st)
	, "HASH(3)", "Quick I2");

    /* Tell the kernel to establish the outbound and routing part of the new SA
     * (the previous state established inbound)
     * (unless the commit bit is set -- which we don't support).
     * We do this before any state updating so that
     * failure won't look like success.
     */
    if (!install_ipsec_sa(st, FALSE))
	return STF_INTERNAL_ERROR;

    /* Advance state */
    st->st_state = STATE_QUICK_R2;
    st->st_connection->newest_ipsec_sa = st->st_serialno;

    update_iv(st);	/* not actually used, but tidy */

    /* note (presumed) success */
    {
	struct gw_info *gw = st->st_connection->gw_info;

	if (gw != NULL)
	    gw->last_worked_time = now();
    }

    return STF_NO_REPLY;
}
