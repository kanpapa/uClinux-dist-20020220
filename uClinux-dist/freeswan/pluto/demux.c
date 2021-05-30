/* demultiplex incoming IKE messages
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
 * RCSID $Id: demux.c,v 1.105 2001/06/16 16:31:40 dhr Exp $
 */

/* Ordering Constraints on Payloads
 *
 * rfc2409: The Internet Key Exchange (IKE)
 *
 * 5 Exchanges:
 *   "The SA payload MUST precede all other payloads in a phase 1 exchange."
 *
 *   "Except where otherwise noted, there are no requirements for ISAKMP
 *    payloads in any message to be in any particular order."
 *
 * 5.3 Phase 1 Authenticated With a Revised Mode of Public Key Encryption:
 *
 *   "If the HASH payload is sent it MUST be the first payload of the
 *    second message exchange and MUST be followed by the encrypted
 *    nonce. If the HASH payload is not sent, the first payload of the
 *    second message exchange MUST be the encrypted nonce."
 *
 *   "Save the requirements on the location of the optional HASH payload
 *    and the mandatory nonce payload there are no further payload
 *    requirements. All payloads-- in whatever order-- following the
 *    encrypted nonce MUST be encrypted with Ke_i or Ke_r depending on the
 *    direction."
 *
 * 5.5 Phase 2 - Quick Mode
 *
 *   "In Quick Mode, a HASH payload MUST immediately follow the ISAKMP
 *    header and a SA payload MUST immediately follow the HASH."
 *   [NOTE: there may be more than one SA payload, so this is not
 *    totally reasonable.  Probably all SAs should be so constrained.]
 *
 *   "If ISAKMP is acting as a client negotiator on behalf of another
 *    party, the identities of the parties MUST be passed as IDci and
 *    then IDcr."
 *
 *   "With the exception of the HASH, SA, and the optional ID payloads,
 *    there are no payload ordering restrictions on Quick Mode."
 */

/* Unfolding of Identity -- a central mystery
 *
 * This concerns Phase 1 identities, those of the IKE hosts.
 * These are the only ones that are authenticated.  Phase 2
 * identities are for IPsec SAs.
 *
 * There are three case of interest:
 *
 * (1) We initiate, based on a whack command specifying a Connection.
 *     We know the identity of the peer from the Connection.
 *
 * (2) (to be implemented) we initiate based on a flow from our client
 *     to some IP address.
 *     We immediately know one of the peer's client IP addresses from
 *     the flow.  We must use this to figure out the peer's IP address
 *     and Id.  To be solved.
 *
 * (3) We respond to an IKE negotiation.
 *     We immediately know the peer's IP address.
 *     We get an ID Payload in Main I2.
 *
 *     Unfortunately, this is too late for a number of things:
 *     - the ISAKMP SA proposals have already been made (Main I1)
 *       AND one accepted (Main R1)
 *     - the SA includes a specification of the type of ID
 *       authentication so this is negotiated without being told the ID.
 *     - with Preshared Key authentication, Main I2 is encrypted
 *       using the key, so it cannot be decoded to reveal the ID
 *       without knowing (or guessing) which key to use.
 *
 *     There are three reasonable choices here for the responder:
 *     + assume that the initiator is making wise offers since it
 *       knows the IDs involved.  We can balk later (but not gracefully)
 *       when we find the actual initiator ID
 *     + attempt to infer identity by IP address.  Again, we can balk
 *       when the true identity is revealed.  Actually, it is enough
 *       to infer properties of the identity (eg. SA properties and
 *       PSK, if needed).
 *     + make all properties universal so discrimination based on
 *       identity isn't required.  For example, always accept the same
 *       kinds of encryption.  Accept Public Key Id authentication
 *       since the Initiator presumably has our public key and thinks
 *       we must have / can find his.  This approach is weakest
 *       for preshared key since the actual key must be known to
 *       decrypt the Initiator's ID Payload.
 *     These choices can be blended.  For example, a class of Identities
 *     can be inferred, sufficient to select a preshared key but not
 *     sufficient to infer a unique identity.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <limits.h>

#if defined(IP_RECVERR) && defined(MSG_ERRQUEUE)
#  include <asm/types.h>	/* for __u8, __u32 */
#  include <linux/errqueue.h>
#  include <sys/uio.h>	/* struct iovec */
#endif

#include <freeswan.h>

#include "constants.h"
#include "defs.h"
#include "cookie.h"
#include "id.h"
#include "connections.h"	/* needs id.h */
#include "state.h"
#include "packet.h"
#include "md5.h"
#include "sha1.h"
#include "crypto.h" /* requires sha1.h and md5.h */
#include "log.h"
#include "demux.h"	/* needs packet.h */
#include "ipsec_doi.h"	/* needs demux.h and state.h */
#include "timer.h"
#include "whack.h"	/* requires connections.h */
#include "server.h"
#ifdef CONFIG_LEDMAN
#include <linux/ledman.h>
#endif

/* This file does basic header checking and demux of
 * incoming packets.
 */

/* state_microcode is a tuple of information parameterizing certain
 * centralized processing of a packet.  For example, it roughly
 * specifies what payloads are expected in this message.
 * The microcode is selected primarily based on the state.
 * In Phase 1, the payload structure often depends on the
 * authentication technique, so that too plays a part in selecting
 * the state_microcode to use.
 */

struct state_microcode {
    enum state_kind state;
    lset_t flags;
    lset_t req_payloads;	/* required payloads (allows just one) */
    lset_t opt_payloads;	/* optional payloads (any mumber) */
    u_int8_t first_out_payload;	/* if not ISAKMP_NEXT_NONE, payload to start with */
    enum event_type timeout_event;
    state_transition_fn *processor;
};

/* State Microcode Flags
 * The first flags are a set of Oakley Auth values
 * used to indicate to which auth values this entry applies
 * (most entries will use SMF_ALL_AUTH because they apply to all).
 * Note: SMF_ALL_AUTH matches 0 for those circumstances when no auth
 * has been set.
 */

#define SMF_ALL_AUTH	LRANGE(0, OAKLEY_AUTH_ROOF-1)
#define SMF_PSK_AUTH	LELEM(OAKLEY_PRESHARED_KEY)
#define SMF_DS_AUTH	(LELEM(OAKLEY_DSS_SIG) | LELEM(OAKLEY_RSA_SIG))
#define SMF_PKE_AUTH	(LELEM(OAKLEY_RSA_ENC) | LELEM(OAKLEY_ELGAMAL_ENC))
#define SMF_RPKE_AUTH	(LELEM(OAKLEY_RSA_ENC_REV) | LELEM(OAKLEY_ELGAMAL_ENC_REV))

#define SMF_INITIATOR	LELEM(OAKLEY_AUTH_ROOF + 0)
#define SMF_FIRST_ENCRYPTED_INPUT	LELEM(OAKLEY_AUTH_ROOF + 1)
#define SMF_INPUT_ENCRYPTED	LELEM(OAKLEY_AUTH_ROOF + 2)
#define SMF_OUTPUT_ENCRYPTED	LELEM(OAKLEY_AUTH_ROOF + 3)
#define SMF_RETRANSMIT_ON_DUPLICATE	LELEM(OAKLEY_AUTH_ROOF + 4)

#define SMF_ENCRYPTED (SMF_INPUT_ENCRYPTED | SMF_OUTPUT_ENCRYPTED)

static state_transition_fn	/* forward declaration */
    unexpected,
    informational;

/*
 * Define Global variable to hold the number of 
 * active IPSec connections
 */
#ifdef CONFIG_LEDMAN
int no_active_tunnels = 0;
#endif

/* state_microcode_table is a table of all state_microcode tuples.
 * It must be in order of state (the first element).
 * After initialization, ike_microcode_index[s] points to the
 * first entry in state_microcode_table for state s.
 * Remember that each state name in Main or Quick Mode describes
 * what has happened in the past, not what this message is.
 */

static const struct state_microcode
    *ike_microcode_index[STATE_IKE_ROOF - STATE_IKE_FLOOR];

static const struct state_microcode state_microcode_table[] = {
#define PT(n) ISAKMP_NEXT_##n
#define P(n) LELEM(PT(n))

    /***** Phase 1 Main Mode *****/

    /* No state for main_outI1: --> HDR, SA */

    /* STATE_MAIN_R0: I1 --> R1
     * HDR, SA --> HDR, SA
     */
    { STATE_MAIN_R0, SMF_ALL_AUTH
    , P(SA), P(VID), PT(NONE)
    , EVENT_RETRANSMIT, main_inI1_outR1},

    /* STATE_MAIN_I1: R1 --> I2
     * HDR, SA --> auth dependent
     * SMF_PSK_AUTH, SMF_DS_AUTH: --> HDR, KE, Ni
     * SMF_PKE_AUTH:
     *	--> HDR, KE, [ HASH(1), ] <IDi1_b>PubKey_r, <Ni_b>PubKey_r
     * SMF_RPKE_AUTH:
     *	--> HDR, [ HASH(1), ] <Ni_b>Pubkey_r, <KE_b>Ke_i, <IDi1_b>Ke_i [,<<Cert-I_b>Ke_i]
     * Note: since we don't know auth at start, we cannot differentiate
     * microcode entries based on it.
     */
    { STATE_MAIN_I1, SMF_ALL_AUTH | SMF_INITIATOR
    , P(SA), P(VID), PT(NONE) /* don't know yet */
    , EVENT_RETRANSMIT, main_inR1_outI2 },

    /* STATE_MAIN_R1: I2 --> R2
     * SMF_PSK_AUTH, SMF_DS_AUTH: HDR, KE, Ni --> HDR, KE, Nr
     * SMF_PKE_AUTH: HDR, KE, [ HASH(1), ] <IDi1_b>PubKey_r, <Ni_b>PubKey_r
     *	    --> HDR, KE, <IDr1_b>PubKey_i, <Nr_b>PubKey_i
     * SMF_RPKE_AUTH:
     *	    HDR, [ HASH(1), ] <Ni_b>Pubkey_r, <KE_b>Ke_i, <IDi1_b>Ke_i [,<<Cert-I_b>Ke_i]
     *	    --> HDR, <Nr_b>PubKey_i, <KE_b>Ke_r, <IDr1_b>Ke_r
     */
    { STATE_MAIN_R1, SMF_PSK_AUTH | SMF_DS_AUTH
    , P(KE) | P(NONCE), P(VID), PT(KE)
    , EVENT_RETRANSMIT, main_inI2_outR2 },

    { STATE_MAIN_R1, SMF_PKE_AUTH
    , P(KE) | P(ID) | P(NONCE), P(VID) | P(HASH), PT(KE)
    , EVENT_RETRANSMIT, unexpected /* ??? not yet implemented */ },

    { STATE_MAIN_R1, SMF_RPKE_AUTH
    , P(NONCE) | P(KE) | P(ID), P(VID) | P(HASH) | P(CERT), PT(NONCE)
    , EVENT_RETRANSMIT, unexpected /* ??? not yet implemented */ },

    /* for states from here on, output message must be encrypted */

    /* STATE_MAIN_I2: R2 --> I3
     * SMF_PSK_AUTH: HDR, KE, Nr --> HDR*, IDi1, HASH_I
     * SMF_DS_AUTH: HDR, KE, Nr --> HDR*, IDi1, [ CERT, ] SIG_I
     * SMF_PKE_AUTH: HDR, KE, <IDr1_b>PubKey_i, <Nr_b>PubKey_i
     *	    --> HDR*, HASH_I
     * SMF_RPKE_AUTH: HDR, <Nr_b>PubKey_i, <KE_b>Ke_r, <IDr1_b>Ke_r
     *	    --> HDR*, HASH_I
     */
    { STATE_MAIN_I2, SMF_PSK_AUTH | SMF_DS_AUTH | SMF_INITIATOR | SMF_OUTPUT_ENCRYPTED
    , P(KE) | P(NONCE), P(VID), PT(ID)
    , EVENT_RETRANSMIT, main_inR2_outI3 },

    { STATE_MAIN_I2, SMF_PKE_AUTH | SMF_INITIATOR | SMF_OUTPUT_ENCRYPTED
    , P(KE) | P(ID) | P(NONCE), P(VID), PT(HASH)
    , EVENT_RETRANSMIT, unexpected /* ??? not yet implemented */ },

    { STATE_MAIN_I2, SMF_ALL_AUTH | SMF_INITIATOR | SMF_OUTPUT_ENCRYPTED
    ,  P(NONCE) | P(KE) | P(ID), P(VID), PT(HASH)
    , EVENT_RETRANSMIT, unexpected /* ??? not yet implemented */ },

    /* for states from here on, input message must be encrypted */

    /* STATE_MAIN_R2: I3 --> R3
     * SMF_PSK_AUTH: HDR*, IDi1, HASH_I --> HDR*, IDr1, HASH_R
     * SMF_DS_AUTH: HDR*, IDi1, [ CERT, ] SIG_I --> HDR*, IDr1, [ CERT, ] SIG_R
     * SMF_PKE_AUTH, SMF_RPKE_AUTH: HDR*, HASH_I --> HDR*, HASH_R
     */
    { STATE_MAIN_R2, SMF_PSK_AUTH | SMF_FIRST_ENCRYPTED_INPUT | SMF_ENCRYPTED
    , P(ID) | P(HASH), P(VID), PT(ID)
    , EVENT_SA_REPLACE, main_inI3_outR3 },

    { STATE_MAIN_R2, SMF_DS_AUTH | SMF_FIRST_ENCRYPTED_INPUT | SMF_ENCRYPTED
    , P(ID) | P(SIG), P(VID) | P(CERT), PT(ID)
    , EVENT_SA_REPLACE, main_inI3_outR3 },

    { STATE_MAIN_R2, SMF_PKE_AUTH | SMF_RPKE_AUTH | SMF_FIRST_ENCRYPTED_INPUT | SMF_ENCRYPTED
    , P(HASH), P(VID), PT(HASH)
    , EVENT_SA_REPLACE, unexpected /* ??? not yet implemented */ },

    /* STATE_MAIN_I3: R3 --> done
     * SMF_PSK_AUTH: HDR*, IDr1, HASH_R --> done
     * SMF_DS_AUTH: HDR*, IDr1, [ CERT, ] SIG_R --> done
     * SMF_PKE_AUTH, SMF_RPKE_AUTH: HDR*, HASH_R --> done
     * May initiate quick mode by calling quick_outI1
     */
    { STATE_MAIN_I3, SMF_PSK_AUTH | SMF_INITIATOR | SMF_FIRST_ENCRYPTED_INPUT | SMF_ENCRYPTED
    , P(ID) | P(HASH), P(VID), PT(NONE)
    , EVENT_SA_REPLACE, main_inR3 },

    { STATE_MAIN_I3, SMF_DS_AUTH | SMF_INITIATOR | SMF_FIRST_ENCRYPTED_INPUT | SMF_ENCRYPTED
    , P(ID) | P(SIG), P(VID) | P(CERT), PT(NONE)
    , EVENT_SA_REPLACE, main_inR3 },

    { STATE_MAIN_I3, SMF_PKE_AUTH | SMF_RPKE_AUTH | SMF_INITIATOR | SMF_FIRST_ENCRYPTED_INPUT | SMF_ENCRYPTED
    , P(HASH), P(VID), PT(NONE)
    , EVENT_SA_REPLACE, unexpected /* ??? not yet implemented */ },

    /* STATE_MAIN_R3: can only get here due to packet loss */
    { STATE_MAIN_R3, SMF_ALL_AUTH | SMF_ENCRYPTED | SMF_RETRANSMIT_ON_DUPLICATE, LEMPTY, LEMPTY
    , PT(NONE), EVENT_NULL, unexpected },

    /* STATE_MAIN_I4: can only get here due to packet loss */
    { STATE_MAIN_I4, SMF_ALL_AUTH | SMF_INITIATOR | SMF_ENCRYPTED, LEMPTY, LEMPTY
    , PT(NONE), EVENT_NULL, unexpected },


    /***** Phase 1 Aggressive Mode *****/

    /* No state for aggr_outI1: -->HDR, SA, KE, Ni, IDii */

    /* STATE_AGGR_R0: HDR, SA, KE, Ni, IDii -->
     * HDR, SA, KE, Nr, IDir, HASH_R
     */
    { STATE_AGGR_R0, SMF_PSK_AUTH,
      P(SA) | P(KE) | P(NONCE) | P(ID), P(VID), PT(NONE),
      EVENT_RETRANSMIT, aggr_inI1_outR1 },

    /* STATE_AGGR_I1: HDR, SA, KE, Nr, IDir, HASH_R --> HDR*, HASH_I */
    { STATE_AGGR_I1, SMF_PSK_AUTH | SMF_INITIATOR | SMF_OUTPUT_ENCRYPTED,
      P(SA) | P(KE) | P(NONCE) | P(ID) | P(HASH), P(VID), PT(NONE),
      EVENT_SA_REPLACE, aggr_inR1_outI2 },

    /* STATE_AGGR_R1: HDR*, HASH_I --> done */
    { STATE_AGGR_R1, SMF_PSK_AUTH | SMF_FIRST_ENCRYPTED_INPUT | SMF_ENCRYPTED,
      P(HASH), P(VID), PT(NONE), EVENT_SA_REPLACE, aggr_inI2 },

    /* STATE_AGGR_I2: can only get here due to packet loss */
    { STATE_AGGR_I2, SMF_PSK_AUTH | SMF_INITIATOR | SMF_RETRANSMIT_ON_DUPLICATE,
      LEMPTY, LEMPTY, PT(NONE), EVENT_NULL, unexpected },

    /* STATE_AGGR_R2: can only get here due to packet loss */
    { STATE_AGGR_R2, SMF_PSK_AUTH,
      LEMPTY, LEMPTY, PT(NONE), EVENT_NULL, unexpected },



    /***** Phase 2 Quick Mode *****/

    /* No state for quick_outI1:
     * --> HDR*, HASH(1), SA, Nr [, KE ] [, IDci, IDcr ]
     */

    /* STATE_QUICK_R0:
     * HDR*, HASH(1), SA, Ni [, KE ] [, IDci, IDcr ] -->
     * HDR*, HASH(2), SA, Nr [, KE ] [, IDci, IDcr ]
     * Installs inbound IPsec SAs.
     * ??? it is legal to have multiple SAs, but we don't support it yet.
     */
    { STATE_QUICK_R0, SMF_ALL_AUTH | SMF_ENCRYPTED
    , P(HASH) | P(SA) | P(NONCE), /* P(SA) | */ P(KE) | P(ID), PT(HASH)
    , EVENT_RETRANSMIT, quick_inI1_outR1 },

    /* STATE_QUICK_I1:
     * HDR*, HASH(2), SA, Nr [, KE ] [, IDci, IDcr ] -->
     * HDR*, HASH(3)
     * Installs inbound and outbound IPsec SAs, routing, etc.
     * ??? it is legal to have multiple SAs, but we don't support it yet.
     */
    { STATE_QUICK_I1, SMF_ALL_AUTH | SMF_INITIATOR | SMF_ENCRYPTED
    , P(HASH) | P(SA) | P(NONCE), /* P(SA) | */ P(KE) | P(ID), PT(HASH)
    , EVENT_SA_REPLACE, quick_inR1_outI2 },

    /* STATE_QUICK_R1: HDR*, HASH(3) --> done
     * Installs outbound IPsec SAs, routing, etc.
     */
    { STATE_QUICK_R1, SMF_ALL_AUTH | SMF_ENCRYPTED
    , P(HASH), LEMPTY, PT(NONE)
    , EVENT_SA_REPLACE, quick_inI2 },

    /* STATE_QUICK_I2: can only happen due to lost packet */
    { STATE_QUICK_I2, SMF_ALL_AUTH | SMF_INITIATOR | SMF_ENCRYPTED | SMF_RETRANSMIT_ON_DUPLICATE
    , LEMPTY, LEMPTY, PT(NONE)
    , EVENT_NULL, unexpected },

    /* STATE_QUICK_R2: can only happen due to lost packet */
    { STATE_QUICK_R2, SMF_ALL_AUTH | SMF_ENCRYPTED
    , LEMPTY, LEMPTY, PT(NONE)
    , EVENT_NULL, unexpected },


    /***** informational messages *****/

    /* STATE_INFO: */
    { STATE_INFO, SMF_ALL_AUTH
    , LEMPTY, LEMPTY, PT(NONE)
    , EVENT_NULL, informational },

    /* STATE_INFO_PROTECTED: */
    { STATE_INFO_PROTECTED, SMF_ALL_AUTH | SMF_ENCRYPTED
    , P(HASH), LEMPTY, PT(NONE)
    , EVENT_NULL, informational },

#undef P
#undef PT
};

void
init_demux(void)
{
    /* fill ike_microcode_index:
     * make ike_microcode_index[s] point to first entry in
     * state_microcode_table for state s (backward scan makes this easier).
     * Check that table is in order -- catch coding errors.
     * For what it's worth, this routine is idempotent.
     */
    const struct state_microcode *t;

    for (t = &state_microcode_table[elemsof(state_microcode_table) - 1];;)
    {
	passert(STATE_IKE_FLOOR <= t->state && t->state < STATE_IKE_ROOF);
	ike_microcode_index[t->state - STATE_IKE_FLOOR] = t;
	if (t == state_microcode_table)
	    break;
	t--;
	passert(t[0].state <= t[1].state);
    }
}

bool
send_packet(struct state *st, const char *where)
{
    struct connection *c = st->st_connection;

    /* XXX: Not very clean.  We manipulate the port of the ip_address to
     * have a port in the sockaddr*
     */
    DBG_cond_dump_chunk(DBG_RAW, "sending:\n", st->st_tpacket);

    setportof(htons(c->that.host_port), &c->that.host_addr);

    if (sendto(c->interface->fd
    , st->st_tpacket.ptr, st->st_tpacket.len, 0
    , sockaddrof(&c->that.host_addr)
    , sockaddrlenof(&c->that.host_addr)) != (ssize_t)st->st_tpacket.len)
    {
	log_errno((e, "sendto() on %s to %s:%u failed in %s"
	    , c->interface->rname, ip_str(&c->that.host_addr)
	    , (unsigned)c->that.host_port, where));
	return FALSE;
    }
    else
    {
	return TRUE;
    }
}

static stf_status
unexpected(struct msg_digest *md)
{
    loglog(RC_LOG_SERIOUS, "unexpected message received in state %s"
	, enum_name(&state_names, md->st->st_state));
    return STF_IGNORE;
}

static stf_status
informational(struct msg_digest *md)
{
    struct payload_digest *const n_pld = md->chain[ISAKMP_NEXT_N];

    /* log contents of any notification payload */
    if (n_pld != NULL)
    {
	pb_stream *const n_pbs = &n_pld->pbs;
	struct isakmp_notification *const n = &n_pld->payload.notification;
	int disp_len;
	char disp_buf[200];

	if (pbs_left(n_pbs) >= sizeof(disp_buf)-1)
	    disp_len = sizeof(disp_buf)-1;
	else
	    disp_len = pbs_left(n_pbs);
	memcpy(disp_buf, n_pbs->cur, disp_len);
	disp_buf[disp_len] = '\0';

	/* should indicate from where... FIXME */
	log("Notification: Pid=%d SPIsz=%d Type=%d Val=%s\n" 
	    , n->isan_protoid, n->isan_spisize, n->isan_type
	    , disp_buf);
    }

    loglog(RC_LOG_SERIOUS, "received and ignored informational message");
    return STF_IGNORE;
}

/* free the resources in a message digest */

static void
free_md(struct msg_digest *md)
{
    freeanychunk(md->raw_packet);
    passert(md->packet_pbs.start != NULL);
    pfree(md->packet_pbs.start);
    md->packet_pbs.start = NULL;
    cur_state = NULL;
    UNSET_CUR_CONNECTION();
    cur_from = NULL;
}

/* Receive a packet. If we pass buffer to a routine that does not return
 * failure indication (e.g. the packet handling routines), it's up to them
 * to free it; otherwise this routine does.
 */
void
comm_handle(const struct iface *ifp)
{
    struct msg_digest md;
    const struct state_microcode *smc;
    bool new_iv_set = FALSE;

    /* initialize md */
    md.iface = ifp;
    md.from_state = STATE_UNDEFINED;		/* not yet valid */
    md.st = NULL;
    md.note = NOTHING_WRONG;
    md.raw_packet.ptr = NULL;
    (void)anyaddr(addrtypeof(&ifp->addr), &md.sender);

    md.encrypted = FALSE;
    md.digest_roof = md.digest;

    {
	int i;
	for (i = 0; i != ISAKMP_NEXT_ROOF; i++)
	    md.chain[i] = NULL;
    }

    /* Now really read the message.
     * Since we don't know its size, we read it into
     * an overly large buffer and then copy it to a
     * new, properly sized buffer.
     */
    {
	int packet_len;
	/* ??? this buffer seems *way* too big */
	u_int8_t bigbuffer[UDP_SIZE];
	union
	{
	    struct sockaddr sa;
	    struct sockaddr_in sa_in4;
	    struct sockaddr_in6 sa_in6;
	} from;
	int from_len = sizeof(from);
	err_t from_ugh = NULL;
	static const char undisclosed[] = "unknown source";

	passert(select_found == ifp->fd);
	zero(&from.sa);
	packet_len = recvfrom(ifp->fd, bigbuffer, sizeof(bigbuffer), 0
	    , &from.sa, &from_len);
	passert(select_found == ifp->fd);	/* true paranoia */
	select_found = NULL_FD;

	/* First: digest the from address.
	 * We presume that nothing here disturbs errno.
	 */
	if (packet_len == -1
	&& from_len == sizeof(from)
	&& all_zero((const void *)&from.sa, sizeof(from)))
	{
	    /* "from" is untouched -- not set by recvfrom */
	    from_ugh = undisclosed;
	}
	else if (from_len
	< (int) (offsetof(struct sockaddr, sa_family) + sizeof(from.sa.sa_family)))
	{
	    from_ugh = "truncated";
	}
	else
	{
	    const struct af_info *afi = aftoinfo(from.sa.sa_family);

	    if (afi == NULL)
	    {
		from_ugh = "unexpected Address Family";
	    }
	    else if (from_len != (int)afi->sa_sz)
	    {
		from_ugh = "wrong length";
	    }
	    else
	    {
		switch (from.sa.sa_family)
		{
		case AF_INET:
		    from_ugh = initaddr((void *) &from.sa_in4.sin_addr
			, sizeof(from.sa_in4.sin_addr), AF_INET, &md.sender);
		    md.sender_port = ntohs(from.sa_in4.sin_port);
		    break;
		case AF_INET6:
		    from_ugh = initaddr((void *) &from.sa_in6.sin6_addr
			, sizeof(from.sa_in6.sin6_addr), AF_INET6, &md.sender);
		    md.sender_port = ntohs(from.sa_in6.sin6_port);
		    break;
		}
	    }
	}

	/* now we report any actual I/O error */
	if (packet_len == -1)
	{
	    if (from_ugh == undisclosed
	    && errno == ECONNREFUSED)
	    {
		/* Tone down scary message for vague event:
		 * We get "connection refused" in response to some
		 * datagram we sent, but we cannot tell which one.
		 */
		log("some IKE message we sent has been rejected with ECONNREFUSED (kernel supplied no details)");
	    }
	    else if (from_ugh != NULL)
	    {
		log_errno((e, "recvfrom() on %s failed in comm_handle (Pluto cannot decode source sockaddr in rejection: %s)"
		    , ifp->rname, from_ugh));
	    }
	    else
	    {
		log_errno((e, "recvfrom() on %s from %s:%u failed in comm_handle"
		    , ifp->rname, ip_str(&md.sender)
		    , (unsigned)md.sender_port));
	    }

	    /* we are going to be daring: we'll try to use information
	     * passed on because of IP_RECVERR.
	     * The API is sparsely documented, and may be LINUX-only.
	     *
	     * - ip(7) describes IP_RECVERR
	     * - recvmsg(2) describes MSG_ERRQUEUE
	     * - readv(2) describes iovec
	     * - cmsg(3) describes how to process auxilliary messages
	     *
	     * ??? we should link this message with one we've sent
	     * so that the diagnostic can refer to that negotiation.
	     */
#if defined(IP_RECVERR) && defined(MSG_ERRQUEUE)
	    {
		struct msghdr emh;
		struct iovec eiov;
		union {
		    /* force alignment (not documented as necessary) */
		    struct cmsghdr ecms;

		    /* how much space is enough? */
		    unsigned char space[256];
		} ecms_buf;
		struct cmsghdr *cm;
		char fromstr[INET6_ADDRSTRLEN + sizeof(" port 65536")];

		zero(&from.sa);
		from_len = sizeof(from);

		emh.msg_name = &from.sa;	/* ??? filled in? */
		emh.msg_namelen = sizeof(from);
		emh.msg_iov = &eiov;
		emh.msg_iovlen = 1;
		emh.msg_control = &ecms_buf;
		emh.msg_controllen = sizeof(ecms_buf);
		emh.msg_flags = 0;

		eiov.iov_base = bigbuffer;	/* see readv(2) */
		eiov.iov_len = sizeof(bigbuffer);

		packet_len = recvmsg(ifp->fd, &emh, MSG_ERRQUEUE);

		if (packet_len == -1)
		{
		    log_errno((e, "recvmsgm(,, MSG_ERRQUEUE) on %s failed in comm_handle"
			, ifp->rname));
		    return;
		}

		DBG_cond_dump(DBG_ALL, "rejected packet:\n", bigbuffer, packet_len);
		DBG_cond_dump(DBG_ALL, "control:\n", emh.msg_control, emh.msg_controllen);
		/* ??? Andi Kleen <ak@suse.de> and misc documentation
		 * suggests that name will have the original destination
		 * of the packet.  We seem to see msg_namelen == 0.
		 * Andi says that this is a kernel bug and has fixed it.
		 * Perhaps in 2.2.18/2.4.0.
		 */
		passert(emh.msg_name == &from.sa);
		DBG_cond_dump(DBG_ALL, "name:\n", emh.msg_name
		    , emh.msg_namelen);
		snprintf(fromstr, sizeof(fromstr), "unknown");
		switch (from.sa.sa_family)
		{
		char as[INET6_ADDRSTRLEN];

		case AF_INET:
		    if (emh.msg_namelen == sizeof(struct sockaddr_in))
			snprintf(fromstr, sizeof(fromstr), "%s port %u"
			    , inet_ntop(from.sa.sa_family
			    , &from.sa_in4.sin_addr, as, sizeof(as))
			    , ntohs(from.sa_in4.sin_port));
		    break;
		case AF_INET6:
		    if (emh.msg_namelen == sizeof(struct sockaddr_in6))
			snprintf(fromstr, sizeof(fromstr), "%s port %u"
			    , inet_ntop(from.sa.sa_family
			    , &from.sa_in6.sin6_addr, as, sizeof(as))
			    , ntohs(from.sa_in6.sin6_port));
		    break;
		}

		for (cm = CMSG_FIRSTHDR(&emh)
		; cm != NULL
		; cm = CMSG_NXTHDR(&emh,cm))
		{
		    if (cm->cmsg_level == SOL_IP
		    && cm->cmsg_type == IP_RECVERR)
		    {
			/* ip(7) and recvmsg(2) specify:
			 * ee_origin is SO_EE_ORIGIN_ICMP for ICMP
			 *  or SO_EE_ORIGIN_LOCAL for locally generated errors.
			 * ee_type and ee_code are from the ICMP header.
			 * ee_info is the discovered MTU for EMSGSIZE errors
			 * ee_data is not used.
			 *
			 * ??? recvmsg(2) says "SOCK_EE_OFFENDER" but
			 * means "SO_EE_OFFENDER".  The OFFENDER is really
			 * the router that complained.  As such, the port
			 * is meaningless.
			 */

			/* ??? cmsg(3) claims that CMSG_DATA returns
			 * void *, but RFC 2292 and /usr/include/bits/socket.h
			 * say unsigned char *.  The manual is being fixed.
			 */
			struct sock_extended_err *ee = (void *)CMSG_DATA(cm);
			const char *offstr = "unspecified";
			char offstrspace[INET6_ADDRSTRLEN];
			const char *orname = "";

			if (cm->cmsg_len > CMSG_LEN(sizeof(struct sock_extended_err)))
			{
			    const struct sockaddr *offender = SO_EE_OFFENDER(ee);

			    switch (offender->sa_family)
			    {
			    case AF_INET:
				offstr = inet_ntop(offender->sa_family
				    , &((const struct sockaddr_in *)offender)->sin_addr
				    , offstrspace, sizeof(offstrspace));
				break;
			    case AF_INET6:
				offstr = inet_ntop(offender->sa_family
				    , &((const struct sockaddr_in6 *)offender)->sin6_addr
				    , offstrspace, sizeof(offstrspace));
				break;
			    default:
				offstr = "unknown";
				break;
			    }
			}

			switch (ee->ee_origin)
			{
			case SO_EE_ORIGIN_NONE:
			    orname = "none ";
			    break;
			case SO_EE_ORIGIN_LOCAL:
			    orname = "local ";
			    break;
			case SO_EE_ORIGIN_ICMP:
			    orname = "ICMP (not authenticated) ";
			    break;
			case SO_EE_ORIGIN_ICMP6:
			    orname = "ICMP6 (not authenticated) ";
			    break;
			}

			log("extended network error info for message to %s:"
			    " compainant %s"
			    ", errno %lu %s"
			    ", origin %s%d, type %d, code %d"
			    /* ", pad %d, info %ld" */
			    /* ", data %ld" */
			    , fromstr
			    , offstr
			    , (unsigned long) ee->ee_errno, strerror(ee->ee_errno)
			    , orname, ee->ee_origin, ee->ee_type, ee->ee_code
			    /* , ee->ee_pad, (unsigned long)ee->ee_info */
			    /* , (unsigned long)ee->ee_data */
			    );

			/* ??? we really should try to infer which
			 * negotiations are implicated.  Then we could
			 * better target the diagnostics.
			 */
		    }
		    else
		    {
			log("unknow cmsg: level %d, type %d, len %d"
			    , cm->cmsg_level, cm->cmsg_type, cm->cmsg_len);
		    }
		}

	    }
#endif /* defined(IP_RECVERR) && defined(MSG_ERRQUEUE) */
	    return;
	}
	else if (packet_len == 0)
	{
		log("received 0 size packet\n");
		return;
	}
	else if (from_ugh != NULL)
	{
	    log("recvfrom on %s returned misformed source sockaddr: %s"
		, ifp->rname, from_ugh);
	}
	cur_from = &md.sender;
	cur_from_port = md.sender_port;

	/* Clone actual message contents
	 * and set up md.packet_pbs to describe it.
	 */
	init_pbs(&md.packet_pbs,
	    clone_bytes(bigbuffer, packet_len, "message buffer in comm_handle()"),
	    packet_len, "packet");
    }

    DBG(DBG_RAW | DBG_CRYPT | DBG_PARSING | DBG_CONTROL,
	{
	    DBG_log(BLANK_FORMAT);
	    DBG_log("*received %d bytes from %s:%u on %s"
		, (int) pbs_room(&md.packet_pbs)
		, ip_str(cur_from), (unsigned) cur_from_port
		, ifp->rname);
	});

    DBG(DBG_RAW,
	DBG_dump("", md.packet_pbs.start, pbs_room(&md.packet_pbs)));

    if (!in_struct(&md.hdr, &isakmp_hdr_desc, &md.packet_pbs, &md.message_pbs))
    {
	/* XXX specific failures (special notification?):
	 * - bad ISAKMP major/minor version numbers
	 * - size of packet vs size of message
	 */
	free_md(&md);
	return;
    }

    if (md.packet_pbs.roof != md.message_pbs.roof)
    {
	log("size (%u) differs from size specified in ISAKMP HDR (%u)"
	    , (unsigned) pbs_room(&md.packet_pbs), md.hdr.isa_length);
	free_md(&md);
	return;
    }

    if (md.hdr.isa_flags & ISAKMP_FLAG_COMMIT)
    {
	/* XXX we should handle this, whatever it means */
	log("IKE message has the Commit Flag set but Pluto doesn't implement this feature");
	/* Win2K IPSec sets this - just ignore it */
	/* free_md(&md);
	   return; */
    }

    switch (md.hdr.isa_xchg)
    {
#ifdef NOTYET
    case ISAKMP_XCHG_NONE:
    case ISAKMP_XCHG_BASE:
#endif

    case ISAKMP_XCHG_AGGR:
    case ISAKMP_XCHG_IDPROT:	/* part of a Main Mode exchange */
	if (md.hdr.isa_msgid != 0)
	{
	    log("Message ID was 0x%08lx but should be zero in Phase 1",
		(unsigned long) md.hdr.isa_msgid);
	    /* XXX Could send notification back */
	    free_md(&md);
	    return;
	}

	if (is_zero_cookie(md.hdr.isa_icookie))
	{
	    log("Initiator Cookie must not be zero in Phase 1 message");
	    /* XXX Could send notification back */
	    free_md(&md);
	    return;
	}

	if (is_zero_cookie(md.hdr.isa_rcookie))
	{
	    /* initial message from initiator
	     * ??? what if this is a duplicate of another message?
	     */
	    if (md.hdr.isa_flags & ISAKMP_FLAG_ENCRYPTION)
	    {
		log("initial Phase 1 message is invalid:"
		    " its Encrypted Flag is on");
		free_md(&md);
		return;
	    }

	    /* don't build a state until the message looks tasty */
	    md.from_state = (md.hdr.isa_xchg == ISAKMP_XCHG_IDPROT
			     ? STATE_MAIN_R0 : STATE_AGGR_R0);
	}
	else
	{
	    /* not an initial message */

	    md.st = find_state(md.hdr.isa_icookie, md.hdr.isa_rcookie
		, &md.sender, md.hdr.isa_msgid);

	    if (md.st == NULL)
	    {
		/* perhaps this is a first message from the responder
		 * and contains a responder cookie that we've not yet seen.
		 */
		md.st = find_state(md.hdr.isa_icookie, zero_cookie
		    , &md.sender, md.hdr.isa_msgid);

		if (md.st == NULL)
		{
		    log("Phase 1 message is part of an unknown exchange");
		    /* XXX Could send notification back */
		    free_md(&md);
		    return;
		}
	    }
	    cur_state = md.st;
#ifdef DEBUG
	    extra_debugging(md.st->st_connection);
#endif
	    md.from_state = md.st->st_state;
	}
	break;

#ifdef NOTYET
    case ISAKMP_XCHG_AO:
#endif

    case ISAKMP_XCHG_INFO:	/* an informational exchange */
	cur_state = md.st = find_state(md.hdr.isa_icookie, md.hdr.isa_rcookie
	    , &md.sender, 0);
#ifdef DEBUG
	if (md.st != NULL)
	    extra_debugging(md.st->st_connection);
#endif
	if (md.hdr.isa_flags & ISAKMP_FLAG_ENCRYPTION)
	{
	    if (md.st == NULL)
	    {
		log("Informational Exchange is for an unknown (expired?) SA");
		/* XXX Could send notification back */
		free_md(&md);
		return;
	    }

	    if (!IS_ISAKMP_SA_ESTABLISHED(md.st->st_state))
	    {
		loglog(RC_LOG_SERIOUS, "encrypted Informational Exchange message is invalid"
		    " because it is for incomplete ISAKMP SA");
		/* XXX Could send notification back */
		free_md(&md);
		return;
	    }

	    if (md.hdr.isa_msgid == 0)
	    {
		loglog(RC_LOG_SERIOUS, "Informational Exchange message is invalid because"
		    " it has a Message ID of 0");
		/* XXX Could send notification back */
		free_md(&md);
		return;
	    }

	    if (!reserve_msgid(md.st, md.hdr.isa_msgid))
	    {
		loglog(RC_LOG_SERIOUS, "Informational Exchange message is invalid because"
		    " it has a previously used Message ID (0x%08lx)"
		    , (unsigned long)md.hdr.isa_msgid);
		/* XXX Could send notification back */
		free_md(&md);
		return;
	    }

	    init_phase2_iv(md.st, &md.hdr.isa_msgid);
	    new_iv_set = TRUE;

	    md.from_state = STATE_INFO_PROTECTED;
	}
	else
	{
	    if (md.st != NULL && IS_ISAKMP_SA_ESTABLISHED(md.st->st_state))
	    {
		loglog(RC_LOG_SERIOUS, "Informational Exchange message for"
		    " an established ISAKMP SA must be encrypted");
		/* XXX Could send notification back */
		free_md(&md);
		return;
	    }
	    md.from_state = STATE_INFO;
	}
	break;

    case ISAKMP_XCHG_QUICK:	/* part of a Quick Mode exchange */
	if (is_zero_cookie(md.hdr.isa_icookie))
	{
	    log("Quick Mode message is invalid because"
		" it has an Initiator Cookie of 0");
	    /* XXX Could send notification back */
	    free_md(&md);
	    return;
	}

	if (is_zero_cookie(md.hdr.isa_rcookie))
	{
	    log("Quick Mode message is invalid because"
		" it has a Responder Cookie of 0");
	    /* XXX Could send notification back */
	    free_md(&md);
	    return;
	}

	if (md.hdr.isa_msgid == 0)
	{
	    log("Quick Mode message is invalid because"
		" it has a Message ID of 0");
	    /* XXX Could send notification back */
	    free_md(&md);
	    return;
	}

	cur_state = md.st = find_state(md.hdr.isa_icookie, md.hdr.isa_rcookie
	    , &md.sender, md.hdr.isa_msgid);

	if (md.st == NULL)
	{
	    /* No appropriate Quick Mode state.
	     * See if we have a Main Mode state.
	     * ??? what if this is a duplicate of another message?
	     */
	    cur_state = md.st = find_state(md.hdr.isa_icookie, md.hdr.isa_rcookie
		, &md.sender, 0);

	    if (md.st == NULL)
	    {
		log("Quick Mode message is for a non-existent (expired?)"
		    " ISAKMP SA");
		/* XXX Could send notification back */
		free_md(&md);
		return;
	    }
#ifdef DEBUG
	    extra_debugging(md.st->st_connection);
#endif
	    if (!IS_ISAKMP_SA_ESTABLISHED(md.st->st_state))
	    {
		loglog(RC_LOG_SERIOUS, "Quick Mode message is unacceptable because"
		    " it is for an incomplete ISAKMP SA");
		/* XXX Could send notification back */
		free_md(&md);
		return;
	    }

	    /* only accept this new Quick Mode exchange if it has a unique message ID */
	    if (!reserve_msgid(md.st, md.hdr.isa_msgid))
	    {
		loglog(RC_LOG_SERIOUS, "Quick Mode I1 message is unacceptable because"
		    " it uses a previously used Message ID 0x%08lx"
		    " (perhaps this is a duplicated packet)"
		    , (unsigned long) md.hdr.isa_msgid);
		/* XXX Could send notification INVALID_MESSAGE_ID back */
		free_md(&md);
		return;
	    }

	    /* Quick Mode Initial IV */
	    init_phase2_iv(md.st, &md.hdr.isa_msgid);
	    new_iv_set = TRUE;

	    md.from_state = STATE_QUICK_R0;
	}
	else
	{
#ifdef DEBUG
	    extra_debugging(md.st->st_connection);
#endif
	    md.from_state = md.st->st_state;
	}

	break;

#ifdef NOTYET
    case ISAKMP_XCHG_NGRP:
    case ISAKMP_XCHG_ACK_INFO:
#endif

    default:
	log("unsupported exchange type %s in message"
	    , enum_show(&exchange_names, md.hdr.isa_xchg));
	free_md(&md);
	return;
    }

    /* We have found a from_state: set smc to describe its properties.
     * (We may not have a state object -- if we need to build one,
     * we wait until the packet has been sanity checked.)
     * Look up the appropriate microcode based on state and
     * possibly Oakley Auth type.
     */
    passert(STATE_IKE_FLOOR <= md.from_state && md.from_state <= STATE_IKE_ROOF);
    smc = ike_microcode_index[md.from_state - STATE_IKE_FLOOR];

    if (md.st != NULL)
    {
	while ((smc->flags & LELEM(md.st->st_oakley.auth)) == 0)
	{
	    smc++;
	    passert(smc->state == md.from_state);
	}
    }
    /* Detect and handle duplicated packets.
     * This won't work for the initial packet of an exchange
     * because we won't have a state object to remember it.
     * If we are in a non-receiving state (terminal), and the preceding
     * state did transmit, then the duplicate may indicate that that
     * transmission wasn't received -- retransmit it.
     * Otherwise, just discard it.
     * ??? Notification packets are like exchanges -- I hope that
     * they are idempotent!
     */
    if (md.st != NULL
    && md.st->st_rpacket.ptr != NULL
    && md.st->st_rpacket.len == pbs_room(&md.packet_pbs)
    && memcmp(md.st->st_rpacket.ptr, md.packet_pbs.start, md.st->st_rpacket.len) == 0)
    {
	if (smc->flags & SMF_RETRANSMIT_ON_DUPLICATE)
	{
	    if (md.st->st_retransmit < MAXIMUM_RETRANSMISSIONS)
	    {
		md.st->st_retransmit++;
		loglog(RC_RETRANSMISSION
		    , "retransmitting in response to duplicate packet; already %s"
		    , enum_name(&state_names, md.st->st_state));
		send_packet(md.st, "retransmit in response to duplicate");
	    }
	    else
	    {
		loglog(RC_LOG_SERIOUS, "discarding duplicate packet -- exhausted retransmission; already %s"
		    , enum_name(&state_names, md.st->st_state));
	    }
	}
	else
	{
	    loglog(RC_LOG_SERIOUS, "discarding duplicate packet; already %s"
		, enum_name(&state_names, md.st->st_state));
	}
	free_md(&md);
	return;
    }

    if (md.hdr.isa_flags & ISAKMP_FLAG_ENCRYPTION)
    {
	DBG(DBG_CRYPT, DBG_log("received encrypted packet from %s:%u"
	    , ip_str(&md.sender), (unsigned)md.sender_port));

	if (md.st == NULL)
	{
	    log("discarding encrypted message for an unknown ISAKMP SA");
	    /* XXX Could send notification back */
	    free_md(&md);
	    return;
	}
	if (md.st->st_skeyid_e.ptr == (u_char *) NULL)
	{
	    loglog(RC_LOG_SERIOUS, "discarding encrypted message"
		" because we haven't yet negotiated keying materiel");
	    /* XXX Could send notification back */
	    free_md(&md);
	    return;
	}

	/* Mark as encrypted */
	md.encrypted = TRUE;

	DBG(DBG_CRYPT, DBG_log("decrypting %u bytes using algorithm %s",
	    (unsigned) pbs_left(&md.message_pbs),
	    enum_show(&oakley_enc_names, md.st->st_oakley.encrypt)));

	/* do the specified decryption
	 *
	 * IV is from md.st->st_iv (md.st->st_iv_len)
	 * The new iv is placed in md.st->st_new_iv
	 *
	 * See draft-ietf-ipsec-isakmp-oakley-07.txt Appendix B
	 *
	 * XXX The IV should only be updated really if the packet
	 * is successfully processed.
	 * We should keep this value, check for a success return
	 * value from the parsing routines and then replace.
	 *
	 * Each post phase 1 exchange generates IVs from
	 * the last phase 1 block, not the last block sent.
	 */
	{
	    const struct encrypt_desc *e = md.st->st_oakley.encrypter;

	    if (pbs_left(&md.message_pbs) % e->blocksize != 0)
	    {
		loglog(RC_LOG_SERIOUS, "malformed message: not a multiple of encryption blocksize");
		/* XXX Could send notification back */
		free_md(&md);
		return;
	    }

	    /* XXX Detect weak keys */

	    /* grab a copy of raw packet (for duplicate packet detection) */
	    clonetochunk(md.raw_packet, md.packet_pbs.start
		, pbs_room(&md.packet_pbs), "raw packet");

	    /* Decrypt everything after header */
	    if (!new_iv_set)
	    {
		/* use old IV */
		passert(md.st->st_iv_len <= sizeof(md.st->st_new_iv));
		md.st->st_new_iv_len = md.st->st_iv_len;
		memcpy(md.st->st_new_iv, md.st->st_iv, md.st->st_new_iv_len);
	    }
	    e->crypt(FALSE, md.message_pbs.cur, pbs_left(&md.message_pbs)
		, md.st);
	}

	DBG_cond_dump(DBG_CRYPT, "decrypted:\n", md.message_pbs.cur,
	    md.message_pbs.roof - md.message_pbs.cur);

	DBG_cond_dump(DBG_CRYPT, "next IV:"
	    , md.st->st_new_iv, md.st->st_new_iv_len);
    }
    else
    {
	/* packet was not encryped -- should it have been? */

	if (smc->flags & SMF_INPUT_ENCRYPTED)
	{
	    loglog(RC_LOG_SERIOUS, "packet rejected: should have been encrypted");
	    /* XXX Could send notification back */
	    free_md(&md);
	    return;
	}
    }

    /* Digest the message.
     * Padding must be removed to make hashing work.
     * Padding comes from encryption (so this code must be after decryption).
     * Padding rules are described before the definition of
     * struct isakmp_hdr in packet.h.
     */
    {
	struct payload_digest *pd = md.digest;
	int np = md.hdr.isa_np;
	lset_t needed = smc->req_payloads;
	const char *excuse = smc->flags & SMF_FIRST_ENCRYPTED_INPUT
	    ? "probable authentication (preshared secret) failure: "
	    : "";

	while (np != ISAKMP_NEXT_NONE)
	{
	    struct_desc *sd = np < ISAKMP_NEXT_ROOF? payload_descs[np] : NULL;

	    if (pd == &md.digest[PAYLIMIT])
	    {
		loglog(RC_LOG_SERIOUS, "more than %d payloads in message; ignored", PAYLIMIT);
		free_md(&md);
		return;
	    }

	    if (sd == NULL)
	    {
		/* payload type is out of range or requires special handling */
		switch (np)
		{
		case ISAKMP_NEXT_ID:
		    sd = IS_PHASE1(md.from_state)
			? &isakmp_identification_desc : &isakmp_ipsec_identification_desc;
		    break;
		default:
		    loglog(RC_LOG_SERIOUS, "%smessage ignored because it contains an unknown or"
			" unexpected payload type (%s) at the outermost level"
			, excuse, enum_show(&payload_names, np));
		    free_md(&md);
		    return;
		}
	    }

	    {
		lset_t s = LELEM(np);

		if (0 == (s & (needed | smc->opt_payloads
		| LELEM(ISAKMP_NEXT_N) | LELEM(ISAKMP_NEXT_D))))
		{
		    loglog(RC_LOG_SERIOUS, "%smessage ignored because it contains an"
			" payload type (%s) unexpected in this message"
			, excuse, enum_show(&payload_names, np));
		    free_md(&md);
		    return;
		}
		needed &= ~s;
	    }

	    if (!in_struct(&pd->payload, sd, &md.message_pbs, &pd->pbs))
	    {
		loglog(RC_LOG_SERIOUS, "%smalformed payload in packet", excuse);
		free_md(&md);
		return;
	    }

	    /* place this payload at the end of the chain for this type */
	    {
		struct payload_digest **p;

		for (p = &md.chain[np]; *p != NULL; p = &(*p)->next)
		    ;
		*p = pd;
		pd->next = NULL;
	    }

	    np = pd->payload.generic.isag_np;
	    pd++;

	    /* since we've digested one payload happily, it is probably
	     * the case that any decryption worked.  So we will not suggest
	     * encryption failure as an excuse for subsequent payload
	     * problems.
	     */
	    excuse = "";
	}

	md.digest_roof = pd;

	DBG(DBG_PARSING,
	    if (pbs_left(&md.message_pbs) != 0)
		DBG_log("removing %d bytes of padding", (int) pbs_left(&md.message_pbs)));

	md.message_pbs.roof = md.message_pbs.cur;

	/* check that all mandatory payloads appeared */

	if (needed != 0)
	{
	    loglog(RC_LOG_SERIOUS, "message for %s is missing payloads %s"
		, enum_show(&state_names, md.from_state)
		, bitnamesof(payload_name, needed));
	    free_md(&md);
	    return;
	}
    }

    /* more sanity checking: enforce most ordering constraints */

    if (IS_PHASE1(md.from_state))
    {
	/* rfc2409: The Internet Key Exchange (IKE), 5 Exchanges:
	 * "The SA payload MUST precede all other payloads in a phase 1 exchange."
	 */
	if (md.chain[ISAKMP_NEXT_SA] != NULL
	&& md.hdr.isa_np != ISAKMP_NEXT_SA)
	{
	    loglog(RC_LOG_SERIOUS, "malformed Phase 1 message: does not start with an SA payload");
	    free_md(&md);
	    return;
	}
    }
    else if (IS_QUICK(md.from_state))
    {
	/* rfc2409: The Internet Key Exchange (IKE), 5.5 Phase 2 - Quick Mode
	 *
	 * "In Quick Mode, a HASH payload MUST immediately follow the ISAKMP
	 *  header and a SA payload MUST immediately follow the HASH."
	 * [NOTE: there may be more than one SA payload, so this is not
	 *  totally reasonable.  Probably all SAs should be so constrained.]
	 *
	 * "If ISAKMP is acting as a client negotiator on behalf of another
	 *  party, the identities of the parties MUST be passed as IDci and
	 *  then IDcr."
	 *
	 * "With the exception of the HASH, SA, and the optional ID payloads,
	 *  there are no payload ordering restrictions on Quick Mode."
	 */

	if (md.hdr.isa_np != ISAKMP_NEXT_HASH)
	{
	    loglog(RC_LOG_SERIOUS, "malformed Quick Mode message: does not start with a HASH payload");
	    free_md(&md);
	    return;
	}

	{
	    struct payload_digest *p;
	    int i;

	    for (p = md.chain[ISAKMP_NEXT_SA], i = 1; p != NULL
	    ; p = p->next, i++)
	    {
		if (p != &md.digest[i])
		{
		    loglog(RC_LOG_SERIOUS, "malformed Quick Mode message: SA payload is in wrong position");
		    free_md(&md);
		    return;
		}
	    }
	}

	/* rfc2409: The Internet Key Exchange (IKE), 5.5 Phase 2 - Quick Mode:
	 * "If ISAKMP is acting as a client negotiator on behalf of another
	 *  party, the identities of the parties MUST be passed as IDci and
	 *  then IDcr."
	 */
	{
	    struct payload_digest *id = md.chain[ISAKMP_NEXT_ID];

	    if (id != NULL)
	    {
		if (id->next == NULL || id->next->next != NULL)
		{
		    loglog(RC_LOG_SERIOUS, "malformed Quick Mode message:"
			" if any ID payload is present,"
			" there must be exactly two");
		    free_md(&md);
		    return;
		}
		if (id+1 != id->next)
		{
		    loglog(RC_LOG_SERIOUS, "malformed Quick Mode message:"
			" the ID payloads are not adjacent");
		    free_md(&md);
		    return;
		}
	    }
	}
    }

    /* Handle (ignore!) Delete/Notification/VendorID Payloads */
    /* XXX Handle deletions */
    /* XXX Handle Notifications */
    /* XXX Handle VID payloads */
    {
	struct payload_digest *p;

	for (p = md.chain[ISAKMP_NEXT_N]; p != NULL; p = p->next)
	{
	    loglog(RC_LOG_SERIOUS, "ignoring informational payload, type %s"
		, enum_show(&ipsec_notification_names, p->payload.notification.isan_type));
	    DBG_cond_dump(DBG_PARSING, "info:", p->pbs.cur, pbs_left(&p->pbs));
	}

	for (p = md.chain[ISAKMP_NEXT_D]; p != NULL; p = p->next)
	{
	    loglog(RC_LOG_SERIOUS, "ignoring Delete SA payload");
	    DBG_cond_dump(DBG_PARSING, "del:", p->pbs.cur, pbs_left(&p->pbs));
	}

	for (p = md.chain[ISAKMP_NEXT_VID]; p != NULL; p = p->next)
	{
	    loglog(RC_LOG_SERIOUS, "ignoring Vendor ID payload");
	    DBG_cond_dump(DBG_PARSING, "VID:", p->pbs.cur, pbs_left(&p->pbs));
	}

	for (p = md.chain[ISAKMP_NEXT_CERT]; p != NULL; p = p->next)
	{
	    loglog(RC_LOG_SERIOUS, "ignoring Certificate payload");
	    DBG_cond_dump(DBG_PARSING, "CERT:", p->pbs.cur, pbs_left(&p->pbs));
	}
    }

    /* XXX Handle Commit Bit set and unset it */

    /* invoke state transition function to do the state-specific things.
     * These include:
     * - process and judge payloads
     * - advance st_state
     * - update st_iv (result of decryption is in st_new_iv)
     * - build reply packet
     * - indicate to us whether to transmit the reply packet
     */
    {
	stf_status result;

	/* ??? this buffer seems *way* too big */
	u_int8_t reply_buffer[UDP_SIZE];

	/* set up reply pb_stream and possibly fill in hdr */
	init_pbs(&md.reply, reply_buffer, sizeof(reply_buffer), "reply packet");
	if (smc->first_out_payload != ISAKMP_NEXT_NONE)
	{
	    struct isakmp_hdr r_hdr = md.hdr;	/* mostly same as incoming header */

	    if (smc->flags & SMF_OUTPUT_ENCRYPTED)
		r_hdr.isa_flags |= ISAKMP_FLAG_ENCRYPTION;
	    /* some day, we may have to set r_hdr.isa_version */
	    r_hdr.isa_np = smc->first_out_payload;
	    if (!out_struct(&r_hdr, &isakmp_hdr_desc, &md.reply, &md.rbody))
		passert(FALSE);	/* surely must have room and be well-formed */
	}

	/* do the real work! */
	result = smc->processor(&md);
	cur_state = md.st;	/* may have been fiddled (eg. by quick_outI1) */
	switch (result)
	{
	    case STF_IGNORE:
		break;
	    case STF_NO_REPLY:
	    case STF_UNPEND_QUICK:
	    case STF_REPLY:
	    case STF_REPLY_UNPEND_QUICK:
		/* Delete previous retransmission event.
		 * New event will be scheduled below.
		 */
		DBG(DBG_CONTROL, DBG_log("comm handle: case STF_REPLY_UNPEND_QUICK"));
		delete_event(md.st);

		/* replace previous receive packet with latest */

		pfreeany(md.st->st_rpacket.ptr);

		if (md.encrypted)
		{
		    /* if encrypted, duplication already done */
		    md.st->st_rpacket = md.raw_packet;
		    md.raw_packet.ptr = NULL;
		}
		else
		{
		    clonetochunk(md.st->st_rpacket
			, md.packet_pbs.start
			, pbs_room(&md.packet_pbs), "raw packet");
		}

		/* free previous transmit packet */
		freeanychunk(md.st->st_tpacket);

		/* if requested, send the new reply packet */
		if (result == STF_REPLY || result == STF_REPLY_UNPEND_QUICK)
		{
		    close_output_pbs(&md.reply);   /* good form, but actually a no-op */

		    clonetochunk(md.st->st_tpacket, md.reply.start
			, pbs_offset(&md.reply), "reply packet");

		    /* actually send the packet
		     * Note: this is a great place to implement "impairments"
		     * for testing purposes.  Suppress or duplicate the
		     * send_packet call depending on md.st->st_state.
		     */
		    send_packet(md.st, "STF_REPLY");
		}

		/* Schedule for whatever timeout is specified */
		{
		    time_t delay;
		    enum event_type kind = smc->timeout_event;

		    switch (kind)
		    {
		    case EVENT_RETRANSMIT:	/* Retransmit packet */
			delay = EVENT_RETRANSMIT_DELAY_0;
			break;

		    case EVENT_SA_REPLACE:	/* SA replacement event */
			if (IS_PHASE1(md.st->st_state))
			{
			    delay = md.st->st_connection->sa_ike_life_seconds;
			    if (delay >= md.st->st_oakley.life_seconds)
				delay = md.st->st_oakley.life_seconds;
			}
			else
			{
			    /* Delay is min of up to four things:
			     * each can limit the lifetime.
			     */
			    delay = md.st->st_connection->sa_ipsec_life_seconds;
			    if (md.st->st_ah.present
			    && delay >= md.st->st_ah.attrs.life_seconds)
				delay = md.st->st_ah.attrs.life_seconds;
			    if (md.st->st_esp.present
			    && delay >= md.st->st_esp.attrs.life_seconds)
				delay = md.st->st_esp.attrs.life_seconds;
			    if (md.st->st_ipcomp.present
			    && delay >= md.st->st_ipcomp.attrs.life_seconds)
				delay = md.st->st_ipcomp.attrs.life_seconds;
			}

			/* If we have enough time, save some for
			 * replacement.  Otherwise, don't attempt.
			 * In fact, we should always have time.
			 * Whack enforces this restriction on our
			 * own lifetime.  If a smaller liftime comes
			 * from the other IKE, we won't have
			 * EVENT_SA_REPLACE.
			 *
			 * Important policy lies buried here.
			 * For example, we favour the initiator over the
			 * responder by making the initiator start rekeying
			 * sooner.  Also, fuzz is only added to the
			 * initiator's margin.
			 */
			{
			    unsigned long marg = md.st->st_connection->sa_rekey_margin;

			    if (smc->flags & SMF_INITIATOR)
				marg += marg
				    * md.st->st_connection->sa_rekey_fuzz / 100.E0
				    * (rand() / (RAND_MAX + 1.E0));
			    else
				marg /= 2;

			    if ((unsigned long)delay > marg)
			    {
				delay -= marg;
				md.st->st_margin = marg;
			    }
			    else
			    {
				kind = EVENT_SA_EXPIRE;
			    }
			}
			break;

		    case EVENT_NULL:	/* non-event */
		    case EVENT_REINIT_SECRET:	/* Refresh cookie secret */
		    default:
			passert(FALSE);
		    }
		    event_schedule(kind, delay, md.st);
		}

		if (IS_ISAKMP_SA_ESTABLISHED(md.st->st_state)
		|| IS_IPSEC_SA_ESTABLISHED(md.st->st_state))
		{
		    /* log our success */
		    loglog(RC_SUCCESS, "%s: %s"
			, enum_name(&state_names, md.st->st_state)
			, state_story[md.st->st_state - STATE_MAIN_R0]);
#ifdef CONFIG_LEDMAN
		    if (IS_IPSEC_SA_ESTABLISHED(md.st->st_state)) {
		    	ledman_cmd(LEDMAN_CMD_ON, LEDMAN_VPN);
			no_active_tunnels++;
		    }
#endif
		}
		else
		{
		    /* tell whack our progress */
		    whack_log(RC_NEW_STATE + md.st->st_state
			, "%s: from %s; %s"
			, enum_name(&state_names, md.st->st_state)
			, enum_name(&state_names, md.from_state)
			, state_story[md.st->st_state - STATE_MAIN_R0]);
		}

		if (result == STF_UNPEND_QUICK
		|| result == STF_REPLY_UNPEND_QUICK)
		{
		    DBG(DBG_CONTROL, DBG_log("comm_handle 1"));
		    /* Initiate any Quick Mode negotiations that
		     * were waiting to piggyback on this Keying Channel.
		     *
		     * ??? there is a potential race condition
		     * if we are the responder: the initial Phase 2
		     * message might outrun the final Phase 1 message.
		     * I think that retransmission will recover.
		     */
		    unpend(md.st);
		}
		DBG(DBG_CONTROL, DBG_log("comm_handle 2"));
		if (IS_ISAKMP_SA_ESTABLISHED(md.st->st_state)
		|| IS_IPSEC_SA_ESTABLISHED(md.st->st_state))
		    release_whack(md.st);
		break;

	    case STF_INTERNAL_ERROR:
		whack_log(RC_INTERNALERR + md.note
		    , "%s: internal error"
		    , enum_name(&state_names, md.st->st_state));

		DBG(DBG_CONTROL,
		    DBG_log("state transition function for %s had internal error",
			enum_name(&state_names, md.from_state)));
		break;

#ifdef DODGE_DH_MISSING_ZERO_BUG
	    case STF_REPLACE_DOOMED_EXCHANGE:
		/* we've got a distateful DH shared secret --
		 * let's renegotiate.
		 */
		loglog(RC_LOG_SERIOUS, "dropping and reinitiating exchange to avoid Pluto 1.0 bug"
		    " handling DH shared secret with leading zero byte");
		ipsecdoi_replace(md.st, md.st->st_try);
		delete_event(md.st);
		delete_state(md.st);
		md.st = NULL;
		break;
#endif

	    default:	/* a shortcut to STF_FAIL, setting md.note */
		md.note = result - STF_FAIL;
		result = STF_FAIL;
		/* FALL THROUGH ... */
	    case STF_FAIL:
		/* XXX Could send notification back
		 * As it is, we act as if this message never happened:
		 * whatever retrying was in place, remains in place.
		 */
		whack_log(RC_NOTIFICATION + md.note
		    , "%s: %s", enum_name(&state_names, md.st->st_state)
		    , enum_name(&ipsec_notification_names, md.note));

		DBG(DBG_CONTROL,
		    DBG_log("state transition function for %s failed: %s"
			, enum_name(&state_names, md.from_state)
			, enum_name(&ipsec_notification_names, md.note)));
		break;
	}
    }
    free_md(&md);
}
