/* PPTP extension for IP connection tracking. 
 * Brian Kuschak <bkuschak@yahoo.com> with some help from
 * Galen Hazelwood <galenh@esoft.com>.
 * Further modifications by Philip Craig <philipc@snapgear.com>
 *
 * Adapted from John Hardin's <jhardin@impsec.org> 2.2.x 
 * PPTP Masquerade patch.
 *
 * Masquerading for PPTP (Point to Point Tunneling Protocol).
 * PPTP is a a protocol for creating virtual private networks.
 * It is a specification defined by Microsoft and some vendors
 * working with Microsoft.  PPTP is built on top of a modified
 * version of the Internet Generic Routing Encapsulation Protocol.
 * GRE is defined in RFC 1701 and RFC 1702.  Documentation of
 * PPTP can be found on the Microsoft web site.
 *
 * Copyright (c) 1997-1998 Gordon Chaffee
 */

#include <linux/config.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/ip.h>
#include <net/checksum.h>
#include <net/tcp.h>
#include <linux/skbuff.h>
#include <linux/proc_fs.h>

#include <linux/netfilter_ipv4/lockhelp.h>
#include <linux/netfilter_ipv4/ip_conntrack_helper.h>
#include <linux/netfilter_ipv4/ip_conntrack_pptp.h>
#include <linux/netfilter_ipv4/ip_conntrack_protocol.h>

#ifdef CONFIG_IP_NF_PPTP_DEBUG
#define DEBUGP printk
#define PRINTK_GRE_HDR printk_gre_hdr
#define PRINTK_PPTP_HDR printk_pptp_hdr
#define DEBUG_DUMP_TUPLE DUMP_TUPLE
#define DEBUG_DUMP_TUPLE_TABLE(tp)                                  \
DEBUGP("tuple %p: master %p: %u.%u.%u.%u:%hu -> %u.%u.%u.%u:%hu\n", \
       (tp), (tp)->master,                                          \
       NIPQUAD((tp)->src.ip), ntohs((tp)->src.u.all),               \
       NIPQUAD((tp)->dst.ip), ntohs((tp)->dst.u.all))
#else
#define DEBUGP(format, args...)
#define PRINTK_GRE_HDR(from, iph, greh)
#define PRINTK_PPTP_HDR(from, iph, pptph)
#define DEBUG_DUMP_TUPLE(tp)
#define DEBUG_DUMP_TUPLE_TABLE(tp)
#endif

DECLARE_LOCK(ip_pptp_lock);
struct module *ip_conntrack_pptp = THIS_MODULE;

static LIST_HEAD(gre_list);
static DECLARE_RWLOCK(gre_list_lock);


#define GRE_TIMEOUT             (3*HZ)          /* after initial packet */
#define GRE_CONNECTED_TIMEOUT   (3*HZ)  /* after bidirectional traffic */

struct tuple_table {
	struct list_head		list;
	struct ip_conntrack_manip src;
	struct ip_conntrack_manip dst;
	struct ip_conntrack		*master;
};

#ifdef CONFIG_IP_NF_PPTP_DEBUG
/* PptpControlMessageType names */
static const char *strMName[] = {
	"UNKNOWN_MESSAGE",
	"START_SESSION_REQUEST",
	"START_SESSION_REPLY",
	"STOP_SESSION_REQUEST",
	"STOP_SESSION_REPLY",
	"ECHO_REQUEST",
	"ECHO_REPLY",
	"OUT_CALL_REQUEST",
	"OUT_CALL_REPLY",
	"IN_CALL_REQUEST",
	"IN_CALL_REPLY",
	"IN_CALL_CONNECTED",
	"CALL_CLEAR_REQUEST",
	"CALL_DISCONNECT_NOTIFY",
	"WAN_ERROR_NOTIFY",
	"SET_LINK_INFO"
};

static void
printk_pptp_hdr(char *from_txt, const struct iphdr *iph, const struct pptp_pkt_hdr *pptph)
{
	struct PptpControlHeader	*ctlh;
	__u16				msg;
        union {
                void				*rawreq;
                struct PptpOutCallRequest       *ocreq;
                struct PptpOutCallReply         *ocack;
                struct PptpInCallRequest        *icreq;
                struct PptpInCallReply          *icack;
		struct PptpClearCallRequest	*clrreq;
                struct PptpCallDisconnectNotify *disc;
                struct PptpWanErrorNotify       *wanerr;
                struct PptpSetLinkInfo          *setlink;
        } pptpReq;

	printk("%s", from_txt);
        printk("%d.%d.%d.%d -> ", NIPQUAD(iph->saddr));
        printk("%d.%d.%d.%d ", NIPQUAD(iph->daddr));
	printk("LEN=%d TY=%d MC=%X", ntohs(pptph->packetLength),
		ntohs(pptph->packetType), ntohl(pptph->magicCookie));

	if (ntohs(pptph->packetType) == PPTP_CONTROL_PACKET) {
		ctlh = (struct PptpControlHeader *) ((char *)pptph + sizeof(struct pptp_pkt_hdr));
		pptpReq.rawreq = (void *) ((char*) ctlh + sizeof(struct PptpControlHeader));

		/* todo call id */
		msg = htons(ctlh->messageType);
		switch(msg)
		{
			case PPTP_OUT_CALL_REQUEST:
				printk(" CID=%d", ntohs(pptpReq.ocreq->callID));
				break;
			case PPTP_IN_CALL_REQUEST:
				printk(" CID=%d", ntohs(pptpReq.icreq->callID));
				break;	
			case PPTP_OUT_CALL_REPLY:
				printk(" CID=%d PCID=%d", ntohs(pptpReq.ocack->callID),
					ntohs(pptpReq.ocack->peersCallID));
				break;
			case PPTP_WAN_ERROR_NOTIFY:
				printk(" PCID=%d", ntohs(pptpReq.wanerr->peersCallID));
				break;
	
			case PPTP_SET_LINK_INFO:
				printk(" PCID=%d", ntohs(pptpReq.setlink->peersCallID));
				break;
	
			case PPTP_CALL_DISCONNECT_NOTIFY:
				printk(" CID=%d", ntohs(pptpReq.disc->callID));
		}
		printk(" CTL=%s", (msg <= PPTP_MSG_MAX)? strMName[msg]:strMName[0]);
	}

	printk("\n");
}

void
printk_gre_hdr(char *from_txt, const struct iphdr *iph, const struct pptp_gre_hdr *greh)
{

	printk("%s GRE: ", from_txt);
	printk("%d.%d.%d.%d -> ", NIPQUAD(iph->saddr));
	printk("%d.%d.%d.%d ", NIPQUAD(iph->daddr));
	printk("PR=%X LEN=%d CID=%d", ntohs(greh->protocol),
		ntohs(greh->payload_len), ntohl(greh->call_id));

	printk("\n");
}
#endif


/*
 *	Store this tuple so we can lookup the peer call id later.
 */

void
put_gre_tuple(	__u32 s_addr, __u32 d_addr, __u16 call_id, __u16 peer_call_id, 
		struct ip_conntrack *master)
{
	struct list_head	*l;
	struct tuple_table	*tt;

	if((tt = kmalloc(sizeof(struct tuple_table), GFP_ATOMIC)) == NULL)
	{
		DEBUGP("put_gre_tuple: out of memory\n");
		return;
	}
	tt->src.ip = s_addr;
	tt->dst.ip = d_addr;
	tt->src.u.gre.call_id = call_id;
	tt->dst.u.gre.call_id = peer_call_id;
	INIT_LIST_HEAD(&tt->list);
	tt->master = master;

	//hash = hash_key(IPPROTO_GRE, d_addr, call_id);
	//l = &gre_table[hash];
	l = &gre_list;
	WRITE_LOCK(&gre_list_lock);
	list_add(&tt->list, l);
	WRITE_UNLOCK(&gre_list_lock);

	DEBUGP("put_gre_tuple(): ");
	DEBUG_DUMP_TUPLE_TABLE(tt);
}

/*
 *	Hunt the list to see if we have an entry for this tuple
 */

static struct tuple_table *
get_gre_tuple(	__u32 s_addr, __u32 d_addr, __u16 call_id)
{
	struct list_head		*l, *e;
	struct tuple_table		*tt;

	//hash = hash_key(IPPROTO_GRE, d_addr, call_id);
	//l = &gre_table[hash];
	l = &gre_list;
	for (e=l->next; e!=l; e=e->next) {
		tt = list_entry(e, struct tuple_table, list);
		
		if ((tt->src.ip == s_addr &&
					tt->dst.ip == d_addr &&
					tt->src.u.gre.call_id == call_id) ||
				(tt->dst.ip == s_addr &&
					tt->src.ip == d_addr &&
					tt->dst.u.gre.call_id == call_id)) {
			DEBUGP("get_gre_tuple(): found tuple: ");
			DEBUGP("%d.%d.%d.%d -> ", NIPQUAD(s_addr));
			DEBUGP("%d.%d.%d.%d ", NIPQUAD(d_addr));
			DEBUGP("CID=%d\n", call_id);
			return tt;
		}
	}

	DEBUGP("get_gre_tuple(): FAILED to lookup tuple: ");
	DEBUGP("%d.%d.%d.%d -> ", NIPQUAD(s_addr));
	DEBUGP("%d.%d.%d.%d ", NIPQUAD(d_addr));
	DEBUGP("CID=%d\n", call_id);
	return NULL;
}

/*
 *	Remove the selected tuple from the list
 *  No new gre packets will be accepted if we can't invert them,
 *  so this effectively closes the gre connections.
 */

static void
clear_gre_tuples(struct ip_conntrack *master)
{
	struct list_head		*l, *e, *enext;
	struct tuple_table		*tt;
	int				found = 0;

	//hash = hash_key(IPPROTO_GRE, d_addr, call_id);
	//l = &gre_table[hash];
	l = &gre_list;
	WRITE_LOCK(&gre_list_lock);
	for (e=l->next; e!=l; e=enext) {
		enext = e->next;
		tt = list_entry(e, struct tuple_table, list);
		if(tt->master == master) {
			DEBUGP("clear_gre_tuple(): ");
			DEBUG_DUMP_TUPLE_TABLE(tt);
			list_del(e);
			kfree(tt);
			found = 1;
		}
	}
	WRITE_UNLOCK(&gre_list_lock);
	if(!found) {
		DEBUGP("clear_gre_tuple(): FAILED to delete tuple: master = %p\n",
				master);
	}
}


static int gre_pkt_to_tuple(const void *datah, size_t datalen,
			    struct ip_conntrack_tuple *tuple)
{
	const struct pptp_gre_hdr *hdr = datah;

	/* Forward direction is easy */
	tuple->src.u.gre.call_id = hdr->call_id;
	tuple->dst.u.all = 0;
	return 1;
}

static int gre_invert_tuple(struct ip_conntrack_tuple *tuple,
			    const struct ip_conntrack_tuple *orig)
{
	struct tuple_table *t;

	READ_LOCK(&gre_list_lock);
	/* A response is harder to figure, lookup in list */
	if((t = get_gre_tuple(orig->src.ip, orig->dst.ip, orig->src.u.gre.call_id)))
	{
		if (orig->src.u.gre.call_id == t->src.u.gre.call_id)
			tuple->src.u.gre.call_id = t->dst.u.gre.call_id;
		else
			tuple->src.u.gre.call_id = t->src.u.gre.call_id;
		tuple->dst.u.all = 0;
		READ_UNLOCK(&gre_list_lock);
		return 1;
	}
	READ_UNLOCK(&gre_list_lock);
	DEBUGP("Couldn't find reponse to ");
	DEBUG_DUMP_TUPLE(orig);
	return 0;
}

/* Print out the per-protocol part of the tuple. */
static unsigned int gre_print_tuple(char *buffer,
				    const struct ip_conntrack_tuple *tuple)
{
	return sprintf(buffer, "call_id=%hu ",
		       ntohs(tuple->src.u.gre.call_id));
}

/* Print out the private part of the conntrack. */
static unsigned int gre_print_conntrack(char *buffer,
					const struct ip_conntrack *conntrack)
{
	return 0;
}

/* Returns verdict for packet, or -1 for invalid. */
static int gre_packet(struct ip_conntrack *conntrack,
		      struct iphdr *iph, size_t len,
		      enum ip_conntrack_info ctinfo)
{
#ifdef CONFIG_IP_NF_PPTP_DEBUG
	struct pptp_gre_hdr *greh = (struct pptp_gre_hdr *)((u_int32_t *)iph + iph->ihl);
#endif

	/* 
	 *	If we've seen traffic both ways, this is a connected GRE stream.
	 * 	Extend timeout. 
	 */
	if (conntrack->status & IPS_SEEN_REPLY) {
		ip_ct_refresh(conntrack, GRE_CONNECTED_TIMEOUT);
		/* Also, more likely to be important, and not a probe */
		set_bit(IPS_ASSURED_BIT, &conntrack->status);
	} else
		ip_ct_refresh(conntrack, GRE_TIMEOUT);

	DEBUGP("CT=%lx, DIR=%s ", (unsigned long) conntrack, 
		(ctinfo >= IP_CT_IS_REPLY ? "reply   " : "original"));
	PRINTK_GRE_HDR("", iph, greh);
	return NF_ACCEPT;
}

/* Called when a new connection for this protocol found. */
static int gre_new(struct ip_conntrack *conntrack,
			     struct iphdr *iph, size_t len)
{
	struct pptp_gre_hdr *greh = (struct pptp_gre_hdr *)((u_int32_t *)iph + iph->ihl);
	struct tuple_table *t;

	/* 
	 *	we only get here if we added a inverse tuple for this packet, meaning
	 *	we expected it.  set the master of this connection 
	 */
	READ_LOCK(&gre_list_lock);
	t = get_gre_tuple(iph->saddr, iph->daddr, greh->call_id);
	if(!t) {
		READ_UNLOCK(&gre_list_lock);
		DEBUGP("gre_new: Unexpected - don't have a tuple for this packet!\n");
		return 0;
	}

#ifdef CONFIG_IP_NF_NAT_PPTP
	/* 	Copy nat info from our master
	 *  (FIXME: This kind of thing should be done in nat_expected...
	 *   or, can we work it out from the tuple_table?)
	 */
	conntrack->nat.help.pptp_info.call_id
		= t->master->nat.help.pptp_info.call_id;
	conntrack->nat.help.pptp_info.mcall_id
		= t->master->nat.help.pptp_info.mcall_id;

	/*
	 * 	normally we see first packet from masqed client to server.  if the
	 *	server sends first, we need to adjust the expected response.
	 */
	conntrack->nat.help.pptp_info.serv_to_client = 0;
	if(iph->saddr != t->master->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.ip)
	{
		conntrack->nat.help.pptp_info.serv_to_client = 1;

		/* original src = pptp serv
		 * original dst = gateway
		 * reply src = client
		 * reply dst = pptp serv
		 */
		conntrack->tuplehash[IP_CT_DIR_REPLY].tuple.src.ip =
			t->master->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.ip;
	}
#endif

	DEBUGP("CT=%lx, Master=%lx, DIR=new ", (unsigned long) conntrack, (unsigned long) t->master);
	PRINTK_GRE_HDR("", iph, greh);
	READ_UNLOCK(&gre_list_lock);

	return 1;
}

struct ip_conntrack_protocol ip_conntrack_protocol_gre =
{ { NULL, NULL }, IPPROTO_GRE, "gre",
    gre_pkt_to_tuple, gre_invert_tuple, gre_print_tuple, gre_print_conntrack,
    gre_packet, gre_new, NULL };

/* 
 *	look for inbound control packets from server through masq gateway to masqed client
 */

static void ip_inbound_pptp_tcp(const struct iphdr *iph, size_t len,
		struct ip_conntrack *ct, enum ip_conntrack_info ctinfo)
{
	struct tcphdr *tcph = (void *)iph + iph->ihl * 4;
	unsigned int tcplen = len - iph->ihl * 4;
	struct pptp_pkt_hdr *pptph = (void *)tcph + tcph->doff * 4;
	unsigned int pptplen = tcplen - tcph->doff * 4;
	struct PptpControlHeader *ctlh = (void *)pptph + sizeof(*pptph);
	unsigned int ctllen = pptplen - sizeof(*pptph);
	union {
		void                            *rawreq;
		struct PptpOutCallRequest       *ocreq;
		struct PptpOutCallReply         *ocack;
		struct PptpInCallRequest        *icreq;
		struct PptpInCallReply          *icack;
		struct PptpClearCallRequest     *clrreq;
		struct PptpCallDisconnectNotify *disc;
		struct PptpWanErrorNotify       *wanerr;
		struct PptpSetLinkInfo          *setlink;
	} pptpReq;
	unsigned int datalen = ctllen - sizeof(*ctlh);
	__u16 msg, *cid, *pcid;
	int dir = CTINFO2DIR(ctinfo);

	DEBUGP("inbound_pptp_tcp(): CT=%lx, ", (unsigned long) ct);
	PRINTK_PPTP_HDR("", iph, pptph);

	if (ctllen < sizeof(*ctlh)) {
		DEBUGP("inbound_pptp_tcp(): ctllen too short\n");
		return;
	}

	pptpReq.rawreq = (void *)ctlh + sizeof(*ctlh);
	switch (msg = htons(ctlh->messageType)) {
		case PPTP_OUT_CALL_REPLY:
			/* server responding to masq'd client */
			if (datalen < sizeof(pptpReq.ocack))
				return;
			cid = &pptpReq.ocack->callID;
			pcid = &pptpReq.ocack->peersCallID;
			break;

		case PPTP_IN_CALL_REPLY:
			/* server responding to masq'd client */
			if (datalen < sizeof(pptpReq.icack))
				return;
			cid = &pptpReq.icack->callID;
			pcid = &pptpReq.icack->peersCallID;
			break;

		case PPTP_WAN_ERROR_NOTIFY:
			/* server notifying masq'd client */
			/* no need to alter conntrack */
			return;

		case PPTP_SET_LINK_INFO:
			/* server notifying masq'd client */
			/* no need to alter conntrack */
			return;

		case PPTP_CALL_DISCONNECT_NOTIFY:
			/* server notifying masq'd client */
			/* expire this connection */
			ip_ct_refresh(ct, (30*HZ));
			clear_gre_tuples(ct);
			return;

		default:
			DEBUGP("UNKNOWN inbound packet: ");
			DEBUGP("%s (TY=%d)\n", (msg <= PPTP_MSG_MAX)? strMName[msg] : strMName[0], msg);
			/* fall through */

		case PPTP_ECHO_REPLY:
		case PPTP_START_SESSION_REQUEST:
		case PPTP_START_SESSION_REPLY:
		case PPTP_STOP_SESSION_REQUEST:
		case PPTP_STOP_SESSION_REPLY:
		case PPTP_ECHO_REQUEST:
			/* no need to alter conntrack */
			return;
	}

	LOCK_BH(&ip_pptp_lock);

	/* tuple for GRE packets (from server to masqed client)
	 * Here src = pptp server, dst = ppp addr 
	 * !dir: src = masq client, dst = pptp server 
	 */

	/*	
	 *	masq client <--> pptp serv 
	 *	new connection replaces any old ones.
	 */
	
	/*
	 * 	populate our lists for peer call ID lookup
	 */
	put_gre_tuple(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.ip,
			ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.ip,
			dir ? *cid : *pcid, dir ? *pcid : *cid, ct);
	put_gre_tuple(ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.ip,
			ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.ip,
			dir ? *pcid : *cid, dir ? *cid : *pcid, ct);

	UNLOCK_BH(&ip_pptp_lock);
}

/* 
 * 	Look for outbound control packets from masqed client through masq gateway to server
 */

static void ip_outbound_pptp_tcp(const struct iphdr *iph, size_t len,
		struct ip_conntrack *ct, enum ip_conntrack_info ctinfo)
{
	struct tcphdr *tcph = (void *)iph + iph->ihl * 4;
	unsigned int tcplen = len - iph->ihl * 4;
	struct pptp_pkt_hdr *pptph = (void *)tcph + tcph->doff * 4;
	unsigned int pptplen = tcplen - tcph->doff * 4;
	struct PptpControlHeader *ctlh = (void *)pptph + sizeof(*pptph);
	unsigned int ctllen = pptplen - sizeof(*pptph);
	union {
		void                            *rawreq;
		struct PptpOutCallRequest       *ocreq;
		struct PptpOutCallReply         *ocack;
		struct PptpInCallRequest        *icreq;
		struct PptpInCallReply          *icack;
		struct PptpClearCallRequest     *clrreq;
		struct PptpCallDisconnectNotify *disc;
		struct PptpWanErrorNotify       *wanerr;
		struct PptpSetLinkInfo          *setlink;
	} pptpReq;
	unsigned int datalen = ctllen - sizeof(*ctlh);
	__u16 msg, *cid;

	DEBUGP("outbound_pptp_tcp(): CT=%lx, ", (unsigned long) ct);
	PRINTK_PPTP_HDR("", iph, pptph);

	if (ctllen < sizeof(*ctlh)) {
		DEBUGP("outbound_pptp_tcp(): ctllen too short\n");
		return;
	}

	pptpReq.rawreq = (void *)ctlh + sizeof(*ctlh);
	switch (msg = htons(ctlh->messageType)) {
		case PPTP_OUT_CALL_REQUEST:
			/* masq'd client initiating connection to server */
			if (datalen < sizeof(pptpReq.ocreq))
				return;
			cid = &pptpReq.ocreq->callID;
			break;		/* create conntrack and get CID */

		case PPTP_IN_CALL_REQUEST:
			/* masq'd client initiating connection to server */
			if (datalen < sizeof(pptpReq.icreq))
				return;
			cid = &pptpReq.icreq->callID;
			break;		/* create conntrack and get CID */

		case PPTP_CALL_CLEAR_REQUEST:
			/* masq'd client sending to server */
			/* no need to alter conntrack */
			return;

		case PPTP_CALL_DISCONNECT_NOTIFY:
			/* masq'd client notifying server */
			/* expire this connection */
			ip_ct_refresh(ct, (30*HZ));
			clear_gre_tuples(ct);
			return;

		default:
			DEBUGP("UNKNOWN outbound packet: ");
			DEBUGP("%s (TY=%d)\n", (msg <= PPTP_MSG_MAX)? strMName[msg]:strMName[0], msg);
			/* fall through */

		case PPTP_SET_LINK_INFO:
		case PPTP_START_SESSION_REQUEST:
		case PPTP_START_SESSION_REPLY:
		case PPTP_STOP_SESSION_REQUEST:
		case PPTP_STOP_SESSION_REPLY:
		case PPTP_ECHO_REQUEST:
			/* no need to alter conntrack */
			return;
	}

#ifdef CONFIG_IP_NF_NAT_PPTP
	/* Info for NAT */
	DEBUGP("ip_outbound_pptp_tcp(): %s, CT=%lx, CID=%d\n",
			strMName[msg], (unsigned long) ct, ntohs(*cid));
	ct->nat.help.pptp_info.call_id = *cid;
#endif
}

/* FIXME: This should be in userspace.  Later. */
static int help(const struct iphdr *iph, size_t len,
		struct ip_conntrack *ct,
		enum ip_conntrack_info ctinfo)
{
	/* tcplen not negative guaranteed by ip_conntrack_tcp.c */
	struct tcphdr *tcph = (void *)iph + iph->ihl * 4;
	unsigned int tcplen = len - iph->ihl * 4;
	struct pptp_pkt_hdr *pptph = (void *)tcph + tcph->doff * 4;
	unsigned int datalen = tcplen - tcph->doff * 4;
	int dir = CTINFO2DIR(ctinfo);

	/* Until there's been traffic both ways, don't look in packets. */
	if (ctinfo != IP_CT_ESTABLISHED
	    && ctinfo != IP_CT_ESTABLISHED+IP_CT_IS_REPLY) {
		DEBUGP("pptp: Conntrackinfo = %u\n", ctinfo);
		return NF_ACCEPT;
	}

	/* If we get a FIN or RST, this connection's going down, and so is */
	/* the GRE tunnel. Deal. */
	if (tcph->rst || tcph->fin) {
		DEBUGP("pptp: bringing down gre connection.\n");
		clear_gre_tuples(ct);
		return NF_ACCEPT;
	}
	
	/* Not whole TCP header? */
	if (tcplen < sizeof(struct tcphdr) || tcplen < tcph->doff*4) {
		DEBUGP("pptp: tcplen = %u\n", (unsigned)tcplen);
		return NF_ACCEPT;
	}

	/* Checksum invalid?  Ignore. */
	/* FIXME: Source route IP option packets --RR */
	if (tcp_v4_check(tcph, tcplen, iph->saddr, iph->daddr,
			 csum_partial((char *)tcph, tcplen, 0))) {
		DEBUGP("pptp_help: bad csum: %p %u %u.%u.%u.%u %u.%u.%u.%u\n",
		       tcph, tcplen, NIPQUAD(iph->saddr),
		       NIPQUAD(iph->daddr));
		return NF_ACCEPT;
	}

	/* if it's not a control message we can't do anything with it */
	if (datalen < sizeof(*pptph) ||
			ntohs(pptph->packetType) != PPTP_CONTROL_PACKET ||
			ntohl(pptph->magicCookie) != PPTP_MAGIC_COOKIE) {
		if (datalen != 0 )
			DEBUGP("pptp_help(): not a control pkt\n");
		return NF_ACCEPT;
	}

	if (dir == IP_CT_DIR_REPLY)
		ip_inbound_pptp_tcp(iph, len, ct, ctinfo);
	else
		ip_outbound_pptp_tcp(iph, len, ct, ctinfo);

	return NF_ACCEPT;
}

static struct ip_conntrack_helper pptp_out = 	{ { NULL, NULL },
						{ { 0, { __constant_htons(PPTP_TCP_PORT) } },
						{ 0, { 0 }, IPPROTO_TCP } },
						{ { 0, { 0xFFFF } },
						{ 0, { 0 }, 0xFFFF } },
						help };


static int __init init(void)
{
	int err;

	err = ip_conntrack_protocol_register(&ip_conntrack_protocol_gre);
	if (err != 0) {
		DEBUGP("pptp: failed to register conntrack protocol GRE!\n");
	} else {
		DEBUGP("pptp: registered conntrack protocol GRE!\n");

		err = ip_conntrack_helper_register(&pptp_out);
		if (err != 0) {
			printk("pptp: failed to register conntrack protocol PPTP!\n");
		} else {
			printk("pptp: registered conntrack protocol PPTP!\n");
		}
	}

	return err;
}

static void __exit fini(void)
{
	ip_conntrack_helper_unregister(&pptp_out);
}

EXPORT_SYMBOL(ip_pptp_lock);
EXPORT_SYMBOL(ip_conntrack_pptp);

module_init(init);
module_exit(fini);
