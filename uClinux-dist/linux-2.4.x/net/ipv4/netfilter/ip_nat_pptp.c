/* PPTP extension for TCP and GRE NAT alteration. 
 * Brian Kuschak <bkuschak@yahoo.com> with some help from
 * Galen Hazelwood <galenh@esoft.com>
 * Further modifications by Philip Craig <philipc@snapgear.com>
 */
#include <linux/config.h>
#include <linux/module.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <net/tcp.h>
#include <linux/netfilter_ipv4/ip_nat.h>
#include <linux/netfilter_ipv4/ip_nat_helper.h>
#include <linux/netfilter_ipv4/ip_nat_pptp.h>
#include <linux/netfilter_ipv4/ip_conntrack_pptp.h>
#include <linux/netfilter_ipv4/ip_conntrack_helper.h>

#ifdef CONFIG_IP_NF_PPTP_DEBUG
#define DEBUGP printk
#else
#define DEBUGP(format, args...)
#endif

/* FIXME: Time out? --RR */

/*
 *	called from PRE/POSTROUING hook for TCP/1723 packets.
 *	masquerade the outgoing call id, demasq the incoming call id.
 */
static unsigned int pptp_help(	struct ip_conntrack *ct,
			 	struct ip_nat_info *info,
			 	enum ip_conntrack_info ctinfo,
			 	unsigned int hooknum,
			 	struct sk_buff **pskb)
{
	struct iphdr *iph = (*pskb)->nh.iph;
	struct tcphdr *tcph = (void *)iph + iph->ihl*4;
	unsigned int tcplen = (*pskb)->len - iph->ihl * 4;
	struct pptp_pkt_hdr *pptph = (void *)tcph +tcph->doff * 4;
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
	__u16 msg, pcid;
	int dir;
	struct ip_nat_pptp_info *nat = &ct->nat.help.pptp_info;

	/* Only mangle things once: original direction in POST_ROUTING
	   and reply direction on PRE_ROUTING. */
	dir = CTINFO2DIR(ctinfo);
	if (!((hooknum == NF_IP_POST_ROUTING && dir == IP_CT_DIR_ORIGINAL)
	      || (hooknum == NF_IP_PRE_ROUTING && dir == IP_CT_DIR_REPLY))) {
		DEBUGP("nat_pptp: Not touching dir %s at hook %s\n",
		       dir == IP_CT_DIR_ORIGINAL ? "ORIG" : "REPLY",
		       hooknum == NF_IP_POST_ROUTING ? "POSTROUTING"
		       : hooknum == NF_IP_PRE_ROUTING ? "PREROUTING"
		       : hooknum == NF_IP_LOCAL_OUT ? "OUTPUT" : "???");
		return NF_ACCEPT;
	}

	/* if it's not a control message we can't do anything with it */
	if (pptplen < sizeof(*pptph) ||
			ntohs(pptph->packetType) != PPTP_CONTROL_PACKET ||
			ntohl(pptph->magicCookie) != PPTP_MAGIC_COOKIE) {
		if (pptplen != 0 )
			DEBUGP("nat_pptp: not a control pkt\n");
		return NF_ACCEPT;
	}

	if (ctllen < sizeof(*ctlh)) {
		DEBUGP("nat_pptp: ctllen too short\n");
		return NF_ACCEPT;
	}

	pptpReq.rawreq = (void*)ctlh + sizeof(*ctlh);

	LOCK_BH(&ip_pptp_lock);

	/* 
	 *	for original direction (outgoing), masquerade the CID 
	 * 	select the masqueraded id on the call_request cmd 
	 *	use tcp source port as masq call id
	 */
	if(hooknum == NF_IP_POST_ROUTING && dir == IP_CT_DIR_ORIGINAL)
	{
		nat->mcall_id = tcph->source;

		switch (msg = htons(ctlh->messageType)) {
			case PPTP_OUT_CALL_REQUEST:
				/* masq'd client initiating connection to server */
				pptpReq.ocreq->callID = nat->mcall_id;
				break;
	
			case PPTP_IN_CALL_REQUEST:
				/* masq'd client initiating connection to server */
				pptpReq.icreq->callID = nat->mcall_id;
				break;	
	
			case PPTP_CALL_CLEAR_REQUEST:
				/* masq'd client sending to server */
				pptpReq.clrreq->callID = nat->mcall_id;
				break;
	
			case PPTP_CALL_DISCONNECT_NOTIFY:
				/* masq'd client sending to server */
				pptpReq.disc->callID = nat->mcall_id;
				break;
	
			default:
				DEBUGP("UNKNOWN inbound packet\n");
				/* fall through */
	
			case PPTP_SET_LINK_INFO:
			case PPTP_START_SESSION_REQUEST:
			case PPTP_START_SESSION_REPLY:
			case PPTP_STOP_SESSION_REQUEST:
			case PPTP_STOP_SESSION_REPLY:
			case PPTP_ECHO_REQUEST:
			case PPTP_ECHO_REPLY:
				/* no need to alter packet */
				UNLOCK_BH(&ip_pptp_lock);
				return NF_ACCEPT;
		}
		DEBUGP("pptp_nat_help: Masq   original CID=%d as MCID=%d\n", 
			ntohs(nat->call_id), ntohs(nat->mcall_id));
	}
	

	/*
	 *	for reply direction (incoming), demasquerade the peer CID 
	 *	lookup original CID in NAT helper struct
	 */
	if(hooknum == NF_IP_PRE_ROUTING && dir == IP_CT_DIR_REPLY)
	{
		switch (msg = htons(ctlh->messageType)) {
			case PPTP_OUT_CALL_REPLY:
				/* server responding to masq'd client */
				//cid = &pptpReq.ocack->callID;
				pcid = pptpReq.ocack->peersCallID;
				DEBUGP("Changing incoming peer call ID from %d to %d\n", 
					ntohs(pcid), ntohs(nat->call_id));
				pptpReq.ocack->peersCallID = nat->call_id;
				break;
	
			case PPTP_IN_CALL_REPLY:
				/* server responding to masq'd client */
				//cid = &pptpReq.icack->callID;
				pcid = pptpReq.icack->peersCallID;
				pptpReq.icack->peersCallID = nat->call_id;
				break;
	
			case PPTP_WAN_ERROR_NOTIFY:
				/* server notifying masq'd client */
				pptpReq.wanerr->peersCallID = nat->call_id;
				break;
	
			case PPTP_SET_LINK_INFO:
				/* server notifying masq'd client */
				pptpReq.setlink->peersCallID = nat->call_id;
				break;
	
			default:
				DEBUGP("UNKNOWN inbound packet\n");
				/* fall through */
	
			case PPTP_START_SESSION_REQUEST:
			case PPTP_STOP_SESSION_REQUEST:
			case PPTP_ECHO_REQUEST:
				/* no need to alter packet */
				UNLOCK_BH(&ip_pptp_lock);
				return NF_ACCEPT;
		}
		DEBUGP("pptp_nat_help: Demasq original MPCID=%d as PCID=%d\n", 
			ntohs(pcid), ntohs(nat->call_id));
	}
	
	UNLOCK_BH(&ip_pptp_lock);

	/* recompute checksum */
	(*pskb)->csum = csum_partial((char *)pptph, pptplen, 0);
	tcph->check = 0;
	tcph->check = tcp_v4_check(tcph, tcplen, iph->saddr, iph->daddr,
			csum_partial((char *)tcph, tcph->doff*4, (*pskb)->csum));

	return NF_ACCEPT;
}

/*
 *	called from PRE/POSTROUING hook for GRE packets.
 *	demasq the incoming call id
 */
static unsigned int gre_help(	struct ip_conntrack *ct,
			 	struct ip_nat_info *info,
			 	enum ip_conntrack_info ctinfo,
			 	unsigned int hooknum,
			 	struct sk_buff **pskb)
{
	struct iphdr *iph = (*pskb)->nh.iph;
	struct pptp_gre_hdr *greh;
	int dir;
	struct ip_nat_pptp_info *nat;
	u_int32_t newdst, newsrc;

	dir = CTINFO2DIR(ctinfo);

	LOCK_BH(&ip_pptp_lock);
	nat = &ct->nat.help.pptp_info;
	greh = (struct pptp_gre_hdr*) ((char *) iph + sizeof(struct iphdr));

	if(!ct->nat.help.pptp_info.serv_to_client)
	{
		/* 
	 	 *	for original direction (outgoing), do nothing
	 	 */
		if(hooknum == NF_IP_POST_ROUTING && dir == IP_CT_DIR_ORIGINAL) {
			DEBUGP("gre_help: outgoing CID=%d\n", ntohs(greh->call_id));
		}
	
		/*
	 	 *	for reply direction (incoming), demasquerade the call id
	 	 */
		else if(hooknum == NF_IP_PRE_ROUTING && dir == IP_CT_DIR_REPLY) {
			if(greh->call_id != nat->mcall_id)
				DEBUGP("Whoops!  Incoming call ID isn't what we expect "
					"(expected %d, recv %d)!\n", 
					ntohs(nat->mcall_id), ntohs(greh->call_id));

			DEBUGP("gre_help: CT=%lx, MCID=%d, demasq CID=%d\n", 
				(unsigned long) ct,
				ntohs(greh->call_id), ntohs(nat->call_id));
	
			greh->call_id = nat->call_id;
		}
	}
	else
	{
		/*
	 	 *	if the server sent us packets first, orig and reply are reversed...
	 	 *	for orig direction (incoming), demasquerade the call id
	 	 */
		if(hooknum == NF_IP_PRE_ROUTING && dir == IP_CT_DIR_ORIGINAL) {
			DEBUGP("Fixing up packets from server first!\n");
	
			if(greh->call_id != nat->mcall_id)
				DEBUGP("Whoops!  Incoming call ID isn't what we expect "
					"(expected %d, recv %d)!\n", 
					ntohs(nat->mcall_id), ntohs(greh->call_id));

			DEBUGP("gre_help: CT=%lx, MCID=%d, demasq CID=%d\n", 
				(unsigned long) ct,
				ntohs(greh->call_id), ntohs(nat->call_id));
	
			greh->call_id = nat->call_id;
	
			/* We might have to demasquerade the IP address also...
		 	*/
			newdst = ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.ip;
			iph->check = ip_nat_cheat_check(~iph->daddr, newdst, iph->check);
			iph->daddr = newdst;

			DEBUGP("PPTP Mangling %p: DST to %u.%u.%u.%u\n",
				*pskb, NIPQUAD(newdst));

		}
		else if(hooknum == NF_IP_POST_ROUTING && dir == IP_CT_DIR_REPLY) {
			
			/* Masquerade the source IP
			 */
			newsrc = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.ip;
			iph->check = ip_nat_cheat_check(~iph->saddr, newsrc, iph->check);
			iph->saddr = newsrc;

			DEBUGP("PPTP Mangling %p: SRC to %u.%u.%u.%u\n",
				*pskb, NIPQUAD(newsrc));
		}
	}
	UNLOCK_BH(&ip_pptp_lock);

	return NF_ACCEPT;
}

static struct ip_nat_helper pptp = { { NULL, NULL },
				    { { 0, { __constant_htons(1723) } },
				      { 0, { 0 }, IPPROTO_TCP } },
				    { { 0, { 0xFFFF } },
				      { 0, { 0 }, 0xFFFF } },
				    pptp_help, "pptp" };

static struct ip_nat_helper gre =  { { NULL, NULL },
				    { { 0, { 0 } },
				      { 0, { 0 }, IPPROTO_GRE } },
				    { { 0, { 0 } },
				      { 0, { 0 }, 0xFFFF } },
				    gre_help, "gre" };

static int __init init(void)
{
	int ret;

	ret = ip_nat_helper_register(&pptp);
	if (ret == 0) {
		ret = ip_nat_helper_register(&gre);
		if (ret != 0)
			ip_nat_helper_unregister(&pptp);
		else
			DEBUGP("PPTP netfilter NAT helper: registered\n");
	}
	return ret;
}

static void __exit fini(void)
{
	ip_nat_helper_unregister(&gre);
	ip_nat_helper_unregister(&pptp);
}

module_init(init);
module_exit(fini);


