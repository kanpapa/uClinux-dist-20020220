/* Router advertisement
 * Copyright (C) 1999 Kunihiro Ishiguro
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.  
 */

#include <zebra.h>

#include "memory.h"
#include "sockopt.h"
#include "thread.h"
#include "if.h"
#include "log.h"
#include "prefix.h"
#include "linklist.h"
#include "command.h"

#include "zebra/interface.h"
#include "zebra/rtadv.h"
#include "zebra/debug.h"

#if defined (HAVE_IPV6) && defined (RTADV)

/* If RFC2133 definition is used. */
#ifndef IPV6_JOIN_GROUP
#define IPV6_JOIN_GROUP  IPV6_ADD_MEMBERSHIP 
#endif
#ifndef IPV6_LEAVE_GROUP
#define IPV6_LEAVE_GROUP IPV6_DROP_MEMBERSHIP 
#endif

#define ALLNODE   "ff02::1"
#define ALLROUTER "ff02::2"

enum rtadv_event {RTADV_START, RTADV_STOP, RTADV_TIMER, RTADV_READ};

void rtadv_event (enum rtadv_event, int);

int if_join_all_router (int, struct interface *);
int if_leave_all_router (int, struct interface *);

/* Structure which hold status of router advertisement. */
struct rtadv
{
  int sock;

  int adv_if_count;

  struct thread *ra_read;
  struct thread *ra_timer;
};

struct rtadv *rtadv;

struct rtadv *
rtadv_new ()
{
  struct rtadv *new;
  new = XMALLOC (MTYPE_TMP, sizeof (struct rtadv));
  memset (new, 0, sizeof (struct rtadv));
  return new;
}

void
rtadv_free (struct rtadv *rtadv)
{
  XFREE (MTYPE_TMP, rtadv);
}

int
rtadv_recv_packet (int sock, u_char *buf, int buflen,
		   struct sockaddr_in6 *from, unsigned int *ifindex,
		   int *hoplimit)
{
  int ret;
  struct msghdr msg;
  struct iovec iov;
  struct cmsghdr  *cmsgptr;
  struct in6_addr dst;

  char adata[1024];

  /* Fill in message and iovec. */
  msg.msg_name = (void *) from;
  msg.msg_namelen = sizeof (struct sockaddr_in6);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = (void *) adata;
  msg.msg_controllen = sizeof adata;
  iov.iov_base = buf;
  iov.iov_len = buflen;

  /* If recvmsg fail return minus value. */
  ret = recvmsg (sock, &msg, 0);
  if (ret < 0)
    return ret;

  for (cmsgptr = CMSG_FIRSTHDR(&msg); cmsgptr != NULL;
       cmsgptr = CMSG_NXTHDR(&msg, cmsgptr)) 
    {
      /* I want interface index which this packet comes from. */
      if (cmsgptr->cmsg_level == IPPROTO_IPV6 &&
	  cmsgptr->cmsg_type == IPV6_PKTINFO) 
	{
	  struct in6_pktinfo *ptr;
	  
	  ptr = (struct in6_pktinfo *) CMSG_DATA (cmsgptr);
	  *ifindex = ptr->ipi6_ifindex;
	  memcpy(&dst, &ptr->ipi6_addr, sizeof(ptr->ipi6_addr));
        }

      /* Incoming packet's hop limit. */
      if (cmsgptr->cmsg_level == IPPROTO_IPV6 &&
	  cmsgptr->cmsg_type == IPV6_HOPLIMIT)
	*hoplimit = *((int *) CMSG_DATA (cmsgptr));
    }
  return ret;
}

#define RTADV_MSG_SIZE 4096

/* Send router advertisement packet. */
void
rtadv_send_packet (int sock, struct interface *ifp)
{
  struct msghdr msg;
  struct iovec iov;
  struct cmsghdr  *cmsgptr;
  struct in6_pktinfo *pkt;
  struct sockaddr_in6 addr;
  char adata [sizeof (struct cmsghdr) + sizeof (struct in6_pktinfo)];
  unsigned char buf[RTADV_MSG_SIZE];
  struct nd_router_advert *rtadv;
  int ret;
  int len = 0;
  struct zebra_if *zif;
  u_char all_nodes_addr[] = {0xff,0x02,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
  listnode node;

  /* Logging of packet. */
  if (IS_ZEBRA_DEBUG_PACKET)
    zlog_info ("Router advertisement send to %s", ifp->name);

  /* Fill in sockaddr_in6. */
  memset (&addr, 0, sizeof (struct sockaddr_in6));
  addr.sin6_family = AF_INET6;
#ifdef SIN6_LEN
  addr.sin6_len = sizeof (struct sockaddr_in6);
#endif /* SIN6_LEN */
  addr.sin6_port = htons (IPPROTO_ICMPV6);
  memcpy (&addr.sin6_addr, all_nodes_addr, sizeof (struct in6_addr));

  /* Fetch interface information. */
  zif = ifp->info;

  /* Make router advertisement message. */
  rtadv = (struct nd_router_advert *) buf;

  rtadv->nd_ra_type = ND_ROUTER_ADVERT;
  rtadv->nd_ra_code = 0;
  rtadv->nd_ra_cksum = 0;

  rtadv->nd_ra_curhoplimit = 64;
  rtadv->nd_ra_flags_reserved = 0;
  rtadv->nd_ra_router_lifetime = htons (600 * 3);
  rtadv->nd_ra_reachable = htonl (0);
  rtadv->nd_ra_retransmit = htonl (0);

  len = sizeof (struct nd_router_advert);

  /* Fill in prefix. */
  for (node = listhead (zif->rtadv.AdvPrefixList); node; node = nextnode (node))
    {
      struct nd_opt_prefix_info *pinfo;
      struct rtadv_prefix *rprefix;

      rprefix = getdata (node);

      pinfo = (struct nd_opt_prefix_info *) (buf + len);

      pinfo->nd_opt_pi_type = ND_OPT_PREFIX_INFORMATION;
      pinfo->nd_opt_pi_len = 4;
      pinfo->nd_opt_pi_prefix_len = 64;

      pinfo->nd_opt_pi_flags_reserved = ND_OPT_PI_FLAG_ONLINK;
      /* (prefix->AdvOnLinkFlag) ? ND_OPT_PI_FLAG_ONLINK : 0; */
      pinfo->nd_opt_pi_flags_reserved |= ND_OPT_PI_FLAG_AUTO;
      /* (prefix->AdvAutonomousFlag) ? ND_OPT_PI_FLAG_AUTO : 0;*/

      pinfo->nd_opt_pi_valid_time	= htonl ((~(u_int32_t)0));
      pinfo->nd_opt_pi_preferred_time = htonl (604800);
      pinfo->nd_opt_pi_reserved2= 0;

      memcpy (&pinfo->nd_opt_pi_prefix, &rprefix->prefix.u.prefix6,
	      sizeof (struct in6_addr));

#ifdef DEBUG
      {
	u_char buf[INET6_ADDRSTRLEN];

	zlog_info ("DEBUG %s", inet_ntop (AF_INET6, &pinfo->nd_opt_pi_prefix, buf, INET6_ADDRSTRLEN));

      }
#endif /* DEBUG */

      len += sizeof (struct nd_opt_prefix_info);
    }

  /* Hardware address. */
#ifdef HAVE_SOCKADDR_DL
#else
  if (ifp->hw_addr_len != 0)
    {
      int i;

      buf[len++] = ND_OPT_SOURCE_LINKADDR;
      buf[len++] = (((ifp->hw_addr_len * 8) + 16 + 63) >> 6);

      i = (ifp->hw_addr_len * 8 + 7) >> 3;
      memcpy (buf + len, ifp->hw_addr, i);
      len += i;
    }
#endif /* HAVE_SOCKADDR_DL */

  msg.msg_name = (void *) &addr;
  msg.msg_namelen = sizeof (struct sockaddr_in6);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = (void *) adata;
  msg.msg_controllen = sizeof adata;
  iov.iov_base = buf;
  iov.iov_len = len;

  cmsgptr = (struct cmsghdr *)adata;
  cmsgptr->cmsg_len = sizeof adata;
  cmsgptr->cmsg_level = IPPROTO_IPV6;
  cmsgptr->cmsg_type = IPV6_PKTINFO;
  pkt = (struct in6_pktinfo *) CMSG_DATA (cmsgptr);
  memset (&pkt->ipi6_addr, 0, sizeof (struct in6_addr));
  pkt->ipi6_ifindex = ifp->ifindex;

  ret = sendmsg (sock, &msg, 0);
  if (ret <0)
    perror ("sendmsg");
}

int
rtadv_timer (struct thread *thread)
{
  listnode node;
  struct interface *ifp;
  struct zebra_if *zif;

  rtadv->ra_timer = NULL;
  rtadv_event (RTADV_TIMER, 30);

  for (node = listhead (iflist); node; nextnode (node))
    {
      ifp = getdata (node);

      if (if_is_loopback (ifp))
	continue;

      zif = ifp->info;

      if (zif->rtadv.AdvSendAdvertisements)
	rtadv_send_packet (rtadv->sock, ifp);
    }
  return 0;
}

void
rtadv_process_solicit (struct interface *ifp)
{
  zlog_info ("Router solicitation received on %s", ifp->name);

  ;
}

void
rtadv_process_advert ()
{
  zlog_info ("Router advertisement received");
}

void
rtadv_process_packet (u_char *buf, int len, unsigned int ifindex, int hoplimit)
{
  struct icmp6_hdr *icmph;
  struct interface *ifp;
  struct zebra_if *zif;

  /* ICMP message length check. */
  if (len < sizeof (struct icmp6_hdr))
    {
      zlog_warn ("Invalid ICMPV6 packet length: %d", len);
      return;
    }

  icmph = (struct icmp6_hdr *) buf;

  /* ICMP message type check. */
  if (icmph->icmp6_type != ND_ROUTER_SOLICIT &&
      icmph->icmp6_type != ND_ROUTER_ADVERT)
    {
      zlog_warn ("Unwanted ICMPV6 message type: %d", icmph->icmp6_type);
      return;
    }

  /* Hoplimit check. */
  if (hoplimit != 255)
    {
      zlog_warn ("Invalid hoplimit %d for router advertisement ICMP packet",
		 hoplimit);
      return;
    }

  /* Interface search. */
  ifp = if_lookup_by_index (ifindex);
  if (ifp == NULL)
    {
      zlog_warn ("Unknown interface index: %d", ifindex);
      return;
    }

  /* Check interface configuration. */
  zif = ifp->info;
  if (! zif->rtadv.AdvSendAdvertisements)
    return;

  /* Check ICMP message type. */
  if (icmph->icmp6_type == ND_ROUTER_SOLICIT)
    rtadv_process_solicit (ifp);
  else if (icmph->icmp6_type == ND_ROUTER_ADVERT)
    rtadv_process_advert ();

  return;
}

int
rtadv_read (struct thread *thread)
{
  int sock;
  int len;
  u_char buf[RTADV_MSG_SIZE];
  struct sockaddr_in6 from;
  unsigned int ifindex;
  int hoplimit = -1;

  sock = THREAD_FD (thread);
  rtadv->ra_read = NULL;

  /* Register myself. */
  rtadv_event (RTADV_READ, sock);

  len = rtadv_recv_packet (sock, buf, BUFSIZ, &from, &ifindex, &hoplimit);

  if (len < 0) 
    {
      zlog_warn ("router solicitation recv failed: %s.", strerror (errno));
      return len;
    }

  rtadv_process_packet (buf, len, ifindex, hoplimit);

  return 0;
}

int
rtadv_make_socket ()
{
  int sock;
  int ret;
  struct icmp6_filter filter;

  if (!rtadv)
    return -1;

  sock = socket (AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
  if (sock < 0)
    {
      zlog_warn ("can't create router advertisement socket: %s", 
		strerror (errno));
      return -1;
    }

  ret = setsockopt_ipv6_pktinfo (sock, 1);
  if (ret < 0)
    return ret;
  ret = setsockopt_ipv6_checksum (sock, 2);
  if (ret < 0)
    return ret;
  ret = setsockopt_ipv6_unicast_hops (sock, 255);
  if (ret < 0)
    return ret;
  ret = setsockopt_ipv6_multicast_hops (sock, 255);
  if (ret < 0)
    return ret;
  ret = setsockopt_ipv6_hoplimit (sock, 1);
  if (ret < 0)
    return ret;

  ICMP6_FILTER_SETBLOCKALL(&filter);
  ICMP6_FILTER_SETPASS (ND_ROUTER_SOLICIT, &filter);
  ICMP6_FILTER_SETPASS (ND_ROUTER_ADVERT, &filter);

  ret = setsockopt (sock, IPPROTO_ICMPV6, ICMP6_FILTER, &filter,
		    sizeof (struct icmp6_filter));
  if (ret < 0)
    {
      zlog_info ("ICMP6_FILTER set fail: %s", strerror (errno));
      return ret;
    }

  return sock;
}

struct rtadv_prefix *
rtadv_prefix_new ()
{
  struct rtadv_prefix *new;

  new = XMALLOC (MTYPE_RTADV_PREFIX, sizeof (struct rtadv_prefix));
  memset (new, 0, sizeof (struct rtadv_prefix));

  return new;
}

void
rtadv_prefix_free (struct rtadv_prefix *rtadv_prefix)
{
  XFREE (MTYPE_RTADV_PREFIX, rtadv_prefix);
}

struct rtadv_prefix *
rtadv_prefix_lookup (list rplist, struct prefix *p)
{
  listnode node;
  struct rtadv_prefix *rprefix;

  for (node = listhead (rplist); node; node = nextnode (node))
    {
      rprefix = getdata (node);
      if (prefix_same (&rprefix->prefix, p))
	return rprefix;
    }
  return NULL;
}

struct rtadv_prefix *
rtadv_prefix_get (list rplist, struct prefix *p)
{
  struct rtadv_prefix *rprefix;
  
  rprefix = rtadv_prefix_lookup (rplist, p);
  if (rprefix)
    return rprefix;

  rprefix = rtadv_prefix_new ();
  memcpy (&rprefix->prefix, p, sizeof (struct prefix));
  list_add_node (rplist, rprefix);
  
  return rprefix;
}

void
rtadv_prefix_set (struct zebra_if *zif, struct prefix *p)
{
  struct rtadv_prefix *rprefix;
  
  rprefix = rtadv_prefix_get (zif->rtadv.AdvPrefixList, p);

  /* Set parameters. */
  ;
}

DEFUN (ipv6_nd_send_ra,
       ipv6_nd_send_ra_cmd,
       "ipv6 nd send-ra",
       IP_STR
       "Neighbor discovery\n"
       "Send router advertisement\n")
{
  struct interface *ifp;
  struct zebra_if *zif;

  ifp = vty->index;
  zif = ifp->info;

  if (! zif->rtadv.AdvSendAdvertisements)
    {
      zif->rtadv.AdvSendAdvertisements = 1;
      rtadv->adv_if_count++;

      if_join_all_router (rtadv->sock, ifp);

      if (rtadv->adv_if_count)
	rtadv_event (RTADV_START, 0);
    }

  return CMD_SUCCESS;
}

DEFUN (no_ipv6_nd_send_ra,
       no_ipv6_nd_send_ra_cmd,
       "no ipv6 nd send-ra",
       NO_STR
       IP_STR
       "Neighbor discovery\n"
       "Send router advertisement\n")
{
  struct interface *ifp;
  struct zebra_if *zif;

  ifp = vty->index;
  zif = ifp->info;

  if (zif->rtadv.AdvSendAdvertisements)
    {
      zif->rtadv.AdvSendAdvertisements = 0;
      rtadv->adv_if_count--;

      if_leave_all_router (rtadv->sock, ifp);

      if (rtadv->adv_if_count == 0)
	rtadv_event (RTADV_STOP, 0);
    }

  return CMD_SUCCESS;
}

DEFUN (ipv6_nd_prefix_advertisement,
       ipv6_nd_prefix_advertisement_cmd,
       "ipv6 nd prefix-advertisement IPV6PREFIX",
       IP_STR
       "Neighbor discovery\n"
       "Router advertisement\n"
       "IPv6 prefix\n")
{
  int ret;
  struct interface *ifp;
  struct zebra_if *zebra_if;
  struct prefix p;

  ifp = (struct interface *) vty->index;
  zebra_if = ifp->info;

  ret = str2prefix_ipv6 (argv[0], (struct prefix_ipv6 *) &p);
  if (!ret)
    {
      vty_out (vty, "Malformed IPv6 prefix%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  rtadv_prefix_set (zebra_if, &p);

  return CMD_SUCCESS;
}

/* Write configuration about router advertisement. */
void
rtadv_config_write (struct vty *vty, struct interface *ifp)
{
  struct zebra_if *zif;
  listnode node;
  struct rtadv_prefix *rprefix;
  u_char buf[INET6_ADDRSTRLEN];

  zif = ifp->info;

  if (zif->rtadv.AdvSendAdvertisements)
    vty_out (vty, " ipv6 nd send-ra%s", VTY_NEWLINE);

  for (node = listhead(zif->rtadv.AdvPrefixList); node; node = nextnode (node))
    {
      rprefix = getdata (node);
      vty_out (vty, " ipv6 nd prefix-advertisement %s/%d%s",
	       inet_ntop (AF_INET6, &rprefix->prefix.u.prefix6, 
			  buf, INET6_ADDRSTRLEN),
	       rprefix->prefix.prefixlen,
	       VTY_NEWLINE);
    }
}

extern struct thread_master *master;

void
rtadv_event (enum rtadv_event event, int val)
{
  switch (event)
    {
    case RTADV_START:
      thread_add_event (master, rtadv_timer, NULL, 0);
      break;
    case RTADV_STOP:
      if (rtadv->ra_timer)
	{
	  thread_cancel (rtadv->ra_timer);
	  rtadv->ra_timer = NULL;
	}
      break;
    case RTADV_TIMER:
      if (! rtadv->ra_timer)
	rtadv->ra_timer = thread_add_timer (master, rtadv_timer, NULL, val);
      break;
    case RTADV_READ:
      rtadv->ra_read = thread_add_read (master, rtadv_read, NULL, val);
      break;
    default:
      break;
    }
  return;
}

void
rtadv_init ()
{
  install_element (INTERFACE_NODE, &ipv6_nd_send_ra_cmd);
  install_element (INTERFACE_NODE, &no_ipv6_nd_send_ra_cmd);
  install_element (INTERFACE_NODE, &ipv6_nd_prefix_advertisement_cmd);

  rtadv = rtadv_new ();
  rtadv->sock = rtadv_make_socket ();
  if (rtadv->sock < 0)
    return;

  /* This should be rtadv_start (). */
  rtadv_event (RTADV_READ, rtadv->sock);
}

int
if_join_all_router (int sock, struct interface *ifp)
{
  int ret;

  struct ipv6_mreq mreq;

  memset (&mreq, 0, sizeof (struct ipv6_mreq));
  inet_pton (AF_INET6, ALLROUTER, &mreq.ipv6mr_multiaddr);
  mreq.ipv6mr_interface = ifp->ifindex;

  ret = setsockopt (sock, IPPROTO_IPV6, IPV6_JOIN_GROUP, 
		    (char *) &mreq, sizeof mreq);
  if (ret < 0)
    zlog_warn ("can't setsockopt IPV6_JOIN_GROUP: %s", strerror (errno));

  zlog_info ("rtadv: %s join to all-routers multicast group", ifp->name);

  return 0;
}

int
if_leave_all_router (int sock, struct interface *ifp)
{
  int ret;

  struct ipv6_mreq mreq;

  memset (&mreq, 0, sizeof (struct ipv6_mreq));
  inet_pton (AF_INET6, ALLROUTER, &mreq.ipv6mr_multiaddr);
  mreq.ipv6mr_interface = ifp->ifindex;

  ret = setsockopt (sock, IPPROTO_IPV6, IPV6_LEAVE_GROUP, 
		    (char *) &mreq, sizeof mreq);
  if (ret < 0)
    zlog_warn ("can't setsockopt IPV6_LEAVE_GROUP: %s", strerror (errno));

  zlog_info ("rtadv: %s leave from all-routers multicast group", ifp->name);

  return 0;
}

#else
void
rtadv_init ()
{
  /* Empty.*/;
}
#endif /* RTADV && HAVE_IPV6 */
