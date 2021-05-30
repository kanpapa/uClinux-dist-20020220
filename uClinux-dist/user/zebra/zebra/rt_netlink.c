/* Kernel routing table updates using netlink over GNU/Linux system.
 * Copyright (C) 1997, 98, 99 Kunihiro Ishiguro
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

/* Hack for GNU libc version 2. */
#ifndef MSG_TRUNC
#define MSG_TRUNC      0x20
#endif /* MSG_TRUNC */

#include "linklist.h"
#include "if.h"
#include "log.h"
#include "prefix.h"
#include "connected.h"
#include "rib.h"

#include "zebra/zserv.h"
#include "zebra/redistribute.h"
#include "zebra/interface.h"

/* #define DEBUG */ 

/* Socket interface to kernel */
struct 
{
  int sock;
  int seq;
  struct sockaddr_nl snl;
} netlink = { -1, 0, {0} };

extern int rtm_table_default;

/* Make socket for Linux netlink interface. */
int
netlink_socket ()
{
  int ret;
  struct sockaddr_nl snl;

  netlink.sock = socket (AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
  if (netlink.sock < 0)
    {
      zlog (NULL, LOG_ERR, "Can't open netlink socket: %s", strerror (errno));
      return -1;
    }

  ret = fcntl (netlink.sock, F_SETFL, O_NONBLOCK);
  if (ret < 0)
    {
      zlog (NULL, LOG_ERR, "Can't set netlink socket flags: %s",
           strerror (errno));
      return -1;
    }
  
  bzero (&snl, sizeof snl);
  snl.nl_family = AF_NETLINK;
  snl.nl_groups = 0;

  snl.nl_groups = RTMGRP_LINK|RTMGRP_IPV4_ROUTE|RTMGRP_IPV4_IFADDR;
#ifdef HAVE_IPV6
  snl.nl_groups |= RTMGRP_IPV6_ROUTE|RTMGRP_IPV6_IFADDR;
#endif /* HAVE_IPV6 */
  
  /* Bind the socket to the netlink structure for anything. */
  ret = bind (netlink.sock, (struct sockaddr *) &snl, sizeof snl);
  if (ret < 0)
    {
      zlog (NULL, LOG_ERR, "Can't bind netlink socket to group 0: %s", 
	    strerror (errno));
      close (netlink.sock);
      netlink.sock = -1;
      return -1;
    }
  return ret;
}

/* Get type specified information from netlink. */
int
netlink_request (int family, int type)
{
  int ret;
  struct sockaddr_nl snl;

  struct
  {
    struct nlmsghdr nlh;
    struct rtgenmsg g;
  } req;


  /* Check netlink socket. */
  if (netlink.sock < 0)
    {
      zlog (NULL, LOG_ERR, "netlink socket isn't active.");
      return -1;
    }

  bzero (&snl, sizeof snl);
  snl.nl_family = AF_NETLINK;

  req.nlh.nlmsg_len = sizeof req;
  req.nlh.nlmsg_type = type;
  req.nlh.nlmsg_flags = NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST;
  req.nlh.nlmsg_pid = 0;
  req.nlh.nlmsg_seq = ++netlink.seq;
  req.g.rtgen_family = family;
  
  ret = sendto (netlink.sock, (void*) &req, sizeof req, 0, 
		(struct sockaddr*) &snl, sizeof snl);
  if (ret < 0)
    {
      zlog (NULL, LOG_ERR, "netlink sendto failed: %s", strerror (errno));
      return -1;
    }
  return 0;
}

/* Recieve message from netlink interface and pass those information
   to the given function. */
int
netlink_parse_info (int (*filter) (struct sockaddr_nl *, struct nlmsghdr *))
{
  int status;
  int ret;
  int seq = 0;

#ifdef DEBUG
  printf ("netlink_parse_info() called\n");
#endif /* DEBUG */

  while (1)
    {
      char buf[4096];
      struct iovec iov = { buf, sizeof buf };
      struct sockaddr_nl snl;
      struct msghdr msg = { (void*)&snl, sizeof snl, &iov, 1, NULL, 0, 0};
      struct nlmsghdr *h;

      status = recvmsg (netlink.sock, &msg, 0);

      if (status < 0)
	{
	  if (errno == EINTR)
	    continue;
	  if (errno == EWOULDBLOCK)
            return 0;
	  zlog (NULL, LOG_ERR, "netlink recvmsg overrun");
	  continue;
	}

      if (status == 0)
	{
	  zlog (NULL, LOG_ERR, "netlink EOF");
	  return -1;
	}

      if (msg.msg_namelen != sizeof snl)
	{
	  zlog (NULL, LOG_ERR, "netlink sender address length error: length %d",
	       msg.msg_namelen);
	  return -1;
	}

      for (h = (struct nlmsghdr *) buf; NLMSG_OK (h, status); 
	   h = NLMSG_NEXT (h, status))
	{
	  /* Message sequence. */
	  seq = h->nlmsg_seq;
	  
#if 0
	  /* pid and seq check. */
	  if (seq && seq != netlink.seq)
	    continue;
#endif

	  /* Finish of reading. */
	  if (h->nlmsg_type == NLMSG_DONE)
	    return 0;

	  /* Error handling. */
	  if (h->nlmsg_type == NLMSG_ERROR)
	    {
	      struct nlmsgerr *err = (struct nlmsgerr *) NLMSG_DATA (h);
	      if (h->nlmsg_len < NLMSG_LENGTH (sizeof (struct nlmsgerr)))
		zlog (NULL, LOG_ERR, "netlink error: message truncated");
	      else
		zlog (NULL, LOG_ERR, "netlink error: %s", 
		      strerror (-err->error));
	      return -1;
	    }

	  /* OK we got netlink message. */
	  ret = (*filter) (&snl, h);
	  if (ret < 0)
	    {
	      zlog (NULL, LOG_ERR, "netlink filter function error");
	      return ret;
	    }
	}

      /* After error care. */
      if (msg.msg_flags & MSG_TRUNC)
	{
	  zlog (NULL, LOG_ERR, "netlink error: message truncated");
	  continue;
	}
      if (status)
	{
	  zlog (NULL, LOG_ERR, "netlink error: data remnant size %d", status);
	  return -1;
	}
      /* This message will be from kernel but reply to user request. */
      if (seq == 0)
	return 0;
    }

  return 0;
}

/* Utility function for parse rtattr. */
static void
netlink_parse_rtattr (struct rtattr **tb, int max, struct rtattr *rta, int len)
{
  while (RTA_OK(rta, len)) 
    {
      if (rta->rta_type <= max)
	tb[rta->rta_type] = rta;
      rta = RTA_NEXT(rta,len);
    }
}

/* Parse netlink interface information. */
int
netlink_interface (struct sockaddr_nl *snl, struct nlmsghdr *h)
{
  int len;
  struct ifinfomsg *ifi;
  struct rtattr *tb[IFLA_MAX + 1];
  struct interface *ifp;
  char *name;
  int i;

  ifi = NLMSG_DATA (h);

  if (h->nlmsg_type != RTM_NEWLINK)
    return 0;

  len = h->nlmsg_len - NLMSG_LENGTH (sizeof (struct ifinfomsg));
  if (len < 0)
    return -1;

  /* Looking up interface name. */
  bzero (tb, sizeof tb);
  netlink_parse_rtattr (tb, IFLA_MAX, IFLA_RTA (ifi), len);
  if (tb[IFLA_IFNAME] == NULL)
    return -1;
  name = (char *)RTA_DATA(tb[IFLA_IFNAME]);

  /* Add interface. */
  ifp = if_get_by_name (name);
  
  ifp->ifindex = ifi->ifi_index;
  ifp->flags = ifi->ifi_flags & 0x0000fffff;
  ifp->mtu = *(int *)RTA_DATA (tb[IFLA_MTU]);
  ifp->metric = 1;

  /* Hardware type and address. */
  ifp->hw_type = ifi->ifi_type;
  if (tb[IFLA_ADDRESS])
    {
      int hw_addr_len;

      hw_addr_len = RTA_PAYLOAD(tb[IFLA_ADDRESS]);

      if (hw_addr_len > INTERFACE_HWADDR_MAX)
	zlog_warn ("Hardware address is too large: %d", hw_addr_len);
      else
	{      
	  ifp->hw_addr_len = hw_addr_len;
	  memcpy (ifp->hw_addr, RTA_DATA(tb[IFLA_ADDRESS]), hw_addr_len);

	  for (i = 0; i < hw_addr_len; i++)
	    if (ifp->hw_addr[i] != 0)
	      break;

	  if (i == hw_addr_len)
	    ifp->hw_addr_len = 0;
	  else
	    ifp->hw_addr_len = hw_addr_len;
	}
    }

  /* If verbose mode log interface index. */
  /* zlog_info ("interface %s index %d.\n", ifp->name, ifp->ifindex); */

  return 0;
}

/* Lookup interface IPv4/IPv6 address. */
int
netlink_interface_addr (struct sockaddr_nl *snl, struct nlmsghdr *h)
{
  int len;
  struct ifaddrmsg *ifa;
  struct rtattr *tb [IFA_MAX + 1];
  struct interface *ifp;
  void *addr = NULL;
  void *broad = NULL;

  ifa = NLMSG_DATA (h);

  if (ifa->ifa_family != AF_INET 
#ifdef HAVE_IPV6
      && ifa->ifa_family != AF_INET6
#endif /* HAVE_IPV6 */
      )
    return 0;

#ifdef DEBUG
  printf ("%s\n", ifa->ifa_family == AF_INET ? "ipv4" : "ipv6");
#endif /* DEBUG */

  if (h->nlmsg_type != RTM_NEWADDR && h->nlmsg_type != RTM_DELADDR)
    return 0;

  len = h->nlmsg_len - NLMSG_LENGTH(sizeof (struct ifaddrmsg));
  if (len < 0)
    return -1;

  bzero (tb, sizeof tb);
  netlink_parse_rtattr (tb, IFA_MAX, IFA_RTA (ifa), len);

  ifp = if_lookup_by_index (ifa->ifa_index);
  if (ifp == NULL)
    {
      zlog (NULL, LOG_INFO,
	    "netlink_interface_addr can't find interface by index %d",
	    ifa->ifa_index);
      return -1;
    }

  if (tb[IFA_ADDRESS] == NULL)
    tb[IFA_ADDRESS] = tb[IFA_LOCAL];

  if (ifp->flags & IFF_POINTOPOINT)
    {
      if (tb[IFA_LOCAL])
	{
	  addr = RTA_DATA (tb[IFA_LOCAL]);
	  if (tb[IFA_ADDRESS])
	    broad = RTA_DATA (tb[IFA_ADDRESS]);
	  else
	    broad = NULL;
	}
      else
	{
	  if (tb[IFA_ADDRESS])
	    addr = RTA_DATA (tb[IFA_ADDRESS]);
	  else
	    addr = NULL;
	}
    }
  else
    {
      if (tb[IFA_ADDRESS])
	addr = RTA_DATA (tb[IFA_ADDRESS]);
      else
	addr = NULL;

      if (tb[IFA_BROADCAST])
	broad = RTA_DATA(tb[IFA_BROADCAST]);
      else
	broad = NULL;
    }

  /* Address label treatment. */
#if 0
  if (tb[IFA_LABEL])
    printf ("This address is for label %s\n", (char *) RTA_DATA (tb[IFA_LABEL]));
#endif /* 0 */

  /* Register interface address to the interface. */
  if (ifa->ifa_family == AF_INET)
    {
      if (h->nlmsg_type == RTM_NEWADDR)
	connected_add_ipv4 (ifp, 
			    (struct in_addr *) addr, ifa->ifa_prefixlen, 
			    (struct in_addr *) broad);
      else
	connected_delete_ipv4 (ifp, 
			       (struct in_addr *) addr, ifa->ifa_prefixlen, 
			       (struct in_addr *) broad);
    }
#ifdef HAVE_IPV6
  if (ifa->ifa_family == AF_INET6)
    {
      if (h->nlmsg_type == RTM_NEWADDR)
	connected_add_ipv6 (ifp, 
			    (struct in6_addr *) addr, ifa->ifa_prefixlen, 
			    (struct in6_addr *) broad);
      else
	connected_delete_ipv6 (ifp, 
			       (struct in6_addr *) addr, ifa->ifa_prefixlen, 
			       (struct in6_addr *) broad);
    }
#endif /* HAVE_IPV6*/

  return 0;
}

/* Looking up routing table by netlink interface. */
int
netlink_routing_table (struct sockaddr_nl *snl, struct nlmsghdr *h)
{
  int len;
  struct rtmsg *rtm;
  struct rtattr *tb [RTA_MAX + 1];
  u_char flags = 0;
  
  char anyaddr[16] = {0};

  int index;
  int table;
  void *dest;
  void *gate;

  rtm = NLMSG_DATA (h);

  if (h->nlmsg_type != RTM_NEWROUTE)
    return 0;
  if (rtm->rtm_type != RTN_UNICAST)
    return 0;

  table = rtm->rtm_table;
#if 0		/* we weed them out later in rib_weed_tables () */
  if (table != RT_TABLE_MAIN && table != rtm_table_default)
    return 0;
#endif

  len = h->nlmsg_len - NLMSG_LENGTH(sizeof (struct rtmsg));
  if (len < 0)
    return -1;

  bzero (tb, sizeof tb);
  netlink_parse_rtattr (tb, RTA_MAX, RTM_RTA (rtm), len);

  if (rtm->rtm_flags & RTM_F_CLONED)
    return 0;
  if (rtm->rtm_protocol == RTPROT_REDIRECT)
    return 0;
  if (rtm->rtm_protocol == RTPROT_KERNEL)
    return 0;
  if (rtm->rtm_src_len != 0)
    return 0;

  /* Route which inserted by Zebra. */
  if (rtm->rtm_protocol == RTPROT_ZEBRA)
    flags |= ZEBRA_FLAG_SELFROUTE;
  
  index = 0;
  dest = NULL;
  gate = NULL;

  if (tb[RTA_OIF])
    index = *(int *) RTA_DATA (tb[RTA_OIF]);

  if (tb[RTA_DST])
    dest = RTA_DATA (tb[RTA_DST]);
  else
    dest = anyaddr;

  if (tb[RTA_GATEWAY])
    gate = RTA_DATA (tb[RTA_GATEWAY]);
  else
    return 0;

  if (rtm->rtm_family == AF_INET)
    {
      struct prefix_ipv4 p;
      p.family = AF_INET;
      memcpy (&p.prefix, dest, 4);
      p.prefixlen = rtm->rtm_dst_len;
      rib_add_ipv4 (ZEBRA_ROUTE_KERNEL, flags, &p, gate, index, table);
    }
#ifdef HAVE_IPV6
  if (rtm->rtm_family == AF_INET6)
    {
      struct prefix_ipv6 p;
      p.family = AF_INET6;
      memcpy (&p.prefix, dest, 16);
      p.prefixlen = rtm->rtm_dst_len;
      rib_add_ipv6 (ZEBRA_ROUTE_KERNEL, flags, &p, gate, index, table);
    }
#endif /* HAVE_IPV6 */

  return 0;
}

struct message rtproto_str [] = 
{
  {RTPROT_REDIRECT, "redirect"},
  {RTPROT_KERNEL,   "kernel"},
  {RTPROT_BOOT,     "boot"},
  {RTPROT_STATIC,   "static"},
  {RTPROT_GATED,    "GateD"},
  {RTPROT_RA,       "router advertisement"},
  {RTPROT_MRT,      "MRT"},
  {RTPROT_ZEBRA,    "Zebra"},
#ifdef RTPROT_BIRD
  {RTPROT_BIRD,     "BIRD"},
#endif /* RTPROT_BIRD */
  {0,               NULL}
};

/* Routing information change from the kernel. */
int
netlink_route_change (struct sockaddr_nl *snl, struct nlmsghdr *h)
{
#ifdef DEBUG
  char buf[BUFSIZ];
#endif /* DEBUG */
  int len;
  struct rtmsg *rtm;
  struct rtattr *tb [RTA_MAX + 1];
  
  char anyaddr[16] = {0};

  int index;
  int table;
  void *dest;
  void *gate;

  rtm = NLMSG_DATA (h);

  if (! (h->nlmsg_type == RTM_NEWROUTE || h->nlmsg_type == RTM_DELROUTE))
    {
      /* If this is not route add/delete message print warning. */
      zlog_warn ("Kernel message: %d\n", h->nlmsg_type);
      return 0;
    }

  /* Connected route. */
#ifdef DEBUG
  printf ("%s ", rtm->rtm_family == AF_INET ? "ipv4" : "ipv6");
  printf ("proto %s ", lookup (rtproto_str, rtm->rtm_protocol));
#endif /* DEBUG */

#ifdef DEBUG
  printf ("%s", rtm->rtm_type == RTN_UNICAST ? "unicast " : "multicast\n");
#endif /* DEBUG */

  if (rtm->rtm_type != RTN_UNICAST)
    {
      return 0;
    }

  table = rtm->rtm_table;
  if (table != RT_TABLE_MAIN && table != rtm_table_default)
    {
#ifdef DEBUG
      printf ("non main\n");
#endif
      return 0;
    }

  len = h->nlmsg_len - NLMSG_LENGTH(sizeof (struct rtmsg));
  if (len < 0)
    return -1;

  bzero (tb, sizeof tb);
  netlink_parse_rtattr (tb, RTA_MAX, RTM_RTA (rtm), len);

  if (rtm->rtm_flags & RTM_F_CLONED)
    {
      return 0;
    }

#ifndef DEBUG
  if (rtm->rtm_protocol == RTPROT_REDIRECT)
    {
      return 0;
    }
  if (rtm->rtm_protocol == RTPROT_KERNEL)
    {
      return 0;
    }
  if (rtm->rtm_protocol == RTPROT_ZEBRA)
    {
      return 0;
    }
#endif /* DEBUG */

  if (rtm->rtm_src_len != 0)
    {
      zlog_warn ("no src len");
      return 0;
    }
  
  index = 0;
  dest = NULL;
  gate = NULL;

  if (tb[RTA_OIF])
    index = *(int *) RTA_DATA (tb[RTA_OIF]);

  if (tb[RTA_DST])
    dest = RTA_DATA (tb[RTA_DST]);
  else
    dest = anyaddr;

  if (tb[RTA_GATEWAY])
    gate = RTA_DATA (tb[RTA_GATEWAY]);
  else
    {
#ifdef DEBUG
      if (rtm->rtm_family == AF_INET)
	{
	  struct prefix_ipv4 p;
	  p.family = AF_INET;
	  memcpy (&p.prefix, dest, 4);
	  p.prefixlen = rtm->rtm_dst_len;
	  printf ("Network %s\n", inet_ntoa (p.prefix));
#if 0
	  if (h->nlmsg_type == RTM_NEWROUTE)
	    rib_add_ipv4 (ZEBRA_ROUTE_KERNEL, 0, &p, gate, index, table);
	  else
	    rib_delete_ipv4 (ZEBRA_ROUTE_KERNEL, 0, &p, gate, index, table);
#endif /* 0 */

	}
#ifdef HAVE_IPV6
      if (rtm->rtm_family == AF_INET6)
	{
	  struct prefix_ipv6 p;
	  p.family = AF_INET6;
	  memcpy (&p.prefix, dest, 16);
	  p.prefixlen = rtm->rtm_dst_len;
	  printf ("Network %s\n", inet_ntop (AF_INET6, &p.prefix, buf, BUFSIZ));
	  
#if 0
	  if (h->nlmsg_type == RTM_NEWROUTE)
	    rib_add_ipv6 (ZEBRA_ROUTE_KERNEL, 0, &p, gate, index, 0);
	  else
	    rib_delete_ipv6 (ZEBRA_ROUTE_KERNEL, 0, &p, gate, index, 0);
#endif /* 0 */
	}
#endif /* HAVE_IPV6 */
#endif
      return 0;
    }

  if (rtm->rtm_family == AF_INET)
    {
      struct prefix_ipv4 p;
      p.family = AF_INET;
      memcpy (&p.prefix, dest, 4);
      p.prefixlen = rtm->rtm_dst_len;

#ifdef DEBUG
      printf ("Network %s\n", inet_ntoa (p.prefix));
#endif /* DEBUG */

      if (h->nlmsg_type == RTM_NEWROUTE)
	rib_add_ipv4 (ZEBRA_ROUTE_KERNEL, 0, &p, gate, index, table);
      else
	rib_delete_ipv4 (ZEBRA_ROUTE_KERNEL, 0, &p, gate, index, table);
    }
#ifdef HAVE_IPV6
  if (rtm->rtm_family == AF_INET6)
    {
      struct prefix_ipv6 p;

      /* Hmmm.  I still can't find the reason. */
      /* return 0; */

      p.family = AF_INET6;
      memcpy (&p.prefix, dest, 16);
      p.prefixlen = rtm->rtm_dst_len;

#ifdef DEBUG
      printf ("Network %s\n", inet_ntop (AF_INET6, &p.prefix, buf, BUFSIZ));
#endif /* DEBUG */

      if (h->nlmsg_type == RTM_NEWROUTE)
	rib_add_ipv6 (ZEBRA_ROUTE_KERNEL, 0, &p, gate, index, 0);
      else
	rib_delete_ipv6 (ZEBRA_ROUTE_KERNEL, 0, &p, gate, index, 0);
    }
#endif /* HAVE_IPV6 */

#ifdef DEBUG
  fflush (stdout);
#endif

  return 0;
}

int
netlink_link_change (struct sockaddr_nl *snl, struct nlmsghdr *h)
{
  int len;
  struct ifinfomsg *ifi;
  struct rtattr *tb [IFLA_MAX + 1];
  struct interface *ifp;
  char *name;

  ifi = NLMSG_DATA (h);

#ifdef DEBUG
  printf ("ifindex %d\n", ifi->ifi_index);
#endif /* DEBUG */

  if (! (h->nlmsg_type == RTM_NEWLINK || h->nlmsg_type == RTM_DELLINK))
    {
      /* If this is not link add/delete message so print warning. */
      zlog_warn ("netlink_link_change: wrong kernel message %d\n",
		 h->nlmsg_type);
      return 0;
    }

  len = h->nlmsg_len - NLMSG_LENGTH (sizeof (struct ifinfomsg));
  if (len < 0)
    return -1;

  /* Looking up interface name. */
  bzero (tb, sizeof tb);
  netlink_parse_rtattr (tb, IFLA_MAX, IFLA_RTA (ifi), len);
  if (tb[IFLA_IFNAME] == NULL)
    return -1;
  name = (char *)RTA_DATA(tb[IFLA_IFNAME]);

  /* Add interface. */
  if (h->nlmsg_type == RTM_NEWLINK)
    {
      ifp = if_lookup_by_name (name);
      if (ifp == NULL)
	{
	  ifp = if_get_by_name (name);
	  zlog_info ("interface %s index %d is added.", 
		     ifp->name, ifi->ifi_index);

	  ifp->ifindex = ifi->ifi_index;
	  ifp->flags = ifi->ifi_flags & 0x0000fffff;
	  ifp->mtu = *(int *)RTA_DATA (tb[IFLA_MTU]);
	  ifp->metric = 1;

	  /* If new link is added. */
	  zebra_interface_add_update (ifp);
	}      
      else
	{
	  /* Interface status change. */
	  ifp->ifindex = ifi->ifi_index;
	  ifp->mtu = *(int *)RTA_DATA (tb[IFLA_MTU]);
	  ifp->metric = 1;

	  if (if_is_up (ifp))
	    {
	      ifp->flags = ifi->ifi_flags & 0x0000fffff;
	      if (! if_is_up (ifp))
		{
		  if_down (ifp);
#ifdef DEBUG
		  printf ("Interface status changed to down message\n");
#endif /* DEBUG */
		}
	    }
	  else
	    {
	      ifp->flags = ifi->ifi_flags & 0x0000fffff;
	      if (if_is_up (ifp))
		{
		  if_up (ifp);
#ifdef DEBUG
		  printf ("Interface status changed to up message\n");
#endif /* DEBUG */
		}
	    }
	}
    }
  else
    {
      ifp = if_lookup_by_name (name);

      if (ifp == NULL)
	zlog (NULL, LOG_WARNING, "interface %s is deleted but can't find",
	      ifp->name);

      zlog (NULL, LOG_INFO, "interface %s index %d is deleted.",
	    ifp->name, ifp->ifindex);

      zebra_interface_delete_update (ifp);
      
      if_delete (ifp);
    }

  return 0;
}

struct message nlmsg_str[] =
{
  {RTM_NEWROUTE, "RTM_NEWROUTE"},
  {RTM_DELROUTE, "RTM_DELROUTE"},
  {RTM_NEWLINK,  "RTM_NEWLINK"},
  {RTM_DELLINK,  "RTM_DELLINK"},
  {RTM_NEWADDR,  "RTM_NEWADDR"},
  {RTM_DELADDR,  "RTM_DELADDR"},
  {0,            NULL}
};

int
netlink_information_fetch (struct sockaddr_nl *snl, struct nlmsghdr *h)
{
#ifdef DEBUG
  printf ("%s: ", lookup(nlmsg_str, h->nlmsg_type));
#endif /* DEBUG */

  switch (h->nlmsg_type)
    {
    case RTM_NEWROUTE:
      return netlink_route_change (snl, h);
      break;
    case RTM_DELROUTE:
      return netlink_route_change (snl, h);
      break;
    case RTM_NEWLINK:
      return netlink_link_change (snl, h);
      break;
    case RTM_DELLINK:
      return netlink_link_change (snl, h);
      break;
    case RTM_NEWADDR:
      return netlink_interface_addr (snl, h);
      break;
    case RTM_DELADDR:
      return netlink_interface_addr (snl, h);
      break;
    default:
      zlog_warn ("Unknown netlink nlmsg_type %d\n", h->nlmsg_type);
      break;
    }
  return 0;
}

/* Interface lookup by netlink socket. */
int
interface_lookup_netlink ()
{
  int ret;

  /* Get interface information. */
  ret = netlink_request (AF_PACKET, RTM_GETLINK);
  if (ret < 0)
    return ret;
  ret = netlink_parse_info (netlink_interface);
  if (ret < 0)
    return ret;

  /* Get IPv4 address of the interfaces. */
  ret = netlink_request (AF_INET, RTM_GETADDR);
  if (ret < 0)
    return ret;
  ret = netlink_parse_info (netlink_interface_addr);
  if (ret < 0)
    return ret;

#ifdef HAVE_IPV6
  /* Get IPv6 address of the interfaces. */
  ret = netlink_request (AF_INET6, RTM_GETADDR);
  if (ret < 0)
    return ret;
  ret = netlink_parse_info (netlink_interface_addr);
  if (ret < 0)
    return ret;
#endif /* HAVE_IPV6 */

  return 0;
}

/* Routing table read function using netlink interface. */
int
netlink_route_read ()
{
  int ret;

  /* Get IPv4 routing table. */
  ret = netlink_request (AF_INET, RTM_GETROUTE);
  if (ret < 0)
    return ret;
  ret = netlink_parse_info (netlink_routing_table);
  if (ret < 0)
    return ret;

#ifdef HAVE_IPV6
  /* Get IPv6 routing table. */
  ret = netlink_request (AF_INET6, RTM_GETROUTE);
  if (ret < 0)
    return ret;
  ret = netlink_parse_info (netlink_routing_table);
  if (ret < 0)
    return ret;
#endif /* HAVE_IPV6 */

  return 0;
}

/* Utility function  comes from iproute2. 
   Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru> */
int
addattr_l (struct nlmsghdr *n, int maxlen, int type, void *data, int alen)
{
  int len;
  struct rtattr *rta;

  len = RTA_LENGTH(alen);

  if (NLMSG_ALIGN(n->nlmsg_len) + len > maxlen)
    return -1;

  rta = (struct rtattr*) (((char*)n) + NLMSG_ALIGN (n->nlmsg_len));
  rta->rta_type = type;
  rta->rta_len = len;
  memcpy (RTA_DATA(rta), data, alen);
  n->nlmsg_len = NLMSG_ALIGN (n->nlmsg_len) + len;

  return 0;
}

/* Utility function comes from iproute2. 
   Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru> */
int
addattr32 (struct nlmsghdr *n, int maxlen, int type, int data)
{
  int len;
  struct rtattr *rta;
  
  len = RTA_LENGTH(4);
  
  if (NLMSG_ALIGN (n->nlmsg_len) + len > maxlen)
    return -1;

  rta = (struct rtattr*) (((char*)n) + NLMSG_ALIGN (n->nlmsg_len));
  rta->rta_type = type;
  rta->rta_len = len;
  memcpy (RTA_DATA(rta), &data, 4);
  n->nlmsg_len = NLMSG_ALIGN (n->nlmsg_len) + len;

  return 0;
}

/* sendmsg() to netlink socket then recvmsg(). */
int
netlink_talk (struct nlmsghdr *n)
{
  int status;
  struct sockaddr_nl snl;
  struct iovec iov = { (void*) n, n->nlmsg_len };
  struct msghdr msg = {(void*) &snl, sizeof snl, &iov, 1, NULL, 0, 0};
  char   buf[4096];
  struct nlmsghdr *h;

  bzero (&snl, sizeof snl);
  snl.nl_family = AF_NETLINK;
  
  n->nlmsg_seq = ++netlink.seq;

  /* Send message to netlink interface. */
  status = sendmsg (netlink.sock, &msg, 0);
  if (status < 0)
    {
      zlog (NULL, LOG_ERR, "netlink_talk sendmsg() error: %s", strerror (errno));
      return -1;
    }

  /* At this point we don't detect error.  Because if sendmsg success,
     there will be no error so recvmsg() blocks. */
  /* return 0; */
  
  /* Result of netlink message. */
  iov.iov_base = buf;
  iov.iov_len = sizeof buf;

  while (1)
    {
      /* Call recvmsg ().  But it block when sendmsg result is success... */

      /* Now it should be work fine.  So I activate this routine from
         zebra-0.69. */
      status = recvmsg (netlink.sock, &msg, 0);
      if (status < 0)
	{
	  if (errno == EINTR)
	    continue;
	  if (errno == EWOULDBLOCK)
            return 0;
	  zlog (NULL, LOG_ERR, "netlink_talk recvmsg() error: %s", strerror (errno));
	  return -1;
	}
      if (status == 0)
	{
	  zlog (NULL, LOG_ERR, "netlink_talk EOF on netlink: %s", strerror (errno));
	  return -1;
	}
      if (msg.msg_namelen != sizeof snl) 
	{
	  zlog (NULL, LOG_ERR, "netlink_talk sender address length %d", msg.msg_namelen);
	  return -1;
	}

      /* Parse return value. */
      for (h = (struct nlmsghdr*) buf; status >= sizeof (struct nlmsghdr); ) {
	int len = h->nlmsg_len;
	pid_t pid = h->nlmsg_pid;
	int l = len - sizeof(*h);
	unsigned seq = h->nlmsg_seq;

	/* Chech length. */
	if (l < 0 || len > status) 
	  {
	    if (msg.msg_flags & MSG_TRUNC) 
	      {
		zlog (NULL, LOG_ERR, "netlink_talk truncated message\n");
		return -1;
	      }
	    zlog (NULL, LOG_ERR, "netlink_talk malformed message: len=%d", len);
	    return -1;
	  }
	
	if (h->nlmsg_pid != pid || h->nlmsg_seq != seq) 
	  continue;

	if (h->nlmsg_type == NLMSG_ERROR) 
	  {
	    struct nlmsgerr *err = (struct nlmsgerr*)NLMSG_DATA(h);

	    if (l < sizeof(struct nlmsgerr)) 
	      zlog (NULL, LOG_ERR, "netlink_talk message truncated\n");
	    else 
	      zlog (NULL, LOG_ERR, "netlink_talk error: %s", strerror (-err->error));
	    return -1;
	  }

	/* zlog (NULL, LOG_ERR, "netlink_talk unexpected reply."); */
	
	status -= NLMSG_ALIGN(len);
	h = (struct nlmsghdr*) ((char*)h + NLMSG_ALIGN(len));
      }

      if (msg.msg_flags & MSG_TRUNC) 
	{
	  zlog (NULL, LOG_ERR, "netlink_talk message truncated\n");
	  continue;
      }

      if (status) 
	{
	  zlog (NULL, LOG_ERR, "netlink_talk error remnant of size %d", status);
	  return -1;
	}
    }
  
  return 0;
}

/* Routing table change via netlink interface. */
int
netlink_route (int cmd, unsigned long flags, int family, void *dest,
	       int length, void *gate, int index, int zebra_flags, int table)
{
  int ret;
  int bytelen;
  struct sockaddr_nl snl;

  struct 
  {
    struct nlmsghdr n;
    struct rtmsg r;
    char buf[1024];
  } req;

  bzero (&req, sizeof req);

  bytelen = (family == AF_INET ? 4 : 16);

  req.n.nlmsg_len = NLMSG_LENGTH (sizeof (struct rtmsg));
  req.n.nlmsg_flags = NLM_F_REQUEST | flags;
  req.n.nlmsg_type = cmd;
  req.r.rtm_family = family;
  req.r.rtm_table = table;
  req.r.rtm_dst_len = length;

  if (cmd != RTM_DELROUTE) 
    {
      req.r.rtm_protocol = RTPROT_ZEBRA;
      req.r.rtm_scope = RT_SCOPE_UNIVERSE;
      /* req.r.rtm_scope = RT_SCOPE_HOST; */
      /* req.r.rtm_scope = RT_SCOPE_LINK; */
      if (zebra_flags & ZEBRA_FLAG_BLACKHOLE)
	req.r.rtm_type = RTN_BLACKHOLE;
      else
	req.r.rtm_type = RTN_UNICAST;
    }

  if (gate)
    addattr_l (&req.n, sizeof req, RTA_GATEWAY, gate, bytelen);
  if (dest)
    addattr_l (&req.n, sizeof req, RTA_DST, dest, bytelen);
  if (index > 0)
    addattr32 (&req.n, sizeof req, RTA_OIF, index);

  /* Destination netlink address. */
  bzero (&snl, sizeof snl);
  snl.nl_family = AF_NETLINK;

  /* Talk to netlink socket. */
  ret = netlink_talk (&req.n);
  if (ret < 0)
    return -1;

  return 0;
}

/* Add IPv4 route to the kernel. */
int
kernel_add_ipv4 (struct prefix_ipv4 *dest, struct in_addr *gate,
		 int index, int flags, int table)
{
  int ret;

  ret = netlink_route (RTM_NEWROUTE, NLM_F_CREATE, AF_INET, &dest->prefix,
		       dest->prefixlen, gate, index, flags, table);
  return ret;
}

/* Delete IPv4 route from the kernel. */
int
kernel_delete_ipv4 (struct prefix_ipv4 *dest, struct in_addr *gate,
		    int index, int flags, int table)
{
  int ret;

  ret = netlink_route (RTM_DELROUTE, NLM_F_CREATE, AF_INET, &dest->prefix,
		       dest->prefixlen, gate, index, flags, table);
  return ret;
}

#ifdef HAVE_IPV6
/* Add IPv6 route to the kernel. */
int
kernel_add_ipv6 (struct prefix_ipv6 *dest, struct in6_addr *gate,
		    int index, int flags, int table)
{
  int ret;

  ret = netlink_route (RTM_NEWROUTE, NLM_F_CREATE, AF_INET6, &dest->prefix,
		       dest->prefixlen, gate, index, flags, table);
  return ret;
}

/* Delete IPv6 route from the kernel. */
int
kernel_delete_ipv6 (struct prefix_ipv6 *dest, struct in6_addr *gate,
		    int index, int flags, int table)
{
  int ret;

  ret = netlink_route (RTM_DELROUTE, NLM_F_CREATE, AF_INET6, &dest->prefix,
		       dest->prefixlen, gate, index, flags, table);
  return ret;
}
#endif /* HAVE_IPV6 */

#include "thread.h"

extern struct thread_master *master;

/* Kernel route reflection. */
int
kernel_read (struct thread *thread)
{
  int ret;
  int sock;

  sock = THREAD_FD (thread);
  ret = netlink_parse_info (netlink_information_fetch);
  thread_add_read (master, kernel_read, NULL, netlink.sock);

  return 0;
}

/* Exported interface function.  This function simply calls
   netlink_socket (). */
void
kernel_init ()
{
  netlink_socket ();

  /* Register kernel socket. */
  if (netlink.sock > 0)
    thread_add_read (master, kernel_read, NULL, netlink.sock);
}
