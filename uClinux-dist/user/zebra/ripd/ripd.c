/* RIP version 1 and 2.
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

#include "if.h"
#include "command.h"
#include "prefix.h"
#include "table.h"
#include "thread.h"
#include "memory.h"
#include "roken.h"
#include "log.h"
#include "stream.h"
#include "filter.h"
#include "sockunion.h"
#include "routemap.h"
#include "plist.h"
#include "distribute.h"

#include "ripd/ripd.h"
#include "ripd/rip_debug.h"

/* RIP Structure. */
struct rip *rip = NULL;

/* RIP neighbor address table. */
struct route_table *rip_neighbor_table;

/* RIP route changes. */
long rip_global_route_changes = 0;

/* RIP queries. */
long rip_global_queries = 0;

/* Prototypes. */
void rip_event (enum rip_event, int);

void rip_output_process (struct interface *, struct sockaddr_in *, 
			 int, int, u_char);

/* RIP output routes type. */
enum
{
  rip_all_route,
  rip_changed_route,
  rip_split_horizon,
  rip_no_split_horizon
};

/* RIP command strings. */
struct message rip_msg[] = 
{
  {RIP_REQUEST,    "REQUEST"},
  {RIP_RESPONSE,   "RESPONSE"},
  {RIP_TRACEON,    "TRACEON"},
  {RIP_TRACEOFF,   "TRACEOFF"},
  {RIP_POLL,       "POLL"},
  {RIP_POLL_ENTRY, "POLL ENTRY"},
  {0,              NULL}
};

/* Each route type's strings and default preference. */
struct
{  
  int key;
  char *str;
  char *str_long;
  int distance;
} route_info[] =
{
  { ZEBRA_ROUTE_SYSTEM,  "X", "system",    10},
  { ZEBRA_ROUTE_KERNEL,  "K", "kernel",    20},
  { ZEBRA_ROUTE_CONNECT, "C", "connected", 30},
  { ZEBRA_ROUTE_STATIC,  "S", "static",    40},
  { ZEBRA_ROUTE_RIP,     "R", "rip",       50},
  { ZEBRA_ROUTE_RIPNG,   "R", "ripng",     50},
  { ZEBRA_ROUTE_OSPF,    "O", "ospf",      60},
  { ZEBRA_ROUTE_OSPF6,   "O", "ospf6",     60},
  { ZEBRA_ROUTE_BGP,     "B", "bgp",       70},
};

/* Utility function to set boradcast option to the socket. */
int
sockopt_broadcast (int sock)
{
  int ret;
  int on = 1;

  ret = setsockopt (sock, SOL_SOCKET, SO_BROADCAST, (char *) &on, sizeof on);
  if (ret < 0)
    {
      zlog_warn ("can't set sockopt SO_BROADCAST to socket %d", sock);
      return -1;
    }
  return 0;
}

struct rip_info *
rip_info_new ()
{
  struct rip_info *new;

  new = XMALLOC (MTYPE_RIP_INFO, sizeof (struct rip_info));
  bzero (new, sizeof (struct rip_info));
  return new;
}

void
rip_info_free (struct rip_info *rinfo)
{
  XFREE (MTYPE_RIP_INFO, rinfo);
}

/* RIP route garbage collect timer. */
int
rip_garbage_collect (struct thread *t)
{
  struct rip_info *rinfo;
  struct route_node *rp;

  rinfo = THREAD_ARG (t);
  rinfo->t_garbage_collect = NULL;

  /* Off timeout timer. */
  RIP_TIMER_OFF (rinfo->t_timeout);
  
  /* Get route_node pointer. */
  rp = rinfo->rp;

  /* Delete this route from the kernel. */
  rip_zebra_ipv4_delete ((struct prefix_ipv4 *)&rp->p, 
			 &rinfo->nexthop, rinfo->ifindex);
  rinfo->flags &= ~RIP_RTF_FIB;

  /* Unlock route_node. */
  rp->info = NULL;
  route_unlock_node (rp);

  /* Free RIP routing information. */
  rip_info_free (rinfo);

  return 0;
}

/* Timeout RIP routes. */
int
rip_timeout (struct thread *t)
{
  struct rip_info *rinfo;
  struct route_node *rp;

  rinfo = THREAD_ARG (t);
  rinfo->t_timeout = NULL;

  /* Get route_node pointer. */
  rp = rinfo->rp;

  /* - The garbage-collection timer is set for 120 seconds. */
  RIP_TIMER_ON (rinfo->t_garbage_collect, rip_garbage_collect, 
		rip->garbage_time);

  /* - The metric for the route is set to 16 (infinity).  This causes
     the route to be removed from service. */
  rinfo->metric = RIP_METRIC_INFINITY;

  /* - The route change flag is to indicate that this entry has been
     changed. */
  rinfo->flags |= RIP_RTF_CHANGED;

  /* - The output process is signalled to trigger a response. */
  rip_event (RIP_TRIGGERED_UPDATE, 0);

  return 0;
}

void
rip_timeout_update (struct rip_info *rinfo)
{
  if (rinfo->metric != RIP_METRIC_INFINITY)
    {
      RIP_TIMER_OFF (rinfo->t_timeout);
      RIP_TIMER_ON (rinfo->t_timeout, rip_timeout, rip->timeout_time);
    }
}

/* RIP add route to routing table. */
void
rip_route_process (struct rte *rte, struct sockaddr_in *from,
		   struct interface *ifp)
{
  struct prefix_ipv4 p;
  struct route_node *rp;
  struct rip_info *rinfo;
  struct rip_interface *ri;
  struct in_addr *nexthop;
  u_char oldmetric;
  int same = 0;

  /* Make prefix structure. */
  memset (&p, 0, sizeof (struct prefix_ipv4));
  p.family = AF_INET;
  p.prefix = rte->prefix;
  p.prefixlen = ip_masklen (rte->mask);

  /* Make sure mask is applied. */
  apply_mask_ipv4 (&p);

  /* Apply input filters. */
  ri = ifp->info;

  /* Input distribute-list filtering. */
  if (ri->list[RIP_FILTER_IN])
    {
      if (access_list_apply (ri->list[RIP_FILTER_IN], 
			     (struct prefix *) &p) == FILTER_DENY)
	{
	  if (IS_RIP_DEBUG_PACKET)
	    zlog_info ("%s/%d filtered by distribute in",
		       inet_ntoa (p.prefix), p.prefixlen);
	  return;
	}
    }
  if (ri->prefix[RIP_FILTER_IN])
    {
      if (prefix_list_apply (ri->prefix[RIP_FILTER_IN], 
			     (struct prefix *) &p) == PREFIX_DENY)
	{
	  if (IS_RIP_DEBUG_PACKET)
	    zlog_info ("%s/%d filtered by prefix-list in",
		       inet_ntoa (p.prefix), p.prefixlen);
	  return;
	}
    }

  /* Set nexthop pointer. */
  if (rte->nexthop.s_addr == 0)
    nexthop = &from->sin_addr;
  else
    nexthop = &rte->nexthop;

  /* Get index for the prefix. */
  rp = route_node_get (rip->table, (struct prefix *) &p);

  if (rp->info == NULL)
    {
      /* Now, check to see whether there is already an explicit route
	 for the destination prefix.  If there is no such route, add
	 this route to the routing table, unless the metric is
	 infinity (there is no point in adding a route which
	 unusable). */
      if (rte->metric != RIP_METRIC_INFINITY)
	{
	  rinfo = rip_info_new ();
	  
	  /* - Setting the destination prefix and length to those in
	     the RTE. */
	  rp->info = rinfo;
	  rinfo->rp = rp;

	  /* - Setting the metric to the newly calculated metric (as
	     described above). */
	  rinfo->metric = rte->metric;
	  rinfo->tag = ntohs (rte->tag);

	  /* - Set the next hop address to be the address of the router
	     from which the datagram came or the next hop address
	     specified by a next hop RTE. */
	  IPV4_ADDR_COPY (&rinfo->nexthop, nexthop);
	  IPV4_ADDR_COPY (&rinfo->from, &from->sin_addr);
	  rinfo->ifindex = ifp->ifindex;

	  /* - Initialize the timeout for the route.  If the
	     garbage-collection timer is running for this route, stop it
	     (see section 2.3 for a discussion of the timers). */
	  rip_timeout_update (rinfo);

	  /* - Set the route change flag. */
	  rinfo->flags |= RIP_RTF_CHANGED;

	  /* - Signal the output process to trigger an update (see section
	     2.5). */
	  rip_event (RIP_TRIGGERED_UPDATE, 0);

	  /* Finally, route goes into the kernel. */
	  rinfo->type = ZEBRA_ROUTE_RIP;
	  rinfo->sub_type = RIP_ROUTE_RTE;

	  rip_zebra_ipv4_add (&p, &rinfo->nexthop, rinfo->ifindex);
	  rinfo->flags |= RIP_RTF_FIB;
	}
    }
  else
    {
      rinfo = rp->info;
	  
      /* If there is an existing route, compare the next hop address
	 to the address of the router from which the datagram came.
	 If this datagram is from the same router as the existing
	 route, reinitialize the timeout.  */
      same = IPV4_ADDR_SAME (&rinfo->from, &from->sin_addr);

      if (same)
	rip_timeout_update (rinfo);

      /* Next, compare the metrics.  If the datagram is from the same
	 router as the existing route, and the new metric is different
	 than the old one; or, if the new metric is lower than the old
	 one; do the following actions: */
      if ((same && rinfo->metric != rte->metric) ||
	  rte->metric < rinfo->metric)
	{
	  /* - Adopt the route from the datagram.  That is, put the
	     new metric in, and adjust the next hop address (if
	     necessary). */
	  oldmetric = rinfo->metric;
	  rinfo->metric = rte->metric;
	  rinfo->tag = ntohs (rte->tag);

	  if (! IPV4_ADDR_SAME (&rinfo->nexthop, nexthop))
	    {
	      rip_zebra_ipv4_delete (&p, &rinfo->nexthop, rinfo->ifindex);
	      rip_zebra_ipv4_add (&p, nexthop, ifp->ifindex);
	      rinfo->flags |= RIP_RTF_FIB;

	      IPV4_ADDR_COPY (&rinfo->nexthop, nexthop);
	    }
	  IPV4_ADDR_COPY (&rinfo->from, &from->sin_addr);
	  rinfo->ifindex = ifp->ifindex;

	  /* - Set the route change flag and signal the output process
	     to trigger an update. */
	  rinfo->flags |= RIP_RTF_CHANGED;
	  rip_event (RIP_TRIGGERED_UPDATE, 0);

	  /* - If the new metric is infinity, start the deletion
	     process (described above); */
	  if (rinfo->metric == RIP_METRIC_INFINITY)
	    {
	      /* If the new metric is infinity, the deletion process
		 begins for the route, which is no longer used for
		 routing packets.  Note that the deletion process is
		 started only when the metric is first set to
		 infinity.  If the metric was already infinity, then a
		 new deletion process is not started. */
	      if (oldmetric != RIP_METRIC_INFINITY)
		{
		  /* - The garbage-collection timer is set for 120 seconds. */
		  RIP_TIMER_ON (rinfo->t_garbage_collect, 
				rip_garbage_collect, rip->garbage_time);
		  RIP_TIMER_OFF (rinfo->t_timeout);

		  /* - The metric for the route is set to 16
		     (infinity).  This causes the route to be removed
		     from service.*/
		  /* - The route change flag is to indicate that this
		     entry has been changed. */
		  /* - The output process is signalled to trigger a
                     response. */
		  ;  /* Above processes are already done previously. */
		}
	    }
	  else
	    {
	      /* otherwise, re-initialize the timeout. */
	      rip_timeout_update (rinfo);

	      /* Should a new route to this network be established
		 while the garbage-collection timer is running, the
		 new route will replace the one that is about to be
		 deleted.  In this case the garbage-collection timer
		 must be cleared. */
	      RIP_TIMER_OFF (rinfo->t_garbage_collect);
	    }
	}
      /* Unlock tempolary lock of the route. */
      route_unlock_node (rp);
    }
}

/* Dump RIP packet */
void
rip_packet_dump (struct rip_packet *packet, int size, char *sndrcv)
{
  caddr_t lim;
  struct rte *rte;
  char *command_str;
  char pbuf[BUFSIZ], nbuf[BUFSIZ];
  u_char netmask = 0;

  /* Set command string. */
  if (packet->command > 0 && packet->command < RIP_COMMAND_MAX)
    command_str = lookup (rip_msg, packet->command);
  else
    command_str = "unknown";

  /* Dump packet header. */
  zlog_info ("%s %s version %d packet size %d",
	     sndrcv, command_str, packet->version, size);

  /* Dump each routing table entry. */
  rte = packet->rte;
  
  for (lim = (caddr_t) packet + size; (caddr_t) rte < lim; rte++)
    {
      if (packet->version == RIPv2)
	{
	  netmask = ip_masklen (rte->mask);

	  if (ntohs (rte->family) == 0xffff)
	    zlog_info ("  auth string: %s family %d type %d",
		       (char *)&rte->prefix,
		       ntohs (rte->family), ntohs (rte->tag));
	  else
	    zlog_info ("  %s/%d -> %s family %d tag %d metric %d",
		       inet_ntop (AF_INET, &rte->prefix, pbuf, BUFSIZ),netmask,
		       inet_ntop (AF_INET, &rte->nexthop, nbuf, BUFSIZ),
		       ntohs (rte->family), ntohs (rte->tag), 
		       ntohl (rte->metric));
	}
      else
	{
	  zlog_info ("  %s family %d tag %d metric %d", 
		     inet_ntop (AF_INET, &rte->prefix, pbuf, BUFSIZ),
		     ntohs (rte->family), ntohs (rte->tag),
		     ntohl (rte->metric));
	}
    }
}

/* Check if the destination address is valid (unicast; not net 0
   or 127) (RFC2453 Section 3.9.2 - Page 26).  But we don't
   check net 0 because we accept default route. */
int
rip_destination_check (struct in_addr addr)
{
  u_int32_t destination;

  /* Convert to host byte order. */
  destination = ntohl (addr.s_addr);

  if (IPV4_NET127 (destination))
    return 0;

#if 0
  /* Net 0 may match to the default route. */
  if (IPV4_NET0 (destination))
    return 0;
#endif /* 0 */

  if (IN_CLASSA (destination))
    return 1;
  if (IN_CLASSB (destination))
    return 1;
  if (IN_CLASSC (destination))
    return 1;

  return 0;
}

/* RIP version 2 authentication. */
int
rip_authentication (struct rte *rte, struct sockaddr_in *from,
		    struct interface *ifp)
{
  struct rip_interface *ri;
  char *auth_str;

  if (IS_RIP_DEBUG_EVENT)
    zlog_info ("RIPv2 authentication from %s", inet_ntoa (from->sin_addr));

  ri = ifp->info;

  /* If authentication string is specified. */
  if (ri->auth_str)
    {
      /* Check authentication type. */
      if (ntohs (rte->tag) == 2)
	{
	  auth_str = (char *) &rte->prefix;

	  if (strncmp (auth_str, ri->auth_str, 16) == 0)
	    return 1;
	}
    }
  return 0;
}

/* RIP routing information. */
void
rip_response_process (struct rip_packet *packet, int size, 
		      struct sockaddr_in *from, struct interface *ifp)
{
  caddr_t lim;
  struct rte *rte;
      
  /* The Response must be ignored if it is not from the RIP
     port. (RFC2453 - Sec. 3.9.2)*/
  if (ntohs (from->sin_port) != RIP_PORT_DEFAULT) 
    {
      zlog_info ("response doesn't come from RIP port: %d",
		 from->sin_port);
      rip_peer_bad_packet (from);
      return;
    }

  /* The datagram's IPv4 source address should be checked to see
     whether the datagram is from a valid neighbor; the source of the
     datagram must be on a directly connected network  */
  if (! if_valid_neighbor (from->sin_addr)) 
    {
      zlog_info ("This datagram doesn't came from a valid neighbor: %s",
		 inet_ntoa (from->sin_addr));
      rip_peer_bad_packet (from);
      return;
    }

  /* It is also worth checking to see whether the response is from one
     of the router's own addresses. */

  ; /* Alredy done in rip_read () */

  /* Update RIP peer. */
  rip_peer_update (from, packet->version);

  /* Set RTE pointer. */
  rte = packet->rte;

  for (lim = (caddr_t) packet + size; (caddr_t) rte < lim; rte++)
    {
      /* RIPv2 authentication check. */
      /* If the Address Family Identifier of the first (and only the
	 first) entry in the message is 0xFFFF, then the remainder of
	 the entry contains the authentication. */
      /* If the packet gets here it means authentication enabled */
      /* Check is done in rip_read(). So, just skipping it */
      if (packet->version == RIPv2 &&
	  rte == packet->rte &&
	  rte->family == 0xffff)
	continue;

      if (ntohs (rte->family) != AF_INET)
	{
	  /* Address family check.  RIP only supports AF_INET. */
	  zlog_info ("Unsupported family %d from %s.",
		     ntohs (rte->family), inet_ntoa (from->sin_addr));
	  continue;
	}

      /* - is the destination address valid (e.g., unicast; not net 0
         or 127) */
      if (! rip_destination_check (rte->prefix))
        {
	  zlog_info ("Network is net 127 or it is not unicast network");
	  rip_peer_bad_route (from);
	  continue;
	} 

      /* Convert metric value to host byte order. */
      rte->metric = ntohl (rte->metric);

      /* - is the metric valid (i.e., between 1 and 16, inclusive) */
      if (! (rte->metric >= 1 && rte->metric <= 16))
	{
	  zlog_info ("Route's metric is not in the 1-16 range.");
	  rip_peer_bad_route (from);
	  continue;
	}

      /* RIPv1 does not have nexthop value. */
      if (packet->version == RIPv1 && rte->nexthop.s_addr != 0)
	{
	  zlog_info ("RIPv1 packet with nexthop value %s",
		     inet_ntoa (rte->nexthop));
	  rip_peer_bad_route (from);
	  continue;
	}

      /* An address specified as a next hop must, per force, be
	 directly reachable on the logical subnet over which the
	 advertisement is made. */
      if (packet->version == RIPv2 && rte->nexthop.s_addr != 0)
	{
	  if (! if_lookup_address (rte->nexthop))
	    {
	      zlog_info ("Next hop is not directly reachable %s", 
			 inet_ntoa (rte->nexthop));
	      rip_peer_bad_route (from);
	      continue;
	    }
	}

     /* For RIPv1, there won't be a valid netmask.  

	This is a best guess at the masks.  If everyone was using old
	Ciscos before the 'ip subnet zero' option, it would be almost
	right too :-)
      
	Cisco summarize ripv1 advertisments to the classful boundary
	(/16 for class B's) except when the RIP packet does to inside
	the classful network in question.  */

      if ((packet->version == RIPv1 && rte->prefix.s_addr != 0) 
	  || (packet->version == RIPv2 
	      && (rte->prefix.s_addr != 0 && rte->mask.s_addr == 0)))
	{
	  u_int32_t destination;

	  destination = ntohl (rte->prefix.s_addr);

	  if (destination & 0xff) 
	    {
	      masklen2ip (32, &rte->mask);
	    }
	  else if ((destination & 0xff00) || IN_CLASSC (destination)) 
	    {
	      masklen2ip (24, &rte->mask);
	    }
	  else if ((destination & 0xff0000) || IN_CLASSB (destination)) 
	    {
	      masklen2ip (16, &rte->mask);
	    }
	  else 
	    {
	      masklen2ip (8, &rte->mask);
	    }
	}

      /* In case of RIPv2, if prefix in RTE is not netmask applied one
         ignore the entry.  */
      if ((packet->version == RIPv2) 
	  && (rte->mask.s_addr != 0) 
	  && ((rte->prefix.s_addr & rte->mask.s_addr) != rte->prefix.s_addr))
	{
	  zlog_warn ("RIPv2 address %s is not mask /%d applied one",
		     inet_ntoa (rte->prefix), ip_masklen (rte->mask));
	  rip_peer_bad_route (from);
	  continue;
	}

      /* Once the entry has been validated, update the metric by
         adding the cost of the network on wich the message
         arrived. If the result is greater than infinity, use infinity
         (RFC2453 Sec. 3.9.2) */
      rte->metric += ifp->metric;
      if (rte->metric > RIP_METRIC_INFINITY)
	rte->metric = RIP_METRIC_INFINITY;

      /* Routing table updates. */
      rip_route_process (rte, from, ifp);
    }
}

/* RIP packet send to destination address. */
int
rip_send_packet (caddr_t buf, int size, struct sockaddr_in *to, 
		 struct interface *ifp)
{
  int ret;
  struct sockaddr_in sin;
  int sock;

  /* Make destination address. */
  memset (&sin, 0, sizeof (struct sockaddr_in));
  sin.sin_family = AF_INET;
#ifdef HAVE_SIN_LEN
  sin.sin_len = sizeof (struct sockaddr_in);
#endif /* HAVE_SIN_LEN */

  /* When destination is specified, use it's port and address. */
  if (to)
    {
      sock = rip->sock;

      sin.sin_port = to->sin_port;
      sin.sin_addr = to->sin_addr;
    }
  else
    {
      sock = socket (AF_INET, SOCK_DGRAM, 0);
      
      sockopt_broadcast (sock);
      sockopt_reuseaddr (sock);
      sockopt_reuseport (sock);

      sin.sin_port = htons (RIP_PORT_DEFAULT);
      sin.sin_addr.s_addr = htonl (INADDR_RIP_GROUP);

      /* Set multicast interface. */
      rip_interface_multicast_set (sock, ifp);
    }

  ret = sendto (sock, buf, size, 0, (struct sockaddr *)&sin,
		sizeof (struct sockaddr_in));

  if (IS_RIP_DEBUG_EVENT)
      zlog_info ("SEND to socket %d port %d addr %s",
                 sock, ntohs (sin.sin_port), inet_ntoa(sin.sin_addr));

  if (ret < 0)
    zlog_warn ("can't send packet : %s", strerror (errno));

  if (! to)
    close (sock);

  return ret;
}

/* Add redistributed route to RIP table. */
void
rip_redistribute_add (int type, int sub_type, struct prefix_ipv4 *p, 
		      unsigned int ifindex, struct in_addr *nexthop)
{
  int ret;
  struct route_node *rp;
  struct rip_info *rinfo;

  /* Redistribute route  */
  ret = rip_destination_check (p->prefix);
  if (! ret)
    return;

  rp = route_node_get (rip->table, (struct prefix *) p);
  rinfo = rp->info;

  if (rinfo)
    {
      RIP_TIMER_OFF (rinfo->t_timeout);
      RIP_TIMER_OFF (rinfo->t_garbage_collect);
      route_unlock_node (rp);
    }
  else
    {
      rinfo = rip_info_new ();
    }

  rinfo->type = type;
  rinfo->sub_type = sub_type;
  rinfo->ifindex = ifindex;
  rinfo->metric = 1;
  if (nexthop)
    rinfo->nexthop = *nexthop;
  rinfo->flags |= RIP_RTF_FIB;

  rinfo->rp = rp;
  rp->info = rinfo;
}

/* Delete redistributed route from RIP table. */
void
rip_redistribute_delete (int type, int sub_type, struct prefix_ipv4 *p, 
			   unsigned int ifindex)
{
  int ret;
  struct route_node *rp;
  struct rip_info *rinfo;

  ret = rip_destination_check (p->prefix);
  if (! ret)
    return;

  rp = route_node_lookup (rip->table, (struct prefix *) p);

  if (rp)
    {
      rinfo = rp->info;

      if (rinfo != NULL
	  && rinfo->type == type 
	  && rinfo->sub_type == sub_type 
	  && rinfo->ifindex == ifindex)
	{
	  rp->info = NULL;
	  rip_info_free (rinfo);

	  route_unlock_node (rp);
	}
      route_unlock_node (rp);
    }
}

/* Response to request called from rip_read ().*/
void
rip_request_process (struct rip_packet *packet, int size, 
		     struct sockaddr_in *from, struct interface *ifp)
{
  caddr_t lim;
  struct rte *rte;
  struct prefix_ipv4 p;
  struct route_node *rp;
  struct rip_info *rinfo;
  /* struct rip_interface *ri; */

  /* Check RIP is enabled on this interface or not. */
  ;

  /* RIP peer update. */
  rip_peer_update (from, packet->version);

  lim = ((caddr_t) packet) + size;
  rte = packet->rte;

  /* The Request is processed entry by entry.  If there are no
     entries, no response is given. */
  if (lim == (caddr_t) rte)
    return;

  /* There is one special case.  If there is exactly one entry in the
     request, and it has an address family identifier of zero and a
     metric of infinity (i.e., 16), then this is a request to send the
     entire routing table. */
  if (lim == ((caddr_t) (rte + 1)) &&
      ntohs (rte->family) == 0 &&
      ntohl (rte->metric) == RIP_METRIC_INFINITY)
    {	
      /* All route with split horizon */
      rip_output_process (ifp, from, rip_all_route, rip_split_horizon,
			  packet->version);
    }
  else
    {
      /* Examine the list of RTEs in the Request one by one.  For each
	 entry, look up the destination in the router's routing
	 database and, if there is a route, put that route's metric in
	 the metric field of the RTE.  If there is no explicit route
	 to the specified destination, put infinity in the metric
	 field.  Once all the entries have been filled in, change the
	 command from Request to Response and send the datagram back
	 to the requestor. */
      p.family = AF_INET;

      for (; ((caddr_t) rte) < lim; rte++)
	{
	  p.prefix = rte->prefix;
	  p.prefixlen = ip_masklen (rte->mask);
	  apply_mask_ipv4 (&p);
	  
	  rp = route_node_lookup (rip->table, (struct prefix *) &p);

	  if (rp)
	    {
	      rinfo = rp->info;
	      rte->metric = htonl (rinfo->metric);
	      route_unlock_node (rp);
	    }
	  else
	    rte->metric = htonl (RIP_METRIC_INFINITY);
	}
      packet->command = RIP_RESPONSE;

      rip_send_packet ((caddr_t) packet, size, from, ifp);
    }
  rip_global_queries++;
}

#if RIP_RECVMSG
/* Set IPv6 packet info to the socket. */
static int
setsockopt_pktinfo (int sock)
{
  int ret;
  int val = 1;
    
  ret = setsockopt(sock, IPPROTO_IP, IP_PKTINFO, &val, sizeof(val));
  if (ret < 0)
    zlog_warn ("Can't setsockopt IP_PKTINFO : %s", strerror (errno));
  return ret;
}

/* Read RIP packet by recvmsg function. */
int
rip_recvmsg (int sock, u_char *buf, int size, struct sockaddr_in *from,
	     int *ifindex)
{
  int ret;
  struct msghdr msg;
  struct iovec iov;
  struct cmsghdr *ptr;
  char adata[1024];

  msg.msg_name = (void *) from;
  msg.msg_namelen = sizeof (struct sockaddr_in);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = (void *) adata;
  msg.msg_controllen = sizeof adata;
  iov.iov_base = buf;
  iov.iov_len = size;

  ret = recvmsg (sock, &msg, 0);
  if (ret < 0)
    return ret;

  for (ptr = CMSG_FIRSTHDR(&msg); ptr != NULL; ptr = CMSG_NXTHDR(&msg, ptr))
    if (ptr->cmsg_level == IPPROTO_IP && ptr->cmsg_type == IP_PKTINFO) 
      {
	struct in_pktinfo *pktinfo;
	int i;

	pktinfo = (struct in_pktinfo *) CMSG_DATA (ptr);
	i = pktinfo->ipi_ifindex;
      }
  return ret;
}

/* RIP packet read function. */
int
rip_read_new (struct thread *t)
{
  int ret;
  int sock;
  char buf[RIP_PACKET_MAXSIZ];
  struct sockaddr_in from;
  unsigned int ifindex;
  
  /* Fetch socket then register myself. */
  sock = THREAD_FD (t);
  rip_event (RIP_READ, sock);

  /* Read RIP packet. */
  ret = rip_recvmsg (sock, buf, RIP_PACKET_MAXSIZ, &from, (int *)&ifindex);
  if (ret < 0)
    {
      zlog_warn ("Can't read RIP packet: %s", strerror (errno));
      return ret;
    }

  return ret;
}
#endif /* RIP_RECVMSG */

/* First entry point of RIP packet. */
int
rip_read (struct thread *t)
{
  int sock;
  int ret;
  int rtenum;
  union rip_buf rip_buf;
  struct rip_packet *packet;
  struct sockaddr_in from;
  int fromlen, len;
  struct interface *ifp;
  struct rip_interface *ri;

  /* Fetch socket then register myself. */
  sock = THREAD_FD (t);
  rip->t_read = NULL;

  /* Add myself to tne next event */
  rip_event (RIP_READ, sock);

  /* RIPd manages only IPv4. */
  memset (&from, 0, sizeof (struct sockaddr_in));
  fromlen = sizeof (struct sockaddr_in);

  len = recvfrom (sock, (char *)&rip_buf.buf, sizeof (rip_buf.buf), 0, 
		  (struct sockaddr *) &from, &fromlen);
  if (len < 0) 
    {
      zlog_info ("recvfrom failed: %s", strerror (errno));
      return len;
    }

  /* Check is this packet comming from myself? */
  if (if_check_address (from.sin_addr)) 
    {
      if (IS_RIP_DEBUG_PACKET)
	zlog_warn ("ignore packet comes from myself");
      return -1;
    }

  /* Which interface is this packet comes from. */
  ifp = if_lookup_address (from.sin_addr);

  /* RIP packet received */
  if (IS_RIP_DEBUG_EVENT)
    zlog_info ("RECV packet from %s port %d on %s",
	       inet_ntoa (from.sin_addr), ntohs (from.sin_port),
	       ifp ? ifp->name : "unknown");

  /* If this packet come from unknown interface, ignore it. */
  if (ifp == NULL)
    {
      zlog_info ("packet comes from unknown interface");
      return -1;
    }

  /* Packet length check. */
  if (len < RIP_PACKET_MINSIZ)
    {
      zlog_warn ("packet size %d is smaller than minimum size %d",
		 len, RIP_PACKET_MINSIZ);
      rip_peer_bad_packet (&from);
      return len;
    }
  if (len > RIP_PACKET_MAXSIZ)
    {
      zlog_warn ("packet size %d is larger than max size %d",
		 len, RIP_PACKET_MAXSIZ);
      rip_peer_bad_packet (&from);
      return len;
    }

  /* Packet alignment check. */
  if ((len - RIP_PACKET_MINSIZ) % 20)
    {
      zlog_warn ("packet size %d is wrong for RIP packet alignment", len);
      rip_peer_bad_packet (&from);
      return len;
    }

  /* Set RTE number. */
  rtenum = ((len - RIP_PACKET_MINSIZ) / 20);

  /* For easy to handle. */
  packet = &rip_buf.rip_packet;

  /* RIP version check. */
  if (packet->version == 0)
    {
      zlog_info ("version 0 with command %d received.", packet->command);
      rip_peer_bad_packet (&from);
      return -1;
    }

  /* Dump RIP packet. */
  if (IS_RIP_DEBUG_PACKET)
    rip_packet_dump (packet, len, "RECV");

  /* RIP version adjust.  This code should rethink now.  RFC1058 says
     that "Version 1 implementations are to ignore this extra data and
     process only the fields specified in this document.". So RIPv3
     packet should be treated as RIPv1 ignoring must be zero field. */
  if (packet->version > RIPv2)
    packet->version = RIPv2;

  /* Is RIP running or is this RIP neighbor ?*/
  ri = ifp->info;
  if (! ri->running && ! rip_neighbor_lookup (&from))
    {
      if (IS_RIP_DEBUG_EVENT)
	zlog_info ("RIP is not enabled on interface %s.", ifp->name);
      rip_peer_bad_packet (&from);
      return -1;
    }

  /* RIP Version check. */
  if (packet->command == RIP_RESPONSE)
    {

      if (ri->ri_receive == RI_RIP_UNSPEC)
	{
	  if (packet->version != rip->version) 
	    {
	      if (IS_RIP_DEBUG_PACKET)
		zlog_warn ("  packet's v%d doesn't fit to my version %d", 
			   packet->version, rip->version);
	      rip_peer_bad_packet (&from);
	      return -1;
	    }
	}
      else
	{
	  if (packet->version == RIPv1)
	    if (! (ri->ri_receive & RIPv1))
	      {
		if (IS_RIP_DEBUG_PACKET)
		  zlog_warn ("  packet's v%d doesn't fit to if version spec", 
			     packet->version);
		rip_peer_bad_packet (&from);
		return -1;
	      }
	  if (packet->version == RIPv2)
	    if (! (ri->ri_receive & RIPv2))
	      {
		if (IS_RIP_DEBUG_PACKET)
		  zlog_warn ("  packet's v%d doesn't fit to if version spec", 
			     packet->version);
		rip_peer_bad_packet (&from);
		return -1;
	      }
	}
    }

  /* RFC2453 5.2 If the router is not configured to authenticate RIP-2
     messages, then RIP-1 and unauthenticated RIP-2 messages will be
     accepted; authenticated RIP-2 messages shall be discarded.  */

  if ((ri->auth_type == RIP_NO_AUTH) 
      && rtenum 
      && (packet->version == RIPv2) && (packet->rte->family == 0xffff))
    {
      if (IS_RIP_DEBUG_EVENT)
	zlog_warn ("packet RIPv%d is dropped because authentication disabled", 
		   packet->version);
      rip_peer_bad_packet (&from);
      return -1;
    }

  /* If the router is configured to authenticate RIP-2 messages, then
     RIP-1 messages and RIP-2 messages which pass authentication
     testing shall be accepted; unauthenticated and failed
     authentication RIP-2 messages shall be discarded.  For maximum
     security, RIP-1 messages should be ignored when authentication is
     in use (see section 4.1); otherwise, the routing information from
     authenticated messages will be propagated by RIP-1 routers in an
     unauthenticated manner. */

  if (ri->auth_type == RIP_AUTH_SIMPLE_PASSWORD)
    {
      /* We follow maximum security. */
      if (packet->version == RIPv1)
	{
	  if (IS_RIP_DEBUG_PACKET)
	    zlog_warn ("packet RIPv%d is dropped because authentication enabled", packet->version);
	  rip_peer_bad_packet (&from);
	  return -1;
	}
      
      /* Check RIPv2 authentication. */
      if (packet->version == RIPv2)
	{
	  if (rtenum && packet->rte->family == 0xffff)
	    {
	      ret = rip_authentication (packet->rte, &from, ifp);
	      if (! ret)
		{
		  if (IS_RIP_DEBUG_EVENT)
		    zlog_warn ("RIP authentication failed");
		  rip_peer_bad_packet (&from);
		  return -1;
		}
	    }
	  else 
	    {
	      if (IS_RIP_DEBUG_EVENT)
		zlog_warn ("RIP authentication failed: no authentication in packet");
	      rip_peer_bad_packet (&from);
	      return -1;
	    }	
	}
    }
  
  /* Process each command. */
  switch (packet->command)
    {
    case RIP_RESPONSE:
      rip_response_process (packet, len, &from, ifp);
      break;
    case RIP_REQUEST:
    case RIP_POLL:
      rip_request_process (packet, len, &from, ifp);
      break;
    case RIP_TRACEON:
    case RIP_TRACEOFF:
      zlog_info ("Obsolete command %s received, please sent it to routed", 
		 lookup (rip_msg, packet->command));
      rip_peer_bad_packet (&from);
      break;
    case RIP_POLL_ENTRY:
      zlog_info ("Obsolete command %s received", 
		 lookup (rip_msg, packet->command));
      rip_peer_bad_packet (&from);
      break;
    default:
      zlog_info ("Unknown RIP command %d received", packet->command);
      rip_peer_bad_packet (&from);
      break;
    }

  return len;
}

/* Make socket for RIP protocol. */
int 
rip_create_socket ()
{
  int ret;
  int sock;
  struct sockaddr_in addr;
  struct servent *sp;

  bzero (&addr, sizeof (struct sockaddr_in));

  /* Set RIP port. */
  sp = getservbyname ("router", "udp");
  if (sp) 
    addr.sin_port = sp->s_port;
  else 
    addr.sin_port = htons (RIP_PORT_DEFAULT);

  /* Address shoud be any address. */
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = INADDR_ANY;

  /* Make datagram socket. */
  sock = socket (AF_INET, SOCK_DGRAM, 0);
  if (sock < 0) 
    {
      perror ("socket");
      exit (1);
    }

  sockopt_broadcast (sock);
  sockopt_reuseaddr (sock);
  sockopt_reuseport (sock);
#ifdef RIP_RECVMSG
  setsockopt_pktinfo (sock);
#endif /* RIP_RECVMSG */

  ret = bind (sock, (struct sockaddr *) & addr, sizeof (addr));
  if (ret < 0)
    {
      perror ("bind");
      return ret;
    }
  
  return sock;
}

/* Write routing table entry to the stream and return next index of
   the routing table entry in the stream. */
int
rip_write_rte (int num, struct stream *s, struct prefix_ipv4 *p,
	       u_char version, struct rip_info *rinfo, struct interface *ifp)
{
  struct in_addr mask;

  /* RIP packet header. */
  if (num == 0)
    {
      stream_putc (s, RIP_RESPONSE);
      stream_putc (s, version);
      stream_putw (s, 0);

      /* In case of we need RIPv2 authentication. */
      if (version == RIPv2 && ifp)
	{
	  struct rip_interface *ri;

	  ri = ifp->info;
	      
	  if (ri->auth_str)
	    {
	      stream_putw (s, 0xffff);
	      stream_putw (s, 2);

	      memset ((s->data + s->putp), 0, 16);
	      strncpy ((s->data + s->putp), ri->auth_str, 16);
	      stream_set_putp (s, s->putp + 16);

	      num++;
	    }
	}
    }

  /* Write routing table entry. */
  if (version == RIPv1)
    {
      stream_putw (s, AF_INET);
      stream_putw (s, 0);
      stream_put_ipv4 (s, p->prefix.s_addr);
      stream_put_ipv4 (s, 0);
      stream_put_ipv4 (s, 0);
      stream_putl (s, rinfo->metric_out);
    }
  else
    {
      masklen2ip (p->prefixlen, &mask);

      stream_putw (s, AF_INET);
      stream_putw (s, rinfo->tag);
      stream_put_ipv4 (s, p->prefix.s_addr);
      stream_put_ipv4 (s, mask.s_addr);
      stream_put_ipv4 (s, rinfo->nexthop_out.s_addr);
      stream_putl (s, rinfo->metric_out);
    }

  return ++num;
}

/* Send update to the ifp or spcified neighbor. */
void
rip_output_process (struct interface *ifp, struct sockaddr_in *to,
		    int route_type, int split_horizon, u_char version)
{
  int ret;
  struct stream *s;
  struct route_node *rp;
  struct rip_info *rinfo;
  struct rip_interface *ri;
  struct prefix_ipv4 *ppref_ipv4;
  struct prefix_ipv4 *p;
  int num;
  int rtemax;

  ppref_ipv4 = NULL;
  
  /* Logging output event. */
  if (IS_RIP_DEBUG_EVENT)
    {
      if (to)
	zlog_info ("update routes to neighbor %s", inet_ntoa (to->sin_addr));
      else
	zlog_info ("update routes on interface %s ifindex %d",
		   ifp->name, ifp->ifindex);
    }

  /* Set output stream. */
  s = rip->obuf;

  /* Reset stream and RTE counter. */
  stream_reset (s);
  num = 0;
  rtemax = (RIP_PACKET_MAXSIZ - 4) / 20;

  /* Get RIP interface. */
  ri = ifp->info;

  for (rp = route_top (rip->table); rp; rp = route_next (rp))
    if ((rinfo = rp->info) != NULL)
      {

	/* Some inheritance stuff:                                          */
	/* Before we process with ipv4 prefix we should mask it             */
	/* with Classful mask if we send RIPv1 packet.That's because        */
	/* user could set non-classful mask or we could get it by RIPv2     */
	/* or other protocol. checked with Cisco's way of life :)             */
	
	if (version == RIPv1)
	  {
	    ppref_ipv4 = XMALLOC (MTYPE_PREFIX_IPV4, sizeof (struct prefix_ipv4));
	    memcpy (ppref_ipv4, &rp->p, sizeof (struct prefix_ipv4));

	    if (IS_RIP_DEBUG_PACKET)
	      zlog_info("%s/%d before RIPv1 mask check ",
			inet_ntoa (ppref_ipv4->prefix), ppref_ipv4->prefixlen);

	    apply_classful_mask_ipv4 (ppref_ipv4);
	    p = ppref_ipv4;

	    if (IS_RIP_DEBUG_PACKET)
	      zlog_info("%s/%d after RIPv1 mask check",
			inet_ntoa (p->prefix), p->prefixlen);
	  }
	else 
	  {
	    ppref_ipv4 = NULL;
	    p = (struct prefix_ipv4 *) &rp->p;
	  }

	  /* Apply output filters. */
	  if (ri->list[RIP_FILTER_OUT])
	    {
	      if (access_list_apply (ri->list[RIP_FILTER_OUT],
				     (struct prefix *) p) == FILTER_DENY)
		{
		  if (IS_RIP_DEBUG_PACKET)
		    zlog_info ("%s/%d is filtered by distribute out",
			       inet_ntoa (p->prefix), p->prefixlen);
		  continue;
		}
	    }
	  if (ri->prefix[RIP_FILTER_OUT])
	    {
	      if (prefix_list_apply (ri->prefix[RIP_FILTER_OUT],
				     (struct prefix *) p) == PREFIX_DENY)
		{
		  if (IS_RIP_DEBUG_PACKET)
		    zlog_info ("%s/%d is filtered by prefix-list out",
			       inet_ntoa (p->prefix), p->prefixlen);
		  continue;
		}
	    }

	  /* Changed route only output. */
	  if (route_type == rip_changed_route &&
	      (! (rinfo->flags & RIP_RTF_CHANGED)))
	    continue;

	  /* Split horizon. */
	  if (split_horizon == rip_split_horizon)
	    {
	      /* We perform split horizon for RIP and connected route. */
	      if ((rinfo->type == ZEBRA_ROUTE_RIP ||
		   rinfo->type == ZEBRA_ROUTE_CONNECT) &&
		  rinfo->ifindex == ifp->ifindex)
		continue;
	    }

	  /* Preparation for route-map. */
	  rinfo->nexthop_out.s_addr = 0;
	  rinfo->metric_out = rinfo->metric;
	  rinfo->ifindex_out = ifp->ifindex;
           
	  /* Apply route map - continue, if deny */
	  if (rip->route_map[rinfo->type].map) 
	    {
	      ret = route_map_apply (rip->route_map[rinfo->type].map,
				     (struct prefix *)p, RMAP_RIP, rinfo);

	      if (ret == RMAP_DENYMATCH) 
		{
		  if (IS_RIP_DEBUG_PACKET)
		    zlog_info ("%s/%d is filtered by route-map",
			       inet_ntoa (p->prefix), p->prefixlen);
		  continue;
		}
	    }
	  
	  /* Write RTE to the stream. */
	  num = rip_write_rte (num, s, p, version, rinfo, to ? NULL : ifp);
	  if (num == rtemax)
	    {
	      ret = rip_send_packet (STREAM_DATA (s), stream_get_endp (s),
				     to, ifp);

	      if (ret >= 0 && IS_RIP_DEBUG_PACKET)
		rip_packet_dump ((struct rip_packet *)STREAM_DATA (s),
				 stream_get_endp(s), "SEND");
	      num = 0;
	      stream_reset (s);
	    }
      }

  /* Flush unwritten RTE. */
  if (num != 0)
    {
      ret = rip_send_packet (STREAM_DATA (s), stream_get_endp (s), to, ifp);

      if (ret >= 0 && IS_RIP_DEBUG_PACKET)
	rip_packet_dump ((struct rip_packet *)STREAM_DATA (s),
			 stream_get_endp (s), "SEND");
      num = 0;
      stream_reset (s);
    }

  /* Statistics updates. */
  ri->sent_updates++;
  /* Freeing memory */
  if (ppref_ipv4)
    XFREE(MTYPE_PREFIX_IPV4,ppref_ipv4);
}

/* Send RIP packet to the interface. */
void
rip_update_interface (struct interface *ifp, u_char version)
{
  struct prefix_ipv4 *p;
  struct connected *connected;
  listnode node;
  struct sockaddr_in to;

  /* When RIP version is 2 and multicast enable interface. */
  if (version == RIPv2 && if_is_multicast (ifp)) 
    {
      if (IS_RIP_DEBUG_EVENT)
	zlog_info ("multicast announce on %s ", ifp->name);

      rip_output_process (ifp, NULL, rip_all_route, rip_split_horizon,
			  version);
      return;
    }

  /* If we can't send multicast packet, send it with unicast. */
  if (if_is_broadcast (ifp) || if_is_pointopoint (ifp))
    {
      for (node = listhead (ifp->connected); node; nextnode (node))
	{	    
	  connected = getdata (node);

	  /* Fetch broadcast address or poin-to-point destination
             address . */
	  p = (struct prefix_ipv4 *) connected->destination;

	  if (p->family == AF_INET)
	    {
	      /* Destination address and port setting. */
	      memset (&to, 0, sizeof (struct sockaddr_in));
	      to.sin_addr = p->prefix;
	      to.sin_port = htons (RIP_PORT_DEFAULT);

	      if (IS_RIP_DEBUG_EVENT)
		zlog_info ("%s announce to %s on %s",
			   if_is_pointopoint (ifp) ? "unicast" : "broadcast",
			   inet_ntoa (to.sin_addr), ifp->name);

	      rip_output_process (ifp, &to, rip_all_route, rip_split_horizon,
				  version);
	    }
	}
    }
}

/* Update send to all interface and neighbor. */
void
rip_update_process (int route_type, int split_horizon)
{
  listnode node;
  struct interface *ifp;
  struct rip_interface *ri;
  struct route_node *rp;
  struct sockaddr_in to;
  struct prefix_ipv4 *p;

  /* Send RIP update to each interface. */
  for (node = listhead (iflist); node; nextnode (node))
    {
      ifp = getdata (node);

      if (if_is_loopback (ifp))
	continue;

      if (! if_is_up (ifp))
	continue;
      
      /* Fetch RIP interface information. */
      ri = ifp->info;

      if (ri->running)
	{
	  if (IS_RIP_DEBUG_EVENT) 
	    {
	      if (ifp->name) 
		zlog_info ("SEND UPDATE to %s ifindex %d",
			   ifp->name, ifp->ifindex);
	      else
		zlog_info ("SEND UPDATE to _unknown_ ifindex %d",
			   ifp->ifindex);
	    }

	  /* If there is no version configuration in the interface,
             use rip's version setting. */
	  if (ri->ri_send == RI_RIP_UNSPEC)
	    {
	      if (rip->version == RIPv1)
		rip_update_interface (ifp, RIPv1);
	      else
		rip_update_interface (ifp, RIPv2);
	    }
	  /* If interface has RIP version configuration use it. */
	  else
	    {
	      if (ri->ri_send & RIPv1)
		rip_update_interface (ifp, RIPv1);
	      if (ri->ri_send & RIPv2)
		rip_update_interface (ifp, RIPv2);
	    }
	}
    }

  /* RIP send updates to each neighbor. */
  for (rp = route_top (rip->neighbor); rp; rp = route_next (rp))
    if (rp->info != NULL)
      {
	p = (struct prefix_ipv4 *) &rp->p;

	ifp = if_lookup_address (p->prefix);
	if (! ifp)
	  {
	    zlog_warn ("Neighbor %s doesn't exist direct connected network",
		       inet_ntoa (p->prefix));
	    continue;
	  }

	/* Set destination address and port */
	memset (&to, 0, sizeof (struct sockaddr_in));
	to.sin_addr = p->prefix;
	to.sin_port = htons (RIP_PORT_DEFAULT);

	/* RIP version is rip's configuration. */
	rip_output_process (ifp, &to, rip_all_route, rip_split_horizon, 
			    rip->version);
      }
}

/* RIP's periodical timer. */
int
rip_update (struct thread *t)
{
  /* Clear timer pointer. */
  rip->t_update = NULL;

  if (IS_RIP_DEBUG_EVENT)
    zlog_info ("update timer fire!");

  /* Process update output. */
  rip_update_process (rip_all_route, rip_split_horizon);

  /* Triggered updates may be suppressed if a regular update is due by
     the time the triggered update would be sent. */
  if (rip->t_triggered_interval)
    {
      thread_cancel (rip->t_triggered_interval);
      rip->t_triggered_interval = NULL;
    }
  rip->trigger = 0;

  /* Register myself. */
  rip_event (RIP_UPDATE_EVENT, 0);

  return 0;
}

/* Walk down the RIP routing table then clear changed flag. */
void
rip_clear_changed_flag ()
{
  struct route_node *rp;
  struct rip_info *rinfo;

  for (rp = route_top (rip->table); rp; rp = route_next (rp))
    if ((rinfo = rp->info) != NULL)
      if (rinfo->flags & RIP_RTF_CHANGED)
	rinfo->flags &= ~RIP_RTF_CHANGED;
}

/* Triggered update interval timer. */
int
rip_triggered_interval (struct thread *t)
{
  int rip_triggered_update (struct thread *);

  rip->t_triggered_interval = NULL;

  if (rip->trigger)
    {
      rip->trigger = 0;
      rip_triggered_update (t);
    }
  return 0;
}     

/* Execute triggered update. */
int
rip_triggered_update (struct thread *t)
{
  int interval;

  /* Clear thred pointer. */
  rip->t_triggered_update = NULL;

  /* Cancel interval timer. */
  if (rip->t_triggered_interval)
    {
      thread_cancel (rip->t_triggered_interval);
      rip->t_triggered_interval = NULL;
    }
  rip->trigger = 0;

  /* Logging triggered update. */
  if (IS_RIP_DEBUG_EVENT)
    zlog_info ("triggered update!");

  /* Split Horizon processing is done when generating triggered
     updates as well as normal updates (see section 2.6). */
  rip_update_process (rip_changed_route, rip_split_horizon);

  /* Once all of the triggered updates have been generated, the route
     change flags should be cleared. */
  rip_clear_changed_flag ();

  /* After a triggered update is sent, a timer should be set for a
   random interval between 1 and 5 seconds.  If other changes that
   would trigger updates occur before the timer expires, a single
   update is triggered when the timer expires. */
  interval = (random () % 5) + 1;

  rip->t_triggered_interval = 
    thread_add_timer (master, rip_triggered_interval, NULL, interval);

  return 0;
}

/* Withdraw redistributed route. */
void
rip_redistribute_withdraw (int type)
{
  struct route_node *rp;
  struct rip_info *rinfo;

  for (rp = route_top (rip->table); rp; rp = route_next (rp))
    if ((rinfo = rp->info) != NULL)
      {
	if (rinfo->type == type)
	  {
	    rinfo->rp->info = NULL;
	    route_unlock_node (rp);

	    rip_info_free (rinfo);
	  }
      }
}

/* Create new RIP instance and set it to global variable. */
int
rip_create ()
{
  rip = XMALLOC (0, sizeof (struct rip));
  memset (rip, 0, sizeof (struct rip));

  /* Set initial value. */
  rip->version = RIPv2;
  rip->update_time = RIP_UPDATE_TIMER_DEFAULT;
  rip->timeout_time = RIP_TIMEOUT_TIMER_DEFAULT;
  rip->garbage_time = RIP_GARBAGE_TIMER_DEFAULT;

  /* Initialize RIP routig table. */
  rip->table = route_table_init ();
  rip->route = route_table_init ();
  rip->neighbor = route_table_init ();

  /* Make output stream. */
  rip->obuf = stream_new (1500);

  /* Make socket. */
  rip->sock = rip_create_socket ();
  if (rip->sock < 0)
    return rip->sock;

  /* Create read and timer thread. */
  rip_event (RIP_READ, rip->sock);
  rip_event (RIP_UPDATE_EVENT, 0);

  return 0;
}

/* Sned RIP request to the destination. */
int
rip_request_send (struct sockaddr_in *to, struct interface *ifp,
		  u_char version)
{
  struct rte *rte;
  struct rip_packet rip_packet;

  memset (&rip_packet, 0, sizeof (rip_packet));

  rip_packet.command = RIP_REQUEST;
  rip_packet.version = version;
  rte = rip_packet.rte;
  rte->metric = htonl (RIP_METRIC_INFINITY);

  return rip_send_packet ((caddr_t) &rip_packet, sizeof (rip_packet), to, ifp);
}

int
rip_update_jitter (int time)
{
  return ((rand () % (time + 1)) - (time / 2));
}

void
rip_event (enum rip_event event, int sock)
{
  int jitter = 0;

  switch (event)
    {
    case RIP_READ:
      rip->t_read = thread_add_read (master, rip_read, NULL, sock);
      break;
    case RIP_UPDATE_EVENT:
      if (rip->t_update)
	{
	  thread_cancel (rip->t_update);
	  rip->t_update = NULL;
	}
      jitter = rip_update_jitter (rip->update_time);
      rip->t_update = thread_add_timer (master, rip_update, NULL, 
					sock ? 2 : rip->update_time + jitter);
      break;
    case RIP_TRIGGERED_UPDATE:
      if (rip->t_triggered_interval)
	rip->trigger = 1;
      else if (! rip->t_triggered_update)
	rip->t_triggered_update = 
	  thread_add_event (master, rip_triggered_update, NULL, 0);
      break;
    default:
      break;
    }
}

DEFUN (router_rip,
       router_rip_cmd,
       "router rip",
       "Enable a routing process\n"
       "Start RIP configuration\n")
{
  int ret;

  /* Change to RIP node. */
  vty->node = RIP_NODE;

  /* If rip is not enabled before. */
  if (! rip)
    {
      ret = rip_create ();
      if (ret < 0)
	{
	  zlog_info ("Can't create RIP");
	  return CMD_WARNING;
	}
    }

  return CMD_SUCCESS;
}

DEFUN (rip_version, rip_version_cmd,
       "version VERSION",
       "Set default rip version\n"
       "Version\n")
{
  int version;

  version = atoi (argv[0]);
  if (version != RIPv1 && version != RIPv2)
    {
      vty_out (vty, "invalid rip version %d%s", version,
	       VTY_NEWLINE);
      return CMD_WARNING;
    }
  rip->version = version;

  return CMD_SUCCESS;
} 

DEFUN (rip_route,
       rip_route_cmd,
       "route A.B.C.D/M",
       "RIP static route configuration\n"
       "RIP static route\n")
{
  int ret;
  struct prefix_ipv4 p;
  struct route_node *node;

  ret = str2prefix_ipv4 (argv[0], &p);
  if (ret < 0)
    {
      vty_out (vty, "Malformed address%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  apply_mask_ipv4 (&p);

  /* For router rip configuration. */
  node = route_node_get (rip->route, (struct prefix *) &p);

  if (node->info)
    {
      vty_out (vty, "There is already same static route.%s", VTY_NEWLINE);
      route_unlock_node (node);
      return CMD_WARNING;
    }

  node->info = "static";

  rip_redistribute_add (ZEBRA_ROUTE_RIP, RIP_ROUTE_STATIC, &p, 0, NULL);

  return CMD_SUCCESS;
}

DEFUN (no_rip_route,
       no_rip_route_cmd,
       "no route A.B.C.D/M",
       NO_STR
       "RIP configuration\n"
       "RIP static route\n"
       "RIP static route\n")
{
  int ret;
  struct prefix_ipv4 p;
  struct route_node *node;

  ret = str2prefix_ipv4 (argv[0], &p);
  if (ret < 0)
    {
      vty_out (vty, "Malformed address%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  apply_mask_ipv4 (&p);

  /* For router rip configuration. */
  node = route_node_lookup (rip->route, (struct prefix *) &p);

  if (! node)
    {
      vty_out (vty, "Can't find route %s.%s", argv[0],
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  rip_redistribute_delete (ZEBRA_ROUTE_RIP, RIP_ROUTE_STATIC, &p, 0);
  route_unlock_node (node);

  node->info = NULL;
  route_unlock_node (node);

  return CMD_SUCCESS;
}

DEFUN (rip_timers,
       rip_timers_cmd,
       "timers basic <0-4294967295> <1-4294967295> <1-4294967295>",
       "RIP timers setup\n"
       "Basic timer\n"
       "Routing table update timer value in second. Default is 30.\n"
       "Routing information timeout timer. Default is 180.\n"
       "Garbage collection timer. Default is 120.\n")
{
  unsigned long update;
  unsigned long timeout;
  unsigned long garbage;
  char *endptr = NULL;

  update = strtoul (argv[0], &endptr, 10);
  if (update == ULONG_MAX || *endptr != '\0')
    {
      vty_out (vty, "update timer value error%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  
  timeout = strtoul (argv[1], &endptr, 10);
  if (timeout == ULONG_MAX || *endptr != '\0')
    {
      vty_out (vty, "timeout timer value error%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  
  garbage = strtoul (argv[2], &endptr, 10);
  if (garbage == ULONG_MAX || *endptr != '\0')
    {
      vty_out (vty, "garbage timer value error%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Set each timer value. */
  rip->update_time = update;
  rip->timeout_time = timeout;
  rip->garbage_time = garbage;

  /* Reset update timer thread. */
  rip_event (RIP_UPDATE_EVENT, 0);

  return CMD_SUCCESS;
}

DEFUN (no_rip_timers,
       no_rip_timers_cmd,
       "no timers basic",
       NO_STR
       "RIP timers setup\n"
       "Basic timer\n")
{
  /* Set each timer value to the default. */
  rip->update_time = RIP_UPDATE_TIMER_DEFAULT;
  rip->timeout_time = RIP_TIMEOUT_TIMER_DEFAULT;
  rip->garbage_time = RIP_GARBAGE_TIMER_DEFAULT;

  /* Reset update timer thread. */
  rip_event (RIP_UPDATE_EVENT, 0);

  return CMD_SUCCESS;
}

/* Print out routes update time. */
void
rip_vty_out_uptime (struct vty *vty, struct rip_info *rinfo)
{
  struct timeval timer_now;
  time_t clock;
  struct tm *tm;
#define TIME_BUF 25
  char timebuf [TIME_BUF];
  struct thread *thread;

  gettimeofday (&timer_now, NULL);

#ifdef HAVE_STRFTIME
  if ((thread = rinfo->t_timeout) != NULL)
    {
      clock = thread->u.sands.tv_sec - timer_now.tv_sec;
      tm = gmtime (&clock);
      strftime (timebuf, TIME_BUF, "%M:%S", tm);
      vty_out (vty, "%5s", timebuf);
    }
  else if ((thread = rinfo->t_garbage_collect) != NULL)
    {
      clock = thread->u.sands.tv_sec - timer_now.tv_sec;
      tm = gmtime (&clock);
      strftime (timebuf, TIME_BUF, "%M:%S", tm);
      vty_out (vty, "%5s", timebuf);
    }
#else
  if ((thread = rinfo->t_timeout) != NULL)
    {
      clock = thread->u.sands.tv_sec - timer_now.tv_sec;
      vty_out (vty, "%02d:%02d", clock / 60, clock % 60);
    }
  else if ((thread = rinfo->t_garbage_collect) != NULL)
    {
      clock = thread->u.sands.tv_sec - timer_now.tv_sec;
      vty_out (vty, "%02d:%02d", clock / 60, clock % 60);
    }
#endif
}

DEFUN (show_ip_rip,
       show_ip_rip_cmd,
       "show ip rip",
       SHOW_STR
       "Show RIP routes\n"
       "Show RIP routes\n")
{
  struct route_node *np;
  struct rip_info *rinfo;

  if (! rip)
    return CMD_SUCCESS;

  vty_out (vty, "%sCodes: R - RIP C - connected%s"
	   "   Network            Next Hop         Metric From            Time%s",
	   VTY_NEWLINE,
	   VTY_NEWLINE,
	   VTY_NEWLINE);
  
  for (np = route_top (rip->table); np; np = route_next (np))
    if ((rinfo = np->info) != NULL)
      {
	int len;

	len = vty_out (vty, "%s%s %s/%d",
		       /* np->lock, For debugging. */
		       route_info[rinfo->type].str,
		       " ",
		       inet_ntoa (np->p.u.prefix4), np->p.prefixlen);
	
	len = 22 - len;

	if (len > 0)
	  vty_out (vty, "%*s", len, " ");

        if (rinfo->nexthop.s_addr) 
	  vty_out (vty, "%-20s %2d ", inet_ntoa (rinfo->nexthop),
		   rinfo->metric);
        else
	  vty_out (vty, "                     %2d ", rinfo->metric);

	/* Route which exist in kernel routing table. */
	if ((rinfo->type == ZEBRA_ROUTE_RIP) && 
	    (rinfo->sub_type == RIP_ROUTE_RTE))
	  {
	    vty_out (vty, "%-15s ", inet_ntoa (rinfo->from));
	    rip_vty_out_uptime (vty, rinfo);
	  }
	else
	  vty_out (vty, "                     %2d ", rinfo->metric);

	vty_out (vty, "%s", VTY_NEWLINE);
      }
  return CMD_SUCCESS;
}

/* Return next event time. */
int
rip_next_thread_timer (struct thread *thread)
{
  struct timeval timer_now;

  gettimeofday (&timer_now, NULL);

  return thread->u.sands.tv_sec - timer_now.tv_sec;
}

DEFUN (show_ip_protocols_rip,
       show_ip_protocols_rip_cmd,
       "show ip protocols",
       SHOW_STR
       IP_STR
       "Routing protocol information\n")
{
  listnode node;
  struct interface *ifp;
  struct rip_interface *ri;
  extern struct message ri_version_msg[];
  char *send_version;
  char *receive_version;

  if (!rip)
    return CMD_SUCCESS;

  vty_out (vty, "Routing Protocol is \"rip\"%s", VTY_NEWLINE);
  vty_out (vty, "  Sending updates every %d seconds with +/-50%%,",
	   rip->update_time);
  vty_out (vty, " next due in %d seconds%s", 
	   rip_next_thread_timer (rip->t_update),
	   VTY_NEWLINE);
  vty_out (vty, "  Timeout after %d seconds,", rip->timeout_time);
  vty_out (vty, " garbage collect after %d seconds%s", rip->garbage_time,
	   VTY_NEWLINE);
  vty_out (vty, "  Outgoing update filter list for all interface is %s%s",
	   "not set", VTY_NEWLINE);
  vty_out (vty, "  Incoming update filter list for all interface is %s%s",
	   "not set", VTY_NEWLINE);

  /* Redistribute information. */
  vty_out (vty, "  Redistributing:");
  config_write_rip_redistribute (vty, 0);
  vty_out (vty, "%s", VTY_NEWLINE);

  vty_out (vty, "  Default version control: send version %d,", rip->version);
  vty_out (vty, " receive version %d %s", rip->version,
	   VTY_NEWLINE);

  /*  vty_out (vty, "    Interface        Send  Recv   Key-chain%s", VTY_NEWLINE); */
  vty_out (vty, "    Interface        Send  Recv%s", VTY_NEWLINE);

  for (node = listhead (iflist); node; node = nextnode (node))
    {
      ifp = getdata (node);
      ri = ifp->info;

      if (ri->enable_network || ri->enable_interface)
	{
	  if (ri->ri_send == RI_RIP_UNSPEC)
	    send_version = lookup (ri_version_msg, rip->version);
	  else
	    send_version = lookup (ri_version_msg, ri->ri_send);

	  if (ri->ri_receive == RI_RIP_UNSPEC)
	    receive_version = lookup (ri_version_msg, rip->version);
	  else
	    receive_version = lookup (ri_version_msg, ri->ri_receive);
	
	  vty_out (vty, "    %-17s%-3s   %-3s%s", ifp->name,
		   send_version,
		   receive_version,
		   VTY_NEWLINE);
	}
    }

  vty_out (vty, "  Routing for Networks:%s", VTY_NEWLINE);
  config_write_rip_network (vty, 0);  

  vty_out (vty, "  Routing Information Sources:%s", VTY_NEWLINE);
  vty_out (vty, "    Gateway          BadPackets BadRoutes  Distance Last Update%s",
	   VTY_NEWLINE);
  rip_peer_display (vty);

#if 0
  for (;;)
    break;
  vty_out (vty, "  Distance: (default is 120)%s", VTY_NEWLINE);
#endif /* 0 */

  return CMD_SUCCESS;
}

/* RIP configuration write function. */
int
config_write_rip (struct vty *vty)
{
  int write = 0;
  struct route_node *node;

  if (rip)
    {
      /* Router RIP statement. */
      vty_out (vty, "router rip%s", VTY_NEWLINE);
      write++;
  
      /* RIP version statement.  Default is RIP version 2. */
      if (rip->version != RIPv2)
	vty_out (vty, " version %d%s", rip->version,
		 VTY_NEWLINE);

      /* RIP enabled network and interface configuration. */
      config_write_rip_network (vty, 1);

      /* Redistribute configuration. */
      config_write_rip_redistribute (vty, 1);

      /* RIP timer configuration. */
      if (rip->update_time != RIP_UPDATE_TIMER_DEFAULT 
	  || rip->timeout_time != RIP_TIMEOUT_TIMER_DEFAULT 
	  || rip->garbage_time != RIP_GARBAGE_TIMER_DEFAULT)
	vty_out (vty, " timers basic %lu %lu %lu%s",
		 rip->update_time,
		 rip->timeout_time,
		 rip->garbage_time,
		 VTY_NEWLINE);

      /* RIP static route configuration. */
      for (node = route_top (rip->route); node; node = route_next (node))
	if (node->info)
	  vty_out (vty, " route %s/%d%s", 
		   inet_ntoa (node->p.u.prefix4),
		   node->p.prefixlen,
		   VTY_NEWLINE);

      /* Distribute configuration. */
      write += config_write_distribute (vty);

    }
  return write;
}

/* RIP node structure. */
struct cmd_node rip_node =
{
  RIP_NODE,
  "%s(config-router)# ",
};

void
rip_distribute_update (struct distribute *dist)
{
  struct interface *ifp;
  struct rip_interface *ri;
  struct access_list *alist;
  struct prefix_list *plist;

  ifp = if_lookup_by_name (dist->ifname);
  if (ifp == NULL)
    return;

  ri = ifp->info;

  if (dist->list[DISTRIBUTE_IN])
    {
      alist = access_list_lookup (AF_INET, dist->list[DISTRIBUTE_IN]);
      if (alist)
	ri->list[RIP_FILTER_IN] = alist;
      else
	ri->list[RIP_FILTER_IN] = NULL;
    }
  else
    ri->list[RIP_FILTER_IN] = NULL;

  if (dist->list[DISTRIBUTE_OUT])
    {
      alist = access_list_lookup (AF_INET, dist->list[DISTRIBUTE_OUT]);
      if (alist)
	ri->list[RIP_FILTER_OUT] = alist;
      else
	ri->list[RIP_FILTER_OUT] = NULL;
    }
  else
    ri->list[RIP_FILTER_OUT] = NULL;

  if (dist->prefix[DISTRIBUTE_IN])
    {
      plist = prefix_list_lookup (AF_INET, dist->prefix[DISTRIBUTE_IN]);
      if (plist)
	ri->prefix[RIP_FILTER_IN] = plist;
      else
	ri->prefix[RIP_FILTER_IN] = NULL;
    }
  else
    ri->prefix[RIP_FILTER_IN] = NULL;

  if (dist->prefix[DISTRIBUTE_OUT])
    {
      plist = prefix_list_lookup (AF_INET, dist->prefix[DISTRIBUTE_OUT]);
      if (plist)
	ri->prefix[RIP_FILTER_OUT] = plist;
      else
	ri->prefix[RIP_FILTER_OUT] = NULL;
    }
  else
    ri->prefix[RIP_FILTER_OUT] = NULL;
}

void
rip_distribute_update_interface (struct interface *ifp)
{
  struct distribute *dist;

  dist = distribute_lookup (ifp->name);
  if (dist)
    rip_distribute_update (dist);
}

/* Update all interface's distribute list. */
void
rip_distribute_update_all ()
{
  struct interface *ifp;
  listnode node;

  for (node = listhead (iflist); node; nextnode (node))
    {
      ifp = getdata (node);
      rip_distribute_update_interface (ifp);
    }
}

/* Delete all added rip route. */
void
rip_clean ()
{
  struct route_node *rp;
  struct rip_info *rinfo;

  /* Clear RIP routes */
  if (rip)
    {
      for (rp = route_top (rip->table); rp; rp = route_next (rp))
	if ((rinfo = rp->info) != NULL)
	  {
	    if (rinfo->type == ZEBRA_ROUTE_RIP &&
		rinfo->sub_type == RIP_ROUTE_RTE)
	      rip_zebra_ipv4_delete ((struct prefix_ipv4 *)&rp->p,
				     &rinfo->nexthop, rinfo->ifindex);
	
	    RIP_TIMER_OFF (rinfo->t_timeout);
	    RIP_TIMER_OFF (rinfo->t_garbage_collect);

	    rp->info = NULL;
	    route_unlock_node (rp);

	    rip_info_free (rinfo);
	  }

      /* Cancel RIP related timers. */
      RIP_TIMER_OFF (rip->t_update);
      RIP_TIMER_OFF (rip->t_triggered_update);
      RIP_TIMER_OFF (rip->t_triggered_interval);

      if (rip->t_read)
	thread_cancel (rip->t_read);

      if (rip->sock >= 0)
	{
	  close (rip->sock);
	  rip->sock = -1;
	}

      /* Looks like these will leak unless we free them */
      stream_free(rip->obuf);			rip->obuf = NULL;
      route_table_finish(rip->table);		rip->table = NULL;
      route_table_finish(rip->route);		rip->route = NULL;
      route_table_finish(rip->neighbor);	rip->neighbor = NULL;

      free (rip);
      rip = NULL;
    }
  rip_clean_network ();
}



/* Reset all values to the default settings. */
void
rip_reset ()
{
  /* Reset global counters. */
  rip_global_route_changes = 0;
  rip_global_queries = 0;

  /* Call ripd related reset functions. */
  rip_zclient_reset ();
  rip_debug_reset ();
  rip_route_map_reset ();

  /* Call library reset functions. */
  vty_reset ();
  access_list_reset ();
  prefix_list_reset ();
  distribute_list_reset ();
}

/* Allocate new rip structure and set default value. */
void
rip_init ()
{
  /* Randomize. */
  srand (time (NULL));

  /* Install top nodes. */
  install_node (&rip_node, config_write_rip);

  /* Install rip commands. */
  install_element (VIEW_NODE, &show_ip_rip_cmd);
  install_element (VIEW_NODE, &show_ip_protocols_rip_cmd);
  install_element (ENABLE_NODE, &show_ip_rip_cmd);
  install_element (ENABLE_NODE, &show_ip_protocols_rip_cmd);
  install_element (CONFIG_NODE, &router_rip_cmd);

  install_default (RIP_NODE);
  install_element (RIP_NODE, &rip_version_cmd);
  install_element (RIP_NODE, &rip_timers_cmd);
  install_element (RIP_NODE, &no_rip_timers_cmd);
  install_element (RIP_NODE, &rip_route_cmd);
  install_element (RIP_NODE, &no_rip_route_cmd);

  /* Debug related init. */
  rip_debug_init ();

  /* Filter related init. */
  rip_route_map_init ();

  /* SNMP init. */
#ifdef HAVE_SNMP
  rip_snmp_init ();
#endif /* HAVE_SNMP */

  /* Access list install. */
  access_list_init ();
  access_list_add_hook (rip_distribute_update_all);
  access_list_delete_hook (rip_distribute_update_all);

  /* Prefix list initialize.*/
  prefix_list_init ();
  prefix_list_add_hook (rip_distribute_update_all);
  prefix_list_delete_hook (rip_distribute_update_all);

  /* Distribute list install. */
  distribute_list_init (RIP_NODE);
  distribute_list_add_hook (rip_distribute_update);
  distribute_list_delete_hook (rip_distribute_update);
}
