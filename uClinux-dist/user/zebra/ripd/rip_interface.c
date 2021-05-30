/*
 * Interface related function for RIP.
 * Copyright (C) 1997, 98 Kunihiro Ishiguro
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

#include "command.h"
#include "if.h"
#include "sockunion.h"
#include "prefix.h"
#include "memory.h"
#include "network.h"
#include "table.h"
#include "roken.h"
#include "log.h"
#include "stream.h"
#include "thread.h"
#include "zclient.h"
#include "filter.h"

#include "zebra/connected.h"

#include "ripd/ripd.h"
#include "ripd/rip_debug.h"

void rip_enable_apply (struct interface *);
int rip_if_down(struct interface *ifp);

struct message ri_version_msg[] = 
{
  {RI_RIP_VERSION_1,       "1"},
  {RI_RIP_VERSION_2,       "2"},
  {RI_RIP_VERSION_1_AND_2, "1 2"},
  {RI_RIP_NONE,            "none"},
  {0,                      NULL}
};

/* Join to the RIP version 2 multicast group. */
int
ipv4_multicast_join (int sock, struct in_addr group, struct in_addr ifa)
{
  int ret;
  struct ip_mreq mreq;

  mreq.imr_multiaddr.s_addr = group.s_addr;
  mreq.imr_interface.s_addr = ifa.s_addr;

  ret = setsockopt (sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, 
		    (char *)&mreq, sizeof (mreq));

  if (ret < 0) 
    zlog (NULL, LOG_INFO, "can't setsockopt IP_ADD_MEMBERSHIP");

  return ret;
}

/* Leave from the RIP version 2 multicast group. */
int
ipv4_multicast_leave (int sock, struct in_addr group, struct in_addr ifa)
{
  int ret;
  struct ip_mreq mreq;

  mreq.imr_multiaddr.s_addr = group.s_addr;
  mreq.imr_interface.s_addr = ifa.s_addr;

  ret = setsockopt (sock, IPPROTO_IP, IP_DROP_MEMBERSHIP, 
		    (char *)&mreq, sizeof (mreq));

  if (ret < 0) 
    zlog (NULL, LOG_INFO, "can't setsockopt IP_DROP_MEMBERSHIP");

  return ret;
}

/* Allocate new RIP's interface configuration. */
struct rip_interface *
rip_interface_new ()
{
  struct rip_interface *ri;

  ri = XMALLOC (MTYPE_IF, sizeof (struct rip_interface));
  bzero (ri, sizeof (struct rip_interface));

  ri->auth_type = RIP_NO_AUTH;

  return ri;
}

void
rip_interface_multicast_set (int sock, struct interface *ifp)
{
  int ret;
  listnode node;
  struct servent *sp;
  struct sockaddr_in from;

  for (node = listhead (ifp->connected); node; nextnode (node))
    {
      struct prefix_ipv4 *p;
      struct connected *connected;
      struct in_addr addr;

      connected = getdata (node);
      p = (struct prefix_ipv4 *) connected->address;

      if (p->family == AF_INET)
	{
	  addr = p->prefix;

	  if (setsockopt (sock, IPPROTO_IP, IP_MULTICAST_IF,
			  (void *) &addr, sizeof (struct in_addr)) < 0) 
	    {
	      zlog_warn ("Can't setsockopt IP_MULTICAST_IF to fd %d", sock);
	      return;
	    }

	  /* Bind myself. */
	  bzero (&from, sizeof (struct sockaddr_in));

	  /* Set RIP port. */
	  sp = getservbyname ("router", "udp");
	  if (sp) 
	    from.sin_port = sp->s_port;
	  else 
	    from.sin_port = htons (RIP_PORT_DEFAULT);

	  /* Address shoud be any address. */
	  from.sin_family = AF_INET;
	  from.sin_addr = addr;
#ifdef HAVE_SIN_LEN
	  from.sin_len = sizeof (struct sockaddr_in);
#endif /* HAVE_SIN_LEN */

	  ret = bind (sock, (struct sockaddr *) & from, 
		      sizeof (struct sockaddr_in));
	  if (ret < 0)
	    {
	      zlog_warn ("Can't bind socket: %s", strerror (errno));
	      return;
	    }

	  return;

	}
    }
}

/* Send RIP request packet to specified interface. */
void
rip_request_interface_send (struct interface *ifp, u_char version)
{
  struct sockaddr_in to;

  /* RIPv2 support multicast. */
  if (version == RIPv2 && if_is_multicast (ifp))
    {
      
      if (IS_RIP_DEBUG_EVENT)
	zlog_info ("multicast request on %s", ifp->name);

      rip_request_send (NULL, ifp, version);
      return;
    }

  /* RIPv1 and non multicast interface. */
  if (if_is_pointopoint (ifp) || if_is_broadcast (ifp))
    {
      listnode cnode;

      if (IS_RIP_DEBUG_EVENT)
	zlog_info ("broadcast request to %s", ifp->name);

      for (cnode = listhead (ifp->connected); cnode; nextnode (cnode))
	{
	  struct prefix_ipv4 *p;
	  struct connected *connected;

	  connected = getdata (cnode);
	  p = (struct prefix_ipv4 *) connected->destination;

	  if (p->family == AF_INET)
	    {
	      bzero (&to, sizeof (struct sockaddr_in));
	      to.sin_port = htons (RIP_PORT_DEFAULT);
	      to.sin_addr = p->prefix;

#if 0
	      if (IS_RIP_DEBUG_EVENT)
		zlog_info ("SEND request to %s", inet_ntoa (to.sin_addr));
#endif /* 0 */
	      
	      rip_request_send (&to, ifp, version);
	    }
	}
    }
}

/* This will be executed when interface goes up. */
void
rip_request_interface (struct interface *ifp)
{
  struct rip_interface *ri;

  /* In default ripd doesn't send RIP_REQUEST to the loopback interface. */
  if (if_is_loopback (ifp))
    return;

  /* If interface is down, don't send RIP packet. */
  if (! if_is_up (ifp))
    return;

  /* Fetch RIP interface information. */
  ri = ifp->info;


  /* If there is no version configuration in the interface,
     use rip's version setting. */
  if (ri->ri_send == RI_RIP_UNSPEC)
    {
      if (rip->version == RIPv1)
	rip_request_interface_send (ifp, RIPv1);
      else
	rip_request_interface_send (ifp, RIPv2);
    }
  /* If interface has RIP version configuration use it. */
  else
    {
      if (ri->ri_send & RIPv1)
	rip_request_interface_send (ifp, RIPv1);
      if (ri->ri_send & RIPv2)
	rip_request_interface_send (ifp, RIPv2);
    }
}

/* Send RIP request to the neighbor. */
void
rip_request_neighbor (struct in_addr addr)
{
  struct sockaddr_in to;

  bzero (&to, sizeof (struct sockaddr_in));
  to.sin_port = htons (RIP_PORT_DEFAULT);
  to.sin_addr = addr;

  rip_request_send (&to, NULL, rip->version);
}

/* Request routes at all interfaces. */
void
rip_request_neighbor_all ()
{
  struct route_node *rp;

  if (! rip)
    return;

  if (IS_RIP_DEBUG_EVENT)
    zlog_info ("request to the all neighbor");

  /* Send request to all neighbor. */
  for (rp = route_top (rip->neighbor); rp; rp = route_next (rp))
    if (rp->info)
      rip_request_neighbor (rp->p.u.prefix4);
}

/* Multicast packet receive socket. */
void
rip_multicast_join (struct interface *ifp, int sock)
{
  listnode cnode;

  if (if_is_up (ifp) && if_is_multicast (ifp))
    {
      if (IS_RIP_DEBUG_EVENT)
	zlog_info ("multicast join at %s", ifp->name);

      for (cnode = listhead (ifp->connected); cnode; nextnode (cnode))
	{
	  struct prefix_ipv4 *p;
	  struct connected *connected;
	  struct in_addr group;
	      
	  connected = getdata (cnode);
	  p = (struct prefix_ipv4 *) connected->address;
      
	  if (p->family != AF_INET)
	    continue;
      
	  group.s_addr = htonl (INADDR_RIP_GROUP);
	  ipv4_multicast_join (sock, group, p->prefix);
	}
    }
}

/* Leave from multicast group. */
void
rip_multicast_leave (struct interface *ifp, int sock)
{
  listnode cnode;

  if (if_is_up (ifp) && if_is_multicast (ifp))
    {
      if (IS_RIP_DEBUG_EVENT)
	zlog_info ("multicast leave from %s", ifp->name);

      for (cnode = listhead (ifp->connected); cnode; nextnode (cnode))
	{
	  struct prefix_ipv4 *p;
	  struct connected *connected;
	  struct in_addr group;
	      
	  connected = getdata (cnode);
	  p = (struct prefix_ipv4 *) connected->address;
      
	  if (p->family != AF_INET)
	    continue;
      
	  group.s_addr = htonl (INADDR_RIP_GROUP);
	  ipv4_multicast_leave (sock, group, p->prefix);
	}
    }
}

/* Does this address belong to me ? */
int
if_check_address (struct in_addr addr)
{
  listnode node;

  for (node = listhead (iflist); node; nextnode (node))
    {
      listnode cnode;
      struct interface *ifp;

      ifp = getdata (node);

      for (cnode = listhead (ifp->connected); cnode; nextnode (cnode))
	{
	  struct connected *connected;
	  struct prefix_ipv4 *p;

	  connected = getdata (cnode);
	  p = (struct prefix_ipv4 *) connected->address;

	  if (p->family != AF_INET)
	    continue;
	  if (IPV4_ADDR_CMP (&p->prefix, &addr) == 0)
	    return 1;
	}
    }
  return 0;
}

/* is this address from a valid neighbor? (RFC2453 - Sec. 3.9.2) */
int
if_valid_neighbor (struct in_addr addr)
{
  listnode node;
  struct connected *connected = NULL;
  struct prefix_ipv4 *p;

  for (node = listhead (iflist); node; nextnode (node))
    {
      listnode cnode;
      struct interface *ifp;

      ifp = getdata (node);

      for (cnode = listhead (ifp->connected); cnode; nextnode (cnode))
	{
	  struct prefix *pxn = NULL; /* Prefix of the neighbor */
	  struct prefix *pxc = NULL; /* Prefix of the connected network */

	  connected = getdata (cnode);

	  if (if_is_pointopoint (ifp))
	    {
	      p = (struct prefix_ipv4 *) connected->address;

	      if (p && p->family == AF_INET)
		{
		  if (IPV4_ADDR_SAME (&p->prefix, &addr))
		    return 1;

		  p = (struct prefix_ipv4 *) connected->destination;
		  if (p && IPV4_ADDR_SAME (&p->prefix, &addr))
		    return 1;
		}
	    }
	  else
	    {
	      p = (struct prefix_ipv4 *) connected->address;

	      if (p->family != AF_INET)
		continue;

	      pxn = prefix_new();
	      pxn->family = AF_INET;
	      pxn->prefixlen = 32;
	      pxn->u.prefix4 = addr;
	      
	      pxc = prefix_new();
	      prefix_copy(pxc, (struct prefix *) p);
	      apply_mask(pxc);
	  
	      if (prefix_match (pxc, pxn)) 
		{
		  prefix_free (pxn);
		  prefix_free (pxc);
		  return 1;
		}
	      prefix_free(pxc);
	      prefix_free(pxn);
	    }
	}
    }
  return 0;
}

/* Inteface link down message processing. */
int
rip_interface_down (int command, struct zebra *zebra, zebra_size_t length)
{
  struct interface *ifp;
  struct stream *s;

  s = zebra->ibuf;  
  /* zebra_interface_state_read() updates interface structure in iflist */
  ifp = zebra_interface_state_read(s);

  if (ifp == NULL)
    return 0;

  rip_if_down(ifp);
 
  return 0;
}

/* Inteface link up message processing */
int
rip_interface_up (int command, struct zebra *zebra, zebra_size_t length)
{
  struct interface *ifp;
  /* zebra_interface_state_read() updates interface structure in iflist */
  ifp = zebra_interface_state_read(zebra->ibuf);

  if (ifp == NULL)
    return 0;

  if (IS_RIP_DEBUG_ZEBRA)
    zlog_info ("interface %s index %d flags %d metric %d mtu %d is up",
	       ifp->name, ifp->ifindex, ifp->flags, ifp->metric, ifp->mtu);

  /* Check if this interface is RIP enabled or not.*/
  rip_enable_apply (ifp);
 
  /* Apply distribute list to the all interface. */
  rip_distribute_update_interface (ifp);

  return 0;
}

/* Inteface addition message from zebra. */
int
rip_interface_add (int command, struct zebra *zebra, zebra_size_t length)
{
  struct interface *ifp;

  ifp = zebra_interface_add_read (zebra->ibuf);

  if (IS_RIP_DEBUG_ZEBRA)
    zlog_info ("interface add %s index %d flags %d metric %d mtu %d",
	       ifp->name, ifp->ifindex, ifp->flags, ifp->metric, ifp->mtu);

  /* Check if this interface is RIP enabled or not.*/
  rip_enable_apply (ifp);

  /* Apply distribute list to the all interface. */
  rip_distribute_update_interface (ifp);

  /* rip_request_neighbor_all (); */

  return 0;
}

int
rip_interface_delete (int command, struct zebra *zebra, zebra_size_t length)
{
  struct interface *ifp;
  struct stream *s;


  s = zebra->ibuf;  
  /* zebra_interface_state_read() updates interface structure in iflist */
  ifp = zebra_interface_state_read(s);

  if (ifp == NULL)
    return 0;

  if (if_is_up (ifp)){
    rip_if_down(ifp);
  } 
  
  zlog_info("interface delete %s index %d flags %d metric %d mtu %d",
	    ifp->name, ifp->ifindex, ifp->flags, ifp->metric, ifp->mtu);  
  
  if_delete(ifp);

  return 0;
}

int
rip_if_down(struct interface *ifp)
{
  struct route_node *rp;
  struct rip_info *rinfo;
  struct rip_interface *ri = NULL;

    /* Clear RIP dynamic routes on the interface*/
  if (rip)
    {
      for (rp = route_top (rip->table); rp; rp = route_next (rp))
	if ((rinfo = rp->info) != NULL)
	  {
	    /* routes got through RIP */
	    if (rinfo->ifindex == ifp->ifindex &&
		rinfo->type == ZEBRA_ROUTE_RIP &&
		rinfo->sub_type == RIP_ROUTE_RTE){

	      rip_zebra_ipv4_delete ( (struct prefix_ipv4 *)&rp->p,
				      &rinfo->nexthop,rinfo->ifindex);

	      RIP_TIMER_OFF (rinfo->t_timeout);
	      RIP_TIMER_OFF (rinfo->t_garbage_collect);
	      
	      rp->info = NULL;
	      route_unlock_node (rp);
	      
	      rip_info_free (rinfo);
	    }
	    else
	      /* all redistributed routes but kernel and static and system */
	      if ((rinfo->ifindex == ifp->ifindex) &&
		  (rinfo->type != ZEBRA_ROUTE_STATIC) &&
		  (rinfo->type != ZEBRA_ROUTE_KERNEL) &&
		  (rinfo->type != ZEBRA_ROUTE_SYSTEM)){

		rip_redistribute_delete(rinfo->type,rinfo->sub_type,
					(struct prefix_ipv4 *)&rp->p,
					rinfo->ifindex);
	      }
	  }
    }
	    
  ri = ifp->info;
  
  if (ri->running)
   {
     if (IS_RIP_DEBUG_EVENT)
       zlog_info ("turn off %s", ifp->name);

     /* Leave from multicast group. */
     rip_multicast_leave (ifp, rip->sock);

     ri->running = 0;
   }

  if (IS_RIP_DEBUG_ZEBRA)
    zlog_info ("interface %s index %d flags %d metric %d mtu %d is down",
	       ifp->name, ifp->ifindex, ifp->flags, ifp->metric, ifp->mtu);

  return 0;
}

int
rip_interface_address_add (int command, struct zebra *zebra,
			   zebra_size_t length)
{
  struct connected *c;
  struct prefix *p;

  c = zebra_interface_address_add_read (zebra->ibuf);

  if (c == NULL)
    return 0;

  if (IS_RIP_DEBUG_ZEBRA)
    {
      p = c->address;
      if (p->family == AF_INET)
	zlog_info ("connected address %s/%d", 
		   inet_ntoa (p->u.prefix4), p->prefixlen);
    }

  /* Check is this interface is RIP enabled or not.*/
  rip_enable_apply (c->ifp);

  return 0;
}

int
rip_interface_address_delete (int command, struct zebra *zebra,
			      zebra_size_t length)
{
  return 0;
}

/* RIP enabled network vector. */
vector rip_enable_if;

/* RIP enabled interface table. */
struct route_table *rip_enable_network;

/* Check interface is enabled by network statement. */
int
rip_enable_network_lookup (struct interface *ifp)
{
  listnode listnode;
  struct connected *connected;

  for (listnode = listhead (ifp->connected); listnode; nextnode (listnode))
    if ((connected = getdata (listnode)) != NULL)
      {
	struct prefix *p; 
	struct route_node *node;

	p = connected->address;

	if (p->family == AF_INET)
	  {
	    node = route_node_match (rip_enable_network, p);
	    if (node)
	      {
		route_unlock_node (node);
		return 1;
	      }
	  }
      }
  return -1;
}

/* Add RIP enable network. */
int
rip_enable_network_add (struct prefix *p)
{
  struct route_node *node;

  node = route_node_get (rip_enable_network, p);

  if (node->info)
    {
      route_unlock_node (node);
      return -1;
    }
  else
    node->info = "enabled";

  return 1;
}

/* Delete RIP enable network. */
int
rip_enable_network_delete (struct prefix *p)
{
  struct route_node *node;

  node = route_node_lookup (rip_enable_network, p);
  if (node)
    {
      node->info = NULL;

      /* Unlock info lock. */
      route_unlock_node (node);

      /* Unlock lookup lock. */
      route_unlock_node (node);

      return 1;
    }
  return -1;
}

/* Check interface is enabled by ifname statement. */
int
rip_enable_if_lookup (char *ifname)
{
  int i;
  char *str;

  for (i = 0; i < vector_max (rip_enable_if); i++)
    if ((str = vector_slot (rip_enable_if, i)) != NULL)
      if (strcmp (str, ifname) == 0)
	return i;
  return -1;
}

/* Add interface to rip_enable_if. */
int
rip_enable_if_add (char *ifname)
{
  int ret;

  ret = rip_enable_if_lookup (ifname);
  if (ret >= 0)
    return -1;

  vector_set (rip_enable_if, strdup (ifname));

  return 1;
}

/* Delete interface from rip_enable_if. */
int
rip_enable_if_delete (char *ifname)
{
  int index;
  char *str;

  index = rip_enable_if_lookup (ifname);
  if (index < 0)
    return -1;

  str = vector_slot (rip_enable_if, index);
  free (str);
  vector_unset (rip_enable_if, index);

  return 1;
}

/* Join to multicast group and send request to the interface. */
int
rip_interface_wakeup (struct thread *t)
{
  struct interface *ifp;
  struct rip_interface *ri;

  /* Get interface. */
  ifp = THREAD_ARG (t);

  ri = ifp->info;
  ri->t_wakeup = NULL;

  /* Join to multicast group. */
  rip_multicast_join (ifp, rip->sock);

  /* Send RIP request to the interface. */
  rip_request_interface (ifp);

  return 0;
}

/* Update interface status. */
void
rip_enable_apply (struct interface *ifp)
{
  int ret;
  struct rip_interface *ri = NULL;

  /* Check interface. */
  if (if_is_loopback (ifp))
    return;

  if (! if_is_up (ifp))
    return;

  ri = ifp->info;

  /* Check network configuration. */
  ret = rip_enable_network_lookup (ifp);

  /* If the interface is matched. */
  if (ret > 0)
    ri->enable_network = 1;
  else
    ri->enable_network = 0;

  /* Check interface name configuration. */
  ret = rip_enable_if_lookup (ifp->name);
  if (ret >= 0)
    ri->enable_interface = 1;
  else
    ri->enable_interface = 0;

  /* Update running status of the interface. */
  if (ri->enable_network || ri->enable_interface)
    {
      if (! ri->running)
	{
	  if (IS_RIP_DEBUG_EVENT)
	    zlog_info ("turn on %s", ifp->name);

	  /* Add interface wake up thread. */
	  if (! ri->t_wakeup)
	    ri->t_wakeup = thread_add_timer (master, rip_interface_wakeup,
					     ifp, 1);
#if 0
	  /* Join to multicast group. */
	  rip_multicast_join (ifp, rip->sock);

	  /* Send RIP request to the interface. */
	  rip_request_interface (ifp);
#endif /* 0 */

	  ri->running = 1;
	}
    }
  else
    {
      if (ri->running)
	{
	  if (IS_RIP_DEBUG_EVENT)
	    zlog_info ("turn off %s", ifp->name);

	  /* Leave from multicast group. */
	  rip_multicast_leave (ifp, rip->sock);

	  ri->running = 0;
	}
    }
}

/* Apply network configuration to all interface. */
void
rip_enable_apply_all ()
{
  struct interface *ifp;
  listnode node;

  /* Check each interface. */
  for (node = listhead (iflist); node; nextnode (node))
    {
      ifp = getdata (node);
      rip_enable_apply (ifp);
    }
}

int
rip_neighbor_lookup (struct sockaddr_in *from)
{
  struct prefix_ipv4 p;
  struct route_node *node;

  memset (&p, 0, sizeof (struct prefix_ipv4));
  p.family = AF_INET;
  p.prefix = from->sin_addr;
  p.prefixlen = IPV4_MAX_BITLEN;

  node = route_node_lookup (rip->neighbor, (struct prefix *) &p);
  if (node)
    {
      route_unlock_node (node);
      return 1;
    }
  return 0;
}

/* Add new RIP neighbor to the neighbor tree. */
int
rip_neighbor_add (struct prefix_ipv4 *p)
{
  struct route_node *node;

  node = route_node_get (rip->neighbor, (struct prefix *) p);

  if (node->info)
    return -1;

  node->info = rip->neighbor;

  return 0;
}

/* Delete RIP neighbor from the neighbor tree. */
int
rip_neighbor_delete (struct prefix_ipv4 *p)
{
  struct route_node *node;

  /* Lock for look up. */
  node = route_node_lookup (rip->neighbor, (struct prefix *) p);

  if (! node)
    return -1;
  
  node->info = NULL;

  /* Unlock lookup lock. */
  route_unlock_node (node);

  /* Unlock real neighbor information lock. */
  route_unlock_node (node);

  return 0;
}

/* Clear all network and neighbor configuration. */
void
rip_clean_network ()
{
  int i;
  char *str;

  for (i = 0; i < vector_max (rip_enable_if); i++)
    if ((str = vector_slot (rip_enable_if, i)) != NULL)
      {
	free (str);
	vector_slot (rip_enable_if, i) = NULL;
      }
}

/* RIP enable network or interface configuration. */
DEFUN (rip_network,
       rip_network_cmd,
       "network IPV4_ADDR",
       "Enable RIP\n"
       "IP prefix or interface name\n")
{
  int ret;
  struct prefix_ipv4 p;

  ret = str2prefix_ipv4 (argv[0], &p);

  if (ret)
    ret = rip_enable_network_add ((struct prefix *) &p);
  else
    ret = rip_enable_if_add (argv[0]);

  if (ret < 0)
    {
      vty_out (vty, "There is a same network configuration %s%s", argv[0],
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  rip_enable_apply_all ();

  return CMD_SUCCESS;
}

/* RIP enable network or interface configuration. */
DEFUN (no_rip_network,
       no_rip_network_cmd,
       "no network IPV4_ADDR",
       NO_STR
       "Disable RIP\n"
       "IP prefix or interface name\n")
{
  int ret;
  struct prefix_ipv4 p;

  ret = str2prefix_ipv4 (argv[0], &p);

  if (ret)
    ret = rip_enable_network_delete ((struct prefix *) &p);
  else
    ret = rip_enable_if_delete (argv[0]);

  if (ret < 0)
    {
      vty_out (vty, "Can't find network configuration %s%s", argv[0],
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  rip_enable_apply_all ();

  return CMD_SUCCESS;
}

/* RIP neighbor configuration set. */
DEFUN (rip_neighbor,
       rip_neighbor_cmd,
       "neighbor A.B.C.D",
       "RIP neighbor router address specification\n"
       "Address of the neighbor router\n")
{
  int ret;
  struct prefix_ipv4 p;

  ret = str2prefix_ipv4 (argv[0], &p);

  if (ret <= 0)
    {
      vty_out (vty, "Please specify address by A.B.C.D%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  rip_neighbor_add (&p);
  
  return CMD_SUCCESS;
}

/* RIP neighbor configuration unset. */
DEFUN (no_rip_neighbor,
       no_rip_neighbor_cmd,
       "no neighbor A.B.C.D",
       NO_STR
       "RIP neighbor router address specification\n"
       "Address of the neighbor router\n")
{
  int ret;
  struct prefix_ipv4 p;

  ret = str2prefix_ipv4 (argv[0], &p);

  if (ret <= 0)
    {
      vty_out (vty, "Please specify address by A.B.C.D%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  rip_neighbor_delete (&p);
  
  return CMD_SUCCESS;
}

DEFUN (ip_rip_receive_version,
       ip_rip_receive_version_cmd,
       "ip rip receive version (1|2)",
       "IP Information\n"
       "RIP configuration\n"
       "Set interface's receive RIP version control\n"
       "RIP version\n"
       "RIP version 1\n"
       "RIP version 2\n")
{
  struct interface *ifp;
  struct rip_interface *ri;

  ifp = (struct interface *)vty->index;
  ri = ifp->info;

  /* Version 1. */
  if (atoi (argv[0]) == 1)
    {
      ri->ri_receive = RI_RIP_VERSION_1;
      return CMD_SUCCESS;
    }
  if (atoi (argv[0]) == 2)
    {
      ri->ri_receive = RI_RIP_VERSION_2;
      return CMD_SUCCESS;
    }
  return CMD_WARNING;
}

DEFUN (ip_rip_receive_version_1,
       ip_rip_receive_version_1_cmd,
       "ip rip receive version 1 2",
       "IP Information\n"
       "RIP configuration\n"
       "Set interface's receive RIP version control\n"
       "RIP version\n"
       "RIP version 1\n"
       "RIP version 2\n")
{
  struct interface *ifp;
  struct rip_interface *ri;

  ifp = (struct interface *)vty->index;
  ri = ifp->info;

  /* Version 1 and 2. */
  ri->ri_receive = RI_RIP_VERSION_1_AND_2;
  return CMD_SUCCESS;
}

DEFUN (ip_rip_receive_version_2,
       ip_rip_receive_version_2_cmd,
       "ip rip receive version 2 1",
       "IP Information\n"
       "RIP configuration\n"
       "Set interface's receive RIP version control\n"
       "RIP version\n"
       "RIP version 2\n"
       "RIP version 1\n")
{
  struct interface *ifp;
  struct rip_interface *ri;

  ifp = (struct interface *)vty->index;
  ri = ifp->info;

  /* Version 1 and 2. */
  ri->ri_receive = RI_RIP_VERSION_1_AND_2;
  return CMD_SUCCESS;
}

DEFUN (no_ip_rip_receive_version,
       no_ip_rip_receive_version_cmd,
       "no ip rip receive version",
       NO_STR
       IP_STR
       "RIP configuration\n"
       "Set interface's receive RIP version control\n"
       "RIP version\n")
{
  struct interface *ifp;
  struct rip_interface *ri;

  ifp = (struct interface *)vty->index;
  ri = ifp->info;

  ri->ri_receive = RI_RIP_UNSPEC;
  return CMD_SUCCESS;
}

DEFUN (ip_rip_send_version,
       ip_rip_send_version_cmd,
       "ip rip send version (1|2)",
       "IP Information\n"
       "RIP configuration\n"
       "Set interface's send RIP version control\n"
       "RIP version\n"
       "RIP version 1\n"
       "RIP version 2\n")
{
  struct interface *ifp;
  struct rip_interface *ri;

  ifp = (struct interface *)vty->index;
  ri = ifp->info;

  /* Version 1. */
  if (atoi (argv[0]) == 1)
    {
      ri->ri_send = RI_RIP_VERSION_1;
      return CMD_SUCCESS;
    }
  if (atoi (argv[0]) == 2)
    {
      ri->ri_send = RI_RIP_VERSION_2;
      return CMD_SUCCESS;
    }
  return CMD_WARNING;
}

DEFUN (ip_rip_send_version_1,
       ip_rip_send_version_1_cmd,
       "ip rip send version 1 2",
       "IP Information\n"
       "RIP configuration\n"
       "Set interface's send RIP version control\n"
       "RIP version\n"
       "RIP version 1\n"
       "RIP version 2\n")
{
  struct interface *ifp;
  struct rip_interface *ri;

  ifp = (struct interface *)vty->index;
  ri = ifp->info;

  /* Version 1 and 2. */
  ri->ri_send = RI_RIP_VERSION_1_AND_2;
  return CMD_SUCCESS;
}

DEFUN (ip_rip_send_version_2,
       ip_rip_send_version_2_cmd,
       "ip rip send version 2 1",
       "IP Information\n"
       "RIP configuration\n"
       "Set interface's send RIP version control\n"
       "RIP version\n"
       "RIP version 2\n"
       "RIP version 1\n")
{
  struct interface *ifp;
  struct rip_interface *ri;

  ifp = (struct interface *)vty->index;
  ri = ifp->info;

  /* Version 1 and 2. */
  ri->ri_send = RI_RIP_VERSION_1_AND_2;
  return CMD_SUCCESS;
}

DEFUN (no_ip_rip_send_version,
       no_ip_rip_send_version_cmd,
       "no ip rip send version",
       NO_STR
       IP_STR
       "RIP configuration\n"
       "Set interface's send RIP version control\n"
       "RIP version\n")
{
  struct interface *ifp;
  struct rip_interface *ri;

  ifp = (struct interface *)vty->index;
  ri = ifp->info;

  ri->ri_send = RI_RIP_UNSPEC;
  return CMD_SUCCESS;
}

DEFUN (ip_rip_authentication_string,
       ip_rip_authentication_string_cmd,
       "ip rip authentication string STRING",
       IP_STR
       "RIP configuration\n"
       "RIP authentication\n"
       "RIP authentication string setting\n"
       "RIP authentication string")
{
  struct interface *ifp;
  struct rip_interface *ri;

  ifp = (struct interface *)vty->index;
  ri = ifp->info;

  if (strlen (argv[0]) > 16)
    {
      vty_out (vty, "RIPv2 authentication string must be shorter than 16%s",
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (ri->auth_str)
    free (ri->auth_str);

  ri->auth_type = RIP_AUTH_SIMPLE_PASSWORD;
  ri->auth_str = strdup (argv[0]);

  return CMD_SUCCESS;
}

DEFUN (no_ip_rip_authentication_string,
       no_ip_rip_authentication_string_cmd,
       "no ip rip authentication string STRING",
       NO_STR
       IP_STR
       "RIP configuration\n"
       "RIP authentication\n"
       "RIP authentication string setting\n"
       "RIP authentication string")
{
  struct interface *ifp;
  struct rip_interface *ri;

  ifp = (struct interface *)vty->index;
  ri = ifp->info;

  if (ri->auth_str)
    free (ri->auth_str);

  ri->auth_type = RIP_NO_AUTH;
  ri->auth_str = NULL;

  return CMD_SUCCESS;
}

/* Write rip configuration of each interface. */
int
interface_config_write (struct vty *vty)
{
  listnode node;
  struct interface *ifp;

  for (node = listhead (iflist); node; nextnode (node))
    {
      struct rip_interface *ri;

      ifp = getdata (node);
      ri = ifp->info;

      vty_out (vty, "interface %s%s", ifp->name,
	       VTY_NEWLINE);

      if (ifp->desc)
	vty_out (vty, " description %s%s", ifp->desc,
		 VTY_NEWLINE);

      if (ri->ri_send != RI_RIP_UNSPEC)
	vty_out (vty, " ip rip send version %s%s",
		 lookup (ri_version_msg, ri->ri_send),
		 VTY_NEWLINE);

      if (ri->ri_receive != RI_RIP_UNSPEC)
	vty_out (vty, " ip rip receive version %s%s",
		 lookup (ri_version_msg, ri->ri_receive),
		 VTY_NEWLINE);

      if (ri->auth_str)
	vty_out (vty, " ip rip authentication string %s%s",
		 ri->auth_str,
		 VTY_NEWLINE);

      vty_out (vty, "!%s", VTY_NEWLINE);
    }
  return 0;
}

int
config_write_rip_network (struct vty *vty, int config_mode)
{
  int i;
  char *ifname;
  struct route_node *node;

  /* Network type RIP enable interface statement. */
  for (node = route_top (rip_enable_network); node; node = route_next (node))
    if (node->info)
      vty_out (vty, "%s%s/%d%s", 
	       config_mode ? " network " : "    ",
	       inet_ntoa (node->p.u.prefix4),
	       node->p.prefixlen,
	       VTY_NEWLINE);

  /* Interface name RIP enable statement. */
  for (i = 0; i < vector_max (rip_enable_if); i++)
    if ((ifname = vector_slot (rip_enable_if, i)) != NULL)
      vty_out (vty, "%s%s%s",
	       config_mode ? " network " : "    ",
	       ifname,
	       VTY_NEWLINE);

  /* RIP neighbors listing. */
  for (node = route_top (rip->neighbor); node; node = route_next (node))
    if (node->info)
      vty_out (vty, "%s%s%s", 
	       config_mode ? " neighbor " : "    ",
	       inet_ntoa (node->p.u.prefix4),
	       VTY_NEWLINE);

  return 0;
}

struct cmd_node interface_node =
{
  INTERFACE_NODE,
  "%s(config-if)# ",
};

/* Called when interface structure allocated. */
int
rip_interface_new_hook (struct interface *ifp)
{
  ifp->info = rip_interface_new ();
  return 0;
}

/* Allocate and initialize interface vector. */
void
rip_if_init ()
{
  /* Default initial size of interface vector. */
  if_init();
  if_add_hook (IF_NEW_HOOK, rip_interface_new_hook);

  /* RIP network init. */
  rip_enable_if = vector_init (1);
  rip_enable_network = route_table_init ();

  /* Install interface node. */
  install_node (&interface_node, interface_config_write);

  /* Install interface's commands. */
  install_element (CONFIG_NODE, &interface_cmd);
  install_element (INTERFACE_NODE, &config_end_cmd);
  install_element (INTERFACE_NODE, &config_exit_cmd);
  install_element (INTERFACE_NODE, &config_help_cmd);
  install_element (INTERFACE_NODE, &interface_desc_cmd);
  install_element (INTERFACE_NODE, &no_interface_desc_cmd);

  install_element (RIP_NODE, &rip_neighbor_cmd);
  install_element (RIP_NODE, &no_rip_neighbor_cmd);

  install_element (INTERFACE_NODE, &ip_rip_send_version_cmd);
  install_element (INTERFACE_NODE, &ip_rip_send_version_1_cmd);
  install_element (INTERFACE_NODE, &ip_rip_send_version_2_cmd);
  install_element (INTERFACE_NODE, &no_ip_rip_send_version_cmd);

  install_element (INTERFACE_NODE, &ip_rip_receive_version_cmd);
  install_element (INTERFACE_NODE, &ip_rip_receive_version_1_cmd);
  install_element (INTERFACE_NODE, &ip_rip_receive_version_2_cmd);
  install_element (INTERFACE_NODE, &no_ip_rip_receive_version_cmd);

  install_element (INTERFACE_NODE, &ip_rip_authentication_string_cmd);
  install_element (INTERFACE_NODE, &no_ip_rip_authentication_string_cmd);

  install_element (RIP_NODE, &rip_network_cmd);
  install_element (RIP_NODE, &no_rip_network_cmd);
}
