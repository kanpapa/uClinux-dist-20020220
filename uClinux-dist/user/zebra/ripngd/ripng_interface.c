/*
 * Interface related function for RIPng.
 * Copyright (C) 1998 Kunihiro Ishiguro
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

#include "linklist.h"
#include "if.h"
#include "prefix.h"
#include "memory.h"
#include "network.h"
#include "filter.h"
#include "log.h"
#include "stream.h"
#include "zclient.h"
#include "command.h"
#include "table.h"
#include "thread.h"

#include "ripngd/ripngd.h"
#include "ripngd/ripng_debug.h"

/* If RFC2133 definition is used. */
#ifndef IPV6_JOIN_GROUP
#define IPV6_JOIN_GROUP  IPV6_ADD_MEMBERSHIP 
#endif
#ifndef IPV6_LEAVE_GROUP
#define IPV6_LEAVE_GROUP IPV6_DROP_MEMBERSHIP 
#endif

/* Static utility function. */
static void ripng_enable_apply (struct interface *);

/* Join to the all rip routers multicast group. */
int
ripng_multicast_join (struct interface *ifp)
{
  int ret;
  struct ipv6_mreq mreq;

  memset (&mreq, 0, sizeof (mreq));
  inet_pton(AF_INET6, RIPNG_GROUP, &mreq.ipv6mr_multiaddr);
  mreq.ipv6mr_interface = ifp->ifindex;

  ret = setsockopt (ripng->sock, IPPROTO_IPV6, IPV6_JOIN_GROUP,
		    (char *) &mreq, sizeof (mreq));
  if (ret < 0)
    zlog_warn ("can't setsockopt IPV6_JOIN_GROUP: %s", strerror (errno));

  if (IS_RIPNG_DEBUG_EVENT)
    zlog_info ("RIPng %s join to all-rip-routers multicast group", ifp->name);

  return ret;
}

/* Leave from the all rip routers multicast group. */
int
ripng_multicast_leave (struct interface *ifp)
{
  int ret;
  struct ipv6_mreq mreq;

  memset (&mreq, 0, sizeof (mreq));
  inet_pton(AF_INET6, RIPNG_GROUP, &mreq.ipv6mr_multiaddr);
  mreq.ipv6mr_interface = ifp->ifindex;

  ret = setsockopt (ripng->sock, IPPROTO_IPV6, IPV6_LEAVE_GROUP,
		    (char *) &mreq, sizeof (mreq));
  if (ret < 0)
    zlog_warn ("can't setsockopt IPV6_LEAVE_GROUP: %s\n", strerror (errno));

  if (IS_RIPNG_DEBUG_EVENT)
    zlog_info ("RIPng %s leave from all-rip-routers multicast group",
	       ifp->name);

  return ret;
}

/* Check max mtu size. */
int
ripng_check_max_mtu ()
{
  listnode node;
  struct interface *ifp;
  int mtu;

  mtu = 0;
  for (node = listhead (iflist); node; nextnode (node))
    {
      ifp = getdata (node);
      if (mtu < ifp->mtu)
	mtu = ifp->mtu;
    }
  return mtu;
}

/* Inteface addition message from zebra. */
int
ripng_interface_add (int command, struct zebra *zebra, zebra_size_t length)
{
  struct interface *ifp;

  ifp = zebra_interface_add_read (zebra->ibuf);

  if (IS_RIPNG_DEBUG_ZEBRA)
    zlog_info ("RIPng interface add %s index %d flags %d metric %d mtu %d",
	       ifp->name, ifp->ifindex, ifp->flags, ifp->metric, ifp->mtu);

  /* Check is this interface is RIP enabled or not.*/
  ripng_enable_apply (ifp);

  /* Apply distribute list to the interface. */
  ripng_distribute_update_interface (ifp);

  /* Check interface routemap. */
  ripng_if_rmap_update_interface (ifp);

  return 0;
}

int
ripng_interface_delete (int command, struct zebra *zebra, zebra_size_t length)
{
  return 0;
}

int
ripng_interface_address_add (int command, struct zebra *zebra,
			     zebra_size_t length)
{
  struct connected *c;
  struct prefix *p;
  char buf[INET6_ADDRSTRLEN];

  c = zebra_interface_address_add_read (zebra->ibuf);

  if (c == NULL)
    return 0;

  if (IS_RIPNG_DEBUG_ZEBRA)
    {
      p = c->address;
      if (p->family == AF_INET6)
	zlog_info ("RIPng connected address %s/%d", 
		   inet_ntop (AF_INET6, &p->u.prefix6, buf, INET6_ADDRSTRLEN),
		   p->prefixlen);
    }

  /* Check is this interface is RIP enabled or not.*/
  ripng_enable_apply (c->ifp);

  return 0;
}

int
ripng_interface_address_delete (int command, struct zebra *zebra,
				zebra_size_t length)
{
  return 0;
}

/* RIPng enable interface vector. */
vector ripng_enable_if;

/* RIPng enable network table. */
struct route_table *ripng_enable_network;

/* Lookup RIPng enable network. */
int
ripng_enable_network_lookup (struct interface *ifp)
{
  listnode listnode;
  struct connected *connected;

  for (listnode = listhead (ifp->connected); listnode; nextnode (listnode))
    if ((connected = getdata (listnode)) != NULL)
      {
	struct prefix *p; 
	struct route_node *node;

	p = connected->address;

	if (p->family == AF_INET6)
	  {
	    node = route_node_match (ripng_enable_network, p);
	    if (node)
	      {
		route_unlock_node (node);
		return 1;
	      }
	  }
      }
  return -1;
}

/* Add RIPng enable network. */
int
ripng_enable_network_add (struct prefix *p)
{
  struct route_node *node;

  node = route_node_get (ripng_enable_network, p);

  if (node->info)
    {
      route_unlock_node (node);
      return -1;
    }
  else
    node->info = "enabled";

  return 1;
}

/* Delete RIPng enable network. */
int
ripng_enable_network_delete (struct prefix *p)
{
  struct route_node *node;

  node = route_node_lookup (ripng_enable_network, p);
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

/* Lookup function. */
int
ripng_enable_if_lookup (char *ifname)
{
  int i;
  char *str;

  for (i = 0; i < vector_max (ripng_enable_if); i++)
    if ((str = vector_slot (ripng_enable_if, i)) != NULL)
      if (strcmp (str, ifname) == 0)
	return i;
  return -1;
}

/* Add interface to ripng_enable_if. */
int
ripng_enable_if_add (char *ifname)
{
  int ret;

  ret = ripng_enable_if_lookup (ifname);
  if (ret >= 0)
    return -1;

  vector_set (ripng_enable_if, strdup (ifname));

  return 1;
}

/* Delete interface from ripng_enable_if. */
int
ripng_enable_if_delete (char *ifname)
{
  int index;
  char *str;

  index = ripng_enable_if_lookup (ifname);
  if (index < 0)
    return -1;

  str = vector_slot (ripng_enable_if, index);
  free (str);
  vector_unset (ripng_enable_if, index);

  return 1;
}

/* Wake up interface. */
int
ripng_interface_wakeup (struct thread *t)
{
  struct interface *ifp;
  struct ripng_interface *ri;

  /* Get interface. */
  ifp = THREAD_ARG (t);

  ri = ifp->info;
  ri->t_wakeup = NULL;

  /* Join to multicast group. */
  ripng_multicast_join (ifp);

  /* Send RIP request to the interface. */
  ripng_request (ifp);

  return 0;
}

/* Check RIPng is enabed on this interface. */
void
ripng_enable_apply (struct interface *ifp)
{
  int ret;
  struct ripng_interface *ri = NULL;

  /* Check interface. */
  if (if_is_loopback (ifp))
    return;

  if (! if_is_up (ifp))
    return;
  
  ri = ifp->info;

  /* Check network configuration. */
  ret = ripng_enable_network_lookup (ifp);

  /* If the interface is matched. */
  if (ret > 0)
    ri->enable_network = 1;
  else
    ri->enable_network = 0;

  /* Check interface name configuration. */
  ret = ripng_enable_if_lookup (ifp->name);
  if (ret >= 0)
    ri->enable_interface = 1;
  else
    ri->enable_interface = 0;

  /* Update running status of the interface. */
  if (ri->enable_network || ri->enable_interface)
    {
      if (! ri->running)
	{
	  if (IS_RIPNG_DEBUG_EVENT)
	    zlog_info ("RIPng turn on %s", ifp->name);

	  /* Add interface wake up thread. */
	  if (! ri->t_wakeup)
	    ri->t_wakeup = thread_add_timer (master, ripng_interface_wakeup,
					     ifp, 1);
#if 0
	  /* Join to multicast group. */
	  ripng_multicast_join (ifp);

	  /* Send RIP request to the interface. */
	  ripng_request (ifp);
#endif /* 0 */

	  ri->running = 1;
	}
    }
  else
    {
      if (ri->running)
	{
	  if (IS_RIPNG_DEBUG_EVENT)
	    zlog_info ("RIPng turn off %s", ifp->name);

	  /* Leave from multicast group. */
	  ripng_multicast_leave (ifp);

	  ri->running = 0;
	}
    }
}

/* Set distribute list to all interfaces. */
static void
ripng_enable_apply_all ()
{
  struct interface *ifp;
  listnode node;

  for (node = listhead (iflist); node; nextnode (node))
    {
      ifp = getdata (node);
      ripng_enable_apply (ifp);
    }
}

/* Write RIPng enable network and interface to the vty. */
int
ripng_network_write (struct vty *vty)
{
  int i;
  char *str;
  struct route_node *node;
  char buf[BUFSIZ];

  /* Write enable network. */
  for (node = route_top (ripng_enable_network); node; node = route_next (node))
    if (node->info)
      {
	struct prefix *p = &node->p;
	vty_out (vty, " network %s/%d%s", 
		 inet_ntop (p->family, &p->u.prefix, buf, BUFSIZ),
		 p->prefixlen,
		 VTY_NEWLINE);

      }
  
  /* Write enable interface. */
  for (i = 0; i < vector_max (ripng_enable_if); i++)
    if ((str = vector_slot (ripng_enable_if, i)) != NULL)
      vty_out (vty, " network %s%s", str,
	       VTY_NEWLINE);

  return 0;
}

/* RIPng enable on specified interface or matched network. */
DEFUN (ripng_network,
       ripng_network_cmd,
       "network IF_OR_ADDR",
       "RIPng enable on specified interface or network.\n"
       "Interface or address")
{
  int ret;
  struct prefix p;

  ret = str2prefix (argv[0], &p);

  /* Given string is IPv6 network or interface name. */
  if (ret)
    ret = ripng_enable_network_add (&p);
  else
    ret = ripng_enable_if_add (argv[0]);

  if (ret < 0)
    {
      vty_out (vty, "There is same network configuration %s%s", argv[0],
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  ripng_enable_apply_all ();

  return CMD_SUCCESS;
}

/* RIPng enable on specified interface or matched network. */
DEFUN (no_ripng_network,
       no_ripng_network_cmd,
       "no network IF_OR_ADDR",
       NO_STR
       "RIPng enable on specified interface or network.\n"
       "Interface or address")
{
  int ret;
  struct prefix p;

  ret = str2prefix (argv[0], &p);

  /* Given string is interface name. */
  if (ret)
    ret = ripng_enable_network_delete (&p);
  else
    ret = ripng_enable_if_delete (argv[0]);

  if (ret < 0)
    {
      vty_out (vty, "can't find network %s%s", argv[0],
	       VTY_NEWLINE);
      return CMD_WARNING;
    }
  
  ripng_enable_apply_all ();

  return CMD_SUCCESS;
}

struct ripng_interface *
ri_new ()
{
  struct ripng_interface *ri;

  ri = XMALLOC (MTYPE_IF, sizeof (struct ripng_interface));
  bzero (ri, sizeof (struct ripng_interface));

  return ri;
}

int
ripng_if_new_hook (struct interface *ifp)
{
  ifp->info = ri_new ();
  return 0;
}

/* Configuration write function for ripngd. */
int
interface_config_write (struct vty *vty)
{
  listnode node;
  struct interface *ifp;
  struct ripng_interface *ri;
  int write = 0;

  for (node = listhead (iflist); node; nextnode (node))
    {
      ifp = getdata (node);
      ri = ifp->info;

      vty_out (vty, "interface %s%s", ifp->name,
	       VTY_NEWLINE);
      if (ifp->desc)
	vty_out (vty, " description %s%s", ifp->desc,
		 VTY_NEWLINE);

      vty_out (vty, "!%s", VTY_NEWLINE);

      write++;
    }
  return write;
}

/* ripngd's interface node. */
struct cmd_node interface_node =
{
  INTERFACE_NODE,
  "%s(config-if)# ",
};

/* Initialization of interface. */
void
ripng_if_init ()
{
  /* Interface initialize. */
  iflist = list_init ();
  if_add_hook (IF_NEW_HOOK, ripng_if_new_hook);

  /* RIPng enable network init. */
  ripng_enable_network = route_table_init ();

  /* RIPng enable interface init. */
  ripng_enable_if = vector_init (1);

  /* Install interface node. */
  install_node (&interface_node, interface_config_write);

  install_element (CONFIG_NODE, &interface_cmd);
  install_element (INTERFACE_NODE, &config_end_cmd);
  install_element (INTERFACE_NODE, &config_exit_cmd);
  install_element (INTERFACE_NODE, &config_help_cmd);
  install_element (INTERFACE_NODE, &interface_desc_cmd);
  install_element (INTERFACE_NODE, &no_interface_desc_cmd);

  install_element (RIPNG_NODE, &ripng_network_cmd);
  install_element (RIPNG_NODE, &no_ripng_network_cmd);
}
