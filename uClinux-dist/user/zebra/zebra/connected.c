/*
 * Address linked list routine.
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

#include "prefix.h"
#include "linklist.h"
#include "if.h"
#include "rib.h"
#include "table.h"

#include "zebra/zserv.h"
#include "zebra/redistribute.h"

/* If same interface address is already exist... */
int
connected_check_ipv4 (struct interface *ifp, struct prefix *p)
{
  struct connected *connected;
  listnode node;

  for (node = listhead (ifp->connected); node; node = nextnode (node))
    {
      connected = getdata (node);

      if (prefix_same (connected->address, p))
	return 1;
    }
  return 0;
}

/* Add connected IPv4 route to the interface. */
void
connected_add_ipv4 (struct interface *ifp, struct in_addr *addr, 
		    int prefixlen, struct in_addr *broad)
{
  struct prefix_ipv4 *p;
  struct prefix_ipv4 rib;
  struct connected *connected;

  /* Allocate new connected address. */
  connected = connected_new ();

  p = prefix_ipv4_new ();
  p->family = AF_INET;
  p->prefix = *addr;
  p->prefixlen = prefixlen;

  /* For connected route. */
  rib = *p;

  connected->address = (struct prefix *) p;
  connected->ifp = ifp;

  /* If there is boroadcast or pointopoint address. */
  if (broad)
    {
      p = prefix_ipv4_new ();
      p->family = AF_INET;
      p->prefix = *broad;
      connected->destination = (struct prefix *) p;
    }

  /* Ok link connected to interface. */
  connected_add (ifp, connected);

  /* Update interface address information to protocol daemon. */
  zebra_interface_address_add_update (ifp, connected);

  /* Apply mask to the network. */
  apply_mask_ipv4 (&rib);

  /* In case of connected address is 0.0.0.0/0 we treat it tunnel
     address. */
  if (prefix_ipv4_any (&rib))
    return;

  if (if_is_up(ifp)){
    rib_add_ipv4 (ZEBRA_ROUTE_CONNECT, 0, &rib, NULL, ifp->ifindex, 0);
  }
}

/* Delete connected IPv4 route to the interface. */
void
connected_delete_ipv4 (struct interface *ifp, struct in_addr *addr, 
		    int prefixlen, struct in_addr *broad)
{
  struct prefix_ipv4 p;
  struct prefix_ipv4 mp;

  p.family = AF_INET;
  p.prefix = *addr;
  p.prefixlen = prefixlen;
  mp = p;

  connected_delete_by_prefix (ifp, (struct prefix *) &p);

  /* Apply mask to the network. */
  apply_mask_ipv4 (&mp);

  /* In case of connected address is 0.0.0.0/0 we treat it tunnel
     address. */
  if (prefix_ipv4_any (&mp))
    return;

  rib_delete_ipv4 (ZEBRA_ROUTE_CONNECT, 0, &mp, NULL, ifp->ifindex, 0);
}

void
connected_up_ipv4 (struct interface *ifp, struct in_addr *addr, 
		   int prefixlen)
{
  struct prefix_ipv4 p;

  p.family = AF_INET;
  p.prefix = *addr;
  p.prefixlen = prefixlen;

  /* Apply mask to the network. */
  apply_mask_ipv4 (&p);

  /* In case of connected address is 0.0.0.0/0 we treat it tunnel
     address. */
  if (prefix_ipv4_any (&p))
    return;

  rib_add_ipv4 (ZEBRA_ROUTE_CONNECT, 0, &p, NULL, ifp->ifindex, 0);
}

void
connected_down_ipv4 (struct interface *ifp, struct in_addr *addr, 
		     int prefixlen)
{
  struct prefix_ipv4 p;

  p.family = AF_INET;
  p.prefix = *addr;
  p.prefixlen = prefixlen;

  /* Apply mask to the network. */
  apply_mask_ipv4 (&p);

  /* In case of connected address is 0.0.0.0/0 we treat it tunnel
     address. */
  if (prefix_ipv4_any (&p))
    return;

  rib_delete_ipv4 (ZEBRA_ROUTE_CONNECT, 0, &p, NULL, ifp->ifindex, 0);
}

#ifdef HAVE_IPV6
/* If same interface address is already exist... */
int
connected_check_ipv6 (struct interface *ifp, struct prefix *p)
{
  struct connected *connected;
  listnode node;

  for (node = listhead (ifp->connected); node; node = nextnode (node))
    {
      connected = getdata (node);

      if (prefix_same (connected->address, p))
	return 1;
    }
  return 0;
}

/* Add connected IPv6 route to the interface. */
void
connected_add_ipv6 (struct interface *ifp, struct in6_addr *address,
		    int prefixlen, struct in6_addr *broad)
{
  struct connected *connected;
  struct prefix_ipv6 *p;
  struct prefix_ipv6 rib;

  connected = connected_new ();

  p = prefix_ipv6_new ();
  p->family = AF_INET6;
  memcpy(&p->prefix, address, sizeof(*address));
  p->prefixlen = prefixlen;
  memcpy(&rib, p, sizeof(*p));

  connected->address = (struct prefix *) p;
  connected->ifp = ifp;

  if (broad)
    {
      p = prefix_ipv6_new ();
      p->family = AF_INET6;
      memcpy(&p->prefix, broad, sizeof(*broad));
      connected->destination = (struct prefix *) p;
    }

  connected_add (ifp, connected);

  if (if_is_up(ifp)){
    rib_add_ipv6 (ZEBRA_ROUTE_CONNECT, 0, &rib, NULL, ifp->ifindex, 0);
  }
}

void
connected_delete_ipv6 (struct interface *ifp, struct in6_addr *address,
                    int prefixlen, struct in6_addr *broad)
{
  struct prefix_ipv6 p;
  struct prefix_ipv6 mp;

  p.family = AF_INET6;
  memcpy(&p.prefix, address, sizeof(*address));
  p.prefixlen = prefixlen;
  mp = p;

  connected_delete_by_prefix (ifp, (struct prefix *) &p);

  apply_mask_ipv6 (&mp);

  rib_delete_ipv6 (ZEBRA_ROUTE_CONNECT, 0, &mp, NULL, ifp->ifindex, 0);
}

void
connected_up_ipv6 (struct interface *ifp, struct in6_addr *address,
		   int prefixlen)
{
  struct prefix_ipv6 p;

  p.family = AF_INET6;
  p.prefix = *address;
  p.prefixlen = prefixlen;

  apply_mask_ipv6 (&p);

  rib_add_ipv6 (ZEBRA_ROUTE_CONNECT, 0, &p, NULL, ifp->ifindex, 0);
}

void
connected_down_ipv6 (struct interface *ifp, struct in6_addr *address,
		     int prefixlen)
{
  struct prefix_ipv6 p;

  p.family = AF_INET6;
  p.prefix = *address;
  p.prefixlen = prefixlen;

  apply_mask_ipv6 (&p);

  rib_delete_ipv6 (ZEBRA_ROUTE_CONNECT, 0, &p, NULL, ifp->ifindex, 0);
}
#endif /* HAVE_IPV6 */
