/* Redistribution Handler
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

#include "vector.h"
#include "vty.h"
#include "command.h"
#include "prefix.h"
#include "table.h"
#include "stream.h"
#include "zclient.h"
#include "linklist.h"

#include "zebra/rib.h"
#include "zebra/zserv.h"
#include "zebra/redistribute.h"

int
zebra_check_addr (struct prefix *p)
{
  if (p->family == AF_INET)
    {
      u_int32_t addr;

      addr = p->u.prefix4.s_addr;
      addr = ntohl (addr);

      if (IPV4_NET127 (addr))
	return 0;
    }
#ifdef HAVE_IPV6
  if (p->family == AF_INET6)
    {
      if (IN6_IS_ADDR_LOOPBACK (&p->u.prefix6))
	return 0;
      if (IN6_IS_ADDR_LINKLOCAL(&p->u.prefix6))
	return 0;
    }
#endif /* HAVE_IPV6 */
  return 1;
}

/* Redistribute routes. */
void
zebra_redistribute (struct zebra_client *client, int type)
{
  struct rib *rib;
  struct route_node *np;

  for (np = route_top (ipv4_rib_table); np; np = route_next (np))
    for (rib = np->info; rib; rib = rib->next)
      if (IS_RIB_FIB (rib) && rib->type == type && zebra_check_addr (&np->p))
	  zebra_ipv4_add (client->fd, type, 0, (struct prefix_ipv4 *)&np->p,
			  &rib->u.gate4, rib->u.ifindex);

#ifdef HAVE_IPV6
  for (np = route_top (ipv6_rib_table); np; np = route_next (np))
    for (rib = np->info; rib; rib = rib->next)
      if (IS_RIB_FIB (rib) && rib->type == type && zebra_check_addr (&np->p))
	zebra_ipv6_add (client->fd, type, 0, (struct prefix_ipv6 *)&np->p,
			&rib->u.gate6, rib->u.ifindex);
#endif /* HAVE_IPV6 */
}

extern list client_list;

void
redistribute_add (struct route_node *np, struct rib *rib)
{
  listnode node;
  struct zebra_client *client;

  for (node = listhead (client_list); node; nextnode (node))
    if ((client = getdata (node)) != NULL)
      if (client->redist[rib->type])
	{
	  if (np->p.family == AF_INET)
	    zebra_ipv4_add (client->fd, rib->type, 0, 
			    (struct prefix_ipv4 *)&np->p, &rib->u.gate4,
			    rib->u.ifindex);
#ifdef HAVE_IPV6
	  if (np->p.family == AF_INET6)
	    zebra_ipv6_add (client->fd, rib->type, 0,
			    (struct prefix_ipv6 *)&np->p, &rib->u.gate6,
			    rib->u.ifindex);
#endif /* HAVE_IPV6 */	  
	}
}

void
redistribute_delete (struct route_node *np, struct rib *rib)
{
  listnode node;
  struct zebra_client *client;

  for (node = listhead (client_list); node; nextnode (node))
    if ((client = getdata (node)) != NULL)
      if (client->redist[rib->type])
	{
	  if (np->p.family == AF_INET)
	    zebra_ipv4_delete (client->fd, rib->type, 0, 
			       (struct prefix_ipv4 *)&np->p, &rib->u.gate4,
			       rib->u.ifindex);
#ifdef HAVE_IPV6
	  if (np->p.family == AF_INET6)
	    zebra_ipv6_delete (client->fd, rib->type, 0,
			       (struct prefix_ipv6 *)&np->p, &rib->u.gate6,
			       rib->u.ifindex);
#endif /* HAVE_IPV6 */	  
	}
}

void
zebra_redistribute_add (int command, struct zebra_client *client, int length)
{
  int type;

  type = stream_getc (client->ibuf);

  switch (type)
    {
    case ZEBRA_ROUTE_KERNEL:
    case ZEBRA_ROUTE_CONNECT:
    case ZEBRA_ROUTE_STATIC:
    case ZEBRA_ROUTE_RIP:
    case ZEBRA_ROUTE_RIPNG:
    case ZEBRA_ROUTE_OSPF:
    case ZEBRA_ROUTE_OSPF6:
    case ZEBRA_ROUTE_BGP:
      if (! client->redist[type])
	{
	  client->redist[type] = 1;
	  zebra_redistribute (client, type);
	}
      break;
    default:
      break;
    }
}     

void
zebra_redistribute_delete (int command, struct zebra_client *client, 
			   int length)
{
  int type;

  type = stream_getc (client->ibuf);

  switch (type)
    {
    case ZEBRA_ROUTE_KERNEL:
    case ZEBRA_ROUTE_CONNECT:
    case ZEBRA_ROUTE_STATIC:
    case ZEBRA_ROUTE_RIP:
    case ZEBRA_ROUTE_RIPNG:
    case ZEBRA_ROUTE_OSPF:
    case ZEBRA_ROUTE_OSPF6:
    case ZEBRA_ROUTE_BGP:
      client->redist[type] = 0;
      break;
    default:
      break;
    }
}     

/* Interface information update. */
void
zebra_interface_add_update (struct interface *ifp)
{
  listnode node;
  struct zebra_client *client;

  for (node = listhead (client_list); node; nextnode (node))
    if ((client = getdata (node)) != NULL)
      zebra_interface_add (client->fd, ifp);
}

void
zebra_interface_delete_update (struct interface *ifp)
{
  listnode node;
  struct zebra_client *client;

  for (node = listhead (client_list); node; nextnode (node))
    if ((client = getdata (node)) != NULL)
      zebra_interface_delete (client->fd, ifp);
}

/* Interface address addition. */
void
zebra_interface_address_add_update (struct interface *ifp, struct connected *c)
{
  listnode node;
  struct zebra_client *client;

  for (node = listhead (client_list); node; nextnode (node))
    if ((client = getdata (node)) != NULL)
      zebra_interface_address_add (client->fd, ifp, c);
}

/* Interface address deletion. */
void
zebra_interface_address_delete_update (struct interface *ifp, struct connected *c)
{
  listnode node;
  struct zebra_client *client;

  for (node = listhead (client_list); node; nextnode (node))
    if ((client = getdata (node)) != NULL)
      zebra_interface_address_delete (client->fd, ifp, c);
}
