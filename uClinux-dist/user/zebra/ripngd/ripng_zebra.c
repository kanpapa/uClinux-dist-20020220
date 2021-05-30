/*
 * RIPngd and zebra interface.
 * Copyright (C) 1998, 1999 Kunihiro Ishiguro
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
#include "prefix.h"
#include "stream.h"
#include "zclient.h"
#include "log.h"

#include "ripngd/ripngd.h"

/* int ripng_zebra_get_interface (int, struct zebra *, zebra_size_t); */
int ripng_interface_add (int, struct zebra *, zebra_size_t);
int ripng_interface_delete (int, struct zebra *, zebra_size_t);
int ripng_interface_address_add (int, struct zebra *, zebra_size_t);
int ripng_interface_address_delete (int, struct zebra *, zebra_size_t);

/* All information about zebra. */
struct zebra *zclient = NULL;

void
ripng_zebra_ipv6_add (struct prefix_ipv6 *p, struct in6_addr *nexthop,
		      unsigned int ifindex)
{
  if (zclient->redist[ZEBRA_ROUTE_RIPNG])
    zebra_ipv6_add (zclient->sock, ZEBRA_ROUTE_RIPNG, 0, p, nexthop, ifindex);
}

void
ripng_zebra_ipv6_delete (struct prefix_ipv6 *p, struct in6_addr *nexthop,
			 unsigned int ifindex)
{
  if (zclient->redist[ZEBRA_ROUTE_RIPNG])
    zebra_ipv6_delete (zclient->sock, ZEBRA_ROUTE_RIPNG, 0, p, nexthop, ifindex);
}

/* Zebra route add and delete treatment. */
int
ripng_zebra_read_ipv6 (int command, struct zebra *zebra, zebra_size_t length)
{
  u_char type;
  u_char flags;
  struct in6_addr nexthop;
  u_char *lim;
  struct stream *s;

  s = zclient->ibuf;

  lim = stream_pnt (s) + length;

  /* Fetch type and nexthop first. */
  type = stream_getc (s);
  flags = stream_getc (s);
  stream_get (&nexthop, s, sizeof (struct in6_addr));

  /* Then fetch IPv6 prefixes. */
  while (stream_pnt (s) < lim)
    {
      int size;
      struct prefix_ipv6 p;
      unsigned int ifindex;

      ifindex = stream_getl (s);

      memset (&p, 0, sizeof (struct prefix_ipv6));
      p.family = AF_INET6;
      p.prefixlen = stream_getc (s);
      size = PSIZE (p.prefixlen);
      stream_get (&p.prefix, s, size);

      if (command == ZEBRA_IPV6_ROUTE_ADD)
	ripng_redistribute_add (type, 0, &p, ifindex);
      else
	ripng_redistribute_delete (type, 0, &p, ifindex);
    }
  return 0;
}

int
ripng_redistribute_unset (int type)
{
  if (! zclient->redist[type])
    return CMD_SUCCESS;

  zclient->redist[type] = 0;

  if (zclient->sock > 0)
    zebra_redistribute_send (ZEBRA_REDISTRIBUTE_DELETE, zclient->sock, type);

  ripng_redistribute_withdraw (type);
  
  return CMD_SUCCESS;
}

DEFUN (router_zebra,
       router_zebra_cmd,
       "router zebra",
       "Enable a routing process\n"
       "Make connection to zebra daemon\n")
{
  vty->node = ZEBRA_NODE;
  zclient->enable = 1;
  zclient_start (zclient);
  return CMD_SUCCESS;
}

DEFUN (no_router_zebra,
       no_router_zebra_cmd,
       "no router zebra",
       NO_STR
       "Disable a routing process\n"
       "Stop connection to zebra daemon\n")
{
  zclient->enable = 0;
  zclient_stop (zclient);
  return CMD_SUCCESS;
}

DEFUN (ripng_redistribute_ripng,
       ripng_redistribute_ripng_cmd,
       "redistribute ripng",
       "Redistribute control\n"
       "RIPng route\n")
{
  zclient->redist[ZEBRA_ROUTE_RIPNG] = 1;
  return CMD_SUCCESS;
}

DEFUN (no_ripng_redistribute_ripng,
       no_ripng_redistribute_ripng_cmd,
       "no redistribute ripng",
       NO_STR
       "Redistribute control\n"
       "RIPng route\n")
{
  zclient->redist[ZEBRA_ROUTE_RIPNG] = 0;
  return CMD_SUCCESS;
}

DEFUN (ripng_redistribute_static,
       ripng_redistribute_static_cmd,
       "redistribute static",
       "Redistribute control\n"
       "Static route\n")
{
  zclient_redistribute_set (zclient, ZEBRA_ROUTE_STATIC);
  return CMD_SUCCESS;
}

DEFUN (no_ripng_redistribute_static,
       no_ripng_redistribute_static_cmd,
       "no redistribute static",
       NO_STR
       "Redistribute control\n"
       "Static route\n")
{
  return ripng_redistribute_unset (ZEBRA_ROUTE_STATIC);
}

DEFUN (ripng_redistribute_kernel,
       ripng_redistribute_kernel_cmd,
       "redistribute kernel",
       "Redistribute control\n"
       "Kernel route\n")
{
  zclient_redistribute_set (zclient, ZEBRA_ROUTE_KERNEL);
  return CMD_SUCCESS;
}

DEFUN (no_ripng_redistribute_kernel,
       no_ripng_redistribute_kernel_cmd,
       "no redistribute kernel",
       NO_STR
       "Redistribute control\n"
       "Kernel route\n")
{
  return ripng_redistribute_unset (ZEBRA_ROUTE_KERNEL);
}

DEFUN (ripng_redistribute_connected,
       ripng_redistribute_connected_cmd,
       "redistribute connected",
       "Redistribute control\n"
       "Connected route\n")
{
  zclient_redistribute_set (zclient, ZEBRA_ROUTE_CONNECT);
  return CMD_SUCCESS;
}

DEFUN (no_ripng_redistribute_connected,
       no_ripng_redistribute_connected_cmd,
       "no redistribute connected",
       NO_STR
       "Redistribute control\n"
       "Connected route\n")
{
  return ripng_redistribute_unset (ZEBRA_ROUTE_CONNECT);
}

DEFUN (ripng_redistribute_bgp,
       ripng_redistribute_bgp_cmd,
       "redistribute bgp",
       "Redistribute control\n"
       "BGP route\n")
{
  zclient_redistribute_set (zclient, ZEBRA_ROUTE_BGP);
  return CMD_SUCCESS;
}

DEFUN (no_ripng_redistribute_bgp,
       no_ripng_redistribute_bgp_cmd,
       "no redistribute bgp",
       NO_STR
       "Redistribute control\n"
       "BGP route\n")
{
  return ripng_redistribute_unset (ZEBRA_ROUTE_BGP);
}

DEFUN (ripng_redistribute_ospf6,
       ripng_redistribute_ospf6_cmd,
       "redistribute ospf6",
       "Redistribute control\n"
       "OSPF6 route\n")
{
  zclient_redistribute_set (zclient, ZEBRA_ROUTE_OSPF6);
  return CMD_SUCCESS;
}

DEFUN (no_ripng_redistribute_ospf6,
       no_ripng_redistribute_ospf6_cmd,
       "no redistribute ospf6",
       NO_STR
       "Redistribute control\n"
       "OSPF6 route\n")
{
  return ripng_redistribute_unset (ZEBRA_ROUTE_OSPF6);
}

void
ripng_redistribute_write (struct vty *vty)
{
  int i;
  char *str[] = { "system", "kernel", "connected", "static", "rip",
		  "ripng", "ospf", "ospf6", "bgp"};

  for (i = 0; i < ZEBRA_ROUTE_MAX; i++)
    if (i != zclient->redist_default && zclient->redist[i])
      vty_out (vty, " redistribute %s%s", str[i],
	       VTY_NEWLINE);
}

/* RIPng configuration write function. */
int
zebra_config_write (struct vty *vty)
{
  if (! zclient->enable)
    {
      vty_out (vty, "no router zebra%s", VTY_NEWLINE);
      return 1;
    }
  else if (! zclient->redist[ZEBRA_ROUTE_RIPNG])
    {
      vty_out (vty, "router zebra%s", VTY_NEWLINE);
      vty_out (vty, " no redistribute ripng%s", VTY_NEWLINE);
      return 1;
    }
  return 0;
}

/* Zebra node structure. */
struct cmd_node zebra_node =
{
  ZEBRA_NODE,
  "%s(config-router)# ",
};

/* Initialize zebra structure and it's commands. */
void
zebra_init ()
{
  /* Allocate zebra structure. */
  zclient = zclient_new ();
  zclient_init (zclient, ZEBRA_ROUTE_RIPNG);
  zclient->interface_add = ripng_interface_add;
  zclient->interface_delete = ripng_interface_delete;
  zclient->interface_address_add = ripng_interface_address_add;
  zclient->interface_address_delete = ripng_interface_address_delete;
  zclient->ipv6_route_add = ripng_zebra_read_ipv6;
  zclient->ipv6_route_delete = ripng_zebra_read_ipv6;
  
  /* Install zebra node. */
  install_node (&zebra_node, zebra_config_write);

  /* Install command element for zebra node. */ 
  install_element (CONFIG_NODE, &router_zebra_cmd);
  install_element (CONFIG_NODE, &no_router_zebra_cmd);
  install_default (ZEBRA_NODE);
  install_element (ZEBRA_NODE, &ripng_redistribute_ripng_cmd);
  install_element (ZEBRA_NODE, &no_ripng_redistribute_ripng_cmd);
  install_element (RIPNG_NODE, &ripng_redistribute_static_cmd);
  install_element (RIPNG_NODE, &no_ripng_redistribute_static_cmd);
  install_element (RIPNG_NODE, &ripng_redistribute_kernel_cmd);
  install_element (RIPNG_NODE, &no_ripng_redistribute_kernel_cmd);
  install_element (RIPNG_NODE, &ripng_redistribute_connected_cmd);
  install_element (RIPNG_NODE, &no_ripng_redistribute_connected_cmd);
  install_element (RIPNG_NODE, &ripng_redistribute_bgp_cmd);
  install_element (RIPNG_NODE, &no_ripng_redistribute_bgp_cmd);
  install_element (RIPNG_NODE, &ripng_redistribute_ospf6_cmd);
  install_element (RIPNG_NODE, &no_ripng_redistribute_ospf6_cmd);
}
