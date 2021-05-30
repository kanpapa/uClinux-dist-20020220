/* RIPd and zebra interface.
 * Copyright (C) 1997, 1999 Kunihiro Ishiguro
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
#include "routemap.h"
#include "zclient.h"
#include "log.h"

#include "ripd/ripd.h"
#include "ripd/rip_debug.h"

/* All information about zebra. */
struct zebra *zclient = NULL;

/* Callback prototypes for zebra client service. */
int rip_interface_add (int, struct zebra *, zebra_size_t);
int rip_interface_delete (int, struct zebra *, zebra_size_t);
int rip_interface_address_add (int, struct zebra *, zebra_size_t);
int rip_interface_address_delete (int, struct zebra *, zebra_size_t);
int rip_interface_up (int, struct zebra *, zebra_size_t);
int rip_interface_down (int, struct zebra *, zebra_size_t);

/* RIPd to zebra command interface. */
void
rip_zebra_ipv4_add (struct prefix_ipv4 *p, struct in_addr *nexthop, 
		    unsigned int ifindex)
{
  if (zclient->redist[ZEBRA_ROUTE_RIP])
    {
      zebra_ipv4_add (zclient->sock, ZEBRA_ROUTE_RIP, 0, 
		      p, nexthop, ifindex);
      rip_global_route_changes++;
    }
}

void
rip_zebra_ipv4_delete (struct prefix_ipv4 *p, struct in_addr *nexthop, 
		       unsigned int ifindex)
{
  if (zclient->redist[ZEBRA_ROUTE_RIP])
    {
      zebra_ipv4_delete (zclient->sock, ZEBRA_ROUTE_RIP, 0, 
			 p, nexthop, ifindex);
      rip_global_route_changes++;
    }
}

/* Zebra route add and delete treatment. */
int
rip_zebra_read_ipv4 (int command, struct zebra *zebra, zebra_size_t length)
{
  u_char type;
  u_char flags;
  struct in_addr nexthop;
  u_char *lim;
  struct stream *s;
  unsigned int ifindex;

  s = zebra->ibuf;
  lim = stream_pnt (s) + length;

  /* Fetch type and nexthop first. */
  type = stream_getc (s);
  flags = stream_getc (s);
  stream_get (&nexthop, s, sizeof (struct in_addr));

  /* Then fetch IPv4 prefixes. */
  while (stream_pnt (s) < lim)
    {
      int size;
      struct prefix_ipv4 p;

      ifindex = stream_getl (s);

      bzero (&p, sizeof (struct prefix_ipv4));
      p.family = AF_INET;
      p.prefixlen = stream_getc (s);
      size = PSIZE (p.prefixlen);
      stream_get (&p.prefix, s, size);

      if (command == ZEBRA_IPV4_ROUTE_ADD)
	rip_redistribute_add (type, 0, &p, ifindex, &nexthop);
      else 
	rip_redistribute_delete (type, 0, &p, ifindex);
    }
  return 0;
}

void
rip_zclient_reset ()
{
  zclient_reset (zclient);
}

/* RIP route-map set for redistribution */
void
rip_routemap_set (int type, char *name)
{
  if (rip->route_map[type].name)
    free(rip->route_map[type].name);

  rip->route_map[type].name = strdup (name);
  rip->route_map[type].map = route_map_lookup_by_name (name);
}

/* RIP route-map unset for redistribution */
void
rip_routemap_unset (int type)
{
  if (! rip->route_map[type].name)
    return;

  free (rip->route_map[type].name);
  rip->route_map[type].name = NULL;
  rip->route_map[type].map = NULL;

  return;
}

/* VTY help string. */
#define REDIST_STR "[kernel|connected|static|ospf|bgp] route"

/* Redistribution types */
static struct {
  int type;
  int str_min_len;
  char *str;
} redist_type[] = {
  {ZEBRA_ROUTE_KERNEL,  1, "kernel"},
  {ZEBRA_ROUTE_CONNECT, 1, "connected"},
  {ZEBRA_ROUTE_STATIC,  1, "static"},
  {ZEBRA_ROUTE_OSPF,    1, "ospf"},
  {ZEBRA_ROUTE_BGP,     1, "bgp"},
  {0, 0, NULL}
};

DEFUN (router_zebra,
       router_zebra_cmd,
       "router zebra",
       "Enable a routing process\n"
       "zebra client connection\n")
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
       "zebra client connection\n")
{
  zclient->enable = 0;
  zclient_stop (zclient);
  return CMD_SUCCESS;
}

int
rip_redistribute_set (int type)
{
  if (zclient->redist[type])
    return CMD_SUCCESS;

  zclient->redist[type] = 1;

  if (zclient->sock > 0)
    zebra_redistribute_send (ZEBRA_REDISTRIBUTE_ADD, zclient->sock, type);

  return CMD_SUCCESS;
}

int
rip_redistribute_unset (int type)
{
  if (! zclient->redist[type])
    return CMD_SUCCESS;

  zclient->redist[type] = 0;

  if (zclient->sock > 0)
    zebra_redistribute_send (ZEBRA_REDISTRIBUTE_DELETE, zclient->sock, type);

  /* Remove the routes from RIP table. */
  rip_redistribute_withdraw (type);

  return CMD_SUCCESS;
}

DEFUN (rip_redistribute_rip,
       rip_redistribute_rip_cmd,
       "redistribute rip",
       "Redistribute control\n"
       "RIP route\n")
{
  zclient->redist[ZEBRA_ROUTE_RIP] = 1;
  return CMD_SUCCESS;
}

DEFUN (no_rip_redistribute_rip,
       no_rip_redistribute_rip_cmd,
       "no redistribute rip",
       NO_STR
       "Redistribute control\n"
       "RIP route\n")
{
  zclient->redist[ZEBRA_ROUTE_RIP] = 0;
  return CMD_SUCCESS;
}

DEFUN (rip_redistribute_type,
       rip_redistribute_type_cmd,
       "redistribute (kernel|connected|static|ospf|bgp)",
       "Redistribute control\n"
       "Kernel routes\n"
       "Connected routes\n"
       "Static routes\n"
       "OSPF routes\n"
       "BGP routes\n")
{
  int i;

  for(i = 0; redist_type[i].str; i++) 
    {
      if (strncmp (redist_type[i].str, argv[0], 
		   redist_type[i].str_min_len) == 0) 
	{
	  zclient_redistribute_set (zclient, redist_type[i].type);
	  return CMD_SUCCESS;
	}
    }

  vty_out(vty, "Invalid type %s%s", argv[0],
	  VTY_NEWLINE);

  return CMD_WARNING;
}

DEFUN (no_rip_redistribute_type,
       no_rip_redistribute_type_cmd,
       "no redistribute (kernel|connected|static|ospf|bgp)",
       NO_STR
       "Redistribute control\n"
       "Kernel routes\n"
       "Connected routes\n"
       "Static routes\n"
       "OSPF routes\n"
       "BGP routes\n")
{
  int i;

  for (i = 0; redist_type[i].str; i++) 
    {
      if (strncmp(redist_type[i].str, argv[0], 
		  redist_type[i].str_min_len) == 0) 
	{
	  rip_routemap_unset (redist_type[i].type);
	  rip_redistribute_unset (redist_type[i].type);
	  return CMD_SUCCESS;
        }
    }

  vty_out(vty, "Invalid type %s%s", argv[0],
	  VTY_NEWLINE);

  return CMD_WARNING;
}

DEFUN (rip_redistribute_type_routemap,
       rip_redistribute_type_routemap_cmd,
       "redistribute (kernel|connected|static|ospf|bgp) route-map ROUTE_MAP_NAME",
       "Redistribute control\n"
       "Kernel routes\n"
       "Connected routes\n"
       "Static routes\n"
       "OSPF routes\n"
       "BGP routes\n"
       "Route map\n"
       "Route map name\n")
{
  int i;

  for (i = 0; redist_type[i].str; i++) {
    if (strncmp(redist_type[i].str, argv[0],
		redist_type[i].str_min_len) == 0) 
      {
	rip_routemap_set (redist_type[i].type, argv[1]);
	zclient_redistribute_set (zclient, redist_type[i].type);
	return CMD_SUCCESS;
      }
  }

  vty_out(vty, "Invalid type %s%s", argv[0],
	  VTY_NEWLINE);

  return CMD_WARNING;
}

/* RIP configuration write function. */
int
config_write_zebra (struct vty *vty)
{
  if (! zclient->enable)
    {
      vty_out (vty, "no router zebra%s", VTY_NEWLINE);
      return 1;
    }
  else if (! zclient->redist[ZEBRA_ROUTE_RIP])
    {
      vty_out (vty, "router zebra%s", VTY_NEWLINE);
      vty_out (vty, " no redistribute rip%s", VTY_NEWLINE);
      return 1;
    }
  return 0;
}

int
config_write_rip_redistribute (struct vty *vty, int config_mode)
{
  int i;
  char *str[] = { "system", "kernel", "connected", "static", "rip",
		  "ripng", "ospf", "ospf6", "bgp"};

  for (i = 0; i < ZEBRA_ROUTE_MAX; i++)
    if (i != zclient->redist_default && zclient->redist[i])
      {
	if (config_mode)
	  {
	    if (rip->route_map[i].name)
	      vty_out (vty, " redistribute %s route-map %s%s",
		       str[i], rip->route_map[i].name,
		       VTY_NEWLINE);
	    else
	      vty_out (vty, " redistribute %s%s", str[i],
		       VTY_NEWLINE);
	  }
	else
	  vty_out (vty, " %s", str[i]);
      }
  return 0;
}

/* Zebra node structure. */
struct cmd_node zebra_node =
{
  ZEBRA_NODE,
  "%s(config-router)# ",
};

void
rip_zclient_init ()
{
  /* Set default value to the zebra client structure. */
  zclient = zclient_new ();
  zclient_init (zclient, ZEBRA_ROUTE_RIP);
  zclient->interface_add = rip_interface_add;
  zclient->interface_delete = rip_interface_delete;
  zclient->interface_address_add = rip_interface_address_add;
  zclient->interface_address_delete = rip_interface_address_delete;
  zclient->ipv4_route_add = rip_zebra_read_ipv4;
  zclient->ipv4_route_delete = rip_zebra_read_ipv4;
  zclient->interface_up = rip_interface_up;
  zclient->interface_down = rip_interface_down;
  

  /* Install zebra node. */
  install_node (&zebra_node, config_write_zebra);

  /* Install command elements to zebra node. */ 
  install_element (CONFIG_NODE, &router_zebra_cmd);
  install_element (CONFIG_NODE, &no_router_zebra_cmd);
  install_default (ZEBRA_NODE);
  install_element (ZEBRA_NODE, &rip_redistribute_rip_cmd);
  install_element (ZEBRA_NODE, &no_rip_redistribute_rip_cmd);

  /* Install command elements to rip node. */
  install_element (RIP_NODE, &rip_redistribute_type_cmd);
  install_element (RIP_NODE, &rip_redistribute_type_routemap_cmd);
  install_element (RIP_NODE, &no_rip_redistribute_type_cmd);
}
