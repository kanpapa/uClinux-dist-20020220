/*
 * RIPv2 routemap.
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
#include "prefix.h"
#include "routemap.h"
#include "command.h"
#include "filter.h"
#include "log.h"
#include "sockunion.h"		/* for inet_aton () */

#include "ripd/ripd.h"

/* Add rip route map rule. */
int
rip_route_match_add (struct vty *vty, struct route_map_index *index,
		     char *command, char *arg)
{
  int ret;

  ret = route_map_add_match (index, command, arg);
  if (ret)
    {
      switch (ret)
	{
	case RMAP_RULE_MISSING:
	  vty_out (vty, "Can't find rule.%s", VTY_NEWLINE);
	  return CMD_WARNING;
	  break;
	case RMAP_COMPILE_ERROR:
	  vty_out (vty, "Argument is malformed.%s", VTY_NEWLINE);
	  return CMD_WARNING;
	  break;
	}
    }
  return CMD_SUCCESS;
}

/* Delete rip route map rule. */
int
rip_route_match_delete (struct vty *vty, struct route_map_index *index,
			char *command, char *arg)
{
  int ret;

  ret = route_map_delete_match (index, command, arg);
  if (ret)
    {
      switch (ret)
	{
	case RMAP_RULE_MISSING:
	  vty_out (vty, "Can't find rule.%s", VTY_NEWLINE);
	  return CMD_WARNING;
	  break;
	case RMAP_COMPILE_ERROR:
	  vty_out (vty, "Argument is malformed.%s", VTY_NEWLINE);
	  return CMD_WARNING;
	  break;
	}
    }
  return CMD_SUCCESS;
}

/* Add rip route map rule. */
int
rip_route_set_add (struct vty *vty, struct route_map_index *index,
		   char *command, char *arg)
{
  int ret;

  ret = route_map_add_set (index, command, arg);
  if (ret)
    {
      switch (ret)
	{
	case RMAP_RULE_MISSING:
	  vty_out (vty, "Can't find rule.%s", VTY_NEWLINE);
	  return CMD_WARNING;
	  break;
	case RMAP_COMPILE_ERROR:
	  vty_out (vty, "Argument is malformed.%s", VTY_NEWLINE);
	  return CMD_WARNING;
	  break;
	}
    }
  return CMD_SUCCESS;
}

/* Delete rip route map rule. */
int
rip_route_set_delete (struct vty *vty, struct route_map_index *index,
		      char *command, char *arg)
{
  int ret;

  ret = route_map_delete_set (index, command, arg);
  if (ret)
    {
      switch (ret)
	{
	case RMAP_RULE_MISSING:
	  vty_out (vty, "Can't find rule.%s", VTY_NEWLINE);
	  return CMD_WARNING;
	  break;
	case RMAP_COMPILE_ERROR:
	  vty_out (vty, "Argument is malformed.%s", VTY_NEWLINE);
	  return CMD_WARNING;
	  break;
	}
    }
  return CMD_SUCCESS;
}

/* Hook function for updating route_map assignment. */
void
rip_route_map_update ()
{
  int i;

  for (i = 0; i < ZEBRA_ROUTE_MAX; i++) 
    {
      if (rip->route_map[i].name)
	rip->route_map[i].map = 
	  route_map_lookup_by_name (rip->route_map[i].name);
    }
}

/* `match metric METRIC' */
/* Match function return 1 if match is success else return zero. */
route_map_result_t
route_match_metric (void *rule, struct prefix *prefix, 
		    route_map_object_t type, void *object)
{
  u_int32_t *metric;
  struct rip_info *rinfo;

  if (type == RMAP_RIP)
    {
      metric = rule;
      rinfo = object;
    
      if (rinfo->metric == *metric)
	return RMAP_MATCH;
      else
	return RMAP_NOMATCH;
    }
  return RMAP_NOMATCH;
}

/* Route map `match metric' match statement. `arg' is METRIC value */
void *
route_match_metric_compile (char *arg)
{
  u_int32_t *metric;

  metric = XMALLOC (MTYPE_ROUTE_MAP_COMPILED, sizeof (u_int32_t));
  *metric = atoi (arg);

  if(*metric > 0)
    return metric;

  XFREE (MTYPE_ROUTE_MAP_COMPILED, metric);
  return NULL;
}

/* Free route map's compiled `match metric' value. */
void
route_match_metric_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Route map commands for metric matching. */
struct route_map_rule_cmd route_match_metric_cmd =
{
  "metric",
  route_match_metric,
  route_match_metric_compile,
  route_match_metric_free
};

/* `match interface IFNAME' */
/* Match function return 1 if match is success else return zero. */
route_map_result_t
route_match_interface (void *rule, struct prefix *prefix,
		       route_map_object_t type, void *object)
{
  struct rip_info *rinfo;
  struct interface *ifp;
  char *ifname;

  if (type == RMAP_RIP)
    {
      ifname = rule;
      ifp = if_lookup_by_name(ifname);

      if (!ifp)
	return RMAP_NOMATCH;

      rinfo = object;

      if (rinfo->ifindex_out == ifp->ifindex)
	return RMAP_MATCH;
      else
	return RMAP_NOMATCH;
    }
  return RMAP_NOMATCH;
}

/* Route map `match interface' match statement. `arg' is IFNAME value */
/* XXX I don`t know if I need to check does interface exist? */
void *
route_match_interface_compile (char *arg)
{
  return XSTRDUP (MTYPE_ROUTE_MAP_COMPILED, arg);
}

/* Free route map's compiled `match interface' value. */
void
route_match_interface_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Route map commands for interface matching. */
struct route_map_rule_cmd route_match_interface_cmd =
{
  "interface",
  route_match_interface,
  route_match_interface_compile,
  route_match_interface_free
};

/* `match ip next-hop IP_ADDRESS' */

/* Match function return 1 if match is success else return zero. */
route_map_result_t
route_match_ip_nexthop (void *rule, struct prefix *prefix,
			route_map_object_t type, void *object)
{
  struct in_addr *addr;
  struct rip_info *rinfo;

  if (type == RMAP_RIP)
    {
      addr = rule;
      rinfo = object;
    
      if (IPV4_ADDR_SAME (&rinfo->nexthop, addr))
	return RMAP_MATCH;
    }

  return RMAP_NOMATCH;
}

/* Route map `ip next-hop' match statement. `arg' is IP address
   string. */
void *
route_match_ip_nexthop_compile (char *arg)
{
  struct in_addr *addr;
  int ret;

  addr = XMALLOC (MTYPE_ROUTE_MAP_COMPILED, sizeof (struct in_addr));

  ret = inet_aton (arg, addr);
  if (!ret)
    {
      XFREE (MTYPE_ROUTE_MAP_COMPILED, addr);
      return NULL;
    }

  return addr;
}

/* Free route map's compiled `ip address' value. */
void
route_match_ip_nexthop_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Route map commands for ip next-hop matching. */
struct route_map_rule_cmd route_match_ip_nexthop_cmd =
{
  "ip next-hop",
  route_match_ip_nexthop,
  route_match_ip_nexthop_compile,
  route_match_ip_nexthop_free
};

/* `match ip address IP_ACCESS_LIST' */

/* Match function should return 1 if match is success else return
   zero. */
route_map_result_t
route_match_ip_address (void *rule, struct prefix *prefix, 
			route_map_object_t type, void *object)
{
  struct access_list *alist;
  /* struct prefix_ipv4 match; */

  if (type == RMAP_RIP)
    {
      alist = access_list_lookup (AF_INET, (char *) rule);
      if (alist == NULL)
	return RMAP_NOMATCH;
    
      return (access_list_apply (alist, prefix) == FILTER_DENY ?
	      RMAP_NOMATCH : RMAP_MATCH);
    }
  return RMAP_NOMATCH;
}

/* Route map `ip address' match statement.  `arg' should be
   access-list name. */
void *
route_match_ip_address_compile (char *arg)
{
  return XSTRDUP (MTYPE_ROUTE_MAP_COMPILED, arg);
}

/* Free route map's compiled `ip address' value. */
void
route_match_ip_address_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Route map commands for ip address matching. */
struct route_map_rule_cmd route_match_ip_address_cmd =
{
  "ip address",
  route_match_ip_address,
  route_match_ip_address_compile,
  route_match_ip_address_free
};

/* `set metric METRIC' */

/* Set metric to attribute. */
route_map_result_t
route_set_metric (void *rule, struct prefix *prefix, 
		  route_map_object_t type, void *object)
{
  u_int32_t *metric;
  struct rip_info *rinfo;

  if (type == RMAP_RIP)
    {
      /* Fetch routemap's rule information. */
      metric = rule;
      rinfo = object;
    
      /* Set metric out value. */
      rinfo->metric_out = *metric;
    }
  return RMAP_OKAY;
}

/* set metric compilation. */
void *
route_set_metric_compile (char *arg)
{
  u_int32_t *metric;

  metric = XMALLOC (MTYPE_ROUTE_MAP_COMPILED, sizeof (u_int32_t));
  *metric = atoi (arg);

  if (*metric > 0)
    return metric;

  XFREE (MTYPE_ROUTE_MAP_COMPILED, metric);
  return NULL;
}

/* Free route map's compiled `set metric' value. */
void
route_set_metric_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Set metric rule structure. */
struct route_map_rule_cmd route_set_metric_cmd = 
{
  "metric",
  route_set_metric,
  route_set_metric_compile,
  route_set_metric_free,
};

/* `set ip next-hop IP_ADDRESS' */

/* Set nexthop to object.  ojbect must be pointer to struct attr. */
route_map_result_t
route_set_ip_nexthop (void *rule, struct prefix *prefix, 
		      route_map_object_t type, void *object)
{
  struct in_addr *address;
  struct rip_info *rinfo;

  if(type == RMAP_RIP)
    {
      /* Fetch routemap's rule information. */
      address = rule;
      rinfo = object;
    
      /* Set next hop value. */ 
      rinfo->nexthop_out = *address;
    }

  return RMAP_OKAY;
}

/* Route map `ip nexthop' compile function.  Given string is converted
   to struct in_addr structure. */
void *
route_set_ip_nexthop_compile (char *arg)
{
  int ret;
  struct in_addr *address;

  address = XMALLOC (MTYPE_ROUTE_MAP_COMPILED, sizeof (struct in_addr));

  ret = inet_aton (arg, address);

  if (ret == 0)
    {
      XFREE (MTYPE_ROUTE_MAP_COMPILED, address);
      return NULL;
    }

  return address;
}

/* Free route map's compiled `ip nexthop' value. */
void
route_set_ip_nexthop_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Route map commands for ip nexthop set. */
struct route_map_rule_cmd route_set_ip_nexthop_cmd =
{
  "ip next-hop",
  route_set_ip_nexthop,
  route_set_ip_nexthop_compile,
  route_set_ip_nexthop_free
};

#define MATCH_STR "Match values from routing table\n"
#define SET_STR "Set values in destination routing protocol\n"

DEFUN (match_metric, 
       match_metric_cmd,
       "match metric <0-16>",
       MATCH_STR
       "Match metric of route\n"
       "Metric value\n")
{
  return rip_route_match_add (vty, vty->index, "metric", argv[0]);
}

DEFUN (no_match_metric,
       no_match_metric_cmd,
       "no match metric <0-16>",
       NO_STR
       MATCH_STR
       "Match metric of route\n"
       "Metric value\n")
{
  return rip_route_match_delete (vty, vty->index, "metric", argv[0]);
}

DEFUN (match_interface,
       match_interface_cmd,
       "match interface WORD",
       MATCH_STR
       "Match first hop interface of route\n"
       "Interface name\n")
{
  return rip_route_match_add (vty, vty->index, "interface", argv[0]);
}

DEFUN (no_match_interface,
       no_match_interface_cmd,
       "no match interface WORD",
       NO_STR
       MATCH_STR
       "Match first hop interface of route\n"
       "Interface name\n")
{
  return rip_route_match_delete (vty, vty->index, "interface", argv[0]);
}

DEFUN (match_ip_nexthop,
       match_ip_nexthop_cmd,
       "match ip next-hop A.B.C.D",
       MATCH_STR
       IP_STR
       "Next hop address\n"
       "IP address of next hop\n")
{
  return rip_route_match_add (vty, vty->index, "ip next-hop", argv[0]);
}

DEFUN (no_match_ip_nexthop,
       no_match_ip_nexthop_cmd,
       "no match ip next-hop A.B.C.D",
       NO_STR
       MATCH_STR
       IP_STR
       "Next hop address\n"
       "IP address of next hop\n")
{
  return rip_route_match_delete (vty, vty->index, "ip next-hop", argv[0]);
}

DEFUN (match_ip_address, 
       match_ip_address_cmd,
       "match ip address WORD",
       MATCH_STR
       IP_STR
       "Match address of route\n"
       "IP access-list name\n")
{
  return rip_route_match_add (vty, vty->index, "ip address", argv[0]);
}

DEFUN (no_match_ip_address, 
       no_match_ip_address_cmd,
       "no match ip address WORD",
       NO_STR
       MATCH_STR
       IP_STR
       "Match address of route\n"
       "IP access-list name\n")
{
  return rip_route_match_delete (vty, vty->index, "ip address", argv[0]);
}

/* set functions */

DEFUN (set_metric,
       set_metric_cmd,
       "set metric <0-16>",
       SET_STR
       "Metric value for destination routing protocol\n"
       "Metric value\n")
{
  return rip_route_set_add (vty, vty->index, "metric", argv[0]);
}

DEFUN (no_set_metric,
       no_set_metric_cmd,
       "no set metric <0-16>",
       NO_STR
       SET_STR
       "Metric value for destination routing protocol\n"
       "Metric value\n")
{
  return rip_route_set_delete (vty, vty->index, "metric", argv[0]);
}

DEFUN (set_ip_nexthop,
       set_ip_nexthop_cmd,
       "set ip next-hop A.B.C.D",
       SET_STR
       IP_STR
       "Next hop address\n"
       "IP address of next hop\n")
{
  return rip_route_set_add (vty, vty->index, "ip next-hop", argv[0]);
}

DEFUN (no_set_ip_nexthop,
       no_set_ip_nexthop_cmd,
       "no set ip next-hop A.B.C.D",
       NO_STR
       SET_STR
       IP_STR
       "Next hop address\n"
       "IP address of next hop\n")
{
  return rip_route_set_delete (vty, vty->index, "ip next-hop", argv[0]);
}

void
rip_route_map_reset ()
{
  ;
}

/* Route-map init */
void
rip_route_map_init ()
{
  route_map_init ();
  route_map_init_vty ();
  route_map_add_hook (rip_route_map_update);

  route_map_install_match (&route_match_metric_cmd);
  route_map_install_match (&route_match_interface_cmd);
  route_map_install_match (&route_match_ip_nexthop_cmd);
  route_map_install_match (&route_match_ip_address_cmd);

  route_map_install_set (&route_set_metric_cmd);
  route_map_install_set (&route_set_ip_nexthop_cmd);

  install_element (RMAP_NODE, &match_metric_cmd);
  install_element (RMAP_NODE, &no_match_metric_cmd);
  install_element (RMAP_NODE, &match_interface_cmd);
  install_element (RMAP_NODE, &no_match_interface_cmd);
  install_element (RMAP_NODE, &match_ip_nexthop_cmd);
  install_element (RMAP_NODE, &no_match_ip_nexthop_cmd);
  install_element (RMAP_NODE, &match_ip_address_cmd);
  install_element (RMAP_NODE, &no_match_ip_address_cmd);
  
  install_element (RMAP_NODE, &set_metric_cmd);
  install_element (RMAP_NODE, &no_set_metric_cmd);
  install_element (RMAP_NODE, &set_ip_nexthop_cmd);
  install_element (RMAP_NODE, &no_set_ip_nexthop_cmd);
}
