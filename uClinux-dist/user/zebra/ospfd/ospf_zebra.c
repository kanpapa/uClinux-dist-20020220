/*
 * Zebra connect library for OSPFd
 * Copyright (C) 1997, 98, 99, 2000 Kunihiro Ishiguro, Toshiaki Takada
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
 * along with GNU Zebra; see the file COPYING.  If not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA. 
 */

#include <zebra.h>

#include "thread.h"
#include "command.h"
#include "network.h"
#include "prefix.h"
#include "table.h"
#include "stream.h"
#include "memory.h"
#include "zclient.h"
#include "filter.h"
#include "log.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_ism.h"
#include "ospfd/ospf_zebra.h"
#include "ospfd/ospf_asbr.h"
#include "ospfd/ospf_abr.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_dump.h"

extern unsigned long term_debug_ospf_zebra;

/* Zebra structure to hold current status. */
struct zebra *zclient = NULL;

/* For registering threads. */
extern struct thread_master *master;

/* Inteface addition message from zebra. */
int
ospf_interface_add (int command, struct zebra *zebra, zebra_size_t length)
{
  struct interface *ifp;

  ifp = zebra_interface_add_read (zclient->ibuf);

  if (IS_DEBUG_OSPF (zebra, ZEBRA_INTERFACE))
    zlog_info ("Zebra: interface add %s index %d flags %d metric %d mtu %d",
	       ifp->name, ifp->ifindex, ifp->flags, ifp->metric, ifp->mtu);

  ospf_if_update ();

  return 0;
}

int
ospf_interface_delete (int command, struct zebra *zebra, zebra_size_t length)
{
  return 0;
}

int
ospf_interface_state_up (int command, struct zebra *zebra, zebra_size_t length)
{
  struct interface *ifp;

  ifp = zebra_interface_state_read (zclient->ibuf);

  if (ifp == NULL)
    return 0;

  if (IS_DEBUG_OSPF (zebra, ZEBRA_INTERFACE))
    zlog_info ("Zebra: Interface[%s] state change to up.", ifp->name);

  ospf_if_up (ifp);

  return 0;
}

int
ospf_interface_state_down (int command, struct zebra *zebra,
			   zebra_size_t length)
{
  struct interface *ifp;

  ifp = zebra_interface_state_read (zclient->ibuf);

  if (ifp == NULL)
    return 0;

  if (IS_DEBUG_OSPF (zebra, ZEBRA_INTERFACE))
    zlog_info ("Zebra: Interface[%s] state change to down.", ifp->name);

  ospf_if_down (ifp);

  return 0;
}

int
ospf_interface_address_add (int command, struct zebra *zebra,
			    zebra_size_t length)
{
  struct connected *c;

  c = zebra_interface_address_add_read (zclient->ibuf);

  if (c == NULL)
    return 0;

#if 0
  if (IS_DEBUG_OSPF (zebra, ZEBRA_INTERFACE))
    {
      struct prefix *p;

      p = c->address;
      if (p->family == AF_INET)
	zlog_info (" connected address %s/%d", 
		   inet_atop (p->u.prefix4), p->prefixlen);
    }
#endif

  ospf_if_update ();

  return 0;
}

int
ospf_interface_address_delete (int command, struct zebra *zebra,
			       zebra_size_t length)
{
  return 0;
}


void
ospf_zebra_add (struct prefix_ipv4 *p, struct in_addr *nexthop)
{
  if (zclient->redist[ZEBRA_ROUTE_OSPF])
    {
      zebra_ipv4_add (zclient->sock, ZEBRA_ROUTE_OSPF, 0, p, nexthop, 0);

      if (IS_DEBUG_OSPF (zebra, ZEBRA_REDISTRIBUTE))
	{
	  char *nexthop_str;

	  nexthop_str = strdup (inet_ntoa (*nexthop));
	  zlog_info ("Zebra: Route add %s/%d nexthop %s",
		     inet_ntoa (p->prefix), p->prefixlen, nexthop_str);
	  free (nexthop_str);
	}
    }
}

void
ospf_zebra_delete (struct prefix_ipv4 *p, struct in_addr *nexthop)
{
  if (zclient->redist[ZEBRA_ROUTE_OSPF])
    {
      zebra_ipv4_delete (zclient->sock, ZEBRA_ROUTE_OSPF, 0, p, nexthop, 0);

      if (IS_DEBUG_OSPF (zebra, ZEBRA_REDISTRIBUTE))
	{
	  char *nexthop_str;

	  nexthop_str = strdup (inet_ntoa (*nexthop));
	  zlog_info ("Zebra: Route delete %s/%d nexthop %s",
		     inet_ntoa (p->prefix), p->prefixlen, nexthop_str);
	  free (nexthop_str);
	}
    }
}

void
ospf_zebra_add_discard (struct prefix_ipv4 *p)
{
  struct in_addr lo_addr;

  lo_addr.s_addr = htonl (INADDR_LOOPBACK);

  if (zclient->redist[ZEBRA_ROUTE_OSPF])
    zebra_ipv4_add (zclient->sock, ZEBRA_ROUTE_OSPF, ZEBRA_FLAG_BLACKHOLE, 
		    p, &lo_addr, 0);
}

void
ospf_zebra_delete_discard (struct prefix_ipv4 *p)
{
  struct in_addr lo_addr;

  lo_addr.s_addr = htonl (INADDR_LOOPBACK);

  if (zclient->redist[ZEBRA_ROUTE_OSPF])
    zebra_ipv4_delete (zclient->sock, ZEBRA_ROUTE_OSPF, ZEBRA_FLAG_BLACKHOLE, 
		       p, &lo_addr, 0);
}

int
ospf_redistribute_set (int type, u_char metric_type,
		       u_char metric_method, u_char metric_value)
{
  if (zclient->redist[type])
    return CMD_SUCCESS;

  zclient->redist[type] = 1;
  ospf_top->dmetric[type].type = metric_type;
  ospf_top->dmetric[type].method = metric_method;
  ospf_top->dmetric[type].value  = metric_value;

  if (zclient->sock > 0)
    {
      zebra_redistribute_send (ZEBRA_REDISTRIBUTE_ADD, zclient->sock, type);

      if (IS_DEBUG_OSPF (zebra, ZEBRA_REDISTRIBUTE))
	zlog_info ("Redistribute[%s]: Start",
		   LOOKUP (ospf_redistributed_proto, type));
    }

  ospf_asbr_status_update (++ospf_top->redistribute);

  return CMD_SUCCESS;
}

int
ospf_redistribute_unset (int type)
{
  if (!zclient->redist[type])
    return CMD_SUCCESS;

  zclient->redist[type] = 0;

  if (zclient->sock > 0)
    {
      zebra_redistribute_send (ZEBRA_REDISTRIBUTE_DELETE, zclient->sock, type);

      if (IS_DEBUG_OSPF (zebra, ZEBRA_REDISTRIBUTE))
	zlog_info ("Redistribute[%s]: Stop",
		   LOOKUP (ospf_redistributed_proto, type));
    }

  /* Remove the routes from OSPF table. */
  ospf_redistribute_withdraw (type);

  ospf_asbr_status_update (--ospf_top->redistribute);

  return CMD_SUCCESS;
}

/* Check the prefix with appling distribut-list.
   0: deny, 1: permit. */
int
ospf_distribute_check (int type, struct prefix_ipv4 *p)
{
  if (DISTRIBUTE_NAME (type))
    /* distirbute-list exists, but access-list may not? */
    if (DISTRIBUTE_LIST (type))
      if (access_list_apply (DISTRIBUTE_LIST (type), p) == FILTER_DENY)
	{
	  if (IS_DEBUG_OSPF (zebra, ZEBRA_REDISTRIBUTE))
	    zlog_info ("Redistribute[%s]: %s/%d filtered by ditribute-list.",
		       LOOKUP (ospf_redistributed_proto, type),
		       inet_ntoa (p->prefix), p->prefixlen);
	  return 0;
	}

  return 1;
}

/* Zebra route add and delete treatment. */
int
ospf_zebra_read_ipv4 (int command, struct zebra *zebra, zebra_size_t length)
{
  u_char type;
  u_char flags;
  struct in_addr nexthop;
  u_char *lim;
  struct stream *s;
  unsigned int ifindex;

  s = zclient->ibuf;
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
      struct external_info *ei;

      ifindex = stream_getl (s);

      bzero (&p, sizeof (struct prefix_ipv4));
      p.family = AF_INET;
      p.prefixlen = stream_getc (s);
      size = PSIZE (p.prefixlen);
      stream_get (&p.prefix, s, size);

      if (command == ZEBRA_IPV4_ROUTE_ADD)
	{
	  ei = ospf_external_info_add (type, p, ifindex, nexthop);

	  if (ospf_top->router_id.s_addr == 0)
	    ospf_top->external_origin = 1;
	  else if (ei)
	    {
	      if (ospf_distribute_check (type, &ei->p))
		{
		  ospf_external_lsa_originate (type, ei);
		  ei->flags = EXTERNAL_ORIGINATED;
		}
	      else
		ei->flags = EXTERNAL_FILTERED;
	    }
	}
      else /* if (command == ZEBRA_IPV4_ROUTE_DELETE) */
	{
	  ospf_external_info_delete (type, p);
	  ospf_external_lsa_flush (type, &p, ifindex, nexthop);
	}
    }

  return 0;
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

#if 0
DEFUN (ospf_redistribute_ospf,
       ospf_redistribute_ospf_cmd,
       "redistribute OSPF",
       "Redistribute control\n"
       "OSPF route\n")
{
  zclient->redist[ZEBRA_ROUTE_OSPF] = 1;
  return CMD_SUCCESS;
}

DEFUN (no_ospf_redistribute_ospf,
       no_ospf_redistribute_ospf_cmd,
       "no redistribute OSPF",
       NO_STR
       "Redistribute control\n"
       "OSPF route\n")
{
  zclient->redist[ZEBRA_ROUTE_OSPF] = 0;
  return CMD_SUCCESS;
}

DEFUN (ospf_redistribute_kernel,
       ospf_redistribute_kernel_cmd,
       "redistribute kernel",
       "Redistribute control\n"
       "Kernel route\n")
{
  return ospf_redistribute_set (ZEBRA_ROUTE_KERNEL, EXTERNAL_METRIC_TYPE_2,
				OSPF_EXT_METRIC_AUTO, 0);
}

DEFUN (no_ospf_redistribute_kernel,
       no_ospf_redistribute_kernel_cmd,
       "no redistribute kernel",
       NO_STR
       "Redistribute control\n"
       "Kernel route\n")
{
  return ospf_redistribute_unset (ZEBRA_ROUTE_KERNEL);
}
#endif

DEFUN (ospf_redistribute_source_metric_type,
       ospf_redistribute_source_metric_type_cmd,
       "redistribute (kernel|connected|static|rip|bgp) metric <0-16777214> metric-type (1|2)",
       "Redistribute control\n"
       "Kernel FIB routes\n"
       "Connected routes\n"
       "Static routes\n"
       "RIP routes\n"
       "BGP routes\n"
       "Set external metric value\n"
       "Metric value\n"
       "Set OSPF external metric type\n"
       "External type-1\n"
       "External type-2\n")
{
  int source, method = OSPF_EXT_METRIC_AUTO;
  u_char type = EXTERNAL_METRIC_TYPE_2;
  u_int32_t metric = 0;

  if (strncmp (argv[0], "k", 1) == 0)
    source = ZEBRA_ROUTE_KERNEL;
  else if (strncmp (argv[0], "c", 1) == 0)
    source = ZEBRA_ROUTE_CONNECT;
  else if (strncmp (argv[0], "s", 1) == 0)
    source = ZEBRA_ROUTE_STATIC;
  else if (strncmp (argv[0], "r", 1) == 0)
    source = ZEBRA_ROUTE_RIP;
  else if (strncmp (argv[0], "b", 1) == 0)
    source = ZEBRA_ROUTE_BGP;
  else
    return CMD_WARNING;

  /* if (argc == 1)
       {
         method = OSPF_EXT_METRIC_AUTO;
         type = EXTERNAL_METRIC_TYPE_2;
	 metric = 0;
       } */
  if (argc >= 2)
    {
      metric = strtol (argv[1], NULL, 10);
      if (metric < 0 && metric > 16777214)
	{
	  vty_out (vty, "OSPF metric value is invalid %s", VTY_NEWLINE);
	  return CMD_WARNING;
	}
      method = OSPF_EXT_METRIC_STATIC;
    }

  if (argc == 3)
    {
      if (strncmp (argv[2], "1", 1) == 0)
	type = EXTERNAL_METRIC_TYPE_1;
      else if (strncmp (argv[1], "2", 1) == 0)
	type = EXTERNAL_METRIC_TYPE_2;
      else
	return CMD_WARNING;
    }

  return ospf_redistribute_set (source, type, method, metric);
}

ALIAS (ospf_redistribute_source_metric_type,
       ospf_redistribute_source_metric_cmd,
       "redistribute (kernel|connected|static|rip|bgp) metric <0-16777214>",
       "Redistribute control\n"
       "Kernel FIB routes\n"
       "Connected routes\n"
       "Static routes\n"
       "RIP routes\n"
       "BGP routes\n"
       "Set OSPF external metric type\n"
       "Set external metric\n"
       "Metric value\n")

DEFUN (ospf_redistribute_source_type_metric,
       ospf_redistribute_source_type_metric_cmd,
       "redistribute (kernel|connected|static|rip|bgp) metric-type (1|2) metric <0-16777214>",
       "Redistribute control\n"
       "Kernel FIB routes\n"
       "Connected routes\n"
       "Static routes\n"
       "RIP routes\n"
       "BGP routes\n"
       "Set OSPF external metric type\n"
       "External type-1\n"
       "External type-2\n"
       "Set external metric value\n"
       "Metric value")
{
  int source, method = OSPF_EXT_METRIC_AUTO;
  u_char type = EXTERNAL_METRIC_TYPE_2;
  u_int32_t metric = 0;

  if (strncmp (argv[0], "k", 1) == 0)
    source = ZEBRA_ROUTE_KERNEL;
  else if (strncmp (argv[0], "c", 1) == 0)
    source = ZEBRA_ROUTE_CONNECT;
  else if (strncmp (argv[0], "s", 1) == 0)
    source = ZEBRA_ROUTE_STATIC;
  else if (strncmp (argv[0], "r", 1) == 0)
    source = ZEBRA_ROUTE_RIP;
  else if (strncmp (argv[0], "b", 1) == 0)
    source = ZEBRA_ROUTE_BGP;
  else
    return CMD_WARNING;

  /* if (argc == 1)
       {
         method = OSPF_EXT_METRIC_AUTO;
         type = EXTERNAL_METRIC_TYPE_2;
	 metric = 0;
       } */
  if (argc >= 2)
    {
      if (strncmp (argv[1], "1", 1) == 0)
	type = EXTERNAL_METRIC_TYPE_1;
      else if (strncmp (argv[1], "2", 1) == 0)
	type = EXTERNAL_METRIC_TYPE_2;
      else
	return CMD_WARNING;
    }

  if (argc == 3)
    {
      metric = strtol (argv[2], NULL, 10);
      if (metric < 0 && metric > 16777214)
	{
	  vty_out (vty, "OSPF metric value is invalid %s", VTY_NEWLINE);
	  return CMD_WARNING;
	}
      method = OSPF_EXT_METRIC_STATIC;
    }

  return ospf_redistribute_set (source, type, method, metric);
}

ALIAS (ospf_redistribute_source_type_metric,
       ospf_redistribute_source_type_cmd,
       "redistribute (kernel|connected|static|rip|bgp) metric-type (1|2)",
       "Redistribute control\n"
       "Kernel FIB routes\n"
       "Connected routes\n"
       "Static routes\n"
       "RIP routes\n"
       "BGP routes\n"
       "Set OSPF external metric type\n"
       "External type-1\n"
       "External type-2\n")

ALIAS (ospf_redistribute_source_type_metric,
       ospf_redistribute_source_cmd,
       "redistribute (kernel|connected|static|rip|bgp)",
       "Redistribute control\n"
       "Kernel FIB routes\n"
       "Connected routes\n"
       "Static routes\n"
       "RIP routes\n"
       "BGP routes\n")


DEFUN (no_ospf_redistribute_source,
       no_ospf_redistribute_source_cmd,
       "no redistribute (kernel|connected|static|rip|bgp)",
       NO_STR
       "Redistribute control\n"
       "Kernel FIB routes\n"
       "Connected routes\n"
       "Static routes\n"
       "RIP routes\n"
       "BGP routes\n")
{
  int source;

  if (strncmp (argv[0], "k", 1) == 0)
    source = ZEBRA_ROUTE_KERNEL;
  else if (strncmp (argv[0], "c", 1) == 0)
    source = ZEBRA_ROUTE_CONNECT;
  else if (strncmp (argv[0], "s", 1) == 0)
    source = ZEBRA_ROUTE_STATIC;
  else if (strncmp (argv[0], "r", 1) == 0)
    source = ZEBRA_ROUTE_RIP;
  else if (strncmp (argv[0], "b", 1) == 0)
    source = ZEBRA_ROUTE_BGP;
  else
    return CMD_WARNING;

  return ospf_redistribute_unset (source);
}

#if 0
ALIAS (no_ospf_redistribute_source,
       no_ospf_redistribute_source_type_cmd,
       "no redistribute (kernel|connected|static|rip|bgp) metric-type (1|2)",
       NO_STR
       "Redistribute control\n"
       "Kernel FIB routes\n"
       "Connected routes\n"
       "Static routes\n"
       "RIP routes\n"
       "BGP routes\n"
       "Set OSPF external metric type\n"
       "External type-1\n"
       "External type-2\n")

ALIAS (no_ospf_redistribute_source,
       no_ospf_redistribute_source_metric_cmd,
       "no redistribute (kernel|connected|static|rip|bgp) metric <0-16777214>",
       NO_STR
       "Redistribute control\n"
       "Kernel FIB routes\n"
       "Connected routes\n"
       "Static routes\n"
       "RIP routes\n"
       "BGP routes\n"
       "Set external metric"
       "Metric value")

ALIAS (no_ospf_redistribute_source,
       no_ospf_redistribute_source_type_metric_cmd,
       "no redistribute (kernel|connected|static|rip|bgp) metric-type (1|2) metric <0-16777214>",
       NO_STR
       "Redistribute control\n"
       "Kernel FIB routes\n"
       "Connected routes\n"
       "Static routes\n"
       "RIP routes\n"
       "BGP routes\n"
       "Set OSPF external metric type\n"
       "External type-1\n"
       "External type-2\n"
       "Set external metric value\n"
       "Metric value\n")
#endif

int
ospf_distribute_list_out_set (struct vty *vty, int type, char *name)
{
  /* Lookup access-list for distribute-list. */
  DISTRIBUTE_LIST (type) = access_list_lookup (AF_INET, name);

  /* Clear previous distribute-name. */
  if (DISTRIBUTE_NAME (type))
    free (DISTRIBUTE_NAME (type));

  /* Set distribute-name. */
  DISTRIBUTE_NAME (type) = strdup (name);

  /* If access-list have been set, schedule update timer. */
  if (DISTRIBUTE_LIST (type))
    ospf_distribute_list_update (type);

  return CMD_SUCCESS;
}

int
ospf_distribute_list_out_unset (struct vty *vty, int type, char *name)
{
  /* Schedule update timer. */
  if (DISTRIBUTE_LIST (type))
    ospf_distribute_list_update (type);

  /* Unset distribute-list. */
  DISTRIBUTE_LIST (type) = NULL;

  /* Clear distribute-name. */
  if (DISTRIBUTE_NAME (type))
    free (DISTRIBUTE_NAME (type));
  
  DISTRIBUTE_NAME (type) = NULL;

  return CMD_SUCCESS;
}

#define OUT_STR "Filter outgoing routing updates\n"
#define IN_STR  "Filter incoming routing updates\n"

DEFUN (ospf_distribute_list_out,
       ospf_distribute_list_out_cmd,
       "distribute-list NAME out (kernel|connected|static|rip|bgp)",
       "Filter networks in routing updates\n"
       "Access-list name\n"
       OUT_STR
       "Kernel routes\n"
       "Connected routes\n"
       "Static routes\n"
       "Routing Information Protocol (RIP)\n"
       "Border Gateway Protocol (BGP)\n")
{
  int source;

  if (strncmp (argv[1], "k", 1) == 0)
    source = ZEBRA_ROUTE_KERNEL;
  else if (strncmp (argv[1], "c", 1) == 0)
    source = ZEBRA_ROUTE_CONNECT;
  else if (strncmp (argv[1], "s", 1) == 0)
    source = ZEBRA_ROUTE_STATIC;
  else if (strncmp (argv[1], "r", 1) == 0)
    source = ZEBRA_ROUTE_RIP;
  else if (strncmp (argv[1], "b", 1) == 0)
    source = ZEBRA_ROUTE_BGP;
  else
    return CMD_WARNING;

  return ospf_distribute_list_out_set (vty, source, argv[0]);
}

DEFUN (no_ospf_distribute_list_out,
       no_ospf_distribute_list_out_cmd,
       "no distribute-list NAME out (kernel|connected|static|rip|bgp)",
       NO_STR
       "Filter networks in routing updates\n"
       "Access-list name\n"
       OUT_STR
       "Kernel routes\n"
       "Connected routes\n"
       "Static routes\n"
       "Routing Information Protocol (RIP)\n"
       "Border Gateway Protocol (BGP)\n")
{
  int source;

  if (strncmp (argv[1], "k", 1) == 0)
    source = ZEBRA_ROUTE_KERNEL;
  else if (strncmp (argv[1], "c", 1) == 0)
    source = ZEBRA_ROUTE_CONNECT;
  else if (strncmp (argv[1], "s", 1) == 0)
    source = ZEBRA_ROUTE_STATIC;
  else if (strncmp (argv[1], "r", 1) == 0)
    source = ZEBRA_ROUTE_RIP;
  else if (strncmp (argv[1], "b", 1) == 0)
    source = ZEBRA_ROUTE_BGP;
  else
    return CMD_WARNING;

  return ospf_distribute_list_out_unset (vty, source, argv[0]);
}

/* distribute-list update timer. */
int
ospf_distribute_list_update_timer (struct thread *thread)
{
  struct route_node *rn;
  struct external_info *ei;
  struct route_table *rt;
  u_char type;

  type = (int) THREAD_ARG (thread);
  rt = EXTERNAL_INFO (type);

  ospf_top->t_distribute_update = NULL;

  zlog_info ("Zebra[Redistribute]: distribute-list update timer fired!");

  /* foreach all external info. */
  for (rn = route_top (rt); rn; rn = route_next (rn))
    if ((ei = rn->info) != NULL)
      {
	/* FILTER_PERMIT. */
	if (ospf_distribute_check (type, (struct prefix_ipv4 *) &ei->p))
	  {
	    if (ei->flags != EXTERNAL_ORIGINATED)
	      {
		ospf_external_lsa_originate (type, ei);
		if (IS_DEBUG_OSPF (zebra, ZEBRA_REDISTRIBUTE))
		  zlog_info ("Redistribute[%s]: %s/%d permitted.",
			     LOOKUP (ospf_redistributed_proto, type),
			     inet_ntoa (ei->p.prefix), ei->p.prefixlen);
		ei->flags = EXTERNAL_ORIGINATED;
	      }
	  }
	/* FILTER_DENY. */
	else
	  {
	    if (ei->flags != EXTERNAL_FILTERED)
	      {
		ospf_external_lsa_flush (type, &ei->p,
					 ei->ifindex, ei->nexthop);
		if (IS_DEBUG_OSPF (zebra, ZEBRA_REDISTRIBUTE))
		  zlog_info ("Redistribute[%s]: %s/%d denied.",
			     LOOKUP (ospf_redistributed_proto, type),
			     inet_ntoa (ei->p.prefix), ei->p.prefixlen);
		ei->flags = EXTERNAL_FILTERED;
	      }
	  }
      }
  return 0;
}

#define OSPF_DISTRIBUTE_UPDATE_DELAY 5

/* Update distribute-list and set timer to apply access-list. */
void
ospf_distribute_list_update (int type)
{
  struct route_table *rt;
  
  zlog_info ("ospf_distribute_list_update(): start");

  /* External info does not exist. */
  if (!(rt = EXTERNAL_INFO (type)))
    return;

  /* If exists previously invoked thread, then cancel it. */
  if (ospf_top->t_distribute_update)
    OSPF_TIMER_OFF (ospf_top->t_distribute_update);

  /* Set timer. */
  ospf_top->t_distribute_update =
    thread_add_timer (master, ospf_distribute_list_update_timer,
		      (void *) type, OSPF_DISTRIBUTE_UPDATE_DELAY);

  zlog_info ("ospf_distribute_list_update(): stop");
}

/* If access-list is updated, apply some check. */
void
ospf_filter_update (struct access_list *access)
{
  int type;
  int abr_inv = 0;
  struct ospf_area *area;
  listnode node;

  /* If OSPF instatnce does not exist, return right now. */
  if (!ospf_top)
    return;

  /* Update distribute-list, and apply filter. */
  for (type = 0; type < ZEBRA_ROUTE_MAX; type++)
    if (DISTRIBUTE_NAME (type))
      {
	/* Keep old access-list for distribute-list. */
	struct access_list *old = DISTRIBUTE_LIST (type);

	/* Update access-list for distribute-list. */
	DISTRIBUTE_LIST (type) =
	  access_list_lookup (AF_INET, DISTRIBUTE_NAME (type));

	/* No update for this distribute type. */
	if (old == NULL && DISTRIBUTE_LIST (type) == NULL)
	  continue;

	/* Schedule distribute-list update timer. */
	if (DISTRIBUTE_LIST (type) == NULL ||
	    strcmp (DISTRIBUTE_NAME (type), access->name) == 0)
	  ospf_distribute_list_update (type);
      }

  /* Update Area access-list. */
  for (node = listhead (ospf_top->areas); node; nextnode (node))
    if ((area = getdata (node)) != NULL)
      {
	if (EXPORT_NAME (area))
	  {
	    EXPORT_LIST (area) = NULL;
	    abr_inv++;
	  }

	if (IMPORT_NAME (area))
	  {
	    IMPORT_LIST (area) = NULL;
	    abr_inv++;
	  }
      }

  /* Schedule ABR tasks -- this will be changed -- takada. */
  if (OSPF_IS_ABR && abr_inv)
    ospf_schedule_abr_task ();
}

/* Default information orginate. */
DEFUN (ospf_default_information_originate,
       ospf_default_information_originate_cmd,
       "default-information originate",
       "Control distribution of default information\n"
       "Distribute a default route\n")
{
  struct external_info *ei;
  struct prefix_ipv4 p;

  ospf_top->default_information = DEFAULT_ORIGINATE_ZEBRA;

  p.family = AF_INET;
  p.prefix.s_addr = 0;
  p.prefixlen = 0;

  ei = ospf_external_info_lookup (ZEBRA_ROUTE_STATIC, &p);
  if (ei)
    ospf_external_lsa_originate (ZEBRA_ROUTE_STATIC, ei);

  return CMD_SUCCESS;
}

DEFUN (no_ospf_default_information_originate,
       no_ospf_default_information_originate_cmd,
       "no default-information originate",
       NO_STR
       "Control distribution of default information\n"
       "Distribute a default route\n")
{
  struct prefix_ipv4 p;
  struct external_info *ei;

  ospf_top->default_information = DEFAULT_ORIGINATE_NONE;

  p.family = AF_INET;
  p.prefix.s_addr = 0;
  p.prefixlen = 0;

  ei = ospf_external_info_lookup (ZEBRA_ROUTE_STATIC, &p);
  if (ei)
    ospf_external_lsa_flush (ZEBRA_ROUTE_STATIC, &ei->p,
			     ei->ifindex, ei->nexthop);

  return CMD_SUCCESS;
}

/* Zebra configuration write function. */
int
zebra_config_write (struct vty *vty)
{
  if (! zclient->enable)
    {
      vty_out (vty, "no router zebra%s", VTY_NEWLINE);
      return 1;
    }
  else if (! zclient->redist[ZEBRA_ROUTE_OSPF])
    {
      vty_out (vty, "router zebra%s", VTY_NEWLINE);
      vty_out (vty, " no redistribute ospf%s", VTY_NEWLINE);
      return 1;
    }
  return 0;
}

int
config_write_ospf_redistribute (struct vty *vty)
{
  int i;
  char *str[] = { "system", "kernel", "connected", "static", "rip",
		  "ripng", "ospf", "ospf6", "bgp"};

  for (i = 0; i < ZEBRA_ROUTE_MAX; i++)
    if (i != zclient->redist_default && zclient->redist[i])
      {
        vty_out (vty, " redistribute %s", str[i]);

        if (ospf_top->dmetric[i].type != EXTERNAL_METRIC_TYPE_2)
	  vty_out (vty, " metric-type 1");

        if (ospf_top->dmetric[i].method != OSPF_EXT_METRIC_AUTO)
	  vty_out (vty, " metric %d", ospf_top->dmetric[i].value);

        vty_out (vty, "%s", VTY_NEWLINE);
      }

  if (ospf_top)
    for (i = 0; i < ZEBRA_ROUTE_MAX; i++)
      if (ospf_top->dlist[i].name)
	vty_out (vty, " distribute-list %s out %s%s", 
		 ospf_top->dlist[i].name, str[i], VTY_NEWLINE);

  return 0;
}

/* Zebra node structure. */
struct cmd_node zebra_node =
{
  ZEBRA_NODE,
  "%s(config-router)#",
};

void
zebra_init ()
{
  /* Allocate zebra structure. */
  zclient = zclient_new ();
  zclient_init (zclient, ZEBRA_ROUTE_OSPF);
  zclient->interface_add = ospf_interface_add;
  zclient->interface_delete = ospf_interface_delete;
  zclient->interface_up = ospf_interface_state_up;
  zclient->interface_down = ospf_interface_state_down;
  zclient->interface_address_add = ospf_interface_address_add;
  zclient->interface_address_delete = ospf_interface_address_delete;
  zclient->ipv4_route_add = ospf_zebra_read_ipv4;
  zclient->ipv4_route_delete = ospf_zebra_read_ipv4;

  /* Install zebra node. */
  install_node (&zebra_node, zebra_config_write);

  /* Install command element for zebra node. */
  install_element (CONFIG_NODE, &router_zebra_cmd);
  install_element (CONFIG_NODE, &no_router_zebra_cmd);
  install_default (ZEBRA_NODE);
  install_element (OSPF_NODE, &ospf_redistribute_source_type_metric_cmd);
  install_element (OSPF_NODE, &ospf_redistribute_source_metric_type_cmd);
  install_element (OSPF_NODE, &ospf_redistribute_source_type_cmd);
  install_element (OSPF_NODE, &ospf_redistribute_source_metric_cmd);
  install_element (OSPF_NODE, &ospf_redistribute_source_cmd);

#if 0
  install_element (OSPF_NODE, &no_ospf_redistribute_source_type_metric_cmd);
  install_element (OSPF_NODE, &no_ospf_redistribute_source_metric_type_cmd); */
  install_element (OSPF_NODE, &no_ospf_redistribute_source_type_cmd);
  install_element (OSPF_NODE, &no_ospf_redistribute_source_metric_cmd);
#endif
  install_element (OSPF_NODE, &no_ospf_redistribute_source_cmd);

  install_element (OSPF_NODE, &ospf_distribute_list_out_cmd);
  install_element (OSPF_NODE, &no_ospf_distribute_list_out_cmd);

  access_list_add_hook (ospf_filter_update);
  access_list_delete_hook (ospf_filter_update);
}

