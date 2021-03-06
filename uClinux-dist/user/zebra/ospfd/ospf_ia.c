/*
 * OSPF inter-area routing.
 * Copyright (C) 1999, 2000 Alex Zinin, Toshiaki Takada
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

#include "thread.h"
#include "memory.h"
#include "hash.h"
#include "linklist.h"
#include "prefix.h"
#include "table.h"
#include "log.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_ism.h"
#include "ospfd/ospf_asbr.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_lsdb.h"
#include "ospfd/ospf_neighbor.h"
#include "ospfd/ospf_nsm.h"
#include "ospfd/ospf_spf.h"
#include "ospfd/ospf_route.h"
#include "ospfd/ospf_ase.h"
#include "ospfd/ospf_abr.h"
#include "ospfd/ospf_ia.h"

#define DEBUG

struct ospf_route *
ospf_find_abr_route (struct route_table *rtrs, 
                     struct prefix_ipv4 *abr,
                     struct ospf_area *area)
{
  struct route_node *rn;
  struct ospf_route *or;
  listnode node;

  if ((rn = route_node_lookup (rtrs, (struct prefix *) abr)) == NULL)
    return NULL;

  route_unlock_node (rn);

  for (node = listhead ((list) rn->info); node; nextnode (node))
    if ((or = getdata (node)) != NULL)
      if (or->u.std.area == area && (or->u.std.flags & ROUTER_LSA_BORDER))
	return or;

  return NULL;
}

void
ospf_ia_network_route (struct route_table *rt, struct prefix_ipv4 *p,
                       struct ospf_route *new_or, struct ospf_route *abr_or)
{
  struct route_node *rn1;
  struct ospf_route *or;

  zlog_info ("Z: ospf_ia_network_route(): processing summary route to %s/%d", 
             inet_ntoa (p->prefix), p->prefixlen);

  /* Find a route to the same dest */
  if ((rn1 = route_node_lookup (rt, (struct prefix *) p)))
    {
      int res;

      route_unlock_node (rn1);

      if ((or = rn1->info))
	{
	  zlog_info ("Z: ospf_ia_network_route(): "
		     "Found a route to the same network");

	  /* Check the existing route. */
	  if ((res = ospf_route_cmp (new_or, or)) < 0)
	    {
	      /* New route is better, so replace old one. */
	      ospf_route_subst (rn1, new_or, abr_or);
	    }
	  else if (res == 0)
	    {
	      /* New and old route are equal, so next hops can be added. */
	      route_lock_node (rn1);
	      ospf_route_copy_nexthops (or, abr_or->path);
	      route_unlock_node (rn1);

	      /* new route can be deleted, because existing route has been updated. */
	      ospf_route_free (new_or);
	    }
	  else
	    {
	      /* New route is worse, so free it. */
	      ospf_route_free (new_or);
	      return;
	    }
	} /* if (or)*/
    } /*if (rn1)*/
  else
    { /* no route */
      zlog_info ("Z: ospf_ia_network_route(): add new route to %s/%d",
                 inet_ntoa (p->prefix), p->prefixlen);

      ospf_route_add (rt, p, new_or, abr_or);
    }
}

void
ospf_ia_router_route (struct route_table *rt, struct prefix_ipv4 *p,
                      struct ospf_route *new_or, struct ospf_route *abr_or)
{
  struct route_node *rn;
  struct ospf_route *or = NULL;
  int ret;

  zlog_info ("Z: ospf_ia_router_route(): considering %s/%d", 
             inet_ntoa (p->prefix), p->prefixlen);

  /* Find a route to the same dest */
  rn = route_node_get (rt,(struct prefix *) p);
   
  if (rn->info == NULL)
    /* This is a new route */
    rn->info = list_init ();
  else
    {
      /* This is an additional route */
      route_unlock_node (rn);
      or = ospf_find_asbr_route_through_area (rt, p, new_or->u.std.area);
    }

  if (or)
    {
      zlog_info ("Z: ospf_ia_router_route(): "
                 "a route to the same ABR through the same area exists");

      /* New route is better */
      if ((ret = ospf_route_cmp (new_or, or)) < 0)
	{
	  list_delete_by_val (rn->info, or);
	  ospf_route_free (or);
	  /* proceed down */
	}
      /* Routes are the same */
      else if (ret == 0)
	{
	  zlog_info ("Z: ospf_ia_router_route(): merging the new route");

	  ospf_route_copy_nexthops (or, abr_or->path);
	  ospf_route_free (new_or);
	  return;
	}
      /* New route is worse */
      else
	{
	  zlog_info ("Z: ospf_ia_router_route(): skipping the new route");

	  ospf_route_free (new_or);
	  return;
	}
    }

  ospf_route_copy_nexthops (new_or, abr_or->path);

  zlog_info ("Z: ospf_ia_router_route(): adding the new route"); 
  list_add_node (rn->info, new_or);
}


struct ia_args
{
  struct route_table *rt;
  struct route_table *rtrs;
  struct ospf_area *area;
};

int
process_summary_lsa (struct ospf_lsa *l, void *v, int i)
{
  struct ospf_area_range *range;
  struct ospf_route *abr_or, *new_or;
  struct summary_lsa *sl;
  struct prefix_ipv4 p, abr;
  u_int32_t metric;
  struct ia_args *args;

  if (l == NULL)
    return 0;

  args = (struct ia_args *) v;
  sl = (struct summary_lsa *) l->data;

  zlog_info ("Z: process_summary_lsa(): LS ID: %s", inet_ntoa (sl->header.id));

  metric = GET_METRIC (sl->metric);
   
  if (metric == OSPF_LS_INFINITY)
    return 0;

  if (LS_AGE (l) == OSPF_LSA_MAX_AGE)
    return 0;

  if (ospf_lsa_is_self_originated (l))
    return 0;

  p.family = AF_INET;
  p.prefix = sl->header.id;
   
  if (sl->header.type == OSPF_SUMMARY_LSA)
    p.prefixlen = ip_masklen (sl->mask);
  else
    p.prefixlen = IPV4_MAX_BITLEN;
      
  apply_mask_ipv4 (&p);

  if (sl->header.type == OSPF_SUMMARY_LSA &&
      (range = ospf_some_area_range_match (&p)) &&
      ospf_range_active (range))
    return 0;

  if (ospf_top->abr_type != OSPF_ABR_STAND &&
      args->area->external_routing != OSPF_AREA_DEFAULT &&
      p.prefix.s_addr == OSPF_DEFAULT_DESTINATION &&
      p.prefixlen == 0)
    return 0; /* Ignore summary default from a stub area */

  abr.family = AF_INET;
  abr.prefix = sl->header.adv_router;
  abr.prefixlen = IPV4_MAX_BITLEN;
  apply_mask_ipv4 (&abr);

  abr_or = ospf_find_abr_route (args->rtrs, &abr, args->area);

  if (abr_or == NULL)
    return 0;

  new_or = ospf_route_new ();
  new_or->type = OSPF_DESTINATION_NETWORK;
  new_or->id = sl->header.id;
  new_or->mask = sl->mask;
  new_or->u.std.options = sl->header.options;
  new_or->u.std.origin = (struct lsa_header *) sl;
  new_or->cost = abr_or->cost + metric;
  new_or->u.std.area = args->area;
  new_or->path_type = OSPF_PATH_INTER_AREA;

  if (sl->header.type == OSPF_SUMMARY_LSA)
    ospf_ia_network_route (args->rt, &p, new_or, abr_or);
  else 
    {
      new_or->type = OSPF_DESTINATION_ROUTER;
      new_or->u.std.flags = ROUTER_LSA_EXTERNAL;
      ospf_ia_router_route (args->rtrs, &p, new_or, abr_or);
    }

  return 0;
}

void
ospf_examine_summaries (struct ospf_area * area,
                        /* struct ospf_lsdb *lsdb, */
			struct route_table *lsdb_rt,
                        struct route_table *rt,
                        struct route_table *rtrs)
{
  struct ia_args args = {rt, rtrs, area};
  /* ospf_lsdb_iterator (lsdb, &args, 0, process_summary_lsa); */
  foreach_lsa (lsdb_rt, &args, 0, process_summary_lsa);
}

int
ospf_area_is_transit (struct ospf_area *area)
{
  return (area->transit == OSPF_TRANSIT_TRUE) ||
    ospf_full_virtual_nbrs(area); /* Cisco forgets to set the V-bit :( */
}

void
ospf_update_network_route (struct route_table *rt, 
                           struct route_table *rtrs,
                           struct summary_lsa *lsa,
                           struct prefix_ipv4 *p,
                           struct ospf_area *area)
{
  struct route_node *rn;
  struct ospf_route *or, *abr_or, *new_or;
  struct prefix_ipv4 abr;
  u_int32_t cost;

  abr.family = AF_INET;
  abr.prefix =lsa->header.adv_router;
  abr.prefixlen = IPV4_MAX_BITLEN;
  apply_mask_ipv4 (&abr);

  abr_or = ospf_find_abr_route (rtrs, &abr, area);

  if (abr_or == NULL)
    {
      zlog_info ("Z: ospf_update_network_route(): can't find a route to the ABR");
      return;
    }

  cost = abr_or->cost + GET_METRIC (lsa->metric);

  rn = route_node_lookup (rt, (struct prefix *) p);

  if (rn == NULL)
    {
      if (ospf_top->abr_type != OSPF_ABR_SHORTCUT)
        return; /* Standard ABR can update only already installed
                   backbone paths                                       */

      zlog_info ("Z: ospf_update_network_route(): "
                 "Allowing Shortcut ABR to add new route");

      new_or = ospf_route_new ();
      new_or->type = OSPF_DESTINATION_NETWORK;
      new_or->id = lsa->header.id;
      new_or->mask = lsa->mask;
      new_or->u.std.options = lsa->header.options;
      new_or->u.std.origin = (struct lsa_header *) lsa;
      new_or->cost = cost;
      new_or->u.std.area = area;
      new_or->path_type = OSPF_PATH_INTER_AREA;
      ospf_route_add (rt, p, new_or, abr_or);

      return;
    }
  else
    {
      route_unlock_node (rn);
      if (rn->info == NULL)
        return;
    }

  or = rn->info;

  if (or->path_type != OSPF_PATH_INTRA_AREA &&
      or->path_type != OSPF_PATH_INTER_AREA)
    {
      zlog_info ("Z: ospf_update_network_route(): ERR: path type is wrong");
      return;
    }

  if (ospf_top->abr_type == OSPF_ABR_SHORTCUT)
    {
      if (or->path_type == OSPF_PATH_INTRA_AREA &&
	  !OSPF_IS_AREA_BACKBONE (or->u.std.area))
	{
	  zlog_info ("Z: ospf_update_network_route(): Shortcut: "
		     "this intra-area path is not backbone");
	  return;
	}
    }
  else   /* Not Shortcut ABR */
    {
      if (!OSPF_IS_AREA_BACKBONE (or->u.std.area))
	{
	  zlog_info ("Z: ospf_update_network_route(): "
		     "route is not BB-associated");
	  return; /* We can update only BB routes */
	}
    }

  if (or->cost < cost)
    {
      zlog_info ("Z: ospf_update_network_route(): new route is worse");
      return;
    }

  if (or->cost == cost)
    {
      zlog_info ("Z: ospf_update_network_route(): "
                 "new route is same distance, adding nexthops");
      ospf_route_copy_nexthops (or, abr_or->path);
    }

  if (or->cost > cost)
    {
      zlog_info ("Z: ospf_update_network_route(): "
                 "new route is better, overriding nexthops");
      ospf_route_subst_nexthops (or, abr_or->path);
      or->cost = cost;

      if ((ospf_top->abr_type == OSPF_ABR_SHORTCUT) &&
	  !OSPF_IS_AREA_BACKBONE (or->u.std.area))
	{
	  or->path_type = OSPF_PATH_INTER_AREA;
	  or->u.std.area = area;

          /* Note that we can do this only in Shortcut ABR mode,
             because standard ABR must leave the route type and area
             unchanged
          */
        }
    }
}

void
ospf_update_router_route (struct route_table *rtrs, 
                          struct summary_lsa *lsa,
                          struct prefix_ipv4 *p,
                          struct ospf_area *area)
{
  struct ospf_route *or, *abr_or, *new_or;
  struct prefix_ipv4 abr;
  u_int32_t cost;

  abr.family = AF_INET;
  abr.prefix = lsa->header.adv_router;
  abr.prefixlen = IPV4_MAX_BITLEN;
  apply_mask_ipv4 (&abr);

  abr_or = ospf_find_abr_route (rtrs, &abr, area);

  if (abr_or == NULL)
    {
      zlog_info ("Z: ospf_update_router_route(): can't find a route to the ABR");
      return;
    }

  cost = abr_or->cost + GET_METRIC (lsa->metric);

  /* First try to find a backbone path,
     because standard ABR can update only BB-associated paths */

  if ((ospf_top->backbone == NULL) &&
      (ospf_top->abr_type != OSPF_ABR_SHORTCUT))

     /* no BB area, not Shortcut ABR, exiting */
     return;
 
  or = ospf_find_asbr_route_through_area (rtrs, p, ospf_top->backbone);

  if (or == NULL)
    {
      if (ospf_top->abr_type != OSPF_ABR_SHORTCUT)

         /* route to ASBR through the BB not found
            the router is not Shortcut ABR, exiting */

          return;
      else
	/* We're a Shortcut ABR*/
	{
	  /* Let it either add a new router or update the route
	     through the same (non-BB) area. */

	  new_or = ospf_route_new ();
	  new_or->type = OSPF_DESTINATION_ROUTER;
	  new_or->id = lsa->header.id;
	  new_or->mask = lsa->mask;
	  new_or->u.std.options = lsa->header.options;
	  new_or->u.std.origin = (struct lsa_header *)lsa;
	  new_or->cost = cost;
	  new_or->u.std.area = area;
	  new_or->path_type = OSPF_PATH_INTER_AREA;
	  new_or->u.std.flags = ROUTER_LSA_EXTERNAL;
	  ospf_ia_router_route (rtrs, p, new_or, abr_or);

          return;
        }
    }

  /* At this point the "or" is always bb-associated */

  if (!(or->u.std.flags & ROUTER_LSA_EXTERNAL))
    {
      zlog_info ("Z: ospf_upd_router_route(): the remote router is not an ASBR");
      return;
    }

  if (or->path_type != OSPF_PATH_INTRA_AREA &&
      or->path_type != OSPF_PATH_INTER_AREA)
    return;

  if (or->cost < cost)
    return;

  else if (or->cost == cost)
    ospf_route_copy_nexthops (or, abr_or->path);

  else if (or->cost > cost)
    {
      ospf_route_subst_nexthops (or, abr_or->path);
      or->cost = cost;

      /* Even if the ABR runs in Shortcut mode, we can't change
         the path type and area, because the "or" is always bb-associated
         at this point and even Shortcut ABR can't change these attributes */
    }
}

int
process_transit_summary_lsa (struct ospf_lsa *l, void *v, int i)
{
  struct summary_lsa *sl;
  struct prefix_ipv4 p;
  u_int32_t metric;
  struct ia_args *args;

  if (l == NULL)
    return 0;

  args = (struct ia_args *) v;
  sl = (struct summary_lsa *) l->data;

  zlog_info ("Z: process_transit_summaries(): LS ID: %s",
             inet_ntoa (l->data->id));

  metric = GET_METRIC (sl->metric);
   
  if (metric == OSPF_LS_INFINITY)
    {
      zlog_info ("Z: process_transit_summaries(): metric is infinity, skip");
      return 0;
    }

  if (LS_AGE (l) == OSPF_LSA_MAX_AGE)
    {
      zlog_info ("Z: process_transit_summaries(): This LSA is too old");
      return 0;
    }

  if (ospf_lsa_is_self_originated (l))
    { 
      zlog_info ("Z: process_transit_summaries(): This LSA is mine, skip");
      return 0;
    }

  p.family = AF_INET;
  p.prefix = sl->header.id;
   
  if (sl->header.type == OSPF_SUMMARY_LSA)
    p.prefixlen = ip_masklen (sl->mask);
  else
    p.prefixlen = IPV4_MAX_BITLEN;
      
  apply_mask_ipv4 (&p);

  if (sl->header.type == OSPF_SUMMARY_LSA)
    ospf_update_network_route (args->rt, args->rtrs, sl, &p, args->area);
  else
    ospf_update_router_route (args->rtrs, sl, &p, args->area);
 
  return 0;
}

void
ospf_examine_transit_summaries (struct ospf_area *area,
                                /* struct ospf_lsdb *lsdb, */
				struct route_table *lsdb_rt,
                                struct route_table *rt,
                                struct route_table *rtrs)
{
  struct ia_args args = {rt, rtrs, area};

  /* ospf_lsdb_iterator (lsdb, &args, 0, process_transit_summary_lsa); */
  foreach_lsa (lsdb_rt, &args, 0, process_transit_summary_lsa);
}

void
ospf_ia_routing (struct route_table *rt,
                 struct route_table *rtrs)
{
  struct ospf_area * area;

  zlog_info ("Z: ospf_ia_routing():start");

  if (OSPF_IS_ABR)
    {
      listnode node; 
      struct ospf_area *area;

      switch (ospf_top->abr_type)
        {
        case OSPF_ABR_STAND:
          zlog_info ("Z: ospf_ia_routing():Standard ABR");

          if ((area = ospf_top->backbone))
            {
              listnode node;

              zlog_info ("Z: ospf_ia_routing():backbone area found");
              zlog_info ("Z: ospf_ia_routing():examining summaries");
              OSPF_EXAMINE_SUMMARIES_ALL (area, rt, rtrs);

              LIST_ITERATOR (ospf_top->areas, node)
                if ((area = getdata (node)) != NULL)
                  if (area != ospf_top->backbone)
		    if (ospf_area_is_transit (area))
		      OSPF_EXAMINE_TRANSIT_SUMMARIES_ALL (area, rt, rtrs);
            }
          else
            zlog_info ("Z: ospf_ia_routing():backbone area NOT found");
          break;
        case OSPF_ABR_IBM:
        case OSPF_ABR_CISCO:
          zlog_info ("Z: ospf_ia_routing():Alternative Cisco/IBM ABR");

          area = ospf_top->backbone; /* Find the BB */

          /* If we have an active BB connection */
          if (area && ospf_act_bb_connection ())
            {
              zlog_info ("Z: ospf_ia_routing(): backbone area found");
              zlog_info ("Z: ospf_ia_routing(): examining BB summaries");

              OSPF_EXAMINE_SUMMARIES_ALL (area, rt, rtrs);

              LIST_ITERATOR (ospf_top->areas, node)
                if ((area = getdata (node)) != NULL)
                  if (area != ospf_top->backbone)
		    if (ospf_area_is_transit (area))
		      OSPF_EXAMINE_TRANSIT_SUMMARIES_ALL (area, rt, rtrs);
            }
          else
            { /* No active BB connection--consider all areas */
              zlog_info ("Z: ospf_ia_routing(): "
                         "Active BB connection not found");

              LIST_ITERATOR (ospf_top->areas, node)
                if ((area = getdata (node)) != NULL)
                  OSPF_EXAMINE_SUMMARIES_ALL (area, rt, rtrs);
            }
          break;
        case OSPF_ABR_SHORTCUT:
          zlog_info ("Z: ospf_ia_routing():Alternative Shortcut");

          area = ospf_top->backbone; /* Find the BB */

          /* If we have an active BB connection */
          if (area && ospf_act_bb_connection ())
            {
              zlog_info ("Z: ospf_ia_routing(): backbone area found");
              zlog_info ("Z: ospf_ia_routing(): examining BB summaries");
              OSPF_EXAMINE_SUMMARIES_ALL (area, rt, rtrs);
            }

          LIST_ITERATOR (ospf_top->areas, node)
            if ((area = getdata (node)) != NULL)
              if (area != ospf_top->backbone)
		if (ospf_area_is_transit (area) ||
		    ((area->shortcut_configured != OSPF_SHORTCUT_DISABLE) &&
		     ((ospf_top->backbone == NULL) ||
                      ((area->shortcut_configured == OSPF_SHORTCUT_ENABLE) &&
		       area->shortcut_capability))))
		  OSPF_EXAMINE_TRANSIT_SUMMARIES_ALL (area, rt, rtrs);
          break;
        default:
          break;
        }
    }
  else 
    {
      listnode node;

      zlog_info ("Z: ospf_ia_routing():not ABR, considering all areas");

      LIST_ITERATOR (ospf_top->areas, node)
        if ((area = getdata (node)) != NULL)
          OSPF_EXAMINE_SUMMARIES_ALL (area, rt, rtrs);
    }
}
