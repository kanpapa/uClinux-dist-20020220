/*
 * OSPF ABR functions.
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
#include "linklist.h"
#include "prefix.h"
#include "if.h"
#include "table.h"
#include "vty.h"
#include "filter.h"
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
#include "ospfd/ospf_ia.h"
#include "ospfd/ospf_flood.h"
#include "ospfd/ospf_abr.h"
#include "ospfd/ospf_ase.h"
#include "ospfd/ospf_zebra.h"


struct ospf_area_range *
ospf_area_range_match (struct ospf_area *area, struct prefix_ipv4 *p)
{
  struct route_node *node;

  node = route_node_match (area->ranges, (struct prefix *) p);
  if (node)
    {
      route_unlock_node (node);
      return node->info;
    }
  return NULL;
}

struct ospf_area_range *
ospf_some_area_range_match (struct prefix_ipv4 *p)
{
  listnode node;
  struct ospf_area_range * range;

  for (node = listhead (ospf_top->areas); node; nextnode (node))
    if ((range = ospf_area_range_match (node->data, p)))
      return range;

  return NULL;
}

int
ospf_range_active (struct ospf_area_range *range)
{
  return range->specifics;
}

int
ospf_area_actively_attached (struct ospf_area *area)
{
  return area->act_ints;
}

int
ospf_act_bb_connection ()
{
  if (ospf_top->backbone == NULL)
    return 0;

  return ospf_top->backbone->full_nbrs;
}

/* Check area border router status. */
void
ospf_check_abr_status ()
{
  struct ospf_area *area;
  listnode node;
  int bb_configured = 0;
  int bb_act_attached = 0;
  int areas_configured = 0;
  int areas_act_attached = 0;

  u_char new_flags = ospf_top->flags;

  if (ospf_zlog)
    zlog_info ("Z: ospf_check_abr_status(): Start");

  for (node = listhead (ospf_top->areas); node; nextnode (node))
    {
      area = getdata (node);

      if (listcount (area->iflist)) 
	{
	  areas_configured++;
	  
	  if (OSPF_IS_AREA_BACKBONE (area))
 	    bb_configured = 1;
	}

      if (ospf_area_actively_attached (area))
	{
	  areas_act_attached++;
	  
	  if (OSPF_IS_AREA_BACKBONE (area))
            bb_act_attached = 1;
	}
    }

  if (ospf_zlog)
    {
      zlog_info ("Z: ospf_check_abr_status(): looked through areas");
      zlog_info ("Z: ospf_check_abr_status(): bb_configured: %d", bb_configured);
      zlog_info ("Z: ospf_check_abr_status(): bb_act_attached: %d",
		 bb_act_attached);
      zlog_info ("Z: ospf_check_abr_status(): areas_configured: %d",
		 areas_configured);
      zlog_info ("Z: ospf_check_abr_status(): areas_act_attached: %d",
		 areas_act_attached);
    }

  switch (ospf_top->abr_type)
    {
    case OSPF_ABR_SHORTCUT:
    case OSPF_ABR_STAND:
      if (areas_act_attached > 1)
	SET_FLAG (new_flags, OSPF_FLAG_ABR);
      else
	UNSET_FLAG (new_flags, OSPF_FLAG_ABR);
      break;

    case OSPF_ABR_IBM:
      if ((areas_act_attached > 1) && bb_configured)
	SET_FLAG (new_flags, OSPF_FLAG_ABR);
      else
	UNSET_FLAG (new_flags, OSPF_FLAG_ABR);
      break;

    case OSPF_ABR_CISCO:
      if ((areas_configured > 1) && bb_act_attached)
	SET_FLAG (new_flags, OSPF_FLAG_ABR);
      else
	UNSET_FLAG (new_flags, OSPF_FLAG_ABR);
      break;
    default:
      break;
    }

  if (new_flags != ospf_top->flags)
    {
      ospf_spf_calculate_schedule ();
      zlog_info ("Z: ospf_check_abr_status(): new router flags: %x",new_flags);

      ospf_top->flags = new_flags;
      OSPF_LSA_UPDATE_TIMER_ON (ospf_top->t_rlsa_update,
				ospf_router_lsa_update_timer);
    }
}

void
ospf_abr_update_aggregate (struct ospf_area_range *range,
			   struct ospf_route *or)
{
  zlog_info ("Z: ospf_abr_update_aggregate(): Start");

  range->specifics++;

  if (or->cost > range->cost)
    {
      zlog_info ("Z: ospf_abr_update_aggregate(): worse cost, update");
      range->cost = or->cost;
    }
}

void
ospf_abr_announce_network_to_area (struct prefix_ipv4 *p, u_int32_t cost,
				   struct ospf_area *area)
{
  struct ospf_lsa *lsa, *old = NULL;
  struct summary_lsa *slsa = NULL;

  zlog_info ("Z: ospf_abr_announce_network_to_area(): Start");

  old = OSPF_SUMMARY_LSA_SELF_FIND_BY_PREFIX (area, p);

  if (old)
    {
      zlog_info ("Z: ospf_abr_announce_network_to_area(): old summary found");

      slsa = (struct summary_lsa *) old->data;

      zlog_info ("Z: ospf_abr_announce_network_to_area(): "
		 "old metric: %d, new metric: %d",
		 GET_METRIC (slsa->metric), cost);
    }


  if (old && (GET_METRIC (slsa->metric) == cost))
    {
      zlog_info ("Z: ospf_abr_announce_network_to_area(): "
		 "old summary approved"); 
      SET_FLAG (old->flags, OSPF_LSA_APPROVED);
    }
  else
    {
      zlog_info("Z: ospf_abr_announce_network_to_area(): "
		"creating new summary");
      lsa = ospf_summary_lsa (p, cost, area, old);
      SET_FLAG (lsa->flags, OSPF_LSA_APPROVED);

      /* Z: check later: Just copy the new body ??? or better remove old and install new ??*/
       
      if (old)
	{
	  zlog_info ("Z: ospf_abr_announce_network_to_area(): "
		     "copying new summary to the old body");
	  memcpy (old->data, lsa->data, sizeof (struct summary_lsa));
          old->tv_recv = lsa->tv_recv;
          old->tv_orig = lsa->tv_orig;
	  old->flags = lsa->flags;
	  ospf_lsa_free (lsa);
          zlog_info ("Z: ospf_lsa_free() in ospf_abr_announce_network_to_area(): %x", lsa);
	  lsa = old;
	  if (lsa->refresh_list)
	    ospf_refresher_unregister_lsa (lsa);
	  ospf_refresher_register_lsa (area->top, lsa);
	}
      else
	{
	  zlog_info ("Z: ospf_abr_announce_network_to_area(): "
		     "installing new summary");
	  ospf_summary_lsa_install (area, lsa);
	}

      zlog_info ("Z: ospf_abr_announce_network_to_area(): "
		 "flooding new version of summary");

      ospf_flood_through_area (area, NULL, lsa);
    }

  zlog_info ("Z: ospf_abr_announce_network_to_area(): Stop");
}

int
ospf_abr_nexthops_belong_to_area (struct ospf_route *or,
				  struct ospf_area *area)
{
  listnode node;

  for (node = listhead (or->path); node; nextnode (node))
    {
      struct ospf_path *path = node->data;
      struct ospf_interface *oi = path->ifp->info;

      if (oi != NULL)
	if (oi->area == area)
	  return 1;
    }

  return 0;
}

int
ospf_abr_should_accept (struct prefix *p, struct ospf_area *area)
{
  if (IMPORT_NAME (area))
    {
      if (IMPORT_LIST (area) == NULL)
	IMPORT_LIST (area) = access_list_lookup (AF_INET, IMPORT_NAME (area));

      if (IMPORT_LIST (area))
        if (access_list_apply (IMPORT_LIST (area), p) == FILTER_DENY)
           return 0;
    }

 return 1;
}

void
ospf_abr_announce_network (struct route_node *n, struct ospf_route *or)
{
  listnode node;
  struct ospf_area_range *range;
  struct prefix_ipv4 *p;
  struct ospf_area *area;

  zlog_info ("Z: ospf_abr_announce_network(): Start");

  p = (struct prefix_ipv4 *) &n->p;

  for (node = listhead (ospf_top->areas); node; nextnode (node))
    {
      area = getdata (node);

      zlog_info ("Z: ospf_abr_announce_network(): looking at area %s",
		 inet_ntoa (area->area_id));

      if (or->u.std.area == area)
	continue;

      if (ospf_abr_nexthops_belong_to_area (or, area))
	continue;

      if (!ospf_abr_should_accept (&n->p, area))
	{
	  zlog_info ("Z: ospf_abr_announce_network(): "
		     "prefix %s/%d was denied by import-list",
		     inet_ntoa (p->prefix), p->prefixlen);
	  continue; 
	}

      if (area->external_routing != OSPF_AREA_DEFAULT && area->no_summary)
	{
	  zlog_info ("Z: ospf_abr_announce_network(): "
		     "area %s is stub and no_summary",
		     inet_ntoa (area->area_id));
          continue;
	}

      if (or->path_type == OSPF_PATH_INTER_AREA)
	{
	  zlog_info ("Z: ospf_abr_announce_network(): this is "
		     "inter-area route to %s/%d",
		     inet_ntoa (p->prefix), p->prefixlen);

          if (!OSPF_IS_AREA_BACKBONE (area))
	    ospf_abr_announce_network_to_area (p, or->cost, area);
	}

      if (or->path_type == OSPF_PATH_INTRA_AREA)
	{
	  zlog_info ("Z: ospf_abr_announce_network(): "
		     "this is intra-area route to %s/%d",
		     inet_ntoa (p->prefix), p->prefixlen);
	  if ((range = ospf_area_range_match (or->u.std.area, p)) &&
              !ospf_area_is_transit (area))
	    ospf_abr_update_aggregate (range, or);
	  else
	    ospf_abr_announce_network_to_area (p, or->cost, area);
	}
    }
}

int
ospf_abr_should_announce (struct prefix *p, struct ospf_route *or)
{
  struct ospf_area *area = or->u.std.area;

  if (EXPORT_NAME (area))
    {
      if (EXPORT_LIST (area) == NULL)
	EXPORT_LIST (area) = access_list_lookup (AF_INET, EXPORT_NAME (area));

      if (EXPORT_LIST (area))
        if (access_list_apply (EXPORT_LIST (area), p) == FILTER_DENY)
           return 0;
    }

  return 1;
}

void
ospf_abr_process_network_rt (struct route_table *rt)
{
  struct route_node *rn;
  struct ospf_route *or;

  zlog_info ("Z: ospf_abr_process_network_rt(): Start");

  RT_ITERATOR (rt, rn)
    {
      if ((or = rn->info) == NULL)
	continue;

      zlog_info ("Z: ospf_abr_process_network_rt(): this is a route to %s/%d",
		 inet_ntoa (rn->p.u.prefix4), rn->p.prefixlen);

      if (or->path_type >= OSPF_PATH_TYPE1_EXTERNAL)
	{
	  zlog_info ("Z: ospf_abr_process_network_rt(): "
		     "this is an External router, skipping");
	  continue;
	}

      if (or->cost >= OSPF_LS_INFINITY)
	{
	  zlog_info ("Z: ospf_abr_process_network_rt():"
		     " this route's cost is infinity, skipping");
	  continue;
	}

      if (or->type == OSPF_DESTINATION_DISCARD)
	{
	  zlog_info ("Z: ospf_abr_process_network_rt():"
		     " this is a discard entry, skipping");
	  continue;
	}

      if ((or->path_type == OSPF_PATH_INTRA_AREA) &&
          (! ospf_abr_should_announce(&rn->p, or)) )
	{
	  zlog_info("Z: ospf_abr_process_network_rt(): denied by export-list");
	  continue;
	}


      if ((or->path_type == OSPF_PATH_INTER_AREA) &&
          (or->u.std.area != ospf_top->backbone))
	{
	  zlog_info ("Z: ospf_abr_process_network_rt():"
		     " this is route is not backbone one, skipping");
	  continue;
	}


      if ((ospf_top->abr_type == OSPF_ABR_CISCO) ||
          (ospf_top->abr_type == OSPF_ABR_IBM))

          if (!ospf_act_bb_connection () &&
              or->path_type != OSPF_PATH_INTRA_AREA)
	     {
 	       zlog_info ("Z: ospf_abr_process_network_rt(): ALT ABR: "
			  "No BB connection, skip not intra-area routes");
	       continue;
	     }


      zlog_info ("Z: ospf_abr_process_network_rt(): announcing");
      ospf_abr_announce_network (rn, or);
    }

  zlog_info ("Z: ospf_abr_process_network_rt(): Stop");
}

void
ospf_abr_announce_rtr_to_area (struct prefix_ipv4 *p, u_int32_t cost,
			       struct ospf_area *area)
{
  struct ospf_lsa *lsa, *old = NULL;
  struct summary_lsa *slsa = NULL;

  zlog_info ("Z: ospf_abr_announce_rtr_to_area(): Start");

  old = OSPF_SUMMARY_ASBR_LSA_SELF_FIND_BY_PREFIX (area, p);
  /* old = ospf_find_self_summary_asbr_lsa_by_prefix (area, p); */

  if (old)
    {
      zlog_info ("Z: ospf_abr_announce_rtr_to_area(): old summary found");
      slsa = (struct summary_lsa *) old->data;

      zlog_info ("Z: ospf_abr_announce_network_to_area(): "
		 "old metric: %d, new metric: %d",
		 GET_METRIC (slsa->metric), cost);
    }

  if (old && (GET_METRIC (slsa->metric) == cost))
    {
      zlog_info ("Z: ospf_abr_announce_rtr_to_area(): old summary approved");
      SET_FLAG (old->flags, OSPF_LSA_APPROVED);
    }
  else
    {
      zlog_info ("Z: ospf_abr_announce_rtr_to_area(): creating new summary");
      lsa = ospf_summary_asbr_lsa (p, cost, area, old);

      SET_FLAG (lsa->flags, OSPF_LSA_APPROVED);

      zlog_info ("Z: ospf_abr_announce_rtr_to_area(): 2.2");

      /* Z: check later: Just copy the new body ??? or better remove old and install new ??*/
       
      if (old) 
	{ 
	  zlog_info ("Z: ospf_abr_announce_rtr_to_area(): "
		     "copying new summary to the old body");
	  memcpy (old->data, lsa->data, sizeof (struct summary_lsa));
          old->tv_recv = lsa->tv_recv;
          old->tv_orig = lsa->tv_orig;
	  ospf_lsa_free (lsa);
          zlog_info ("Z: ospf_lsa_free() in ospf_abr_announce_rtr_to_area(): %x", lsa);
	  lsa = old;
	  if (lsa->refresh_list)
	    ospf_refresher_unregister_lsa (lsa);
          ospf_refresher_register_lsa (area->top, lsa);
	}
      else
	{
	  zlog_info ("Z: ospf_abr_announce_rtr_to_area(): "
		     "installing new summary");
	  ospf_summary_asbr_lsa_install (area, lsa);
	}

      zlog_info ("Z: ospf_abr_announce_rtr_to_area(): "
		 "flooding new version of summary");

      ospf_flood_through_area (area, NULL, lsa);
    }

  zlog_info ("Z: ospf_abr_announce_rtr_to_area(): Stop");
}


void
ospf_abr_announce_rtr (struct prefix_ipv4 *p, struct ospf_route *or)
{
  listnode node;
  struct ospf_area *area;

  zlog_info ("Z: ospf_abr_announce_rtr(): Start");

  LIST_ITERATOR (ospf_top->areas, node)
    {
      area = getdata (node);

      zlog_info ("Z: ospf_abr_announce_rtr(): looking at area %s",
		 inet_ntoa (area->area_id));

      if (or->u.std.area == area)
	continue;

      if (ospf_abr_nexthops_belong_to_area (or, area))
	continue;

      if (area->external_routing != OSPF_AREA_DEFAULT)
	{
	  zlog_info ("Z: ospf_abr_announce_network(): "
		     "area %s doesn't support external routing",
		     inet_ntoa(area->area_id));
          continue;
	}

      if (or->path_type == OSPF_PATH_INTER_AREA)
	{
	  zlog_info ("Z: ospf_abr_announce_rtr(): "
		     "this is inter-area route to %s", inet_ntoa (p->prefix));

          if (!OSPF_IS_AREA_BACKBONE (area))
	    ospf_abr_announce_rtr_to_area (p, or->cost, area);
	}

      if (or->path_type == OSPF_PATH_INTRA_AREA)
	{
	  zlog_info ("Z: ospf_abr_announce_rtr(): "
		     "this is intra-area route to %s", inet_ntoa (p->prefix));
          ospf_abr_announce_rtr_to_area (p, or->cost, area);
	}
    }

  zlog_info ("Z: ospf_abr_announce_rtr(): Stop");
}

void
ospf_abr_process_router_rt (struct route_table *rt)
{
  struct route_node *rn;
  struct ospf_route *or;
  list list;

  zlog_info ("Z: ospf_abr_process_router_rt(): Start");

  RT_ITERATOR (rt, rn)
    {
      listnode node;
      char flag = 0;
      struct ospf_route *best = NULL;

      if (rn->info == NULL)
	continue;

      list = rn->info;

      zlog_info ("Z: ospf_abr_process_router_rt(): this is a route to %s",
		 inet_ntoa (rn->p.u.prefix4));

      LIST_ITERATOR (list, node)
	{
	  or = getdata (node);
	  if (or == NULL)
	    continue;

	  if (!CHECK_FLAG (or->u.std.flags, ROUTER_LSA_EXTERNAL))
	    {
	      zlog_info ("Z: ospf_abr_process_router_rt(): "
			 "This is not an ASBR, skipping");
	      continue;
	    }

        if (!flag)
	  {
	    best = ospf_find_asbr_route (rt, (struct prefix_ipv4 *) &rn->p);
	    flag = 1;
	  }

        if (best == NULL)
	  continue;

        if (or != best)
	  {
	    zlog_info ("Z: ospf_abr_process_router_rt(): "
		       "This route is not the best among possible, skipping");
	    continue;
	  }

        if (or->path_type == OSPF_PATH_INTER_AREA &&
            or->u.std.area != ospf_top->backbone)
	  {
	    zlog_info ("Z: ospf_abr_process_router_rt(): "
		       "This route is not a backbone one, skipping");
	    continue;
	  }

        if (or->cost >= OSPF_LS_INFINITY)
	  {
	    zlog_info ("Z: ospf_abr_process_router_rt(): "
		       "This route has LS_INFINITY metric, skipping");
	    continue;
	  }


        if (ospf_top->abr_type == OSPF_ABR_CISCO ||
            ospf_top->abr_type == OSPF_ABR_IBM)
	  if (!ospf_act_bb_connection () &&
	      or->path_type != OSPF_PATH_INTRA_AREA)
	    {
	      zlog_info("Z: ospf_abr_process_network_rt(): ALT ABR: "
			"No BB connection, skip not intra-area routes");
	      continue;
	    }

        ospf_abr_announce_rtr ((struct prefix_ipv4 *) &rn->p, or);

	} /* LIST_ITERATOR */

    } /* RT_ITERATOR */

  zlog_info ("Z: ospf_abr_process_router_rt(): Stop");
}

int
ospf_abr_unapprove_summaries_apply (struct ospf_lsa *lsa, void *p_arg,
				    int int_arg)
{
  if (ospf_lsa_is_self_originated (lsa))
    UNSET_FLAG (lsa->flags, OSPF_LSA_APPROVED);

  return 0;
}

void
ospf_abr_unapprove_summaries ()
{
  listnode node;
  struct ospf_area *area;

  zlog_info ("Z: ospf_abr_unapprove_summaries(): Start");

  for (node = listhead (ospf_top->areas); node; nextnode (node))
    {
      area = getdata (node);
      foreach_lsa (SUMMARY_LSDB (area), NULL, 0,
		   ospf_abr_unapprove_summaries_apply);
      foreach_lsa (SUMMARY_ASBR_LSDB (area), NULL, 0,
		   ospf_abr_unapprove_summaries_apply);
#if 0
      ospf_lsdb_iterator (SUMMARY_LSA (area), NULL, 0,
			  ospf_abr_unapprove_summaries_apply);
      
      ospf_lsdb_iterator (SUMMARY_LSA_ASBR (area), NULL, 0,
			  ospf_abr_unapprove_summaries_apply);
#endif
    }

  zlog_info ("Z: ospf_abr_unapprove_summaries(): Stop");
}

void
ospf_abr_prepare_aggregates ()
{
  listnode node;
  struct route_node *rn;
  struct ospf_area_range *range;

  zlog_info ("Z: ospf_abr_prepare_aggregates(): Start");

  for (node = listhead (ospf_top->areas); node; nextnode (node))
    {
      struct ospf_area *area = getdata (node);

      for (rn = route_top (area->ranges); rn; rn = route_next (rn))
	if ((range = rn->info) != NULL)
	  {
	    range->cost = 0;
	    range->specifics = 0;
	  }
    }

  zlog_info ("Z: ospf_abr_prepare_aggregates(): Stop");
}

void
ospf_abr_announce_aggregates ()
{
  listnode node, n;
  struct ospf_area *area, *ar;
  struct route_node *rn;
  struct ospf_area_range *range;
  struct prefix_ipv4 p;

  zlog_info ("Z: ospf_abr_announce_aggregates(): Start");

  for (node = listhead (ospf_top->areas); node; nextnode (node))
    {
      area = getdata (node);

      zlog_info ("Z: ospf_abr_announce_aggregates(): looking at area %s",
		 inet_ntoa (area->area_id));

      for (rn = route_top (area->ranges); rn; rn = route_next (rn))
	{
          if (rn->info == NULL)
	    continue;

	  range = rn->info;

          if (CHECK_FLAG (range->flags, OSPF_RANGE_SUPPRESS))
	    {
	      zlog_info ("Z: ospf_abr_announce_aggregates():"
			 " discarding suppress-ranges");
	      continue;
	    }

          p.family = AF_INET;
          p.prefix = range->node->p.u.prefix4;
          p.prefixlen = range->node->p.prefixlen;

          zlog_info ("Z: ospf_abr_announce_aggregates():"
		     " this is range: %s/%d",
		     inet_ntoa (p.prefix), p.prefixlen);

          if (CHECK_FLAG (range->flags, OSPF_RANGE_SUBST))
	    p = range->substitute;

          if (range->specifics)
	    {
	      zlog_info ("Z: ospf_abr_announce_aggregates(): active range");

	      for (n = listhead (ospf_top->areas); n; nextnode (n))
    		{
      		  ar = getdata (n);
                  if (ar == area)
		    continue;

                  /* We do not check nexthops here, because
                     intra-area routes can be associated with
		     one area only
		   */

		  /* backbone routes are not summarized
		     when announced into transit areas
                   */                  

                  if (ospf_area_is_transit (ar) &&
		      OSPF_IS_AREA_BACKBONE (area))
		    {
		      zlog_info ("Z: ospf_abr_announce_aggregates(): Skipping "
				 "announcement of BB aggregate into"
				 " a transit area");
		      continue; 
		    }
		  ospf_abr_announce_network_to_area (&p, range->cost, ar);
		}

	    } /* if (range->specifics)*/

	} /* all area ranges*/

    } /* all areas */

  zlog_info ("Z: ospf_abr_announce_aggregates(): Stop");
}

void
ospf_abr_announce_stub_defaults ()
{
  listnode node;
  struct ospf_area *area;
  struct prefix_ipv4 p;

  if (! OSPF_IS_ABR)
    return;

  zlog_info ("Z: ospf_abr_announce_stub_defaults(): Start");

  p.family = AF_INET;
  p.prefix.s_addr = OSPF_DEFAULT_DESTINATION;
  p.prefixlen = 0;

  for (node = listhead (ospf_top->areas); node; nextnode (node))
    {
      area = getdata (node);
      zlog_info ("Z: ospf_abr_announce_stub_defaults(): looking at area %s",
		 inet_ntoa (area->area_id));
      
      if (area->external_routing == OSPF_AREA_DEFAULT)
	continue;

      if (OSPF_IS_AREA_BACKBONE (area))
	continue; /* Sanity Check */

      zlog_info ("Z: ospf_abr_announce_stub_defaults(): "
		 "announcing 0.0.0.0/0 to this area");
      ospf_abr_announce_network_to_area (&p, area->default_cost, area);
    }

  zlog_info ("Z: ospf_abr_announce_stub_defaults(): Stop");
}

#if 0
void
ospf_abr_withdraw_summary (struct ospf_area *area, struct ospf_lsa *lsa)
{
  struct route_node *rn;
  struct prefix p;
  struct route_table *rt;

  get_lsa_prefix (lsa, &p);

  if (lsa->data->type == OSPF_SUMMARY_LSA)
    rt = area->summary_lsa_self;
  else if (lsa->data->type == OSPF_SUMMARY_LSA_ASBR)
    rt = area->summary_lsa_asbr_self;
  else
    {
      rt = NULL;
      zlog_info ("Z: Alarm: non-summary LSA in ABR function !");
      return;
    }

 rn = route_node_lookup (rt,&p);

 if (rn == NULL)
   return;
 if (rn->info == NULL)
   return;

 rn->info = NULL;
 route_unlock_node (rn);

 /* instead of all this stuff, we should better use LSDB...later */

 ospf_lsa_flush_area (lsa, area);
}
#endif /* 0 */

int
ospf_abr_remove_unapproved_summaries_apply (struct ospf_lsa *lsa, void *p_arg,
					    int int_arg)
{
  struct ospf_area *area;

  area = (struct ospf_area *) p_arg;

  if (ospf_lsa_is_self_originated (lsa) &&
      !CHECK_FLAG (lsa->flags, OSPF_LSA_APPROVED))
    {
      zlog_info ("Z: ospf_abr_remove_unapproved_summaries(): "
		 "removing unapproved summary, ID: %s",
		 inet_ntoa (lsa->data->id));
      ospf_lsa_flush_area (lsa, area);
    }
  return 0;
}

void
ospf_abr_remove_unapproved_summaries ()
{
  listnode node;
  struct ospf_area *area;

  zlog_info ("Z: ospf_abr_remove_unapproved_summaries(): Start");

  for (node = listhead (ospf_top->areas); node; nextnode (node))
    {
      area = getdata (node);

      zlog_info ("Z: ospf_abr_remove_unapproved_summaries(): "
		 "looking at area %s", inet_ntoa (area->area_id));

      foreach_lsa (SUMMARY_LSDB (area), area, 0,
		   ospf_abr_remove_unapproved_summaries_apply);
      foreach_lsa (SUMMARY_ASBR_LSDB (area), area, 0,
		   ospf_abr_remove_unapproved_summaries_apply);
#if 0
      ospf_lsdb_iterator (SUMMARY_LSA (area), area, 0,
			  ospf_abr_remove_unapproved_summaries_apply);
      
      ospf_lsdb_iterator (SUMMARY_LSA_ASBR (area), area, 0,
			  ospf_abr_remove_unapproved_summaries_apply);
#endif
    }
 
  zlog_info ("Z: ospf_abr_remove_unapproved_summaries(): Stop");
}

void
ospf_abr_manage_discard_routes ()
{
  listnode node;
  struct route_node *rn;
  struct ospf_area *area;
  struct ospf_area_range *range;

  for (node = listhead (ospf_top->areas); node; nextnode (node))
    if ((area = node->data) != NULL)
      for (rn = route_top (area->ranges); rn; rn = route_next (rn))
	if ((range = rn->info) != NULL)
	  if (!CHECK_FLAG (range->flags, OSPF_RANGE_SUPPRESS))
	    {
	      if (range->specifics)
		ospf_add_discard_route (ospf_top->new_table, area,
					(struct prefix_ipv4 *) &rn->p);
	      else
		ospf_delete_discard_route ((struct prefix_ipv4 *) &rn->p);
	    }
}

/* This is the function taking care about ABR stuff, i.e.
   summary-LSA origination and flooding. */
void
ospf_abr_task ()
{
  zlog_info ("Z: ospf_abr_task(): Start");

  if (ospf_top->new_table == NULL || ospf_top->new_rtrs == NULL)
    {
      zlog_info ("Z: ospf_abr_task(): Routing tables are not yet ready");
      return;
    }

  zlog_info ("Z: ospf_abr_task(): unapprove summaries");
  ospf_abr_unapprove_summaries ();

  zlog_info ("Z: ospf_abr_task(): prepare aggregates");
  ospf_abr_prepare_aggregates ();

  if (OSPF_IS_ABR)
    {
      zlog_info ("Z: ospf_abr_task(): process network RT");
      ospf_abr_process_network_rt (ospf_top->new_table);

      zlog_info ("Z: ospf_abr_task(): process router RT");
      ospf_abr_process_router_rt (ospf_top->new_rtrs);

      zlog_info ("Z: ospf_abr_task(): announce aggregates");
      ospf_abr_announce_aggregates ();

      zlog_info ("Z: ospf_abr_task(): announce stub defaults");
      ospf_abr_announce_stub_defaults ();
    }

  zlog_info ("Z: ospf_abr_task(): remove unapproved summaries");
  ospf_abr_remove_unapproved_summaries ();

  ospf_abr_manage_discard_routes ();

  zlog_info ("Z: ospf_abr_task(): Stop");
}


int
ospf_abr_task_timer (struct thread *t)
{
  ospf_top->t_abr_task = 0;

  zlog_info ("Z: Running ABR task on timer");

  ospf_check_abr_status ();

  ospf_abr_task ();

 return 0;
}

void
ospf_schedule_abr_task ()
{
  zlog_info ("Z: Scheduling ABR task");
  if (! ospf_top->t_abr_task)
    ospf_top->t_abr_task = thread_add_timer (master, ospf_abr_task_timer,
					     0, OSPF_ABR_TASK_DELAY);
}
