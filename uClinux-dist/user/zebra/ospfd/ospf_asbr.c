/*
 * OSPF AS Boundary Router functions.
 * Copyright (C) 1999, 2000 Kunihiro Ishiguro, Toshiaki Takada
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
#include "ospfd/ospf_asbr.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_lsdb.h"
#include "ospfd/ospf_neighbor.h"
#include "ospfd/ospf_spf.h"
#include "ospfd/ospf_flood.h"
#include "ospfd/ospf_route.h"
#include "ospfd/ospf_zebra.h"
#include "ospfd/ospf_dump.h"

extern unsigned long term_debug_ospf_lsa;


/* Remove external route. */
void
ospf_external_route_remove (struct prefix_ipv4 *p)
{
  struct route_node *rn;
  struct ospf_route *or;
  listnode node;

  rn = route_node_lookup (ospf_top->external_route, (struct prefix *) p);
  if (rn)
    if ((or = rn->info))
      {
	zlog_info ("Route[%s/%d]: external path deleted",
		   inet_ntoa (p->prefix), p->prefixlen);

	/* Remove route from zebra. */
        if (or->type == OSPF_DESTINATION_NETWORK)
	  {
	    for (node = listhead (or->path); node; nextnode (node))
	      {
		struct ospf_path *path = getdata (node);
		if (path->nexthop.s_addr != INADDR_ANY)
		  ospf_zebra_delete ((struct prefix_ipv4 *) &rn->p,
				     &path->nexthop);
	      }
	  }

	ospf_route_free (or);
	rn->info = NULL;

	route_unlock_node (rn);
	route_unlock_node (rn);
	return;
      }

  zlog_info ("Route[%s/%d]: no such external path",
	     inet_ntoa (p->prefix), p->prefixlen);
}

/* Lookup external route. */
struct ospf_route *
ospf_external_route_lookup (struct prefix_ipv4 *p)
{
  struct route_node *rn;

  rn = route_node_lookup (ospf_top->external_route, (struct prefix *) p);
  if (rn)
    {
      route_unlock_node (rn);
      if (rn->info)
	return rn->info;
    }

  zlog_warn ("Route[%s/%d]: lookup, no such prefix",
	     inet_ntoa (p->prefix), p->prefixlen);

  return NULL;
}


/* Create an External info for AS-external-LSA. */
struct external_info *
ospf_external_info_add (u_char type, struct prefix_ipv4 p,
			unsigned int ifindex, struct in_addr nexthop)
{
  struct external_info *new;
  struct route_node *rn;

  /* Initialize route table. */
  if (EXTERNAL_INFO (type) == NULL)
    EXTERNAL_INFO (type) = route_table_init ();

  rn = route_node_get (EXTERNAL_INFO (type), (struct prefix *) &p);
  /* If old info exists, -- discard new one or overwrite with new one? */
  if (rn)
    if (rn->info)
      {
	route_unlock_node (rn);
	zlog_warn ("Redistribute[%s]: %s/%d already exists, discard.",
		   LOOKUP (ospf_redistributed_proto, type),
		   inet_ntoa (p.prefix), p.prefixlen);
	/* XFREE (MTYPE_OSPF_TMP, rn->info); */
	return NULL;
      }

  new = (struct external_info *)
    XMALLOC (MTYPE_OSPF_EXTERNAL_INFO, sizeof (struct external_info));
  new->flags = EXTERNAL_INITIAL;
  new->p = p;
  new->ifindex = ifindex;
  new->nexthop = nexthop;
  new->tag = 0;

  rn->info = new;

  if (IS_DEBUG_OSPF (lsa, LSA_GENERATE))
    zlog_info ("Redistribute[%s]: %s/%d external info created.",
	       LOOKUP (ospf_redistributed_proto, type),
	       inet_ntoa (p.prefix), p.prefixlen);
  return new;
}

void
ospf_external_info_delete (u_char type, struct prefix_ipv4 p)
{
  struct route_node *rn;

  rn = route_node_lookup (EXTERNAL_INFO (type), (struct prefix *) &p);
  if (rn == NULL)
    return;

  XFREE (MTYPE_OSPF_EXTERNAL_INFO, rn->info);
  rn->info = NULL;
  route_unlock_node (rn);
  route_unlock_node (rn);
}

struct external_info *
ospf_external_info_lookup (u_char type, struct prefix_ipv4 *p)
{
  struct route_node *rn;
  rn = route_node_lookup (EXTERNAL_INFO (type), (struct prefix *) p);
  if (rn)
    {
      if (rn->info)
	{
	  route_unlock_node (rn);
	  return rn->info;
	}
      else
	route_unlock_node (rn);
    }

  return NULL;
}


/* Update ASBR status. */
void
ospf_asbr_status_update (u_char status)
{
  zlog_info ("ASBR[Status:%d]: Update", status);

  /* ASBR on. */
  if (status)
    {
      /* Already ASBR. */
      if (OSPF_IS_ASBR)
	{
	  zlog_info ("ASBR[Status:%d]: Already ASBR", status);
	  return;
	}
      SET_FLAG (ospf_top->flags, OSPF_FLAG_ASBR);
    }
  else
    {
      /* Already non ASBR. */
      if (! OSPF_IS_ASBR)
	{
	  zlog_info ("ASBR[Status:%d]: Already noo ASBR", status);
	  return;
	}
      UNSET_FLAG (ospf_top->flags, OSPF_FLAG_ASBR);
    }

  /* Transition from/to status ASBR, schedule timer. */
  ospf_spf_calculate_schedule ();
  OSPF_LSA_UPDATE_TIMER_ON (ospf_top->t_rlsa_update,
			    ospf_router_lsa_update_timer);
}

void
ospf_redistribute_withdraw (u_char type)
{
  struct route_node *rn;
  struct external_info *ei;

  /* Delete external info for specified type. */
  if (EXTERNAL_INFO (type))
    for (rn = route_top (EXTERNAL_INFO (type)); rn; rn = route_next (rn))
      if ((ei = rn->info))
	if (ei->flags == EXTERNAL_ORIGINATED)
	  {
	    ospf_external_lsa_flush (type, &ei->p, ei->ifindex, ei->nexthop);
	    ospf_external_info_delete (type, ei->p);
	  }
}

#if 0
int
unapprove_lsa (struct ospf_lsa *lsa, void *v, int i)
{
  if (ospf_lsa_is_self_originated (lsa))
    UNSET_FLAG (lsa->flags, OSPF_LSA_APPROVED);

  return 0;
}

void
ospf_asbr_unapprove_lsas ()
{
  foreach_lsa (EXTERNAL_LSDB (ospf_top), NULL, 0, unapprove_lsa);
  /* ospf_lsdb_iterator (ospf_top->external_lsa, NULL, 0, unapprove_lsa); */
}

/* Check all AS external route. */
void
ospf_asbr_check_lsas ()
{
  struct route_node *rn;
  struct ospf_route *er;
  struct ospf_lsa *lsa = NULL;
  struct as_external_lsa *old_lsa;
  struct in_addr fwd_addr;

  RT_ITERATOR (ospf_top->external_self, rn)
    if ((er = rn->info) != NULL)
      {
	if (! ospf_asbr_should_announce ((struct prefix_ipv4 *) &rn->p, er))
	  {
	    if (er->u.ext.origin)
	      er->u.ext.origin = NULL; 
	    /* It remains in the LSDB and will be flushed*/
	    continue;
	  }

	/* We didn't announce it, but now we want to */
	if (er->u.ext.origin == NULL)
	  {
	    /* XXX: Temporarily comment out.
	    lsa = ospf_external_lsa ((struct prefix_ipv4 *) &rn->p,
				     er->metric_type, er->metric,
				     er->tag, er->nexthop, er->lsa);
	    lsa = ospf_external_lsa_install (lsa);
	    */
	    ospf_flood_through_as (NULL, lsa);
	    er->u.ext.origin = lsa;
	    SET_FLAG (er->u.ext.origin->flags, OSPF_LSA_APPROVED);
	  }
	else
	  {
	    /* er hold old lsa. */
	    old_lsa = (struct as_external_lsa *) er->u.ext.origin->data;

	    /*
	      ospf_forward_address_get (er->nexthop, &fwd_addr); */

	    /* Check the fwd_addr, as it may change since the last time
	       the LSA was originated. */
	    if (old_lsa->e[0].fwd_addr.s_addr != fwd_addr.s_addr)
	      {
		/* XXX: Temprarily comment out.
		lsa = ospf_external_lsa ((struct prefix_ipv4 *) &rn->p,
					 er->metric_type, er->metric,
					 er->tag, er->nexthop, er->lsa);

		zlog_info ("Z: ospf_asbr_check_lsas(): "
			   "fwd_addr changed for LSA ID: %s"
			   "originating the new one", inet_ntoa (lsa->data->id));
		if (lsa->refresh_list)
		  ospf_refresher_unregister_lsa (lsa);

		lsa = ospf_external_lsa_install (lsa);
		ospf_flood_through_as (NULL, lsa);
		*/
		er->u.ext.origin = lsa;
	      }
	    else /* LSA hasn't changed */
	      { 
		if (ospf_zlog)
		  zlog_info ("Z: ospf_asbr_check_lsas(): "
			     "fwd_addr is ok for LSA ID: %s",
			     inet_ntoa (er->u.ext.origin->data->id));
	      }
	    SET_FLAG (er->u.ext.origin->flags, OSPF_LSA_APPROVED);
	  }
      }
}
#endif

#if 0
int
flush_unapproved (struct ospf_lsa *lsa, void * v, int i)
{
  if (ospf_lsa_is_self_originated (lsa))
    if (! CHECK_FLAG (lsa->flags, OSPF_LSA_APPROVED))
      {
	zlog_info ("Z: ospf_asbr_flush_unapproved(): Flushing LSA, ID: %s",
		   inet_ntoa (lsa->data->id));
	ospf_lsa_flush_as (lsa);
      }

  return 0;
}

void
ospf_asbr_flush_unapproved_lsas ()
{
  foreach_lsa (EXTERNAL_LSDB (ospf_top), NULL, 0, flush_unapproved);
  /*
  ospf_lsdb_iterator (ospf_top->external_lsa, NULL, 0, flush_unapproved);
  */
}
#endif

/* This function performs checking of self-originated LSAs
   unapproved LSAs are flushed from the domain */

#if 0
void 
ospf_asbr_check ()
{
  /* ospf_asbr_unapprove_lsas (); */
  /* ospf_asbr_check_lsas (); */
  /* ospf_asbr_flush_unapproved_lsas (); */
}

int 
ospf_asbr_check_timer (struct thread *thread)
{
  ospf_top->t_asbr_check = 0;
  ospf_asbr_check ();

  return 0;
}

void
ospf_schedule_asbr_check ()
{
  if (! ospf_top->t_asbr_check)
    ospf_top->t_asbr_check =
      thread_add_timer (master, ospf_asbr_check_timer,
			0, OSPF_ASBR_CHECK_DELAY);
}
#endif
