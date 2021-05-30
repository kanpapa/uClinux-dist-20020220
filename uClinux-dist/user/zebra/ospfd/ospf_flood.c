/*
 * OSPF Flooding -- RFC2328 Section 13.
 * Copyright (C) 1999, 2000 Toshiaki Takada
 *
 * This file is part of GNU Zebra.
 * 
 * GNU Zebra is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2, or (at your
 * option) any later version.
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

#include "linklist.h"
#include "prefix.h"
#include "if.h"
#include "table.h"
#include "thread.h"
#include "memory.h"
#include "log.h"
#include "zclient.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_ism.h"
#include "ospfd/ospf_asbr.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_lsdb.h"
#include "ospfd/ospf_neighbor.h"
#include "ospfd/ospf_nsm.h"
#include "ospfd/ospf_spf.h"
#include "ospfd/ospf_flood.h"
#include "ospfd/ospf_packet.h"
#include "ospfd/ospf_abr.h"

extern struct zebra *zclient;


/* Check LSA is related to external info. */
int
ospf_external_info_check (struct ospf_lsa *lsa)
{
  struct as_external_lsa *al;
  struct prefix_ipv4 p;
  struct route_node *rn;
  int type;

  al = (struct as_external_lsa *) lsa->data;

  p.family = AF_INET;
  p.prefix = lsa->data->id;
  p.prefixlen = ip_masklen (al->mask);

  for (type = 0; type < ZEBRA_ROUTE_MAX; type++)
    if (zclient->redist[type])
      if (EXTERNAL_INFO (type))
	{
	  rn = route_node_lookup (EXTERNAL_INFO (type), (struct prefix *) &p);
	  if (rn != NULL)
	    {
	      if (rn->info != NULL)
		{
		  route_unlock_node (rn);
		  return 1;
		}
	      else
		route_unlock_node (rn);
	    }
	}

  return 0;
}

void
ospf_process_self_originated_lsa (struct ospf_lsa *new, struct ospf_area *area)
{
  struct network_lsa *nlsa;
  listnode node;
  struct ospf_interface *oi;
  struct interface *ifp;

  zlog_info ("LSA[Type%d:%s]: Process self-originated LSA",
	     new->data->type, inet_ntoa (new->data->id));

  /* If we're here, we installed a self-originated LSA that we received
     from a neighbor, i.e. it's more recent.  We must see whether we want
     to originate it.
     If yes, we should use this LSA's sequence number and reoriginate
     a new instance.
     if not --- we must flush this LSA from the domain. */
  switch (new->data->type)
    {
    case OSPF_ROUTER_LSA:
      /* Originate a new instance and schedule flooding */
      /* It shouldn't be necessary, but anyway */
      area->router_lsa_self = new;

      ospf_schedule_router_lsa_originate (area);
      return;
    case OSPF_NETWORK_LSA:
      /* We must find the interface the LSA could belong to.
	 If the interface is no more a broadcast type or we are no more
	 the DR, we flush the LSA otherwise -- create the new instance and
	 schedule flooding. */
      nlsa = (struct network_lsa *) new->data;

      /* Look through all interfaces, not just area, since interface
	 could be moved from one area to another. */
      for (node = listhead (ospf_top->iflist); node; nextnode (node))
	/* These are sanity check. */
	if ((ifp = getdata (node)) != NULL)
          if ((oi = ifp->info) != NULL)
	    if (oi->address != NULL)
	      if (IPV4_ADDR_SAME (&oi->address->u.prefix4, &new->data->id))
		{
		  if (oi->area != area ||
		      oi->type != OSPF_IFTYPE_BROADCAST ||
		      !IPV4_ADDR_SAME (&oi->address->u.prefix4, &DR (oi)))
		    {
		      ospf_schedule_lsa_flush_area (area, new);
		      return;
		    }

		  oi->network_lsa_self = new;

		  /* Schedule network-LSA origination. */
		  ospf_schedule_network_lsa_originate (oi);
		  return;
		}
   case OSPF_SUMMARY_LSA:
   case OSPF_SUMMARY_LSA_ASBR:
     ospf_schedule_abr_task ();
     break;
   case OSPF_AS_EXTERNAL_LSA :
     if (ospf_external_info_check (new))
       ospf_external_lsa_refresh (new);
     else
       ospf_lsa_flush_as (new);
     /* ospf_schedule_asbr_check (); */
     break;
  }
}

/* OSPF LSA flooding -- RFC2328 Section 13.(5). */
int
ospf_flood (struct ospf_neighbor *nbr, struct ospf_lsa *current,
	    struct ospf_lsa *new)
{
  struct ospf_interface *oi;
  /* time_t ts; */
  struct timeval now;

  zlog_info ("LSA[:Flooding]: start");

  oi = nbr->oi;

  /* Get current time. */
  /* ts = time (NULL); */
  gettimeofday (&now, NULL);

  /* If there is already a database copy, and if the
     database copy was received via flooding and installed less
     than MinLSArrival seconds ago, discard the new LSA
     (without acknowledging it). */
  /*  if (current && (ts - current->tv_recv) < OSPF_MIN_LS_ARRIVAL) */
  if (current != NULL &&
      tv_cmp (tv_sub (now, current->tv_recv),
	      int2tv (OSPF_MIN_LS_ARRIVAL)) < 0)
    {
      zlog_info ("LSA[:Flooding]: LSA is received recently.");
      return -1;
    }

  /* Flood the new LSA out some subset of the router's interfaces.
     In some cases (e.g., the state of the receiving interface is
     DR and the LSA was received from a router other than the
     Backup DR) the LSA will be flooded back out the receiving
     interface. */
  ospf_flood_through (nbr, new);

  /* Remove the current database copy from all neighbors'
     Link state retransmission lists. */
  if (current)
    {
      if(current->data->type != OSPF_AS_EXTERNAL_LSA) 
	ospf_ls_retransmit_delete_nbr_all (nbr->oi->area, current);
      else
	ospf_ls_retransmit_delete_nbr_all (NULL, current);
    }

  /* Install the new LSA in the link state database
     (replacing the current database copy).  This may cause the
     routing table calculation to be scheduled.  In addition,
     timestamp the new LSA with the current time.  The flooding
     procedure cannot overwrite the newly installed LSA until
     MinLSArrival seconds have elapsed. */  
  if (!current || ospf_lsa_different (current, new))
    ospf_spf_calculate_schedule ();

  SET_FLAG (new->flags, OSPF_LSA_RECEIVED);
  ospf_lsa_is_self_originated (new); /* Let it set the flag */
  new = ospf_lsa_install (nbr, new);

  /* Acknowledge the receipt of the LSA by sending a Link State
     Acknowledgment packet back out the receiving interface. */
  /* ospf_ls_ack_send (nbr, new); */

  /* If this new LSA indicates that it was originated by the
     receiving router itself, the router must take special action,
     either updating the LSA or in some cases flushing it from
     the routing domain. */
  if (ospf_lsa_is_self_originated (new))
    ospf_process_self_originated_lsa (new, oi->area);

  return 0;
}

/* OSPF LSA flooding -- RFC2328 Section 13.3. */
void
ospf_flood_through_area (struct ospf_area * area,struct ospf_neighbor *inbr,
			 struct ospf_lsa *lsa)
{
  listnode node;

  for (node = listhead (area->iflist); node; nextnode (node))
    {
      struct interface *ifp;
      struct ospf_interface *oi;
      struct ospf_neighbor *onbr;
      struct route_node *rn;
      list update;
      int flag;

      ifp = getdata (node);
      if (ospf_zlog)
	zlog_info ("Z: ospf_flood_through_area(): considering int %s",
		   ifp->name);
      oi = ifp->info;

      if (!ospf_if_is_enable (ifp))
	continue;

      /* Remember if new LSA is flooded out back. */
      flag = 0;

      /* Each of the neighbors attached to this interface are examined,
	 to determine whether they must receive the new LSA.  The following
	 steps are executed for each neighbor: */
      for (rn = route_top (oi->nbrs); rn; rn = route_next (rn))
	{
	  struct ospf_lsa *ls_req;
 
	  if (rn->info == NULL)
	    continue;

	  onbr = rn->info;
	  if (ospf_zlog)
	    zlog_info ("Z: ospf_flood_through_area(): considering nbr %s",
		       inet_ntoa (onbr->router_id));

	  /* If the neighbor is in a lesser state than Exchange, it
	     does not participate in flooding, and the next neighbor
	     should be examined. */
	  if (onbr->status < NSM_Exchange)
	    continue;

	  /* If the adjacency is not yet full (neighbor state is
	     Exchange or Loading), examine the Link state request
	     list associated with this adjacency.  If there is an
	     instance of the new LSA on the list, it indicates that
	     the neighboring router has an instance of the LSA
	     already.  Compare the new LSA to the neighbor's copy: */
	  if (onbr->status < NSM_Full)
	    {
	      if (ospf_zlog)
		zlog_info ("Z: ospf_flood_through_area(): nbr adj is not Full");

	      ls_req = ospf_ls_request_lookup (onbr, lsa);
	      if (ls_req != NULL)
		{
		  int ret;

		  ret = ospf_lsa_more_recent (ls_req, lsa);
		  /* The new LSA is less recent. */
		  if (ret > 0)
		    continue;
		  /* The two copies are the same instance, then delete
		     the LSA from the Link state request list. */
		  else if (ret == 0)
		    {
		      ospf_ls_request_delete (onbr, ls_req);
                      ospf_check_nbr_loading (onbr);
		      continue;
		    }
		  /* The new LSA is more recent.  Delete the LSA
		     from the Link state request list. */
		  else
		    {
		      ospf_ls_request_delete (onbr, ls_req);
		      ospf_check_nbr_loading (onbr);
		    }
		}
	    }

	  /* If the new LSA was received from this neighbor,
	     examine the next neighbor. */
          if (inbr)
 	    if (IPV4_ADDR_SAME (&inbr->router_id, &onbr->router_id))
	      continue;

	  /* Add the new LSA to the Link state retransmission list
	     for the adjacency. The LSA will be retransmitted
	     at intervals until an acknowledgment is seen from
	     the neighbor. */
	  ospf_ls_retransmit_add (onbr, lsa);
	  flag = 1;
	}

      /* LSA is more recent than database copy, but was not flooded
         back out receiving interface. */
      if (flag == 0)
	if (inbr && (oi->status != ISM_Backup || NBR_IS_DR (inbr)))
	  list_add_node (oi->ls_ack, ospf_lsa_dup (lsa));

      /* If in the previous step, the LSA was NOT added to any of
	 the Link state retransmission lists, there is no need to
	 flood the LSA out the interface. */

      /* If the new LSA was received on this interface, and it was
	 received from either the Designated Router or the Backup
	 Designated Router, chances are that all the neighbors have
	 received the LSA already. */
      if (inbr && (inbr->oi == oi))
	{
	  if (NBR_IS_DR (inbr) || NBR_IS_BDR (inbr))
	    continue;
	}

      /* If the new LSA was received on this interface, and the
	 interface state is Backup, examine the next interface.  The
	 Designated Router will do the flooding on this interface.
	 However, if the Designated Router fails the router will
	 end up retransmitting the updates. */
/*      else if (IPV4_ADDR_SAME (&oi->address->u.prefix4, &BDR (oi))) */
	else if (inbr && (inbr->oi == oi) &&
		 IPV4_ADDR_SAME (&oi->address->u.prefix4, &BDR (oi)))
	continue;

      /* The LSA must be flooded out the interface. Send a Link State
	 Update packet (including the new LSA as contents) out the
	 interface.  The LSA's LS age must be incremented by InfTransDelay
	 (which	must be	> 0) when it is copied into the outgoing Link
	 State Update packet (until the LS age field reaches the maximum
	 value of MaxAge). */
      if (flag)
	{
	  if (ospf_zlog)
	    zlog_info ("Z: ospf_flood_through_area(): "
		       "sending upd to int %s", oi->ifp->name);
	  update = list_init ();
	  list_add_node (update, lsa);

	  ospf_ls_upd_send (oi->nbr_self, update,
			    OSPF_SEND_PACKET_INDIRECT);
	  list_delete_all (update);
	}
    }
}

void
ospf_flood_through_as (struct ospf_neighbor *inbr, struct ospf_lsa *lsa)
{
  struct ospf_area *area;
  listnode node;

  for (node = listhead (ospf_top->areas); node; nextnode (node))
    {
      area = getdata (node);

      if (area->external_routing == OSPF_AREA_DEFAULT)
	ospf_flood_through_area (area, inbr, lsa);
    }
}

void
ospf_flood_through (struct ospf_neighbor *inbr, struct ospf_lsa *lsa)
{
  switch (lsa->data->type)
    {
    case OSPF_ROUTER_LSA:
    case OSPF_NETWORK_LSA:
    case OSPF_SUMMARY_LSA:
    case OSPF_SUMMARY_LSA_ASBR:
      ospf_flood_through_area (inbr->oi->area, inbr, lsa);
      break;
    case OSPF_AS_EXTERNAL_LSA:
      ospf_flood_through_as (inbr, lsa);
      break;
    default:
      break;
    }
}


/* Management functions for neighbor's Link State Request list. */
void
ospf_ls_request_add (struct ospf_neighbor *nbr, struct ospf_lsa *lsa)
{
  new_lsdb_add (&nbr->ls_req, lsa);
}

unsigned long
ospf_ls_request_count (struct ospf_neighbor *nbr)
{
  return new_lsdb_count (&nbr->ls_req);
}

int
ospf_ls_request_isempty (struct ospf_neighbor *nbr)
{
  return new_lsdb_isempty (&nbr->ls_req);
}

/* Remove LSA from neighbor's ls-request list. */
void
ospf_ls_request_delete (struct ospf_neighbor *nbr, struct ospf_lsa *lsa)
{
  if (nbr->ls_req_last == lsa)
    nbr->ls_req_last = NULL;
  new_lsdb_delete (&nbr->ls_req, lsa);
  ospf_lsa_free (lsa);
}

/* Remove all LSA from neighbor's ls-requenst list. */
void
ospf_ls_request_delete_all (struct ospf_neighbor *nbr)
{
  nbr->ls_req_last = NULL;
  new_lsdb_delete_all (&nbr->ls_req);
}

/* Lookup LSA from neighbor's ls-request list. */
struct ospf_lsa *
ospf_ls_request_lookup (struct ospf_neighbor *nbr, struct ospf_lsa *lsa)
{
  return new_lsdb_lookup (&nbr->ls_req, lsa);
}

struct ospf_lsa *
ospf_ls_request_new (struct lsa_header *lsah)
{
  struct ospf_lsa *new;

  new = ospf_lsa_new ();
  new->data = ospf_lsa_data_new (OSPF_LSA_HEADER_SIZE);
  memcpy (new->data, lsah, OSPF_LSA_HEADER_SIZE);

  return new;
}

void
ospf_ls_request_free (struct ospf_lsa *lsa)
{
  assert (lsa);
  ospf_lsa_free (lsa);
}

/* Management functions for neighbor's ls-retransmit list. */
#if 1
unsigned long
ospf_ls_retransmit_count (struct ospf_neighbor *nbr)
{
  return new_lsdb_count (&nbr->ls_rxmt);
}

int
ospf_ls_retransmit_isempty (struct ospf_neighbor *nbr)
{
  return new_lsdb_isempty (&nbr->ls_rxmt);
}

/* Add LSA to be retransmitted to neighbor's ls-retransmit list. */
void
ospf_ls_retransmit_add (struct ospf_neighbor *nbr, struct ospf_lsa *lsa)
{
  new_lsdb_add (&nbr->ls_rxmt, lsa);
  lsa->ref++;
}

/* Remove LSA from neibghbor's ls-retransmit list. */
void
ospf_ls_retransmit_delete (struct ospf_neighbor *nbr, struct ospf_lsa *lsa)
{
  new_lsdb_delete (&nbr->ls_rxmt, lsa);
  if (lsa->ref)
    lsa->ref--;
}

/* Clear neighbor's ls-retransmit list. */
void
ospf_ls_retransmit_clear (struct ospf_neighbor *nbr)
{
  struct route_node *rn;
  struct ospf_lsa *lsa;
  struct new_lsdb *lsdb;
  int i;

  lsdb = &nbr->ls_rxmt;

  for (i = OSPF_MIN_LSA; i < OSPF_MAX_LSA; i++)
    {
      struct route_table *table = lsdb->type[i].db;

      for (rn = route_top (table); rn; rn = route_next (rn))
	if ((lsa = rn->info) != NULL)
	  {
	    if (lsa->ref)
	      lsa->ref--;
	    new_lsdb_delete (&nbr->ls_rxmt, lsa);
	  }
    }
}

/* Lookup LSA from neighbor's ls-retransmit list. */
struct ospf_lsa *
ospf_ls_retransmit_lookup (struct ospf_neighbor *nbr, struct ospf_lsa *lsa)
{
  return new_lsdb_lookup (&nbr->ls_rxmt, lsa);
}

/* Remove a neighbor's Link State Retransmit list. */
void
ospf_ls_retransmit_delete_all (struct ospf_neighbor *nbr)
{
  new_lsdb_delete_all (&nbr->ls_rxmt);
}

/* Remove All neighbor/interface's Link State Retransmit list in area. */
void
ospf_ls_retransmit_delete_nbr_all (struct ospf_area *area,
				   struct ospf_lsa *lsa)
{
  listnode node;
  list iflist = area ? area->iflist : ospf_top->iflist;
  
  for (node = listhead (iflist); node; nextnode (node))
    {
      struct interface *ifp = node->data;
      struct ospf_interface *oi = ifp->info;
      struct route_node *rn;
      struct ospf_neighbor *nbr;
      struct ospf_lsa *lsr;
      
      if (ospf_if_is_enable (ifp))
	for (rn = route_top (oi->nbrs); rn; rn = route_next (rn))
	  /* If LSA find in LS-retransmit list, then remove it. */
	  if ((nbr = rn->info) != NULL)
	    {
	      lsr = ospf_ls_retransmit_lookup (nbr, lsa);
	     
	      /* If LSA find in ls-retransmit list, remove it. */
	      if (lsr != NULL && lsr->data->ls_seqnum == lsa->data->ls_seqnum)
		ospf_ls_retransmit_delete (nbr, lsr);
	      /* ospf_ls_retransmit_clear (nbr); */
	    }
    }
}

/* Add LSA to the current database copy of all neighbors'
   Link state retransmission lists. */
void
ospf_ls_retransmit_add_nbr_all (struct ospf_interface *ospfi,
				struct ospf_lsa *lsa)
{
  listnode node;

  for (node = listhead (ospf_top->iflist); node; nextnode (node))
    {
      struct interface *ifp = node->data;
      struct ospf_interface *oi = ifp->info;
      struct route_node *rn;
      struct ospf_neighbor *nbr;
      struct ospf_lsa *old;

      if (ospf_if_is_enable (ifp))
	if (OSPF_AREA_SAME (&ospfi->area, &oi->area))
	  for (rn = route_top (oi->nbrs); rn; rn = route_next (rn))
	    if ((nbr = rn->info) != NULL)
	      if (nbr->status == NSM_Full)
		{
		  if ((old = ospf_ls_retransmit_lookup (nbr, lsa)))
		    ospf_ls_retransmit_delete (nbr, old);

		  ospf_ls_retransmit_add (nbr, lsa);
		}
    }
}

#else
void
debug_ospf_ls_retransmit (struct ospf_neighbor *nbr)
{
  int i = 0;
  listnode n;

  zlog_info ("L: --------start---------");
  zlog_info ("L: nbr->router_id=%s", inet_ntoa (nbr->router_id));
  zlog_info ("L: ls_retransmit=%d", listcount (nbr->ls_retransmit));

  for (n = listhead (nbr->ls_retransmit); n; nextnode (n))
    {
      struct ospf_lsa *lsa;
      lsa = getdata (n);

      zlog_info ("L: lsa num %d", ++i);
      zlog_info ("L: lsa->flags=%x", lsa->flags);
      zlog_info ("L: lsa->ts=%x", lsa->ts);
      zlog_info ("L: lsa->data=%x", lsa->data);
      zlog_info ("L: lsa->ref=%d", lsa->ref);
    }
  zlog_info ("L: --------end---------");
}

/* Add LSA to be retransmitted to neighbor's ls-retransmit list. */
void
ospf_ls_retransmit_add (struct ospf_neighbor *nbr, struct ospf_lsa *lsa)
{
  list_add_node (nbr->ls_retransmit, lsa);
  lsa->ref++;
}

/* Remove LSA from neibghbor's ls-retransmit list. */
void
ospf_ls_retransmit_delete (struct ospf_neighbor *nbr, struct ospf_lsa *lsa)
{
  list_delete_by_val (nbr->ls_retransmit, lsa);
  if (lsa->ref)
    lsa->ref--;
}

/* Clear neighbor's ls-retransmit list. */
void
ospf_ls_retransmit_clear (struct ospf_neighbor *nbr)
{
  listnode node;
  listnode next;
  struct ospf_lsa *lsa;

  for (node = listhead (nbr->ls_retransmit); node; node = next)
    {
      lsa = getdata (node);
      next = node->next;

      if (lsa->ref)
	lsa->ref--;
      list_delete_by_val (nbr->ls_retransmit, lsa);
    }
}

/* Lookup LSA from neighbor's ls-retransmit list. */
struct ospf_lsa *
ospf_ls_retransmit_lookup (struct ospf_neighbor *nbr, struct lsa_header *lsah)
{
  listnode node;
  struct ospf_lsa *lsr;		/* LSA to be retransmitted. */

  for (node = listhead (nbr->ls_retransmit); node; nextnode (node))
    {
      lsr = getdata (node);

      /* Simple than comparing each fields. */
      if (memcmp (&lsr->data->type, &lsah->type, 15) == 0)
	return lsr;
    }

  return NULL;
}

/* Remove the current database copy from all neighbors'
   Link state retransmission lists. */
void
ospf_ls_retransmit_delete_nbr_all (struct ospf_lsa *lsa)
{
  listnode node;
  struct interface *ifp;
  struct ospf_interface *oi;
  struct ospf_neighbor *nbr;
  struct ospf_lsa *lsr;
  struct route_node *rn;

  for (node = listhead (ospf_top->iflist); node; nextnode (node))
    {
      ifp = getdata (node);
      oi = ifp->info;

      if (ospf_if_is_enable (ifp))
	for (rn = route_top (oi->nbrs); rn; rn = route_next (rn))
	  if ((nbr = rn->info) != NULL)
	    {
	      lsr = ospf_ls_retransmit_lookup (nbr, lsa->data);

	      /* If LSA find in ls-retransmit list, remove it. */
	      if (lsr != NULL)
		ospf_ls_retransmit_delete (nbr, lsr);
	    }
    }
}  

/* Add LSA to the current database copy of all neighbors'
   Link state retransmission lists. */
void
ospf_ls_retransmit_add_nbr_all (struct ospf_interface *ospfi,
				struct ospf_lsa *lsa)
{
  listnode node;
  struct route_node *rn;
  struct interface *ifp;
  struct ospf_interface *oi;
  struct ospf_neighbor *nbr;
  struct ospf_lsa *lsr;

  for (node = listhead (ospf_top->iflist); node; nextnode (node))
    {
      ifp = getdata (node);
      oi = ifp->info;

      if (!ospf_if_is_enable (ifp))
	continue;

      if (!OSPF_AREA_SAME (&ospfi->area, &oi->area))
	continue;

      for (rn = route_top (oi->nbrs); rn; rn = route_next (rn))
	{
	  if ((nbr = rn->info) == NULL)
	    continue;

	  if (nbr->status != NSM_Full)
	    continue;

	  /* If old LSA in ls-retransmit list, first remove it. */
	  if ((lsr = ospf_ls_retransmit_lookup (nbr, lsa->data)))
	    ospf_ls_retransmit_delete (nbr, lsr);

	  /* Then add new LSA to the neighbor's ls-retransmit list. */
	  ospf_ls_retransmit_add (nbr, lsa);
	}
    }
}
#endif


/* Sets ls_age to MaxAge and floods throu the area. 
   When we implement ASE routing, there will be anothe function
   flushing an LSA from the whole domain. */
void
ospf_lsa_flush_area (struct ospf_lsa *lsa, struct ospf_area *area)
{
  lsa->data->ls_age = htons (OSPF_LSA_MAX_AGE);
  ospf_flood_through_area (area, NULL, lsa);
  ospf_lsa_maxage (lsa);
}

void
ospf_lsa_flush_as (struct ospf_lsa *lsa)
{
  lsa->data->ls_age = htons (OSPF_LSA_MAX_AGE);
  ospf_flood_through_as (NULL, lsa);
  ospf_lsa_maxage (lsa);
}

/* Flush LSA through AS -- used for AS-external-LSAs. */
void
ospf_flush_through_as (struct ospf_lsa *lsa)
{
  lsa->data->ls_age = htons (OSPF_LSA_MAX_AGE);
  ospf_flood_through_as (NULL, lsa);
  ospf_lsa_maxage (lsa);
}
