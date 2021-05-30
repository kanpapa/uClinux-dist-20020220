/*
 * OSPF version 2  Neighbor State Machine
 * From RFC2328 [OSPF Version 2]
 * Copyright (C) 1999, 2000 Toshiaki Takada
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
#include "if.h"
#include "table.h"
#include "stream.h"
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
#include "ospfd/ospf_network.h"
#include "ospfd/ospf_packet.h"
#include "ospfd/ospf_dump.h"
#include "ospfd/ospf_flood.h"
#include "ospfd/ospf_abr.h"

extern unsigned long term_debug_ospf_nsm;


/* OSPF NSM Timer functions. */
int
ospf_inactivity_timer (struct thread *thread)
{
  struct ospf_neighbor *nbr;

  nbr = THREAD_ARG (thread);
  nbr->t_inactivity = NULL;

  if (IS_DEBUG_OSPF (nsm, NSM_TIMERS))
    zlog (NULL, LOG_DEBUG, "NSM[%s:%s]: Timer (Inactivity timer expire)",
	  nbr->oi->ifp->name, inet_ntoa (nbr->router_id));

  OSPF_NSM_EVENT_SCHEDULE (nbr, NSM_InactivityTimer);

  return 0;
}

int
ospf_db_desc_timer (struct thread *thread)
{
  struct ospf_interface *oi;
  struct ospf_neighbor *nbr;

  nbr = THREAD_ARG (thread);
  nbr->t_db_desc = NULL;

  oi = nbr->oi;

  if (IS_DEBUG_OSPF (nsm, NSM_TIMERS))
    zlog (NULL, LOG_INFO, "NSM[%s:%s]: Timer (DD Retransmit timer expire)",
	  nbr->oi->ifp->name, inet_ntoa (nbr->src));

  /* Sending DD packet. If Last send DD packet remains, re-send it. */
  if (nbr->last_send)
    ospf_db_desc_resend (nbr);
  else
    ospf_db_desc_send (nbr);

  /* DD Retransmit timer set. */
  OSPF_NSM_TIMER_ON (nbr->t_db_desc, ospf_db_desc_timer, nbr->v_db_desc);

  return 0;
}

/* Hook function called after ospf NSM event is occured. */

void
nsm_timer_set (struct ospf_neighbor *nbr)
{
  switch (nbr->status)
    {
    case NSM_Down:
      OSPF_NSM_TIMER_OFF (nbr->t_db_desc);
      break;
    case NSM_Attempt:
      OSPF_NSM_TIMER_OFF (nbr->t_db_desc);
      break;
    case NSM_Init:
      OSPF_NSM_TIMER_OFF (nbr->t_db_desc);
      break;
    case NSM_TwoWay:
      OSPF_NSM_TIMER_OFF (nbr->t_db_desc);
      break;
    case NSM_ExStart:
      OSPF_NSM_TIMER_ON (nbr->t_db_desc, ospf_db_desc_timer, nbr->v_db_desc);
      break;
    case NSM_Exchange:
      OSPF_NSM_TIMER_OFF (nbr->t_db_desc);
      break;
    case NSM_Loading:
      OSPF_NSM_TIMER_OFF (nbr->t_db_desc);
      break;
    case NSM_Full:
      OSPF_NSM_TIMER_OFF (nbr->t_db_desc);
      break;
    default:
      OSPF_NSM_TIMER_OFF (nbr->t_db_desc);
      break;
    }
}


/* OSPF NSM functions. */
int
nsm_ignore (struct ospf_neighbor *nbr)
{
  if (IS_DEBUG_OSPF (nsm, NSM_EVENTS))
    zlog (NULL, LOG_INFO, "NSM[%s:%s]: nsm_ignore called",
	  nbr->oi->ifp->name, inet_ntoa (nbr->router_id));

  return 0;
}

int
nsm_hello_received (struct ospf_neighbor *nbr)
{
  /* Start or Restart Inactivity Timer. */
  OSPF_NSM_TIMER_OFF (nbr->t_inactivity);
  
  OSPF_NSM_TIMER_ON (nbr->t_inactivity, ospf_inactivity_timer,
		     nbr->v_inactivity);

  return 0;
}

int
nsm_start (struct ospf_neighbor *nbr)
{
  return 0;
}

int
nsm_twoway_received (struct ospf_neighbor *nbr)
{
  struct ospf_interface *oi;
  int next_state = NSM_TwoWay;

  oi = nbr->oi;

  /* These netowork types must be adjacency. */
  if (oi->type == OSPF_IFTYPE_POINTOPOINT ||
      oi->type == OSPF_IFTYPE_POINTOMULTIPOINT ||
      oi->type == OSPF_IFTYPE_VIRTUALLINK)
    next_state = NSM_ExStart;

  /* Router itself is the DRouter or the BDRouter. */
  if (IPV4_ADDR_SAME (&oi->address->u.prefix4, &DR (oi)) ||
      IPV4_ADDR_SAME (&oi->address->u.prefix4, &BDR (oi)))
    next_state = NSM_ExStart;

  /* Neighboring Router is the DRouter or the BDRouter. */
  if (IPV4_ADDR_SAME (&nbr->address.u.prefix4, &nbr->d_router) ||
      IPV4_ADDR_SAME (&nbr->address.u.prefix4, &nbr->bd_router))
    next_state = NSM_ExStart;

  if (next_state == NSM_ExStart)
    {
      /* Get initial sequence number from time (). */
      if (nbr->dd_seqnum == 0)
	nbr->dd_seqnum = time (NULL);
      else
	nbr->dd_seqnum++;

      /* Send Initial DD packet. */
      ospf_db_desc_send (nbr);
    }

  /* Schedule DR Election. */
  /*  OSPF_ISM_EVENT_SCHEDULE (oi, ISM_NeighborChange); */

  return next_state;
}

int
ospf_db_summary_count (struct ospf_neighbor *nbr)
{
  return new_lsdb_count (&nbr->db_sum);
}

int
ospf_db_summary_isempty (struct ospf_neighbor *nbr)
{
  return new_lsdb_isempty (&nbr->db_sum);
}

int
ospf_db_summary_add (struct ospf_lsa *lsa, void *v, int i)
{
  struct ospf_neighbor *nbr;

  if ((nbr = (struct ospf_neighbor *) v) == NULL)
    return 0;

  if (lsa == NULL)
    return 0;

  if (LS_AGE (lsa) == OSPF_LSA_MAX_AGE)
    {
      zlog_info ("LSA[Type%d:%s]: LSA is MaxAge, add retransmit list",
		 lsa->data->id, inet_ntoa (lsa->data->id));
      ospf_ls_retransmit_add (nbr, lsa);                      
    }
  else 
    new_lsdb_add (&nbr->db_sum, lsa);

  return 0;
}

void
ospf_db_summary_delete_all (struct ospf_neighbor *nbr)
{
  new_lsdb_delete_all (&nbr->db_sum);
}

void
ospf_db_summary_clear (struct ospf_neighbor *nbr)
{
  struct new_lsdb *lsdb;
  int i;

  lsdb = &nbr->db_sum;
  for (i = OSPF_MIN_LSA; i < OSPF_MAX_LSA; i++)
    {
      struct route_table *table = lsdb->type[i].db;
      struct route_node *rn;

      for (rn = route_top (table); rn; rn = route_next (rn))
	if (rn->info)
	  new_lsdb_delete (&nbr->db_sum, rn->info);
    }
}


void nsm_reset_nbr (struct ospf_neighbor *);

/* The area link state database consists of the router-LSAs,
   network-LSAs and summary-LSAs contained in the area structure,
   along with the AS-external- LSAs contained in the global structure.
   AS- external-LSAs are omitted from a virtual neighbor's Database
   summary list.  AS-external-LSAs are omitted from the Database
   summary list if the area has been configured as a stub. */
int
nsm_negotiation_done (struct ospf_neighbor *nbr)
{
  struct ospf_area *area;

  area = nbr->oi->area;

  foreach_lsa (ROUTER_LSDB (area), nbr, 0, ospf_db_summary_add);
  foreach_lsa (NETWORK_LSDB (area), nbr, 0, ospf_db_summary_add);
  foreach_lsa (SUMMARY_LSDB (area), nbr, 0, ospf_db_summary_add);
  foreach_lsa (SUMMARY_ASBR_LSDB (area), nbr, 0, ospf_db_summary_add);
#if 0
  ospf_lsdb_iterator (ROUTER_LSA (area), nbr, 0, ospf_db_summary_add);
  ospf_lsdb_iterator (NETWORK_LSA (area), nbr, 0, ospf_db_summary_add);
  ospf_lsdb_iterator (SUMMARY_LSA (area), nbr, 0, ospf_db_summary_add);
  ospf_lsdb_iterator (SUMMARY_LSA_ASBR (area), nbr, 0, ospf_db_summary_add);
#endif
  
  if (nbr->oi->type != OSPF_IFTYPE_VIRTUALLINK &&
      area->external_routing == OSPF_AREA_DEFAULT)
    foreach_lsa (EXTERNAL_LSDB (ospf_top), nbr, 0, ospf_db_summary_add);

  OSPF_NSM_TIMER_OFF (nbr->t_db_desc);

  return 0;
}

int
nsm_exchange_done (struct ospf_neighbor *nbr)
{
  struct ospf_interface *oi;

  oi = nbr->oi;

  if (ospf_ls_request_isempty (nbr))
    return NSM_Full;

  /* Cancel dd retransmit timer. */
  OSPF_NSM_TIMER_OFF (nbr->t_db_desc);

  /* Send Link State Request. */
  ospf_ls_req_send (nbr);

  return NSM_Loading;
}

int
nsm_bad_ls_req (struct ospf_neighbor *nbr)
{
  /* Reset flags. */
  nbr->dd_flags = OSPF_DD_FLAG_I|OSPF_DD_FLAG_M|OSPF_DD_FLAG_MS;

  /* Clear neighbor. */
  nsm_reset_nbr (nbr);

  /* Send initial DD packet. */
  ospf_db_desc_send (nbr);

  return 0;
}

int
nsm_adj_ok (struct ospf_neighbor *nbr)
{
  struct ospf_interface *oi;
  int next_state;
  int flag = 0;

  oi = nbr->oi;
  next_state = nbr->status;

  /* These netowork types must be adjacency. */
  if (oi->type == OSPF_IFTYPE_POINTOPOINT ||
      oi->type == OSPF_IFTYPE_POINTOMULTIPOINT ||
      oi->type == OSPF_IFTYPE_VIRTUALLINK)
    flag = 1;

  /* Router itself is the DRouter or the BDRouter. */
  if (IPV4_ADDR_SAME (&oi->address->u.prefix4, &DR (oi)) ||
      IPV4_ADDR_SAME (&oi->address->u.prefix4, &BDR (oi)))
    flag = 1;

  /* Neighboring Router is the DRouter or the BDRouter. */
  /*
  if (IPV4_ADDR_SAME (&nbr->address.u.prefix4, &nbr->d_router) ||
      IPV4_ADDR_SAME (&nbr->address.u.prefix4, &nbr->bd_router))
  */
  if (IPV4_ADDR_SAME (&nbr->address.u.prefix4, &DR (oi)) ||
      IPV4_ADDR_SAME (&nbr->address.u.prefix4, &BDR (oi)))
    flag = 1;

  if (nbr->status == NSM_TwoWay && flag == 1)
    {
      next_state = NSM_ExStart;

      /* Get initial sequence number from time (). */
      if (nbr->dd_seqnum == 0)
	nbr->dd_seqnum = time (NULL);
      else
	nbr->dd_seqnum++;

      /* Send initial DD packet. */
      ospf_db_desc_send (nbr);
    }
  else if (nbr->status >= NSM_ExStart && flag == 0)
    next_state = NSM_TwoWay;

  /* Schedule DR Election. */
  /*
  if (nbr->status != next_state)
    OSPF_ISM_EVENT_SCHEDULE (oi, ISM_NeighborChange);
  */

  return next_state;
}

int
nsm_seq_number_mismatch (struct ospf_neighbor *nbr)
{
  /* Reset flags. */
  nbr->dd_flags = OSPF_DD_FLAG_I|OSPF_DD_FLAG_M|OSPF_DD_FLAG_MS;

  /* Clear neighbor. */
  nsm_reset_nbr (nbr);

  /* Send initial DD packet. */
  ospf_db_desc_send (nbr);

  return 0;
}

int
nsm_oneway_received (struct ospf_neighbor *nbr)
{
  /* Reset flags. */
  nbr->dd_flags = OSPF_DD_FLAG_I|OSPF_DD_FLAG_M|OSPF_DD_FLAG_MS;
  /* Note we don't need to change the master-slave (MS) flag status.  */
  /* Changed. we should reset master-slave (MS) flag. */

  /* Clear neighbor. */
  nsm_reset_nbr (nbr);

  return 0;
}

void
nsm_reset_nbr (struct ospf_neighbor *nbr)
{
  /* Clear Database Summary list. */
  if (!ospf_db_summary_isempty (nbr))
    ospf_db_summary_clear (nbr);

  /* Clear Link State Request list. */
  if (!ospf_ls_request_isempty (nbr))
    ospf_ls_request_delete_all (nbr);

  /* Clear Link State Retransmission list. */
  if (!ospf_ls_retransmit_isempty (nbr))
    ospf_ls_retransmit_clear (nbr);

  /* Cancel thread. */
  OSPF_NSM_TIMER_OFF (nbr->t_inactivity);
  OSPF_NSM_TIMER_OFF (nbr->t_db_desc);
  OSPF_NSM_TIMER_OFF (nbr->t_ls_req);
  OSPF_NSM_TIMER_OFF (nbr->t_ls_upd);
}

int
nsm_kill_nbr (struct ospf_neighbor *nbr)
{
  /* Schedule network-LSA origination, if DR. */
  /*  if (nbr->oi->status == ISM_DR)
      ospf_schedule_network_lsa_originate (nbr->oi);*/

  nsm_change_status (nbr, NSM_Down);
  
  /* Reset neighbor. */
  nsm_reset_nbr (nbr);

  /* Delete neighbor from interface. */
  ospf_nbr_delete (nbr);

  return 0;
}

int
nsm_inactivity_timer (struct ospf_neighbor *nbr)
{
  /* Kill neighbor. */
  nsm_kill_nbr (nbr);

  return 0;
}

int
nsm_ll_down (struct ospf_neighbor *nbr)
{
  /* Reset neighbor. */
  /*nsm_reset_nbr (nbr);*/
  
  /* Kill neighbor. */
  nsm_kill_nbr (nbr);

  return 0;
}

/* Neighbor State Machine */
struct {
  int (*func) ();
  int next_state;
} NSM [OSPF_NSM_STATUS_MAX][OSPF_NSM_EVENT_MAX] =
{
  {
    /* DependUpon: dummy state. */
    { nsm_ignore,              NSM_DependUpon }, /* NoEvent           */
    { nsm_ignore,              NSM_DependUpon }, /* HelloReceived     */
    { nsm_ignore,              NSM_DependUpon }, /* Start             */
    { nsm_ignore,              NSM_DependUpon }, /* 2-WayReceived     */
    { nsm_ignore,              NSM_DependUpon }, /* NegotiationDone   */
    { nsm_ignore,              NSM_DependUpon }, /* ExchangeDone      */
    { nsm_ignore,              NSM_DependUpon }, /* BadLSReq          */
    { nsm_ignore,              NSM_DependUpon }, /* LoadingDone       */
    { nsm_ignore,              NSM_DependUpon }, /* AdjOK?            */
    { nsm_ignore,              NSM_DependUpon }, /* SeqNumberMismatch */
    { nsm_ignore,              NSM_DependUpon }, /* 1-WayReceived     */
    { nsm_ignore,              NSM_DependUpon }, /* KillNbr           */
    { nsm_ignore,              NSM_DependUpon }, /* InactivityTimer   */
    { nsm_ignore,              NSM_DependUpon }, /* LLDown            */
  },
  {
    /* Down: */
    { nsm_ignore,              NSM_DependUpon }, /* NoEvent           */
    { nsm_hello_received,      NSM_Init       }, /* HelloReceived     */
    { nsm_start,               NSM_Attempt    }, /* Start             */
    { nsm_ignore,              NSM_Down       }, /* 2-WayReceived     */
    { nsm_ignore,              NSM_Down       }, /* NegotiationDone   */
    { nsm_ignore,              NSM_Down       }, /* ExchangeDone      */
    { nsm_ignore,              NSM_Down       }, /* BadLSReq          */
    { nsm_ignore,              NSM_Down       }, /* LoadingDone       */
    { nsm_ignore,              NSM_Down       }, /* AdjOK?            */
    { nsm_ignore,              NSM_Down       }, /* SeqNumberMismatch */
    { nsm_ignore,              NSM_Down       }, /* 1-WayReceived     */
    { nsm_kill_nbr,            NSM_Down       }, /* KillNbr           */
    { nsm_inactivity_timer,    NSM_Down       }, /* InactivityTimer   */
    { nsm_ll_down,             NSM_Down       }, /* LLDown            */
  },
  {
    /* Attempt: */
    { nsm_ignore,              NSM_DependUpon }, /* NoEvent           */
    { nsm_hello_received,      NSM_Init       }, /* HelloReceived     */
    { nsm_ignore,              NSM_Attempt    }, /* Start             */
    { nsm_ignore,              NSM_Attempt    }, /* 2-WayReceived     */
    { nsm_ignore,              NSM_Attempt    }, /* NegotiationDone   */
    { nsm_ignore,              NSM_Attempt    }, /* ExchangeDone      */
    { nsm_ignore,              NSM_Attempt    }, /* BadLSReq          */
    { nsm_ignore,              NSM_Attempt    }, /* LoadingDone       */
    { nsm_ignore,              NSM_Attempt    }, /* AdjOK?            */
    { nsm_ignore,              NSM_Attempt    }, /* SeqNumberMismatch */
    { nsm_ignore,              NSM_Attempt    }, /* 1-WayReceived     */
    { nsm_kill_nbr,            NSM_Down       }, /* KillNbr           */
    { nsm_inactivity_timer,    NSM_Down       }, /* InactivityTimer   */
    { nsm_ll_down,             NSM_Down       }, /* LLDown            */
  },
  {
    /* Init: */
    { nsm_ignore,              NSM_DependUpon }, /* NoEvent           */
    { nsm_hello_received,      NSM_Init       }, /* HelloReceived     */
    { nsm_ignore,              NSM_Init       }, /* Start             */
    { nsm_twoway_received,     NSM_DependUpon }, /* 2-WayReceived     */
    { nsm_ignore,              NSM_Init       }, /* NegotiationDone   */
    { nsm_ignore,              NSM_Init       }, /* ExchangeDone      */
    { nsm_ignore,              NSM_Init       }, /* BadLSReq          */
    { nsm_ignore,              NSM_Init       }, /* LoadingDone       */
    { nsm_ignore,              NSM_Init       }, /* AdjOK?            */
    { nsm_ignore,              NSM_Init       }, /* SeqNumberMismatch */
    { nsm_ignore,              NSM_Init       }, /* 1-WayReceived     */
    { nsm_kill_nbr,            NSM_Down       }, /* KillNbr           */
    { nsm_inactivity_timer,    NSM_Down       }, /* InactivityTimer   */
    { nsm_ll_down,             NSM_Down       }, /* LLDown            */
  },
  {
    /* 2-Way: */
    { nsm_ignore,              NSM_DependUpon }, /* NoEvent           */
    { nsm_hello_received,      NSM_TwoWay     }, /* HelloReceived     */
    { nsm_ignore,              NSM_TwoWay     }, /* Start             */
    { nsm_ignore,              NSM_TwoWay     }, /* 2-WayReceived     */
    { nsm_ignore,              NSM_TwoWay     }, /* NegotiationDone   */
    { nsm_ignore,              NSM_TwoWay     }, /* ExchangeDone      */
    { nsm_ignore,              NSM_TwoWay     }, /* BadLSReq          */
    { nsm_ignore,              NSM_TwoWay     }, /* LoadingDone       */
    { nsm_adj_ok,              NSM_DependUpon }, /* AdjOK?            */
    { nsm_ignore,              NSM_TwoWay     }, /* SeqNumberMismatch */
    { nsm_oneway_received,     NSM_Init       }, /* 1-WayReceived     */
    { nsm_kill_nbr,            NSM_Down       }, /* KillNbr           */
    { nsm_inactivity_timer,    NSM_Down       }, /* InactivityTimer   */
    { nsm_ll_down,             NSM_Down       }, /* LLDown            */
  },
  {
    /* ExStart: */
    { nsm_ignore,              NSM_DependUpon }, /* NoEvent           */
    { nsm_hello_received,      NSM_ExStart    }, /* HelloReceived     */
    { nsm_ignore,              NSM_ExStart    }, /* Start             */
    { nsm_ignore,              NSM_ExStart    }, /* 2-WayReceived     */
    { nsm_negotiation_done,    NSM_Exchange   }, /* NegotiationDone   */
    { nsm_ignore,              NSM_ExStart    }, /* ExchangeDone      */
    { nsm_ignore,              NSM_ExStart    }, /* BadLSReq          */
    { nsm_ignore,              NSM_ExStart    }, /* LoadingDone       */
    { nsm_adj_ok,              NSM_DependUpon }, /* AdjOK?            */
    { nsm_ignore,              NSM_ExStart    }, /* SeqNumberMismatch */
    { nsm_oneway_received,     NSM_Init       }, /* 1-WayReceived     */
    { nsm_kill_nbr,            NSM_Down       }, /* KillNbr           */
    { nsm_inactivity_timer,    NSM_Down       }, /* InactivityTimer   */
    { nsm_ll_down,             NSM_Down       }, /* LLDown            */
  },
  {
    /* Exchange: */
    { nsm_ignore,              NSM_DependUpon }, /* NoEvent           */
    { nsm_hello_received,      NSM_Exchange   }, /* HelloReceived     */
    { nsm_ignore,              NSM_Exchange   }, /* Start             */
    { nsm_ignore,              NSM_Exchange   }, /* 2-WayReceived     */
    { nsm_ignore,              NSM_Exchange   }, /* NegotiationDone   */
    { nsm_exchange_done,       NSM_DependUpon }, /* ExchangeDone      */
    { nsm_bad_ls_req,          NSM_ExStart    }, /* BadLSReq          */
    { nsm_ignore,              NSM_Exchange   }, /* LoadingDone       */
    { nsm_adj_ok,              NSM_DependUpon }, /* AdjOK?            */
    { nsm_seq_number_mismatch, NSM_ExStart    }, /* SeqNumberMismatch */
    { nsm_oneway_received,     NSM_Init       }, /* 1-WayReceived     */
    { nsm_kill_nbr,            NSM_Down       }, /* KillNbr           */
    { nsm_inactivity_timer,    NSM_Down       }, /* InactivityTimer   */
    { nsm_ll_down,             NSM_Down       }, /* LLDown            */
  },
  {
    /* Loading: */
    { nsm_ignore,              NSM_DependUpon }, /* NoEvent           */
    { nsm_hello_received,      NSM_Loading    }, /* HelloReceived     */
    { nsm_ignore,              NSM_Loading    }, /* Start             */
    { nsm_ignore,              NSM_Loading    }, /* 2-WayReceived     */
    { nsm_ignore,              NSM_Loading    }, /* NegotiationDone   */
    { nsm_ignore,              NSM_Loading    }, /* ExchangeDone      */
    { nsm_bad_ls_req,          NSM_ExStart    }, /* BadLSReq          */
    { nsm_ignore,              NSM_Full       }, /* LoadingDone       */
    { nsm_adj_ok,              NSM_DependUpon }, /* AdjOK?            */
    { nsm_seq_number_mismatch, NSM_ExStart    }, /* SeqNumberMismatch */
    { nsm_oneway_received,     NSM_Init       }, /* 1-WayReceived     */
    { nsm_kill_nbr,            NSM_Down       }, /* KillNbr           */
    { nsm_inactivity_timer,    NSM_Down       }, /* InactivityTimer   */
    { nsm_ll_down,             NSM_Down       }, /* LLDown            */
  },
  { /* Full: */
    { nsm_ignore,              NSM_DependUpon }, /* NoEvent           */
    { nsm_hello_received,      NSM_Full       }, /* HelloReceived     */
    { nsm_ignore,              NSM_Full       }, /* Start             */
    { nsm_ignore,              NSM_Full       }, /* 2-WayReceived     */
    { nsm_ignore,              NSM_Full       }, /* NegotiationDone   */
    { nsm_ignore,              NSM_Full       }, /* ExchangeDone      */
    { nsm_bad_ls_req,          NSM_ExStart    }, /* BadLSReq          */
    { nsm_ignore,              NSM_Full       }, /* LoadingDone       */
    { nsm_adj_ok,              NSM_DependUpon }, /* AdjOK?            */
    { nsm_seq_number_mismatch, NSM_ExStart    }, /* SeqNumberMismatch */
    { nsm_oneway_received,     NSM_Init       }, /* 1-WayReceived     */
    { nsm_kill_nbr,            NSM_Down       }, /* KillNbr           */
    { nsm_inactivity_timer,    NSM_Down       }, /* InactivityTimer   */
    { nsm_ll_down,             NSM_Down       }, /* LLDown            */
  },
};

static char *ospf_nsm_event_str[] =
{
  "NoEvent",
  "HelloReceived",
  "Start",
  "2-WayReceived",
  "NegotiationDone",
  "ExchangeDone",
  "BadLSReq",
  "LoadingDone",
  "AdjOK?",
  "SeqNumberMismatch",
  "1-WayReceived",
  "KillNbr",
  "InactivityTimer",
  "LLDown",
};

void
nsm_change_status (struct ospf_neighbor *nbr, int status)
{
  int old_status;
  struct ospf_interface *oi;

  /* Logging change of status. */
  if (IS_DEBUG_OSPF (nsm, NSM_STATUS))
    zlog_info ("NSM[%s:%s]: Status change %s -> %s",
	       nbr->oi->ifp->name, inet_ntoa (nbr->router_id),
	       LOOKUP (ospf_nsm_status_msg, nbr->status),
	       LOOKUP (ospf_nsm_status_msg, status));

  /* Preserve old status. */
  old_status = nbr->status;

  /* Change to new status. */
  nbr->status = status;

  /* Statistics. */
  nbr->state_change++;

  oi = nbr->oi;
  /* One of the neighboring routers changes to/from the FULL state. */
  if ((old_status != NSM_Full && status == NSM_Full) ||
      (old_status == NSM_Full && status != NSM_Full))
    { 
      if (status == NSM_Full)
	{
	  oi->full_nbrs++;
	  oi->area->full_nbrs++;

          ospf_check_abr_status ();

	  if (oi->type == OSPF_IFTYPE_VIRTUALLINK)
            if (++oi->vl_data->vl_area->full_vls == 1)
	      ospf_schedule_abr_task ();
	}
      else
	{
	  oi->full_nbrs--;
	  oi->area->full_nbrs--;

          ospf_check_abr_status ();

	  if (oi->type == OSPF_IFTYPE_VIRTUALLINK)
	    if (oi->vl_data->vl_area->full_vls > 0)
	      if (--oi->vl_data->vl_area->full_vls == 0)
		ospf_schedule_abr_task ();
	}

      zlog_info ("Z: nsm_change_status(): "
		 "scheduling new router-LSA origination");

      ospf_schedule_router_lsa_originate (oi->area);

      if (oi->type == OSPF_IFTYPE_VIRTUALLINK)
	ospf_schedule_router_lsa_originate (oi->vl_data->vl_area);

      /* Originate network-LSA. */
      if (oi->status == ISM_DR)
	{
	  if (oi->network_lsa_self && oi->full_nbrs == 0)
	    {
	      ospf_lsa_flush_area (oi->network_lsa_self, oi->area);
	      oi->network_lsa_self = NULL;
	      OSPF_TIMER_OFF (oi->t_network_lsa_self);
	    }
	  else
	    ospf_schedule_network_lsa_originate (oi);
	}
    }
    
  /* Generete NeighborChange ISM event. */
  if ((old_status < NSM_TwoWay && status >= NSM_TwoWay) ||
      (old_status >= NSM_TwoWay && status < NSM_TwoWay))
    OSPF_ISM_EVENT_SCHEDULE (oi, ISM_NeighborChange);

  /* Preserve old status? */
}

/* Execute NSM event process. */
int
ospf_nsm_event (struct thread *thread)
{
  int event;
  int next_state;
  struct ospf_neighbor *nbr;
  struct in_addr router_id;
  int old_status;
  struct ospf_interface *oi;

  nbr = THREAD_ARG (thread);
  event = THREAD_VAL (thread);
  router_id = nbr->router_id;

  old_status = nbr->status ;
  oi = nbr->oi ;
  
  /* Call function. */
  next_state = (*(NSM [nbr->status][event].func))(nbr);

  /* When event is NSM_KillNbr or InactivityTimer, the neighbor is
     deleted. */
  if (event == NSM_KillNbr || event == NSM_InactivityTimer)
    {
      if (IS_DEBUG_OSPF (nsm, NSM_EVENTS))
	zlog_info ("NSM[%s:%s]: neighbor deleted",
		   oi->ifp->name, inet_ntoa (router_id));

      /* Timers are canceled in ospf_nbr_free, moreover we cannot call
         nsm_timer_set here because nbr is freed already!!!*/
      /*nsm_timer_set (nbr);*/

      return 0;
    }

  if (! next_state)
    next_state = NSM [nbr->status][event].next_state;

  if (IS_DEBUG_OSPF (nsm, NSM_EVENTS))
    zlog_info ("NSM[%s:%s]: %s (%s)", oi->ifp->name,
	       inet_ntoa (nbr->router_id),
	       LOOKUP (ospf_nsm_status_msg, nbr->status),
	       ospf_nsm_event_str [event]);
  
  /* If status is changed. */
  if (next_state != nbr->status)
    nsm_change_status (nbr, next_state);

  /* Make sure timer is set. */
  nsm_timer_set (nbr);

  return 0;
}

/* Check loading status. */
void
ospf_check_nbr_loading (struct ospf_neighbor *nbr)
{
  if (nbr->status == NSM_Loading)
    {
      if (ospf_ls_request_isempty (nbr))
	OSPF_NSM_EVENT_SCHEDULE (nbr, NSM_LoadingDone);
      else if (nbr->ls_req_last == NULL)
	ospf_ls_req_event (nbr);
    }
}

