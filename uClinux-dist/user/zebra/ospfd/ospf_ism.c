/*
 * OSPF version 2  Interface State Machine
 *   From RFC2328 [OSPF Version 2] 
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
#include "linklist.h"
#include "prefix.h"
#include "if.h"
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
#include "ospfd/ospf_dump.h"
#include "ospfd/ospf_packet.h"
#include "ospfd/ospf_flood.h"
#include "ospfd/ospf_abr.h"

extern unsigned long term_debug_ospf_ism;


/* elect DR and BDR. Refer to RFC2319 section 9.4 */
struct ospf_neighbor *
ospf_dr_election_sub (list routers)
{
  listnode node;
  struct ospf_neighbor *nbr, *max = NULL;

  /* Choose highest router priority.
     In case of tie, choose highest Router ID. */
  for (node = listhead (routers); node; nextnode (node))
    {
      nbr = getdata (node);

      if (max == NULL)
	max = nbr;
      else
	{
	  if (max->priority < nbr->priority)
	    max = nbr;
	  else if (max->priority == nbr->priority)
	    if (IPV4_ADDR_CMP (&max->router_id, &nbr->router_id) < 0)
	      max = nbr;
	}
    }

  return max;
}

struct ospf_neighbor *
ospf_elect_dr (struct ospf_interface *oi, list el_list)
{
  list dr_list;
  listnode node;
  struct ospf_neighbor *nbr, *dr = NULL, *bdr = NULL;

  dr_list = list_init ();

  /* Add neighbors to the list. */
  for (node = listhead (el_list); node; nextnode (node))
    {
      nbr = getdata (node);

      /* neighbor declared to be DR. */
      if (IPV4_ADDR_SAME (&nbr->address.u.prefix4, &nbr->d_router))
	list_add_node (dr_list, nbr);

      /* Preserve neighbor BDR. */
      if (IPV4_ADDR_SAME (&BDR (oi), &nbr->address.u.prefix4))
	bdr = nbr;
    }

  /* Elect Designated Router. */
  if (listcount (dr_list) > 0)
    dr = ospf_dr_election_sub (dr_list);
  else
    dr = bdr;

  /* Set DR to interface. */
  if (dr)
    DR (oi) = dr->address.u.prefix4;
  else 
    DR(oi).s_addr = 0;

  list_delete_all (dr_list);

  return dr;
}

struct ospf_neighbor *
ospf_elect_bdr (struct ospf_interface *oi, list el_list)
{
  list bdr_list, no_dr_list;
  listnode node;
  struct ospf_neighbor *nbr, *bdr = NULL;

  bdr_list = list_init ();
  no_dr_list = list_init ();

  /* Add neighbors to the list. */
  for (node = listhead (el_list); node; nextnode (node))
    {
      nbr = getdata (node);

      /* neighbor declared to be DR. */
      if (IPV4_ADDR_SAME (&nbr->address.u.prefix4, &nbr->d_router))
	continue;

      /* neighbor declared to be BDR. */
      if (IPV4_ADDR_SAME (&nbr->address.u.prefix4, &nbr->bd_router))
	list_add_node (bdr_list, nbr);

      list_add_node (no_dr_list, nbr);
    }

  /* Elect Backup Designated Router. */
  if (listcount (bdr_list) > 0)
    bdr = ospf_dr_election_sub (bdr_list);
  else
    bdr = ospf_dr_election_sub (no_dr_list);

  /* Set BDR to interface. */
  if (bdr)
    BDR (oi) = bdr->address.u.prefix4;
  else
    BDR (oi).s_addr = 0;

  list_delete_all (bdr_list);
  list_delete_all (no_dr_list);

  return bdr;
}

int
ospf_ism_status (struct ospf_interface *oi)
{
  if (IPV4_ADDR_SAME (&DR (oi), &oi->address->u.prefix4))
    return ISM_DR;
  else if (IPV4_ADDR_SAME (&BDR (oi), &oi->address->u.prefix4))
    return ISM_Backup;
  else
    return ISM_DROther;
}

void
ospf_dr_eligible_routers (struct route_table *nbrs, list el_list)
{
  struct route_node *rn;
  struct ospf_neighbor *nbr;

  for (rn = route_top (nbrs); rn; rn = route_next (rn))
    if ((nbr = rn->info) != NULL)
      /* Ignore 0.0.0.0 node*/
      if (nbr->router_id.s_addr != 0)
	/* Is neighbor eligible? */
	if (nbr->priority != 0)
	  /* Is neighbor upper 2-Way? */
	  if (nbr->status >= NSM_TwoWay)
	    list_add_node (el_list, nbr);
}

/* Generate AdjOK? NSM event. */
void
ospf_dr_change (struct route_table *nbrs)
{
  struct route_node *rn;
  struct ospf_neighbor *nbr;

  for (rn = route_top (nbrs); rn; rn = route_next (rn))
    if ((nbr = rn->info) != NULL)
      /* Ignore 0.0.0.0 node*/
      if (nbr->router_id.s_addr != 0)
	/* Is neighbor upper 2-Way? */
	if (nbr->status >= NSM_TwoWay)
	  /* Ignore myself. */
	  if (!IPV4_ADDR_SAME (&nbr->router_id, &ospf_top->router_id))
	    OSPF_NSM_EVENT_SCHEDULE (nbr, NSM_AdjOK);
}

int
ospf_dr_election (struct ospf_interface *oi)
{
  struct in_addr old_dr, old_bdr;
  int old_status, new_status;
  list el_list;
  struct ospf_neighbor *dr, *bdr;

  /* backup current values. */
  old_dr = DR (oi);
  old_bdr = BDR (oi);
  old_status = oi->status;

  el_list = list_init ();

  /* List eligible routers. */
  ospf_dr_eligible_routers (oi->nbrs, el_list);

  /* First election of DR and BDR. */
  bdr = ospf_elect_bdr (oi, el_list);
  dr = ospf_elect_dr (oi, el_list);

  new_status = ospf_ism_status (oi);

  zlog_info ("DR-Election[1st]: Backup %s", inet_ntoa (BDR (oi)));
  zlog_info ("DR-Election[1st]: DR     %s", inet_ntoa (DR (oi)));

  if (IPV4_ADDR_SAME (&DR (oi), &BDR (oi)))
    {
      list_delete_by_val (el_list, dr);

      ospf_elect_bdr (oi, el_list);
   /* ospf_elect_dr (oi, el_list); */

      new_status = ospf_ism_status (oi);

      zlog_info ("DR-Election[2nd]: Backup %s", inet_ntoa (BDR (oi)));
      zlog_info ("DR-Election[2nd]: DR     %s", inet_ntoa (DR (oi)));
    }

  list_delete_all (el_list);

  /* if DR or BDR changes, cause AdjOK? neighbor event. */
  if (!IPV4_ADDR_SAME (&old_dr, &DR (oi)) ||
      !IPV4_ADDR_SAME (&old_bdr, &BDR (oi)))
    ospf_dr_change (oi->nbrs);

  /* Multicast group change. */
  if ((old_status != ISM_DR && old_status != ISM_Backup) &&
      (new_status == ISM_DR || new_status == ISM_Backup))
    ospf_if_add_alldrouters (oi->ifp, oi->fd, oi->address);
  else if ((old_status == ISM_DR || old_status == ISM_Backup) &&
	   (new_status != ISM_DR && new_status != ISM_Backup))
    ospf_if_drop_alldrouters (oi->ifp, oi->fd, oi->address);

  return new_status;
}


int
ospf_hello_timer (struct thread *thread)
{
  struct ospf_interface *oi;

  oi = THREAD_ARG (thread);
  oi->t_hello = NULL;

  if (IS_DEBUG_OSPF (ism, ISM_TIMERS))
    zlog (NULL, LOG_DEBUG, "ISM[%s]: Timer (Hello timer expire)",
	  oi->ifp->name);

  /* Sending hello packet. */
  ospf_hello_send (oi);

  /* Hello timer set. */
  OSPF_ISM_TIMER_ON (oi->t_hello, ospf_hello_timer, oi->v_hello);

  return 0;
}

int
ospf_wait_timer (struct thread *thread)
{
  struct ospf_interface *oi;

  oi = THREAD_ARG (thread);
  oi->t_wait = NULL;

  if (IS_DEBUG_OSPF (ism, ISM_TIMERS))
    zlog (NULL, LOG_DEBUG, "ISM[%s]: Timer (Wait timer expire)",
	  oi->ifp->name);

  OSPF_ISM_EVENT_SCHEDULE (oi, ISM_WaitTimer);

  return 0;
}

/* Hook function called after ospf ISM event is occured. And vty's
   network command invoke this function after making interface
   structure. */
void
ism_timer_set (struct ospf_interface *oi)
{
  switch (oi->status)
    {
    case ISM_Down:
      /* First entry point of ospf interface state machine. In this state
	 interface parameters must be set to initial values, and timers are
	 reset also. */
      OSPF_ISM_TIMER_OFF (oi->t_hello);
      OSPF_ISM_TIMER_OFF (oi->t_wait);
      break;
    case ISM_Loopback:
      /* In this state, the interface may be looped back and will be
	 unavailable for regular data traffic. */
      OSPF_ISM_TIMER_OFF (oi->t_hello);
      OSPF_ISM_TIMER_OFF (oi->t_wait);
      break;
    case ISM_Waiting:
      /* The router is trying to determine the identity of DRouter and
	 BDRouter. The router begin to receive and send Hello Packets. */
      OSPF_ISM_TIMER_ON (oi->t_hello, ospf_hello_timer, oi->v_hello);
      OSPF_ISM_TIMER_ON (oi->t_wait, ospf_wait_timer, oi->v_wait);
      break;
    case ISM_PointToPoint:
      /* The interface connects to a physical Point-to-point network or
	 virtual link. The router attempts to form an adjacency with
	 neighboring router. Hello packets are also sent. */
      OSPF_ISM_TIMER_ON (oi->t_hello, ospf_hello_timer, oi->v_hello);
      OSPF_ISM_TIMER_OFF (oi->t_wait);
      break;
    case ISM_DROther:
      /* The network type of the interface is broadcast or NBMA network,
	 and the router itself is neither Designated Router nor
	 Backup Designated Router. */
      OSPF_ISM_TIMER_ON (oi->t_hello, ospf_hello_timer, oi->v_hello);
      OSPF_ISM_TIMER_OFF (oi->t_wait);
      break;
    case ISM_Backup:
      /* The network type of the interface is broadcast os NBMA network,
	 and the router is Backup Designated Router. */
      OSPF_ISM_TIMER_ON (oi->t_hello, ospf_hello_timer, oi->v_hello);
      OSPF_ISM_TIMER_OFF (oi->t_wait);
      break;
    case ISM_DR:
      /* The network type of the interface is broadcast or NBMA network,
	 and the router is Designated Router. */
      OSPF_ISM_TIMER_ON (oi->t_hello, ospf_hello_timer, oi->v_hello);
      OSPF_ISM_TIMER_OFF (oi->t_wait);
      break;
    }
}

/* This function is the first starting point of all OSPF instances.
 */
void
ospf_ism_start (struct ospf_interface *oi)
{
  switch (oi->status)
    {
      ;
    }
}

int
ism_stop (struct ospf_interface *oi)
{
  return 0;
}

int
ism_interface_up (struct ospf_interface *oi)
{
  int next_state = 0;

  /* if network type is point-to-point, Point-to-MultiPoint or virtual link,
     the state transitions to Point-to-Point. */
  if (oi->type == OSPF_IFTYPE_POINTOPOINT ||
      oi->type == OSPF_IFTYPE_POINTOMULTIPOINT ||
      oi->type == OSPF_IFTYPE_VIRTUALLINK)
    next_state = ISM_PointToPoint;
  /* Else if the router is not eligible to DR, the state transitions to
     DROther. */
  else if (PRIORITY (oi) == 0) /* router is eligible? */
    next_state = ISM_DROther;
  else
    /* Otherwise, the state transitions to Waiting. */
    next_state = ISM_Waiting;

  /*  ospf_ism_event (t); */
  return next_state;
}

int
ism_loop_ind (struct ospf_interface *oi)
{
  int ret = 0;

  /* call ism_interface_down. */
  /* ret = ism_interface_down (oi); */

  return ret;
}

/* Interface down event handler. */
int
ism_interface_down (struct ospf_interface *oi)
{
  struct route_node *rn;
  struct ospf_neighbor *nbr;

  /* send Neighbor event KillNbr to all associated neighbors. */
  for (rn = route_top (oi->nbrs); rn; rn = route_next (rn))
    if ((nbr = rn->info) != NULL)
      {
	/* It's bad idea comparing router_id for detecting this is
           self neighbor or not.  -- kunihiro  */
	/* if (IPV4_ADDR_SAME (&nbr->router_id, &ospf_top->router_id)) */
	/* This is myself. */
	if (nbr == oi->nbr_self)
	  {
	    nbr->d_router.s_addr = 0;
	    nbr->bd_router.s_addr = 0;
	    continue;
	  }

	OSPF_NSM_EVENT_EXECUTE (nbr, NSM_KillNbr);
      }

  /* Reset interface variables. */
  /* ospf_if_reset_variables (oi); */

  /* Cancel Threads. */
  OSPF_ISM_TIMER_OFF (oi->t_hello);
  OSPF_ISM_TIMER_OFF (oi->t_wait);
  OSPF_ISM_TIMER_OFF (oi->t_ls_ack);

  return 0;
}


int
ism_backup_seen (struct ospf_interface *oi)
{
  return ospf_dr_election (oi);
}

int
ism_wait_timer (struct ospf_interface *oi)
{
  return ospf_dr_election (oi);
}

int
ism_neighbor_change (struct ospf_interface *oi)
{
  return ospf_dr_election (oi);
}

int
ism_ignore (struct ospf_interface *oi)
{
  if (IS_DEBUG_OSPF (ism, ISM_EVENTS))
    zlog (NULL, LOG_INFO, "ISM[%s]: ism_ignore called", oi->ifp->name);

  return 0;
}

/* Interface State Machine */
struct {
  int (*func) ();
  int next_state;
} ISM [OSPF_ISM_STATUS_MAX][OSPF_ISM_EVENT_MAX] =
{
  {
    /* DependUpon: dummy state. */
    { ism_ignore,          ISM_DependUpon },    /* NoEvent        */
    { ism_ignore,          ISM_DependUpon },    /* InterfaceUp    */
    { ism_ignore,          ISM_DependUpon },    /* WaitTimer      */
    { ism_ignore,          ISM_DependUpon },    /* BackupSeen     */
    { ism_ignore,          ISM_DependUpon },    /* NeighborChange */
    { ism_ignore,          ISM_DependUpon },    /* LoopInd        */
    { ism_ignore,          ISM_DependUpon },    /* UnloopInd      */
    { ism_ignore,          ISM_DependUpon },    /* InterfaceDown  */
  },
  {
    /* Down:*/
    { ism_ignore,          ISM_DependUpon },    /* NoEvent        */
    { ism_interface_up,    ISM_DependUpon },    /* InterfaceUp    */
    { ism_ignore,          ISM_Down },          /* WaitTimer      */
    { ism_ignore,          ISM_Down },          /* BackupSeen     */
    { ism_ignore,          ISM_Down },          /* NeighborChange */
    { ism_loop_ind,        ISM_Loopback },      /* LoopInd        */
    { ism_ignore,          ISM_Down },          /* UnloopInd      */
    { ism_interface_down,  ISM_Down },          /* InterfaceDown  */
  },
  {
    /* Loopback: */
    { ism_ignore,          ISM_DependUpon },    /* NoEvent        */
    { ism_ignore,          ISM_Loopback },      /* InterfaceUp    */
    { ism_ignore,          ISM_Loopback },      /* WaitTimer      */
    { ism_ignore,          ISM_Loopback },      /* BackupSeen     */
    { ism_ignore,          ISM_Loopback },      /* NeighborChange */
    { ism_ignore,          ISM_Loopback },      /* LoopInd        */
    { ism_ignore,          ISM_Down },          /* UnloopInd      */
    { ism_interface_down,  ISM_Down },          /* InterfaceDown  */
  },
  {
    /* Waiting: */
    { ism_ignore,          ISM_DependUpon },    /* NoEvent        */
    { ism_ignore,          ISM_Waiting },       /* InterfaceUp    */
    { ism_wait_timer,	   ISM_DependUpon },    /* WaitTimer      */
    { ism_backup_seen,     ISM_DependUpon },    /* BackupSeen     */
    { ism_ignore,          ISM_Waiting },       /* NeighborChange */
    { ism_loop_ind,	   ISM_Loopback },      /* LoopInd        */
    { ism_ignore,          ISM_Waiting },       /* UnloopInd      */
    { ism_interface_down,  ISM_Down },          /* InterfaceDown  */
  },
  {
    /* Point-to-Point: */
    { ism_ignore,          ISM_DependUpon },    /* NoEvent        */
    { ism_ignore,          ISM_PointToPoint },  /* InterfaceUp    */
    { ism_ignore,          ISM_PointToPoint },  /* WaitTimer      */
    { ism_ignore,          ISM_PointToPoint },  /* BackupSeen     */
    { ism_ignore,          ISM_PointToPoint },  /* NeighborChange */
    { ism_loop_ind,	   ISM_Loopback },      /* LoopInd        */
    { ism_ignore,          ISM_PointToPoint },  /* UnloopInd      */
    { ism_interface_down,  ISM_Down },          /* InterfaceDown  */
  },
  {
    /* DROther: */
    { ism_ignore,          ISM_DependUpon },    /* NoEvent        */
    { ism_ignore,          ISM_DROther },       /* InterfaceUp    */
    { ism_ignore,          ISM_DROther },       /* WaitTimer      */
    { ism_ignore,          ISM_DROther },       /* BackupSeen     */
    { ism_neighbor_change, ISM_DependUpon },    /* NeighborChange */
    { ism_loop_ind,        ISM_Loopback },      /* LoopInd        */
    { ism_ignore,          ISM_DROther },       /* UnloopInd      */
    { ism_interface_down,  ISM_Down },          /* InterfaceDown  */
  },
  {
    /* Backup: */
    { ism_ignore,          ISM_DependUpon },    /* NoEvent        */
    { ism_ignore,          ISM_Backup },        /* InterfaceUp    */
    { ism_ignore,          ISM_Backup },        /* WaitTimer      */
    { ism_ignore,          ISM_Backup },        /* BackupSeen     */
    { ism_neighbor_change, ISM_DependUpon },    /* NeighborChange */
    { ism_loop_ind,        ISM_Loopback },      /* LoopInd        */
    { ism_ignore,          ISM_Backup },        /* UnloopInd      */
    { ism_interface_down,  ISM_Down },          /* InterfaceDown  */
  },
  {
    /* DR: */
    { ism_ignore,          ISM_DependUpon },    /* NoEvent        */
    { ism_ignore,          ISM_DR },            /* InterfaceUp    */
    { ism_ignore,          ISM_DR },            /* WaitTimer      */
    { ism_ignore,          ISM_DR },            /* BackupSeen     */
    { ism_neighbor_change, ISM_DependUpon },    /* NeighborChange */
    { ism_loop_ind,        ISM_Loopback },      /* LoopInd        */
    { ism_ignore,          ISM_DR },            /* UnloopInd      */
    { ism_interface_down,  ISM_Down },          /* InterfaceDown  */
  },
};  

static char *ospf_ism_event_str[] =
{
  "NoEvent",
  "InterfaceUp",
  "WaitTimer",
  "BackupSeen",
  "NeighborChange",
  "LoopInd",
  "UnLoopInd",
  "InterfaceDown",
};

void
ism_change_status (struct ospf_interface *oi, int status)
{
  int old_status;
  struct ospf_lsa *lsa;

  /* Logging change of status. */
  if (IS_DEBUG_OSPF (ism, ISM_STATUS))
    zlog (NULL, LOG_INFO, "ISM[%s]: Status change %s -> %s", oi->ifp->name,
	  LOOKUP (ospf_ism_status_msg, oi->status),
	  LOOKUP (ospf_ism_status_msg, status));

  old_status = oi->status;
  oi->status = status;

  if (old_status == ISM_Down || status == NSM_Down)
    ospf_check_abr_status();

  /* Originate router-LSA. */
  if (oi->area)
    {
      if (status == ISM_Down)
	{
	  if (oi->area->act_ints > 0)
	    oi->area->act_ints--;
	}
      else if (old_status == ISM_Down)
	oi->area->act_ints++;

      /* schedule router-LSA originate. */
      ospf_schedule_router_lsa_originate (oi->area);
    }

  /* Originate network-LSA. */
  if (old_status != ISM_DR && status == ISM_DR)
    ospf_schedule_network_lsa_originate (oi);
  else if (old_status == ISM_DR && status != ISM_DR)
    {
      /* Free self originated network LSA. */
      lsa = oi->network_lsa_self;
      if (lsa)
	{
/*	  new_lsdb_delete ((struct new_lsdb *) lsa->lsdb, lsa);
	  ospf_lsa_free (lsa); */
	  ospf_lsa_flush_area (lsa, oi->area);
	  OSPF_TIMER_OFF (oi->t_network_lsa_self);
	}
      oi->network_lsa_self = NULL;
    }

  /* Preserve old status? */

  /* Check area border status.  */
  ospf_check_abr_status ();
}

/* Execute ISM event process. */
int
ospf_ism_event (struct thread *thread)
{
  int event;
  int next_state;
  struct ospf_interface *oi;

  oi = THREAD_ARG (thread);
  event = THREAD_VAL (thread);

  /* Call function. */
  next_state = (*(ISM [oi->status][event].func))(oi);

  if (! next_state)
    next_state = ISM [oi->status][event].next_state;

  if (IS_DEBUG_OSPF (ism, ISM_EVENTS))
    zlog (NULL, LOG_INFO, "ISM[%s]: %s (%s)", oi->ifp->name,
	  LOOKUP (ospf_ism_status_msg, oi->status),
	  ospf_ism_event_str[event]);

  /* If status is changed. */
  if (next_state != oi->status)
    ism_change_status (oi, next_state);

  /* Make sure timer is set. */
  ism_timer_set (oi);

  return 0;
}

