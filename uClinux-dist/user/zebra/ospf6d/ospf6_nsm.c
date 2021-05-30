/*
 * Copyright (C) 1999 Yasuhiro Ohara
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

#include "ospf6d.h"

int
nbs_change (state_t nbs_next, char *reason, struct neighbor *nbr)
{
  state_t nbs_previous;

  nbs_previous = nbr->state;
  nbr->state = nbs_next;

  if (nbs_previous == nbs_next)
    return 0;

  /* statistics */
  nbr->ospf6_stat_state_changed++;

  /* log */
  if (IS_OSPF6_DUMP_NEIGHBOR)
    {
      if (reason)
        zlog_info ("Neighbor status change %s: [%s]->[%s](%s)",
                   nbr->str,
                   nbs_name[nbs_previous], nbs_name[nbs_next],
                   reason);
      else
        zlog_info ("Neighbor status change %s: [%s]->[%s]",
                   nbr->str,
                   nbs_name[nbs_previous], nbs_name[nbs_next]);
    }

  if (nbs_previous == NBS_FULL || nbs_next == NBS_FULL)
    nbs_full_change (nbr->ospf6_interface);

#if 0
  /* check for LSAs that already reached MaxAge */
  /* for Interface scope LSA */
  ospf6_lsdb_maxage_remove_interface (nbr->ospf6_interface);

  /* for Area scope LSA */
  ospf6_lsdb_maxage_remove_area (nbr->ospf6_interface->area);

  /* for AS scope LSA */
  ospf6_lsdb_maxage_remove_as (nbr->ospf6_interface->area->ospf6);
#else
  ospf6_lsdb_check_maxage_lsa (ospf6);
#endif

  return 0;
}

int
nbs_full_change (struct ospf6_interface *ospf6_interface)
{
  struct ospf6_lsa *lsa;

  /* construct Router-LSA */
  lsa = ospf6_make_router_lsa (ospf6_interface->area);
  if (lsa)
    {
      ospf6_lsa_flood (lsa);
      ospf6_lsdb_install (lsa);
      ospf6_lsa_unlock (lsa);
    }

  if (ospf6_interface->state == IFS_DR)
    {
      /* construct Network-LSA */
      lsa = ospf6_make_network_lsa (ospf6_interface);
      if (lsa)
        {
          ospf6_lsa_flood (lsa);
          ospf6_lsdb_install (lsa);
          ospf6_lsa_unlock (lsa);
        }
      /* construct Intra-Area-Prefix-LSA */
      lsa = ospf6_make_intra_prefix_lsa (ospf6_interface);
      if (lsa)
        {
          ospf6_lsa_flood (lsa);
          ospf6_lsdb_install (lsa);
          ospf6_lsa_unlock (lsa);
        }
    }
  return 0;
}

/* RFC2328 section 10.4 */
int
need_adjacency (struct neighbor *nbr)
{

  if (nbr->ospf6_interface->state == IFS_PTOP)
    return 1;
  if (nbr->ospf6_interface->state == IFS_DR)
    return 1;
  if (nbr->ospf6_interface->state == IFS_BDR)
    return 1;
  if (nbr->rtr_id == nbr->ospf6_interface->dr)
    return 1;
  if (nbr->rtr_id == nbr->ospf6_interface->bdr)
    return 1;

  return 0;
}

int
hello_received (struct thread *thread)
{
  struct neighbor *nbr;

  nbr = (struct neighbor *)THREAD_ARG  (thread);
  assert (nbr);

  if (IS_OSPF6_DUMP_NEIGHBOR)
    zlog_info ("Neighbor Event %s: *HelloReceived*", nbr->str);

  if (nbr->inactivity_timer)
    thread_cancel (nbr->inactivity_timer);

  nbr->inactivity_timer = thread_add_timer (master, inactivity_timer, nbr,
                                            nbr->ospf6_interface->dead_interval);
  if (nbr->state <= NBS_DOWN)
    nbs_change (NBS_INIT, "HelloReceived", nbr);
  return 0;
}

int
twoway_received (struct thread *thread)
{
  struct neighbor *nbr;

  nbr = (struct neighbor *)THREAD_ARG  (thread);
  assert (nbr);

  if (nbr->state > NBS_INIT)
    return 0;

  if (IS_OSPF6_DUMP_NEIGHBOR)
    zlog_info ("Neighbor Event %s: *2Way-Received*", nbr->str);

  thread_add_event (master, neighbor_change, nbr->ospf6_interface, 0);

  if (!need_adjacency (nbr))
    {
      nbs_change (NBS_TWOWAY, "No Need Adjacency", nbr);
      return 0;
    }
  else
    nbs_change (NBS_EXSTART, "Need Adjacency", nbr);

  DD_MSBIT_SET (nbr->dd_bits);
  DD_MBIT_SET (nbr->dd_bits);
  DD_IBIT_SET (nbr->dd_bits);

  thread_add_event (master, ospf6_send_dbdesc, nbr, 0);

  return 0;
}

int
negotiation_done (struct thread *thread)
{
  struct neighbor *nbr;

  nbr = (struct neighbor *)THREAD_ARG  (thread);
  assert (nbr);

  if (nbr->state != NBS_EXSTART)
    return 0;

  if (IS_OSPF6_DUMP_NEIGHBOR)
    zlog_info ("Neighbor Event %s: *NegotiationDone*", nbr->str);

  nbs_change (NBS_EXCHANGE, "NegotiationDone", nbr);
  DD_IBIT_CLEAR (nbr->dd_bits);

  return 0;
}

int
exchange_done (struct thread *thread)
{
  struct neighbor *nbr;

  nbr = (struct neighbor *)THREAD_ARG  (thread);
  assert (nbr);

  if (nbr->state != NBS_EXCHANGE)
    return 0;

  if (nbr->thread_dbdesc_retrans)
    thread_cancel (nbr->thread_dbdesc_retrans);
  nbr->thread_dbdesc_retrans = (struct thread *) NULL;

  if (IS_OSPF6_DUMP_NEIGHBOR)
    zlog_info ("Neighbor Event %s: *ExchangeDone*", nbr->str);

  list_delete_all_node (nbr->dd_retrans);

  thread_add_timer (master, free_last_dd, nbr,
                    nbr->ospf6_interface->dead_interval);

  if (list_isempty (nbr->requestlist))
    nbs_change (NBS_FULL, "Requestlist Empty", nbr);
  else
    {
      thread_add_event (master, ospf6_send_lsreq, nbr, 0);
      nbs_change (NBS_LOADING, "Requestlist Not Empty", nbr);
    }
  return 0;
}

int
loading_done (struct thread *thread)
{
  struct neighbor *nbr;

  nbr = (struct neighbor *) THREAD_ARG  (thread);
  assert (nbr);

  if (nbr->state != NBS_LOADING)
    return 0;

  if (IS_OSPF6_DUMP_NEIGHBOR)
    zlog_info ("Neighbor Event %s: *LoadingDone*", nbr->str);

  assert (list_isempty (nbr->requestlist));

  nbs_change (NBS_FULL, "LoadingDone", nbr);

  return 0;
}

int
adj_ok (struct thread *thread)
{
  struct neighbor *nbr;

  nbr = (struct neighbor *)THREAD_ARG  (thread);
  assert (nbr);

  if (IS_OSPF6_DUMP_NEIGHBOR)
    zlog_info ("Neighbor Event %s: *AdjOK?*", nbr->str);

  if (nbr->state == NBS_TWOWAY)
    {
      if (!need_adjacency (nbr))
        {
          nbs_change (NBS_TWOWAY, "No Need Adjacency", nbr);
          return 0;
        }
      else
        nbs_change (NBS_EXSTART, "Need Adjacency", nbr);

      DD_MSBIT_SET (nbr->dd_bits);
      DD_MBIT_SET (nbr->dd_bits);
      DD_IBIT_SET (nbr->dd_bits);

      thread_add_event (master, ospf6_send_dbdesc, nbr, 0);

      return 0;
    }

  if (nbr->state >= NBS_EXSTART)
    {
      if (need_adjacency (nbr))
        return 0;
      else
        {
          nbs_change (NBS_TWOWAY, "No Need Adjacency", nbr);
          list_cleared_of_lsa (nbr);
        }
    }
  return 0;
}

int
seqnumber_mismatch (struct thread *thread)
{
  struct neighbor *nbr;

  nbr = (struct neighbor *)THREAD_ARG  (thread);
  assert (nbr);

  if (nbr->state < NBS_EXCHANGE)
    return 0;

  /* statistics */
  nbr->ospf6_stat_seqnum_mismatch++;

  if (IS_OSPF6_DUMP_NEIGHBOR)
    zlog_info ("Neighbor Event %s: *SeqNumberMismatch*", nbr->str);

  nbs_change (NBS_EXSTART, "SeqNumberMismatch", nbr);

  DD_MSBIT_SET (nbr->dd_bits);
  DD_MBIT_SET (nbr->dd_bits);
  DD_IBIT_SET (nbr->dd_bits);
  list_cleared_of_lsa (nbr);

  thread_add_event (master, ospf6_send_dbdesc, nbr, 0);

  return 0;
}

int
bad_lsreq (struct thread *thread)
{
  struct neighbor *nbr;

  nbr = (struct neighbor *)THREAD_ARG  (thread);
  assert (nbr);

  if (nbr->state < NBS_EXCHANGE)
    return 0;

  /* statistics */
  nbr->ospf6_stat_bad_lsreq++;

  if (IS_OSPF6_DUMP_NEIGHBOR)
    zlog_info ("Neighbor Event %s: *BadLSReq*", nbr->str);

  nbs_change (NBS_EXSTART, "BadLSReq", nbr);

  DD_MSBIT_SET (nbr->dd_bits);
  DD_MBIT_SET (nbr->dd_bits);
  DD_IBIT_SET (nbr->dd_bits);
  list_cleared_of_lsa (nbr);

  thread_add_event (master, ospf6_send_dbdesc, nbr, 0);

  return 0;
}

int
oneway_received (struct thread *thread)
{
  struct neighbor *nbr;

  nbr = (struct neighbor *)THREAD_ARG  (thread);
  assert (nbr);

  if (nbr->state < NBS_TWOWAY)
    return 0;

  /* statistics */
  nbr->ospf6_stat_oneway_received++;

  if (IS_OSPF6_DUMP_NEIGHBOR)
    zlog_info ("Neighbor Event %s: *1Way-Received*", nbr->str);

  nbs_change (NBS_INIT, "1Way-Received", nbr);

  thread_add_event (master, neighbor_change, nbr->ospf6_interface, 0);
  neighbor_thread_cancel (nbr);
  list_cleared_of_lsa (nbr);
  return 0;
}

int
inactivity_timer (struct thread *thread)
{
  struct neighbor *nbr;

  nbr = (struct neighbor *)THREAD_ARG  (thread);
  assert (nbr);

  /* statistics */
  nbr->ospf6_stat_inactivity_timer++;

  if (IS_OSPF6_DUMP_NEIGHBOR)
    zlog_info ("Neighbor Event %s: *InactivityTimer*", nbr->str);

  nbr->inactivity_timer = NULL;
  nbr->dr = nbr->bdr = nbr->prevdr = nbr->prevbdr = 0;
  nbs_change (NBS_DOWN, "InactivityTimer", nbr);
  neighbor_thread_cancel (nbr);
  list_cleared_of_lsa (nbr);
  thread_add_event (master, neighbor_change, nbr->ospf6_interface, 0);

  return 0;
}

