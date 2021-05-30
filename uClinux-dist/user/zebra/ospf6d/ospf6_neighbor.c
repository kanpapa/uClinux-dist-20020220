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

void
delete_ospf6_nbr (struct neighbor *nbr)
{
}

int
neighbor_thread_cancel (struct neighbor *nbr)
{
  if (nbr->inactivity_timer)
    thread_cancel (nbr->inactivity_timer);
  if (nbr->send_update)
    thread_cancel (nbr->send_update);

  nbr->inactivity_timer = nbr->send_update
    = (struct thread *)NULL;

  /* new */
  if (nbr->thread_dbdesc_retrans)
    thread_cancel (nbr->thread_dbdesc_retrans);
  nbr->thread_dbdesc_retrans = (struct thread *) NULL;

  if (nbr->thread_lsreq_retrans)
    thread_cancel (nbr->thread_lsreq_retrans);
  nbr->thread_lsreq_retrans = (struct thread *) NULL;

  return 0;
}

int
list_cleared_of_lsa (struct neighbor *nbr)
{
  list_delete_all_node (nbr->dd_retrans);
  ospf6_lsdb_finish_neighbor (nbr);
  ospf6_lsdb_init_neighbor (nbr);
  return 0;
}

int
free_last_dd (struct thread *thread)
{
  struct neighbor *nbr;

  nbr = (struct neighbor *)THREAD_ARG (thread);
  assert (nbr);
  memset (&nbr->last_dd, 0, sizeof (struct ospf6_dbdesc));
  return 0;
}

/* count neighbor which is in "state" in this area*/
unsigned int
count_nbr_in_state (state_t state, struct area *area)
{
  listnode n, o;
  struct ospf6_interface *o6if;
  struct neighbor *nbr;
  unsigned int count = 0;

  for (n = listhead (area->if_list); n; nextnode (n))
    {
      o6if = (struct ospf6_interface *) getdata (n);
      for (o = listhead (o6if->neighbor_list); o; nextnode (o))
        {
          nbr = (struct neighbor *) getdata (o);
          if (nbr->state == state)
            count++;
        }
    }
  return count;
}

/* Neighbor section */
/* Allocate new Neighbor data structure */
static struct neighbor *
neighbor_new ()
{
  struct neighbor *new = (struct neighbor *)
      XMALLOC (MTYPE_OSPF6_NEIGHBOR, sizeof (struct neighbor));
  if (new)
    memset (new, 0, sizeof (struct neighbor));
  else
    zlog_warn ("Can't malloc neighbor");
  return new;
}



/* Make new neighbor structure */
struct neighbor *
make_neighbor (rtr_id_t rtr_id, struct ospf6_interface *ospf6_interface)
{
  struct neighbor *nbr = neighbor_new ();

  if (!nbr)
    return (struct neighbor *)NULL;
  nbr->state = NBS_DOWN;
  nbr->ospf6_interface = ospf6_interface;
  nbr->rtr_id = rtr_id;
  inet_ntop (AF_INET, &rtr_id, nbr->str, sizeof (nbr->str));
  nbr->inactivity_timer = (struct thread *)NULL;
  nbr->dd_retrans = list_init ();
  nbr->summarylist = list_init ();
  nbr->retranslist = list_init ();
  nbr->requestlist = list_init ();
  nbr->direct_ack = list_init ();
  list_add_node (ospf6_interface->neighbor_list, nbr);

  return nbr;
}

/* delete neighbor from ospf6_interface nbr_list */
void
delete_neighbor (struct neighbor *nbr, struct ospf6_interface *ospf6_interface)
{
  /* xxx not yet */
  return;
}

/* delete all neighbor on ospf6_interface nbr_list */
void
delete_all_neighbors (struct ospf6_interface *ospf6_interface)
{
  /* xxx not yet */
  return;
}


/* Lookup functions. */
/* lookup neighbor from OSPF6 interface.
   because neighbor may appear on two different OSPF interface */
struct neighbor *
nbr_lookup (rtr_id_t rtr_id, struct ospf6_interface *o6if)
{
  struct neighbor *nbr;
  listnode k;

  for (k = listhead (o6if->neighbor_list); k; nextnode (k))
    {
      nbr = (struct neighbor *)getdata (k);
      if (nbr->rtr_id == rtr_id)
        return nbr;
    }

  return (struct neighbor *)NULL;
}


/* show specified area structure */

/* show neighbor structure */
int
show_nbr (struct vty *vty, struct neighbor *nbr)
{
  char rtrid[16], dr[16], bdr[16];

#if 0
  vty_out (vty, "%-15s %-6s %-8s %-15s %-15s %s[%s]%s",
     "RouterID", "I/F-ID", "State", "DR", "BDR", "I/F", "State", VTY_NEWLINE);
#endif

  inet_ntop (AF_INET, &nbr->rtr_id, rtrid, sizeof (rtrid));
  inet_ntop (AF_INET, &nbr->dr, dr, sizeof (dr));
  inet_ntop (AF_INET, &nbr->bdr, bdr, sizeof (bdr));
  vty_out (vty, "%-15s %6lu %-8s %-15s %-15s %s[%s]%s",
           rtrid, nbr->ifid, nbs_name[nbr->state], dr, bdr,
           nbr->ospf6_interface->interface->name,
           ifs_name[nbr->ospf6_interface->state],
	   VTY_NEWLINE);
  return 0;
}

void
ospf6_neighbor_vty_summary (struct vty *vty, struct neighbor *nbr)
{
  char rtrid[16], dr[16], bdr[16];

/*
   vty_out (vty, "%-15s %-6s %-8s %-15s %-15s %s[%s]%s",
            "RouterID", "I/F-ID", "State", "DR",
            "BDR", "I/F", "State", VTY_NEWLINE);
*/

  inet_ntop (AF_INET, &nbr->rtr_id, rtrid, sizeof (rtrid));
  inet_ntop (AF_INET, &nbr->dr, dr, sizeof (dr));
  inet_ntop (AF_INET, &nbr->bdr, bdr, sizeof (bdr));
  vty_out (vty, "%-15s %6lu %-8s %-15s %-15s %s[%s]%s",
           rtrid, nbr->ifid, nbs_name[nbr->state], dr, bdr,
           nbr->ospf6_interface->interface->name,
           ifs_name[nbr->ospf6_interface->state],
	   VTY_NEWLINE);
}

void
ospf6_neighbor_vty (struct vty *vty, struct neighbor *o6n)
{
  char hisaddr[64];
  inet_ntop (AF_INET6, &o6n->hisaddr.sin6_addr, hisaddr, sizeof (hisaddr));
  vty_out (vty, " Neighbor %s, interface address %s%s",
                o6n->str, hisaddr, VTY_NEWLINE);
  vty_out (vty, "    In the area %s via interface %s(ifindex %d)%s",
                o6n->ospf6_interface->area->str,
                o6n->ospf6_interface->interface->name,
                o6n->ospf6_interface->interface->ifindex,
                VTY_NEWLINE);
  vty_out (vty, "    Neighbor priority is %d, State is %s, %d state changes%s",
                o6n->rtr_pri, nbs_name[o6n->state],
                o6n->ospf6_stat_state_changed, VTY_NEWLINE);
}

void
ospf6_neighbor_vty_detail (struct vty *vty, struct neighbor *o6n)
{
  char dbdesc_bit[64], hisdr[16], hisbdr[16];
  ospf6_neighbor_vty (vty, o6n);

  inet_ntop (AF_INET, &o6n->dr, hisdr, sizeof (hisdr));
  inet_ntop (AF_INET, &o6n->bdr, hisbdr, sizeof (hisbdr));

  ospf6_dump_ddbit (o6n->dd_bits, dbdesc_bit, sizeof (dbdesc_bit));
  vty_out (vty, "    My DbDesc bit for this neighbor: %s%s",
                dbdesc_bit, VTY_NEWLINE);
  vty_out (vty, "    His Ifindex of myside: %lu%s",
                o6n->ifid, VTY_NEWLINE);
  vty_out (vty, "    His DRDecision: DR %s, BDR %s%s",
                hisdr, hisbdr, VTY_NEWLINE);
  ospf6_dump_ddbit (o6n->last_dd.bits, dbdesc_bit, sizeof (dbdesc_bit));
  vty_out (vty, "    Last received DbDesc: opt:%s"
                " ifmtu:%hu bit:%s seqnum:%lu%s",
                "xxx", ntohs (o6n->last_dd.ifmtu), dbdesc_bit,
                ntohl (o6n->last_dd.seqnum), VTY_NEWLINE);
  vty_out (vty, "    Number of LSAs retransmitting: %d%s",
                listcount (o6n->dd_retrans), VTY_NEWLINE);
  vty_out (vty, "    Number of LSAs direct-ack'ing: %d%s",
                listcount (o6n->direct_ack), VTY_NEWLINE);
  vty_out (vty, "    Number of LSAs in SummaryList: %d%s",
                listcount (o6n->summarylist), VTY_NEWLINE);
  vty_out (vty, "    Number of LSAs in RequestList: %d%s",
                listcount (o6n->requestlist), VTY_NEWLINE);
  vty_out (vty, "    Number of LSAs in RetransList: %d%s",
                listcount (o6n->retranslist), VTY_NEWLINE);
  vty_out (vty, "    %-16s %5d times, %-16s %5d times%s",
                "SeqnumMismatch", o6n->ospf6_stat_seqnum_mismatch,
                "BadLSReq", o6n->ospf6_stat_bad_lsreq, VTY_NEWLINE);
  vty_out (vty, "    %-16s %5d times, %-16s %5d times%s",
                "OnewayReceived", o6n->ospf6_stat_oneway_received,
                "InactivityTimer", o6n->ospf6_stat_inactivity_timer,
                VTY_NEWLINE);
  vty_out (vty, "    %-16s %5d times, %-16s %5d times%s",
                "DbDescRetrans", o6n->ospf6_stat_retrans_dbdesc,
                "LSReqRetrans", o6n->ospf6_stat_retrans_lsreq,
                VTY_NEWLINE);
  vty_out (vty, "    %-16s %5d times%s",
                "LSUpdateRetrans", o6n->ospf6_stat_retrans_lsupdate,
                VTY_NEWLINE);
  vty_out (vty, "    %-16s %5d times, %-16s %5d times%s",
                "LSAReceived", o6n->ospf6_stat_received_lsa,
                "LSUpdateReceived", o6n->ospf6_stat_received_lsupdate,
                VTY_NEWLINE);
}

