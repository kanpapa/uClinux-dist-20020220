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

#ifndef OSPF6_NEIGHBOR_H
#define OSPF6_NEIGHBOR_H

struct neighbor
{
  struct ospf6_interface     *ospf6_interface;
  unsigned char        state;
  struct thread       *inactivity_timer;
  struct thread       *send_lsreq;       /* Retransmit LSReq */
  struct thread       *send_update;      /* Retransmit LSUpdate */
  unsigned char        dd_bits;          /* including MASTER bit */
  unsigned long        seqnum;        /* DD sequence number */
  char                 str[16];          /* Router ID String */
  unsigned long        rtr_id;           /* Router ID of this neighbor */
  unsigned char        rtr_pri;          /* Router Priority of this neighbor */
  unsigned long        ifid;
  unsigned long        prevdr;
  unsigned long        dr;
  unsigned long        prevbdr;
  unsigned long        bdr;
  struct sockaddr_in6  hisaddr;        /* IPaddr of I/F on our side link */
                                       /* Probably LinkLocal address     */
  struct ospf6_dbdesc last_dd; /* last received DD , including     */
                                       /* OSPF capability of this neighbor */

  /* LSAs to retransmit to this neighbor */
  list dd_retrans;
  list direct_ack;  /* we will retrans in the case of direct ack. */

  /* LSA lists for this neighbor */
  list summarylist;
  list requestlist;
  list retranslist;

  /* new member for dbdesc */
  /* retransmission thread */
  struct thread *thread_dbdesc_retrans;        /* Retransmit DbDesc */
  struct iovec dbdesc_last_send[MAXIOVLIST];   /* placeholder for DbDesc */
  struct thread *thread_lsreq_retrans;         /* Retransmit LsReq */

  /* statistics */
  unsigned int ospf6_stat_state_changed;
  unsigned int ospf6_stat_seqnum_mismatch;
  unsigned int ospf6_stat_bad_lsreq;
  unsigned int ospf6_stat_oneway_received;
  unsigned int ospf6_stat_inactivity_timer;
  unsigned int ospf6_stat_dr_election;
  unsigned int ospf6_stat_retrans_dbdesc;
  unsigned int ospf6_stat_retrans_lsreq;
  unsigned int ospf6_stat_retrans_lsupdate;
  unsigned int ospf6_stat_received_lsa;
  unsigned int ospf6_stat_received_lsupdate;
};



/* Function Prototypes */
void delete_ospf6_nbr (struct neighbor *);
int neighbor_thread_cancel (struct neighbor *);
int list_cleared_of_lsa (struct neighbor *);
int free_last_dd (struct thread *);
unsigned int count_nbr_in_state (state_t, struct area *);
void ospf6_ipv4_nexthop_from_linklocal (struct in6_addr *,
                                        struct in_addr *,
                                        u_int);

struct neighbor *make_neighbor (rtr_id_t, struct ospf6_interface *);
struct neighbor *nbr_lookup (rtr_id_t, struct ospf6_interface *);
int show_nbr (struct vty *, struct neighbor *);

void ospf6_neighbor_vty_summary (struct vty *, struct neighbor *);
void ospf6_neighbor_vty (struct vty *, struct neighbor *);
void ospf6_neighbor_vty_detail (struct vty *, struct neighbor *);

#endif /* OSPF6_NEIGHBOR_H */

