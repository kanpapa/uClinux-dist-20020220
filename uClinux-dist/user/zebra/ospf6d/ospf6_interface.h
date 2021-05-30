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

#ifndef OSPF6_INTERFACE_H
#define OSPF6_INTERFACE_H

/* This file defines interface data structure. */

struct ospf6_interface
{
  /* IF info from zebra */
  struct interface *interface;

  /* back pointer */
  struct ospf6 *ospf6;
  struct area *area;

  /* list of ospf6 neighbor */
  list neighbor_list;

  /* linklocal address of this I/F */
  struct in6_addr *lladdr;

  /* list of network prefixes: used by DR only */
  list network_prefixes;

  /* Interface ID; same as ifindex */
  u_int32_t if_id;

  /* ospf6 instance id */
  u_char instance_id;

  /* I/F transmission delay */
  u_int32_t transdelay;

  /* Router Priority */
  u_char priority;

  /* Timers */
  u_int16_t hello_interval;
  u_int16_t dead_interval;
  u_int32_t rxmt_interval;

  /* Cost */
  u_int32_t cost;

  /* I/F MTU */
  u_int32_t ifmtu;

  /* Interface State */
  u_char state;

  /* OSPF6 Interface flag */
  int is_passive;

  /* Decision of DR Election */
  u_int32_t dr;
  u_int32_t bdr;
  u_int32_t prevdr;
  u_int32_t prevbdr;

  /* Ongoing Tasks */
  struct thread *thread_send_hello;
  struct thread *thread_send_lsack_delayed;

  /* LSAs to Delayed Acknowledge */
  list lsa_delayed_ack;

  /* Linklocal LSA Database: includes Link-LSA */
  list lsdb;

  /* Sequence number place holder */
  int32_t       lsa_seqnum_link;
  int32_t       lsa_seqnum_network;
  int32_t       lsa_seqnum_intra_prefix;

  /* statistics */
  unsigned int ospf6_stat_dr_election;
  unsigned int ospf6_stat_delayed_lsack;
};



/* Function Prototypes */
struct ospf6_interface *
  ospf6_interface_create (struct interface *, struct ospf6 *);

void
  ospf6_interface_delete (struct ospf6_interface *);

struct in6_addr *
  ospf6_interface_linklocal_addr (struct interface *);

void ospf6_interface_if_add (struct interface *, struct ospf6 *);
void ospf6_interface_if_del (struct interface *, struct ospf6 *);
void ospf6_interface_address_update (struct interface *);

void ospf6_interface_init ();
void delete_ospf6_interface (struct ospf6_interface *);
struct ospf6_interface *ospf6_interface_lookup_by_index (int, struct ospf6 *);
int ospf6_interface_count_full_nbr (struct ospf6_interface *);
int ospf6_interface_is_enabled (struct ospf6_interface *);
int show_if (struct vty *, struct interface *);
int ospf6_interface_config_write (struct vty *);
void ospf6_interface_init ();

#endif /* OSPF6_INTERFACE_H */

