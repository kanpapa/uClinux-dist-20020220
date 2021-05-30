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

#ifndef OSPF6_LSDB_H
#define OSPF6_LSDB_H

#define MAXLISTEDLSA 512
#define MAXLSASIZE   1024

#define AREALSTYPESIZE              0x0009

#define HASHVAL   64
#define hash(x)  ((x) % HASHVAL)

#define MY_ROUTER_LSA_ID    0

/* Function Prototypes */
int lsa_change (struct ospf6_lsa *);
struct ospf6_lsa_hdr *
attach_lsa_hdr_to_iov (struct ospf6_lsa *, struct iovec *);
struct ospf6_lsa_hdr *
attach_lsa_to_iov (struct ospf6_lsa *lsa, struct iovec *iov);

struct ospf6_lsa *
ospf6_lookup_maxage (struct ospf6_lsa *lsa, struct ospf6 *);
void ospf6_add_maxage (struct ospf6_lsa *, struct ospf6 *);
void ospf6_remove_maxage (struct ospf6_lsa *, struct ospf6 *);

struct ospf6_lsa *
ospf6_lookup_summary (struct ospf6_lsa *lsa, struct neighbor *);
void ospf6_add_summary (struct ospf6_lsa *, struct neighbor *);
void ospf6_remove_summary (struct ospf6_lsa *, struct neighbor *);
void ospf6_remove_summary_all (struct neighbor *);

struct ospf6_lsa *
ospf6_lookup_request (struct ospf6_lsa *lsa, struct neighbor *nbr);
void ospf6_add_request (struct ospf6_lsa *, struct neighbor *);
void ospf6_remove_request (struct ospf6_lsa *, struct neighbor *);
void ospf6_remove_request_all (struct neighbor *);

struct ospf6_lsa *
ospf6_lookup_retrans (struct ospf6_lsa *lsa, struct neighbor *nbr);
void ospf6_add_retrans (struct ospf6_lsa *, struct neighbor *);
void ospf6_remove_retrans (struct ospf6_lsa *, struct neighbor *);
void ospf6_remove_retrans_all (struct neighbor *);

void
ospf6_add_delayed_ack (struct ospf6_lsa *, struct ospf6_interface *);
void
ospf6_remove_delayed_ack (struct ospf6_lsa *, struct ospf6_interface *);

void ospf6_lsdb_collect_type_advrtr (list, unsigned short,
                                     unsigned long, void *);
void ospf6_lsdb_collect_type (list, unsigned short, void *);

struct ospf6_lsa*
ospf6_lsdb_lookup (unsigned short, unsigned long, unsigned long, void *);
struct ospf6_lsa*
ospf6_lsdb_lookup_new (unsigned short, unsigned long,
                       unsigned long, struct ospf6 *);
void ospf6_lsdb_add (struct ospf6_lsa *);
void ospf6_lsdb_remove (struct ospf6_lsa *);

void ospf6_lsdb_init_neighbor (struct neighbor *);
void ospf6_lsdb_finish_neighbor (struct neighbor *);
void ospf6_lsdb_init_interface (struct ospf6_interface *);
void ospf6_lsdb_finish_interface (struct ospf6_interface *);
void ospf6_lsdb_init_area (struct area *);
void ospf6_lsdb_finish_area (struct area *);
void ospf6_lsdb_init_as (struct ospf6 *);
void ospf6_lsdb_finish_as (struct ospf6 *);

void ospf6_lsdb_install (struct ospf6_lsa *);

void ospf6_lsdb_maxage_remove_interface (struct ospf6_interface *);
void ospf6_lsdb_maxage_remove_area (struct area *);
void ospf6_lsdb_maxage_remove_as (struct ospf6 *);
void ospf6_lsdb_check_maxage_lsa (struct ospf6 *);

void ospf6_lsdb_interface_update (struct ospf6_interface *);
void ospf6_lsdb_init ();

#endif /* OSPF6_LSDB_H */

