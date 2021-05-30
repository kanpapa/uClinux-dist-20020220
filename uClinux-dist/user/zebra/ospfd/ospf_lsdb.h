/*
 * OSPF LSDB support.
 * Copyright (C) 1999, 2000 Alex Zinin, Kunihiro Ishiguro, Toshiaki Takada
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

#ifndef _ZEBRA_OSPF_LSDB_H
#define _ZEBRA_OSPF_LSDB_H

#define OSPF_LSDB_HASH 0x1
#define OSPF_LSDB_LIST 0x2
#define OSPF_LSDB_RT   0x4

#define OSPF_LSDB_DEF  OSPF_LSDB_HASH

/* New LSDB structure. */
struct new_lsdb
{
  struct
  {
    unsigned long count;
    struct route_table *db;
  } type[OSPF_MAX_LSA];
  unsigned long total;
};

#if 0
struct ospf_lsdb
{
  u_char       flags;

  struct Hash *hash;		/* Hash table for LSAs. */
  list	       list;		/* List version. */
  struct route_table *rt;	/* RT version. */
  u_int	       count;
  u_int	       count_self;
  struct ospf_area * area;	/* Associated area */
};
#endif

/* Macros. */
#define ROUTER_LSDB(A)       ((A)->lsdb->type[OSPF_ROUTER_LSA].db)
#define NETWORK_LSDB(A)	     ((A)->lsdb->type[OSPF_NETWORK_LSA].db)
#define SUMMARY_LSDB(A)      ((A)->lsdb->type[OSPF_SUMMARY_LSA].db)
#define SUMMARY_ASBR_LSDB(A) ((A)->lsdb->type[OSPF_SUMMARY_LSA_ASBR].db)
#define EXTERNAL_LSDB(O) \
        ((O)->external_lsa->type[OSPF_AS_EXTERNAL_LSA].db)

/* Prototypes. */
struct ospf_lsa *foreach_lsa (struct route_table *, void *, int,
	              int (*callback) (struct ospf_lsa *, void *, int));

/* New LSDB related functions. */
struct new_lsdb *new_lsdb_new ();
void new_lsdb_init (struct new_lsdb *);
void new_lsdb_free (struct new_lsdb *);
void new_lsdb_cleanup (struct new_lsdb *);
void new_lsdb_add (struct new_lsdb *, struct ospf_lsa *);
struct ospf_lsa *new_lsdb_insert (struct new_lsdb *, struct ospf_lsa *);
void new_lsdb_delete (struct new_lsdb *, struct ospf_lsa *);
void new_lsdb_delete_all (struct new_lsdb *);
struct ospf_lsa *new_lsdb_lookup (struct new_lsdb *, struct ospf_lsa *);
struct ospf_lsa *new_lsdb_lookup_by_id (struct new_lsdb *, u_char,
					struct in_addr, struct in_addr);
unsigned long new_lsdb_count (struct new_lsdb *);
unsigned long new_lsdb_isempty (struct new_lsdb *);

#endif /* _ZEBRA_OSPF_LSDB_H */
