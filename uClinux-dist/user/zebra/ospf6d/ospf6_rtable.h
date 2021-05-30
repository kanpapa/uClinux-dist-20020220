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

#ifndef OSPF6_RTABLE_H
#define OSPF6_RTABLE_H

/* Destination Types (from draft-ietf-ospf-ospfv6-06.txt 3.3) */
#define DTYPE_NONE                0x00
#define DTYPE_PREFIX              0x01 /* IPv6 prefix */
#define DTYPE_ASBR                0x02 /* AS boundary router */
#define DTYPE_INTRA_ROUTER        0x03 /* each router in the area */
#define DTYPE_INTRA_LINK          0x04 /* each transit link in the area */
#define DTYPE_STATIC_REDISTRIBUTE 0xf1 /* redistributed from static */
#define DTYPE_RIPNG_REDISTRIBUTE  0xf2 /* redistributed from ripng */
#define DTYPE_BGP_REDISTRIBUTE    0xf3 /* redistributed from bgp */
#define DTYPE_KERNEL_REDISTRIBUTE 0xf4 /* redistributed from kernel */

/* Path-types (from RFC2328 11), decreasing order of preference */
#define PTYPE_INTRA          1    /* intra-area */
#define PTYPE_INTER          2    /* inter-area */
#define PTYPE_TYPE1_EXTERNAL 3    /* type 1 external */
#define PTYPE_TYPE2_EXTERNAL 4    /* type 2 external */

/* Next Hop */
struct ospf6_nexthop
{
  unsigned long   ifindex;
  struct in6_addr ipaddr;    /* if any */
  unsigned long   advrtr;    /* for inter-area and AS external nexthop */
                             /* 0 for intra-area routes */
  unsigned int    lock;      /* reference count of this nexthop(nexthop) */
};

struct ospf6_route_node_info
{
  unsigned char     dest_type;       /* Destination Type */
  unsigned char     opt_cap[3];      /* Optional Capability */
  struct area      *area;            /* Associated area */
    /* note: multiple entry for the same ABR is different
       in routing table by index */
  unsigned char     path_type;       /* Path-type */
  unsigned long     cost;            /* Cost to this route */
  struct ospf6_lsa *ls_origin;       /* Link State Origin, for MOSPF */
  list              nhlist;          /* nexthop list */

  /* For External LSA */
  unsigned long     ase_lsid;        /* mapped LS ID */
  int               ase_protocol;    /* source protocol */
};


/* function definition */

void nexthop_init ();
void nexthop_finish ();
struct ospf6_nexthop *nexthop_make (unsigned long,
                                    struct in6_addr *,
                                    unsigned long);
void nexthop_delete (struct ospf6_nexthop *);
void nexthop_add_from_vertex (struct vertex *, struct vertex *, list);
int routing_table_calculation (struct thread *);
char *nexthop_str (struct ospf6_nexthop *, char *, size_t);

struct route_node *ospf6_route_lookup (struct prefix_ipv6 *,
                                       struct route_table *);
void ospf6_route_add (struct prefix_ipv6 *,
                      struct ospf6_route_node_info *,
                      struct route_table *);
void ospf6_route_delete (struct prefix_ipv6 *,
                         struct ospf6_route_node_info *,
                         struct route_table *);
void ospf6_route_delete_node (struct route_node *);

struct route_table *ospf6_route_table_init (void);
struct route_table *ospf6_route_table_clear (struct route_table *);
void ospf6_route_table_finish (struct route_table *);

void ospf6_route_set_dst_rtrid (unsigned long, struct prefix_ipv6 *);
void ospf6_route_set_dst_ifid (unsigned long, struct prefix_ipv6 *);
unsigned long ospf6_route_get_dst_rtrid (struct prefix_ipv6 *);
unsigned long ospf6_route_get_dst_ifid (struct prefix_ipv6 *);

char *ospf6_route_str (struct route_node *, char *, size_t);
void ospf6_route_vty (struct vty *, struct route_node *);

int ospf6_route_calc (struct thread *);
void ospf6_route_update_zebra ();

void ospf6_route_vty_new (struct vty *, struct route_node *, int);

void ospf6_rtable_init ();

#endif /* OSPF6_RTABLE_H */

