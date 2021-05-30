/*
 * Routing Information Base header
 * Copyright (C) 1997 Kunihiro Ishiguro
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

#ifndef _ZEBRA_RIB_H
#define _ZEBRA_RIB_H

#define RIB_FIB       0x01
#define RIB_LINK      0x02
#define RIB_INTERNAL  0x04

#ifndef INTERFACE_UNKNOWN
#define INTERFACE_UNKNOWN 0
#endif /* INTERFACE_UNKNOWN */

#define RIB_FIB_SET(RIB) (((RIB)->status) |= RIB_FIB)
#define RIB_FIB_UNSET(RIB) (((RIB)->status) &= ~RIB_FIB)
#define IS_RIB_FIB(RIB)  (((RIB)->status) & RIB_FIB)

#define RIB_LINK_SET(RIB) (((RIB)->status) |= RIB_LINK)
#define RIB_LINK_UNSET(RIB) (((RIB)->status) &= ~RIB_LINK)
#define IS_RIB_LINK(RIB) (((RIB)->status) & RIB_LINK)

#define RIB_INTERNAL_SET(RIB) (((RIB)->status) |= RIB_INTERNAL)
#define RIB_INTERNAL_UNSET(RIB) (((RIB)->status) &= ~RIB_INTERNAL)
#define IS_RIB_INTERNAL(RIB) (((RIB)->status) & RIB_INTERNAL)

/* Structure for routing information base. */
struct rib
{
  int type;			/* Type of this route */
  u_char flags;			/*  */
  unsigned int status;		/* Have this route goes to fib. */
  int distance;			/* Distance of this route. */
  int table;			/* Which routing table */
  struct
  {
    struct in_addr gate4;
#ifdef HAVE_IPV6
    struct in6_addr gate6;
#endif
    unsigned int ifindex;
  } u;
  struct
  {
    struct in_addr gate4;
#ifdef HAVE_IPV6
    struct in6_addr gate6;
#endif
    unsigned int ifindex;
  } i;

  struct rib *next;
  struct rib *prev;
};

/* RIB table. */
extern struct route_table *ipv4_rib_table;
#ifdef HAVE_IPV6
extern struct route_table *ipv6_rib_table;
#endif /* HAVE_IPV6 */

/* Prototypes. */
void zebra_sweep_route ();
void rib_close ();
void rib_init ();
struct rt *rib_search_rt (int, struct rt *);

int
rib_add_ipv4 (int type, int flags, struct prefix_ipv4 *p, 
	      struct in_addr *gate, unsigned int ifindex, int table);
int
rib_delete_ipv4 (int type, int flags, struct prefix_ipv4 *p,
		 struct in_addr *gate, unsigned int ifindex, int table);

#ifdef HAVE_IPV6
int
rib_add_ipv6 (int type, int flags, struct prefix_ipv6 *p,
	      struct in6_addr *gate, unsigned int ifindex, int table);

int
rib_delete_ipv6 (int type, int flags, struct prefix_ipv6 *p,
		 struct in6_addr *gate, unsigned int ifindex, int table);
#endif /* HAVE_IPV6 */

void rib_if_up (struct interface *);
void rib_if_down (struct interface *);
void rib_if_delete (struct interface *);


#endif /*_ZEBRA_RIB_H */
