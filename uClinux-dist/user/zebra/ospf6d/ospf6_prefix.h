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

#ifndef OSPF6_PREFIX_H
#define OSPF6_PREFIX_H

struct ospf6_prefix
{
  u_int8_t o6p_prefix_len;
  u_int8_t o6p_prefix_opt;
  u_int16_t o6p_prefix_metric;
  /* followed by one address_prefix */
};

/* size_t OSPF6_PREFIX_SPACE (int prefixlength); */
#define OSPF6_PREFIX_SPACE(x) ((((x) + 31) / 32) * 4)

/* size_t OSPF6_PREFIX_SIZE (struct ospf6_prefix *); */
#define OSPF6_PREFIX_SIZE(x) \
   (OSPF6_PREFIX_SPACE ((x)->o6p_prefix_len) + sizeof (struct ospf6_prefix))

/* struct ospf6_prefix *OSPF6_NEXT_PREFIX (struct ospf6_prefix *); */
#define OSPF6_NEXT_PREFIX(x) \
   ((struct ospf6_prefix *)((char *)(x) + OSPF6_PREFIX_SIZE (x)))



/* Function Prototypes */
struct ospf6_prefix *
  ospf6_prefix_make (u_int8_t, u_int16_t, struct prefix_ipv6 *);
void ospf6_prefix_free (struct ospf6_prefix *);
void ospf6_prefix_add (list, struct ospf6_prefix *);
void ospf6_prefix_in6_addr (struct ospf6_prefix *, struct in6_addr *);
void ospf6_prefix_str (struct ospf6_prefix *, char *, size_t);
void ospf6_prefix_copy (struct ospf6_prefix *, struct ospf6_prefix *,
                        size_t);

#endif /* OSPF6_PREFIX_H */

