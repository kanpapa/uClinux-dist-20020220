/*
 * OSPF6 Area Data Structure
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

#ifndef OSPF_AREA_H
#define OSPF_AREA_H

/* This file defines area parameters and data structures. */

#define OSPF6_AREA_RANGE_ADVERTISE     0
#define OSPF6_AREA_RANGE_NOT_ADVERTISE 1

struct area
{
  char            str[16];

  struct ospf6   *ospf6;      /* back pointer */
  u_int32_t       area_id;
  u_char          options[3]; /* OSPF Option including ExternalCapability */

  list            if_list; /* OSPF interface to this area */
  list            lsdb;
  struct spftree  spftree;

  struct thread  *spf_calc;
  struct thread  *route_calc;
  int             stat_spf_execed;
  int             stat_route_execed;

  struct route_table *table; /* new route table */
};

/* prototypes */
struct area *ospf6_area_lookup (unsigned long);
struct area *ospf6_area_init (unsigned long);
void ospf6_area_delete (struct area *);
void ospf6_area_vty (struct vty *, struct area *);

#endif /* OSPF_AREA_H */

