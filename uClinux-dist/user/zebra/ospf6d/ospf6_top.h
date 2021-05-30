/*
 * OSPFv3 Top Level Data Structure
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

#ifndef OSPF6_TOP_H
#define OSPF6_TOP_H

#include "routemap.h"

/* ospfv3 top level data structure */
struct ospf6
{
  /* process id & instance id*/
  /* unsinged long instance_id; */
  unsigned long process_id;

  /* start time */
  struct timeval starttime;

  /* ospf version must be 3 */
  unsigned char version;

  /* my router id */
  unsigned long router_id;

  /* list of areas */
  list area_list;

  /* AS scope link state database */
  list lsdb;

  /* current routing table */
  struct route_table *table;

  /* zebra/system routing table */
  struct route_table *table_zebra;

  /* redistribute routing table */
  struct route_table *table_redistribute;

  /* redistribute configuration */
  int redist_connected;
  int redist_static;
  int redist_ripng;
  int redist_bgp;
  int redist_kernel;

  /* XXX, redistribute cost */
  unsigned short cost_static;
  unsigned short cost_ripng;
  unsigned short cost_bgp;
  unsigned short cost_kernel;

  /* XXX, redistribute table */
  struct route_table *table_external;
  struct route_table *table_connected;

  /* map of redistributed route and external LSA */
  struct route_table *redistribute_map;
  /* XXX, next LS-ID of AS-external-LSA */
  unsigned long ase_ls_id;

  /* redistribute route-map */
  struct
  {
    char *name;
    struct route_map *map;
  } rmap[ZEBRA_ROUTE_MAX];

  /* Interfaces */
  list ospf6_interface_list;
};

/* prototypes */
void ospf6_vty (struct vty *);
struct ospf6 *ospf6_start ();
void ospf6_stop ();

#endif /* OSPF6_TOP_H */

