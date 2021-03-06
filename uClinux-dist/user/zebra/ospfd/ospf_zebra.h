/*
 * Zebra connect library for OSPFd
 * Copyright (C) 1997, 98, 99 Kunihiro Ishiguro, Toshiaki Takada
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

#ifndef _ZEBRA_OSPF_ZEBRA_H
#define _ZEBRA_OSPF_ZEBRA_H

#define EXTERNAL_METRIC_TYPE_1      0
#define EXTERNAL_METRIC_TYPE_2      1

/* Prototypes */
void zebra_init ();
void ospf_zclient_start ();

void ospf_zebra_add (struct prefix_ipv4 *, struct in_addr *);
void ospf_zebra_delete (struct prefix_ipv4 *, struct in_addr *);
void ospf_zebra_add_discard (struct prefix_ipv4 *);
void ospf_zebra_delete_discard (struct prefix_ipv4 *);

int ospf_distribute_check (int, struct prefix_ipv4 *);
void ospf_distribute_list_update (int);

int config_write_ospf_redistribute (struct vty *);

#endif /* _ZEBRA_OSPF_ZEBRA_H */
