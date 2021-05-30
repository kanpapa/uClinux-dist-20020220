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

#ifndef OSPF6_SPF_H
#define OSPF6_SPF_H

#define MAX_ENTRY          ( 256 )
#define ROUTING_TABLE_SIZE (sizeof (struct routing_table_entry) * MAX_ENTRY)

struct vertex                /* Transit Vertex */
{
#define vtx_rtrid vtx_id[0]
#define vtx_ifid  vtx_id[1]
  unsigned long        vtx_id[2];    /* [Router-ID][Interface-ID] */
                                     /* Network vertex when Interface-ID !0 */
  char str[128];                     /* Identifier String */
  struct ospf6_lsa    *vtx_lsa;      /* Associated LSA */
  list                 vtx_nexthops; /* For ECMP */
  cost_t               vtx_distance; /* Distance from Root (Cost) */
  list                 vtx_path;     /* Lower node */
  list                 vtx_parent;   /* for vertex on candidate list */
  unsigned char        vtx_depth;    /* for vertex on spf tree */
};
#define MAXDEPTH       256

struct spftree
{
  struct vertex *root;
  list searchlist[HASHVAL][HASHVAL];   /* having (struct vertex *) as data */
  list depthlist[MAXDEPTH];            /* having (struct vertex *) as data */
};

#define IS_VTX_ROUTER_TYPE(x)  (!(x)->vtx_id[1])
#define IS_VTX_NETWORK_TYPE(x) ((x)->vtx_id[1])

/* Function Prototypes */
int spf_calculation (struct thread *);

#endif /* OSPF6_SPF_H */

