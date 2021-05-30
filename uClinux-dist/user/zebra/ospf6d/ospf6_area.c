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

#include "ospf6d.h"

/* Make new area structure */
struct area *
ospf6_area_init (unsigned long area_id)
{
  struct area *o6a;

  /* allocate memory */
  o6a = (struct area *) XMALLOC (MTYPE_OSPF6_AREA, sizeof (struct area));
  if (!o6a)
    {
      char str[16];
      inet_ntop (AF_INET, &area_id, str, sizeof (str));
      zlog_warn ("can't malloc area %s", str);
      return NULL;
    }

  /* initialize */
  memset (o6a, 0, sizeof (struct area));
  inet_ntop (AF_INET, &area_id, o6a->str, sizeof (o6a->str));
  o6a->ospf6 = ospf6;
  o6a->area_id = area_id;
  o6a->if_list = list_init ();
  o6a->table = ospf6_route_table_init ();
  ospf6_lsdb_init_area (o6a);

  /* xxx, set options */
  V3OPT_SET (o6a->options, V3OPT_V6);
  V3OPT_SET (o6a->options, V3OPT_E);
  V3OPT_SET (o6a->options, V3OPT_R);

  /* add area list */
  list_add_node (ospf6->area_list, o6a);

  return o6a;
}

void
ospf6_area_delete (struct area *o6a)
{
  listnode n;
  struct ospf6_interface *o6if;

  /* ospf6 interface list */
  for (n = listhead (o6a->if_list); n; nextnode (n))
    {
      o6if = (struct ospf6_interface *) getdata (n);
      /* ospf6_interface_terminate (o6if); */
    }
  list_delete_all (o6a->if_list);

  /* terminate LSDB */
  ospf6_lsdb_finish_area (o6a);

  /* spf tree terminate */
  /* xxx */

  /* threads */
  if (o6a->spf_calc)
    thread_cancel (o6a->spf_calc);
  o6a->spf_calc = (struct thread *) NULL;
  if (o6a->route_calc)
    thread_cancel (o6a->route_calc);
  o6a->route_calc = (struct thread *) NULL;

  /* route table terminate */
  ospf6_route_table_finish (o6a->table);

  /* free area */
  XFREE (MTYPE_OSPF6_AREA, o6a);
}

struct area *
ospf6_area_lookup (unsigned long area_id)
{
  struct area *area;
  listnode n;

  for (n = listhead (ospf6->area_list); n; nextnode (n))
    {
      area = (struct area *)getdata (n);
      if (area->area_id == area_id)
        return area;
    }
  return (struct area *)NULL;
}

void
ospf6_area_vty (struct vty *vty, struct area *o6a)
{
  listnode i;
  struct ospf6_interface *o6i;

  vty_out (vty, "    Area %s%s", o6a->str, VTY_NEWLINE);
  vty_out (vty, "        Interface attached to this area:");
  for (i = listhead (o6a->if_list); i; nextnode (i))
    {
      o6i = (struct ospf6_interface *) getdata (i);
      vty_out (vty, " %s", o6i->interface->name);
    }
  vty_out (vty, "%s", VTY_NEWLINE);
  vty_out (vty, "        SPF algorithm executed %d times%s",
           o6a->stat_spf_execed, VTY_NEWLINE);
  vty_out (vty, "        Route calculation executed %d times%s",
           o6a->stat_route_execed, VTY_NEWLINE);
  vty_out (vty, "        Number of Area scoped LSAs is %u%s",
           listcount (o6a->lsdb), VTY_NEWLINE);
}

