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

#include "ospf6d.h"

#include "ospf6_redistribute.h"

void
ospf6_vty_redistribute_config (struct vty *vty, struct ospf6 *ospf6)
{
  if (ospf6->redist_static || ospf6->redist_kernel || ospf6->redist_ripng || ospf6->redist_bgp)
    vty_out (vty, " Redistributing External Routes from,%s", VTY_NEWLINE);
  else
    return;

  if (ospf6->redist_static)
    vty_out (vty, "    static with metric mapped to %hu%s",
             ospf6->cost_static, VTY_NEWLINE);
  if (ospf6->redist_kernel)
    vty_out (vty, "    kernel with metric mapped to %hu%s",
             ospf6->cost_kernel, VTY_NEWLINE);
  if (ospf6->redist_ripng)
    vty_out (vty, "    ripng with metric mapped to %hu%s",
             ospf6->cost_ripng, VTY_NEWLINE);
  if (ospf6->redist_bgp)
    vty_out (vty, "    bgp with metric mapped to %hu%s",
             ospf6->cost_bgp, VTY_NEWLINE);
}

void
ospf6_vty (struct vty *vty)
{
  listnode n;
  struct area *area;

  /* process id, router id */
  {
    char rid_buf[64];
    inet_ntop (AF_INET, &ospf6->router_id, rid_buf, sizeof (rid_buf));
    vty_out (vty, " Routing Process (%lu) with ID %s%s",
             ospf6->process_id, rid_buf, VTY_NEWLINE);
  }

  /* running time */
  {
    unsigned long day, hour, min, sec, left;
    struct timeval now;

    gettimeofday (&now, (struct timezone *)NULL);
    left = now.tv_sec - ospf6->starttime.tv_sec;
    day = left / 86400; left -= day * 86400;
    hour = left / 3600; left -= hour * 3600;
    min = left / 60;    left -= min * 60;
    sec = left;
    vty_out (vty, " Running %d days %d hours %d minutes %d seconds%s",
             day, hour, min, sec, VTY_NEWLINE);
  }

  vty_out (vty, " Supports only single TOS(TOS0) routes%s", VTY_NEWLINE);

  /* Redistribute config */
  ospf6_vty_redistribute_config (vty, ospf6);

  /* LSAs */
  vty_out (vty, " Number of AS scoped LSAs is %u%s",
           listcount (ospf6->lsdb), VTY_NEWLINE);

  /* Areas */
  vty_out (vty, " Number of areas in this router is %u%s",
           listcount (ospf6->area_list), VTY_NEWLINE);
  for (n = listhead (ospf6->area_list); n; nextnode (n))
    {
      area = (struct area *) getdata (n);
      ospf6_area_vty (vty, area);
    }

#if 0
  /* Interface */
  vty_out (vty, " Number of interfaces in this OSPF is %u%s",
           listcount (ospf6->ospf6_interface_list), VTY_NEWLINE);
  for (n = listhead (ospf6->ospf6_interface_list); n; nextnode (n))
    {
      o6i = (struct ospf6_interface *) getdata (n);
      ospf6_interface_vty (vty, o6i);
    }
#endif /*0*/

}

static struct ospf6 *
ospf6_new ()
{
  struct ospf6 *new;
  new = XMALLOC (MTYPE_OSPF6_TOP, sizeof (struct ospf6));
  if (new)
    memset (new, 0, sizeof (struct ospf6));
  return new;
}

static void
ospf6_free (struct ospf6 *ospf6)
{
  XFREE (MTYPE_OSPF6_TOP, ospf6);
}

struct ospf6 *
ospf6_create (unsigned long process_id)
{
  struct ospf6 *ospf6;

  /* allocate memory to global pointer */
  ospf6 = ospf6_new ();

  /* initialize */
  gettimeofday (&ospf6->starttime, (struct timezone *)NULL);
  ospf6->process_id = process_id;
  ospf6->version = OSPF6_VERSION;
  ospf6->area_list = list_init ();
  ospf6_lsdb_init_as (ospf6);
  ospf6->ospf6_interface_list = list_init ();
  ospf6->ase_ls_id = 0;

  /* route table init */
  ospf6->table = ospf6_route_table_init ();
  ospf6->table_zebra = ospf6_route_table_init ();
  ospf6->table_redistribute = ospf6_route_table_init ();
  ospf6->table_connected = ospf6_route_table_init ();
  ospf6->table_external = ospf6_route_table_init ();

  ospf6_redistribute_init (ospf6);

  /* default redistribute */
  ospf6->redist_connected = 1;

  return ospf6;
}

void
ospf6_delete (struct ospf6 *ospf6)
{
  listnode n;
  struct area *area;

  /* shutdown areas */
  for (n = listhead (ospf6->area_list); n; nextnode (n))
    {
      area = (struct area *) getdata (n);
      ospf6_area_delete (area);
    }
  list_delete_all (ospf6->area_list);

  /* finish AS scope link state database */
  ospf6_lsdb_finish_as (ospf6);

  /* finish route tables */
  ospf6_route_table_finish (ospf6->table);
  ospf6_route_table_finish (ospf6->table_zebra);
  ospf6_route_table_finish (ospf6->table_connected);
  ospf6_route_table_finish (ospf6->table_external);

  ospf6_redistribute_finish (ospf6);

  ospf6_free (ospf6);
}

struct ospf6 *
ospf6_start ()
{
  if (ospf6)
    return ospf6;

  ospf6 = ospf6_create (0);
  return ospf6;
}

void
ospf6_stop ()
{
  if (!ospf6)
    return;

  ospf6_delete (ospf6);
  ospf6 = NULL;
}

