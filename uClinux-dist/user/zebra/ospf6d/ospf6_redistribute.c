/*
 * OSPFv3 Redistribute
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

#include <zebra.h>

#include "prefix.h"
#include "table.h"
#include "linklist.h"
#include "vty.h"
#include "memory.h"
#include "log.h"
#include "routemap.h"

#include "ospf6_top.h"
#include "ospf6_redistribute.h"
#include "ospf6_dump.h"

/* xxx */
extern struct ospf6 *ospf6;

void
ospf6_redistribute_routemap_set (struct ospf6 *o6, int type, char *mapname)
{
  if (o6->rmap[type].name)
    free (o6->rmap[type].name);

  o6->rmap[type].name = strdup (mapname);
  o6->rmap[type].map = route_map_lookup_by_name (mapname);

  if (o6->rmap[type].map == NULL)
    zlog_info ("DEBUG: route-map set failed");
}

void
ospf6_redistribute_routemap_update ()
{
  struct ospf6 *o6 = ospf6;
  int i;

  for (i = 0; i < ZEBRA_ROUTE_MAX; i++)
    {
      if (o6->rmap[i].name)
        o6->rmap[i].map = route_map_lookup_by_name (o6->rmap[i].name);
      else
        o6->rmap[i].map = NULL;
    }
}

void
ospf6_redistribute_routemap_unset (struct ospf6 *o6, int type)
{
  if (o6->rmap[type].name)
    free (o6->rmap[type].name);

  o6->rmap[type].name = NULL;
  o6->rmap[type].map = NULL;
}

u_int32_t
ospf6_redistribute_lsid_get (struct prefix_ipv6 *p)
{
  u_int32_t lsid = 1;
  struct ospf6_lsa *lsa;
  struct prefix_ipv6 prefix6;
  struct as_external_lsa *aselsa;
  struct ospf6_prefix *o6_prefix;

  prefix6.family = AF_INET6;

  while (1)
    {
      lsa = ospf6_lsdb_lookup (htons (LST_AS_EXTERNAL_LSA), htonl (lsid),
                               ospf6->router_id, ospf6);
      if (! lsa)
        break;

      aselsa = (struct as_external_lsa *) (lsa->lsa_hdr + 1);
      o6_prefix = (struct ospf6_prefix *) (&aselsa->ase_prefix_len);
      prefix6.prefixlen = o6_prefix->o6p_prefix_len;
      ospf6_prefix_in6_addr (o6_prefix, &prefix6.prefix);

      if (prefix_same ((struct prefix *) &prefix6, (struct prefix *) p))
        break;

      lsid ++;
    }

  return lsid;
}

void
ospf6_redistribute_route_add (int type, int ifindex, struct prefix_ipv6 *p)
{
  char buf[128];
  struct ospf6_redistribute_info *info;
  struct ospf6_lsa *lsa = NULL;
  int ret;
  struct route_node *rn;

  if (type == ZEBRA_ROUTE_CONNECT)
    return;

  /* set redistribute info */
  info = XMALLOC (MTYPE_OSPF6_OTHER, sizeof (struct ospf6_redistribute_info));
  info->metric_type = 1;
  info->metric = 100;
  info->type = type;
  info->ifindex = ifindex;

  if (ospf6->rmap[type].map)
    {
      ret = route_map_apply (ospf6->rmap[type].map, (struct prefix *)p,
                             RMAP_OSPF6, info);
      if (ret == RMAP_DENYMATCH)
        {
          XFREE (MTYPE_OSPF6_OTHER, info);
          return;
        }
    }

  info->ls_id = ospf6_redistribute_lsid_get (p);
  rn = route_node_get (ospf6->redistribute_map, (struct prefix *) p);
  rn->info = info;

  /* log */
/*  if (IS_OSPF6_DUMP_ROUTE) */
    {
      zlog_info ("Redistribute add: type:%d index:%d %s/%d LS-ID %lu",
                 type, ifindex,
                 inet_ntop (AF_INET6, &p->prefix, buf, sizeof (buf)),
                 p->prefixlen, info->ls_id);
    }

  lsa = ospf6_lsa_create_as_external (info, p);
  if (!lsa)
    return;

  ospf6_lsa_flood (lsa);
  ospf6_lsdb_install (lsa);
  ospf6_lsa_unlock (lsa);
}

void
ospf6_redistribute_route_remove (int type, int ifindex, struct prefix_ipv6 *p)
{
  char buf[128];
  struct ospf6_lsa *lsa = NULL;
  struct ospf6_redistribute_info *info;
  struct route_node *rn;

  rn = route_node_lookup (ospf6->redistribute_map, (struct prefix *) p);
  if (! rn)
    return;

  info = rn->info;
  if (! info)
    return;

  if (info->type != type || info->ifindex != ifindex)
    return;

  /* log */
  if (IS_OSPF6_DUMP_ROUTE)
    {
      zlog_info ("Redistribute remove: type:%d index:%d %s/%d", type,
                 ifindex, inet_ntop (AF_INET6, &p->prefix, buf, sizeof (buf)),
                 p->prefixlen);
    }

  lsa = ospf6_lsdb_lookup (htons (LST_AS_EXTERNAL_LSA), htonl (info->ls_id),
                           ospf6->router_id, (void *) ospf6);
  if (lsa)
    ospf6_premature_aging (lsa);

  XFREE (MTYPE_OSPF6_OTHER, info);
  rn->info = NULL;
}

DEFUN (show_ipv6_ospf6_redistribute_map,
       show_ipv6_ospf6_redistribute_map_cmd,
       "show ipv6 ospf6 redistribute map",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       "redistribute infomation\n"
       "LS ID mapping\n")
{
  struct ospf6 *o6 = ospf6;
  struct route_node *rn;
  struct ospf6_redistribute_info *info;
  char buf[128];

  static char *type_name[ZEBRA_ROUTE_MAX] =
    { "System", "Kernel", "Connect", "Static", "RIP", "RIPng",
      "OSPF", "OSPF6", "BGP" };

  for (rn = route_top (o6->redistribute_map); rn; rn = route_next (rn))
    {
      if (! rn || ! rn->info)
        continue;

      info = (struct ospf6_redistribute_info *) rn->info;
      inet_ntop (rn->p.family, &rn->p.u.prefix6, buf, sizeof (buf));
      snprintf (buf, sizeof (buf), "%s/%d", buf, rn->p.prefixlen);
      vty_out (vty, "%-38s I/F:%d LS-ID:%lu Type-%d Metric %d %s%s",
               buf, info->ifindex, info->ls_id,
               info->metric_type, info->metric,
               type_name[info->type], VTY_NEWLINE);
    }

  return CMD_SUCCESS;
}

DEFUN (ospf6_redistribute_static,
       ospf6_redistribute_static_cmd,
       "redistribute static",
       "Redistribute\n"
       "Static route\n")
{
  ospf6->redist_static = 1;
  ospf6_zebra_redistribute (ZEBRA_ROUTE_STATIC);
  ospf6_redistribute_routemap_unset (ospf6, ZEBRA_ROUTE_STATIC);
  return CMD_SUCCESS;
}

DEFUN (ospf6_redistribute_static_routemap,
       ospf6_redistribute_static_routemap_cmd,
       "redistribute static route-map WORD",
       "Redistribute\n"
       "Static routes\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")
{
  ospf6->redist_static = 1;
  ospf6_zebra_redistribute (ZEBRA_ROUTE_STATIC);
  ospf6_redistribute_routemap_set (ospf6, ZEBRA_ROUTE_STATIC, argv[0]);
  return CMD_SUCCESS;
}

DEFUN (no_ospf6_redistribute_static,
       no_ospf6_redistribute_static_cmd,
       "no redistribute static",
       NO_STR
       "Redistribute\n"
       "Static route\n")
{
  ospf6->redist_static = 0;
  ospf6_zebra_no_redistribute (ZEBRA_ROUTE_STATIC);
  ospf6_redistribute_routemap_unset (ospf6, ZEBRA_ROUTE_STATIC);
  return CMD_SUCCESS;
}

DEFUN (ospf6_redistribute_kernel,
       ospf6_redistribute_kernel_cmd,
       "redistribute kernel",
       "Redistribute\n"
       "Static route\n")
{
  ospf6->redist_kernel = 1;
  ospf6_zebra_redistribute (ZEBRA_ROUTE_KERNEL);
  ospf6_redistribute_routemap_unset (ospf6, ZEBRA_ROUTE_KERNEL);
  return CMD_SUCCESS;
}

DEFUN (ospf6_redistribute_kernel_routemap,
       ospf6_redistribute_kernel_routemap_cmd,
       "redistribute kernel route-map WORD",
       "Redistribute\n"
       "Static routes\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")
{
  ospf6->redist_kernel = 1;
  ospf6_zebra_redistribute (ZEBRA_ROUTE_KERNEL);
  ospf6_redistribute_routemap_set (ospf6, ZEBRA_ROUTE_KERNEL, argv[0]);
  return CMD_SUCCESS;
}

DEFUN (no_ospf6_redistribute_kernel,
       no_ospf6_redistribute_kernel_cmd,
       "no redistribute kernel",
       NO_STR
       "Redistribute\n"
       "Static route\n")
{
  ospf6->redist_kernel = 0;
  ospf6_zebra_no_redistribute (ZEBRA_ROUTE_KERNEL);
  ospf6_redistribute_routemap_unset (ospf6, ZEBRA_ROUTE_KERNEL);
  return CMD_SUCCESS;
}

DEFUN (ospf6_redistribute_connected,
       ospf6_redistribute_connected_cmd,
       "redistribute connected",
       "Redistribute\n"
       "Connected route\n")
{
  ospf6->redist_connected = 1;
  ospf6_zebra_redistribute (ZEBRA_ROUTE_CONNECT);
  ospf6_redistribute_routemap_unset (ospf6, ZEBRA_ROUTE_CONNECT);
  return CMD_SUCCESS;
}

DEFUN (ospf6_redistribute_connected_routemap,
       ospf6_redistribute_connected_routemap_cmd,
       "redistribute connected route-map WORD",
       "Redistribute\n"
       "Connected routes\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")
{
  ospf6->redist_connected = 1;
  ospf6_zebra_redistribute (ZEBRA_ROUTE_CONNECT);
  ospf6_redistribute_routemap_set (ospf6, ZEBRA_ROUTE_CONNECT, argv[0]);
  return CMD_SUCCESS;
}

DEFUN (no_ospf6_redistribute_connected,
       no_ospf6_redistribute_connected_cmd,
       "no redistribute connected",
       NO_STR
       "Redistribute\n"
       "Connected route\n")
{
  ospf6->redist_connected = 0;
  ospf6_zebra_no_redistribute (ZEBRA_ROUTE_CONNECT);
  ospf6_redistribute_routemap_unset (ospf6, ZEBRA_ROUTE_CONNECT);
  return CMD_SUCCESS;
}

DEFUN (ospf6_redistribute_ripng,
       ospf6_redistribute_ripng_cmd,
       "redistribute ripng",
       "Redistribute\n"
       "RIPng route\n")
{
  ospf6->redist_ripng = 1;
  ospf6_zebra_redistribute (ZEBRA_ROUTE_RIPNG);
  ospf6_redistribute_routemap_unset (ospf6, ZEBRA_ROUTE_RIPNG);
  return CMD_SUCCESS;
}

DEFUN (ospf6_redistribute_ripng_routemap,
       ospf6_redistribute_ripng_routemap_cmd,
       "redistribute ripng route-map WORD",
       "Redistribute\n"
       "RIPng routes\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")
{
  ospf6->redist_ripng = 1;
  ospf6_zebra_redistribute (ZEBRA_ROUTE_RIPNG);
  ospf6_redistribute_routemap_set (ospf6, ZEBRA_ROUTE_RIPNG, argv[0]);
  return CMD_SUCCESS;
}

DEFUN (no_ospf6_redistribute_ripng,
       no_ospf6_redistribute_ripng_cmd,
       "no redistribute ripng",
       NO_STR
       "Redistribute\n"
       "RIPng route\n")
{
  ospf6->redist_ripng = 0;
  ospf6_zebra_no_redistribute (ZEBRA_ROUTE_RIPNG);
  ospf6_redistribute_routemap_unset (ospf6, ZEBRA_ROUTE_RIPNG);
  return CMD_SUCCESS;
}

DEFUN (ospf6_redistribute_bgp,
       ospf6_redistribute_bgp_cmd,
       "redistribute bgp",
       "Redistribute\n"
       "RIPng route\n")
{
  ospf6->redist_bgp = 1;
  ospf6_zebra_redistribute (ZEBRA_ROUTE_BGP);
  ospf6_redistribute_routemap_unset (ospf6, ZEBRA_ROUTE_BGP);
  return CMD_SUCCESS;
}

DEFUN (ospf6_redistribute_bgp_routemap,
       ospf6_redistribute_bgp_routemap_cmd,
       "redistribute bgp route-map WORD",
       "Redistribute\n"
       "BGP routes\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")
{
  ospf6->redist_bgp = 1;
  ospf6_zebra_redistribute (ZEBRA_ROUTE_BGP);
  ospf6_redistribute_routemap_set (ospf6, ZEBRA_ROUTE_BGP, argv[0]);
  return CMD_SUCCESS;
}

DEFUN (no_ospf6_redistribute_bgp,
       no_ospf6_redistribute_bgp_cmd,
       "no redistribute bgp",
       NO_STR
       "Redistribute\n"
       "RIPng route\n")
{
  ospf6->redist_bgp = 0;
  ospf6_zebra_no_redistribute (ZEBRA_ROUTE_BGP);
  ospf6_redistribute_routemap_unset (ospf6, ZEBRA_ROUTE_BGP);
  return CMD_SUCCESS;
}

int
ospf6_redistribute_config_write (struct vty *vty)
{
  /* redistribution */
  if (!ospf6->redist_connected)
    vty_out (vty, " no redistribute connected%s", VTY_NEWLINE);
  else if (ospf6->rmap[ZEBRA_ROUTE_CONNECT].map)
    vty_out (vty, " redistribute connected route-map %s%s",
             ospf6->rmap[ZEBRA_ROUTE_CONNECT].name, VTY_NEWLINE);

  if (ospf6->redist_static)
    {
      if (ospf6->rmap[ZEBRA_ROUTE_STATIC].map)
        vty_out (vty, " redistribute static route-map %s%s",
                 ospf6->rmap[ZEBRA_ROUTE_STATIC].name, VTY_NEWLINE);
      else
        vty_out (vty, " redistribute static%s", VTY_NEWLINE);
    }

  if (ospf6->redist_kernel)
    {
      if (ospf6->rmap[ZEBRA_ROUTE_KERNEL].map)
        vty_out (vty, " redistribute kernel route-map %s%s",
                 ospf6->rmap[ZEBRA_ROUTE_KERNEL].name, VTY_NEWLINE);
      else
        vty_out (vty, " redistribute kernel%s", VTY_NEWLINE);
    }

  if (ospf6->redist_ripng)
    {
      if (ospf6->rmap[ZEBRA_ROUTE_RIPNG].map)
        vty_out (vty, " redistribute ripng route-map %s%s",
                 ospf6->rmap[ZEBRA_ROUTE_RIPNG].name, VTY_NEWLINE);
      else
        vty_out (vty, " redistribute ripng%s", VTY_NEWLINE);
    }

  if (ospf6->redist_bgp)
    {
      if (ospf6->rmap[ZEBRA_ROUTE_BGP].map)
        vty_out (vty, " redistribute bgp route-map %s%s",
                 ospf6->rmap[ZEBRA_ROUTE_BGP].name, VTY_NEWLINE);
      else
        vty_out (vty, " redistribute bgp%s", VTY_NEWLINE);
    }

  return 0;
}

void
ospf6_redistribute_init (struct ospf6 *o6)
{
  o6->redistribute_map = route_table_init ();

  install_element (VIEW_NODE, &show_ipv6_ospf6_redistribute_map_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_redistribute_map_cmd);

  install_element (OSPF6_NODE, &ospf6_redistribute_static_cmd);
  install_element (OSPF6_NODE, &ospf6_redistribute_static_routemap_cmd);
  install_element (OSPF6_NODE, &no_ospf6_redistribute_static_cmd);
  install_element (OSPF6_NODE, &ospf6_redistribute_kernel_cmd);
  install_element (OSPF6_NODE, &ospf6_redistribute_kernel_routemap_cmd);
  install_element (OSPF6_NODE, &no_ospf6_redistribute_kernel_cmd);
  install_element (OSPF6_NODE, &ospf6_redistribute_connected_cmd);
  install_element (OSPF6_NODE, &ospf6_redistribute_connected_routemap_cmd);
  install_element (OSPF6_NODE, &no_ospf6_redistribute_connected_cmd);
  install_element (OSPF6_NODE, &ospf6_redistribute_ripng_cmd);
  install_element (OSPF6_NODE, &ospf6_redistribute_ripng_routemap_cmd);
  install_element (OSPF6_NODE, &no_ospf6_redistribute_ripng_cmd);
  install_element (OSPF6_NODE, &ospf6_redistribute_bgp_cmd);
  install_element (OSPF6_NODE, &ospf6_redistribute_bgp_routemap_cmd);
  install_element (OSPF6_NODE, &no_ospf6_redistribute_bgp_cmd);
}

void
ospf6_redistribute_finish (struct ospf6 *o6)
{
  struct route_node *rn;
  list l;
  listnode n;
  struct ospf6_redistribute_info *info;

  for (rn = route_top (o6->redistribute_map); rn; rn = route_next (rn))
    {
      l = (list) rn->info;
      while ((n = listhead (l)) != NULL)
        {
          info = (struct ospf6_redistribute_info *) getdata (n);
          ospf6_redistribute_route_remove (info->type, info->ifindex,
                                           (struct prefix_ipv6 *) &rn->p);
        }
      list_delete_all (l);
      rn->info = NULL;
    }
  route_table_finish (o6->redistribute_map);
}



