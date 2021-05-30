/*
 * ospf6 routing table calculation function
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

#include "if.h"
#include "table.h"
#include "vty.h"

#include "ospf6_rtable.h"

char *dtype_string[] =
{
  "None",
  "Prefix",
  "ASBR",
  "IntraRouter",
  "IntraLink",
  NULL
};

char *ptype_string[] =
{
  "Unknown",
  "IntraArea",
  "InterArea",
  "T1External",
  "T2External",
  NULL
};

static struct ospf6_nexthop *
nexthop_new ()
{
  struct ospf6_nexthop *p;
  p = XMALLOC (MTYPE_OSPF6_ROUTE, sizeof (struct ospf6_nexthop));
  if (!p)
    {
      zlog_warn ("can't alloc for nexthop");
      return NULL;
    }
  return p;
}

static void
nexthop_free (struct ospf6_nexthop *p)
{
  assert (p);
  XFREE (MTYPE_OSPF6_ROUTE, p);
  return;
}

static void
nexthop_lock (struct ospf6_nexthop *p)
{
  assert (p);
  p->lock++;
  return;
}

static void
nexthop_unlock (struct ospf6_nexthop *p)
{
  assert (p);
  assert (p->lock > 0);
  p->lock--;
  if (p->lock == 0)
    {
      list_delete_by_val (nexthoplist, p);
      nexthop_free (p);
    }
  return;
}

static struct ospf6_nexthop *
nexthop_lookup (unsigned long ifindex, struct in6_addr *ipaddr,
                unsigned long advrtr)
{
  struct ospf6_nexthop *p;
  listnode n;

  for (n = listhead (nexthoplist); n; nextnode (n))
    {
      p = getdata (n);
      if (p->ifindex == ifindex &&
          IN6_ARE_ADDR_EQUAL (&p->ipaddr, ipaddr) &&
          p->advrtr == advrtr)
        return p;
    }
  return NULL;
}

struct ospf6_nexthop *
nexthop_make (unsigned long ifindex, struct in6_addr *ipaddr,
              unsigned long advrtr)
{
  struct ospf6_nexthop *p;

  p = nexthop_lookup (ifindex, ipaddr, advrtr);
  if (p)
    {
      nexthop_lock (p);
      return p;
    }

  p = nexthop_new ();
  p->ifindex = ifindex;
  memcpy (&p->ipaddr, ipaddr, sizeof (p->ipaddr));
  p->advrtr = advrtr;
  nexthop_lock (p);
  list_add_node (nexthoplist, p);
  return p;
}

void nexthop_delete (struct ospf6_nexthop *p)
{
  nexthop_unlock (p);
  return;
}

void nexthop_init ()
{
  if (!nexthoplist)
    nexthoplist = list_init ();
  else
    zlog_warn ("*** !nexthoplist already exists");
}

void nexthop_finish ()
{
  if (!list_isempty (nexthoplist))
    zlog_warn ("*** !nexthop memory leak");
  else
    {
      list_delete_all (nexthoplist);
      nexthoplist = NULL;
    }
}


/* RFC2328 16.1.1 The next hop calculation */
void
nexthop_add_from_vertex (struct vertex *dst, struct vertex *parent, list l)
{
  listnode n, o;
  struct ospf6_nexthop *p;
  unsigned long ifindex;
  struct in6_addr ipaddr;
  struct ospf6_interface *o6if;
  struct ospf6_lsa *lsa;
  struct ospf6_lsa_hdr *lsa_hdr;
  struct link_lsa *linklsa;
  list m;

  if (dst->vtx_depth > 2 ||
      (dst->vtx_depth == 2 && IS_VTX_ROUTER_TYPE (parent)))
    {
      /* simply inherits from the parent */
      for (n = listhead (parent->vtx_nexthops); n; nextnode (n))
        {
          p = getdata (n);

          /* check if this is already on the nexthop list */
          for (o = listhead (l); o; nextnode (o))
            if (p == getdata (o))
              continue;

          nexthop_lock (p);
          list_add_node (l, p);
        }
      return;
    }
  else if (dst->vtx_depth == 1)
    {
      struct neighbor *nbr;

      /* the parent is root */
      assert (parent->vtx_depth == 0);

      ifindex = get_ifindex_to_router (dst->vtx_rtrid, parent->vtx_lsa);
      assert (ifindex);
      memset (&ipaddr, 0, sizeof (struct in6_addr));

      /* get ospf6_interface data structure */
      o6if = ospf6_interface_lookup_by_index (ifindex, ospf6);
      assert (o6if);

      /* set nexthop to ip address of neighbor router */
      if (IS_VTX_ROUTER_TYPE (dst))
        {
          nbr = nbr_lookup (dst->vtx_rtrid, o6if);
          assert (nbr);
          memcpy (&ipaddr, &nbr->hisaddr.sin6_addr,
                  sizeof (struct in6_addr));
        }

      p = nexthop_make (ifindex, &ipaddr, 0);
      list_add_node (l, p);
      return;
    }
  else if (dst->vtx_depth == 2)
    {
      assert (IS_VTX_ROUTER_TYPE (dst));
      assert (IS_VTX_NETWORK_TYPE (parent));

      /* simply inherit ifindex from the parent network */
      assert (listcount (parent->vtx_nexthops) == 1);
      p = getdata (listhead (parent->vtx_nexthops));
      ifindex = p->ifindex;
      assert (ifindex);

      /* get ospf6_interface data structure */
      o6if = ospf6_interface_lookup_by_index (ifindex, ospf6);
      assert (o6if);

      /* get LinkLSA of destination router */
      m = list_init ();
      ospf6_lsdb_collect_type_advrtr (m, htons (LST_LINK_LSA),
                                      dst->vtx_rtrid, (void *)o6if);
      /* set nexthop address */
      if (list_isempty (m))
        {
          char rtrid_str[16];

          /* if no LinkLSA found, set to :: */
          inet_ntop (AF_INET, &dst->vtx_rtrid,
                     rtrid_str, sizeof (rtrid_str));
          zlog_warn ("*** Can't find Link-LSA for %s, null nexthop",
                     rtrid_str);
          memset (&ipaddr, 0, sizeof (struct in6_addr));
        }
      else
        {
          assert (listcount (m) == 1);
          lsa = (struct ospf6_lsa *) getdata (listhead (m));
          lsa_hdr = lsa->lsa_hdr;
          linklsa = (struct link_lsa *)(lsa_hdr + 1);
          memcpy (&ipaddr, &linklsa->llsa_linklocal,
                  sizeof (struct in6_addr));
        }

      p = nexthop_make (ifindex, &ipaddr, 0);
      list_add_node (l, p);
      list_delete_all (m);
      return;
    }
  else
    {
      assert (dst->vtx_depth == 0 && parent == NULL);
    }
  return;
}

char *
nexthop_str (struct ospf6_nexthop *nh, char *buf, size_t bufsize)
{
  struct interface *ifp;
  char *ifname, ipaddr[64], advrtr[24];

  memset (advrtr, 0, sizeof(advrtr));
  ifp = if_lookup_by_index (nh->ifindex);
  if (!ifp)
    ifname = "???";
  else
    ifname = ifp->name;

  if (IN6_IS_ADDR_UNSPECIFIED (&nh->ipaddr))
    snprintf (ipaddr, sizeof (ipaddr), "Link#%lu", nh->ifindex);
  else
    inet_ntop (AF_INET6, &nh->ipaddr, ipaddr, sizeof (ipaddr));
  if (nh->advrtr)
    {
      inet_ntop (AF_INET, &nh->advrtr, advrtr, sizeof (advrtr));
      snprintf (buf, bufsize, "%s %s %s", ipaddr, ifname, advrtr);
    }
  else
      snprintf (buf, bufsize, "%s %s", ipaddr, ifname);
     
  return buf;
}


char *
ptype_str (unsigned char path_type, char *buf, int bufsize)
{
  switch (path_type)
    {
      case PTYPE_INTRA:
        snprintf (buf, bufsize, "%s", "Intra");
        break;

      case PTYPE_INTER:
        snprintf (buf, bufsize, "%s", "Inter");
        break;

      case PTYPE_TYPE1_EXTERNAL:
        snprintf (buf, bufsize, "%s", "T1Ext");
        break;

      case PTYPE_TYPE2_EXTERNAL:
        snprintf (buf, bufsize, "%s", "T2Ext");
        break;

      default:
        snprintf (buf, bufsize, "%s", "?????");
        break;
    }
  return buf;
}

static struct ospf6_route_node_info *
ospf6_route_node_info_new ()
{
  struct ospf6_route_node_info *info;
  info = XMALLOC (MTYPE_OSPF6_ROUTE, sizeof (struct ospf6_route_node_info));
  if (info)
    memset (info, 0, sizeof (struct ospf6_route_node_info));
  return info;
}

static void
ospf6_route_node_info_free (struct ospf6_route_node_info *info)
{
  XFREE (MTYPE_OSPF6_ROUTE, info);
  return;
}

struct ospf6_route_node_info *
ospf6_route_node_info_make ()
{
  struct ospf6_route_node_info *new;
  new = ospf6_route_node_info_new ();
  new->nhlist = list_init ();
  return new;
}

void
ospf6_route_node_info_delete (struct ospf6_route_node_info *info)
{
  listnode n;
  struct ospf6_nexthop *nh;

  /* delete nexthop list */
  for (n = listhead (info->nhlist); n; nextnode (n))
    {
      nh = (struct ospf6_nexthop *) getdata (n);
      nexthop_unlock (nh);
    }
  list_delete_all (info->nhlist);

  /* free */
  ospf6_route_node_info_free (info);
}

struct route_node *
ospf6_route_lookup (struct prefix_ipv6 *dst, struct route_table *table)
{
  return route_node_lookup (table, (struct prefix *)dst);
}

void
ospf6_route_add (struct prefix_ipv6 *dst,
                 struct ospf6_route_node_info *info,
                 struct route_table *table)
{
  struct route_node *node;
  struct ospf6_route_node_info *info_new, *info_current;
  struct ospf6_nexthop *nh;
  listnode n;

  info_new = (struct ospf6_route_node_info *) NULL;
  info_current = (struct ospf6_route_node_info *) NULL;

  /* get current entry. if not exists, make entry in table */
  node = route_node_get (table, (struct prefix *)dst);

  /* get current info entry */
  if (node->info)
    info_current = (struct ospf6_route_node_info *) node->info;

  /* make info_new instance and copy from info */
  info_new = ospf6_route_node_info_make ();
  info_new->dest_type = info->dest_type;
  memcpy (info_new->opt_cap, info->opt_cap, sizeof (info_new->opt_cap));
  info_new->area = info->area;
  info_new->path_type = info->path_type;
  info_new->cost = info->cost;
  info_new->ls_origin = info->ls_origin;
  /* copy nexthop list */
  for (n = listhead (info->nhlist); n; nextnode (n))
    {
      nh = (struct ospf6_nexthop *) getdata (n);
      nexthop_lock (nh);
      list_add_node (info_new->nhlist, nh);
    }

  if (!info_current)
    {
      /* if not installed, simply set info */
      node->info = info_new;
      return;
    }

  /* there's already entry. */

  /* path type preference */
  if (info_new->path_type < info_current->path_type)
    {
      /* replace */
      node->info = info_new;
      ospf6_route_node_info_delete (info_current);
      return;
    }
  else if (info_new->path_type > info_current->path_type)
    {
      /* preferable entry already exists, don't add */
      ospf6_route_node_info_delete (info_new);
      return;
    }

  /* cost preference for the same path type */
  if (info_new->cost < info_current->cost)
    {
      /* replace */
      node->info = info_new;
      ospf6_route_node_info_delete (info_current);
      return;
    }
  else if (info_new->cost > info_current->cost)
    {
      /* preferable entry already exists, don't add */
      ospf6_route_node_info_delete (info_new);
      return;
    }

  /* the same cost, merge nexthops to current entry */
  for (n = listhead (info_new->nhlist); n; nextnode (n))
    {
      nh = (struct ospf6_nexthop *) getdata (n);
      if (list_lookup_node (info_current->nhlist, nh))
        continue;
      nexthop_lock (nh);
      list_add_node (info_current->nhlist, nh);
    }
  ospf6_route_node_info_delete (info_new);

  return;
}

void
ospf6_route_delete (struct prefix_ipv6 *dst,
                    struct ospf6_route_node_info *info,
                    struct route_table *table)
{
  struct route_node *node;
  struct ospf6_route_node_info *info_current;
  struct ospf6_nexthop *nh;
  listnode n;
  char buf[128], routestr[128], nhstr[128];

  /* get current entry. node will be locked */
  node = route_node_get (table, (struct prefix *)dst);
  info_current = (struct ospf6_route_node_info *) node->info;

  /* delete nexthop specified by info */
  if (info_current)
    {
      ospf6_route_str (node, routestr, sizeof (routestr));

      for (n = listhead (info->nhlist); n; nextnode (n))
        {
          nh = (struct ospf6_nexthop *) getdata (n);
          nexthop_str (nh, nhstr, sizeof (nhstr));

          if (list_lookup_node (info_current->nhlist, nh))
            {
              o6log.rtable ("delete nexthop %s from %s", nhstr, routestr);
              list_delete_by_val (info_current->nhlist, nh);
              nexthop_unlock (nh);
            }
          else
            {
              o6log.rtable ("no such nexthop %s in %s", nhstr, routestr);
            }
        }

      /* if all nexthop deleted, delete info */
      if (list_isempty (info_current->nhlist))
        {
          ospf6_route_node_info_delete (info_current);
          node->info = NULL;
        }
    }
  else
    {
      prefix2str ((struct prefix *)dst, buf, sizeof (buf));
      o6log.rtable ("route_delete: no such route %s", buf);
    }

  /* unlock node */
  route_unlock_node (node);

  return;
}

void
ospf6_route_delete_node (struct route_node *node)
{
  struct ospf6_route_node_info *info;
  struct ospf6_nexthop *nh;
  listnode n;

  info = (struct ospf6_route_node_info *) node->info;

  if (info)
    {
      for (n = listhead (info->nhlist); n; nextnode (n))
        {
          nh = (struct ospf6_nexthop *) getdata (n);
          nexthop_unlock (nh);
        }
      list_delete_all (info->nhlist);
      ospf6_route_node_info_free (info);
      node->info = NULL;
    }

  route_unlock_node (node);
}

struct route_table *
ospf6_route_table_init ()
{
  return route_table_init ();
}

void
ospf6_route_table_finish (struct route_table *rt)
{
  struct route_node *rn;
  for (rn = route_top (rt); rn; rn = route_next (rn))
    ospf6_route_delete_node (rn);
  route_table_finish (rt);
}

struct route_table *
ospf6_route_table_clear (struct route_table *table)
{
  struct route_table *new;
  ospf6_route_table_finish (table);
  new = ospf6_route_table_init ();
  return new;
}

void
ospf6_route_set_dst_rtrid (unsigned long rtrid, struct prefix_ipv6 *p)
{
  memcpy(&p->prefix.s6_addr[0], &rtrid, sizeof(rtrid));  /*XXX*/
}

unsigned long 
ospf6_route_get_dst_rtrid (struct prefix_ipv6 *p)
{
  unsigned long x;
  x = *(unsigned long *)&p->prefix.s6_addr[0];
  return x;
}

void
ospf6_route_set_dst_ifid (unsigned long ifid, struct prefix_ipv6 *p)
{
  memcpy(&p->prefix.s6_addr[4], &ifid, sizeof(ifid));  /*XXX*/
}

unsigned long 
ospf6_route_get_dst_ifid (struct prefix_ipv6 *p)
{
  unsigned long x;
  x = *(unsigned long *)&p->prefix.s6_addr[4];
  return x;
}

char *
ospf6_route_str (struct route_node *node, char *buf, size_t bufsize)
{
  char *dtype;
  unsigned long rtrid, ifid;
  char dstr[128], pstr[128], tmp[128];
  struct ospf6_route_node_info *info;

  info = (struct ospf6_route_node_info *) node->info;

  /* destination type, id */
  switch (info->dest_type)
    {
      case DTYPE_PREFIX:
        dtype = "";
        prefix2str (&node->p, dstr, sizeof (dstr));
        break;

      case DTYPE_ASBR:
        dtype = "ASBR";
        rtrid = ospf6_route_get_dst_rtrid ((struct prefix_ipv6 *)&node->p);
        inet_ntop (AF_INET, &rtrid, dstr, sizeof (dstr));
        break;

      case DTYPE_INTRA_ROUTER:
        dtype = "Router";
        rtrid = ospf6_route_get_dst_rtrid ((struct prefix_ipv6 *)&node->p);
        inet_ntop (AF_INET, &rtrid, dstr, sizeof (dstr));
        break;

      case DTYPE_INTRA_LINK:
        dtype = "Link";
        rtrid = ospf6_route_get_dst_rtrid ((struct prefix_ipv6 *)&node->p);
        ifid = ospf6_route_get_dst_ifid ((struct prefix_ipv6 *)&node->p),
        inet_ntop (AF_INET, &rtrid, tmp, sizeof (tmp));
        snprintf (dstr, sizeof (dstr), "%s[%ld]", tmp, 
		  (unsigned long) ntohl (ifid));
        break;

      case DTYPE_STATIC_REDISTRIBUTE:
        dtype = "Static";
        prefix2str (&node->p, dstr, sizeof (dstr));
        break;

      case DTYPE_RIPNG_REDISTRIBUTE:
        dtype = "RIPng";
        prefix2str (&node->p, dstr, sizeof (dstr));
        break;

      case DTYPE_BGP_REDISTRIBUTE:
        dtype = "BGP";
        prefix2str (&node->p, dstr, sizeof (dstr));
        break;

      default:
        dtype = "unknown";
        prefix2str (&node->p, dstr, sizeof (dstr));
        break;
    }

  /* path type */
  ptype_str (info->path_type, pstr, sizeof (pstr));

  if (info->path_type != PTYPE_TYPE1_EXTERNAL &&
      info->path_type != PTYPE_TYPE2_EXTERNAL)
    snprintf (buf, bufsize, "%-38s%s %s:%s %lu",
              dstr, dtype, pstr, info->area->str, info->cost);
  else
    snprintf (buf, bufsize, "%-38s %s %s %lu",
              dstr, dtype, pstr, info->cost);

  return buf;
}

void
ospf6_route_table_vty (struct vty *vty, struct route_node *rn, int detail)
{
  char destination[128], buf[128];
  listnode n;
  struct ospf6_nexthop *nh;
  struct ospf6_route_node_info *info;

  info = (struct ospf6_route_node_info *)rn->info;
  prefix2str (&rn->p, destination, sizeof (destination));

  for (n = listhead (info->nhlist); n; nextnode (n))
    {
      nh = (struct ospf6_nexthop *) getdata (n);
      nexthop_str (nh, buf, sizeof (buf));
      vty_out (vty, "%-38s %-25s%s", destination, buf, VTY_NEWLINE);

      if (!detail)
        continue;

      vty_out (vty, "    %s %s %s %s %lu%s",
               dtype_string[info->dest_type], "xxx",
               info->area->str, ptype_string[info->path_type],
               info->cost, VTY_NEWLINE);

      if (! info->ls_origin)
        continue;
      vty_out (vty, "    Origin: %s Advrtr:%s LS-ID:%lu%s",
               lstype_name[typeindex (info->ls_origin->lsa_hdr->lsh_type)],
               inet_ntop (AF_INET, &info->ls_origin->lsa_hdr->lsh_advrtr,
                          buf, sizeof (buf)),
               (unsigned long) ntohl (info->ls_origin->lsa_hdr->lsh_id));
    }
}

void
ospf6_route_intra_vty (struct vty *vty, struct route_node *rn, int detail)
{
  char destination[64], nexthop[128];
  unsigned long rtrid, ifid;
  listnode n;
  struct ospf6_nexthop *nh;
  struct ospf6_route_node_info *info;

  info = (struct ospf6_route_node_info *)rn->info;
  rtrid = ospf6_route_get_dst_rtrid ((struct prefix_ipv6 *)&rn->p);
  ifid = ntohl (ospf6_route_get_dst_ifid ((struct prefix_ipv6 *)&rn->p));

  inet_ntop (AF_INET, &rtrid, destination, sizeof (destination));

  for (n = listhead (info->nhlist); n; nextnode (n))
    {
      nh = (struct ospf6_nexthop *) getdata (n);
      nexthop_str (nh, nexthop, sizeof (nexthop));
      if (info->dest_type == DTYPE_INTRA_LINK)
        vty_out (vty, "%-11s %-15s[%3lu] %-25s%s",
                 dtype_string[info->dest_type],
                 destination, ifid, nexthop, VTY_NEWLINE);
      else
        vty_out (vty, "%-11s %-20s %25s%s", dtype_string[info->dest_type],
                 destination, nexthop, VTY_NEWLINE);
      if (detail)
        vty_out (vty, "    %s %s %s %lu%s",
                 "xxx", info->area->str,
                 ptype_string[info->path_type],
                 info->cost, VTY_NEWLINE);
    }
}

void
ospf6_route_vty_new (struct vty *vty, struct route_node *rn, int detail)
{
  struct ospf6_route_node_info *info;

  info = (struct ospf6_route_node_info *)rn->info;
  assert (info);

  switch (info->dest_type)
    {
      case DTYPE_PREFIX:
        ospf6_route_table_vty (vty, rn, detail);
        break;
      case DTYPE_ASBR:
      case DTYPE_INTRA_ROUTER:
      case DTYPE_INTRA_LINK:
        ospf6_route_intra_vty (vty, rn, detail);
        break;
      default:
        zlog_warn ("*** unknown destination type");
        break;
    }
}

void
ospf6_route_withdraw_area (struct area *area)
{
  struct route_node *rn;
  struct ospf6_route_node_info *info;

  for (rn = route_top (ospf6->table); rn; rn = route_next (rn))
    {
      info = (struct ospf6_route_node_info *) rn->info;
      if (!info)
        continue;

#if 0
      if (info->path_type == PTYPE_TYPE1_EXTERNAL ||
          info->path_type == PTYPE_TYPE2_EXTERNAL)
        continue;
#endif

      assert (info->area);

      if (info->area == area)
        ospf6_route_delete_node (rn);
    }
}

int
ospf6_route_calc (struct thread *thread)
{
  struct area *area;
  struct route_node *rn, *rn2;
  struct prefix_ipv6 prefix;
  struct ospf6_route_node_info *info, newinfo;
  unsigned short lstype;
  unsigned long lsadvrtr, lsid;
  struct ospf6_lsa *lsa;
  struct intra_area_prefix_lsa *iaplsa;
  struct as_external_lsa *aselsa;
  struct ospf6_prefix *o6p;
  int prefix_count, i;
  list pll; /* prefix LSA list */
  listnode ln;
  char rn_str[128];
  /*  char nh_str[128], dst_str[128]; */

  area = (struct area *) THREAD_ARG (thread);
  assert (area);

  area->route_calc = (struct thread *) NULL;

  area->stat_route_execed++;
  /* log */
  if (IS_OSPF6_DUMP_AREA)
    zlog_info ("Area: route calculation for %s", area->str);

  ospf6_route_withdraw_area (area);

  /* stage 1, for each transit network */
  for (rn = route_top (area->table); rn; rn = route_next (rn))
    {
      info = (struct ospf6_route_node_info *) rn->info;
      if (!info || info->dest_type != DTYPE_INTRA_LINK)
        continue;

      /* log */
      ospf6_route_str (rn, rn_str, sizeof (rn_str));
#if 0
      if (IS_OSPF6_DUMP_ROUTE)
        zlog_info ("  Check %s's route", rn_str);
#endif /*0*/

      /* get prefix LSA */
      lstype = htons (LST_INTRA_AREA_PREFIX_LSA);
      lsid = ospf6_route_get_dst_ifid ((struct prefix_ipv6 *)&rn->p);
      lsadvrtr = ospf6_route_get_dst_rtrid ((struct prefix_ipv6 *)&rn->p);
      lsa = ospf6_lsdb_lookup (lstype, lsid, lsadvrtr, area);
      if (!lsa)
        {
#if 0
          zlog_warn ("  *** can't find prefix LSA for %s", rn_str);
#endif /*0*/
          continue;
        }

      /* check LS reference */
      if (!is_reference_network_ok (lsa, info->ls_origin))
        {
#if 0
          if (IS_OSPF6_DUMP_ROUTE)
            zlog_info ("  !!!Reference to %s failed", rn_str);
#endif
          continue;
        }

      iaplsa = (struct intra_area_prefix_lsa *) (lsa->lsa_hdr + 1);
      prefix_count = ntohs (iaplsa->intra_prefix_num);

      /* for each OSPF6 prefix */
      o6p = (struct ospf6_prefix *) (iaplsa + 1);
      for (i = 0; i < prefix_count; i++)
        {
          /* set prefix destination */
          memset (&prefix, 0, sizeof (prefix));
          prefix.family = AF_INET6;
          ospf6_prefix_in6_addr (o6p, &prefix.prefix);
          prefix.prefixlen = o6p->o6p_prefix_len;

          /* set newinfo */
          memset (&newinfo, 0, sizeof (newinfo));
          newinfo.dest_type = DTYPE_PREFIX;
          newinfo.area = area;
          newinfo.path_type = PTYPE_INTRA;
          newinfo.cost = info->cost + ntohs (o6p->o6p_prefix_metric);
          newinfo.nhlist = info->nhlist;

          /* log */
#if 0
          if (IS_OSPF6_DUMP_ROUTE)
            {
              listnode n;
              struct ospf6_nexthop *nh;

              prefix2str ((struct prefix *)&prefix, dst_str, sizeof (dst_str));
              for (n = listhead (newinfo.nhlist); n; nextnode (n))
                {
                  nh = (struct ospf6_nexthop *) getdata (n);
                  nexthop_str (nh, nh_str, sizeof (nh_str));
                  zlog_info ("    %s %s", dst_str, nh_str);
                }
            }
#endif /*0*/

          /* add ospf6 route table */
          ospf6_route_add (&prefix, &newinfo, ospf6->table);

          o6p = OSPF6_NEXT_PREFIX (o6p);
        }
    }

  /* stage 2, for each reachable router */
  for (rn = route_top (area->table); rn; rn = route_next (rn))
    {
      info = (struct ospf6_route_node_info *) rn->info;
      if (!info)
        continue;
      if (info->dest_type != DTYPE_INTRA_ROUTER &&
          info->dest_type != DTYPE_ASBR)
        continue;

      /* log */
      ospf6_route_str (rn, rn_str, sizeof (rn_str));
#if 0
      if (IS_OSPF6_DUMP_ROUTE)
        zlog_info ("  Check %s's route", rn_str);
#endif /*0*/

      /* get prefix LSA */
      pll = list_init ();
      lstype = htons (LST_INTRA_AREA_PREFIX_LSA);
      lsadvrtr = ospf6_route_get_dst_rtrid ((struct prefix_ipv6 *)&rn->p);
      ospf6_lsdb_collect_type_advrtr (pll, lstype, lsadvrtr, area);
      if (list_isempty (pll))
        {
#if 0
          zlog_warn ("  *** can't find prefix LSA for %s", rn_str);
#endif /*0*/
          continue;
        }

      /* for each prefix LSA */
      for (ln = listhead (pll); ln; nextnode (ln))
        {
          lsa = (struct ospf6_lsa *) getdata (ln);
          iaplsa = (struct intra_area_prefix_lsa *) (lsa->lsa_hdr + 1);
          prefix_count = ntohs (iaplsa->intra_prefix_num);

          /* check LS reference */
          if (!is_reference_router_ok (lsa, info->ls_origin))
            {
#if 0
              if (IS_OSPF6_DUMP_ROUTE)
                zlog_info ("  !!!Reference to %s failed", rn_str);
#endif
              continue;
            }

          /* for each OSPF6 prefix */
          o6p = (struct ospf6_prefix *) (iaplsa + 1);
          for (i = 0; i < prefix_count; i++)
            {
              /* set prefix destination */
              memset (&prefix, 0, sizeof (prefix));
              prefix.family = AF_INET6;
              ospf6_prefix_in6_addr (o6p, &prefix.prefix);
              prefix.prefixlen = o6p->o6p_prefix_len;

              /* set newinfo */
              memset (&newinfo, 0, sizeof (newinfo));
              newinfo.dest_type = DTYPE_PREFIX;
              newinfo.area = area;
              newinfo.path_type = PTYPE_INTRA;
              newinfo.cost = info->cost + ntohs (o6p->o6p_prefix_metric);
              newinfo.nhlist = info->nhlist;

              /* log */
#if 0
              if (IS_OSPF6_DUMP_ROUTE)
                {
                  listnode n;
                  struct ospf6_nexthop *nh;

                  prefix2str ((struct prefix *)&prefix,
                              dst_str, sizeof (dst_str));
                  for (n = listhead (newinfo.nhlist); n; nextnode (n))
                    {
                      nh = (struct ospf6_nexthop *) getdata (n);
                      nexthop_str (nh, nh_str, sizeof (nh_str));
                      zlog_info ("    %s %s", dst_str, nh_str);
                    }
                }
#endif /*0*/

              /* add ospf6 route table */
              ospf6_route_add (&prefix, &newinfo, ospf6->table);

              o6p = OSPF6_NEXT_PREFIX (o6p);
            }
        }
      list_delete_all (pll);
    }

  /* inter area route */
  /* xxx */

  /* AS external route */
  for (rn = route_top (area->table); rn; rn = route_next (rn))
    {
      info = (struct ospf6_route_node_info *) rn->info;
      if (!info || info->dest_type != DTYPE_ASBR)
        continue;

      /* log */
      ospf6_route_str (rn, rn_str, sizeof (rn_str));
#if 0
      if (IS_OSPF6_DUMP_ROUTE)
        zlog_info ("  Check %s's route", rn_str);
#endif /*0*/

      /* get external LSAs */
      pll = list_init ();
      lstype = htons (LST_AS_EXTERNAL_LSA);
      lsadvrtr = ospf6_route_get_dst_rtrid ((struct prefix_ipv6 *)&rn->p);
      ospf6_lsdb_collect_type_advrtr (pll, lstype, lsadvrtr, ospf6);
      if (list_isempty (pll))
        {
#if 0
          zlog_warn ("  *** can't find external LSA for %s", rn_str);
#endif /*0*/
          list_delete_all (pll);
          continue;
        }

      /* for each prefix LSA */
      for (ln = listhead (pll); ln; nextnode (ln))
        {
          lsa = (struct ospf6_lsa *) getdata (ln);
          aselsa = (struct as_external_lsa *) (lsa->lsa_hdr + 1);

          /* point OSPF6 prefix */
          o6p = (struct ospf6_prefix *) (&aselsa->ase_prefix_len);

          /* set prefix destination */
          memset (&prefix, 0, sizeof (prefix));
          prefix.family = AF_INET6;
          ospf6_prefix_in6_addr (o6p, &prefix.prefix);
          prefix.prefixlen = o6p->o6p_prefix_len;

          /* XXX must be reviewed XXX */
          rn2 = route_node_lookup (ospf6->redistribute_map,
                                   (struct prefix *)&prefix);
          if (rn2)
            {
              if (! rn2->info)
                zlog_info (" **********Mulformed********** ");
              /* if route_node_lookup succeeded, router itself
                 already have the route, ignore. */
              route_unlock_node (rn2);
              rn2 = NULL;
              continue;
            }

          /* set newinfo */
          memset (&newinfo, 0, sizeof (newinfo));
          newinfo.dest_type = DTYPE_PREFIX;
          newinfo.area = area;
          if (!ASE_LSA_ISSET (aselsa, ASE_LSA_BIT_E))
            {
              newinfo.path_type = PTYPE_TYPE1_EXTERNAL;
              newinfo.cost = info->cost + ntohs (aselsa->ase_metric);
            }
          else
            {
              newinfo.path_type = PTYPE_TYPE2_EXTERNAL;
              newinfo.cost = ntohs (aselsa->ase_metric);
            }
          newinfo.nhlist = info->nhlist;

          /* log */
#if 0
          if (IS_OSPF6_DUMP_ROUTE)
            {
              listnode n;
              struct ospf6_nexthop *nh;

              prefix2str ((struct prefix *)&prefix, dst_str,
                          sizeof (dst_str));
              for (n = listhead (newinfo.nhlist); n; nextnode (n))
                {
                  nh = (struct ospf6_nexthop *) getdata (n);
                  nexthop_str (nh, nh_str, sizeof (nh_str));
                  zlog_info ("    %s %s", dst_str, nh_str);
                }
            }
#endif /*0*/

          /* add ospf6 route table */
          ospf6_route_add (&prefix, &newinfo, ospf6->table);
        }
      list_delete_all (pll);
    }

  ospf6_route_update_zebra ();

  return 0;
}

void
ospf6_route_update_zebra ()
{
  struct route_node *rn1, *rn2;
  struct ospf6_route_node_info *info1, *info2, infoq;
  struct ospf6_nexthop *nh;
  listnode n;
  list nhdiff;

  /* deleted routes update */
  for (rn1 = route_top (ospf6->table_zebra); rn1; rn1 = route_next (rn1))
    {
      if (!rn1->info)
        continue;

      /* get current entry */
      rn2 = ospf6_route_lookup ((struct prefix_ipv6 *)&rn1->p, ospf6->table);

      /* if there is no entry for this route currently, delete all */
      if (!rn2 || !rn2->info)
        {
          ospf6_zebra_route_delete ((struct prefix_ipv6 *)&rn1->p,
                                    rn1->info);
          continue;
        }

      /* diff nexthop */
      info1 = (struct ospf6_route_node_info *) rn1->info;
      info2 = (struct ospf6_route_node_info *) rn2->info;
      nhdiff = list_init ();
      for (n = listhead (info1->nhlist); n; nextnode (n))
        {
          nh = (struct ospf6_nexthop *) getdata (n);
          if (!list_lookup_node (info2->nhlist, nh))
            list_add_node (nhdiff, nh);
        }

      if (listcount (nhdiff))
        {
          /* delete differences */
          memset (&infoq, 0, sizeof (infoq));
          infoq.dest_type = info1->dest_type;
          infoq.path_type = info1->path_type;
          infoq.cost = info1->cost;
          infoq.nhlist = nhdiff;
          ospf6_zebra_route_delete ((struct prefix_ipv6 *)&rn1->p, &infoq);
        }

      list_delete_all (nhdiff);
    }

  /* added routes update */
  for (rn1 = route_top (ospf6->table); rn1; rn1 = route_next (rn1))
    {
      if (!rn1->info)
        continue;

      /* get previous entry */
      rn2 = ospf6_route_lookup ((struct prefix_ipv6 *)&rn1->p,
                                ospf6->table_zebra);

      /* if there is no entry for this route previously, add all */
      if (!rn2 || !rn2->info)
        {
          ospf6_zebra_route_add ((struct prefix_ipv6 *)&rn1->p, rn1->info);
          continue;
        }

      /* diff nexthop */
      info1 = (struct ospf6_route_node_info *) rn1->info;
      info2 = (struct ospf6_route_node_info *) rn2->info;
      nhdiff = list_init ();
      for (n = listhead (info1->nhlist); n; nextnode (n))
        {
          nh = (struct ospf6_nexthop *) getdata (n);
          if (!list_lookup_node (info2->nhlist, nh))
            list_add_node (nhdiff, nh);
        }

      if (listcount (nhdiff))
        {
          /* add differences */
          memset (&infoq, 0, sizeof (infoq));
          infoq.dest_type = info1->dest_type;
          infoq.path_type = info1->path_type;
          infoq.cost = info1->cost;
          infoq.nhlist = nhdiff;
          ospf6_zebra_route_add ((struct prefix_ipv6 *)&rn1->p, &infoq);
        }

      list_delete_all (nhdiff);
    }
}


DEFUN (show_ipv6_route_ospf6_area_detail,
       show_ipv6_route_ospf6_area_detail_cmd,
       "show ipv6 route ospf6 area A.B.C.D (detail|)",
       SHOW_STR
       IP6_STR
       ROUTE_STR
       OSPF6_STR
       "show route table in area structure\n"
       "OSPF6 area ID\n"
       "detailed infomation\n"
       )
{
  struct area *area;
  area_id_t area_id;
  struct route_node *rn;

  if (!ospf6)
    {
      vty_out (vty, "OSPF6 not started%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (argc && strncmp (argv[0], "d", 1) != 0)
    inet_pton (AF_INET, argv[0], &area_id);
  else
    area_id = 0;

  area = ospf6_area_lookup (area_id);
  if (!area)
    {
       vty_out (vty, "no match by area id: %s%s", argv[0],
		VTY_NEWLINE);
       return CMD_WARNING;
    }

  for (rn = route_top (area->table); rn; rn = route_next (rn))
    {
      if (rn->info)
        {
          if (strncmp (argv[argc-1], "detail", 7) == 0)
            ospf6_route_vty_new (vty, rn, 1);
          else
            ospf6_route_vty_new (vty, rn, 0);
        }
    }

  return CMD_SUCCESS;
}

ALIAS (show_ipv6_route_ospf6_area_detail,
       show_ipv6_route_ospf6_area_cmd,
       "show ipv6 route ospf6 area A.B.C.D",
       SHOW_STR
       IP6_STR
       ROUTE_STR
       OSPF6_STR
       "show route table in area structure\n"
       "OSPF6 area ID\n"
       )

ALIAS (show_ipv6_route_ospf6_area_detail,
       show_ipv6_route_ospf6_backbone_detail_cmd,
       "show ipv6 route ospf6 backbone (detail|)",
       SHOW_STR
       IP6_STR
       ROUTE_STR
       OSPF6_STR
       "show route table in area structure\n"
       "detailed infomation\n"
       )

ALIAS (show_ipv6_route_ospf6_area_detail,
       show_ipv6_route_ospf6_backbone_cmd,
       "show ipv6 route ospf6 backbone",
       SHOW_STR
       IP6_STR
       ROUTE_STR
       OSPF6_STR
       "show route table in area structure\n"
       )

DEFUN (show_ipv6_route_ospf6_detail,
       show_ipv6_route_ospf6_detail_cmd,
       "show ipv6 route ospf6 (detail|)",
       SHOW_STR
       IP6_STR
       ROUTE_STR
       OSPF6_STR
       "detailed infomation\n"
       )
{
  struct route_node *rn;
  int i, ret, detail;
  struct prefix p;

  ret = 0;
  detail = 0;

  if (!ospf6)
    {
      vty_out (vty, "OSPF6 not started%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  for (i = 0; i < argc; i++)
    {
      if (strncmp (argv[argc-1], "detail", 7) == 0)
        {
          detail = 1;
          continue;
        }

      ret = str2prefix_ipv6 (argv[i], (struct prefix_ipv6 *) &p);
      if (ret != 1)
        continue;
    }

  if (ret)
    {
      rn = route_node_match (ospf6->table, &p);
      if (rn && rn->info)
        {
          ospf6_route_vty_new (vty, rn, 1);
          route_unlock_node (rn);
        }
      else
        vty_out (vty, "Route not found.%s", VTY_NEWLINE);
      return CMD_SUCCESS;
    }

  for (rn = route_top (ospf6->table); rn; rn = route_next (rn))
    {
      if (! rn->info)
        continue;

      ospf6_route_vty_new (vty, rn, detail);
    }

  return CMD_SUCCESS;
}

ALIAS (show_ipv6_route_ospf6_detail,
       show_ipv6_route_ospf6_cmd,
       "show ipv6 route ospf6",
       SHOW_STR
       IP6_STR
       ROUTE_STR
       OSPF6_STR
       )

ALIAS (show_ipv6_route_ospf6_detail,
       show_ipv6_route_ospf6_prefix_cmd,
       "show ipv6 route ospf6 X::X",
       SHOW_STR
       IP6_STR
       ROUTE_STR
       OSPF6_STR
       "IPv6 Address search\n"
       )

void
ospf6_rtable_init ()
{
  install_element (VIEW_NODE, &show_ipv6_route_ospf6_cmd);
  install_element (VIEW_NODE, &show_ipv6_route_ospf6_prefix_cmd);
  install_element (VIEW_NODE, &show_ipv6_route_ospf6_detail_cmd);
  install_element (VIEW_NODE, &show_ipv6_route_ospf6_area_cmd);
  install_element (VIEW_NODE, &show_ipv6_route_ospf6_area_detail_cmd);
  install_element (VIEW_NODE, &show_ipv6_route_ospf6_backbone_cmd);
  install_element (VIEW_NODE, &show_ipv6_route_ospf6_backbone_detail_cmd);

  install_element (ENABLE_NODE, &show_ipv6_route_ospf6_cmd);
  install_element (ENABLE_NODE, &show_ipv6_route_ospf6_prefix_cmd);
  install_element (ENABLE_NODE, &show_ipv6_route_ospf6_detail_cmd);
  install_element (ENABLE_NODE, &show_ipv6_route_ospf6_area_cmd);
  install_element (ENABLE_NODE, &show_ipv6_route_ospf6_area_detail_cmd);
  install_element (ENABLE_NODE, &show_ipv6_route_ospf6_backbone_cmd);
  install_element (ENABLE_NODE, &show_ipv6_route_ospf6_backbone_detail_cmd);
}


