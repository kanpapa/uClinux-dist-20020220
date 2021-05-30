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

#include "ospf6d.h"

static void
print_vertex (struct vertex *W)
{
  o6log.spf (" vtx %s[%lu]", inet4str (W->vtx_id[0]), W->vtx_id[1]);
}

static struct vertex *
make_vertex (struct ospf6_lsa *lsa)
{
  struct vertex *v;
  char buf[128];

  assert (lsa && lsa->lsa_hdr);

  v = (struct vertex *) XMALLOC (MTYPE_OSPF6_VERTEX,
                                 sizeof (struct vertex));
  assert (v);

  switch (ntohs (lsa->lsa_hdr->lsh_type))
    {
    case LST_ROUTER_LSA:
      v->vtx_id[0] = lsa->lsa_hdr->lsh_advrtr;
      v->vtx_id[1] = 0;
      break;
    case LST_NETWORK_LSA:
      v->vtx_id[0] = lsa->lsa_hdr->lsh_advrtr;
      v->vtx_id[1] = lsa->lsa_hdr->lsh_id;
      break;
    default:
      return (struct vertex *)NULL;
    }

  /* Identifier String */
  snprintf (v->str, sizeof (v->str), "%s[%lu]",
            inet_ntop (AF_INET, &v->vtx_id[0], buf, sizeof (buf)),
            (unsigned long) ntohl (v->vtx_id[1]));

  v->vtx_lsa = lsa;
  v->vtx_nexthops = list_init ();
  v->vtx_distance = 0;
  v->vtx_path = list_init ();
  v->vtx_parent = list_init ();
  v->vtx_depth = 0;

  return v;
}

static int
vertex_free (struct vertex *v)
{

  list_delete_all (v->vtx_nexthops);
  list_delete_all (v->vtx_path);
  list_delete_all (v->vtx_parent);

  XFREE (MTYPE_OSPF6_ROUTE, v);
  return 0;
}

/* hold the intermediate results on area routing table */
static void
transit_vertex_rtable_install (struct vertex *v, struct area *area)
{
  unsigned char dtype;

  /* new, still bit messy */
  {
    struct prefix_ipv6 prefix;
    struct ospf6_route_node_info info;

    memset (&prefix, 0, sizeof (prefix));
    prefix.family = AF_INET6;

    /* set router id */
    ospf6_route_set_dst_rtrid (v->vtx_id[0], &prefix);

    if (IS_VTX_ROUTER_TYPE (v))
      {
        struct router_lsa *rlsa;
        /* check for E bit of router lsa */
        rlsa = (struct router_lsa *) (v->vtx_lsa->lsa_hdr + 1);
        if (ROUTER_LSA_ISSET (rlsa, ROUTER_LSA_BIT_E))
          dtype = DTYPE_ASBR;
        else
          dtype = DTYPE_INTRA_ROUTER;

        /* set prefixlen to 32 (exact route-id length) */
        prefix.prefixlen = 32;
      }
    else if (IS_VTX_NETWORK_TYPE (v))
      {
        dtype = DTYPE_INTRA_LINK;
        ospf6_route_set_dst_ifid (v->vtx_id[1], &prefix);
        /* set prefixlen to 64 (route-id + if-id length) */
        prefix.prefixlen = 64;
      }
    else
      {
        zlog_warn ("*** unkown vertex type");
        assert (0);
      }

    /* set info */
    memset (&info, 0, sizeof (info));
    info.dest_type = dtype;
    info.area = area;
    info.path_type = PTYPE_INTRA;
    info.cost = v->vtx_distance;
    info.nhlist = v->vtx_nexthops;
    info.ls_origin = v->vtx_lsa;

    /* add area table */
    ospf6_route_add (&prefix, &info, area->table);
  }

}

static int
spf_install (struct vertex *v, struct area *area)
{
  listnode n;
  struct vertex *parent;

  if (IS_OSPF6_DUMP_SPF)
    {
      zlog_info ("SPF Install: Depth:%lu Distance%lu",
                 v->vtx_depth, v->vtx_distance);
      zlog_info ("  %s[%lu]", inet4str (v->vtx_id[0]), ntohl (v->vtx_id[1]));
    }

  if (v->vtx_depth == 0)
    area->spftree.root = v;

  for (n = listhead (v->vtx_parent); n; nextnode (n))
    {
      parent = getdata (n);
      list_add_node (parent->vtx_path, v);
      nexthop_add_from_vertex (v, parent, v->vtx_nexthops);
    }

  list_add_node (area->spftree.searchlist[hash (v->vtx_id[0])]
                                         [hash (v->vtx_id[1])], v);
  list_add_node (area->spftree.depthlist [v->vtx_depth], v);

  if (v->vtx_depth != 0) /* don't install root to routing table */
    transit_vertex_rtable_install (v, area);

  return 0;
}

static int
spf_init (struct area *area)
{
  int i, j;
  listnode n;
  struct vertex *v;
  struct ospf6_lsa *myself;

  area->table = ospf6_route_table_clear (area->table);

  /* Clear search list */
  for (i = 0; i < HASHVAL; i++)
    {
      for (j = 0; j < HASHVAL; j++)
        {
          if (area->spftree.searchlist[i][j] == NULL)
            area->spftree.searchlist[i][j] = list_init();

          while (listcount (area->spftree.searchlist[i][j]))
            {
              n = listhead (area->spftree.searchlist[i][j]);
              v = (struct vertex *)getdata (n);
              vertex_free (v);
              list_delete_node (area->spftree.searchlist[i][j], n);
            }
        }
    }

  /* Clear depth list */
  for (i = 0; i < MAXDEPTH; i++)
    {
      if (area->spftree.depthlist[i] == NULL)
        area->spftree.depthlist[i] = list_init();

      while (listcount (area->spftree.depthlist[i]))
        {
          list_delete_node (area->spftree.depthlist[i],
          listhead (area->spftree.depthlist[i]));
        }
    }

  /* Install myself as root */
  myself = ospf6_lsdb_lookup (htons (LST_ROUTER_LSA), htonl (MY_ROUTER_LSA_ID),
                              area->ospf6->router_id, (void *) area);
  if (!myself)
    {
      if (IS_OSPF6_DUMP_SPF)
        zlog_warn (" *** Router-LSA of myself not found");
      return -1;
    }

  v = make_vertex (myself);
  v->vtx_distance = 0;
  v->vtx_depth = 0;

  spf_install (v, area);

  return 0;
}

static struct vertex *
router_link (struct vertex *V)
{
  static struct router_lsd *currentlink;
  static struct ospf6_lsa *lsa;

  struct ospf6_lsa *w_lsa;
  void *end;
  rtr_id_t *attachedrtr;
  struct router_lsd *rlsd;
  int linkback;
  struct vertex *W;

  assert (V);
  if (V->vtx_lsa != lsa)
    {
      lsa = V->vtx_lsa;
      currentlink = (struct router_lsd *)
                     ((struct router_lsa *)(lsa->lsa_hdr + 1) + 1);
    }
  end = (char *)lsa->lsa_hdr + ntohs (lsa->lsa_hdr->lsh_len);

 nextlink:

  if (currentlink == end)
    {
      lsa = (struct ospf6_lsa *)NULL;
      return (struct vertex *)NULL;
    }

  linkback = 0;
  switch (currentlink->rlsd_type)
    {
    case LSDT_TRANSIT_NETWORK:
      w_lsa = ospf6_lsdb_lookup (htons (LST_NETWORK_LSA),
                                 currentlink->rlsd_neighbor_interface_id,
                                 currentlink->rlsd_neighbor_router_id,
                                 (void *)lsa->scope);
      if (!w_lsa || !w_lsa->lsa_hdr || ospf6_age_current (w_lsa) == MAXAGE)
        {
          currentlink++;
          goto nextlink;
        }

      /* Examin if this LSA have link back to V */
      for (attachedrtr = (rtr_id_t *)
                           (((struct network_lsa *)(w_lsa->lsa_hdr + 1)) + 1);
           (char *)attachedrtr < (char *)w_lsa->lsa_hdr +
                           ntohs (w_lsa->lsa_hdr->lsh_len);
           attachedrtr++)
        {
          if (*attachedrtr == lsa->lsa_hdr->lsh_advrtr)
          linkback++;
        }
      if (linkback == 0)
        {
          currentlink++;
          goto nextlink;
        }

      W = make_vertex(w_lsa);
      assert (W);
      W->vtx_distance = V->vtx_distance + ntohs (currentlink->rlsd_metric);
      list_add_node (W->vtx_parent, V);
      W->vtx_depth = V->vtx_depth + 1;

      currentlink++;
      return W;

    case LSDT_POINTTOPOINT:
      /* XXX multiple RouterLSA not yet */
      w_lsa = ospf6_lsdb_lookup (htons (LST_ROUTER_LSA),
                                 htonl (MY_ROUTER_LSA_ID),
                                 currentlink->rlsd_neighbor_router_id,
                                 (void *)lsa->scope);
      if (!w_lsa || !w_lsa->lsa_hdr
          || ospf6_age_current (w_lsa) == MAXAGE)
        {
          currentlink++;
          goto nextlink;
        }
      /* Examin if this LSA have link back to V */
      for (rlsd = (struct router_lsd *)
                    (((struct router_lsa *)(w_lsa->lsa_hdr + 1)) + 1);
           (char *)rlsd < (char *)w_lsa->lsa_hdr
                                  + ntohs (w_lsa->lsa_hdr->lsh_len);
           rlsd++)
        {
          /* XXX Should we check rlsd_neighbor_interface_id, too? */
          if (rlsd->rlsd_type == LSDT_POINTTOPOINT &&
              rlsd->rlsd_neighbor_router_id == lsa->lsa_hdr->lsh_advrtr)
            {
              linkback++;
              break;
            }
        }
      if (linkback == 0)
        {
          currentlink++;
          goto nextlink;
        }

      W = make_vertex(w_lsa);
      assert (W);
      W->vtx_distance = V->vtx_distance + ntohs (currentlink->rlsd_metric);
      list_add_node (W->vtx_parent, V);
      W->vtx_depth = V->vtx_depth + 1;

      currentlink++;
      return W;

    default:
      zlog_warn ("*** unknown link type, stop calculation for area %s",
                 ((struct area *)(V->vtx_lsa->scope))->str);
      lsa = (struct ospf6_lsa *)NULL;
      return (struct vertex *)NULL;
    }
}

static struct vertex *
network_link (struct vertex *V)
{
  static rtr_id_t *currentlink;
  static struct ospf6_lsa *lsa;

  struct ospf6_lsa *w_lsa;
  void *end;
  struct router_lsd *rlsd;
  int linkback;
  struct vertex *W;

  assert (V);
  if (V->vtx_lsa != lsa)
    {
      lsa = V->vtx_lsa;
      currentlink = (rtr_id_t *)((struct network_lsa *)(lsa->lsa_hdr + 1) + 1);
    }
  end = (char *)lsa->lsa_hdr + ntohs (lsa->lsa_hdr->lsh_len);

 nextlink_of_this_network:

  if (currentlink == end)
    {
      lsa = (struct ospf6_lsa *)NULL;
      return (struct vertex *)NULL;
    }

  linkback = 0;
  w_lsa = ospf6_lsdb_lookup (htons (LST_ROUTER_LSA),
                             htonl (MY_ROUTER_LSA_ID),
                             *currentlink, lsa->scope);
  if (!w_lsa || !w_lsa->lsa_hdr || ospf6_age_current (w_lsa) == MAXAGE)
    {
      currentlink++;
      goto nextlink_of_this_network;
    }
  /* Examin if this LSA have link back to V */
  for (rlsd = (struct router_lsd *)
                (((struct router_lsa *)(w_lsa->lsa_hdr + 1)) + 1);
       (char *)rlsd < (char *)w_lsa->lsa_hdr + ntohs (w_lsa->lsa_hdr->lsh_len);
       rlsd++)
    {
      if (rlsd->rlsd_type == LSDT_TRANSIT_NETWORK &&
          rlsd->rlsd_neighbor_router_id == lsa->lsa_hdr->lsh_advrtr &&
          rlsd->rlsd_neighbor_interface_id == lsa->lsa_hdr->lsh_id)
        {
          linkback++;
          break;
        }
    }
  if (linkback == 0)
    {
      currentlink++;
      goto nextlink_of_this_network;
    }

  W = make_vertex(w_lsa);
  assert (W);
  W->vtx_distance = V->vtx_distance + 0;
  list_add_node (W->vtx_parent, V);
  W->vtx_depth = V->vtx_depth + 1;

  currentlink++;
  return W;
}

struct vertex *
linktovertex (struct vertex *V)
{
  assert (V);
  switch (ntohs (V->vtx_lsa->lsa_hdr->lsh_type))
    {
    case LST_ROUTER_LSA:
      return router_link (V);
    case LST_NETWORK_LSA:
      return network_link (V);
    default:
      break;
    }
  return (struct vertex *)NULL;
}

/* should be added to linklist.c */
void
spf_list_add_list (list l, list m)
{
  listnode n;

  for (n = listhead (m); n; nextnode (n))
    list_add_node (l, getdata (n));

  return;
}

/* RFC2328 section 16.1 */
int
spf_calculation (struct thread *thread)
{
  listnode n;
  struct area *area;

  list candidatelist;
  struct vertex *V, *W, *p, *closest;
  int already;

  area = (struct area *)THREAD_ARG (thread);
  assert (area);

  area->spf_calc = (struct thread *)NULL;

  area->stat_spf_execed++;
  if (IS_OSPF6_DUMP_SPF)
    zlog_info ("SPF Calculation for area %s", area->str);

  /* (1) */
  if (spf_init (area) < 0)
    return -1;
  candidatelist = list_init ();
  V = area->spftree.root;             /* Myself */

  /* (2) */
  while (1)
    {
      for (W = linktovertex (V); W; W = linktovertex (V))     /* (b) */
        {
          print_vertex (W);

          already = 0;
          /* (c) */
          for (n = listhead (area->spftree.searchlist
                             [hash(W->vtx_id[0])][hash(W->vtx_id[1])]);
               n;
               nextnode (n))
            {
              p = getdata (n);
              if (p->vtx_id[0] == W->vtx_id[0] &&
                  p->vtx_id[1] == W->vtx_id[1])
                already++;
            }
          if (already)
            {
              vertex_free (W);
              continue;
            }

          /* (d) */
          for (n = listhead (candidatelist);
               n;
               nextnode (n))
            {
              p = getdata (n);
              if (p->vtx_id[0] == W->vtx_id[0] &&
                  p->vtx_id[1] == W->vtx_id[1])
                {
                  if (p->vtx_distance < W->vtx_distance)
                    {
                      vertex_free (W);
                      goto not_candidate;
                    }
                  if (p->vtx_distance > W->vtx_distance)
                    {
                      list_delete_by_val (candidatelist, p);
                      break;
                    }
                  if (p->vtx_distance == W->vtx_distance)
                    {
                      if (IS_OSPF6_DUMP_SPF)
                        {
                          zlog_info ("SPF MultiPath found:");
                          zlog_info ("  merge %s's parent to %s's",
                                     W->str, p->str);
                        }

                      /* This is ECMP */
                      spf_list_add_list (p->vtx_parent, W->vtx_parent);
                      vertex_free (W);
                      goto not_candidate;
                    }
                }
            }
          list_add_node (candidatelist, W);

        not_candidate:
        }

      /* (3) */
      if (listcount (candidatelist) == 0)
        break;

      closest = (struct vertex *)NULL;
      for (n = listhead (candidatelist);
           n;
           nextnode (n))
        {
          p = getdata (n);
          if (!closest || p->vtx_distance < closest->vtx_distance)
            closest = p;
          else if (p->vtx_distance == closest->vtx_distance &&
                   IS_VTX_ROUTER_TYPE (closest))
            closest = p;
        }
      list_delete_by_val (candidatelist, closest);
      spf_install (closest, area);
      V = closest;
    }

  assert (listcount (candidatelist) == 0);
  list_free (candidatelist);

  if (IS_OSPF6_DUMP_SPF)
    zlog_info ("SPF Calculation for area %s done", area->str);
  return 0;
}

