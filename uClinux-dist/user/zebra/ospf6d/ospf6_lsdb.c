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

int
lsa_change (struct ospf6_lsa *lsa)
{
  struct area *area;
  struct ospf6_interface *o6if;
  struct ospf6 *ospf6;

  switch (ntohs (lsa->lsa_hdr->lsh_type))
    {
    case LST_ROUTER_LSA:
    case LST_NETWORK_LSA:
      area = (struct area *)lsa->scope;
      if (area->spf_calc == (struct thread *)NULL)
        area->spf_calc = thread_add_event (master, spf_calculation,
                                           area, 0);
      if (area->route_calc == (struct thread *)NULL)
        area->route_calc = thread_add_event (master, ospf6_route_calc,
                                             area, 0);
      break;
    case LST_LINK_LSA:
      o6if = (struct ospf6_interface *)lsa->scope;
      area = (struct area *) o6if->area;
      if (area->spf_calc == (struct thread *)NULL)
        area->spf_calc = thread_add_event (master, spf_calculation,
                                           area, 0);
      if (area->route_calc == (struct thread *)NULL)
        area->route_calc = thread_add_event (master, ospf6_route_calc,
                                             area, 0);
      break;
    case LST_INTRA_AREA_PREFIX_LSA:
      area = (struct area *)lsa->scope;
      if (area->route_calc == (struct thread *)NULL)
        area->route_calc = thread_add_event (master, ospf6_route_calc,
                                             area, 0);
      break;
    case LST_AS_EXTERNAL_LSA:
      ospf6 = (struct ospf6 *)lsa->scope;
      area = (struct area *)ospf6->area_list->head->data;
      if (area->route_calc == (struct thread *)NULL)
        area->route_calc = thread_add_event (master, ospf6_route_calc,
                                             area, 0);
      break;
    default:
      break;
    }

  return 0;
}

struct ospf6_lsa_hdr *
attach_lsa_to_iov (struct ospf6_lsa *lsa, struct iovec *iov)
{
  assert (lsa && lsa->lsa_hdr);

  return ((struct ospf6_lsa_hdr *)
          iov_attach_last (iov, lsa->lsa_hdr,
                           ntohs (lsa->lsa_hdr->lsh_len)));
}

struct ospf6_lsa_hdr *
attach_lsa_hdr_to_iov (struct ospf6_lsa *lsa, struct iovec *iov)
{
  assert (lsa && lsa->lsa_hdr);

  return ((struct ospf6_lsa_hdr *)
          iov_attach_last (iov, lsa->lsa_hdr,
                           sizeof (struct ospf6_lsa_hdr)));
}


/* lookup lsa on summary list of neighbor */
struct ospf6_lsa *
ospf6_lookup_summary (struct ospf6_lsa *lsa, struct neighbor *nbr)
{
  if (list_lookup_node (nbr->summarylist, lsa))
    {
#ifndef NDEBUG
      if (!list_lookup_node (lsa->summary_nbr, nbr))
        assert (0);
#endif /* NDEBUG */
      return lsa;
    }
  return NULL;
}

/* add lsa to summary list of neighbor */
void
ospf6_add_summary (struct ospf6_lsa *lsa, struct neighbor *nbr)
{
  if (ospf6_lookup_summary (lsa, nbr))
    return;

  list_add_node (nbr->summarylist, lsa);
  list_add_node (lsa->summary_nbr, nbr);
  ospf6_lsa_lock (lsa);
  return;
}

/* remove lsa from summary list of neighbor */
void
ospf6_remove_summary (struct ospf6_lsa *lsa, struct neighbor *nbr)
{
  if (!ospf6_lookup_summary (lsa, nbr))
    return;

  list_delete_by_val (nbr->summarylist, lsa);
  list_delete_by_val (lsa->summary_nbr, nbr);
  ospf6_lsa_unlock (lsa);
  return;
}

/* remove all lsa from summary list of neighbor */
void
ospf6_remove_summary_all (struct neighbor *nbr)
{
  struct ospf6_lsa *lsa;
  listnode n;
  while (listcount (nbr->summarylist))
    {
      n = listhead (nbr->summarylist);
      lsa = (struct ospf6_lsa *) getdata (n);
      ospf6_remove_summary (lsa, nbr);
    }
  return;
}

/* lookup lsa on request list of neighbor */
  /* this lookup is different from others, because this lookup is to find
     the same LSA instance of different memory space */
struct ospf6_lsa *
ospf6_lookup_request (struct ospf6_lsa *lsa, struct neighbor *nbr)
{
  listnode n;
  struct ospf6_lsa *p;

  for (n = listhead (nbr->requestlist); n; nextnode (n))
    {
      p = (struct ospf6_lsa *) getdata (n);
      if (ospf6_lsa_issame (p->lsa_hdr, lsa->lsa_hdr))
        {
#ifndef NDEBUG
          if (!list_lookup_node (p->request_nbr, nbr))
          assert (0);
#endif /* NDEBUG */
          return p;
        }
    }
  return NULL;
}

/* add lsa to request list of neighbor */
void
ospf6_add_request (struct ospf6_lsa *lsa, struct neighbor *nbr)
{
  if (ospf6_lookup_request (lsa, nbr))
    return;

  list_add_node (nbr->requestlist, lsa);
  list_add_node (lsa->request_nbr, nbr);
  ospf6_lsa_lock (lsa);
  return;
}

/* remove lsa from request list of neighbor */
void
ospf6_remove_request (struct ospf6_lsa *lsa, struct neighbor *nbr)
{
  if (!ospf6_lookup_request (lsa, nbr))
    return;

  list_delete_by_val (nbr->requestlist, lsa);
  list_delete_by_val (lsa->request_nbr, nbr);
  ospf6_lsa_unlock (lsa);
  return;
}

/* remove all lsa from request list of neighbor */
void
ospf6_remove_request_all (struct neighbor *nbr)
{
  listnode n;
  struct ospf6_lsa *lsa;
  while (listcount (nbr->requestlist))
    {
      n = listhead (nbr->requestlist);
      lsa = (struct ospf6_lsa *) getdata (n);
      ospf6_remove_request (lsa, nbr);
    }
  return;
}

/* lookup lsa on retrans list of neighbor */
struct ospf6_lsa *
ospf6_lookup_retrans (struct ospf6_lsa *lsa, struct neighbor *nbr)
{
  if (list_lookup_node (nbr->retranslist, lsa))
    {
#ifndef NDEBUG
      if (!list_lookup_node (lsa->retrans_nbr, nbr))
        assert (0);
#endif /* NDEBUG */
      return lsa;
    }
  return NULL;
}

/* add lsa to retrans list of neighbor */
void
ospf6_add_retrans (struct ospf6_lsa *lsa, struct neighbor *nbr)
{
  if (ospf6_lookup_retrans (lsa, nbr))
    return;

  list_add_node (nbr->retranslist, lsa);
  list_add_node (lsa->retrans_nbr, nbr);
  ospf6_lsa_lock (lsa);
}

/* remove lsa from retrans list of neighbor */
void
ospf6_remove_retrans (struct ospf6_lsa *lsa, struct neighbor *nbr)
{
  /* if not on retranslist, return */
  if (!ospf6_lookup_retrans (lsa, nbr))
    return;

  /* remove from retrans list */
  list_delete_by_val (nbr->retranslist, lsa);
  list_delete_by_val (lsa->retrans_nbr, nbr);
  ospf6_lsa_unlock (lsa);

  ospf6_lsdb_check_maxage_lsa (ospf6);
}

/* remove all lsa from retrans list of neighbor */
void
ospf6_remove_retrans_all (struct neighbor *nbr)
{
  listnode n;
  struct ospf6_lsa *lsa;
  while (listcount (nbr->retranslist))
    {
      n = listhead (nbr->retranslist);
      lsa = (struct ospf6_lsa *) getdata (n);
      ospf6_remove_retrans (lsa, nbr);
    }
  return;
}


/* lookup delayed acknowledge list of ospf6_interface */
struct ospf6_lsa *
ospf6_lookup_delayed_ack (struct ospf6_lsa *lsa, struct ospf6_interface *o6if)
{
  if (list_lookup_node (o6if->lsa_delayed_ack, lsa))
    {
#ifndef NDEBUG
      if (!list_lookup_node (lsa->delayed_ack_if, o6if))
        assert (0);
#endif /* NDEBUG */
      return lsa;
    }
  return NULL;
}

/* add to delayed acknowledge list of ospf6_interface */
void
ospf6_add_delayed_ack (struct ospf6_lsa *lsa, struct ospf6_interface *o6if)
{
  if (ospf6_lookup_delayed_ack (lsa, o6if))
    return;

  list_add_node (o6if->lsa_delayed_ack, lsa);
  list_add_node (lsa->delayed_ack_if, o6if);
  ospf6_lsa_lock (lsa);
}

/* remove from delayed acknowledge list of ospf6_interface */
void
ospf6_remove_delayed_ack (struct ospf6_lsa *lsa, struct ospf6_interface *o6if)
{
  if (!ospf6_lookup_delayed_ack (lsa, o6if))
    return;

  list_delete_by_val (o6if->lsa_delayed_ack, lsa);
  list_delete_by_val (lsa->delayed_ack_if, o6if);
  ospf6_lsa_unlock (lsa);
}


/* lsdb functions */

/* interface scope */
/* lookup from interface lsdb */
static struct ospf6_lsa *
ospf6_lsdb_lookup_interface (unsigned short type, unsigned long id,
                             unsigned long advrtr, struct ospf6_interface *o6if)
{
  listnode n;
  struct ospf6_lsa *lsa;
  assert (ospf6_lsa_get_scope_type (type) == SCOPE_LINKLOCAL);
  for (n = listhead (o6if->lsdb); n; nextnode (n))
    {
      lsa = (struct ospf6_lsa *) getdata (n);
      if (lsa->lsa_hdr->lsh_advrtr != advrtr)
        continue;
      if (lsa->lsa_hdr->lsh_id != id)
        continue;
      return lsa;
    }
  return NULL;
}

/* add to interface lsdb */
static void
ospf6_lsdb_add_interface (struct ospf6_lsa *lsa, struct ospf6_interface *o6if)
{
  assert (ospf6_lsa_get_scope_type (lsa->lsa_hdr->lsh_type)
          == SCOPE_LINKLOCAL);
  list_add_node (o6if->lsdb, lsa);
  ospf6_lsa_lock (lsa);
}

/* remove from interface lsdb */
static void
ospf6_lsdb_remove_interface (struct ospf6_lsa *lsa, struct ospf6_interface *o6if)
{
  assert (ospf6_lsa_get_scope_type (lsa->lsa_hdr->lsh_type)
          == SCOPE_LINKLOCAL);
  list_delete_by_val (o6if->lsdb, lsa);
  ospf6_lsa_unlock (lsa);
}

/* area scope */
  /* I wanna know the effection of database algorithm to the performance,
     so the algorithm of these functions is so poor, should be rewrited
     near future. */
/* lookup from area lsdb */
static struct ospf6_lsa *
ospf6_lsdb_lookup_area (unsigned short type, unsigned long id,
                        unsigned long advrtr, struct area *area)
{
  listnode n;
  struct ospf6_lsa *lsa;

  assert (area);
  for (n = listhead (area->lsdb); n; nextnode (n))
    {
      lsa = (struct ospf6_lsa *) getdata (n);
      if (lsa->lsa_hdr->lsh_type == type &&
          lsa->lsa_hdr->lsh_id == id &&
          lsa->lsa_hdr->lsh_advrtr == advrtr)
        return lsa;
    }
  return NULL;
}

/* add to area lsdb */
static void
ospf6_lsdb_add_area (struct ospf6_lsa *lsa, struct area *area)
{
  assert (area);
  list_add_node (area->lsdb, lsa);
  ospf6_lsa_lock (lsa);
}

/* remove from area lsdb */
static void
ospf6_lsdb_remove_area (struct ospf6_lsa *lsa, struct area *area)
{
  assert (area);
  list_delete_by_val (area->lsdb, lsa);
  ospf6_lsa_unlock (lsa);
}

/* as scope */
/* lookup from as lsdb */
static struct ospf6_lsa *
ospf6_lsdb_lookup_as (unsigned short type, unsigned long id,
                        unsigned long advrtr, struct ospf6 *ospf6)
{
  listnode n;
  struct ospf6_lsa *lsa;

  assert (ospf6);

  for (n = listhead (ospf6->lsdb); n; nextnode (n))
    {
      lsa = (struct ospf6_lsa *) getdata (n);
      if (lsa->lsa_hdr->lsh_type == type &&
          lsa->lsa_hdr->lsh_id == id &&
          lsa->lsa_hdr->lsh_advrtr == advrtr)
        return lsa;
    }
  return NULL;
}

/* add to as lsdb */
static void
ospf6_lsdb_add_as (struct ospf6_lsa *lsa, struct ospf6 *ospf6)
{
  assert (ospf6);
  list_add_node (ospf6->lsdb, lsa);
  ospf6_lsa_lock (lsa);
}

/* remove from as lsdb */
static void
ospf6_lsdb_remove_as (struct ospf6_lsa *lsa, struct ospf6 *ospf6)
{
  assert (ospf6);
  list_delete_by_val (ospf6->lsdb, lsa);
  ospf6_lsa_unlock (lsa);
}

/* lsdb lookup */
  /* It is better to specify scope when lookup lsdb, because there may
     be the same LSAs in different scoped structure. this will happen
     when duplicate router id is mis-configured over a different scope. */

  /* need two particular function for lookup */
  /* to treat multiple router-lsa as one */
void
ospf6_lsdb_collect_type_advrtr (list l, unsigned short type,
                                unsigned long advrtr, void *scope)
{
  struct ospf6 *ospf6;
  struct area *area;
  struct ospf6_interface *o6if;
  listnode n;
  struct ospf6_lsa *lsa;

  assert (l && scope);
  switch (ospf6_lsa_get_scope_type (type))
    {
      case SCOPE_AREA:
        area = (struct area *) scope;
        for (n = listhead (area->lsdb); n; nextnode (n))
          {
            lsa = (struct ospf6_lsa *) getdata (n);
            if (lsa->lsa_hdr->lsh_type == type &&
                lsa->lsa_hdr->lsh_advrtr == advrtr)
              list_add_node (l, lsa);
          }
        break;

      case SCOPE_LINKLOCAL:
        o6if = (struct ospf6_interface *)scope;
        for (n = listhead (o6if->lsdb); n; nextnode (n))
          {
            lsa = (struct ospf6_lsa *) getdata (n);
            if (lsa->lsa_hdr->lsh_type == type &&
                lsa->lsa_hdr->lsh_advrtr == advrtr)
              list_add_node (l, lsa);
          }
        break;

      case SCOPE_AS:
        ospf6 = (struct ospf6 *) scope;
        for (n = listhead (ospf6->lsdb); n; nextnode (n))
          {
            lsa = (struct ospf6_lsa *) getdata (n);
            if (lsa->lsa_hdr->lsh_type == type &&
                lsa->lsa_hdr->lsh_advrtr == advrtr)
              list_add_node (l, lsa);
          }
        break;

      case SCOPE_RESERVED:
      default:
        o6log.lsdb ("unsupported scope, can't collect advrtr from lsdb");
        break;
    }
  return;
}

  /* to process all as-external-lsa, *-area-prefix-lsa */
void
ospf6_lsdb_collect_type (list l, unsigned short type, void *scope)
{
  struct ospf6 *ospf6;
  struct ospf6_interface *o6if;
  struct area *area;
  listnode n;
  struct ospf6_lsa *lsa;

  assert (l && scope);
  switch (ospf6_lsa_get_scope_type (type))
    {
      case SCOPE_AREA:
        area = (struct area *) scope;
        for (n = listhead (area->lsdb); n; nextnode (n))
          {
            lsa = (struct ospf6_lsa *) getdata (n);
            if (lsa->lsa_hdr->lsh_type == type)
              list_add_node (l, lsa);
          }
        break;

      case SCOPE_LINKLOCAL:
        /* used by show_ipv6_ospf6_database_link_cmd */
        o6if = (struct ospf6_interface *) scope;
        for (n = listhead (o6if->lsdb); n; nextnode (n))
          {
            lsa = (struct ospf6_lsa *) getdata (n);
            if (lsa->lsa_hdr->lsh_type == type)
              list_add_node (l, lsa);
          }
        break;

      case SCOPE_AS:
        /* used by show_ipv6_ospf6_database_as_external_cmd */
        ospf6 = (struct ospf6 *) scope;
        for (n = listhead (ospf6->lsdb); n; nextnode (n))
          {
            lsa = (struct ospf6_lsa *) getdata (n);
            if (lsa->lsa_hdr->lsh_type == type)
              list_add_node (l, lsa);
          }
        break;
      case SCOPE_RESERVED:
      default:
        o6log.lsdb ("unsupported scope, can't collect advrtr from lsdb");
        break;
    }
  return;
}

  /* ordinary lookup function */
struct ospf6_lsa *
ospf6_lsdb_lookup (unsigned short type, unsigned long id,
                   unsigned long advrtr, void *scope)
{
  struct ospf6_interface *o6if;
  struct area *area;
  struct ospf6 *ospf6;
  struct ospf6_lsa *found;

  switch (ospf6_lsa_get_scope_type (type))
    {
      case SCOPE_LINKLOCAL:
        o6if = (struct ospf6_interface *) scope;
        found = ospf6_lsdb_lookup_interface (type, id, advrtr, o6if);
        return found;
      case SCOPE_AREA:
        area = (struct area *) scope;
        found = ospf6_lsdb_lookup_area (type, id, advrtr, area);
        return found;
      case SCOPE_AS:
        ospf6 = (struct ospf6 *) scope;
        found = ospf6_lsdb_lookup_as (type, id, advrtr, ospf6);
        return found;
      case SCOPE_RESERVED:
      default:
        o6log.lsdb ("unsupported scope, can't lookup lsdb");
        break;
    }
  return NULL;
}

/* new ordinary lookup function */
struct ospf6_lsa *
ospf6_lsdb_lookup_new (unsigned short type, unsigned long id,
                       unsigned long advrtr, struct ospf6 *o6)
{
  struct ospf6_interface *o6i;
  struct area *area;
  struct ospf6_lsa *found;
  listnode i, j;

  found = (struct ospf6_lsa *) NULL;
  switch (ospf6_lsa_get_scope_type (type))
    {
      case SCOPE_LINKLOCAL:
        for (i = listhead (o6->area_list); i; nextnode (i))
          {
            area = (struct area *) getdata (i);
            for (j = listhead (area->if_list); j; nextnode (j))
              {
                o6i = (struct ospf6_interface *) getdata (j);
                found = ospf6_lsdb_lookup_interface (type, id, advrtr, o6i);
                if (found)
                  return found;
              }
          }
        break;
      case SCOPE_AREA:
        for (i = listhead (o6->area_list); i; nextnode (i))
          {
            area = (struct area *) getdata (i);
            found = ospf6_lsdb_lookup_area (type, id, advrtr, area);
            if (found)
              return found;
          }
        break;
      case SCOPE_AS:
        found = ospf6_lsdb_lookup_as (type, id, advrtr, o6);
        if (found)
          return found;
        break;
      case SCOPE_RESERVED:
      default:
        zlog_info ("LSDB lookup: Unknown scope");
        break;
    }
  return NULL;
}

void
ospf6_lsdb_add (struct ospf6_lsa *lsa)
{
  struct ospf6_interface *o6if;
  struct area *area;
  struct ospf6 *ospf6;
  struct timeval now;

  assert (lsa && lsa->lsa_hdr);

  /* set installed time */
  if (gettimeofday (&now, (struct timezone *)NULL) < 0)
    o6log.lsa ("gettimeofday () failed, can't set installed: %s",
               strerror (errno));
  lsa->installed = now.tv_sec;

  /* add appropriate scope */
  switch (ospf6_lsa_get_scope_type (lsa->lsa_hdr->lsh_type))
    {
      case SCOPE_LINKLOCAL:
        o6if = (struct ospf6_interface *) lsa->scope;
        ospf6_lsdb_add_interface (lsa, o6if);
        break;
      case SCOPE_AREA:
        area = (struct area *) lsa->scope;
        ospf6_lsdb_add_area (lsa, area);
        break;
      case SCOPE_AS:
        ospf6 = (struct ospf6 *) lsa->scope;
        ospf6_lsdb_add_as (lsa, ospf6);
        break;
      case SCOPE_RESERVED:
      default:
        zlog_err ("!!!unsupported scope, can't add to lsdb");
        return;
    }
  lsa_change (lsa);
  return;
}

void
ospf6_lsdb_remove (struct ospf6_lsa *lsa)
{
  struct ospf6_interface *o6if;
  struct area *area;
  struct ospf6 *ospf6;
  listnode n;

  /* LSA going to be removed from lsdb should not be (delayed)
     acknowledged. I must prevent from being delayed acknowledged
     here */
  for (n = listhead (lsa->delayed_ack_if); n;
       n = listhead (lsa->delayed_ack_if))
    {
      o6if = (struct ospf6_interface *) getdata (n);
      ospf6_remove_delayed_ack (lsa, o6if);
    }

  switch (ospf6_lsa_get_scope_type (lsa->lsa_hdr->lsh_type))
    {
      case SCOPE_LINKLOCAL:
        o6if = (struct ospf6_interface *) lsa->scope;
        ospf6_lsdb_remove_interface (lsa, o6if);
        break;
      case SCOPE_AREA:
        area = (struct area *) lsa->scope;
        ospf6_lsdb_remove_area (lsa, area);
        break;
      case SCOPE_AS:
        ospf6 = (struct ospf6 *) lsa->scope;
        ospf6_lsdb_remove_as (lsa, ospf6);
        break;
      case SCOPE_RESERVED:
      default:
        zlog_err ("!!!unsupported scope, can't remove from lsdb");
        return;
    }
  return;
}

/* initialize and finish function */
/* neighbor lsdb */
void
ospf6_lsdb_init_neighbor (struct neighbor *nbr)
{
  nbr->summarylist = list_init ();
  nbr->requestlist = list_init ();
  nbr->retranslist = list_init ();
  return;
}

void
ospf6_lsdb_finish_neighbor (struct neighbor *nbr)
{
  ospf6_remove_summary_all (nbr);
  list_delete_all (nbr->summarylist);
  ospf6_remove_request_all (nbr);
  list_delete_all (nbr->requestlist);
  ospf6_remove_retrans_all (nbr);
  list_delete_all (nbr->retranslist);
  return;
}

/* interface lsdb */
void
ospf6_lsdb_init_interface (struct ospf6_interface *o6if)
{
  o6if->lsdb = list_init ();
  o6if->lsa_delayed_ack = list_init ();
  return;
}

void
ospf6_lsdb_finish_interface (struct ospf6_interface *o6if)
{
  listnode n;
  struct ospf6_lsa *lsa;

  /* delayed ack list */
  while (listcount (o6if->lsa_delayed_ack))
    {
      n = listhead (o6if->lsa_delayed_ack);
      lsa = (struct ospf6_lsa *) getdata (n);
      ospf6_remove_delayed_ack (lsa, o6if);
    }
  list_delete_all (o6if->lsa_delayed_ack);

  /* interface lsdb */
  while (listcount (o6if->lsdb))
    {
      n = listhead (o6if->lsdb);
      lsa = (struct ospf6_lsa *) getdata (n);
      ospf6_lsdb_remove_interface (lsa, o6if);
    }
  list_delete_all (o6if->lsdb);

  return;
}

/* area lsdb */
void
ospf6_lsdb_init_area (struct area *area)
{
  area->lsdb = list_init ();
  return;
}

void
ospf6_lsdb_finish_area (struct area *area)
{
  listnode n;
  struct ospf6_lsa *lsa;
  while (listcount (area->lsdb))
    {
      n = listhead (area->lsdb);
      lsa = (struct ospf6_lsa *) getdata (n);
      ospf6_lsdb_remove_area (lsa, area);
    }
  list_delete_all (area->lsdb);
  return;
}

/* as lsdb */
void
ospf6_lsdb_init_as (struct ospf6 *ospf6)
{
  ospf6->lsdb = list_init ();
  return;
}

void
ospf6_lsdb_finish_as (struct ospf6 *ospf6)
{
  listnode n;
  struct ospf6_lsa *lsa;
  while (listcount (ospf6->lsdb))
    {
      n = listhead (ospf6->lsdb);
      lsa = (struct ospf6_lsa *) getdata (n);
      ospf6_lsdb_remove_as (lsa, ospf6);
    }
  list_delete_all (ospf6->lsdb);
  return;
}

/* when installing more recent LSA, must detach less recent database copy
   from LS-lists of neighbors, and attach new one. */
void ospf6_lsdb_install (struct ospf6_lsa *new)
{
  listnode n;
  struct neighbor *nbr;
  struct ospf6_lsa *old;

  if (IS_OSPF6_DUMP_LSA)
    {
      zlog_info ("LSA Install:");
      ospf6_dump_lsa (new);
    }

  old = ospf6_lsdb_lookup (new->lsa_hdr->lsh_type,
                           new->lsa_hdr->lsh_id,
                           new->lsa_hdr->lsh_advrtr, new->scope);

  if (old)
    {
      while (listcount (old->retrans_nbr))
        {
          n = listhead (old->retrans_nbr);
          nbr = (struct neighbor *) getdata (n);
          ospf6_remove_retrans (old, nbr);
        }

      ospf6_lsdb_remove (old);
      ospf6_lsdb_add (new);
    }
  else
    ospf6_lsdb_add (new);

  return;
}


/* maxage LSA remover */
/* from RFC2328 14.
    A MaxAge LSA must be removed immediately from the router's link
    state database as soon as both a) it is no longer contained on any
    neighbor Link state retransmission lists and b) none of the router's
    neighbors are in states Exchange or Loading.
 */
void
ospf6_lsdb_check_maxage_lsa (struct ospf6 *o6)
{
  listnode i, j, k;
  struct area *o6a;
  struct ospf6_interface *o6i;
  struct ospf6_lsa *lsa;
  list remove_list;

  /* if any neighbor is in state Exchange or Loading, quit */
  for (i = listhead (o6->area_list); i; nextnode (i))
    {
      o6a = (struct area *) getdata (i);
      if (count_nbr_in_state (NBS_EXCHANGE, o6a))
        return;
      if (count_nbr_in_state (NBS_LOADING, o6a))
        return;
    }

  /* prepare remove list */
  remove_list = list_init ();

  /* for AS LSDB */
  for (i = listhead (o6->lsdb); i; nextnode (i))
    {
      lsa = (struct ospf6_lsa *) getdata (i);

      if (ospf6_age_current (lsa) == MAXAGE
          && listcount (lsa->retrans_nbr) == 0)
        list_add_node (remove_list, lsa);
    }

  /* for Area LSDB */
  for (i = listhead (o6->area_list); i; nextnode (i))
    {
      o6a = (struct area *) getdata (i);

      for (j = listhead (o6a->lsdb); j; nextnode (j))
        {
          lsa = (struct ospf6_lsa *) getdata (j);

          if (ospf6_age_current (lsa) == MAXAGE
              && listcount (lsa->retrans_nbr) == 0)
            list_add_node (remove_list, lsa);
        }
    }

  /* for Interface LSDB */
  for (i = listhead (o6->area_list); i; nextnode (i))
    {
      o6a = (struct area *) getdata (i);

      for (j = listhead (o6a->if_list); j; nextnode (j))
        {
          o6i = (struct ospf6_interface *) getdata (j);

          for (k = listhead (o6i->lsdb); k; nextnode (k))
            {
              lsa = (struct ospf6_lsa *) getdata (k);

              if (ospf6_age_current (lsa) == MAXAGE
                  && listcount (lsa->retrans_nbr) == 0)
                list_add_node (remove_list, lsa);
            }
        }
    }

  for (i = listhead (remove_list); i; nextnode (i))
    {
      lsa = (struct ospf6_lsa *) getdata (i);
      ospf6_lsa_maxage_remove (lsa);
    }

  list_delete_all (remove_list);
}


DEFUN (show_ipv6_ospf6_database_router,
       show_ipv6_ospf6_database_router_cmd,
       "show ipv6 ospf6 database router",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       "Database summary\n"
       "Router-LSA\n"
       )
{
  listnode j, k;
  struct area *area;
  list l;

  for (j = listhead (ospf6->area_list); j; nextnode (j))
    {
      area = (struct area *) getdata (j);
      vty_out (vty, "Area %s%s", inet4str (area->area_id),
	       VTY_NEWLINE);
      l = list_init ();
      ospf6_lsdb_collect_type (l, htons (LST_ROUTER_LSA), area);
      for (k = listhead (l); k; nextnode (k))
        {
          vty_lsa (vty, (struct ospf6_lsa *) getdata (k));
        }
      list_delete_all (l);
    }

  return CMD_SUCCESS;
}

DEFUN (show_ipv6_ospf6_database_network,
       show_ipv6_ospf6_database_network_cmd,
       "show ipv6 ospf6 database network",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       "Database summary\n"
       "Network-LSA\n"
       )
{
  listnode j, k;
  struct area *area;
  list l;

  for (j = listhead (ospf6->area_list); j; nextnode (j))
    {
      area = (struct area *) getdata (j);
      vty_out (vty, "Area %s%s", inet4str (area->area_id), VTY_NEWLINE);
      l = list_init ();
      ospf6_lsdb_collect_type (l, htons (LST_NETWORK_LSA), area);
      for (k = listhead (l); k; nextnode (k))
        {
          vty_lsa (vty, (struct ospf6_lsa *) getdata (k));
        }
      list_delete_all (l);
    }

  return CMD_SUCCESS;
}

DEFUN (show_ipv6_ospf6_database_link,
       show_ipv6_ospf6_database_link_cmd,
       "show ipv6 ospf6 database link",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       "Database summary\n"
       "Link-LSA\n"
       )
{
  listnode j, k, n;
  list l;
  struct area *area;
  struct ospf6_interface *ospf6_interface;

  for (j = listhead (ospf6->area_list); j; nextnode (j))
    {
      area = (struct area *) getdata (j);
      vty_out (vty, "Area %s%s", inet4str (area->area_id),
	       VTY_NEWLINE);
      for (k = listhead (area->if_list); k; nextnode (k))
        {
          ospf6_interface = (struct ospf6_interface *) getdata (k);
          vty_out (vty, "Interface %s%s", ospf6_interface->interface->name,
		   VTY_NEWLINE);
          l = list_init ();
          ospf6_lsdb_collect_type (l, htons (LST_LINK_LSA), ospf6_interface);
          for (n = listhead (l); n; nextnode (n))
            {
              vty_lsa (vty, (struct ospf6_lsa *) getdata (n));
            }
          list_delete_all (l);
        }
    }

  return CMD_SUCCESS;
}

DEFUN (show_ipv6_ospf6_database_intraprefix,
       show_ipv6_ospf6_database_intraprefix_cmd,
       "show ipv6 ospf6 database intra-area-prefix",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       "Database summary\n"
       "Intra-Area-Prefix-LSA\n"
       )
{
  listnode j, k;
  struct area *area;
  list l;

  for (j = listhead (ospf6->area_list); j; nextnode (j))
    {
      area = (struct area *) getdata (j);
      vty_out (vty, "Area %s%s", inet4str (area->area_id),
	       VTY_NEWLINE);
      l = list_init ();
      ospf6_lsdb_collect_type (l, htons (LST_INTRA_AREA_PREFIX_LSA), area);
      for (k = listhead (l); k; nextnode (k))
        {
          vty_lsa (vty, (struct ospf6_lsa *) getdata (k));
        }
      list_delete_all (l);
    }

  return CMD_SUCCESS;
}

DEFUN (show_ipv6_ospf6_database_asexternal,
       show_ipv6_ospf6_database_asexternal_cmd,
       "show ipv6 ospf6 database as-external",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       "Database summary\n"
       "AS-External-LSA\n"
       )
{
  listnode j;
  u_int32_t advrtr = 0;
  struct ospf6_lsa *lsa;

  if (argc)
    inet_pton (AF_INET, argv[0], &advrtr);

  for (j = listhead (ospf6->lsdb); j; nextnode (j))
    {
      lsa = (struct ospf6_lsa *) getdata (j);
      if (advrtr && lsa->lsa_hdr->lsh_advrtr != advrtr)
        continue;
      vty_lsa (vty, lsa);
    }

  return CMD_SUCCESS;
}

ALIAS (show_ipv6_ospf6_database_asexternal,
       show_ipv6_ospf6_database_asexternal_advrtr_cmd,
       "show ipv6 ospf6 database as-external advrtr A.B.C.D",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       "Database summary\n"
       "AS-External-LSA\n"
       "Advertising Router\n"
       "Router ID\n"
       )

DEFUN (show_ipv6_ospf6_database,
       show_ipv6_ospf6_database_cmd,
       "show ipv6 ospf6 database",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       "Database summary\n"
       )
{
  show_ipv6_ospf6_database_router (&show_ipv6_ospf6_database_router_cmd,
                                   vty, 0, NULL);
  show_ipv6_ospf6_database_network (&show_ipv6_ospf6_database_network_cmd,
                                    vty, 0, NULL);
  show_ipv6_ospf6_database_link (&show_ipv6_ospf6_database_link_cmd,
                                 vty, 0, NULL);
  show_ipv6_ospf6_database_intraprefix (&show_ipv6_ospf6_database_intraprefix_cmd,
                                        vty, 0, NULL);
  show_ipv6_ospf6_database_asexternal (&show_ipv6_ospf6_database_asexternal_cmd,
                                        vty, 0, NULL);
  return CMD_SUCCESS;
}

void
ospf6_lsdb_init ()
{
  install_element (VIEW_NODE, &show_ipv6_ospf6_database_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_database_network_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_database_router_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_database_link_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_database_intraprefix_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_database_asexternal_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_database_asexternal_advrtr_cmd);

  install_element (ENABLE_NODE, &show_ipv6_ospf6_database_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_database_network_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_database_router_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_database_link_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_database_intraprefix_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_database_asexternal_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_database_asexternal_advrtr_cmd);
}

