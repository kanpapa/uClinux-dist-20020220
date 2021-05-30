/*
 * OSPF LSDB support.
 * Copyright (C) 1999, 2000 Alex Zinin, Kunihiro Ishiguro, Toshiaki Takada
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
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#include <zebra.h>

#include "thread.h"
#include "memory.h"
#include "hash.h"
#include "linklist.h"
#include "prefix.h"
#include "if.h"
#include "table.h"
#include "command.h"
#include "vty.h"
#include "stream.h"
#include "log.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_ism.h"
#include "ospfd/ospf_asbr.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_lsdb.h"
#include "ospfd/ospf_neighbor.h"
#include "ospfd/ospf_nsm.h"
#include "ospfd/ospf_flood.h"
#include "ospfd/ospf_packet.h"
#include "ospfd/ospf_spf.h"
#include "ospfd/ospf_dump.h"
#include "ospfd/ospf_route.h"


void
tmp_log ( char *str, struct ospf_lsa *lsa)
{
  return;
  printf ("%s %s ", str, inet_ntoa (lsa->data->id));
  printf ("%s\n", inet_ntoa (lsa->data->adv_router));
}

struct new_lsdb *
new_lsdb_new ()
{
  struct new_lsdb *new;

  new = XMALLOC (MTYPE_OSPF_LSDB, sizeof (struct new_lsdb));
  bzero (new, sizeof (struct new_lsdb));
  new_lsdb_init (new);

  return new;
}

void
new_lsdb_init (struct new_lsdb *lsdb)
{
  lsdb->type[1].db = route_table_init ();
  lsdb->type[2].db = route_table_init ();
  lsdb->type[3].db = route_table_init ();
  lsdb->type[4].db = route_table_init ();
  lsdb->type[5].db = route_table_init ();
}

void
new_lsdb_free (struct new_lsdb *lsdb)
{
  new_lsdb_cleanup (lsdb);
  XFREE (MTYPE_OSPF_LSDB, lsdb);
}

void
new_lsdb_cleanup (struct new_lsdb *lsdb)
{
  assert (lsdb);
  assert (lsdb->total == 0);
  
  route_table_finish (lsdb->type[1].db);
  route_table_finish (lsdb->type[2].db);
  route_table_finish (lsdb->type[3].db);
  route_table_finish (lsdb->type[4].db);
  route_table_finish (lsdb->type[5].db);
}

void
lsdb_prefix_set (struct prefix_ls *lp, struct ospf_lsa *lsa)
{
  memset (lp, 0, sizeof (struct prefix_ls));
  lp->family = 0;
  lp->prefixlen = 64;
  lp->id = lsa->data->id;
  lp->adv_router = lsa->data->adv_router;
}

/* Add new LSA to lsdb. */
void
new_lsdb_add (struct new_lsdb *lsdb, struct ospf_lsa *lsa)
{
  struct route_table *table;
  struct prefix_ls lp;
  struct route_node *rn;

  table = lsdb->type[lsa->data->type].db;
  lsdb_prefix_set (&lp, lsa);
  rn = route_node_get (table, (struct prefix *)&lp);
  if (! rn->info)
    {
      lsdb->type[lsa->data->type].count++;
      lsdb->total++;
    }
  else
    {
      ((struct ospf_lsa *)rn->info)->ref--;
      route_unlock_node (rn);
    }

  rn->info = lsa;
  tmp_log ("add", lsa);
}

/* Insert an LSA to lsdb. */
struct ospf_lsa *
new_lsdb_insert (struct new_lsdb *lsdb, struct ospf_lsa *lsa)
{
  struct route_table *table;
  struct prefix_ls lp;
  struct route_node *rn;

  table = lsdb->type[lsa->data->type].db;
  lsdb_prefix_set (&lp, lsa);
  rn = route_node_get (table, (struct prefix *)&lp);
  /* Newly install LSA. */
  if (!rn->info)
    {
      zlog_info ("new_lsdb_insert: Newly install");

      lsdb->type[lsa->data->type].count++;
      lsdb->total++;
    }
  /* Replace old LSA with new one. */
  else
    {
      struct ospf_lsa *old = rn->info;

      zlog_info ("new_lsdb_insert: Replace");

      /* Preserve old value. */
      /* lsa->flags = old->flags; */

      /* Make sure registering MaxAge LSA to delete. */
      /* ospf_lsa_maxage (old); */
      if (old->refresh_list)
	ospf_refresher_unregister_lsa (old);

      ospf_ls_retransmit_delete_nbr_all (old->area, old);
      
      list_delete_by_val (ospf_top->maxage_lsa, old);

      ospf_lsa_free (old);

      route_unlock_node (rn);
    }
  
  rn->info = lsa;
  tmp_log ("insert", rn->info);
  return rn->info;
}

void
new_lsdb_delete (struct new_lsdb *lsdb, struct ospf_lsa *lsa)
{
  struct route_table *table;
  struct prefix_ls lp;
  struct route_node *rn;

  table = lsdb->type[lsa->data->type].db;
  lsdb_prefix_set (&lp, lsa);
  rn = route_node_lookup (table, (struct prefix *) &lp);
  if (rn)
    if (rn->info == lsa)
      {
	rn->info = NULL;
	route_unlock_node (rn);
	route_unlock_node (rn);
	lsdb->type[lsa->data->type].count--;
	lsdb->total--;
	tmp_log ("delete", lsa);
	return;
      }
  tmp_log ("can't delete", lsa);
}

void
new_lsdb_delete_all (struct new_lsdb *lsdb)
{
  struct route_table *table;
  struct route_node *rn;
  struct ospf_lsa *lsa;
  int i;

  for (i = OSPF_MIN_LSA; i < OSPF_MAX_LSA; i++)
    {
      table = lsdb->type[i].db;
      for (rn = route_top (table); rn; rn = route_next (rn))
	if ((lsa = (rn->info)) != NULL)
	  {
	    rn->info = NULL;
	    route_unlock_node (rn);
	    ospf_lsa_free (lsa);
	    lsdb->type[i].count--;
	    lsdb->total--;
	  }
    }
}

struct ospf_lsa *
new_lsdb_lookup (struct new_lsdb *lsdb, struct ospf_lsa *lsa)
{
  struct route_table *table;
  struct prefix_ls lp;
  struct route_node *rn;
  struct ospf_lsa *find;

  table = lsdb->type[lsa->data->type].db;
  lsdb_prefix_set (&lp, lsa);
  rn = route_node_lookup (table, (struct prefix *) &lp);
  if (rn)
    {
      find = rn->info;
      route_unlock_node (rn);
      tmp_log ("lookup", lsa);
      return find;
    }
  tmp_log ("can't lookup", lsa);
  return NULL;
}

struct ospf_lsa *
new_lsdb_lookup_by_id (struct new_lsdb *lsdb, u_char type,
		       struct in_addr id, struct in_addr adv_router)
{
  struct route_table *table;
  struct prefix_ls lp;
  struct route_node *rn;
  struct ospf_lsa *find;

  table = lsdb->type[type].db;

  memset (&lp, 0, sizeof (struct prefix_ls));
  lp.family = 0;
  lp.prefixlen = 64;
  lp.id = id;
  lp.adv_router = adv_router;

  rn = route_node_lookup (table, (struct prefix *) &lp);
  if (rn)
    {
      find = rn->info;
      route_unlock_node (rn);
      return find;
    }
  return NULL;
}

unsigned long
new_lsdb_count (struct new_lsdb *lsdb)
{
  return lsdb->total;
}

unsigned long
new_lsdb_isempty (struct new_lsdb *lsdb)
{
  return (lsdb->total == 0);
}

struct ospf_lsa *
foreach_lsa (struct route_table *table, void *p_arg, int int_arg, 
	     int (*callback) (struct ospf_lsa *, void *, int))
{
  struct route_node *rn;
  struct ospf_lsa *lsa;

  for (rn = route_top (table); rn; rn = route_next (rn))
    if ((lsa = rn->info) != NULL)
      if (callback (lsa, p_arg, int_arg))
	return lsa;

  return NULL;
}
