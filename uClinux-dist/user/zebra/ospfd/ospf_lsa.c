/*
 * OSPF Link State Advertisement
 * Copyright (C) 1999, 2000 Toshiaki Takada
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

#include "linklist.h"
#include "prefix.h"
#include "if.h"
#include "table.h"
#include "memory.h"
#include "command.h"
#include "vty.h"
#include "stream.h"
#include "log.h"
#include "thread.h"
#include "hash.h"

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
#include "ospfd/ospf_ase.h"
#include "ospfd/ospf_zebra.h"

/* Debug flags. */
extern unsigned long term_debug_ospf_lsa;


u_int32_t
get_metric (u_char *metric)
{
  u_int32_t m;
  m = metric[0];
  m = (m << 8) + metric[1];
  m = (m << 8) + metric[2];
  return m;
}


void
tv_debug (struct timeval a)
{
  printf ("%ld.%ld\n", a.tv_sec, a.tv_usec);
}

struct timeval
tv_adjust (struct timeval a)
{
  while (a.tv_usec >= 1000000)
    {
      a.tv_usec -= 1000000;
      a.tv_sec++;
    }

  while (a.tv_usec < 0)
    {
      a.tv_usec += 1000000;
      a.tv_sec--;
    }

  return a;
}

int
tv_ceil (struct timeval a)
{
  a = tv_adjust (a);

  return (a.tv_usec ? a.tv_sec + 1 : a.tv_sec);
}

int
tv_floor (struct timeval a)
{
  a = tv_adjust (a);

  return a.tv_sec;
}

struct timeval
int2tv (int a)
{
  struct timeval ret;

  ret.tv_sec = a;
  ret.tv_usec = 0;

  return ret;
}

struct timeval
tv_add (struct timeval a, struct timeval b)
{
  struct timeval ret;

  ret.tv_sec = a.tv_sec + b.tv_sec;
  ret.tv_usec = a.tv_usec + b.tv_usec;

  return tv_adjust (ret);
}

struct timeval
tv_sub (struct timeval a, struct timeval b)
{
  struct timeval ret;

  ret.tv_sec = a.tv_sec - b.tv_sec;
  ret.tv_usec = a.tv_usec - b.tv_usec;

  return tv_adjust (ret);
}

int
tv_cmp (struct timeval a, struct timeval b)
{
  return (a.tv_sec == b.tv_sec ?
	  a.tv_usec - b.tv_usec : a.tv_sec - b.tv_sec);
}


int
get_age (struct ospf_lsa *lsa)
{
  int age;
  struct timeval now;

  gettimeofday (&now, NULL);
  age = ntohs (lsa->data->ls_age) + tv_floor (tv_sub (now, lsa->tv_recv));

  return age;
}


/* Fletcher Checksum -- Refer to RFC1008. */
#define MODX                 4102
#define LSA_CHECKSUM_OFFSET    15

u_int16_t
ospf_lsa_checksum (struct lsa_header *lsa)
{
  u_char *sp, *ep, *p, *q;
  int c0 = 0, c1 = 0;
  int x, y;
  u_int16_t length;

  lsa->checksum = 0;
  length = ntohs (lsa->length) - 2;
  sp = (char *) &lsa->options;

  for (ep = sp + length; sp < ep; sp = q)
    {
      q = sp + MODX;
      if (q > ep)
        q = ep;
      for (p = sp; p < q; p++)
        {
          c0 += *p;
          c1 += c0;
        }
      c0 %= 255;
      c1 %= 255;
    }

  /* r = (c1 << 8) + c0; */
  x = ((length - LSA_CHECKSUM_OFFSET) * c0 - c1) % 255;
  if (x <= 0)
    x += 255;
  y = 510 - c0 - x;
  if (y > 255)
    y -= 255;

  /* take care endian issue. */
  lsa->checksum = htons ((x << 8) + y);

  return (lsa->checksum);
}

/* Create OSPF LSA. */
struct ospf_lsa *
ospf_lsa_new ()
{
  struct ospf_lsa *new;

  new = XMALLOC (MTYPE_OSPF_LSA, sizeof (struct ospf_lsa));

  assert (new);

  bzero (new, sizeof (struct ospf_lsa));

  new->flags = 0;
  gettimeofday (&new->tv_recv, NULL);
  new->tv_orig = new->tv_recv;

  return new;
}

/* Duplicate OSPF LSA. */
struct ospf_lsa *
ospf_lsa_dup (struct ospf_lsa *lsa)
{
  struct ospf_lsa *new;

  if (lsa == NULL)
    return NULL;

  new = XMALLOC (MTYPE_OSPF_LSA, sizeof (struct ospf_lsa));
  assert (new);
  bzero (new, sizeof (struct ospf_lsa));

  new->flags = lsa->flags;
  new->tv_recv = lsa->tv_recv;
  new->tv_orig = lsa->tv_orig;

  new->data = ospf_lsa_data_dup (lsa->data);

  return new;
}

/* Free OSPF LSA. */
void
ospf_lsa_free (struct ospf_lsa *lsa)
{
  if (IS_DEBUG_OSPF (lsa, LSA))
    zlog_info ("LSA: freed %x", lsa);

  /* Delete LSA data. */
  if (lsa->data != NULL)
    ospf_lsa_data_free (lsa->data);

  /* Make sure to unregister LSA from refresh-list. */
  if (lsa->refresh_list != NULL)
    ospf_refresher_unregister_lsa (lsa);

  XFREE (MTYPE_OSPF_LSA, lsa);
}

/* Create LSA data. */
struct lsa_header *
ospf_lsa_data_new (size_t size)
{
  struct lsa_header *new;

  new = (struct lsa_header *) XMALLOC (MTYPE_OSPF_LSA_DATA, size);
  assert (new);
  bzero (new, size);

  return new;
}

/* Duplicate LSA data. */
struct lsa_header *
ospf_lsa_data_dup (struct lsa_header *lsah)
{
  struct lsa_header *new;

  new = ospf_lsa_data_new (ntohs (lsah->length));
  memcpy (new, lsah, ntohs (lsah->length));

  return new;
}

/* Free LSA data. */
void
ospf_lsa_data_free (struct lsa_header *lsah)
{
  if (IS_DEBUG_OSPF (lsa, LSA))
    zlog_info ("LSA[Type%d:%s]: data freed %x",
	       lsah->type, inet_ntoa (lsah->id), lsah);

  XFREE (MTYPE_OSPF_LSA_DATA, lsah);
}


void
lsa_seqnum_increment (struct lsa_header *lsah)
{
  u_int32_t seqnum;

  seqnum = ntohl (lsah->ls_seqnum) + 1;
  lsah->ls_seqnum = htonl (seqnum);
}

void
ospf_lsa_header_set (struct stream *s, u_int16_t ls_age,
		     u_char options, u_char type, struct in_addr id)
{
  struct lsa_header *lsah;

  lsah = (struct lsa_header *) STREAM_DATA (s);

  lsah->ls_age = htons (ls_age);
  lsah->options = options;
  lsah->type = type;
  lsah->id = id;
  lsah->adv_router = ospf_top->router_id;
  lsah->ls_seqnum = htonl (OSPF_INITIAL_SEQUENCE_NUMBER);

  ospf_output_forward (s, OSPF_LSA_HEADER_SIZE);
}

/* Get router-LSA flags. */
u_char
router_lsa_flags (struct ospf_area *area)
{
  u_char flags;

  flags = ospf_top->flags;

  /* Set virtual link flag. */
  if (ospf_full_virtual_nbrs (area))
    SET_FLAG (flags, ROUTER_LSA_VIRTUAL);
  else
    /* Just sanity check */
    UNSET_FLAG (flags, ROUTER_LSA_VIRTUAL);

  /* Set Shortcut ABR behabiour flag. */
  UNSET_FLAG (flags, ROUTER_LSA_SHORTCUT);
  if (ospf_top->abr_type == OSPF_ABR_SHORTCUT)
    if (!OSPF_IS_AREA_BACKBONE (area))
      if ((area->shortcut_configured == OSPF_SHORTCUT_DEFAULT &&
	   !ospf_top->backbone) ||
	  area->shortcut_configured == OSPF_SHORTCUT_ENABLE)
	SET_FLAG (flags, ROUTER_LSA_SHORTCUT);

  return flags;
}

/* Lookup neighbor other than myself.
   And check neighbor count,
   Point-to-Point link must have only 1 neighbor. */
struct ospf_neighbor *
ospf_nbr_lookup_ptop (struct route_table *nbrs, struct in_addr router_id)
{
  struct route_node *rn;
  struct ospf_neighbor *nbr = NULL;

  /* Search neighbor, there must be one of two nbrs. */
  for (rn = route_top (nbrs); rn; rn = route_next (rn))
    if ((nbr = rn->info) != NULL)
      /* Ignore myself. */
      if (!IPV4_ADDR_SAME (&nbr->router_id, &ospf_top->router_id))
	if (nbr->status == NSM_Full)
	  break;

  /* PtoP link must have only 1 neighbor. */
  if (ospf_nbr_count (nbrs, 0) > 1)
    zlog_warn ("Point-to-Point link has more than 2 neighobrs.");

  return nbr;
}

/* Set a link information. */
void
link_info_set (struct stream *s, struct in_addr id,
	       struct in_addr data, u_char type, u_char tos, u_int16_t cost)
{
  /* TOS based routing is not supported. */
  stream_put_ipv4 (s, id.s_addr);		/* Link ID. */
  stream_put_ipv4 (s, data.s_addr);		/* Link Data. */
  stream_putc (s, type);			/* Link Type. */
  stream_putc (s, tos);				/* TOS = 0. */
  stream_putw (s, cost);			/* Link Cost. */
}

/* Describe Point-to-Point link. */
int
lsa_link_ptop_set (struct stream *s, struct ospf_interface *oi)
{
  int links = 0;
  struct ospf_neighbor *nbr;
  struct in_addr id, mask;

  if (IS_DEBUG_OSPF (lsa, LSA_GENERATE))
    zlog_info ("LSA[Type1]: Set link Point-to-Point");

  if ((nbr = ospf_nbr_lookup_ptop (oi->nbrs, ospf_top->router_id)))
    if (nbr->status == NSM_Full)
      {
	/* For unnumbered point-to-point networks, the Link Data field
	   should specify the interface's MIB-II ifIndex value. */
	link_info_set (s, nbr->router_id, oi->address->u.prefix4,
		       LSA_LINK_TYPE_POINTOPOINT, 0, oi->output_cost);
	links++;
      }
  /* Option 1:  It's rather legacy.
     link_type = LSA_LINK_TYPE_STUB;
     link_id = nbr->address.u.prefix4;
     link_data.s_addr = 0xffffffff;
     link_cost = o->output_cost; */

  /* Option 2:  We need to include link to a stub
     network regardless of the state of the neighbor */
  masklen2ip (oi->address->prefixlen, &mask);
  id.s_addr = oi->address->u.prefix4.s_addr & mask.s_addr;
  link_info_set (s, id, mask, LSA_LINK_TYPE_STUB,
		 0, oi->output_cost);
  links++;

  return links;
}

/* Describe Broadcast Link. */
int
lsa_link_broadcast_set (struct stream *s, struct ospf_interface *oi)
{
  struct ospf_neighbor *dr;
  struct in_addr id, mask;

  /* Describe Type 3 Link. */
  if (oi->status == ISM_Waiting)
    {
      masklen2ip (oi->address->prefixlen, &mask);
      id.s_addr = oi->address->u.prefix4.s_addr & mask.s_addr;
      link_info_set (s, id, mask, LSA_LINK_TYPE_STUB,
		     0, oi->output_cost);
      return 1;
    }

  /* There is no DR, no links here. */
  if ((dr = ospf_nbr_lookup_by_addr (oi->nbrs, &DR (oi))))
    {
      /* Describe Type 2 link. */
      if ((dr->status == NSM_Full ||
	   IPV4_ADDR_SAME (&oi->address->u.prefix4, &DR (oi))) &&
	  ospf_nbr_count (oi->nbrs, NSM_Full) > 0)
	{
	  link_info_set (s, DR (oi), oi->address->u.prefix4,
			 LSA_LINK_TYPE_TRANSIT, 0, oi->output_cost);
	}
      /* Describe type 3 link. */
      else
	{
	  masklen2ip (oi->address->prefixlen, &mask);
	  id.s_addr = oi->address->u.prefix4.s_addr & mask.s_addr;
	  link_info_set (s, id, mask, LSA_LINK_TYPE_STUB,
			 0, oi->output_cost);
	}
      return 1;
    }

  return 0;
}

/* Describe Virtual Link. */
int
lsa_link_virtuallink_set (struct stream *s, struct ospf_interface *oi)
{
  struct ospf_neighbor *nbr;

  if (IS_DEBUG_OSPF (lsa, LSA_GENERATE))
    zlog_info ("LSA[Type1]: Set link type VL, state %d", oi->status);

  if (oi->status == ISM_PointToPoint)
    if ((nbr = ospf_nbr_lookup_ptop (oi->nbrs, ospf_top->router_id)))
      if (nbr->status == NSM_Full)
	{
	  link_info_set (s, nbr->router_id, oi->address->u.prefix4,
			 LSA_LINK_TYPE_VIRTUALLINK, 0, oi->output_cost);
	  return 1;
	}

  return 0;
}

/* Describe secondary subnets. */
int
lsa_link_secondary_set (struct stream *s, struct ospf_interface *oi)
{
  listnode cn;
  struct connected *co;
  struct in_addr id, mask;
  int links = 0;

  if (IS_DEBUG_OSPF (lsa, LSA_GENERATE))
    zlog_info ("LSA[Type1]: Set link secondary");

  for (cn = listhead (oi->ifp->connected); cn; nextnode (cn))
    if ((co = cn->data) != NULL)
      if (co->address->family == AF_INET)
	if (!prefix_same (co->address, oi->address))
	  {
	    masklen2ip (co->address->prefixlen, &mask);
	    id.s_addr = co->address->u.prefix4.s_addr & mask.s_addr;
	    link_info_set (s, id, mask, LSA_LINK_TYPE_STUB,
			   0, oi->output_cost);
	    links++;
	  }

  return links++;
}

#define lsa_link_nbma_set(S,O)  lsa_link_broadcast_set (S, O)

/* Set router-LSA link information. */
int
router_lsa_link_set (struct stream *s, struct ospf_area *area)
{
  listnode node;
  int links = 0;

  for (node = listhead (area->iflist); node; node = nextnode (node))
    {
      struct interface *ifp = node->data;
      struct ospf_interface *oi;

      /* Check interface is up, OSPF is enable. */
      if (if_is_up (ifp))
	{
	  oi = ifp->info;
	  if (oi->flag == OSPF_IF_ENABLE && oi->status != ISM_Down)
	    {
	      /* Describe each link. */
	      switch (oi->type)
		{
		case OSPF_IFTYPE_POINTOPOINT:
		  links += lsa_link_ptop_set (s, oi);
		  break;
		case OSPF_IFTYPE_BROADCAST:
		  links += lsa_link_broadcast_set (s, oi);
		  break;
		case OSPF_IFTYPE_NBMA:
		  links += lsa_link_nbma_set (s, oi);
		  break;
		case OSPF_IFTYPE_POINTOMULTIPOINT:
		  /* Not supproted yet. */
		  break;
		case OSPF_IFTYPE_VIRTUALLINK:
		  links += lsa_link_virtuallink_set (s, oi);
		  break;
		}
	    }
	  /* Describe secondary subnets as stub networks. */
	  if (oi->type != OSPF_IFTYPE_VIRTUALLINK)
	    links += lsa_link_secondary_set (s, oi);
	}
    }

  return links;
}

/* Set router-LSA body. */
void
ospf_router_lsa_body_set (struct stream *s, struct ospf_area *area)
{
  unsigned long putp;
  u_int16_t cnt;

  /* Set flags. */
  stream_putc (s, router_lsa_flags (area));

  /* Set Zero fields. */
  stream_putc (s, 0);

  /* Keep pointer to # links. */
  putp = s->putp;

  /* Forward word */
  stream_putw(s, 0);

  /* Set all link information. */
  cnt = router_lsa_link_set (s, area);

  /* Set # of links here. */
  stream_putw_at (s, putp, cnt);
}

/* Originate Router-LSA. */
struct ospf_lsa *
ospf_router_lsa_originate (struct ospf_area *area, struct ospf_lsa *old)
{
  struct stream *s;
  struct lsa_header *lsah;
  struct ospf_lsa *new;
  /* struct in_addr id; */
  u_char options;
  int length;

  if (IS_DEBUG_OSPF (lsa, LSA_GENERATE))
    zlog_info ("LSA[Type1]: Originate router-LSA start");

  /* Create new stream for LSA. */
  s = stream_new (OSPF_MAX_LSA_SIZE);
  lsah = (struct lsa_header *) STREAM_DATA (s);

  /* Set LSA common header fields. */
  options = (area->external_routing == OSPF_AREA_DEFAULT) ? OSPF_OPTION_E : 0;
  ospf_lsa_header_set (s, 0, options, OSPF_ROUTER_LSA, ospf_top->router_id);

  if (old != NULL)
    {
      lsa_seqnum_increment (old->data);
      lsah->ls_seqnum = old->data->ls_seqnum;
    }

  /* Set router-LSA body fields. */
  ospf_router_lsa_body_set (s, area);

  /* Set length. */
  length = stream_get_endp (s);
  lsah->length = htons (length);

  /* Now, create OSPF LSA instance. */
  new = ospf_lsa_new ();
  new->area = area;
  SET_FLAG (new->flags, OSPF_LSA_SELF);

  /* Copy LSA data to store, discard stream. */
  new->data = ospf_lsa_data_new (length);
  memcpy (new->data, lsah, length);
  stream_free (s);

  /* Calculate Checksum. */
  ospf_lsa_checksum (new->data);

  if (new->data->adv_router.s_addr == 0)
    {
      zlog_info ("LSA[Type1]: AdvRouter is 0, discard");
      ospf_lsa_free (new);
      return NULL;
    }

  /* Install LSA to LSDB. */
  new = ospf_router_lsa_install (area, new);

  /* Flooding new LSA through area. */
  ospf_flood_through_area (area, NULL, new);

  if (IS_DEBUG_OSPF (lsa, LSA_GENERATE))
    {
      zlog_info ("LSA[Type1]: Originate router-LSA %x", new);
      ospf_lsa_header_dump (new->data);
    }

  return new;
}

#if 0
/* Flush a router-LSA from LSDB and routing domain. */
void
ospf_router_lsa_flush ()
{
  if (IS_DEBUG_OSPF (lsa, LSA_FLOODING))
    zlog_info ("LSA: Flushing router-LSA");

  /* First lookup LSA from LSDB. */
}
#endif

/* Originate Network-LSA. */
#if 1
void
ospf_network_lsa_body_set (struct stream *s, struct ospf_interface *oi)
{
  struct in_addr mask;
  struct route_node *rn;
  struct ospf_neighbor *nbr;

  masklen2ip (oi->address->prefixlen, &mask);
  stream_put_ipv4 (s, mask.s_addr);

  for (rn = route_top (oi->nbrs); rn; rn = route_next (rn))
    if ((nbr = rn->info) != NULL)
      stream_put_ipv4 (s, nbr->router_id.s_addr);
}

struct ospf_lsa *
ospf_network_lsa (struct ospf_interface *oi)
{
  struct stream *s;
  struct ospf_lsa *new, *old = NULL;
  struct lsa_header *lsah;
  int options;
  int length;

  /* If there are no neighbours on this network (the net is stub),
     the router does not originate network-LSA (see RFC 12.4.2) */
  if (oi->full_nbrs == 0)
    return NULL;
  
  if (IS_DEBUG_OSPF (lsa, LSA_GENERATE))
    zlog_info ("LSA[Type2]: Originate network-LSA start");

  /* Create new stream for LSA. */
  s = stream_new (OSPF_MAX_LSA_SIZE);
  lsah = (struct lsa_header *) STREAM_DATA (s);

  options = OPTIONS (oi) | (oi->area->external_routing == OSPF_AREA_DEFAULT ?
			    OSPF_OPTION_E : 0);
  ospf_lsa_header_set (s, 0, options, OSPF_NETWORK_LSA, DR (oi));

  old = oi->network_lsa_self;
  if (old != NULL)
    {
      lsa_seqnum_increment (old->data);
      lsah->ls_seqnum = old->data->ls_seqnum;
    }

  /* Set network-LSA body fields. */
  ospf_network_lsa_body_set (s, oi);

  /* Set length. */
  length = stream_get_endp (s);
  lsah->length = htons (length);

  /* Create OSPF LSA instance. */
  new = ospf_lsa_new ();
  new->area = oi->area;
  SET_FLAG (new->flags, OSPF_LSA_SELF);

  /* Copy LSA to store. */
  new->data = ospf_lsa_data_new (length);
  memcpy (new->data, lsah, length);
  stream_free (s);

  /* Set Checksum. */
  ospf_lsa_checksum (new->data);
  if (IS_DEBUG_OSPF (lsa, LSA_GENERATE))
    zlog_info ("LSA[Type%d:%s]: Originate 0x%x for area %x",
	       new->data->type, inet_ntoa (new->data->id),
	       ntohl (new->data->ls_seqnum), oi->area->area_id.s_addr);

  if (IS_DEBUG_OSPF (lsa, LSA_GENERATE))
    {
      zlog_info ("LSA[Type2]: Originate network-LSA %x", new);
      ospf_lsa_header_dump (new->data);
    }

  return new;
}
#else
struct ospf_lsa *
ospf_network_lsa (struct ospf_interface *oi)
{
  struct ospf *ospf = oi->ospf;
  struct ospf_lsa *new, *old;
  struct lsa_header *lsah;
  struct in_addr mask;
  struct route_node *rn;
  struct stream *s;
  struct ospf_neighbor *nbr;
  int length;
  u_int32_t seqnum;

  /* If there are no neighbours on this network (the net is stub),
     the router does not originate NetworkLSA (see RFC 12.4.2) */
  if (oi->full_nbrs == 0)
    return NULL ;
  
  if (IS_OSPF_DEBUG (lsa, LSA_GENERATE))
    zlog_info ("LSA: Originate network-LSA start");

  ospf = oi->ospf;

  s = stream_new (oi->ifp->mtu);
  lsah = (struct lsa_header *) STREAM_DATA (s);

  lsah->ls_age = 0;
  lsah->options = OPTIONS (oi);

  if (oi->area->external_routing == OSPF_AREA_DEFAULT)
    SET_FLAG (lsah->options, OSPF_OPTION_E);
  else
    UNSET_FLAG (lsah->options, OSPF_OPTION_E);

  lsah->type = (u_char) OSPF_NETWORK_LSA;
  lsah->id = DR (oi);
  lsah->adv_router = ospf->router_id;

  old = oi->network_lsa_self;
  if (old)
    {
      seqnum = ntohl (old->data->ls_seqnum) + 1;
      lsah->ls_seqnum = htonl (seqnum);
    }
  else
    lsah->ls_seqnum = htonl (OSPF_INITIAL_SEQUENCE_NUMBER);

  ospf_output_forward (s, OSPF_LSA_HEADER_SIZE);
  length = OSPF_LSA_HEADER_SIZE;

  masklen2ip (oi->address->prefixlen, &mask);

  /* Put Network Mask. */
  stream_put_ipv4 (s, mask.s_addr);
  length += 4;

  for (rn = route_top (oi->nbrs); rn; rn = route_next (rn))
    if ((nbr = rn->info) != NULL)
      {
	stream_put_ipv4 (s, nbr->router_id.s_addr);
	length += 4;
      }

  /* Set length. */
  lsah->length = htons (length);

  /* Set Checksum. */
  ospf_lsa_checksum (lsah);

  /* Create OSPF LSA instance. */
  new = ospf_lsa_new ();
  new->area = oi->area;
  if (IS_DEBUG_OSPF (lsa, LSA_GENERATE))
    zlog_info("Z: ospf_lsa_new() in ospf_network_lsa(): %x", new);
  SET_FLAG (new->flags, OSPF_LSA_SELF);

  /* Copy LSA to store. */
  new->data = ospf_lsa_data_new (length);
  memcpy (new->data, lsah, length);
  stream_free (s);

  if (IS_DEBUG_OSPF (lsa, LSA_GENERATE))
    zlog_info ("Originate network-LSA sequence number 0x%x",
             ntohl (new->data->ls_seqnum));

  return new;
}
#endif

/* Originate Summary-LSA. */
struct ospf_lsa *
ospf_summary_lsa (struct prefix_ipv4 *p, u_int32_t metric, 
                  struct ospf_area *for_area, struct ospf_lsa *old)
{
  struct ospf_lsa *new;
  struct lsa_header *lsah;
  struct in_addr mask;
  struct stream *s;
  int length;
  char *mp;
  u_int32_t seqnum;

  s = stream_new (OSPF_MAX_LSA_SIZE);
  lsah = (struct lsa_header *) STREAM_DATA (s);

  lsah->ls_age = 0;

  lsah->options = 0;

  if (for_area->external_routing == OSPF_AREA_DEFAULT)
    SET_FLAG (lsah->options, OSPF_OPTION_E);
  else
    UNSET_FLAG (lsah->options, OSPF_OPTION_E);

  lsah->type = (u_char) OSPF_SUMMARY_LSA;

  /* We should take care about host bits here */

  if (old)
    lsah->id = old->data->id;
  else
    lsah->id = ospf_lsa_unique_id (for_area->lsdb, OSPF_SUMMARY_LSA, p);
#if 0
    lsah->id = ospf_get_free_id_for_prefix (SUMMARY_LSA (for_area), p,
                                            ospf_top->router_id);
#endif

  lsah->adv_router = ospf_top->router_id;

  if (old)
    {
      seqnum = ntohl (old->data->ls_seqnum) + 1;
      lsah->ls_seqnum = htonl (seqnum);
    }
  else
    lsah->ls_seqnum = htonl (OSPF_INITIAL_SEQUENCE_NUMBER);

  ospf_output_forward (s, OSPF_LSA_HEADER_SIZE);
  length = OSPF_LSA_HEADER_SIZE;

  masklen2ip (p->prefixlen, &mask);

  /* Put Network Mask. */
  stream_put_ipv4 (s, mask.s_addr);
  length += 4;

  stream_putc (s, (u_char) 0);          /* # TOS. */
  length += 1;

  metric = htonl (metric);
  mp = (char *) &metric;
  mp++;
  stream_put(s, mp, 3);
  length += 3;

  /* Set length. */
  lsah->length = htons (length);

  /* Set Checksum. */
  ospf_lsa_checksum (lsah);

  /* Create OSPF LSA instance. */
  new = ospf_lsa_new ();
  new->area = for_area;
  
  if (IS_DEBUG_OSPF (lsa, LSA_GENERATE))
    zlog_info("Z: ospf_lsa_new() in ospf_summary_lsa(): %x", new);
  SET_FLAG (new->flags, OSPF_LSA_SELF);

  /* Copy LSA to store. */
  new->data = ospf_lsa_data_new (length);
  memcpy (new->data, lsah, length);
  stream_free (s);

  if (IS_DEBUG_OSPF (lsa, LSA_GENERATE))
    zlog_info ("Originate summary-LSA sequence number 0x%x",
	       ntohl (lsah->ls_seqnum));

  return new;
}

/* Originate summary-ASBR-LSA. */
struct ospf_lsa *
ospf_summary_asbr_lsa (struct prefix_ipv4 *p, u_int32_t metric, 
                       struct ospf_area *for_area, struct ospf_lsa *old)
{
  struct ospf_lsa *new;
  struct lsa_header *lsah;
  struct in_addr mask;
  struct stream *s;
  int length;
  char *mp;
  u_int32_t seqnum;

  s = stream_new (OSPF_MAX_LSA_SIZE);
  lsah = (struct lsa_header *) STREAM_DATA (s);

  lsah->ls_age = 0;

  lsah->options = 0;

  if (for_area->external_routing == OSPF_AREA_DEFAULT)
    SET_FLAG (lsah->options, OSPF_OPTION_E);
  else
    UNSET_FLAG (lsah->options, OSPF_OPTION_E);

  lsah->type = (u_char) OSPF_SUMMARY_LSA_ASBR;
  lsah->id.s_addr = p->prefix.s_addr;
  lsah->adv_router = ospf_top->router_id;

  if (old)
    {
      seqnum = ntohl (old->data->ls_seqnum) + 1;
      lsah->ls_seqnum = htonl (seqnum);
    }
  else
    lsah->ls_seqnum = htonl (OSPF_INITIAL_SEQUENCE_NUMBER);

  ospf_output_forward (s, OSPF_LSA_HEADER_SIZE);
  length = OSPF_LSA_HEADER_SIZE;

  mask.s_addr = 0;

  /* Put Network Mask. */
  stream_put_ipv4 (s, mask.s_addr);
  length += 4;

  stream_putc (s, (u_char) 0);          /* # TOS. */
  length += 1;

  metric = htonl (metric);
  mp = (char *) &metric;
  mp++;
  stream_put(s, mp, 3);
  length += 3;

  /* Set length. */
  lsah->length = htons (length);

  /* Set Checksum. */
  ospf_lsa_checksum (lsah);

  /* Create OSPF LSA instance. */
  new = ospf_lsa_new ();
  new->area = for_area;
  if (IS_DEBUG_OSPF (lsa, LSA_GENERATE))
    zlog_info ("Z: ospf_lsa_new() in ospf_asbr_summary_lsa(): %x", new);
  SET_FLAG (new->flags, OSPF_LSA_SELF);

  /* Copy LSA to store. */
  new->data = ospf_lsa_data_new (length);
  memcpy (new->data, lsah, length);
  stream_free (s);

  if (IS_DEBUG_OSPF (lsa, LSA_GENERATE))
    zlog_info ("Originate ASBR-summary-LSA sequence number 0x%x",
	       ntohl (lsah->ls_seqnum));

  return new;
}

/* Get nexthop for AS-external-LSAs. */
struct in_addr
ospf_external_lsa_nexthop_get (struct in_addr nexthop)
{
  struct in_addr fwd;
  struct prefix nh;
  struct route_node *rn;

  fwd.s_addr = 0;

  if (!nexthop.s_addr)
    return fwd;

  /* Check whether nexthop is covered by OSPF network. */
  nh.family = AF_INET;
  nh.u.prefix4 = nexthop;
  nh.prefixlen = IPV4_MAX_BITLEN;

  for (rn = route_top (ospf_top->networks); rn; rn = route_next (rn))
    if (rn->info)
      if (prefix_match (&rn->p, &nh))
	return nexthop;

  return fwd;
}

#if 0
/* Get forward address. */
int
ospf_forward_address_get (struct in_addr nexthop, struct in_addr *fwd_addr)
{
  listnode nh_node;
  struct ospf_interface *oi;
  struct ospf_path *path, *direct_path = NULL;
  struct prefix nh;
  struct route_node *rn;
  struct ospf_route *or;

  fwd_addr->s_addr = 0;

  if (!nexthop.s_addr)
    return 0;

  if (!ospf_top->new_table)
    return 0;

  /* Check if the nexthop is covered by OSPF routing table. */
  nh.family = AF_INET;
  nh.u.prefix4.s_addr = nexthop.s_addr;
  nh.prefixlen = IPV4_MAX_BITLEN;

  if ((rn = route_node_match (ospf_top->new_table, &nh)) == NULL)
    return 0;

  if (IS_DEBUG_OSPF (lsa, LSA_GENERATE))
    zlog_info ("Z: ospf_external_lsa(): found a route to nexthop");
  or = rn->info;
  route_unlock_node (rn);

  if (or->path_type != OSPF_PATH_INTRA_AREA)
    {
      if (IS_DEBUG_OSPF (lsa, LSA_GENERATE))
	zlog_info ("Z: ospf_external_lsa(): "
		   "but it's not intra-area, sorry");
      return 0;
    }

  for (nh_node = listhead (or->path); nh_node; nextnode (nh_node))
    if ((path = getdata (nh_node)) != NULL)
      {
	if (path->nexthop.s_addr != 0)
	  {
	    if (IS_DEBUG_OSPF (lsa, LSA_GENERATE))
	      zlog_info ("Z: ospf_external_lsa(): "
			 "route is known as remote, not ok");
	    return 0;
	  }
	direct_path = path;
      }

  /* Now check if we know this path from OSPF. */
  if (direct_path)
    {
      if ((oi = direct_path->ifp->info) == NULL) 
	return 0;

      if (ospf_nbr_lookup_by_addr (oi->nbrs, &nexthop) == NULL)
	{
	  if (IS_DEBUG_OSPF (lsa, LSA_GENERATE))
	    zlog_info("Z: ospf_external_lsa(): "
		      "nexthop is known from OSPF, not OK");
	  return 0;
	}
    }

  if (IS_DEBUG_OSPF (lsa, LSA_GENERATE))
    zlog_info ("Z: ospf_external_lsa(): nexthop is ok, setting");
  fwd_addr->s_addr = nexthop.s_addr;

  return 1;
}
#endif


int
metric_type (u_char src)
{
  return ospf_top->dmetric[src].type;
}

int
metric_value (u_char src)
{
  if (ospf_top->dmetric[src].method == OSPF_EXT_METRIC_AUTO)
    return 1;

  return ospf_top->dmetric[src].value;
}

/* Set AS-external-LSA body. */
void
ospf_external_lsa_body_set (struct stream *s, u_char type,
			    struct prefix_ipv4 *p, struct in_addr nexthop)
{
  struct in_addr mask, fwd_addr;
  char *mp;
  u_int32_t metric;

  /* Put Network Mask. */
  masklen2ip (p->prefixlen, &mask);
  stream_put_ipv4 (s, mask.s_addr);

  /* Put type of external metric. */
  stream_putc (s, (metric_type (type) == EXTERNAL_METRIC_TYPE_2 ? 0x80 : 0));

  /* Put 0 metric. TOS metric is not supported. */
  metric = htonl (metric_value (type));
  mp = (char *) &metric;
  mp++;
  stream_put (s, mp, 3);
  
  /* Get forwarding address. */
  fwd_addr = ospf_external_lsa_nexthop_get (nexthop);

  /* Put forwarding address. */
  stream_put_ipv4 (s, fwd_addr.s_addr);
  
  /* Put route tag -- This value should be introduced from configuration. */
  stream_putl (s, 0);
}

/* Originate an AS-external-LSA, install and flood. */
struct ospf_lsa *
ospf_external_lsa_originate (u_char type, struct external_info *ei)
{
  struct stream *s;
  struct lsa_header *lsah;
  struct ospf_lsa *new;
  struct in_addr id;
  int length;

  if (IS_DEBUG_OSPF (lsa, LSA_GENERATE))
    zlog_info ("LSA[Type5]: Originate AS-external-LSA start");

  /* Get Link State ID. */
  id = ospf_lsa_unique_id (ospf_top->external_lsa,
			   OSPF_AS_EXTERNAL_LSA, &ei->p);
  if (id.s_addr == 0)
    {
      /* Maybe Link State ID not available. */
      if (IS_DEBUG_OSPF (lsa, LSA_GENERATE))
	zlog_info ("LSA[Type5]: Link ID not available, can't originate");
      return NULL;
    }

  /* Create new stream for LSA. */
  s = stream_new (OSPF_MAX_LSA_SIZE);
  lsah = (struct lsa_header *) STREAM_DATA (s);

  /* Set LSA common header fields. */
  ospf_lsa_header_set (s, 0, OSPF_OPTION_E, OSPF_AS_EXTERNAL_LSA, id);

  /* Set AS-external-LSA body fields. */
  ospf_external_lsa_body_set (s, type, &ei->p, ei->nexthop);

  /* Set length. */
  length = stream_get_endp (s);
  lsah->length = htons (length);

  /* Now, create OSPF LSA instance. */
  new = ospf_lsa_new ();
  SET_FLAG (new->flags, OSPF_LSA_SELF);

  /* Copy LSA data to store, discard stream. */
  new->data = ospf_lsa_data_new (length);
  memcpy (new->data, lsah, length);
  stream_free (s);

  /* Some flags set. */
  new->flags |= OSPF_LSA_APPROVED;
  new->redistribute = type;

  /* Calculate Checksum. */
  ospf_lsa_checksum (new->data);

  /* Install LSA to LSDB. */
  ospf_external_lsa_install (new);

  /* Flooding new LSA. */
  ospf_flood_through_as (NULL, new);

  /* Debug logging. */
  if (IS_DEBUG_OSPF (lsa, LSA_GENERATE))
    {
      zlog_info ("LSA: Originate AS-external-LSA %x", new);
      ospf_lsa_header_dump (new->data);
    }

  return new;
}

/* Originate AS-external-LSA from external info with initial flag. */
int
ospf_external_lsa_originate_timer (struct thread *t)
{
  struct route_node *rn;
  struct external_info *ei;
  struct route_table *rt;
  int type;

  ospf_top->t_external_origin = NULL;

  /* Originate As-external-LSA from all type of distribute source. */
  for (type = 0; type < ZEBRA_ROUTE_MAX; type++)
    if ((rt = EXTERNAL_INFO (type)))
      for (rn = route_top (rt); rn; rn = route_next (rn))
	if ((ei = rn->info) != NULL)
	  {
	    /* Check distribute-list. */
	    if (ospf_distribute_check (type, &ei->p))
	      {
		if (ei->flags == EXTERNAL_INITIAL)
		  {
		    if (ospf_external_lsa_originate (type, ei))
		      ei->flags = EXTERNAL_ORIGINATED;
		    else
		      zlog_warn ("LSA: AS-external-LSA was not originated.");
		  }
	      }
	    else
	      ei->flags = EXTERNAL_FILTERED;
	  }
  return 0;
}

/* Flush an AS-external-LSA from LSDB and routing domain. */
void
ospf_external_lsa_flush (u_char type, struct prefix_ipv4 *p,
			 unsigned int ifindex, struct in_addr nexthop)
{
  struct ospf_lsa *lsa;
  struct as_external_lsa *al;
  struct in_addr mask, id;

  if (IS_DEBUG_OSPF (lsa, LSA_FLOODING))
    zlog_info ("LSA: Flushing AS-external-LSA %s/%d",
	       inet_ntoa (p->prefix), p->prefixlen);

  /* First lookup LSA from LSDB. */
  lsa = new_lsdb_lookup_by_id (ospf_top->external_lsa, OSPF_AS_EXTERNAL_LSA,
			       p->prefix, ospf_top->router_id);
  if (!lsa)
    {
      if (IS_DEBUG_OSPF (lsa, LSA_FLOODING))
	zlog_warn ("LSA: There is no such AS-external-LSA %s/%d in LSDB",
		   inet_ntoa (p->prefix), p->prefixlen);
      return;
    }

  al = (struct as_external_lsa *) lsa->data;

  masklen2ip (p->prefixlen, &mask);
  if (mask.s_addr != al->mask.s_addr)
    {
      id.s_addr = p->prefix.s_addr | (~mask.s_addr);
      lsa = new_lsdb_lookup_by_id (ospf_top->external_lsa,
				   OSPF_AS_EXTERNAL_LSA, id,
				   ospf_top->router_id);
      if (!lsa)
	{
	  if (IS_DEBUG_OSPF (lsa, LSA_FLOODING))
	    zlog_warn ("LSA: There is no such AS-external-LSA %s/%d in LSDB",
		       inet_ntoa (p->prefix), p->prefixlen);
	  return;
	}
    }

  /* Sweep LSA from Link State Retransmit List. */
  ospf_ls_retransmit_delete_nbr_all (NULL, lsa);

  /* Unregister LSA from Refresh queue. */
  if (LS_AGE (lsa) != OSPF_LSA_MAX_AGE)
    ospf_refresher_unregister_lsa (lsa);

  /* There must be no self-originated LSA in rtrs_external. */
#if 0
  /* Remove External route from Zebra. */
  ospf_zebra_delete ((struct prefix_ipv4 *) p, &nexthop);
#endif

  /* Flush AS-external-LSA through AS. */
  if (LS_AGE (lsa) != OSPF_LSA_MAX_AGE)
    ospf_flush_through_as (lsa);

  if (IS_DEBUG_OSPF (lsa, LSA_FLOODING))
    zlog_info ("ospf_external_lsa_flush(): stop");
}

struct ospf_lsa *
ospf_external_lsa_refresh (struct ospf_lsa *lsa)
{
  /* Sanity check. */
  assert (lsa->data);

  if (IS_DEBUG_OSPF (lsa, LSA_GENERATE))
    zlog_info ("LSA[Type%d:%s]: AS-external-LSA refresh start",
	       lsa->data->type, inet_ntoa (lsa->data->id));

  ospf_ls_retransmit_delete_nbr_all (NULL, lsa);

  /* Unregister AS-external-LSA from refresh-list. */
  if (CHECK_FLAG (lsa->flags, OSPF_LSA_SELF))
    if (lsa->refresh_list)
      ospf_refresher_unregister_lsa (lsa);

  /* Increment LS Seqnum. */
  lsa_seqnum_increment (lsa->data);

  /* Reset LS age. */
  lsa->data->ls_age = ntohs (0);

  /* Record timestamp. */
  /* lsa->tv_recv = time (NULL); */
  gettimeofday (&lsa->tv_recv, NULL);
  lsa->tv_orig = lsa->tv_recv;

  /* Re-calculate checksum. */
  ospf_lsa_checksum (lsa->data);

  /* Flood LSA through AS. */
  ospf_flood_through_as (NULL, lsa);

  /* Register slef-originated LSA to refresh queue. */
  if (CHECK_FLAG (lsa->flags, OSPF_LSA_SELF))
    ospf_refresher_register_lsa (ospf_top, lsa);

  /* Debug logging. */
  if (IS_DEBUG_OSPF (lsa, LSA_GENERATE))
    ospf_lsa_header_dump (lsa->data);

  return NULL;
}


/* Callback function for router-LSA origination. */
#if 0
int
ospf_router_lsa_refresh (struct thread *t)
{
  struct ospf_area *area;
  struct ospf_lsa *lsa;

  if (IS_DEBUG_OSPF (lsa, LSA_GENERATE))
    zlog_info ("LSA[Refresh]: router-LSA");

  area = THREAD_ARG (t);
  area->t_router_lsa_self = NULL;

  lsa = ospf_router_lsa (area);
  if (lsa->data->adv_router.s_addr == 0)
    {
      zlog_info ("LSA[Refresh]: AdvRouter is 0, discard.");
      ospf_lsa_free (lsa);
      return 0;
    }

  lsa = ospf_router_lsa_install (area, lsa);
  ospf_flood_through_area (area, NULL, lsa);

  return 0;
}
#else
struct ospf_lsa *
ospf_router_lsa_refresh (struct ospf_area *area, struct ospf_lsa *lsa)
{
  struct ospf_lsa *new;

  if (IS_DEBUG_OSPF (lsa, LSA_GENERATE))
    zlog_info ("LSA[Type%d:%s]: router-LSA refresh",
	       lsa->data->type, inet_ntoa (lsa->data->id));

  /* Sanity check. */
  assert (lsa->data);

  /* */
  ospf_ls_retransmit_delete_nbr_all (area, lsa);

  /* Increment LS Seqnum. */
  /* lsa_seqnum_increment (lsa->data); */

  new = ospf_router_lsa_originate (area, lsa);

#if 0
  /* Re-calculate checksum. */
  ospf_lsa_checksum (lsa->data);

  /* Flood LSA through area. */
  ospf_flood_through_area (area, NULL, lsa);
#endif

  /* Debug logging. */
  if (IS_DEBUG_OSPF (lsa, LSA_GENERATE))
    ospf_lsa_header_dump (new->data);

  return NULL;
}

int
ospf_router_lsa_refresh_timer (struct thread *t)
{
  struct ospf_area *area;
  struct ospf_lsa *lsa;

  zlog_info ("LSA[Refresh]: Timer (router-LSA Refresh expire)");

  area = THREAD_ARG (t);
  area->t_router_lsa_self = NULL;

  if ((lsa = area->router_lsa_self))
    /* Now refresh router-LSA. */
    ospf_router_lsa_refresh (area, lsa);
  else
    /* Newly originate router-LSA. */
    ospf_router_lsa_originate (area, NULL);

  return 0;
}

#endif

int
ospf_network_lsa_refresh (struct thread *t)
{
  struct ospf_interface *oi;
  struct ospf_lsa *lsa;

  oi = THREAD_ARG (t);
  oi->t_network_lsa_self = NULL;

  lsa = ospf_network_lsa (oi);
  if (lsa == NULL)
    return 0 ;

  if (IS_DEBUG_OSPF (lsa, LSA_GENERATE))
    zlog_info ("LSA[Type%d:%s]: network-LSA refresh",
	       lsa->data->type, inet_ntoa (lsa->data->id));

  lsa = ospf_network_lsa_install (oi, lsa);
  ospf_flood_through_area (oi->area, NULL, lsa);

  return 0;
}

void
ospf_summary_lsa_refresh (struct ospf_lsa * lsa)
{
  struct ospf_area *area = lsa->area;
  struct prefix_ipv4 p;
  struct summary_lsa * slsa = (struct summary_lsa *) lsa->data;

  assert (lsa);
  assert (area);

  if (IS_DEBUG_OSPF (lsa, LSA_GENERATE))
    zlog_info ("LSA[Type%d:%s]: summary-LSA refresh",
	       lsa->data->type, inet_ntoa (lsa->data->id));

  p.family = AF_INET;
  p.prefix = slsa->header.id;
  p.prefixlen = ip_masklen (slsa->mask);
  apply_mask_ipv4 (&p);

  lsa = ospf_summary_lsa (&p, GET_METRIC (slsa->metric), area, lsa);
  lsa = ospf_summary_lsa_install (area, lsa);

  ospf_flood_through_area (area, NULL, lsa);
}

void
ospf_summary_lsa_asbr_refresh (struct ospf_lsa * lsa)
{
  struct ospf_area *area = lsa->area;
  struct prefix_ipv4 p;
  struct summary_lsa *slsa = (struct summary_lsa *) lsa->data;

  assert (area);

  if (IS_DEBUG_OSPF (lsa, LSA_GENERATE))
    zlog_info ("LSA[Type%d:%s]: summary-ASBR-LSA refresh",
	       lsa->data->type, inet_ntoa (lsa->data->id));

  p.family = AF_INET;
  p.prefix = slsa->header.id;
  p.prefixlen = IPV4_MAX_BITLEN;

  lsa = ospf_summary_asbr_lsa (&p, GET_METRIC (slsa->metric), area, lsa);
  lsa = ospf_summary_asbr_lsa_install (area, lsa);

  ospf_flood_through_area (area, NULL, lsa);
}


/* Install router-LSA to an area. */
struct ospf_lsa *
ospf_router_lsa_install (struct ospf_area *area, struct ospf_lsa *new)
{
  struct ospf_lsa *lsa;

  /* Install new instance. */
  lsa = new_lsdb_insert (area->lsdb, new);
  lsa->lsdb = area->lsdb;
  assert (lsa->lsdb);

  /* LSA was replaced. */
  if (lsa != NULL)
    new = lsa;

  /* Schedule SPF calculation. */
  ospf_spf_calculate_schedule ();

  if (IS_DEBUG_OSPF (lsa, LSA_FLOODING))
    zlog_info("LSA[Type%d]: Area %s",
	      new->data->type, inet_ntoa (area->area_id));

  if (CHECK_FLAG (new->flags, OSPF_LSA_SELF)) 
    {
      /* Set router-LSA refresh timer. */
      OSPF_TIMER_OFF (area->t_router_lsa_self);
      OSPF_AREA_TIMER_ON (area->t_router_lsa_self,
			  ospf_router_lsa_refresh_timer, OSPF_LS_REFRESH_TIME);
      
      /* Set self-originated router-LSA. */
      area->router_lsa_self = new;

      if (IS_DEBUG_OSPF (lsa, LSA_FLOODING))
	zlog_info("LSA[Type%d]: ID %s is self-originated",
		  new->data->type, inet_ntoa (new->data->id));
    }

  if (IS_DEBUG_OSPF (lsa, LSA_FLOODING))
    zlog_info ("LSA[Type%d:%s]: Install router-LSA",
	       new->data->type, inet_ntoa (new->data->id));

  return new;
}

/* Install network-LSA to an area. */
struct ospf_lsa *
ospf_network_lsa_install (struct ospf_interface *oi, struct ospf_lsa *new)
{
  struct ospf_lsa *lsa;

  /* Add new LSA to lsdb. */
  /* lsa = ospf_lsdb_add (NETWORK_LSA (oi->area), new); */
  lsa = new_lsdb_insert ((struct new_lsdb *) oi->area->lsdb, new);

  /* Set lsdb pointer to the lsa. */
  lsa->lsdb = oi->area->lsdb;

  /* Schedule SPF calculation. */
  ospf_spf_calculate_schedule ();

  /* We supposed that when LSA is originated by us, we pass the int
     for which it was originated. If LSA was received by flooding,
     the RECEIVED flag is set, so we do not link the LSA to the int. */

  if (CHECK_FLAG (lsa->flags, OSPF_LSA_SELF) &&
      !CHECK_FLAG (lsa->flags, OSPF_LSA_RECEIVED))
    {
      /* Set LSRefresh timer. */
      if (oi->t_network_lsa_self)
        OSPF_TIMER_OFF (oi->t_network_lsa_self);

      oi->t_network_lsa_self = 
        thread_add_timer (master, ospf_network_lsa_refresh,
                          oi, OSPF_LS_REFRESH_TIME);
      
      oi->network_lsa_self = lsa;
    }

  if (IS_DEBUG_OSPF (lsa, LSA_FLOODING))
    zlog_info ("Install network-LSA %s", inet_ntoa (lsa->data->id));

  return lsa;
}

/* Install summary-LSA to an area. */
struct ospf_lsa *
ospf_summary_lsa_install (struct ospf_area *area, struct ospf_lsa *new)
{
#if 0
  struct route_node *rn;
  struct prefix p;
#endif /* 0 */
  struct ospf_lsa *lsa = NULL;

  if (IS_DEBUG_OSPF (lsa, LSA_FLOODING))
    zlog_info ("Z: ospf_summary_lsa_install(): Start");

  /* lsa = ospf_lsdb_add (SUMMARY_LSA (area), new); */
  lsa = new_lsdb_insert (area->lsdb, new);

  if (IS_DEBUG_OSPF (lsa, LSA_FLOODING))
    zlog_info ("Z: ospf_summary_lsa_install(): setting lsa->lsdb");

  lsa->lsdb = area->lsdb;

  if (IS_DEBUG_OSPF (lsa, LSA_FLOODING))
    zlog_info ("Z: ospf_summary_lsa_install(): Well done !");

  /* Schedule SPF calculation. */
  if (!CHECK_FLAG (lsa->flags, OSPF_LSA_SELF))
    ospf_spf_calculate_schedule ();

  if (IS_DEBUG_OSPF (lsa, LSA_FLOODING))
    zlog_info ("Z: ospf_summary_lsa_install(): SPF scheduled");

#if 0
  if (CHECK_FLAG (lsa->flags, OSPF_LSA_SELF))
    {
      p.family = AF_INET;
      p.prefixlen = IPV4_MAX_BITLEN;
      p.u.prefix4 = lsa->data->id;

      zlog_info("Z: ospf_summary_lsa_install(): It is self-originated");
      rn = route_node_get (area->summary_lsa_self, &p);
      rn->info = lsa;
      zlog_info("Z: ospf_summary_lsa_install(): Installed into the list");
    }
#endif /* 0 */

  if (CHECK_FLAG (lsa->flags, OSPF_LSA_SELF))
    ospf_refresher_register_lsa (ospf_top, lsa);

  if (IS_DEBUG_OSPF (lsa, LSA_FLOODING))
    zlog_info ("Install summary-LSA %s", inet_ntoa (lsa->data->id));

  return lsa;
}

/* Install ASBR-summary-LSA to an area. */
struct ospf_lsa *
ospf_summary_asbr_lsa_install (struct ospf_area *area, struct ospf_lsa *new)
{
#if 0
  struct route_node *rn;
  struct prefix p;
#endif /* 0 */
  struct ospf_lsa *lsa = NULL;
  
  /* lsa = ospf_lsdb_add (SUMMARY_LSA_ASBR (area), new); */
  lsa = new_lsdb_insert (area->lsdb, new);
  lsa->lsdb = area->lsdb;

  /* Schedule SPF calculation. */
  ospf_spf_calculate_schedule ();

#if 0
  if (CHECK_FLAG (lsa->flags, OSPF_LSA_SELF))
    {
      p.family = AF_INET;
      p.prefixlen = IPV4_MAX_BITLEN;
      p.u.prefix4 = lsa->data->id;

      rn = route_node_get (area->summary_lsa_asbr_self, &p);
      rn->info = lsa;
    }
#endif /* 0 */

  if (CHECK_FLAG (lsa->flags, OSPF_LSA_SELF))
    ospf_refresher_register_lsa (ospf_top, lsa);

  if (IS_DEBUG_OSPF (lsa, LSA_FLOODING))
    zlog_info ("Install ASBR-summary-LSA %s", inet_ntoa (lsa->data->id));

  return lsa;
}

/* Install AS-external-LSA. */
struct ospf_lsa *
ospf_external_lsa_install (struct ospf_lsa *new)
{
  struct ospf_lsa *lsa = NULL;
  
  if (IS_DEBUG_OSPF (lsa, LSA_FLOODING))
    zlog_info ("LSA[Install]: AS-external-LSA %x", new);

  /* Insert new LSA to LSDB. */
  lsa = new_lsdb_insert (ospf_top->external_lsa, new); 
  lsa->lsdb = ospf_top->external_lsa;
  assert (lsa->lsdb);

  /* LSA was replaced. */
  if (lsa != NULL)
    new = lsa;

  if (!CHECK_FLAG (new->flags, OSPF_LSA_SELF))
    ospf_ase_rtrs_register_lsa (new);
  /* If LSA is not self-originated, calculate an external route. */
  if (!CHECK_FLAG (new->flags, OSPF_LSA_SELF))
    ospf_ase_calculate (new, ospf_top->new_table, ospf_top->new_rtrs);
  /* Register self-originated LSA to refresh queue. */
  else
    ospf_refresher_register_lsa (ospf_top, new);

  return new;
}

int
ospf_check_nbr_status ()
{
  listnode node;

  for (node = listhead (ospf_top->iflist); node; node = nextnode (node))
    {
      struct interface *ifp = getdata (node);
      struct ospf_interface *oi = ifp->info;
      struct route_node *rn;
      struct ospf_neighbor *nbr;

      if (ospf_if_is_enable (ifp))
	for (rn = route_top (oi->nbrs); rn; rn = route_next (rn))
          if ((nbr = rn->info) != NULL)
	    if (nbr->status == NSM_Exchange || nbr->status == NSM_Loading)
	      {
		route_unlock_node (rn);
		return 0;
	      }
    }

  return 1;
}


/* Remove related LSA from rtrs_external. */
void
ospf_rtrs_external_remove (struct in_addr id, struct in_addr adv_router)
{
  struct prefix_ipv4 p, q;
  struct route_node *rn1, *rn2;

  /* First, lookup table by AdvRouter. */
  p.family = AF_INET;
  p.prefixlen = IPV4_MAX_BITLEN;
  p.prefix = adv_router;

  rn1 = route_node_get (ospf_top->rtrs_external, (struct prefix *) &p);
  if (rn1->info != NULL)
    {
      route_unlock_node (rn1);

      /* Second, lookup table by Link State ID. */
      q.family = AF_INET;
      q.prefixlen = IPV4_MAX_BITLEN;
      q.prefix = id;

      rn2 = route_node_get (rn1->info, (struct prefix *) &q);
      if (rn2->info != NULL)
	{
	  rn2->info = NULL;
	  route_unlock_node (rn2);
	  route_unlock_node (rn2);
	}
    }      
}


int
ospf_maxage_lsa_remover (struct thread *thread)
{
  listnode node;
  listnode next;
  struct ospf_lsa *lsa;
  u_int left = 0;

  ospf_top->t_maxage = NULL;

  if (IS_DEBUG_OSPF (lsa, LSA_FLOODING))
    zlog_info ("LSA[MaxAge]: remover Start");

  if (ospf_check_nbr_status ())
    {
      for (node = listhead (ospf_top->maxage_lsa); node; node = next)
        {
          lsa = getdata (node);
          next = node->next;

          if (lsa->ref == 0)
            {
              /* Remove LSA from the LSDB */
	      if (IS_DEBUG_OSPF (lsa, LSA_FLOODING))
		{
		  zlog_info ("LSA[Type%d:%s]: This LSA is no more referenced",
			     lsa->data->type, inet_ntoa (lsa->data->id));
		}
              if (CHECK_FLAG (lsa->flags, OSPF_LSA_SELF))
		if (IS_DEBUG_OSPF (lsa, LSA_FLOODING))
                  zlog_info ("LSA[Type%d:%s]: This LSA is self-oririnated: ",
                             lsa->data->type, inet_ntoa (lsa->data->id));
              
	      /* XXX: This should be changed -- takada. */
	      if (lsa->data->type == OSPF_AS_EXTERNAL_LSA)
		{
		  struct prefix_ipv4 p;
		  struct as_external_lsa *al;

		  new_lsdb_delete ((struct new_lsdb *) lsa->lsdb, lsa);

		  ospf_rtrs_external_remove (lsa->data->id,
					     lsa->data->adv_router);

		  /* Also remove route from routing table. */
		  al = (struct as_external_lsa *) lsa->data;
		  p.family = AF_INET;
		  p.prefixlen = ip_masklen (al->mask);
		  p.prefix = lsa->data->id;
		  ospf_external_route_remove (&p);
		}
	      else
		new_lsdb_delete (lsa->lsdb, lsa);

	      if (IS_DEBUG_OSPF (lsa, LSA_FLOODING))
		zlog_info ("LSA[Type%d:%s]: MaxAge LSA removed from list",
			   lsa->data->type, inet_ntoa (lsa->data->id));

              list_delete_by_val (ospf_top->maxage_lsa, lsa);
              ospf_lsa_free (lsa);
            }
          else
            left++;
        }
    }
  else
    left = 1;

  if (left)
    {
      if (IS_DEBUG_OSPF (lsa, LSA_FLOODING))
	zlog_info ("LSA[MaxAge]: MaxAge LSAs exists, remover rescheduled");

      OSPF_SCHEDULE_MAXAGE (ospf_top->t_maxage, ospf_maxage_lsa_remover);
    }

  return 0;
}

int
ospf_lsa_maxage_exist (struct ospf_lsa *new)
{
  listnode node;

  for (node = listhead (ospf_top->maxage_lsa); node; nextnode (node))
    if (((struct ospf_lsa *) node->data) == new)
      return 1;

  return 0;
}

void
ospf_lsa_maxage (struct ospf_lsa *lsa)
{
  /* When we saw a MaxAge LSA flooded to us, we put it on the list
     and schedule the MaxAge LSA remover. */
  if (ospf_lsa_maxage_exist (lsa))
    {
      if (IS_DEBUG_OSPF (lsa, LSA_FLOODING))
	zlog_info ("LSA[Type%d:%s]: %x already exists on MaxAge LSA list",
		   lsa->data->type, inet_ntoa (lsa->data->id), lsa);
      return;
    }

  if (CHECK_FLAG (lsa->flags, OSPF_LSA_SELF) && lsa->refresh_list) 
    ospf_refresher_unregister_lsa (lsa);

  list_add_node (ospf_top->maxage_lsa, lsa);

  if (IS_DEBUG_OSPF (lsa, LSA_FLOODING))
    zlog_info ("LSA[Type%d:%s]: MaxAge LSA remover scheduled.",
	       lsa->data->type, inet_ntoa (lsa->data->id));

  OSPF_SCHEDULE_MAXAGE (ospf_top->t_maxage, ospf_maxage_lsa_remover);
}

int
ospf_lsa_maxage_walker_remover (struct ospf_lsa *lsa, void *p_arg, int int_arg)
{
  if (LS_AGE (lsa) == OSPF_LSA_MAX_AGE)
    /* Self-originated LSAs should NOT time-out instead,
       they're flushed and submitted to the max_age list explicitly. */
    if (!ospf_lsa_is_self_originated (lsa))
      {
	if (IS_DEBUG_OSPF (lsa, LSA_FLOODING))
	  zlog_info("LSA[Type%d:%s]: is MaxAge", lsa->data->type,
		    inet_ntoa (lsa->data->id));

	ospf_lsa_maxage (lsa);
      }

  return 0;
}

/* Periodical check of MaxAge LSA. */
int
ospf_lsa_maxage_walker (struct thread *t)
{
  listnode node;

  ospf_top->t_maxage_walker = NULL;

  for (node = listhead (ospf_top->areas); node; nextnode (node))
    {
      struct ospf_area *area = node->data;

      foreach_lsa (ROUTER_LSDB (area), NULL, 0,
		   ospf_lsa_maxage_walker_remover);
      foreach_lsa (NETWORK_LSDB (area), NULL, 0,
		   ospf_lsa_maxage_walker_remover);
      foreach_lsa (SUMMARY_LSDB (area), NULL, 0,
		   ospf_lsa_maxage_walker_remover);
      foreach_lsa (SUMMARY_ASBR_LSDB (area), NULL, 0,
		   ospf_lsa_maxage_walker_remover);
    }

  /* for AS-eternal-LSAs. */
  if (ospf_top->external_lsa)
    foreach_lsa (EXTERNAL_LSDB (ospf_top), NULL, 0,
		 ospf_lsa_maxage_walker_remover);

  ospf_top->t_maxage_walker = 
    thread_add_timer (master, ospf_lsa_maxage_walker, NULL,
                      OSPF_LSA_MAX_AGE_CHECK_INTERVAL);
  return 0;
}

struct ospf_lsa *
ospf_lsa_install (struct ospf_neighbor *nbr, struct ospf_lsa *lsa)
{
  switch (lsa->data->type)
    {
    case OSPF_ROUTER_LSA:
      lsa = ospf_router_lsa_install (nbr->oi->area, lsa);
      break;
    case OSPF_NETWORK_LSA:
      lsa = ospf_network_lsa_install (nbr->oi, lsa);
      break;
    case OSPF_SUMMARY_LSA:
      lsa = ospf_summary_lsa_install (nbr->oi->area, lsa);
      break;
    case OSPF_SUMMARY_LSA_ASBR:
      lsa = ospf_summary_asbr_lsa_install (nbr->oi->area, lsa);
      break;
    case OSPF_AS_EXTERNAL_LSA:
      lsa = ospf_external_lsa_install (lsa);
      break;
    default:
      break;
    }

  if (LS_AGE (lsa) == OSPF_LSA_MAX_AGE &&
      !CHECK_FLAG (lsa->flags, OSPF_LSA_SELF))
    {
      if (IS_DEBUG_OSPF (lsa, LSA_FLOODING))
	zlog_info ("LSA[Type%d:%s]: Installing LSA, MaxAge",
		   lsa->data->type, inet_ntoa (lsa->data->id));
      ospf_lsa_maxage (lsa);
    }

  return lsa;
}

int
find_summary (struct ospf_lsa *lsa, void * v, int i)
{
  struct prefix_ipv4 *p, pr;

  if ((p = (struct prefix_ipv4 *) v) != NULL)
    if (lsa != NULL)
      /* We're looking for self-originated one */
      if (ospf_lsa_is_self_originated (lsa))
	{
	  struct summary_lsa *sl = (struct summary_lsa *) lsa->data;

	  pr.family = AF_INET;
	  pr.prefix = sl->header.id;
	  pr.prefixlen = ip_masklen (sl->mask);
	  apply_mask_ipv4 (&pr);

	  if (prefix_same ((struct prefix*) &pr, (struct prefix*) p))
	    return 1;
	}

  return 0;
}

int
find_asbr_summary (struct ospf_lsa *lsa, void * v, int i)
{
  struct prefix_ipv4 *p;

  if ((p = (struct prefix_ipv4 *) v) != NULL)
    if (lsa != NULL)
      /* We're looking for self-originated one */
      if (ospf_lsa_is_self_originated (lsa))
	{
	  struct summary_lsa *sl = (struct summary_lsa *) lsa->data;

	  if (IPV4_ADDR_SAME (&p->prefix, &sl->header.id))
	    return 1;
	}

  return 0;
}

struct ospf_lsa *
ospf_lsa_lookup (struct ospf_area *area, u_int32_t type,
                 struct in_addr id, struct in_addr adv_router)
{
  switch (type)
    {
    case OSPF_ROUTER_LSA:
    case OSPF_NETWORK_LSA:
    case OSPF_SUMMARY_LSA:
    case OSPF_SUMMARY_LSA_ASBR:
      return new_lsdb_lookup_by_id (area->lsdb, type, id, adv_router);
      /* return ospf_lsdb_lookup (area->lsa[type - 1], id, adv_router); */
      break;
    case OSPF_AS_EXTERNAL_LSA:
      return new_lsdb_lookup_by_id (ospf_top->external_lsa,
				    type, id, adv_router);
      break;
    default:
      break;
    }

  return NULL;
}

struct ospf_lsa *
ospf_lsa_lookup_by_id (struct ospf_area *area, u_int32_t type, 
                       struct in_addr id)
{
  struct ospf_lsa *lsa;
  struct route_node *rn;

  switch (type)
    {
    case OSPF_ROUTER_LSA:
      return new_lsdb_lookup_by_id (area->lsdb, type, id, id);
      break;
    case OSPF_NETWORK_LSA:
      for (rn = route_top (NETWORK_LSDB (area)); rn; rn = route_next (rn))
	if ((lsa = rn->info))
	  if (IPV4_ADDR_SAME (&lsa->data->id, &id))
	    {
	      route_unlock_node (rn);
	      return lsa;
	    }
      break;
    case OSPF_SUMMARY_LSA:
    case OSPF_SUMMARY_LSA_ASBR:
      /* Currently not used. */
      assert (1);
      return new_lsdb_lookup_by_id (area->lsdb, type, id, id);
      /* return ospf_lsdb_lookup_by_id (area->lsa[type-1], id); */
      break;
    case OSPF_AS_EXTERNAL_LSA:
    default:
      break;
    }

  return NULL;
}

struct ospf_lsa *
ospf_lsa_lookup_by_header (struct ospf_area *area, struct lsa_header *lsah)
{
  struct ospf_lsa *match;

  match = ospf_lsa_lookup (area, lsah->type, lsah->id, lsah->adv_router);

  if (match == NULL)
    if (IS_DEBUG_OSPF (lsa, LSA) == OSPF_DEBUG_LSA)
      zlog_info ("LSA[Type%d:%s]: Lookup by header, NO MATCH",
		 lsah->type, inet_ntoa (lsah->id));

  return match;
}

/* return +n, l1 is more recent.
   return -n, l2 is more recent.
   return 0, l1 and l2 is identical. */
int
ospf_lsa_more_recent (struct ospf_lsa *l1, struct ospf_lsa *l2)
{
  int r;

  if (l1 == NULL && l2 == NULL)
    return 0;
  if (l1 == NULL)
    return -1;
  if (l2 == NULL)
    return 1;

  /* compare LS sequence number. */
  r = ntohl (l1->data->ls_seqnum) - ntohl (l2->data->ls_seqnum);
  if (r)
    return r;

  /* compare LS checksum. */
  r = ntohs (l1->data->checksum) - ntohs (l2->data->checksum);
  if (r)
    return r;

  /* compare LS age. */
  if (LS_AGE (l1) == OSPF_LSA_MAX_AGE &&
      LS_AGE (l2) != OSPF_LSA_MAX_AGE)
    return 1;
  else if (LS_AGE (l1) != OSPF_LSA_MAX_AGE &&
           LS_AGE (l2) == OSPF_LSA_MAX_AGE)
    return -1;

  /* compare LS age with MaxAgeDiff. */
  if (LS_AGE (l1) - LS_AGE (l2) > OSPF_LSA_MAX_AGE_DIFF)
    return -1;
  else if (LS_AGE (l2) - LS_AGE (l1) > OSPF_LSA_MAX_AGE_DIFF)
    return 1;

  /* LSAs are identical. */
  return 0;
}

/* If two LSAs are different, return 1, otherwise return 0. */
int
ospf_lsa_different (struct ospf_lsa *l1, struct ospf_lsa *l2)
{
  char * p1, *p2;
  assert (l1);
  assert (l2);
  assert (l1->data);
  assert (l2->data);

  if (l1->data->options != l2->data->options)
    return 1;

  if ((LS_AGE (l1) == OSPF_LSA_MAX_AGE) && (LS_AGE (l2) != OSPF_LSA_MAX_AGE))
    return 1;

  if ((LS_AGE (l2) == OSPF_LSA_MAX_AGE) && (LS_AGE (l1) != OSPF_LSA_MAX_AGE))
    return 1;

  if (l1->data->length != l2->data->length)
    return 1;

  if (l1->data->length ==  0)
    return 1;

  assert (l1->data->length > OSPF_LSA_HEADER_SIZE);

  p1 = (char *) l1->data;
  p2 = (char *) l2->data;

  if (memcmp (p1 + OSPF_LSA_HEADER_SIZE, p2 + OSPF_LSA_HEADER_SIZE,
              ntohs( l1->data->length ) - OSPF_LSA_HEADER_SIZE) != 0)
    return 1;

  return 0;
}

void
ospf_lsa_flush_self_originated (struct ospf_neighbor *nbr,
                                struct ospf_lsa *self,
                                struct ospf_lsa *new)
{
  u_int32_t seqnum;

  /* Adjust LS Sequence Number. */
  seqnum = ntohl (new->data->ls_seqnum) + 1;
  self->data->ls_seqnum = htonl (seqnum);

  /* Recalculate LSA checksum. */
  ospf_lsa_checksum (self->data);

  /* Reflooding LSA. */
  ospf_ls_upd_send_lsa (nbr, self, OSPF_SEND_PACKET_INDIRECT);

  if (IS_DEBUG_OSPF (lsa, LSA_GENERATE))
    zlog_info ("LSA[Type%d:%s]: Flush self-originated LSA",
	       self->data->type, inet_ntoa (self->data->id));
}

/* If there is self-originated LSA, then return 1, otherwise return 0. */
/* An interface-independent version of ospf_lsa_is_self_originated */
int 
ospf_lsa_is_self_originated (struct ospf_lsa *lsa)
{
  listnode node;

  if (CHECK_FLAG (lsa->flags, OSPF_LSA_SELF_CHECKED))
    return CHECK_FLAG (lsa->flags, OSPF_LSA_SELF);

  if (IPV4_ADDR_SAME (&lsa->data->adv_router, &ospf_top->router_id))
    {
      SET_FLAG (lsa->flags, OSPF_LSA_SELF|OSPF_LSA_SELF_CHECKED); 
      /* to make it easier later */

      /* XXX: avoid overrite new_lsdb for ASE-LSA -- takada. */
#if 0
      if (lsa->data->type == OSPF_SUMMARY_LSA ||
	  lsa->data->type == OSPF_SUMMARY_LSA_ASBR)
	if (lsa->lsdb)
	  lsa->lsdb->count_self++;
#endif

      return 1;
    }

  if (lsa->data->type == OSPF_ROUTER_LSA &&
      IPV4_ADDR_SAME (&lsa->data->id, &ospf_top->router_id))
    {
      SET_FLAG (lsa->flags, OSPF_LSA_SELF|OSPF_LSA_SELF_CHECKED);
      /* to make it easier later */
      /*
      if (lsa->lsdb)
        lsa->lsdb->count_self++;
      */

      return 1;
    }

  if (lsa->data->type == OSPF_NETWORK_LSA)
    for (node = listhead (ospf_top->iflist); node; nextnode (node))
      {
	struct interface *ifp = getdata (node);
	struct ospf_interface *oi = ifp->info;
	listnode cn;

	/* Ignore virtual link. */
        if (oi->type != OSPF_IFTYPE_VIRTUALLINK)
	  for (cn = listhead (ifp->connected); cn; nextnode (cn))
	    {
	      struct connected *co = getdata (cn);

	      if (co->address->family == AF_INET)
		if (IPV4_ADDR_SAME (&lsa->data->id, &co->address->u.prefix4))
		  {
		    /* to make it easier later */
		    SET_FLAG (lsa->flags, OSPF_LSA_SELF|OSPF_LSA_SELF_CHECKED);
		    /*
		    if (lsa->lsdb)
		      lsa->lsdb->count_self++;
		    */
		    return 1;
		  }
	    }
      }

  SET_FLAG (lsa->flags, OSPF_LSA_SELF_CHECKED);
  return 0;
}

int
count_lsa (struct ospf_lsa *lsa, void *v, int i)
{
  int *ip = (int *) v;

  if (ip)
    (*ip)++;

  return 0;
}

void
ospf_router_lsa_update ()
{
  listnode node;
  struct in_addr new_router_id;
  u_char new_flags;

  new_router_id = ospf_top->router_id;
  new_flags = ospf_top->flags;

  if (IS_DEBUG_OSPF (lsa, LSA_GENERATE))
    zlog_info ("LSA: update router-LSA");

  for (node = listhead (ospf_top->areas); node; nextnode (node))
    {
      struct router_lsa *rl;
      struct ospf_area *area = getdata (node);

      if (IS_DEBUG_OSPF (lsa, LSA_GENERATE))
	zlog_info ("LSA[Update]: Area %s", inet_ntoa (area->area_id));

      if (area->router_lsa_self == NULL)
        {
	  if (IS_DEBUG_OSPF (lsa, LSA_GENERATE))
	    zlog_info("LSA[Update]: There is no router-LSA, "
		      "originate new one");
	  ospf_router_lsa_originate (area, NULL);
          continue;
        }

      rl = (struct router_lsa *) area->router_lsa_self->data;

      if (IPV4_ADDR_SAME (&rl->header.id, &new_router_id) &&
          rl->flags == new_flags)
        {
	  if (IS_DEBUG_OSPF (lsa, LSA_GENERATE))
	    zlog_info ("Z: router_lsa_update(): Ignore this area");
          continue;
        }

      if (!IPV4_ADDR_SAME (&rl->header.id, &new_router_id))
        {
	  if (IS_DEBUG_OSPF (lsa, LSA_GENERATE))
	    zlog_info("Z: router_lsa_update(): "
		      "flushing the old LSA and delinking");
          ospf_lsa_flush_area (area->router_lsa_self, area);
          area->router_lsa_self = NULL;
        }

      /* Refresh router-LSA, (not install) and flood through area. */
      ospf_schedule_router_lsa_originate (area);
    }

  if (IS_DEBUG_OSPF (lsa, LSA_GENERATE))
    zlog_info ("Z: router_lsa_update(): Stop");
}

int
ospf_router_lsa_update_timer (struct thread *t)
{
  if (IS_DEBUG_OSPF (lsa, LSA_GENERATE))
    zlog_info ("LSA[Update]: router-LSA timer fire!");

  ospf_top->t_rlsa_update = NULL;
  ospf_router_lsa_update ();

  return 0;
}

/* Get unique Link State ID. */
struct in_addr
ospf_lsa_unique_id (struct new_lsdb *lsdb, u_char type, struct prefix_ipv4 *p)
{
  struct ospf_lsa *lsa;
  struct in_addr mask, id;

  id = p->prefix;

  /* Check existence of LSA instance. */
  lsa = new_lsdb_lookup_by_id (lsdb, type, id, ospf_top->router_id);
  if (lsa)
    {
      struct as_external_lsa *al = (struct as_external_lsa *) lsa->data;
      if (ip_masklen (al->mask) == p->prefixlen)
	{
	  if (IS_DEBUG_OSPF (lsa, LSA_GENERATE))
	    zlog_warn ("ospf_lsa_unique_id(): "
		       "Can't get Link State ID for %s/%d",
		       inet_ntoa (p->prefix), p->prefixlen);
	  id.s_addr = 0;
	  return id;
	}
      /* Masklen differs, then apply wildcard mask to Link State ID. */
      else
	{
	  masklen2ip (p->prefixlen, &mask);

	  id.s_addr = p->prefix.s_addr | (~mask.s_addr);
	  lsa = new_lsdb_lookup_by_id (ospf_top->external_lsa, type,
				       id, ospf_top->router_id);
	  if (lsa)
	    {
	      if (IS_DEBUG_OSPF (lsa, LSA_GENERATE))
		zlog_warn ("ospf_lsa_unique_id(): "
			   "Can't get Link State ID for %s/%d",
			   inet_ntoa (p->prefix), p->prefixlen);
	      id.s_addr = 0;
	      return id;
	    }
	}
    }

  return id;
}


#define LSA_ACTION_ORIGN_RTR  1
#define LSA_ACTION_ORIGN_NET  2
#define LSA_ACTION_FLOOD_AREA 3
#define LSA_ACTION_FLOOD_AS   4
#define LSA_ACTION_FLUSH_AREA 5
#define LSA_ACTION_FLUSH_AS   6

struct lsa_action
{
  u_char action;
  struct ospf_area * area;
  struct ospf_interface *oi; 
  struct ospf_lsa  * lsa;
};

int
ospf_lsa_action (struct thread *t)
{
  struct lsa_action *data;
  struct ospf_lsa *lsa;

  data = THREAD_ARG (t);

  if (IS_DEBUG_OSPF (lsa, LSA) == OSPF_DEBUG_LSA)
    zlog_info ("Z: Performing scheduled LSA action: %d", data->action);

  switch (data->action)
    {
    case LSA_ACTION_ORIGN_RTR:
      ospf_router_lsa_refresh (data->area, data->area->router_lsa_self);
      /*
      lsa = ospf_router_lsa (data->area);
      if (lsa == NULL)
	break;
      lsa = ospf_router_lsa_install (data->area, lsa);
      ospf_flood_through_area (data->area, NULL, lsa);
      */
      break;
    case LSA_ACTION_ORIGN_NET:
      lsa = ospf_network_lsa (data->oi);
      lsa = ospf_network_lsa_install (data->oi, lsa);
      ospf_flood_through_area (data->area, NULL, lsa);
      break;
    case LSA_ACTION_FLOOD_AREA:
      ospf_flood_through_area (data->area, NULL, data->lsa);
      break;
    case LSA_ACTION_FLOOD_AS:
      ospf_flood_through_as (NULL, data->lsa);
      break;
    case LSA_ACTION_FLUSH_AREA:
      ospf_lsa_flush_area (data->lsa, data->area);
      break;
    case LSA_ACTION_FLUSH_AS:
      ospf_lsa_flush_as(data->lsa);
      break;
    }

  XFREE (MTYPE_OSPF_MESSAGE, data);
  return 0;
}

void
ospf_schedule_lsa_flood_area (struct ospf_area *area, struct ospf_lsa *lsa)
{
  struct lsa_action *data;

  data = XMALLOC (MTYPE_OSPF_MESSAGE, sizeof (struct lsa_action));
  bzero (data, sizeof (struct lsa_action));

  data->action = LSA_ACTION_FLOOD_AREA;
  data->area = area;
  data->lsa  = lsa;

  thread_add_event (master, ospf_lsa_action, data, 0);
}

void
ospf_schedule_lsa_flush_area (struct ospf_area *area, struct ospf_lsa *lsa)
{
  struct lsa_action *data;

  data = XMALLOC (MTYPE_OSPF_MESSAGE, sizeof (struct lsa_action));
  bzero (data, sizeof (struct lsa_action));

  data->action = LSA_ACTION_FLUSH_AREA;
  data->area = area;
  data->lsa  = lsa;

  thread_add_event (master, ospf_lsa_action, data, 0);
}

void
ospf_schedule_router_lsa_originate (struct ospf_area *area)
{
  /* Keep area's self-originated router-LSA. */
  struct ospf_lsa *lsa = area->router_lsa_self;

  /* Cancel previously schedules router-LSA self. */
  OSPF_TIMER_OFF (area->t_router_lsa_self);
  if (IS_DEBUG_OSPF (lsa, LSA_GENERATE))
    zlog_info ("LSA: Cancelling previously scheduled router-LSA origination");

  /* If router-LSA is originated previously, check the interval time. */
  if (lsa)
    {
      struct timeval delta, now;

      gettimeofday (&now, NULL);
      delta = tv_sub (now, lsa->tv_orig);

      if (tv_cmp (delta, int2tv (OSPF_MIN_LS_INTERVAL)) < 0)
        {
	  int delay = tv_ceil (tv_sub (int2tv (OSPF_MIN_LS_INTERVAL), delta));

	  if (IS_DEBUG_OSPF (lsa, LSA_GENERATE))
	    zlog_info ("LSA: Delaying router-LSA origination for %d seconds", 
		       delay);

	  OSPF_AREA_TIMER_ON (area->t_router_lsa_self,
			      ospf_router_lsa_refresh_timer, delay);
          return;
        }
    }

  if (IS_DEBUG_OSPF (lsa, LSA_GENERATE))
    zlog_info ("LSA: Scheduling router-LSA origination right away");

  /* Immediately refresh router-LSA. */
  OSPF_AREA_TIMER_ON (area->t_router_lsa_self,
		      ospf_router_lsa_refresh_timer, 0);
}

void
ospf_schedule_network_lsa_originate (struct ospf_interface *oi)
{
  struct timeval delta, now;
  struct ospf_lsa *nlsa;

  nlsa = oi->network_lsa_self;

  if (oi->t_network_lsa_self)
    {
      if (IS_DEBUG_OSPF (lsa, LSA_GENERATE))
	zlog_info ("Z: Cancelling previously scheduled network-LSA origination");
      thread_cancel (oi->t_network_lsa_self);
    }

  if (nlsa)
    {
      gettimeofday (&now, NULL);
      delta = tv_sub (now, nlsa->tv_orig);

      if (tv_cmp (delta, int2tv (OSPF_MIN_LS_INTERVAL)) < 0)
        {
	  int delay = tv_ceil (tv_sub (int2tv (OSPF_MIN_LS_INTERVAL), delta));

	  if (IS_DEBUG_OSPF (lsa, LSA_GENERATE))
	    zlog_info ("Z: Delaying network-LSA origination for %d seconds", 
		       delay);

          oi->t_network_lsa_self =
            thread_add_timer (master, ospf_network_lsa_refresh, oi, delay);
          return;
        }
    }

  if (IS_DEBUG_OSPF (lsa, LSA_GENERATE))
    zlog_info ("Z: Scheduling network-LSA origination right away");

  /* Immediately refresh network-LSA. */
  oi->t_network_lsa_self =
    thread_add_event (master, ospf_network_lsa_refresh, oi, 0);
}


/* LSA Refreshment functions. */
void
ospf_lsa_refresh (struct ospf_lsa *lsa)
{
  assert (CHECK_FLAG (lsa->flags, OSPF_LSA_SELF));

  switch (lsa->data->type)
    {
      /* Router and Network LSAs are processed differently. */
    case OSPF_ROUTER_LSA:
    case OSPF_NETWORK_LSA: 
      break;
    case OSPF_SUMMARY_LSA:
      ospf_summary_lsa_refresh (lsa);
      break;
    case OSPF_SUMMARY_LSA_ASBR:
      ospf_summary_lsa_asbr_refresh (lsa);
      break;
    case OSPF_AS_EXTERNAL_LSA:
      ospf_external_lsa_refresh (lsa);
      break;
   }
}

int
ospf_lsa_refresher (struct thread *t)
{
  struct ospf *top;
  int count = 0;
  listnode node, next;
  struct ospf_lsa *lsa;

  if (IS_DEBUG_OSPF (lsa, LSA_GENERATE))
    zlog_info("Z: ospf_lsa_refresher(): Start");

  top = THREAD_ARG (t);

  if (top)
    if (top->refresh_queue)
      for (node = listhead (top->refresh_queue); node; node = next)
        {
          next = node->next;
          lsa = getdata (node);
          assert (lsa);

          list_delete_by_val (top->refresh_queue, lsa);
          assert (lsa->refresh_list == top->refresh_queue);
          lsa->refresh_list = NULL;
          ospf_lsa_refresh (lsa);

          top->refresh_queue_count++;

          if (++count == OSPF_REFRESH_PER_SLICE)
            break;

          if (top->refresh_queue_count >= top->refresh_queue_limit)
            break;
        }

  count = listcount (top->refresh_queue);

  if (top->refresh_queue_count >= top->refresh_queue_limit)
    {
      top->refresh_queue_count = 0;
      if (count)
        top->t_lsa_refresher =
          thread_add_timer (master, ospf_lsa_refresher, top,
                            top->refresh_queue_interval);
      else
        top->t_lsa_refresher = NULL;

    }
  else if (count)
    top->t_lsa_refresher = thread_add_event (master, ospf_lsa_refresher, 
                                             top, 0);
  else
    top->t_lsa_refresher = NULL;

  if (IS_DEBUG_OSPF (lsa, LSA_GENERATE))
    zlog_info("Z: ospf_lsa_refresher(): Stop");
  return 0;
}

struct refresh_event
{
  struct ospf *top;
  list group;
};

int
ospf_refresh_event (struct thread *t)
{
  struct refresh_event *event;
  listnode node;
  struct ospf_lsa *lsa;

  if (IS_DEBUG_OSPF (lsa, LSA_GENERATE))
    zlog_info("Z: ospf_refresh_event(): Start");

  event = THREAD_ARG (t);

  if (IS_DEBUG_OSPF (lsa, LSA_GENERATE))
    zlog_info ("Z: ospf_refresh_event(): Copying %d LSAs to Refresh Queue",
	       listcount (event->group));

  LIST_ITERATOR (event->group, node)
    {
      lsa = getdata (node);
      assert (lsa);

      list_add_node (event->top->refresh_queue, lsa);
      lsa->refresh_list = event->top->refresh_queue;
    }

  if (IS_DEBUG_OSPF (lsa, LSA_GENERATE))
    zlog_info ("T: debug list refresh_group list_delete_all: %x",
	       event->group);
  list_delete_all (event->group); /* Free the list and list nodes */

  if (event->top->t_lsa_refresher == NULL)
    {
      if (IS_DEBUG_OSPF (lsa, LSA_GENERATE))
	zlog_info ("Z: ospf_refresh_event(): "
		   "Scheduling Refresh Queue Server right away");

      event->top->t_lsa_refresher =
        thread_add_event (master, ospf_lsa_refresher, event->top, 0);

      event->top->refresh_queue_count = 0;
    }
      
  XFREE (MTYPE_OSPF_MESSAGE, event);

  if (IS_DEBUG_OSPF (lsa, LSA_GENERATE))
    zlog_info("Z: ospf_refresh_event(): Stop");
  return 0;
}

void
ospf_refresher_flush_group (struct ospf *top)
{
  struct refresh_event *event;
  int delay;
  listnode node;
  struct ospf_lsa *lsa;

  assert (top);
 
  if (listcount (top->refresh_group))
    {
      event = XMALLOC (MTYPE_OSPF_MESSAGE, sizeof (struct refresh_event));
      assert (event);

      bzero (event, sizeof (struct refresh_event));

      event->top = top;
      event->group = top->refresh_group;

      if (IS_DEBUG_OSPF (lsa, LSA_GENERATE))
	zlog_info ("Z: refresher: group age %d", top->group_age);

      node = listhead (top->refresh_group);
      lsa = getdata (node);

      assert (lsa);

      if (top->group_age == 0 &&
          ntohl (lsa->data->ls_seqnum) == OSPF_INITIAL_SEQUENCE_NUMBER)

        /* Randomizing the first refresh interval*/
        delay = OSPF_LS_REFRESH_SHIFT + (random () % OSPF_LS_REFRESH_TIME);
      else
        {
          delay = OSPF_LS_REFRESH_TIME - top->group_age;

          if (delay < 0)
            delay = 0;

          delay = delay + (random () % OSPF_LS_REFRESH_JITTER) +1; 
          /* Randomize to avoid syncing */
        }

      if (IS_DEBUG_OSPF (lsa, LSA_GENERATE))
	zlog_info ("Z: refresher: delay %d", delay);

      thread_add_timer (master, ospf_refresh_event, event, delay);

      top->refresh_group = list_init ();
      if (IS_DEBUG_OSPF (lsa, LSA_GENERATE))
	zlog_info ("T: debug list refresh_group list_init: %x",
		   top->refresh_group);
      assert (top->refresh_group);
    }

  top->t_refresh_group = NULL;
}

int
ospf_ref_group_checker (struct thread *t)
{
  struct ospf *top;

  if (IS_DEBUG_OSPF (lsa, LSA_GENERATE))
    zlog_info("Z: ospf_ref_group_checker(): Start");

  top = THREAD_ARG (t);

  if (top)
    {
      assert (top->refresh_group);
      ospf_refresher_flush_group (top);
    }

  if (IS_DEBUG_OSPF (lsa, LSA_GENERATE))
    zlog_info ("Z: ospf_ref_group_checker(): Stop");
  return 0;
}

void
ospf_refresher_register_lsa (struct ospf *top, struct ospf_lsa *lsa)
{
  if (lsa->refresh_list)
    {
      zlog_warn ("LSA: Refresh: Already registerd to refresh-list .");
      return;
    }

  if (top->t_refresh_group)
    {
      /* Not the first LSA in the group
         Check the age and fire an event, if ages are too different */

      if (abs (top->group_age - LS_AGE (lsa)) > OSPF_REFRESH_GROUP_AGE_DIF ||
          listcount (top->refresh_group) == OSPF_REFRESH_GROUP_LIMIT)
        ospf_refresher_flush_group (top);
    }

  if (top->t_refresh_group == NULL)
    {
      if (IS_DEBUG_OSPF (lsa, LSA_GENERATE))
	zlog_info ("ospf_refresher_register_lsa(): Scheduling Checker");

      top->t_refresh_group = thread_add_timer (master, ospf_ref_group_checker, 
                                               top, OSPF_REFRESH_GROUP_TIME);
      top->group_age = LS_AGE (lsa);
    }

  list_add_node (top->refresh_group, lsa);
  lsa->refresh_list = top->refresh_group;
}

void
ospf_refresher_unregister_lsa (struct ospf_lsa *lsa)
{
  assert (lsa);

  if (lsa->data->type == OSPF_ROUTER_LSA ||
      lsa->data->type == OSPF_NETWORK_LSA)
    return; /* These LSAs are processed differently */

  /* assert (lsa->refresh_list); */
  if (!lsa->refresh_list)
    {
      zlog_warn ("LSA: Refresh: refresh-list is NULL.");
      return;
    }

  if (IS_DEBUG_OSPF (lsa, LSA))
    zlog_info ("LSA[Type%d:%s]: Unregister from refresh-list %x",
	       lsa->data->type, inet_ntoa (lsa->data->id), lsa->data);

  list_delete_by_val (lsa->refresh_list, lsa);
  lsa->refresh_list = NULL;
}


/* Show functions */
int
show_router_lsa (struct ospf_lsa *lsa, void *v, int i)
{
  if (lsa != NULL)
    {
      struct vty *vty = (struct vty *) v;
      struct router_lsa *rl = (struct router_lsa *) lsa->data;

      vty_out (vty, "%-15s ", inet_ntoa (lsa->data->id));
      vty_out (vty, "%-15s %4d 0x%08x 0x%04x %-d%s",
	       inet_ntoa (lsa->data->adv_router), LS_AGE (lsa),
	       ntohl (lsa->data->ls_seqnum), ntohs (lsa->data->checksum),
	       ntohs (rl->links), VTY_NEWLINE);
    }

  return 0;
}

int
show_any_lsa (struct ospf_lsa *lsa, void *v, int i)
{
  struct router_lsa *rl;
  struct summary_lsa *sl;
  struct as_external_lsa *asel;
  struct vty *vty;
  struct prefix_ipv4 p;

  if (lsa == NULL)
    return 0;

  vty = (struct vty *) v;
  rl = (struct router_lsa *) lsa->data;

  vty_out (vty, "%-15s ", inet_ntoa (lsa->data->id));
  vty_out (vty, "%-15s %4d 0x%08x 0x%04x",
           inet_ntoa (lsa->data->adv_router), LS_AGE (lsa),
           ntohl (lsa->data->ls_seqnum), ntohs (lsa->data->checksum));

  switch (lsa->data->type)
    {
    case OSPF_SUMMARY_LSA:
      sl = (struct summary_lsa *) lsa->data;

      p.family = AF_INET;
      p.prefix = sl->header.id;
      p.prefixlen = ip_masklen (sl->mask);
      apply_mask_ipv4 (&p);

      vty_out (vty, " %s/%d", inet_ntoa (p.prefix), p.prefixlen);
      break;
    case OSPF_AS_EXTERNAL_LSA:
      asel = (struct as_external_lsa *) lsa->data;

      p.family = AF_INET;
      p.prefix = asel->header.id;
      p.prefixlen = ip_masklen (asel->mask);
      apply_mask_ipv4 (&p);

      vty_out (vty, " %s %s/%d [0x%x]",
	       IS_EXTERNAL_METRIC (asel->e[0].tos) ? "E2" : "E1",
	       inet_ntoa (p.prefix), p.prefixlen,
	       ntohl (asel->e[0].route_tag));
      break;
    default:
      break;
    }

  vty_out (vty, VTY_NEWLINE);

  return 0;
}

char *show_database_desc[] =
{
  "unknown",
  "Router Link States",
  "Net Link States",
  "Summary Link States",
  "ASBR-Summary Link States",
  "Type-5 AS External Link States",
};

#define SHOW_OSPF_COMMON_HEADER \
  "Link ID         ADV Router      Age  Seq#       CkSum"

char *show_database_header[] =
{
  "",
  "Link ID         ADV Router      Age  Seq#       CkSum  Link count",
  "Link ID         ADV Router      Age  Seq#       CkSum",
  "Link ID         ADV Router      Age  Seq#       CkSum  Route",
  "Link ID         ADV Router      Age  Seq#       CkSum",
  "Link ID         ADV Router      Age  Seq#       CkSum  Route",
};

void
show_ip_ospf_database_all (struct vty *vty)
{
  listnode node;
  int type;

  for (node = listhead (ospf_top->areas); node; nextnode (node))
    {
      struct ospf_area *area = node->data;

      for (type = 1; type <= 4; type++)
	if (area->lsdb->type[type].count > 0)
	  {
	    vty_out (vty, "                %s (Area %s)%s%s",
		     show_database_desc[type], inet_ntoa (area->area_id),
		     VTY_NEWLINE, VTY_NEWLINE);

	    vty_out (vty, "%s%s", show_database_header[type], VTY_NEWLINE);

	    if (type == OSPF_ROUTER_LSA)
	      foreach_lsa (area->lsdb->type[type].db, vty, 0, show_router_lsa);
	    else
	      foreach_lsa (area->lsdb->type[type].db, vty, 0, show_any_lsa);

	    vty_out (vty, "%s", VTY_NEWLINE);
	  }
    }

  /* Show AS-external-LSAs. */
  if (new_lsdb_count (ospf_top->external_lsa))
    {
      vty_out (vty, "                %s%s%s",
	       show_database_desc[5], VTY_NEWLINE, VTY_NEWLINE);
      vty_out (vty, "%s%s", show_database_header[5], VTY_NEWLINE);
      foreach_lsa (EXTERNAL_LSDB (ospf_top), vty, 0, show_any_lsa);
    }

  vty_out (vty, "%s", VTY_NEWLINE);
}

void
show_ip_ospf_database_header (struct vty *vty, struct ospf_lsa *lsa)
{
  struct router_lsa *rlsa = (struct router_lsa*) lsa->data;

  vty_out (vty, "  LS age: %d%s", LS_AGE (lsa), VTY_NEWLINE);
  vty_out (vty, "  Options: %d%s", lsa->data->options, VTY_NEWLINE);

  if (lsa->data->type == OSPF_ROUTER_LSA)
    {
      vty_out (vty, "  Flags: 0x%x" , rlsa->flags);

      if (rlsa->flags)
        {
          vty_out (vty, " :");
          if (IS_ROUTER_LSA_BORDER (rlsa))
            vty_out (vty, " ABR");
          if (IS_ROUTER_LSA_EXTERNAL (rlsa))
            vty_out (vty, " ASBR");
          if (IS_ROUTER_LSA_VIRTUAL (rlsa))
            vty_out (vty, " VL-endpoint");
          if (IS_ROUTER_LSA_SHORTCUT (rlsa))
            vty_out (vty, " Shortcut");
        }
    }

  vty_out (vty, "%s", VTY_NEWLINE);
  vty_out (vty, "  LS Type: %s%s",
           LOOKUP (ospf_lsa_type_msg, lsa->data->type), VTY_NEWLINE);
  vty_out (vty, "  Link State ID: %s %s%s", inet_ntoa (lsa->data->id),
           LOOKUP (ospf_link_state_id_type_msg, lsa->data->type), VTY_NEWLINE);
  vty_out (vty, "  Advertising Router: %s%s",
           inet_ntoa (lsa->data->adv_router), VTY_NEWLINE);
  vty_out (vty, "  LS Seq Number: %08x%s", ntohl (lsa->data->ls_seqnum),
           VTY_NEWLINE);
  vty_out (vty, "  Checksum: 0x%04x%s", ntohs (lsa->data->checksum),
           VTY_NEWLINE);
  vty_out (vty, "  Length: %d%s", ntohs (lsa->data->length), VTY_NEWLINE);
}

char *link_type_desc[] =
{
  "(null)",
  "another Router (point-to-point)",
  "a Transit Network",
  "Stub Network",
  "a Virtual Link",
};

char *link_id_desc[] =
{
  "(null)",
  "Neighboring Router ID",
  "Designated Router address",
  "Network/subnet number",
  "Neighboring Router ID",
};

char *link_data_desc[] =
{
  "(null)",
  "Router Interface address",
  "Router Interface address",
  "Network Mask",
  "Router Interface address",
};

void
show_ip_ospf_database_router_links (struct vty *vty,
                                    struct router_lsa *rl)
{
  int len, i, type;

  len = ntohs (rl->header.length) - 4;
  for (i = 0; i < ntohs (rl->links) && len > 0; len -= 12, i++)
    {
      type = rl->link[i].type;

      vty_out (vty, "    Link connected to: %s%s",
	       link_type_desc[type], VTY_NEWLINE);
      vty_out (vty, "     (Link ID) %s: %s%s", link_id_desc[type],
	       inet_ntoa (rl->link[i].link_id), VTY_NEWLINE);
      vty_out (vty, "     (Link Data) %s: %s%s", link_data_desc[type],
	       inet_ntoa (rl->link[i].link_data), VTY_NEWLINE);
      vty_out (vty, "      Number of TOS metrics: 0%s", VTY_NEWLINE);
      vty_out (vty, "       TOS 0 Metric: %d%s",
	       ntohs (rl->link[i].metric), VTY_NEWLINE);
      vty_out (vty, "%s", VTY_NEWLINE);
    }
}

int
show_router_lsa_detail (struct ospf_lsa *lsa, void *v, int i)
{
  if (lsa != NULL)
    {
      struct vty *vty = (struct vty *) v;
      struct router_lsa *rl = (struct router_lsa *) lsa->data;

      show_ip_ospf_database_header (vty, lsa);
          
      vty_out (vty, "   Number of Links: %d%s%s", ntohs (rl->links),
	       VTY_NEWLINE, VTY_NEWLINE);

      show_ip_ospf_database_router_links (vty, rl);
    }

  return 0;
}

void
show_ip_ospf_database_router (struct vty *vty)
{
  listnode node;

  for (node = listhead (ospf_top->areas); node; nextnode (node))
    {
      struct ospf_area *area = getdata (node);
      
      vty_out (vty, "%s                %s (Area %s)%s%s",
	       VTY_NEWLINE, show_database_desc[OSPF_ROUTER_LSA],
	       inet_ntoa (area->area_id), VTY_NEWLINE, VTY_NEWLINE);

      foreach_lsa (ROUTER_LSDB (area), vty, 0, show_router_lsa_detail);

      vty_out (vty, "%s", VTY_NEWLINE);
    }
}

int
show_network_lsa_detail (struct ospf_lsa *lsa, void *v, int i_arg)
{
  int length, i;

  if (lsa != NULL)
    {
      struct vty *vty = (struct vty*) v;
      struct network_lsa *nl = (struct network_lsa *) lsa->data;

      show_ip_ospf_database_header (vty, lsa);

      vty_out (vty, "  Network Mask: /%d%s",
	       ip_masklen (nl->mask), VTY_NEWLINE);

      length = ntohs (lsa->data->length) - OSPF_LSA_HEADER_SIZE - 4;

      for (i = 0; length > 0; i++, length -= 4)
	vty_out (vty, "        Attached Router: %s%s",
		 inet_ntoa (nl->routers[i]), VTY_NEWLINE);

      vty_out (vty, "%s", VTY_NEWLINE);
    }

  return 0;
}

void
show_ip_ospf_database_network (struct vty *vty)
{
  listnode node;

  for (node = listhead (ospf_top->areas); node; nextnode (node))
    {
      struct ospf_area *area = getdata (node);

      vty_out (vty, "                %s (Area %s)%s%s",
	       show_database_desc[OSPF_NETWORK_LSA],
               inet_ntoa (area->area_id), VTY_NEWLINE, VTY_NEWLINE);

      foreach_lsa (NETWORK_LSDB (area), vty, 0, show_network_lsa_detail);

      vty_out (vty, "%s%s", VTY_NEWLINE, VTY_NEWLINE);
    }
}

int
show_summary_lsa_detail (struct ospf_lsa *lsa, void *v, int i_arg)
{
  if (lsa != NULL)
    {
      struct vty *vty = (struct vty*) v;
      struct summary_lsa *sl = (struct summary_lsa *) lsa->data;

      show_ip_ospf_database_header (vty, lsa);

      vty_out (vty, "  Network Mask: /%d%s", ip_masklen (sl->mask),
	       VTY_NEWLINE);
      vty_out (vty, "        TOS: 0  Metric: %d%s", GET_METRIC (sl->metric),
	       VTY_NEWLINE);
    }

  return 0;
}

void
show_ip_ospf_database_summary (struct vty *vty)
{
  listnode node;

  for (node = listhead (ospf_top->areas); node; nextnode (node))
    {
      struct ospf_area *area = getdata (node);

      vty_out (vty, "                %s (Area %s)%s%s",
	       show_database_desc[OSPF_SUMMARY_LSA],
               inet_ntoa (area->area_id), VTY_NEWLINE, VTY_NEWLINE);

      foreach_lsa (SUMMARY_LSDB (area), vty, 0, show_summary_lsa_detail);

      vty_out (vty, "%s", VTY_NEWLINE);
    }
}

int
show_summary_asbr_lsa_detail (struct ospf_lsa *lsa, void *v, int i_arg)
{
  if (lsa != NULL)
    {
      struct vty *vty = (struct vty *) v;
      struct summary_lsa *sl = (struct summary_lsa *) lsa->data;

      show_ip_ospf_database_header (vty, lsa);

      vty_out (vty, "  Network Mask: /%d%s",
	       ip_masklen (sl->mask), VTY_NEWLINE);
      vty_out (vty, "        TOS: 0  Metric: %d%s", GET_METRIC (sl->metric),
	       VTY_NEWLINE);
    }

  return 0;
}

void
show_ip_ospf_database_summary_asbr (struct vty *vty)
{
  listnode node;

  for (node = listhead (ospf_top->areas); node; nextnode (node))
    {
      struct ospf_area *area = getdata (node);

      vty_out (vty, "                %s (Area %s)%s%s",
	       show_database_desc[OSPF_SUMMARY_LSA_ASBR],
               inet_ntoa (area->area_id), VTY_NEWLINE, VTY_NEWLINE);

      foreach_lsa (SUMMARY_ASBR_LSDB (area), vty, 0, show_summary_lsa_detail);
      vty_out (vty, "%s", VTY_NEWLINE);
    }
}

int
show_as_external_lsa_detail (struct ospf_lsa *lsa, void *v, int i)
{
  if (lsa != NULL)
    {
      struct vty *vty = (struct vty *) v;
      struct as_external_lsa *al = (struct as_external_lsa *) lsa->data;

      show_ip_ospf_database_header (vty, lsa);

      vty_out (vty, "  Network Mask: /%d%s",
	       ip_masklen (al->mask), VTY_NEWLINE);
      vty_out (vty, "        Metric Type: %s%s",
	       IS_EXTERNAL_METRIC (al->e[0].tos) ?
	       "2 (Larger than any link state path)" : "1", VTY_NEWLINE);
      vty_out (vty, "        TOS: 0%s", VTY_NEWLINE);
      vty_out (vty, "        Metric: %d%s",
	       GET_METRIC (al->e[0].metric), VTY_NEWLINE);
      vty_out (vty, "        Forward Address: %s%s",
	       inet_ntoa (al->e[0].fwd_addr), VTY_NEWLINE);

      vty_out (vty, "        External Route Tag: %d%s%s",
	       ntohl (al->e[0].route_tag), VTY_NEWLINE, VTY_NEWLINE);
    }

  return 0;
}

void
show_ip_ospf_database_external (struct vty *vty)
{
  vty_out (vty, "                %s%s%s",
	   show_database_header[OSPF_AS_EXTERNAL_LSA],
	   VTY_NEWLINE, VTY_NEWLINE);

  foreach_lsa (EXTERNAL_LSDB (ospf_top), vty, 0, show_as_external_lsa_detail);

  vty_out (vty, "%s", VTY_NEWLINE);
}

int
show_router_lsa_self (struct ospf_lsa *lsa, void *v, int i)
{
  struct vty *vty = (struct vty *) v;

  if (lsa != NULL)
    if (ospf_lsa_is_self_originated (lsa))
      {
	struct router_lsa *rl = (struct router_lsa *) lsa->data;

	vty_out (vty, "%-15s ", inet_ntoa (lsa->data->id));
	vty_out (vty, "%-15s %4d 0x%08x 0x%04x %-d%s",
		 inet_ntoa (lsa->data->adv_router), LS_AGE (lsa),
		 ntohl (lsa->data->ls_seqnum), ntohs (lsa->data->checksum),
		 ntohs (rl->links), VTY_NEWLINE);
      }

  return 0;
}

int
show_any_lsa_self (struct ospf_lsa *lsa, void *v, int i)
{
  struct vty *vty = (struct vty *) v;

  if (lsa != NULL)
    if (ospf_lsa_is_self_originated (lsa))
      {
	vty_out (vty, "%-15s ", inet_ntoa (lsa->data->id));
	vty_out (vty, "%-15s %4d 0x%08x 0x%04x%s",
		 inet_ntoa (lsa->data->adv_router), LS_AGE (lsa),
		 ntohl (lsa->data->ls_seqnum), ntohs (lsa->data->checksum),
		 VTY_NEWLINE);
      }

 return 0;
}

void
show_ip_ospf_database_self_originate (struct vty *vty)
{
  listnode node;
  int type;

  /* Show self-originated Type1-4 LSAs for each areas. */
  for (node = listhead (ospf_top->areas); node; nextnode (node))
    {
      struct ospf_area *area = node->data;

      if ((area = getdata (node)) != NULL)
	for (type = 1; type <= 4; type++)
	  if (area->lsdb->type[type].count > 0)
	    {
	      vty_out (vty, "                %s (Area %s)%s%s",
		       show_database_desc[type], inet_ntoa (area->area_id),
		       VTY_NEWLINE, VTY_NEWLINE);

	      vty_out (vty, "%s%s", show_database_header[type], VTY_NEWLINE);

	      if (type == OSPF_ROUTER_LSA)
		foreach_lsa (area->lsdb->type[type].db, vty, 0,
			     show_router_lsa_self);
	      else
		foreach_lsa (area->lsdb->type[type].db, vty, 0,
			     show_any_lsa_self);

	      vty_out (vty, "%s", VTY_NEWLINE);
	    }
    }

  /* Show self-originated AS-external-LSAs. */
  if (new_lsdb_count (ospf_top->external_lsa))
    {
      vty_out (vty, "                %s%s%s",
	       show_database_desc[OSPF_AS_EXTERNAL_LSA],
	       VTY_NEWLINE, VTY_NEWLINE);
      vty_out (vty, "%s%s", show_database_header[OSPF_AS_EXTERNAL_LSA],
	       VTY_NEWLINE);
      foreach_lsa (EXTERNAL_LSDB (ospf_top), vty, 0, show_any_lsa_self);

      vty_out (vty, "%s", VTY_NEWLINE);
    }

  vty_out (vty, "%s", VTY_NEWLINE);
}

void
show_ip_ospf_database_maxage (struct vty *vty)
{
  listnode node;
  struct ospf_lsa *lsa;

  vty_out (vty, "%s                MaxAge Link States:%s%s",
           VTY_NEWLINE, VTY_NEWLINE, VTY_NEWLINE);

  for (node = listhead (ospf_top->maxage_lsa); node; nextnode (node))
    if ((lsa = node->data) != NULL)
      {
	vty_out (vty, "Link type: %d%s", lsa->data->type, VTY_NEWLINE);
	vty_out (vty, "Link State ID: %s%s",
		 inet_ntoa (lsa->data->id), VTY_NEWLINE);
	vty_out (vty, "Advertising Router: %s%s",
		 inet_ntoa (lsa->data->adv_router), VTY_NEWLINE);
	vty_out (vty, "LS Reference counter: %d%s", lsa->ref, VTY_NEWLINE);
	vty_out (vty, "%s", VTY_NEWLINE);
      }
}

DEFUN (show_ip_ospf_database,
       show_ip_ospf_database_cmd,
       "show ip ospf database",
       SHOW_STR
       IP_STR
       "OSPF information\n"
       "Database summary\n")
{
  if (ospf_top == NULL)
    return CMD_SUCCESS;

  vty_out (vty, "%s       OSPF Router with ID (%s)%s%s", VTY_NEWLINE,
           inet_ntoa (ospf_top->router_id), VTY_NEWLINE, VTY_NEWLINE);

  /* Show all LSA. */
  if (argc == 0)
    show_ip_ospf_database_all (vty);
  else if (argc == 1)
    {
      if (strncmp (argv[0], "a", 1) == 0)
        show_ip_ospf_database_summary_asbr (vty);
      else if (strncmp (argv[0], "e", 1) == 0)
        show_ip_ospf_database_external (vty);
      else if (strncmp (argv[0], "m", 1) == 0)
        show_ip_ospf_database_maxage (vty);
      else if (strncmp (argv[0], "n", 1) == 0)
        show_ip_ospf_database_network (vty);
      else if (strncmp (argv[0], "r", 1) == 0)
        show_ip_ospf_database_router (vty);
      else if (strncmp (argv[0], "se", 2) == 0)
        show_ip_ospf_database_self_originate (vty);
      else if (strncmp (argv[0], "su", 2) == 0)
        show_ip_ospf_database_summary (vty);
      else
        return CMD_WARNING;
    }

  return CMD_SUCCESS;
}
       
ALIAS (show_ip_ospf_database,
       show_ip_ospf_database_type_cmd,
       "show ip ospf database (asbr-summary|external|max-age|network|router|self-originate|summary)",
       SHOW_STR
       IP_STR
       "OSPF information\n"
       "Database summary\n"
       "ASBR summary link states\n"
       "External link states\n"
       "LSAs in MaxAge list\n"
       "Network link states\n"
       "Router link states\n"
       "Self-originated link states\n"
       "Network summary link states\n")

DEFUN (show_ip_ospf_refresher,
       show_ip_ospf_refresher_cmd,
       "show ip ospf refresher",
       SHOW_STR
       IP_STR
       "OSPF information\n"
       "LSA Refresher process info\n")
{
  listnode node;
  struct ospf_lsa * lsa;
  u_char buf1[INET_ADDRSTRLEN];
  u_char buf2[INET_ADDRSTRLEN];

  if (ospf_top == NULL)
    return CMD_SUCCESS;

  if (listcount (ospf_top->refresh_queue) == 0)
    {
      vty_out (vty, " LSA refresh queue is empty%s", VTY_NEWLINE);
      return CMD_SUCCESS;
    }

  vty_out (vty, " LSA Refresher is active. Queue :%s", VTY_NEWLINE);
  LIST_ITERATOR (ospf_top->refresh_queue, node)
    {
      lsa = getdata (node);
      assert (lsa);

      bzero (&buf1, INET_ADDRSTRLEN);
      bzero (&buf2, INET_ADDRSTRLEN);
      strncpy (buf1, inet_ntoa (lsa->data->id), INET_ADDRSTRLEN);
      strncpy (buf2, inet_ntoa (lsa->data->adv_router), INET_ADDRSTRLEN);

      vty_out (vty, " LSA Type: %d, LSID: %s, AdvRtr: %s, Age: %d, Seq: %X%s",
               lsa->data->type, buf1, buf2, LS_AGE(lsa), 
               ntohs (lsa->data->ls_seqnum), VTY_NEWLINE);
    }

  vty_out (vty, "%s", VTY_NEWLINE);

  return CMD_SUCCESS;
}

/* Install LSA related commands. */
void
ospf_lsa_init ()
{
  install_element (VIEW_NODE, &show_ip_ospf_database_type_cmd);
  install_element (VIEW_NODE, &show_ip_ospf_database_cmd);
  install_element (VIEW_NODE, &show_ip_ospf_refresher_cmd);
  install_element (ENABLE_NODE, &show_ip_ospf_database_type_cmd);
  install_element (ENABLE_NODE, &show_ip_ospf_database_cmd);
  install_element (ENABLE_NODE, &show_ip_ospf_refresher_cmd);
}
