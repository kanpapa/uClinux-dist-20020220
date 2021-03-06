/*
 * BGP attributes. 
 * Copyright (C) 1996, 97, 98 Kunihiro Ishiguro
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

#ifndef _ZEBRA_BGP_ATTR_H
#define _ZEBRA_BGP_ATTR_H

/* Attribute flags */
#define ATTR_FLAG_OPTIONAL   0x80	/* Attribute is optional. */
#define ATTR_FLAG_TRANS      0x40	/* Attribute is transitive. */
#define ATTR_FLAG_PARTIAL    0x20	/* Attribute is partial. */
#define ATTR_FLAG_EXTLEN     0x10	/* Extended length flag. */

#define BGP_ATTR_MIN_LEN        2       /* Attribute flag and type. */

/* Default attribute value. */
#define DEFAULT_LOCAL_PREF    100


/* Router Reflector related structure. */
struct cluster_list
{
  unsigned long refcnt;
  int length;
  struct in_addr *list;
};

struct attr
{
  /* Reference count of this attribute. */
  int refcnt;

  /* Flag of attribute is set or not. */
  u_int32_t flag;

  /* Attributes. */
  u_char origin;
  struct in_addr nexthop;
  u_int32_t med;
  u_int32_t local_pref;
  as_t aggregator_as;
  struct in_addr aggregator_addr;
  u_int32_t dpa;
  u_int32_t weight;
  struct in_addr originator_id;
  struct cluster_list *cluster;

  u_char mp_nexthop_len;
#ifdef HAVE_IPV6
  struct in6_addr mp_nexthop_global;
  struct in6_addr mp_nexthop_local;
#endif /* HAVE_IPV6 */
  struct in_addr mp_nexthop_global_in;
  struct in_addr mp_nexthop_local_in;

  /* AS Path structure */
  struct aspath *aspath;

  /* Community structure */
  struct community *community;	

  /* Extended Communities attribute. */
  struct ecommunity *ecommunity;

  /* Invalid. */
  u_char invalid;
};

#define ATTR_FLAG_BIT(X)  (1 << ((X) - 1))

/* Prototypes. */
void bgp_attr_init ();
int bgp_attr_parse (struct peer *, struct attr *, bgp_size_t, 
		    struct bgp_nlri *, struct bgp_nlri *);
int bgp_attr_check (struct peer *, struct attr *);

struct attr *bgp_attr_intern (struct attr *attr);
void bgp_attr_unintern (struct attr *);
void bgp_attr_flush (struct attr *);

struct attr *bgp_attr_default_set (struct attr *attr, u_char);
struct attr *bgp_attr_default_intern (u_char);

bgp_size_t bgp_packet_attribute (struct peer_conf *conf, struct peer *, struct stream *, struct attr *, struct prefix *, afi_t, safi_t, struct peer *, struct prefix_rd *, u_char *);
bgp_size_t bgp_packet_withdraw (struct peer *peer, struct stream *s, struct prefix *p, afi_t, safi_t, struct prefix_rd *, u_char *);
int  cluster_loop_check (struct cluster_list *cluster, struct in_addr originator);
struct cluster_list *cluster_parse (caddr_t, int);
struct cluster_list *cluster_intern (struct cluster_list *);
void cluster_unintern (struct cluster_list *);
void cluster_free (struct cluster_list *);
struct cluster_list *cluster_dup (struct cluster_list *);

#endif /* _ZEBRA_BGP_ATTR_H */
