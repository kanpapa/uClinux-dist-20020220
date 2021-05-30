/*
 * Route map function of bgpd.
 * Copyright (C) 1998, 1999 Kunihiro Ishiguro
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

#include "memory.h"
#include "prefix.h"
#include "filter.h"
#include "routemap.h"
#include "command.h"
#include "linklist.h"
#include "log.h"
#include "plist.h"
#ifdef HAVE_GNU_REGEX
#include <regex.h>
#else
#include "regex-gnu.h"
#endif /* HAVE_GNU_REGEX */
#include "buffer.h"
#include "table.h"
#include "sockunion.h"
#include "newlist.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_regex.h"
#include "bgpd/bgp_community.h"
#include "bgpd/bgp_clist.h"
#include "bgpd/bgp_filter.h"
#include "bgpd/bgp_mplsvpn.h"
#include "bgpd/bgp_ecommunity.h"

/* Memo of route-map commands.

o Cisco route-map

 match as-path          :  Done
       community        :  Done
       interface        :  Not yet
       ip address       :  Done
       ip next-hop      :  Done
       ip route-source  :  (This will not be implemented by bgpd)
       ip prefix-list   :  Done
       ipv6 address     :  Done
       ipv6 next-hop    :  Done
       ipv6 route-source:  (This will not be implemented by bgpd)
       ipv6 prefix-list :  Done
       length           :  (This will not be implemented by bgpd)
       metric           :  Done
       route-type       :  (This will not be implemented by bgpd)
       tag              :  (This will not be implemented by bgpd)

 set  as-path prepend   :  Done
      as-path tag       :  Not yet
      automatic-tag     :  (This will not be implemented by bgpd)
      community         :  Done
      comm-list         :  Not yet
      dampning          :  Not yet
      default           :  (This will not be implemented by bgpd)
      interface         :  (This will not be implemented by bgpd)
      ip default        :  (This will not be implemented by bgpd)
      ip next-hop       :  Done
      ip precedence     :  (This will not be implemented by bgpd)
      ip tos            :  (This will not be implemented by bgpd)
      level             :  (This will not be implemented by bgpd)
      local-preference  :  Done
      metric            :  Done
      metric-type       :  (This will not be implemented by bgpd)
      origin            :  Done
      tag               :  (This will not be implemented by bgpd)
      weight            :  Done

o mrt extension

  set dpa as %d %d      :  Not yet
      atomic-aggregate  :  Done
      aggregator as %d %M :  Done

o Local extention

  set ipv6 next-hop global: Done
  set ipv6 next-hop local : Done

*/ 

/* `match ip address IP_ACCESS_LIST' */

/* Match function should return 1 if match is success else return
   zero. */
route_map_result_t
route_match_ip_address (void *rule, struct prefix *prefix, 
			route_map_object_t type, void *object)
{
  struct access_list *alist;
  /* struct prefix_ipv4 match; */

  if (type == RMAP_BGP)
    {
      alist = access_list_lookup (AF_INET, (char *) rule);
      if (alist == NULL)
	return RMAP_NOMATCH;
    
      return (access_list_apply (alist, prefix) == FILTER_DENY ?
	      RMAP_NOMATCH : RMAP_MATCH);
    }
  return RMAP_NOMATCH;
}

/* Route map `ip address' match statement.  `arg' should be
   access-list name. */
void *
route_match_ip_address_compile (char *arg)
{
  return XSTRDUP (MTYPE_ROUTE_MAP_COMPILED, arg);
}

/* Free route map's compiled `ip address' value. */
void
route_match_ip_address_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Route map commands for ip address matching. */
struct route_map_rule_cmd route_match_ip_address_cmd =
{
  "ip address",
  route_match_ip_address,
  route_match_ip_address_compile,
  route_match_ip_address_free
};

/* `match ip next-hop IP_ADDRESS' */

/* Match function return 1 if match is success else return zero. */
route_map_result_t
route_match_ip_next_hop (void *rule, struct prefix *prefix, 
			 route_map_object_t type, void *object)
{
  struct in_addr *addr;
  struct bgp_info *bgp_info;

  if(type == RMAP_BGP){
    addr = rule;
    bgp_info = object;
    
    if (IPV4_ADDR_CMP (&bgp_info->attr->nexthop, rule) == 0)
      return RMAP_MATCH;
    else
      return RMAP_NOMATCH;
  }

  return RMAP_NOMATCH;
}

/* Route map `ip next-hop' match statement. `arg' is IP address
   string. */
void *
route_match_ip_next_hop_compile (char *arg)
{
  struct in_addr *addr;
  int ret;

  addr = XMALLOC (MTYPE_ROUTE_MAP_COMPILED, sizeof (struct in_addr));

  ret = inet_aton (arg, addr);
  if (!ret)
    {
      XFREE (MTYPE_ROUTE_MAP_COMPILED, addr);
      return NULL;
    }

  return addr;
}

/* Free route map's compiled `ip address' value. */
void
route_match_ip_next_hop_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Route map commands for ip next-hop matching. */
struct route_map_rule_cmd route_match_ip_next_hop_cmd =
{
  "ip next-hop",
  route_match_ip_next_hop,
  route_match_ip_next_hop_compile,
  route_match_ip_next_hop_free
};

/* `match ip prefix-list PREFIX_LIST' */

route_map_result_t
route_match_ip_prefix_list (void *rule, struct prefix *prefix, 
			    route_map_object_t type, void *object)
{
  struct prefix_list *plist;

  if (type == RMAP_BGP)
    {
      plist = prefix_list_lookup (AF_INET, (char *) rule);
      if (plist == NULL)
	return RMAP_NOMATCH;
    
      return (prefix_list_apply (plist, prefix) == PREFIX_DENY ?
	      RMAP_NOMATCH : RMAP_MATCH);
    }
  return RMAP_NOMATCH;
}

void *
route_match_ip_prefix_list_compile (char *arg)
{
  return XSTRDUP (MTYPE_ROUTE_MAP_COMPILED, arg);
}

void
route_match_ip_prefix_list_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);
}

struct route_map_rule_cmd route_match_ip_prefix_list_cmd =
{
  "ip prefix-list",
  route_match_ip_prefix_list,
  route_match_ip_prefix_list_compile,
  route_match_ip_prefix_list_free
};

/* `match ip address prefix-list PREFIX_LIST' */

route_map_result_t
route_match_ip_address_prefix_list (void *rule, struct prefix *prefix, 
				    route_map_object_t type, void *object)
{
  struct prefix_list *plist;

  if (type == RMAP_BGP)
    {
      plist = prefix_list_lookup (AF_INET, (char *) rule);
      if (plist == NULL)
	return RMAP_NOMATCH;
    
      return (prefix_list_apply (plist, prefix) == PREFIX_DENY ?
	      RMAP_NOMATCH : RMAP_MATCH);
    }
  return RMAP_NOMATCH;
}

void *
route_match_ip_address_prefix_list_compile (char *arg)
{
  return XSTRDUP (MTYPE_ROUTE_MAP_COMPILED, arg);
}

void
route_match_ip_address_prefix_list_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);
}

struct route_map_rule_cmd route_match_ip_address_prefix_list_cmd =
{
  "ip address prefix-list",
  route_match_ip_address_prefix_list,
  route_match_ip_address_prefix_list_compile,
  route_match_ip_address_prefix_list_free
};

/* `match metric METRIC' */

/* Match function return 1 if match is success else return zero. */
route_map_result_t
route_match_metric (void *rule, struct prefix *prefix, 
		    route_map_object_t type, void *object)
{
  u_int32_t *med;
  struct bgp_info *bgp_info;

  if (type == RMAP_BGP)
    {
      med = rule;
      bgp_info = object;
    
      if (bgp_info->attr->med == *med)
	return RMAP_MATCH;
      else
	return RMAP_NOMATCH;
    }
  return RMAP_NOMATCH;
}

/* Route map `match metric' match statement. `arg' is MED value */
void *
route_match_metric_compile (char *arg)
{
  u_int32_t *med;
  char *endptr = NULL;

  med = XMALLOC (MTYPE_ROUTE_MAP_COMPILED, sizeof (u_int32_t));
  *med = strtoul (arg, &endptr, 10);
  if (*endptr != '\0' || *med == ULONG_MAX)
    {
      XFREE (MTYPE_ROUTE_MAP_COMPILED, med);
      return NULL;
    }
  return med;
}

/* Free route map's compiled `match metric' value. */
void
route_match_metric_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Route map commands for metric matching. */
struct route_map_rule_cmd route_match_metric_cmd =
{
  "metric",
  route_match_metric,
  route_match_metric_compile,
  route_match_metric_free
};

/* `match as-path ASPATH' */

/* Match function for as-path match.  I assume given object is */
route_map_result_t
route_match_aspath (void *rule, struct prefix *prefix, 
		    route_map_object_t type, void *object)
{
  
  struct as_list *as_list;
  struct bgp_info *bgp_info;

  if (type == RMAP_BGP)
    {
      as_list = as_list_lookup ((char *) rule);
      if (as_list == NULL)
	return RMAP_NOMATCH;
    
      bgp_info = object;
    
      /* Perform match. */
      return ((as_list_apply (as_list, bgp_info->attr->aspath) == AS_FILTER_DENY) ? RMAP_NOMATCH : RMAP_MATCH);
    }
  return RMAP_NOMATCH;
}

/* Compile function for as-path match. */
void *
route_match_aspath_compile (char *arg)
{
  return XSTRDUP (MTYPE_ROUTE_MAP_COMPILED, arg);
}

/* Compile function for as-path match. */
void
route_match_aspath_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Route map commands for aspath matching. */
struct route_map_rule_cmd route_match_aspath_cmd = 
{
  "as-path",
  route_match_aspath,
  route_match_aspath_compile,
  route_match_aspath_free
};

#if ROUTE_MATCH_ASPATH_OLD
/* `match as-path ASPATH' */

/* Match function for as-path match.  I assume given object is */
int
route_match_aspath (void *rule, struct prefix *prefix, void *object)
{
  regex_t *regex;
  struct bgp_info *bgp_info;

  regex = rule;
  bgp_info = object;
  
  /* Perform match. */
  return bgp_regexec (regex, bgp_info->attr->aspath);
}

/* Compile function for as-path match. */
void *
route_match_aspath_compile (char *arg)
{
  regex_t *regex;

  regex = bgp_regcomp (arg);
  if (! regex)
    return NULL;

  return regex;
}

/* Compile function for as-path match. */
void
route_match_aspath_free (void *rule)
{
  regex_t *regex = rule;

  bgp_regex_free (regex);
}

/* Route map commands for aspath matching. */
struct route_map_rule_cmd route_match_aspath_cmd = 
{
  "as-path",
  route_match_aspath,
  route_match_aspath_compile,
  route_match_aspath_free
};
#endif /* ROUTE_MATCH_ASPATH_OLD */

/* `match community COMMUNIY' */

/* Match function for community match. */
route_map_result_t
route_match_community (void *rule, struct prefix *prefix, 
		       route_map_object_t type, void *object)
{
  struct community_list *list;
  struct bgp_info *bgp_info;

  if (type == RMAP_BGP) 
    {
      list = community_list_lookup ((char *) rule);
      bgp_info = object;
    
      if (list == NULL || bgp_info->attr->community == NULL)
	return RMAP_NOMATCH;
    
      /* Perform match. */
      return (community_list_match (bgp_info->attr->community, list) ? RMAP_MATCH : RMAP_NOMATCH);
    }
  return RMAP_NOMATCH;
}

/* Compile function for community match. */
void *
route_match_community_compile (char *arg)
{
  return XSTRDUP (MTYPE_ROUTE_MAP_COMPILED, arg);
}

/* Compile function for community match. */
void
route_match_community_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Route map commands for community matching. */
struct route_map_rule_cmd route_match_community_cmd = 
{
  "community",
  route_match_community,
  route_match_community_compile,
  route_match_community_free
};
/* `match nlri unicast | multicast ' */

/* Match function return 1 if match is success else return zero. */
route_map_result_t
route_match_nlri (void *rule, struct prefix *prefix, 
		    route_map_object_t type, void *object)
{
  u_int32_t *safi;
  struct bgp_info *bgp_info;

  if (type == RMAP_BGP)
    {
      safi = rule;
      bgp_info = object;
    
      if (prefix->safi == *safi)
	return RMAP_MATCH;
      else
	return RMAP_NOMATCH;
    }
  return RMAP_NOMATCH;
}

/* Route map `match nlri' match statement. `arg' is nlri value */
void *
route_match_nlri_compile (char *arg)
{
  u_int32_t *safi;

  safi = XMALLOC (MTYPE_ROUTE_MAP_COMPILED, sizeof (u_int32_t));

  if( strcmp( arg, "multicast" ) == 0) *safi = SAFI_MULTICAST;
  else if( strcmp( arg, "unicast" ) == 0) *safi = SAFI_UNICAST;
  else *safi = 0;
  return safi;
}

/* Free route map's compiled `match nlri' value. */
void
route_match_nlri_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Route map commands for nlri matching. */
struct route_map_rule_cmd route_match_nlri_cmd =
{
  "nlri",
  route_match_nlri,
  route_match_nlri_compile,
  route_match_nlri_free
};
/* `set nlri unicast | multicast ' */

/* Set function return 1 if match is success else return zero. */
route_map_result_t
route_set_nlri (void *rule, struct prefix *prefix, 
		    route_map_object_t type, void *object)
{
  u_int32_t *safi;
  struct bgp_info *bgp_info;

  if (type == RMAP_BGP)
    {
      safi = rule;
      bgp_info = object;
      prefix->safi = *safi;
    }
  return RMAP_OKAY;
}

/* Route map `set nlri' aet statement. `arg' is nlri value */
void *
route_set_nlri_compile (char *arg)
{
  u_int32_t *safi;
  int tmp;

  if( strcmp( arg, "multicast" ) == 0) tmp = SAFI_MULTICAST;
  else if( strcmp( arg, "unicast" ) == 0) tmp = SAFI_UNICAST;
  else return NULL;
  
  safi = XMALLOC (MTYPE_ROUTE_MAP_COMPILED, sizeof (u_int32_t));
  *safi = tmp;
  return safi;
}

/* Free route map's compiled `set nlri' value. */
void
route_set_nlri_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Route map commands for nlri matching. */
struct route_map_rule_cmd route_set_nlri_cmd =
{
  "nlri",
  route_set_nlri,
  route_set_nlri_compile,
  route_set_nlri_free
};

/* `set ip next-hop IP_ADDRESS' */

/* Set nexthop to object.  ojbect must be pointer to struct attr. */
route_map_result_t
route_set_ip_nexthop (void *rule, struct prefix *prefix, route_map_object_t type, void *object)
{
  struct in_addr *address;
  struct bgp_info *bgp_info;

  if(type == RMAP_BGP){
    /* Fetch routemap's rule information. */
    address = rule;
    bgp_info = object;
    
    /* Set next hop value. */ 
    bgp_info->attr->nexthop = *address;
  }

  return RMAP_OKAY;
}

/* Route map `ip nexthop' compile function.  Given string is converted
   to struct in_addr structure. */
void *
route_set_ip_nexthop_compile (char *arg)
{
  int ret;
  struct in_addr *address;

  address = XMALLOC (MTYPE_ROUTE_MAP_COMPILED, sizeof (struct in_addr));

  ret = inet_aton (arg, address);

  if (ret == 0)
    {
      XFREE (MTYPE_ROUTE_MAP_COMPILED, address);
      return NULL;
    }

  return address;
}

/* Free route map's compiled `ip nexthop' value. */
void
route_set_ip_nexthop_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Route map commands for ip nexthop set. */
struct route_map_rule_cmd route_set_ip_nexthop_cmd =
{
  "ip next-hop",
  route_set_ip_nexthop,
  route_set_ip_nexthop_compile,
  route_set_ip_nexthop_free
};

/* `set local-preference LOCAL_PREF' */

/* Set local preference. */
route_map_result_t
route_set_local_pref (void *rule, struct prefix *prefix, route_map_object_t type, void *object)
{
  u_int32_t *local_pref;
  struct bgp_info *bgp_info;

  if(type == RMAP_BGP){
    /* Fetch routemap's rule information. */
    local_pref = rule;
    bgp_info = object;
    
    /* Set local preference value. */ 
    bgp_info->attr->flag |= ATTR_FLAG_BIT (BGP_ATTR_LOCAL_PREF);
    bgp_info->attr->local_pref = *local_pref;
  }

  return RMAP_OKAY;
}

/* set local preference compilation. */
void *
route_set_local_pref_compile (char *arg)
{
  u_int32_t *local_pref;
  char *endptr = NULL;

  /* Local preference value shoud be integer. */
  if (! all_digit (arg))
    return NULL;

  local_pref = XMALLOC (MTYPE_ROUTE_MAP_COMPILED, sizeof (u_int32_t));
  *local_pref = strtoul (arg, &endptr, 10);
  if (*endptr != '\0' || *local_pref == ULONG_MAX)
    {
      XFREE (MTYPE_ROUTE_MAP_COMPILED, local_pref);
      return NULL;
    }
  return local_pref;
}

/* Free route map's local preference value. */
void
route_set_local_pref_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Set local preference rule structure. */
struct route_map_rule_cmd route_set_local_pref_cmd = 
{
  "local-preference",
  route_set_local_pref,
  route_set_local_pref_compile,
  route_set_local_pref_free,
};

/* `set weight WEIGHT' */

/* Set weight. */
route_map_result_t
route_set_weight (void *rule, struct prefix *prefix, route_map_object_t type, void *object)
{
  u_int32_t *weight;
  struct bgp_info *bgp_info;

  if(type == RMAP_BGP){
    /* Fetch routemap's rule information. */
    weight = rule;
    bgp_info = object;
    
    /* Set weight value. */ 
    bgp_info->attr->weight = *weight;
  }

  return RMAP_OKAY;
}

/* set local preference compilation. */
void *
route_set_weight_compile (char *arg)
{
  u_int32_t *weight;
  char *endptr = NULL;

  /* Local preference value shoud be integer. */
  if (! all_digit (arg))
    return NULL;

  weight = XMALLOC (MTYPE_ROUTE_MAP_COMPILED, sizeof (u_int32_t));
  *weight = strtoul (arg, &endptr, 10);
  if (*endptr != '\0' || *weight == ULONG_MAX)
    {
      XFREE (MTYPE_ROUTE_MAP_COMPILED, weight);
      return NULL;
    }
  return weight;
}

/* Free route map's local preference value. */
void
route_set_weight_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Set local preference rule structure. */
struct route_map_rule_cmd route_set_weight_cmd = 
{
  "weight",
  route_set_weight,
  route_set_weight_compile,
  route_set_weight_free,
};

/* `set metric METRIC' */

/* Set metric to attribute. */
route_map_result_t
route_set_metric (void *rule, struct prefix *prefix, 
		  route_map_object_t type, void *object)
{
  char *metric;
  struct bgp_info *bgp_info;

  if(type == RMAP_BGP)
    {
      /* Fetch routemap's rule information. */
      metric = rule;
      bgp_info = object;
    
      /* Set next hop value. */ 
      bgp_info->attr->flag |= ATTR_FLAG_BIT (BGP_ATTR_MULTI_EXIT_DISC);
      bgp_info->attr->med = atoi (metric);
    }
  return RMAP_OKAY;
}

/* set metric compilation. */
void *
route_set_metric_compile (char *arg)
{
  /* Metric value shoud be integer.  Check needed at here XXX. */
  return XSTRDUP (MTYPE_ROUTE_MAP_COMPILED, arg);
}

/* Free route map's compiled `set metric' value. */
void
route_set_metric_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Set metric rule structure. */
struct route_map_rule_cmd route_set_metric_cmd = 
{
  "metric",
  route_set_metric,
  route_set_metric_compile,
  route_set_metric_free,
};

/* `set as-path prepend ASPATH' */

/* For AS path prepend mechanism. */
route_map_result_t
route_set_aspath_prepend (void *rule, struct prefix *prefix, route_map_object_t type, void *object)
{
  struct aspath *aspath;
  struct aspath *new;
  struct bgp_info *bgp_info;

  if (type == RMAP_BGP)
    {
      aspath = rule;
      bgp_info = object;
    
      new = aspath_dup (bgp_info->attr->aspath);

      aspath_prepend (aspath, new);
      bgp_info->attr->aspath = new;
    }

  return RMAP_OKAY;
}

/* Compile function for as-path prepend. */
void *
route_set_aspath_prepend_compile (char *arg)
{
  struct aspath *aspath;

  aspath = aspath_str2aspath (arg);
  if (! aspath)
    return NULL;
  return aspath;
}

/* Compile function for as-path prepend. */
void
route_set_aspath_prepend_free (void *rule)
{
  struct aspath *aspath = rule;
  aspath_free (aspath);
}

/* Set metric rule structure. */
struct route_map_rule_cmd route_set_aspath_prepend_cmd = 
{
  "as-path prepend",
  route_set_aspath_prepend,
  route_set_aspath_prepend_compile,
  route_set_aspath_prepend_free,
};

/* `set community COMMUNITY' */

/* For community set mechanism. */
route_map_result_t
route_set_community (void *rule, struct prefix *prefix, route_map_object_t type, void *object)
{
  struct community *com;
  struct bgp_info *bgp_info;

  if(type == RMAP_BGP)
    {
      com = rule;
      bgp_info = object;
    
      if (!com)
	return RMAP_OKAY;
    
      bgp_info->attr->flag |= ATTR_FLAG_BIT (BGP_ATTR_COMMUNITIES);
      bgp_info->attr->community = community_dup (com);
    }

  return RMAP_OKAY;
}

/* Compile function for set community. */
void *
route_set_community_compile (char *arg)
{
  struct community *com;

  com = community_str2com (arg);
  if (! com)
    return NULL;
  return com;
}

/* Free function for set community. */
void
route_set_community_free (void *rule)
{
  struct community *com = rule;
  community_free (com);
}

/* Set community rule structure. */
struct route_map_rule_cmd route_set_community_cmd = 
{
  "community",
  route_set_community,
  route_set_community_compile,
  route_set_community_free,
};

/* `set community-additive COMMUNITY' */

/* For community set mechanism. */
route_map_result_t
route_set_community_additive (void *rule, struct prefix *prefix, route_map_object_t type, void *object)
{
  struct community *com;
  struct community *old_com;
  struct community *new_com;
  struct bgp_info *bgp_info;

  if(type == RMAP_BGP)
    {
      com = rule;
      bgp_info = object;
    
      if (!com)
	return RMAP_OKAY;

      old_com = bgp_info->attr->community;

      if (old_com)
	new_com = community_merge (community_dup (old_com), com);
      else
	new_com = community_dup (com);

      bgp_info->attr->community = new_com;

      bgp_info->attr->flag |= ATTR_FLAG_BIT (BGP_ATTR_COMMUNITIES);
    }

  return RMAP_OKAY;
}

/* Compile function for set community. */
void *
route_set_community_additive_compile (char *arg)
{
  struct community *com;

  com = community_str2com (arg);
  if (! com)
    return NULL;
  return com;
}

/* Free function for set community. */
void
route_set_community_additive_free (void *rule)
{
  struct community *com = rule;
  community_free (com);
}

/* Set community rule structure. */
struct route_map_rule_cmd route_set_community_additive_cmd = 
{
  "community-additive",
  route_set_community_additive,
  route_set_community_additive_compile,
  route_set_community_additive_free,
};

/* "community set none". */
route_map_result_t
route_set_community_none (void *rule, struct prefix *prefix,
			  route_map_object_t type, void *object)
{
  struct bgp_info *bgp_info;

  if (type == RMAP_BGP)
    {
      bgp_info = object;
      bgp_info->attr->flag &= ~(ATTR_FLAG_BIT (BGP_ATTR_COMMUNITIES));
      bgp_info->attr->community = NULL;
    }
  return RMAP_OKAY;
}

void *
route_set_community_none_compile (char *arg)
{
  /* Only return success. */
  return (void *) 1;
}

void
route_set_community_none_free (void *rule)
{
  return;
}

struct route_map_rule_cmd route_set_community_none_cmd = 
{
  "community none",
  route_set_community_none,
  route_set_community_none_compile,
  route_set_community_none_free,
};

/* `set extcommunity rt COMMUNITY' */

/* For community set mechanism. */
route_map_result_t
route_set_ecommunity_rt (void *rule, struct prefix *prefix, 
			 route_map_object_t type, void *object)
{
  struct ecommunity *ecom;
  struct ecommunity *new_ecom;
  struct ecommunity *old_ecom;
  struct bgp_info *bgp_info;

  if (type == RMAP_BGP)
    {
      ecom = rule;
      bgp_info = object;
    
      if (! ecom)
	return RMAP_OKAY;
    
      /* We assume additive for Extended Community. */
      old_ecom = bgp_info->attr->ecommunity;

      if (old_ecom)
	new_ecom = ecommunity_merge (ecommunity_dup (old_ecom), ecom);
      else
	new_ecom = ecommunity_dup (ecom);

      bgp_info->attr->ecommunity = new_ecom;

      bgp_info->attr->flag |= ATTR_FLAG_BIT (BGP_ATTR_EXT_COMMUNITIES);
    }
  return RMAP_OKAY;
}

/* Compile function for set community. */
void *
route_set_ecommunity_rt_compile (char *arg)
{
  struct ecommunity *ecom;

  ecom = ecommunity_str2com (ECOMMUNITY_ROUTE_TARGET, arg);
  if (! ecom)
    return NULL;
  return ecom;
}

/* Free function for set community. */
void
route_set_ecommunity_rt_free (void *rule)
{
  struct ecommunity *ecom = rule;
  ecommunity_free (ecom);
}

/* Set community rule structure. */
struct route_map_rule_cmd route_set_ecommunity_rt_cmd = 
{
  "extcommunity rt",
  route_set_ecommunity_rt,
  route_set_ecommunity_rt_compile,
  route_set_ecommunity_rt_free,
};

/* `set extcommunity soo COMMUNITY' */

/* For community set mechanism. */
route_map_result_t
route_set_ecommunity_soo (void *rule, struct prefix *prefix, 
			 route_map_object_t type, void *object)
{
  struct ecommunity *ecom;
  struct bgp_info *bgp_info;

  if (type == RMAP_BGP)
    {
      ecom = rule;
      bgp_info = object;
    
      if (! ecom)
	return RMAP_OKAY;
    
      bgp_info->attr->flag |= ATTR_FLAG_BIT (BGP_ATTR_EXT_COMMUNITIES);
      bgp_info->attr->ecommunity = ecommunity_dup (ecom);
    }
  return RMAP_OKAY;
}

/* Compile function for set community. */
void *
route_set_ecommunity_soo_compile (char *arg)
{
  struct ecommunity *ecom;

  ecom = ecommunity_str2com (ECOMMUNITY_SITE_ORIGIN, arg);
  if (! ecom)
    return NULL;
  
  return ecom;
}

/* Free function for set community. */
void
route_set_ecommunity_soo_free (void *rule)
{
  struct ecommunity *ecom = rule;
  ecommunity_free (ecom);
}

/* Set community rule structure. */
struct route_map_rule_cmd route_set_ecommunity_soo_cmd = 
{
  "extcommunity soo",
  route_set_ecommunity_soo,
  route_set_ecommunity_soo_compile,
  route_set_ecommunity_soo_free,
};

/* `set origin ORIGIN' */

/* For origin set. */
route_map_result_t
route_set_origin (void *rule, struct prefix *prefix, route_map_object_t type, void *object)
{
  u_char *origin;
  struct bgp_info *bgp_info;

  if(type == RMAP_BGP){
    origin = rule;
    bgp_info = object;
    
    bgp_info->attr->origin = *origin;
  }

  return RMAP_OKAY;
}

/* Compile function for origin set. */
void *
route_set_origin_compile (char *arg)
{
  u_char *origin;

  if (strcmp (arg, "igp") == 0)
    {
      origin = XMALLOC (MTYPE_ROUTE_MAP_COMPILED, sizeof (u_char));
      *origin = 0;
      return origin;
    }
  else if (strcmp (arg, "egp") == 0)
    {
      origin = XMALLOC (MTYPE_ROUTE_MAP_COMPILED, sizeof (u_char));
      *origin = 1;
      return origin;
    }
  else if (strcmp (arg, "incomplete") == 0)
    {
      origin = XMALLOC (MTYPE_ROUTE_MAP_COMPILED, sizeof (u_char));
      *origin = 2;
      return origin;
    }    
  return NULL;
}

/* Compile function for origin set. */
void
route_set_origin_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Set metric rule structure. */
struct route_map_rule_cmd route_set_origin_cmd = 
{
  "origin",
  route_set_origin,
  route_set_origin_compile,
  route_set_origin_free,
};

/* `set atomic-aggregate' */

/* For atomic aggregate set. */
route_map_result_t
route_set_atomic_aggregate (void *rule, struct prefix *prefix, route_map_object_t type, void *object)
{
  struct bgp_info *bgp_info;

  if(type == RMAP_BGP){
    bgp_info = object;
    bgp_info->attr->flag |= ATTR_FLAG_BIT (BGP_ATTR_ATOMIC_AGGREGATE);
  }

  return RMAP_OKAY;
}

/* Compile function for atomic aggregate. */
void *
route_set_atomic_aggregate_compile (char *arg)
{
  return (void *)1;
}

/* Compile function for atomic aggregate. */
void
route_set_atomic_aggregate_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Set atomic aggregate rule structure. */
struct route_map_rule_cmd route_set_atomic_aggregate_cmd = 
{
  "atomic-aggregate",
  route_set_atomic_aggregate,
  route_set_atomic_aggregate_compile,
  route_set_atomic_aggregate_free,
};

/* `set aggregator as AS A.B.C.D' */
struct aggregator
{
  as_t as;
  struct in_addr address;
};

route_map_result_t
route_set_aggregator_as (void *rule, struct prefix *prefix, 
			 route_map_object_t type, void *object)
{
  struct bgp_info *bgp_info;
  struct aggregator *aggregator;

  if(type == RMAP_BGP){
    bgp_info = object;
    aggregator = rule;
    
    bgp_info->attr->aggregator_as = aggregator->as;
    bgp_info->attr->aggregator_addr = aggregator->address;
    bgp_info->attr->flag |= ATTR_FLAG_BIT (BGP_ATTR_AGGREGATOR);
  }

  return RMAP_OKAY;
}

void *
route_set_aggregator_as_compile (char *arg)
{
  struct aggregator *aggregator;
  char as[10];
  char address[20];

  aggregator = XMALLOC (MTYPE_ROUTE_MAP_COMPILED, sizeof (struct aggregator));
  memset (aggregator, 0, sizeof (struct aggregator));

  sscanf (arg, "%s %s", as, address);

  aggregator->as = strtoul (as, NULL, 10);
  inet_aton (address, &aggregator->address);

  return aggregator;
}

void
route_set_aggregator_as_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);
}

struct route_map_rule_cmd route_set_aggregator_as_cmd = 
{
  "aggregator as",
  route_set_aggregator_as,
  route_set_aggregator_as_compile,
  route_set_aggregator_as_free,
};

#ifdef HAVE_IPV6
/* `match ipv6 address IP_ACCESS_LIST' */

route_map_result_t
route_match_ipv6_address (void *rule, struct prefix *prefix, 
			  route_map_object_t type, void *object)
{
  struct access_list *alist;

  if (type == RMAP_BGP)
    {
      alist = access_list_lookup (AF_INET6, (char *) rule);
      if (alist == NULL)
	return RMAP_NOMATCH;
    
      return (access_list_apply (alist, prefix) == FILTER_DENY ?
	      RMAP_NOMATCH : RMAP_MATCH);
    }
  return RMAP_NOMATCH;
}

void *
route_match_ipv6_address_compile (char *arg)
{
  return XSTRDUP (MTYPE_ROUTE_MAP_COMPILED, arg);
}

void
route_match_ipv6_address_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Route map commands for ip address matching. */
struct route_map_rule_cmd route_match_ipv6_address_cmd =
{
  "ipv6 address",
  route_match_ipv6_address,
  route_match_ipv6_address_compile,
  route_match_ipv6_address_free
};

/* `match ipv6 next-hop IP_ADDRESS' */

route_map_result_t
route_match_ipv6_next_hop (void *rule, struct prefix *prefix, 
			   route_map_object_t type, void *object)
{
  struct in6_addr *addr;
  struct bgp_info *bgp_info;

  if (type == RMAP_BGP)
    {
      addr = rule;
      bgp_info = object;
    
      if (IPV6_ADDR_SAME (&bgp_info->attr->mp_nexthop_global, rule))
	return RMAP_MATCH;

      if (bgp_info->attr->mp_nexthop_len == 32 &&
	  IPV6_ADDR_SAME (&bgp_info->attr->mp_nexthop_local, rule))
	return RMAP_MATCH;

      return RMAP_NOMATCH;
    }

  return RMAP_NOMATCH;
}

void *
route_match_ipv6_next_hop_compile (char *arg)
{
  struct in6_addr *addr;
  int ret;

  addr = XMALLOC (MTYPE_ROUTE_MAP_COMPILED, sizeof (struct in6_addr));

  ret = inet_pton (AF_INET6, arg, &addr);
  if (!ret)
    {
      XFREE (MTYPE_ROUTE_MAP_COMPILED, addr);
      return NULL;
    }

  return addr;
}

void
route_match_ipv6_next_hop_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);
}

struct route_map_rule_cmd route_match_ipv6_next_hop_cmd =
{
  "ipv6 next-hop",
  route_match_ipv6_next_hop,
  route_match_ipv6_next_hop_compile,
  route_match_ipv6_next_hop_free
};

/* `match ipv6 prefix-list PREFIX_LIST' */

route_map_result_t
route_match_ipv6_prefix_list (void *rule, struct prefix *prefix, 
			      route_map_object_t type, void *object)
{
  struct prefix_list *plist;

  if (type == RMAP_BGP)
    {
      plist = prefix_list_lookup (AF_INET6, (char *) rule);
      if (plist == NULL)
	return RMAP_NOMATCH;
    
      return (prefix_list_apply (plist, prefix) == PREFIX_DENY ?
	      RMAP_NOMATCH : RMAP_MATCH);
    }
  return RMAP_NOMATCH;
}

void *
route_match_ipv6_prefix_list_compile (char *arg)
{
  return XSTRDUP (MTYPE_ROUTE_MAP_COMPILED, arg);
}

void
route_match_ipv6_prefix_list_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);
}

struct route_map_rule_cmd route_match_ipv6_prefix_list_cmd =
{
  "ipv6 prefix-list",
  route_match_ipv6_prefix_list,
  route_match_ipv6_prefix_list_compile,
  route_match_ipv6_prefix_list_free
};

/* `set ipv6 nexthop global IP_ADDRESS' */

/* Set nexthop to object.  ojbect must be pointer to struct attr. */
route_map_result_t
route_set_ipv6_nexthop_global (void *rule, struct prefix *prefix, 
			       route_map_object_t type, void *object)
{
  struct in6_addr *address;
  struct bgp_info *bgp_info;

  if (type == RMAP_BGP)
    {
      /* Fetch routemap's rule information. */
      address = rule;
      bgp_info = object;
    
      /* Set next hop value. */ 
      bgp_info->attr->mp_nexthop_global = *address;
    
      /* Set nexthop length. */
      if (bgp_info->attr->mp_nexthop_len == 0)
	bgp_info->attr->mp_nexthop_len = 16;
    }

  return RMAP_OKAY;
}

/* Route map `ip next-hop' compile function.  Given string is converted
   to struct in_addr structure. */
void *
route_set_ipv6_nexthop_global_compile (char *arg)
{
  int ret;
  struct in6_addr *address;

  address = XMALLOC (MTYPE_ROUTE_MAP_COMPILED, sizeof (struct in6_addr));

  ret = inet_pton (AF_INET6, arg, address);

  if (ret == 0)
    {
      XFREE (MTYPE_ROUTE_MAP_COMPILED, address);
      return NULL;
    }

  return address;
}

/* Free route map's compiled `ip next-hop' value. */
void
route_set_ipv6_nexthop_global_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Route map commands for ip nexthop set. */
struct route_map_rule_cmd route_set_ipv6_nexthop_global_cmd =
{
  "ipv6 next-hop global",
  route_set_ipv6_nexthop_global,
  route_set_ipv6_nexthop_global_compile,
  route_set_ipv6_nexthop_global_free
};

/* `set ipv6 nexthop local IP_ADDRESS' */

/* Set nexthop to object.  ojbect must be pointer to struct attr. */
route_map_result_t
route_set_ipv6_nexthop_local (void *rule, struct prefix *prefix, 
			      route_map_object_t type, void *object)
{
  struct in6_addr *address;
  struct bgp_info *bgp_info;

  if (type == RMAP_BGP)
    {
      /* Fetch routemap's rule information. */
      address = rule;
      bgp_info = object;
    
      /* Set next hop value. */ 
      bgp_info->attr->mp_nexthop_local = *address;
    
      /* Set nexthop length. */
      if (bgp_info->attr->mp_nexthop_len != 32)
	bgp_info->attr->mp_nexthop_len = 32;
    }

  return RMAP_OKAY;
}

/* Route map `ip nexthop' compile function.  Given string is converted
   to struct in_addr structure. */
void *
route_set_ipv6_nexthop_local_compile (char *arg)
{
  int ret;
  struct in6_addr *address;

  address = XMALLOC (MTYPE_ROUTE_MAP_COMPILED, sizeof (struct in6_addr));

  ret = inet_pton (AF_INET6, arg, address);

  if (ret == 0)
    {
      XFREE (MTYPE_ROUTE_MAP_COMPILED, address);
      return NULL;
    }

  return address;
}

/* Free route map's compiled `ip nexthop' value. */
void
route_set_ipv6_nexthop_local_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Route map commands for ip nexthop set. */
struct route_map_rule_cmd route_set_ipv6_nexthop_local_cmd =
{
  "ipv6 next-hop local",
  route_set_ipv6_nexthop_local,
  route_set_ipv6_nexthop_local_compile,
  route_set_ipv6_nexthop_local_free
};
#endif /* HAVE_IPV6 */

/* `set originator-id' */

/* For origin set. */
route_map_result_t
route_set_originator_id (void *rule, struct prefix *prefix, route_map_object_t type, void *object)
{
  struct in_addr *address;
  struct bgp_info *bgp_info;

  if (type == RMAP_BGP) 
    {
      address = rule;
      bgp_info = object;
    
      bgp_info->attr->flag |= ATTR_FLAG_BIT (BGP_ATTR_ORIGINATOR_ID);
      bgp_info->attr->originator_id = *address;
    }

  return RMAP_OKAY;
}

/* Compile function for originator-id set. */
void *
route_set_originator_id_compile (char *arg)
{
  int ret;
  struct in_addr *address;

  address = XMALLOC (MTYPE_ROUTE_MAP_COMPILED, sizeof (struct in_addr));

  ret = inet_aton (arg, address);

  if (ret == 0)
    {
      XFREE (MTYPE_ROUTE_MAP_COMPILED, address);
      return NULL;
    }

  return address;
}

/* Compile function for originator_id set. */
void
route_set_originator_id_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Set metric rule structure. */
struct route_map_rule_cmd route_set_originator_id_cmd = 
{
  "originator-id",
  route_set_originator_id,
  route_set_originator_id_compile,
  route_set_originator_id_free,
};

/* Add bgp route map rule. */
int
bgp_route_match_add (struct vty *vty, struct route_map_index *index,
		    char *command, char *arg)
{
  int ret;

  ret = route_map_add_match (index, command, arg);
  if (ret)
    {
      switch (ret)
	{
	case RMAP_RULE_MISSING:
	  vty_out (vty, "Can't find rule.%s", VTY_NEWLINE);
	  return CMD_WARNING;
	  break;
	case RMAP_COMPILE_ERROR:
	  vty_out (vty, "Argument is malformed.%s", VTY_NEWLINE);
	  return CMD_WARNING;
	  break;
	}
    }
  return CMD_SUCCESS;
}

/* Delete bgp route map rule. */
int
bgp_route_match_delete (struct vty *vty, struct route_map_index *index,
			char *command, char *arg)
{
  int ret;

  ret = route_map_delete_match (index, command, arg);
  if (ret)
    {
      switch (ret)
	{
	case RMAP_RULE_MISSING:
	  vty_out (vty, "Can't find rule.%s", VTY_NEWLINE);
	  return CMD_WARNING;
	  break;
	case RMAP_COMPILE_ERROR:
	  vty_out (vty, "Argument is malformed.%s", VTY_NEWLINE);
	  return CMD_WARNING;
	  break;
	}
    }
  return CMD_SUCCESS;
}

/* Add bgp route map rule. */
int
bgp_route_set_add (struct vty *vty, struct route_map_index *index,
		   char *command, char *arg)
{
  int ret;

  ret = route_map_add_set (index, command, arg);
  if (ret)
    {
      switch (ret)
	{
	case RMAP_RULE_MISSING:
	  vty_out (vty, "Can't find rule.%s", VTY_NEWLINE);
	  return CMD_WARNING;
	  break;
	case RMAP_COMPILE_ERROR:
	  vty_out (vty, "Argument is malformed.%s", VTY_NEWLINE);
	  return CMD_WARNING;
	  break;
	}
    }
  return CMD_SUCCESS;
}

/* Delete bgp route map rule. */
int
bgp_route_set_delete (struct vty *vty, struct route_map_index *index,
		      char *command, char *arg)
{
  int ret;

  ret = route_map_delete_set (index, command, arg);
  if (ret)
    {
      switch (ret)
	{
	case RMAP_RULE_MISSING:
	  vty_out (vty, "Can't find rule.%s", VTY_NEWLINE);
	  return CMD_WARNING;
	  break;
	case RMAP_COMPILE_ERROR:
	  vty_out (vty, "Argument is malformed.%s", VTY_NEWLINE);
	  return CMD_WARNING;
	  break;
	}
    }
  return CMD_SUCCESS;
}

/* Hook function for updating route_map assignment. */
void
bgp_route_map_update ()
{
  int i;
  struct newnode *nn, *nm;
  struct bgp *bgp;
  struct peer_conf *conf;
  struct bgp_filter *filter;

  NEWLIST_LOOP (bgp_list, bgp, nn)
    {
      NEWLIST_LOOP (bgp->peer_conf, conf, nm)
	{
	  filter = &conf->filter;
	  
	  /* Input filter update. */
	  if (filter->map[BGP_FILTER_IN].name)
	    filter->map[BGP_FILTER_IN].map = 
	      route_map_lookup_by_name (filter->map[BGP_FILTER_IN].name);
	  else
	    filter->map[BGP_FILTER_IN].map = NULL;

	  /* Output filter update. */
	  if (filter->map[BGP_FILTER_OUT].name)
	    filter->map[BGP_FILTER_OUT].map = 
	      route_map_lookup_by_name (filter->map[BGP_FILTER_OUT].name);
	  else
	    filter->map[BGP_FILTER_OUT].map = NULL;
	}
    }

  /* For redistribute route-map updates. */
  NEWLIST_LOOP (bgp_list, bgp, nn)
    {
      for (i = 0; i < ZEBRA_ROUTE_MAX; i++)
	{
	  if (bgp->rmap[ZEBRA_FAMILY_IPV4][i].name)
	    bgp->rmap[ZEBRA_FAMILY_IPV4][i].map = 
	      route_map_lookup_by_name (bgp->rmap[ZEBRA_FAMILY_IPV4][i].name);
#ifdef HAVE_IPV6
	  if (bgp->rmap[ZEBRA_FAMILY_IPV6][i].name)
	    bgp->rmap[ZEBRA_FAMILY_IPV6][i].map =
	      route_map_lookup_by_name (bgp->rmap[ZEBRA_FAMILY_IPV6][i].name);
#endif /* HAVE_IPV6 */
	}
    }
}

#define MATCH_STR "Match values from routing table\n"
#define SET_STR "Set values in destination routing protocol\n"

DEFUN (match_ip_address, 
       match_ip_address_cmd,
       "match ip address WORD",
       MATCH_STR
       IP_STR
       "Match address of route\n"
       "IP access-list name\n")
{
  return bgp_route_match_add (vty, vty->index, "ip address", argv[0]);
}

DEFUN (no_match_ip_address, 
       no_match_ip_address_cmd,
       "no match ip address WORD",
       NO_STR
       MATCH_STR
       IP_STR
       "Match address of route\n"
       "IP access-list name\n")
{
  return bgp_route_match_delete (vty, vty->index, "ip address", argv[0]);
}

DEFUN (match_ip_next_hop, 
       match_ip_next_hop_cmd,
       "match ip next-hop A.B.C.D",
       MATCH_STR
       IP_STR
       "Match next-hop address of route\n"
       "IP address of next hop\n")
{
  return bgp_route_match_add (vty, vty->index, "ip next-hop", argv[0]);
}

DEFUN (no_match_ip_next_hop,
       no_match_ip_next_hop_cmd,
       "no match ip next-hop A.B.C.D",
       NO_STR
       MATCH_STR
       IP_STR
       "Match next-hop address of route\n"
       "IP address of next hop\n")
{
  return bgp_route_match_delete (vty, vty->index, "ip next-hop", argv[0]);
}

DEFUN (match_ip_prefix_list, 
       match_ip_prefix_list_cmd,
       "match ip prefix-list WORD",
       MATCH_STR
       IP_STR
       "Match entries of prefix-lists\n"
       "IP prefix-list name\n")
{
  return bgp_route_match_add (vty, vty->index, "ip prefix-list", argv[0]);
}

DEFUN (no_match_ip_prefix_list,
       no_match_ip_prefix_list_cmd,
       "no match ip prefix-list WORD",
       NO_STR
       MATCH_STR
       IP_STR
       "Match entries of prefix-lists\n"
       "IP prefix-list name\n")
{
  return bgp_route_match_delete (vty, vty->index, "ip prefix-list", argv[0]);
}

DEFUN (match_ip_address_prefix_list, 
       match_ip_address_prefix_list_cmd,
       "match ip address prefix-list WORD",
       MATCH_STR
       IP_STR
       "Match address of route\n"
       "Match entries of prefix-lists\n"
       "IP prefix-list name\n")
{
  return bgp_route_match_add (vty, vty->index, "ip address prefix-list", argv[0]);
}

DEFUN (no_match_ip_address_prefix_list,
       no_match_ip_address_prefix_list_cmd,
       "no match ip address prefix-list WORD",
       NO_STR
       MATCH_STR
       IP_STR
       "Match address of route\n"
       "Match entries of prefix-lists\n"
       "IP prefix-list name\n")
{
  return bgp_route_match_delete (vty, vty->index, "ip address prefix-list", argv[0]);
}

DEFUN (match_metric, 
       match_metric_cmd,
       "match metric <0-4294967295>",
       MATCH_STR
       "Match metric of route\n"
       "Metric value\n")
{
  return bgp_route_match_add (vty, vty->index, "metric", argv[0]);
}

DEFUN (no_match_metric,
       no_match_metric_cmd,
       "no match metric <0-4294967295>",
       NO_STR
       MATCH_STR
       "Match metric of route\n"
       "Metric value\n")
{
  return bgp_route_match_delete (vty, vty->index, "metric", argv[0]);
}

DEFUN (match_community, 
       match_community_cmd,
       "match community WORD",
       MATCH_STR
       "Match BGP community list\n"
       "Community-list name (not community value itself)\n")
{
  return bgp_route_match_add (vty, vty->index, "community", argv[0]);
}

DEFUN (no_match_community,
       no_match_community_cmd,
       "no match community WORD",
       NO_STR
       MATCH_STR
       "Match BGP community list\n"
       "Community-list name (not community value itself)\n")
{
  return bgp_route_match_delete (vty, vty->index, "community", argv[0]);
}

DEFUN (match_aspath,
       match_aspath_cmd,
       "match as-path WORD",
       MATCH_STR
       "Match BGP AS path list\n"
       "AS path access-list name\n")
{
  int i;
  struct buffer *b;
  char *regstr;
  int first;

  first = 0;
  b = buffer_new (BUFFER_STRING, 1024);
  for (i = 0; i < argc; i++)
    {
      if (first)
	buffer_putc (b, ' ');
      else
	first = 1;

      buffer_putstr (b, argv[i]);
    }
  buffer_putc (b, '\0');

  regstr = buffer_getstr (b);
  buffer_free (b);

  return bgp_route_match_add (vty, vty->index, "as-path", regstr);
}

DEFUN (no_match_aspath,
       no_match_aspath_cmd,
       "no match as-path WORD",
       NO_STR
       MATCH_STR
       "Match BGP AS path list\n"
       "AS path access-list name\n")
{
  int i;
  struct buffer *b;
  char *regstr;
  int first;

  first = 0;
  b = buffer_new (BUFFER_STRING, 1024);
  for (i = 0; i < argc; i++)
    {
      if (first)
	buffer_putc (b, ' ');
      else
	first = 1;

      buffer_putstr (b, argv[i]);
    }
  buffer_putc (b, '\0');

  regstr = buffer_getstr (b);
  buffer_free (b);

  return bgp_route_match_delete (vty, vty->index, "as-path", regstr);
}

DEFUN (match_nlri, 
       match_nlri_cmd,
       "match nlri (multicast|unicast)",
       MATCH_STR
       "Match Network Layer Reachability Information\n"
       "Multicast\n"
       "Unicast\n")
{
  return bgp_route_match_add (vty, vty->index, "nlri", argv[0]);
}

DEFUN (no_match_nlri,
       no_match_nlri_cmd,
       "no match nlri (multicast|unicast)",
       NO_STR
       MATCH_STR
       "Match Network Layer Reachability Information\n"
       "Multicast\n"
       "Unicast\n")
{
  return bgp_route_match_delete (vty, vty->index, "nlri", argv[0]);
}

DEFUN (set_nlri, 
       set_nlri_cmd,
       "set nlri (multicast|unicast)",
       SET_STR
       "Network Layer Reachability Information\n"
       "Multicast\n"
       "Unicast\n")
{
  return bgp_route_set_add (vty, vty->index, "nlri", argv[0]);
}

DEFUN (no_set_nlri,
       no_set_nlri_cmd,
       "no set nlri (multicast|unicast)",
       NO_STR
       SET_STR
       "Network Layer Reachability Information\n"
       "Multicast\n"
       "Unicast\n")
{
  return bgp_route_set_delete (vty, vty->index, "nlri", argv[0]);
}

DEFUN (set_ip_nexthop,
       set_ip_nexthop_cmd,
       "set ip next-hop A.B.C.D",
       SET_STR
       IP_STR
       "Next hop address\n"
       "IP address of next hop\n")
{
  return bgp_route_set_add (vty, vty->index, "ip next-hop", argv[0]);
}

DEFUN (no_set_ip_nexthop,
       no_set_ip_nexthop_cmd,
       "no set ip next-hop A.B.C.D",
       NO_STR
       SET_STR
       IP_STR
       "Next hop address\n"
       "IP address of next hop\n")
{
  return bgp_route_set_delete (vty, vty->index, "ip next-hop", argv[0]);
}

DEFUN (set_metric,
       set_metric_cmd,
       "set metric <0-4294967295>",
       SET_STR
       "Metric value for destination routing protocol\n"
       "Metric value\n")
{
  return bgp_route_set_add (vty, vty->index, "metric", argv[0]);
}

DEFUN (no_set_metric,
       no_set_metric_cmd,
       "no set metric <0-4294967295>",
       NO_STR
       SET_STR
       "Metric value for destination routing protocol\n"
       "Metric value\n")
{
  return bgp_route_set_delete (vty, vty->index, "metric", argv[0]);
}

DEFUN (set_local_pref,
       set_local_pref_cmd,
       "set local-preference <0-4294967295>",
       SET_STR
       "BGP local preference path attribute\n"
       "Preference value\n")
{
  return bgp_route_set_add (vty, vty->index, "local-preference", argv[0]);
}

DEFUN (no_set_local_pref,
       no_set_local_pref_cmd,
       "no set local-preference <0-4294967295>",
       NO_STR
       SET_STR
       "BGP local preference path attribute\n"
       "Preference value\n")
{
  return bgp_route_set_delete (vty, vty->index, "local-preference", argv[0]);
}

DEFUN (set_weight,
       set_weight_cmd,
       "set weight <0-4294967295>",
       SET_STR
       "BGP weight for routing table\n"
       "Weight value\n")
{
  return bgp_route_set_add (vty, vty->index, "weight", argv[0]);
}

DEFUN (no_set_weight,
       no_set_weight_cmd,
       "no set weight <0-4294967295>",
       NO_STR
       SET_STR
       "BGP weight for routing table\n"
       "Weight value\n")
{
  return bgp_route_set_delete (vty, vty->index, "weight", argv[0]);
}


DEFUN (set_aspath_prepend,
       set_aspath_prepend_cmd,
       "set as-path prepend .<1-65535>",
       SET_STR
       "Prepend string for a BGP AS-path attribute\n"
       "Prepend to the as-path\n"
       "AS number\n")
{
  int i;
  struct buffer *b;
  char *asstr;
  int first;

  first = 0;
  b = buffer_new (BUFFER_STRING, 1024);
  for (i = 0; i < argc; i++)
    {
      if (first)
	buffer_putc (b, ' ');
      else
	first = 1;

      buffer_putstr (b, argv[i]);
    }
  buffer_putc (b, '\0');

  asstr = buffer_getstr (b);
  buffer_free (b);

  return bgp_route_set_add (vty, vty->index, "as-path prepend", asstr);
}

DEFUN (no_set_aspath_prepend,
       no_set_aspath_prepend_cmd,
       "no set as-path prepend .<1-65535>",
       NO_STR
       SET_STR
       "Prepend string for a BGP AS-path attribute\n"
       "Prepend to the as-path\n"
       "AS number\n")
{
  int i;
  struct buffer *b;
  char *asstr;
  int first;

  first = 0;
  b = buffer_new (BUFFER_STRING, 1024);
  for (i = 0; i < argc; i++)
    {
      if (first)
	buffer_putc (b, ' ');
      else
	first = 1;

      buffer_putstr (b, argv[i]);
    }
  buffer_putc (b, '\0');

  asstr = buffer_getstr (b);
  buffer_free (b);

  return bgp_route_set_delete (vty, vty->index, "as-path prepend", asstr);
}

DEFUN (set_community,
       set_community_cmd,
       "set community .AA:NN",
       SET_STR
       "BGP community attribute\n"
       "Community number in aa:nn format or local-AS|no-advertise|no-export\n")
{
  int i;
  struct buffer *b;
  char *str;
  int first;

  first = 0;
  b = buffer_new (BUFFER_STRING, 1024);
  for (i = 0; i < argc; i++)
    {
      if (first)
	buffer_putc (b, ' ');
      else
	first = 1;

      buffer_putstr (b, argv[i]);
    }
  buffer_putc (b, '\0');

  str = buffer_getstr (b);
  buffer_free (b);

  return bgp_route_set_add (vty, vty->index, "community", str);
}

DEFUN (no_set_community,
       no_set_community_cmd,
       "no set community .AA:NN",
       NO_STR
       SET_STR
       "BGP community attribute\n"
       "Community number in aa:nn format or local-AS|no-advertise|no-export\n")
{
  int i;
  struct buffer *b;
  char *str;
  int first;

  first = 0;
  b = buffer_new (BUFFER_STRING, 1024);
  for (i = 0; i < argc; i++)
    {
      if (first)
	buffer_putc (b, ' ');
      else
	first = 1;

      buffer_putstr (b, argv[i]);
    }
  buffer_putc (b, '\0');

  str = buffer_getstr (b);
  buffer_free (b);

  return bgp_route_set_delete (vty, vty->index, "community", str);
}

DEFUN (set_community_additive,
       set_community_additive_cmd,
       "set community-additive .AA:NN",
       SET_STR
       "BGP community attribute (Add to the existing community)\n"
       "Community number in aa:nn format or local-AS|no-advertise|no-export\n")
{
  int i;
  struct buffer *b;
  char *str;
  int first;

  first = 0;
  b = buffer_new (BUFFER_STRING, 1024);
  for (i = 0; i < argc; i++)
    {
      if (first)
	buffer_putc (b, ' ');
      else
	first = 1;

      buffer_putstr (b, argv[i]);
    }
  buffer_putc (b, '\0');

  str = buffer_getstr (b);
  buffer_free (b);

  return bgp_route_set_add (vty, vty->index, "community-additive", str);
}

DEFUN (no_set_community_additive,
       no_set_community_additive_cmd,
       "no set community-additive .AA:NN",
       NO_STR
       SET_STR
       "BGP community attribute (Add to the existing community)\n"
       "Community number in aa:nn format or local-AS|no-advertise|no-export\n")
{
  int i;
  struct buffer *b;
  char *str;
  int first;

  first = 0;
  b = buffer_new (BUFFER_STRING, 1024);
  for (i = 0; i < argc; i++)
    {
      if (first)
	buffer_putc (b, ' ');
      else
	first = 1;

      buffer_putstr (b, argv[i]);
    }
  buffer_putc (b, '\0');

  str = buffer_getstr (b);
  buffer_free (b);

  return bgp_route_set_delete (vty, vty->index, "community-additive", str);
}

DEFUN (set_community_none,
       set_community_none_cmd,
       "set community none",
       SET_STR
       "BGP community attribute\n"
       "No community attribute\n")
{
  return bgp_route_set_add (vty, vty->index, "community none", NULL);
}

DEFUN (no_set_community_none,
       no_set_community_none_cmd,
       "no set community none",
       NO_STR
       SET_STR
       "BGP community attribute\n"
       "No community attribute\n")
{
  return bgp_route_set_delete (vty, vty->index, "community none", NULL);
}

DEFUN (set_ecommunity_rt,
       set_ecommunity_rt_cmd,
       "set extcommunity rt .ASN:nn_or_IP-address:nn",
       SET_STR
       "BGP extended community attribute\n"
       "Route Target extened communityt\n"
       "VPN extended community\n")
{
  int i;
  struct buffer *b;
  char *str;
  int first;

  first = 0;
  b = buffer_new (BUFFER_STRING, 1024);
  for (i = 0; i < argc; i++)
    {
      if (first)
	buffer_putc (b, ' ');
      else
	first = 1;

      buffer_putstr (b, argv[i]);
    }
  buffer_putc (b, '\0');

  str = buffer_getstr (b);
  buffer_free (b);

  return bgp_route_set_add (vty, vty->index, "extcommunity rt", str);
}

DEFUN (no_set_ecommunity_rt,
       no_set_ecommunity_rt_cmd,
       "no set extcommunity rt .ASN:nn_or_IP-address:nn",
       NO_STR
       SET_STR
       "BGP extended community attribute\n"
       "Route Target extened communityt\n"
       "VPN extended community\n")
{
  int i;
  struct buffer *b;
  char *str;
  int first;

  first = 0;
  b = buffer_new (BUFFER_STRING, 1024);
  for (i = 0; i < argc; i++)
    {
      if (first)
	buffer_putc (b, ' ');
      else
	first = 1;

      buffer_putstr (b, argv[i]);
    }
  buffer_putc (b, '\0');

  str = buffer_getstr (b);
  buffer_free (b);

  return bgp_route_set_delete (vty, vty->index, "extcommunity rt", str);
}

DEFUN (set_ecommunity_soo,
       set_ecommunity_soo_cmd,
       "set extcommunity soo .ASN:nn_or_IP-address:nn",
       SET_STR
       "BGP extended community attribute\n"
       "Site-of-Origin extended community\n"
       "VPN extended community\n")
{
  int i;
  struct buffer *b;
  char *str;
  int first;

  first = 0;
  b = buffer_new (BUFFER_STRING, 1024);
  for (i = 0; i < argc; i++)
    {
      if (first)
	buffer_putc (b, ' ');
      else
	first = 1;

      buffer_putstr (b, argv[i]);
    }
  buffer_putc (b, '\0');

  str = buffer_getstr (b);
  buffer_free (b);

  return bgp_route_set_add (vty, vty->index, "extcommunity soo", str);
}

DEFUN (no_set_ecommunity_soo,
       no_set_ecommunity_soo_cmd,
       "no set extcommunity soo .ASN:nn_or_IP-address:nn",
       NO_STR
       SET_STR
       "BGP extended community attribute\n"
       "Site-of-Origin extended community\n"
       "VPN extended community\n")
{
  int i;
  struct buffer *b;
  char *str;
  int first;

  first = 0;
  b = buffer_new (BUFFER_STRING, 1024);
  for (i = 0; i < argc; i++)
    {
      if (first)
	buffer_putc (b, ' ');
      else
	first = 1;

      buffer_putstr (b, argv[i]);
    }
  buffer_putc (b, '\0');

  str = buffer_getstr (b);
  buffer_free (b);

  return bgp_route_set_delete (vty, vty->index, "extcommunity soo", str);
}

DEFUN (set_origin,
       set_origin_cmd,
       "set origin (egp|igp|incomplete)",
       SET_STR
       "BGP origin code\n"
       "remote EGP\n"
       "local IGP\n"
       "unknown heritage\n")
{
  return bgp_route_set_add (vty, vty->index, "origin", argv[0]);
}

DEFUN (no_set_origin,
       no_set_origin_cmd,
       "no set origin (egp|igp|incomplete)",
       NO_STR
       SET_STR
       "BGP origin code\n"
       "remote EGP\n"
       "local IGP\n"
       "unknown heritage\n")
{
  return bgp_route_set_delete (vty, vty->index, "origin", argv[0]);
}

DEFUN (set_atomic_aggregate,
       set_atomic_aggregate_cmd,
       "set atomic-aggregate",
       SET_STR
       "BGP atomic aggregate attribute\n" )
{
  return bgp_route_set_add (vty, vty->index, "atomic-aggregate", NULL);
}

DEFUN (no_set_atomic_aggregate,
       no_set_atomic_aggregate_cmd,
       "no set atomic-aggregate",
       NO_STR
       SET_STR
       "BGP atomic aggregate attribute\n" )
{
  return bgp_route_set_delete (vty, vty->index, "atomic-aggregate", NULL);
}

DEFUN (set_aggregator_as,
       set_aggregator_as_cmd,
       "set aggregator as <1-65535> A.B.C.D",
       SET_STR
       "BGP aggregator attribute\n"
       "AS number of aggregator\n"
       "AS number\n"
       "IP address of aggregator\n")
{
  int ret;
  as_t as;
  struct in_addr address;
  char *endptr = NULL;
  char *argstr;

  as = strtoul (argv[0], &endptr, 10);
  if (as == 0 || as == ULONG_MAX || *endptr != '\0')
    {
      vty_out (vty, "AS path value malformed%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  ret = inet_aton (argv[1], &address);
  if (ret == 0)
    {
      vty_out (vty, "Aggregator IP address is invalid%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  argstr = XMALLOC (MTYPE_ROUTE_MAP_COMPILED,
		    strlen (argv[0]) + strlen (argv[1]) + 2);

  sprintf (argstr, "%s %s", argv[0], argv[1]);

  ret = bgp_route_set_add (vty, vty->index, "aggregator as", argstr);

  XFREE (MTYPE_ROUTE_MAP_COMPILED, argstr);

  return ret;
}

DEFUN (no_set_aggregator_as,
       no_set_aggregator_as_cmd,
       "no set aggregator as <1-65535> A.B.C.D",
       NO_STR
       SET_STR
       "BGP aggregator attribute\n"
       "AS number of aggregator\n"
       "AS number\n"
       "IP address of aggregator\n")
{
  int ret;
  as_t as;
  struct in_addr address;
  char *endptr = NULL;
  char *argstr;

  as = strtoul (argv[0], &endptr, 10);
  if (as == 0 || as == ULONG_MAX || *endptr != '\0')
    {
      vty_out (vty, "AS path value malformed%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  ret = inet_aton (argv[1], &address);
  if (ret == 0)
    {
      vty_out (vty, "Aggregator IP address is invalid%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  argstr = XMALLOC (MTYPE_ROUTE_MAP_COMPILED,
		    strlen (argv[0]) + strlen (argv[1]) + 2);

  sprintf (argstr, "%s %s", argv[0], argv[1]);

  ret = bgp_route_set_delete (vty, vty->index, "aggregator as", argstr);

  XFREE (MTYPE_ROUTE_MAP_COMPILED, argstr);

  return ret;
}


#ifdef HAVE_IPV6
DEFUN (match_ipv6_address, 
       match_ipv6_address_cmd,
       "match ipv6 address WORD",
       MATCH_STR
       IPV6_STR
       "Match IPv6 address of route\n"
       "IPv6 access-list name\n")
{
  return bgp_route_match_add (vty, vty->index, "ipv6 address", argv[0]);
}

DEFUN (no_match_ipv6_address, 
       no_match_ipv6_address_cmd,
       "no match ipv6 address WORD",
       NO_STR
       MATCH_STR
       IPV6_STR
       "Match IPv6 address of route\n"
       "IPv6 access-list name\n")
{
  return bgp_route_match_delete (vty, vty->index, "ipv6 address", argv[0]);
}

DEFUN (match_ipv6_next_hop, 
       match_ipv6_next_hop_cmd,
       "match ipv6 next-hop X:X::X:X",
       MATCH_STR
       IPV6_STR
       "Match IPv6 next-hop address of route\n"
       "IPv6 address of next hop\n")
{
  return bgp_route_match_add (vty, vty->index, "ipv6 next-hop", argv[0]);
}

DEFUN (no_match_ipv6_next_hop,
       no_match_ipv6_next_hop_cmd,
       "no match ipv6 next-hop X:X::X:X",
       NO_STR
       MATCH_STR
       IPV6_STR
       "Match IPv6 next-hop address of route\n"
       "IPv6 address of next hop\n")
{
  return bgp_route_match_delete (vty, vty->index, "ipv6 next-hop", argv[0]);
}

DEFUN (match_ipv6_prefix_list, 
       match_ipv6_prefix_list_cmd,
       "match ipv6 prefix-list WORD",
       MATCH_STR
       IPV6_STR
       "Match entries of IPv6 prefix-list\n"
       "IPv6 prefix-list name\n")
{
  return bgp_route_match_add (vty, vty->index, "ipv6 prefix-list", argv[0]);
}

DEFUN (no_match_ipv6_prefix_list,
       no_match_ipv6_prefix_list_cmd,
       "no match ipv6 prefix-list WORD",
       NO_STR
       MATCH_STR
       IPV6_STR
       "Match entries of IPv6 prefix-list\n"
       "IPv6 prefix-list name\n")
{
  return bgp_route_match_delete (vty, vty->index, "ipv6 prefix-list", argv[0]);
}

DEFUN (set_ipv6_nexthop_global,
       set_ipv6_nexthop_global_cmd,
       "set ipv6 next-hop global X:X::X:X",
       SET_STR
       IPV6_STR
       "IPv6 next-hop address\n"
       "IPv6 global address\n"
       "IPv6 address of next hop\n")
{
  return bgp_route_set_add (vty, vty->index, "ipv6 next-hop global", argv[0]);
}

DEFUN (no_set_ipv6_nexthop_global,
       no_set_ipv6_nexthop_global_cmd,
       "no set ipv6 next-hop global X:X::X:X",
       NO_STR
       SET_STR
       IPV6_STR
       "IPv6 next-hop address\n"
       "IPv6 global address\n"
       "IPv6 address of next hop\n")
{
  return bgp_route_set_delete (vty, vty->index, "ipv6 next-hop global", argv[0]);
}

DEFUN (set_ipv6_nexthop_local,
       set_ipv6_nexthop_local_cmd,
       "set ipv6 next-hop local X:X::X:X",
       SET_STR
       IPV6_STR
       "IPv6 next-hop address\n"
       "IPv6 local address\n"
       "IPv6 address of next hop\n")
{
  return bgp_route_set_add (vty, vty->index, "ipv6 next-hop local", argv[0]);
}

DEFUN (no_set_ipv6_nexthop_local,
       no_set_ipv6_nexthop_local_cmd,
       "no set ipv6 next-hop local X:X::X:X",
       NO_STR
       SET_STR
       IPV6_STR
       "IPv6 next-hop address\n"
       "IPv6 local address\n"
       "IPv6 address of next hop\n")
{
  return bgp_route_set_delete (vty, vty->index, "ipv6 next-hop local", argv[0]);
}
#endif /* HAVE_IPV6 */

DEFUN (set_originator_id,
       set_originator_id_cmd,
       "set originator-id A.B.C.D",
       SET_STR
       "BGP originator ID attribute\n"
       "IP address of originator\n")
{
  return bgp_route_set_add (vty, vty->index, "originator-id", argv[0]);
}

DEFUN (no_set_originator_id,
       no_set_originator_id_cmd,
       "no set originator-id A.B.C.D",
       NO_STR
       SET_STR
       "BGP originator ID attribute\n"
       "IP address of originator\n")
{
  return bgp_route_set_delete (vty, vty->index, "originator-id", argv[0]);
}


/* Initialization of route map. */
void
bgp_route_map_init ()
{
  route_map_init ();
  route_map_init_vty ();
  route_map_add_hook (bgp_route_map_update);
  route_map_delete_hook (bgp_route_map_update);

  route_map_install_match (&route_match_ip_address_cmd);
  route_map_install_match (&route_match_ip_next_hop_cmd);
  route_map_install_match (&route_match_ip_prefix_list_cmd);
  route_map_install_match (&route_match_ip_address_prefix_list_cmd);
  route_map_install_match (&route_match_aspath_cmd);
  route_map_install_match (&route_match_community_cmd);
  route_map_install_match (&route_match_nlri_cmd);
  route_map_install_match (&route_match_metric_cmd);

  route_map_install_set (&route_set_ip_nexthop_cmd);
  route_map_install_set (&route_set_local_pref_cmd);
  route_map_install_set (&route_set_weight_cmd);
  route_map_install_set (&route_set_metric_cmd);
  route_map_install_set (&route_set_aspath_prepend_cmd);
  route_map_install_set (&route_set_origin_cmd);
  route_map_install_set (&route_set_atomic_aggregate_cmd);
  route_map_install_set (&route_set_aggregator_as_cmd);
  route_map_install_set (&route_set_community_cmd);
  route_map_install_set (&route_set_community_additive_cmd);
  route_map_install_set (&route_set_community_none_cmd);
  route_map_install_set (&route_set_nlri_cmd);
  route_map_install_set (&route_set_originator_id_cmd);
  route_map_install_set (&route_set_ecommunity_rt_cmd);
  route_map_install_set (&route_set_ecommunity_soo_cmd);

  install_element (RMAP_NODE, &match_ip_address_cmd);
  install_element (RMAP_NODE, &no_match_ip_address_cmd);
  install_element (RMAP_NODE, &match_ip_next_hop_cmd);
  install_element (RMAP_NODE, &no_match_ip_next_hop_cmd);
  install_element (RMAP_NODE, &match_ip_prefix_list_cmd);
  install_element (RMAP_NODE, &no_match_ip_prefix_list_cmd);

  install_element (RMAP_NODE, &match_ip_address_prefix_list_cmd);
  install_element (RMAP_NODE, &no_match_ip_address_prefix_list_cmd);

  install_element (RMAP_NODE, &match_aspath_cmd);
  install_element (RMAP_NODE, &no_match_aspath_cmd);
  install_element (RMAP_NODE, &match_metric_cmd);
  install_element (RMAP_NODE, &no_match_metric_cmd);
  install_element (RMAP_NODE, &match_community_cmd);
  install_element (RMAP_NODE, &no_match_community_cmd);
  install_element (RMAP_NODE, &match_nlri_cmd);
  install_element (RMAP_NODE, &no_match_nlri_cmd);

  install_element (RMAP_NODE, &set_ip_nexthop_cmd);
  install_element (RMAP_NODE, &no_set_ip_nexthop_cmd);
  install_element (RMAP_NODE, &set_local_pref_cmd);
  install_element (RMAP_NODE, &no_set_local_pref_cmd);
  install_element (RMAP_NODE, &set_weight_cmd);
  install_element (RMAP_NODE, &no_set_weight_cmd);
  install_element (RMAP_NODE, &set_metric_cmd);
  install_element (RMAP_NODE, &no_set_metric_cmd);
  install_element (RMAP_NODE, &set_aspath_prepend_cmd);
  install_element (RMAP_NODE, &no_set_aspath_prepend_cmd);
  install_element (RMAP_NODE, &set_origin_cmd);
  install_element (RMAP_NODE, &no_set_origin_cmd);
  install_element (RMAP_NODE, &set_atomic_aggregate_cmd);
  install_element (RMAP_NODE, &no_set_atomic_aggregate_cmd);
  install_element (RMAP_NODE, &set_aggregator_as_cmd);
  install_element (RMAP_NODE, &no_set_aggregator_as_cmd);
  install_element (RMAP_NODE, &set_nlri_cmd);
  install_element (RMAP_NODE, &no_set_nlri_cmd);
  install_element (RMAP_NODE, &set_community_cmd);
  install_element (RMAP_NODE, &no_set_community_cmd);
  install_element (RMAP_NODE, &set_community_additive_cmd);
  install_element (RMAP_NODE, &no_set_community_additive_cmd);
  install_element (RMAP_NODE, &set_community_none_cmd);
  install_element (RMAP_NODE, &no_set_community_none_cmd);
  install_element (RMAP_NODE, &set_ecommunity_rt_cmd);
  install_element (RMAP_NODE, &no_set_ecommunity_rt_cmd);
  install_element (RMAP_NODE, &set_ecommunity_soo_cmd);
  install_element (RMAP_NODE, &no_set_ecommunity_soo_cmd);

#ifdef HAVE_IPV6
  route_map_install_match (&route_match_ipv6_address_cmd);
  route_map_install_match (&route_match_ipv6_next_hop_cmd);
  route_map_install_match (&route_match_ipv6_prefix_list_cmd);
  route_map_install_set (&route_set_ipv6_nexthop_global_cmd);
  route_map_install_set (&route_set_ipv6_nexthop_local_cmd);

  install_element (RMAP_NODE, &match_ipv6_address_cmd);
  install_element (RMAP_NODE, &no_match_ipv6_address_cmd);
  install_element (RMAP_NODE, &match_ipv6_next_hop_cmd);
  install_element (RMAP_NODE, &no_match_ipv6_next_hop_cmd);
  install_element (RMAP_NODE, &match_ipv6_prefix_list_cmd);
  install_element (RMAP_NODE, &no_match_ipv6_prefix_list_cmd);
  install_element (RMAP_NODE, &set_ipv6_nexthop_global_cmd);
  install_element (RMAP_NODE, &no_set_ipv6_nexthop_global_cmd);
  install_element (RMAP_NODE, &set_ipv6_nexthop_local_cmd);
  install_element (RMAP_NODE, &no_set_ipv6_nexthop_local_cmd);
#endif /* HAVE_IPV6 */

  install_element (RMAP_NODE, &set_originator_id_cmd);
  install_element (RMAP_NODE, &no_set_originator_id_cmd);
}
