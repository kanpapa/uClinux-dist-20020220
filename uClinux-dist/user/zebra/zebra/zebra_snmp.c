/* BGP4 SNMP support
 * Copyright (C) 1999 Kunihiro Ishiguro
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

#ifdef HAVE_SNMP
#include <asn1.h>
#include <snmp.h>
#include <snmp_impl.h>

#include "if.h"
#include "log.h"
#include "prefix.h"
#include "command.h"
#include "smux.h"
#include "table.h"

#include "zebra/rib.h"


#define IPFWMIB 1,3,6,1,2,1,4,24
/* #define ZEBRAOID 1,3,6,1,4,1,4,3,1,4 */
#define ZEBRAOID 1,3,6,1,4,1,3317,1,2,1

/* BGP4-MIB. */
oid ipfw_oid [] = { IPFWMIB };
oid zebra_oid [] = { ZEBRAOID };

/* Hook functions. */
u_char * ipFwNumber ();
u_char * ipFwTable ();
u_char * ipCidrNumber ();
u_char * ipCidrTable ();

/* ipForwardTable */
#define IPFORWARDDEST                         1
#define IPFORWARDMASK                         2
#define IPFORWARDPOLICY                       3
#define IPFORWARDNEXTHOP                      4
#define IPFORWARDIFINDEX                      5
#define IPFORWARDTYPE                         6
#define IPFORWARDPROTO                        7
#define IPFORWARDAGE                          8
#define IPFORWARDINFO                         9
#define IPFORWARDNEXTHOPAS                   10
#define IPFORWARDMETRIC1                     11
#define IPFORWARDMETRIC2                     12
#define IPFORWARDMETRIC3                     13
#define IPFORWARDMETRIC4                     14
#define IPFORWARDMETRIC5                     15

/* ipCidrRouteTable */
#define IPCIDRROUTEDEST                       1
#define IPCIDRROUTEMASK                       2
#define IPCIDRROUTETOS                        3
#define IPCIDRROUTENEXTHOP                    4
#define IPCIDRROUTEIFINDEX                    5
#define IPCIDRROUTETYPE                       6
#define IPCIDRROUTEPROTO                      7
#define IPCIDRROUTEAGE                        8
#define IPCIDRROUTEINFO                       9
#define IPCIDRROUTENEXTHOPAS                 10
#define IPCIDRROUTEMETRIC1                   11
#define IPCIDRROUTEMETRIC2                   12
#define IPCIDRROUTEMETRIC3                   13
#define IPCIDRROUTEMETRIC4                   14
#define IPCIDRROUTEMETRIC5                   15
#define IPCIDRROUTESTATUS                    16

#define INTEGER32 ASN_INTEGER
#define GAUGE32 ASN_INTEGER
#define ENUMERATION ASN_INTEGER
#define ROWSTATUS ASN_INTEGER
#define IPADDRESS ASN_IPADDRESS
#define OBJECTIDENTIFIER ASN_OBJECT_ID

struct variable zebra_variables[] = 
{
  {0, GAUGE32, RONLY, ipFwNumber, 1, {1}},
  {IPFORWARDDEST, IPADDRESS, RONLY, ipFwTable, 3, {2, 1, 1}},
  {IPFORWARDMASK, IPADDRESS, RONLY, ipFwTable, 3, {2, 1, 2}},
  {IPFORWARDPOLICY, INTEGER32, RONLY, ipFwTable, 3, {2, 1, 3}},
  {IPFORWARDNEXTHOP, IPADDRESS, RONLY, ipFwTable, 3, {2, 1, 4}},
  {IPFORWARDIFINDEX, INTEGER32, RONLY, ipFwTable, 3, {2, 1, 5}},
  {IPFORWARDTYPE, ENUMERATION, RONLY, ipFwTable, 3, {2, 1, 6}},
  {IPFORWARDPROTO, ENUMERATION, RONLY, ipFwTable, 3, {2, 1, 7}},
  {IPFORWARDAGE, INTEGER32, RONLY, ipFwTable, 3, {2, 1, 8}},
  {IPFORWARDINFO, OBJECTIDENTIFIER, RONLY, ipFwTable, 3, {2, 1, 9}},
  {IPFORWARDNEXTHOPAS, INTEGER32, RONLY, ipFwTable, 3, {2, 1, 10}},
  {IPFORWARDMETRIC1, INTEGER32, RONLY, ipFwTable, 3, {2, 1, 11}},
  {IPFORWARDMETRIC2, INTEGER32, RONLY, ipFwTable, 3, {2, 1, 12}},
  {IPFORWARDMETRIC3, INTEGER32, RONLY, ipFwTable, 3, {2, 1, 13}},
  {IPFORWARDMETRIC4, INTEGER32, RONLY, ipFwTable, 3, {2, 1, 14}},
  {IPFORWARDMETRIC5, INTEGER32, RONLY, ipFwTable, 3, {2, 1, 15}},
  {0, GAUGE32, RONLY, ipCidrNumber, 1, {3}},
  {IPCIDRROUTEDEST, IPADDRESS, RONLY, ipCidrTable, 3, {4, 1, 1}},
  {IPCIDRROUTEMASK, IPADDRESS, RONLY, ipCidrTable, 3, {4, 1, 2}},
  {IPCIDRROUTETOS, INTEGER32, RONLY, ipCidrTable, 3, {4, 1, 3}},
  {IPCIDRROUTENEXTHOP, IPADDRESS, RONLY, ipCidrTable, 3, {4, 1, 4}},
  {IPCIDRROUTEIFINDEX, INTEGER32, RONLY, ipCidrTable, 3, {4, 1, 5}},
  {IPCIDRROUTETYPE, ENUMERATION, RONLY, ipCidrTable, 3, {4, 1, 6}},
  {IPCIDRROUTEPROTO, ENUMERATION, RONLY, ipCidrTable, 3, {4, 1, 7}},
  {IPCIDRROUTEAGE, INTEGER32, RONLY, ipCidrTable, 3, {4, 1, 8}},
  {IPCIDRROUTEINFO, OBJECTIDENTIFIER, RONLY, ipCidrTable, 3, {4, 1, 9}},
  {IPCIDRROUTENEXTHOPAS, INTEGER32, RONLY, ipCidrTable, 3, {4, 1, 10}},
  {IPCIDRROUTEMETRIC1, INTEGER32, RONLY, ipCidrTable, 3, {4, 1, 11}},
  {IPCIDRROUTEMETRIC2, INTEGER32, RONLY, ipCidrTable, 3, {4, 1, 12}},
  {IPCIDRROUTEMETRIC3, INTEGER32, RONLY, ipCidrTable, 3, {4, 1, 13}},
  {IPCIDRROUTEMETRIC4, INTEGER32, RONLY, ipCidrTable, 3, {4, 1, 14}},
  {IPCIDRROUTEMETRIC5, INTEGER32, RONLY, ipCidrTable, 3, {4, 1, 15}},
  {IPCIDRROUTESTATUS, ROWSTATUS, RONLY, ipCidrTable, 3, {4, 1, 16}}
};


u_char *
ipFwNumber (struct variable *v, oid objid[], size_t *objid_len,
	    int exact, size_t *val_len, WriteMethod **write_method)
{
  static int result;
  struct route_node *np;

  if (smux_header_generic(v, objid, objid_len, exact, val_len, write_method) == MATCH_FAILED)
    return NULL;

  /* Return number of routing entries. */
  result = 0;
  for (np = route_top (ipv4_rib_table); np; np = route_next (np))
    result++;

  return (u_char *)&result;
}

u_char *
ipCidrNumber (struct variable *v, oid objid[], size_t *objid_len,
	    int exact, size_t *val_len, WriteMethod **write_method)
{
  static int result;
  struct route_node *np;

  if (smux_header_generic(v, objid, objid_len, exact, val_len, write_method) == MATCH_FAILED)
    return NULL;

  /* Return number of routing entries. */
  result = 0;
  for (np = route_top (ipv4_rib_table); np; np = route_next (np))
    result++;

  return (u_char *)&result;
}

int
in_addr_cmp(u_char *p1, u_char *p2)
{
  int i;

  for (i=0; i<4; i++)
    {
      if (*p1 < *p2)
        return -1;
      if (*p1 > *p2)
        return 1;
      p1++; p2++;
    }
  return 0;
}

int proto_trans(int type)
{
  switch (type)
    {
      case ZEBRA_ROUTE_SYSTEM:
        return 1; /* other */
      case ZEBRA_ROUTE_KERNEL:
        return 1; /* other */
      case ZEBRA_ROUTE_CONNECT:
        return 2; /* local interface */
      case ZEBRA_ROUTE_STATIC:
        return 3; /* static route */
      case ZEBRA_ROUTE_RIP:
        return 8; /* rip */
      case ZEBRA_ROUTE_RIPNG:
        return 1; /* shouldn't happen */
      case ZEBRA_ROUTE_OSPF:
        return 13; /* ospf */
      case ZEBRA_ROUTE_OSPF6:
        return 1; /* shouldn't happen */
      case ZEBRA_ROUTE_BGP:
        return 14; /* bgp */
      default:
        return 1; /* other */
    }
}

void
check_replace(struct route_node *np2, struct rib *rib2, 
              struct route_node **np, struct rib **rib)
{
  int proto, proto2;

  if (!*np)
    {
      *np = np2;
      *rib = rib2;
      return;
    }

  if (in_addr_cmp(&(*np)->p.u.prefix, &np2->p.u.prefix) < 0)
    return;
  if (in_addr_cmp(&(*np)->p.u.prefix, &np2->p.u.prefix) > 0)
    {
      *np = np2;
      *rib = rib2;
      return;
    }

  proto = proto_trans((*rib)->type);
  proto2 = proto_trans(rib2->type);

  if (proto2 > proto)
    return;
  if (proto2 < proto)
    {
      *np = np2;
      *rib = rib2;
      return;
    }

  if (in_addr_cmp((u_char *)&(*rib)->u.gate4, (u_char *)&rib2->u.gate4) <= 0)
    return;

  *np = np2;
  *rib = rib2;
  return;
}

void
get_fwtable_route_node(struct variable *v, oid objid[], size_t *objid_len, 
		       int exact, struct route_node **np, struct rib **rib)
{
  struct in_addr dest;
  struct route_node *np2;
  struct rib *rib2;
  int proto;
  int policy;
  struct in_addr nexthop;
  u_char *pnt;
  int i;

/* Init index variables */

  pnt = (u_char *) &dest;
  for (i = 0; i < 4; i++)
    *pnt++ = 0;

  pnt = (u_char *) &nexthop;
  for (i = 0; i < 4; i++)
    *pnt++ = 0;

  proto = 0;
  policy = 0;
 
/* Init return variables */

  *np = NULL;
  *rib = NULL;

/* Short circuit exact matches of wrong length */

  if (exact && (*objid_len != v->namelen + 10))
    return;

/* Get INDEX information out of OID.
 * ipForwardDest, ipForwardProto, ipForwardPolicy, ipForwardNextHop
 */

  if (*objid_len > v->namelen)
    oid2in_addr (objid + v->namelen, MIN(4, *objid_len - v->namelen), &dest);

  if (*objid_len > v->namelen + 4)
    proto = objid[v->namelen + 4];

  if (*objid_len > v->namelen + 5)
    policy = objid[v->namelen + 5];

  if (*objid_len > v->namelen + 6)
    oid2in_addr (objid + v->namelen + 6, MIN(4, *objid_len - v->namelen - 6),
      &nexthop);

  /* Apply GETNEXT on not exact search */

  if (!exact && (*objid_len >= v->namelen + 10))
    {
      pnt = ((u_char *) &nexthop)+3;
      (*pnt)++;
    }

  /* For exact: search matching entry in rib table. */

  if (exact)
    {
      if (policy) /* Not supported (yet?) */
        return;
      for (*np = route_top (ipv4_rib_table); *np; *np = route_next (*np))
	{
	  if (!in_addr_cmp(&(*np)->p.u.prefix, (u_char *)&dest))
	    {
	      for (*rib = (*np)->info; *rib; *rib = (*rib)->next)
	        {
		  if (!in_addr_cmp((u_char *)&(*rib)->u.gate4,
		    (u_char *)&nexthop))
		    if (proto == proto_trans((*rib)->type))
		      return;
		}
	    }
	}
      return;
    }

/* Search next best entry */

  for (np2 = route_top (ipv4_rib_table); np2; np2 = route_next (np2))
    {

      /* Check destination first */
      if (in_addr_cmp(&np2->p.u.prefix, (u_char *)&dest) > 0)
        for (rib2 = np2->info; rib2; rib2 = rib2->next)
	  check_replace(np2, rib2, np, rib);

      if (in_addr_cmp(&np2->p.u.prefix, (u_char *)&dest) == 0)
        { /* have to look at each rib individually */
          for (rib2 = np2->info; rib2; rib2 = rib2->next)
	    {
	      int proto2, policy2;

	      proto2 = proto_trans(rib2->type);
	      policy2 = 0;

	      if (   (policy < policy2)
	          || ((policy == policy2) && (proto < proto2))
		  || ((policy == policy2) && (proto == proto2) &&
		      (in_addr_cmp((u_char *)&rib2->u.gate4,
		      (u_char *) &nexthop) >= 0)))
		check_replace(np2, rib2, np, rib);
	    }
	}
    }

  if (!*rib)
    return;

  policy = 0;
  proto = proto_trans((*rib)->type);

  *objid_len = v->namelen + 10;
  pnt = (u_char *) &(*np)->p.u.prefix;
  for (i = 0; i < 4; i++)
    objid[v->namelen + i] = *pnt++;

  objid[v->namelen + 4] = proto;
  objid[v->namelen + 5] = policy;
  pnt = (u_char *) &(*rib)->u.gate4;
  for (i = 0; i < 4; i++)
    objid[i + v->namelen + 6] = *pnt++;

  return;
}

u_char *
ipFwTable (struct variable *v, oid objid[], size_t *objid_len,
	   int exact, size_t *val_len, WriteMethod **write_method)
{
  struct route_node *np;
  struct rib *rib;
  static int result;
  static int resarr[2];
  static struct in_addr netmask;

  get_fwtable_route_node(v, objid, objid_len, exact, &np, &rib);
  if (!np)
    return NULL;

  switch (v->magic)
    {
    case IPFORWARDDEST:
      *val_len = 4;
      return &np->p.u.prefix;
      break;
    case IPFORWARDMASK:
      masklen2ip(np->p.prefixlen, &netmask);
      *val_len = 4;
      return (u_char *)&netmask;
      break;
    case IPFORWARDPOLICY:
      result = 0;
      *val_len  = sizeof(int);
      return (u_char *)&result;
      break;
    case IPFORWARDNEXTHOP:
      *val_len = 4;
      return (u_char *)&rib->u.gate4;
      break;
    case IPFORWARDIFINDEX:
      *val_len = sizeof(int);
      return (u_char *)&rib->u.ifindex;
      break;
    case IPFORWARDTYPE:
      if (IS_RIB_LINK (rib))
        result = 3;
      else
        result = 4;
      *val_len  = sizeof(int);
      return (u_char *)&result;
      break;
    case IPFORWARDPROTO:
      result = proto_trans(rib->type);
      *val_len  = sizeof(int);
      return (u_char *)&result;
      break;
    case IPFORWARDAGE:
      result = 0;
      *val_len  = sizeof(int);
      return (u_char *)&result;
      break;
    case IPFORWARDINFO:
      resarr[0] = 0;
      resarr[1] = 0;
      *val_len  = 2 * sizeof(int);
      return (u_char *)resarr;
      break;
    case IPFORWARDNEXTHOPAS:
      result = -1;
      *val_len  = sizeof(int);
      return (u_char *)&result;
      break;
    case IPFORWARDMETRIC1:
      result = 0;
      *val_len  = sizeof(int);
      return (u_char *)&result;
      break;
    case IPFORWARDMETRIC2:
      result = 0;
      *val_len  = sizeof(int);
      return (u_char *)&result;
      break;
    case IPFORWARDMETRIC3:
      result = 0;
      *val_len  = sizeof(int);
      return (u_char *)&result;
      break;
    case IPFORWARDMETRIC4:
      result = 0;
      *val_len  = sizeof(int);
      return (u_char *)&result;
      break;
    case IPFORWARDMETRIC5:
      result = 0;
      *val_len  = sizeof(int);
      return (u_char *)&result;
      break;
    default:
      return NULL;
      break;
    }  
  return NULL;
}

u_char *
ipCidrTable (struct variable *v, oid objid[], size_t *objid_len,
	   int exact, size_t *val_len, WriteMethod **write_method)
{
  switch (v->magic)
    {
    case IPCIDRROUTEDEST:
      break;
    default:
      return NULL;
      break;
    }  
  return NULL;
}

void
zebra_snmp_init ()
{
  smux_init (zebra_oid, sizeof (zebra_oid) / sizeof (oid));
  REGISTER_MIB("mibII/ipforward", zebra_variables, variable, ipfw_oid);
  smux_start ();
}
#endif /* HAVE_SNMP */
