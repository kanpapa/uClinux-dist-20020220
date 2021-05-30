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

#include "bgpd/bgpd.h"

#define BGP4MIB 1,3,6,1,2,1,15
/* #define BGPDMIB 1,3,6,1,4,1,4,3,1,4 */
#define BGPDMIB 1,3,6,1,4,1,3317,1,2,2

/* BGP4-MIB. */
oid bgp_oid [] = { BGP4MIB };
oid bgpd_oid [] = { BGPDMIB };

/* Hook functions. */
u_char * bgpVersion ();
u_char * bgpLocalAs ();
u_char * bgpPeerTable ();
u_char * bgpRcvdPathAttrTable ();
u_char * bgpIdentifier ();
u_char * bgp4PathAttrTable ();
u_char * bgpTraps ();

/* bgpPeerTable */
#define BGPPEERIDENTIFIER                     1
#define BGPPEERSTATE                          2
#define BGPPEERADMINSTATUS                    3
#define BGPPEERNEGOTIATEDVERSION              4
#define BGPPEERLOCALADDR                      5
#define BGPPEERLOCALPORT                      6
#define BGPPEERREMOTEADDR                     7
#define BGPPEERREMOTEPORT                     8
#define BGPPEERREMOTEAS                       9
#define BGPPEERINUPDATES                     10
#define BGPPEEROUTUPDATES                    11
#define BGPPEERINTOTALMESSAGES               12
#define BGPPEEROUTTOTALMESSAGES              13
#define BGPPEERLASTERROR                     14
#define BGPPEERFSMESTABLISHEDTRANSITIONS     15
#define BGPPEERFSMESTABLISHEDTIME            16
#define BGPPEERCONNECTRETRYINTERVAL          17
#define BGPPEERHOLDTIME                      18
#define BGPPEERKEEPALIVE                     19
#define BGPPEERHOLDTIMECONFIGURED            20
#define BGPPEERKEEPALIVECONFIGURED           21
#define BGPPEERMINASORIGINATIONINTERVAL      22
#define BGPPEERMINROUTEADVERTISEMENTINTERVAL 23
#define BGPPEERINUPDATEELAPSEDTIME           24

/* bgpRcvdPathAttrTable */
#define BGPPATHATTRPEER                       1
#define BGPPATHATTRDESTNETWORK                2
#define BGPPATHATTRORIGIN                     3
#define BGPPATHATTRASPATH                     4
#define BGPPATHATTRNEXTHOP                    5
#define BGPPATHATTRINTERASMETRIC              6

#define BGP4PATHATTRPEER                      1
#define BGP4PATHATTRIPADDRPREFIXLEN           2
#define BGP4PATHATTRIPADDRPREFIX              3
#define BGP4PATHATTRORIGIN                    4
#define BGP4PATHATTRASPATHSEGMENT             5
#define BGP4PATHATTRNEXTHOP                   6
#define BGP4PATHATTRMULTIEXITDISC             7
#define BGP4PATHATTRLOCALPREF                 8
#define BGP4PATHATTRATOMICAGGREGATE           9
#define BGP4PATHATTRAGGREGATORAS             10
#define BGP4PATHATTRAGGREGATORADDR           11
#define BGP4PATHATTRCALCLOCALPREF            12
#define BGP4PATHATTRBEST                     13
#define BGP4PATHATTRUNKNOWN                  14

#define INTEGER ASN_INTEGER
#define INTEGER32 ASN_INTEGER
#define COUNTER32 ASN_INTEGER
#define OCTET_STRING ASN_OCTET_STR
#define IPADDRESS ASN_IPADDRESS
#define GAUGE32 ASN_UNSIGNED

struct variable bgp_variables[] = 
{
  {0, OCTET_STRING, RONLY, bgpVersion, 1, {1}},
  {0, INTEGER, RONLY, bgpLocalAs, 1, {2}},
  {BGPPEERIDENTIFIER, IPADDRESS, RONLY, bgpPeerTable, 3, {3, 1, 1}},
  {BGPPEERSTATE, INTEGER, RONLY, bgpPeerTable, 3, {3, 1, 2}},
  {BGPPEERADMINSTATUS, INTEGER, RONLY, bgpPeerTable, 3, {3, 1, 3}},
  {BGPPEERNEGOTIATEDVERSION, INTEGER32, RONLY, bgpPeerTable, 3, {3, 1, 4}},
  {BGPPEERLOCALADDR, IPADDRESS, RONLY, bgpPeerTable, 3, {3, 1, 5}},
  {BGPPEERLOCALPORT, INTEGER, RONLY, bgpPeerTable, 3, {3, 1, 6}},
  {BGPPEERREMOTEADDR, IPADDRESS, RONLY, bgpPeerTable, 3, {3, 1, 7}},
  {BGPPEERREMOTEPORT, INTEGER, RONLY, bgpPeerTable, 3, {3, 1, 8}},
  {BGPPEERREMOTEAS, INTEGER, RONLY, bgpPeerTable, 3, {3, 1, 9}},
  {BGPPEERINUPDATES, COUNTER32, RONLY, bgpPeerTable, 3, {3, 1, 10}},
  {BGPPEEROUTUPDATES, COUNTER32, RONLY, bgpPeerTable, 3, {3, 1, 11}},
  {BGPPEERINTOTALMESSAGES, COUNTER32, RONLY, bgpPeerTable, 3, {3, 1, 12}},
  {BGPPEEROUTTOTALMESSAGES, COUNTER32, RONLY, bgpPeerTable, 3, {3, 1, 13}},
  {BGPPEERLASTERROR, OCTET_STRING, RONLY, bgpPeerTable, 3, {3, 1, 14}},
  {BGPPEERFSMESTABLISHEDTRANSITIONS, COUNTER32, RONLY, bgpPeerTable, 3, {3, 1, 15}},
  {BGPPEERFSMESTABLISHEDTIME, GAUGE32, RONLY, bgpPeerTable, 3, {3, 1, 16}},
  {BGPPEERCONNECTRETRYINTERVAL, INTEGER, RONLY, bgpPeerTable, 3, {3, 1, 17}},
  {BGPPEERHOLDTIME, INTEGER, RONLY, bgpPeerTable, 3, {3, 1, 18}},
  {BGPPEERKEEPALIVE, INTEGER, RONLY, bgpPeerTable, 3, {3, 1, 19}},
  {BGPPEERHOLDTIMECONFIGURED, INTEGER, RONLY, bgpPeerTable, 3, {3, 1, 20}},
  {BGPPEERKEEPALIVECONFIGURED, INTEGER, RONLY, bgpPeerTable, 3, {3, 1, 21}},
  {BGPPEERMINASORIGINATIONINTERVAL, INTEGER, RONLY, bgpPeerTable, 3, {3, 1, 22}},
  {BGPPEERMINROUTEADVERTISEMENTINTERVAL, INTEGER, RONLY, bgpPeerTable, 3, {3, 1, 23}},
  {BGPPEERINUPDATEELAPSEDTIME, GAUGE32, RONLY, bgpPeerTable, 3, {3, 1, 24}},
  {0, IPADDRESS, RONLY, bgpIdentifier, 1, {4}},
  {BGPPATHATTRPEER, IPADDRESS, RONLY, bgpRcvdPathAttrTable, 3, {5, 1, 1}},
  {BGPPATHATTRDESTNETWORK, IPADDRESS, RONLY, bgpRcvdPathAttrTable, 3, {5, 1, 2}},
  {BGPPATHATTRORIGIN, INTEGER, RONLY, bgpRcvdPathAttrTable, 3, {5, 1, 3}},
  {BGPPATHATTRASPATH, OCTET_STRING, RONLY, bgpRcvdPathAttrTable, 3, {5, 1, 4}},
  {BGPPATHATTRNEXTHOP, IPADDRESS, RONLY, bgpRcvdPathAttrTable, 3, {5, 1, 5}},
  {BGPPATHATTRINTERASMETRIC, INTEGER32, RONLY, bgpRcvdPathAttrTable, 3, {5, 1, 6}},
  {BGP4PATHATTRPEER, IPADDRESS, RONLY, bgp4PathAttrTable, 3, {6, 1, 1}},
  {BGP4PATHATTRIPADDRPREFIXLEN, INTEGER, RONLY, bgp4PathAttrTable, 3, {6, 1, 2}},
  {BGP4PATHATTRIPADDRPREFIX, IPADDRESS, RONLY, bgp4PathAttrTable, 3, {6, 1, 3}},
  {BGP4PATHATTRORIGIN, INTEGER, RONLY, bgp4PathAttrTable, 3, {6, 1, 4}},
  {BGP4PATHATTRASPATHSEGMENT, OCTET_STRING, RONLY, bgp4PathAttrTable, 3, {6, 1, 5}},
  {BGP4PATHATTRNEXTHOP, IPADDRESS, RONLY, bgp4PathAttrTable, 3, {6, 1, 6}},
  {BGP4PATHATTRMULTIEXITDISC, INTEGER, RONLY, bgp4PathAttrTable, 3, {6, 1, 7}},
  {BGP4PATHATTRLOCALPREF, INTEGER, RONLY, bgp4PathAttrTable, 3, {6, 1, 8}},
  {BGP4PATHATTRATOMICAGGREGATE, INTEGER, RONLY, bgp4PathAttrTable, 3, {6, 1, 9}},
  {BGP4PATHATTRAGGREGATORAS, INTEGER, RONLY, bgp4PathAttrTable, 3, {6, 1, 10}},
  {BGP4PATHATTRAGGREGATORADDR, IPADDRESS, RONLY, bgp4PathAttrTable, 3, {6, 1, 11}},
  {BGP4PATHATTRCALCLOCALPREF, INTEGER, RONLY, bgp4PathAttrTable, 3, {6, 1, 12}},
  {BGP4PATHATTRBEST, INTEGER, RONLY, bgp4PathAttrTable, 3, {6, 1, 13}},
  {BGP4PATHATTRUNKNOWN, OCTET_STRING, RONLY, bgp4PathAttrTable, 3, {6, 1, 14}},
  {0, INTEGER, RONLY, bgpTraps, 1, {7}}
};

u_char *
bgpVersion (struct variable *v, oid objid[], size_t *objid_len,
	    int exact, size_t *val_len, WriteMethod **write_method)
{
  static int version;

  if (smux_header_generic(v, objid, objid_len, exact, val_len, write_method) == MATCH_FAILED)
    return NULL;

  /* Retrun BGP version.  Zebra bgpd only support version 4. */
  version = (0x80 >> (BGP_VERSION_4 - 1));

  return (u_char *)&version;
}

u_char *
bgpLocalAs (struct variable *v, oid objid[], size_t *objid_len,
	    int exact, size_t *val_len, WriteMethod **write_method)
{
  static long localas;
  struct bgp *bgp;

  if (smux_header_generic(v, objid, objid_len, exact, val_len, write_method) == MATCH_FAILED)
    return NULL;

  /* Get first bgp structure. */
  bgp = bgp_get_default ();
  if (!bgp)
    return NULL;

  localas = bgp->as;

  *val_len = sizeof (localas);
  return (u_char *)&localas;
}

struct peer *
bgpPeerTable_lookup (struct variable *v, oid objid[], size_t *objid_len, 
		     struct in_addr *addr, int exact)
{
  struct peer *peer = NULL;

  if (exact)
    {
      /* Check the length. */
      if (*objid_len - v->namelen != sizeof (struct in_addr))
	return NULL;

      oid2in_addr (objid, sizeof (struct in_addr), addr);

      /* peer =  peer_lookup_addr_ipv4 (*addr); */
      return peer;
    }

  return NULL;
}

u_char *
bgpPeerTable (struct variable *v, oid objid[], size_t *objid_len,
	      int exact, size_t *val_len, WriteMethod **write_method)
{
  static struct in_addr addr;
  struct peer *peer;

  peer = bgpPeerTable_lookup (v, objid, objid_len, &addr, exact);
  if (! peer)
    return NULL;

  switch (v->magic)
    {
    case BGPPEERIDENTIFIER:
      break;
    case BGPPEERSTATE:
      break;
    case BGPPEERADMINSTATUS:
      break;
    case BGPPEERNEGOTIATEDVERSION:
      break;
    case BGPPEERLOCALADDR:
      break;
    case BGPPEERLOCALPORT:
      break;
    case BGPPEERREMOTEADDR:
      break;
    case BGPPEERREMOTEPORT:
      break;
    case BGPPEERREMOTEAS:
      break;
    case BGPPEERINUPDATES:
      break;
    case BGPPEEROUTUPDATES:
      break;
    case BGPPEERINTOTALMESSAGES:
      break;
    case BGPPEEROUTTOTALMESSAGES:
      break;
    case BGPPEERLASTERROR:
      break;
    case BGPPEERFSMESTABLISHEDTRANSITIONS:
      break;
    case BGPPEERFSMESTABLISHEDTIME:
      break;
    case BGPPEERCONNECTRETRYINTERVAL:
      break;
    case BGPPEERHOLDTIME:
      break;
    case BGPPEERKEEPALIVE:
      break;
    case BGPPEERHOLDTIMECONFIGURED:
      break;
    case BGPPEERKEEPALIVECONFIGURED:
      break;
    case BGPPEERMINASORIGINATIONINTERVAL:
      break;
    case BGPPEERMINROUTEADVERTISEMENTINTERVAL:
      break;
    case BGPPEERINUPDATEELAPSEDTIME:
      break;
    default:
      return NULL;
      break;
    }  

  return NULL;
}

u_char *
bgpRcvdPathAttrTable (struct variable *v, oid objid[], size_t *objid_len,
		      int exact, size_t *val_len, WriteMethod **write_method)
{
  return NULL;
}

u_char *
bgpIdentifier (struct variable *v, oid objid[], size_t *objid_len,
	       int exact, size_t *val_len, WriteMethod **write_method)
{
  return NULL;
}

u_char *
bgp4PathAttrTable (struct variable *v, oid objid[], size_t *objid_len,
		   int exact, size_t *val_len, WriteMethod **write_method)
{
  return NULL;
}

u_char *
bgpTraps (struct variable *v, oid objid[], size_t *objid_len,
	  int exact, size_t *val_len, WriteMethod **write_method)
{
  return NULL;
}

void
bgp_snmp_init ()
{
  smux_init (bgpd_oid, sizeof (bgpd_oid) / sizeof (oid));
  REGISTER_MIB("mibII/bgp", bgp_variables, variable, bgp_oid);
  smux_start ();
}
#endif /* HAVE_SNMP */
