/* RIP SNMP support
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

#include "ripd/ripd.h"

#define RIPV2MIB 1,3,6,1,2,1,23
/* #define RIPDOID 1,3,6,1,4,1,4,3,1,4 */
#define RIPDOID 1,3,6,1,4,1,3317,1,2,3

/* RIPv2-MIB. */
oid rip_oid [] = { RIPV2MIB };
oid ripd_oid [] = { RIPDOID };

/* Hook functions. */
u_char * rip2Globals ();
u_char * rip2IfStatEntry ();
u_char * rip2IfConfAddress ();
u_char * rip2PeerTable ();

/* RIPv2-MIB rip2Globals values. */
#define RIP2GLOBALROUTECHANGES  1
#define RIP2GLOBALQUERIES       2

/* RIPv2-MIB rip2IfStatEntry. */
#define RIP2IFSTATENTRY         1

/* RIPv2-MIB rip2IfStatTable. */
#define RIP2IFSTATADDRESS       1
#define RIP2IFSTATRCVBADPACKETS 2
#define RIP2IFSTATRCVBADROUTES  3
#define RIP2IFSTATSENTUPDATES   4
#define RIP2IFSTATSTATUS        5

/* RIPv2-MIB rip2IfConfTable. */
#define RIP2IFCONFADDRESS       1
#define RIP2IFCONFDOMAIN        2
#define RIP2IFCONFAUTHTYPE      3
#define RIP2IFCONFAUTHKEY       4
#define RIP2IFCONFSEND          5
#define RIP2IFCONFRECEIVE       6
#define RIP2IFCONFDEFAULTMETRIC 7
#define RIP2IFCONFSTATUS        8
#define RIP2IFCONFSRCADDRESS    9

/* RIPv2-MIB rip2PeerTable. */
#define RIP2PEERADDRESS         1
#define RIP2PEERDOMAIN          2
#define RIP2PEERLASTUPDATE      3
#define RIP2PEERVERSION         4
#define RIP2PEERRCVBADPACKETS   5
#define RIP2PEERRCVBADROUTES    6

#define COUNTER ASN_INTEGER
#define IPADDRESS ASN_IPADDRESS
#define STRING ASN_OCTET_STR

struct variable rip_variables[] = 
{
  {RIP2GLOBALROUTECHANGES, COUNTER, RONLY, rip2Globals, 2, {1, 1}},
  {RIP2GLOBALQUERIES, COUNTER, RONLY, rip2Globals, 2, {1, 2}},
  {RIP2IFSTATADDRESS, IPADDRESS, RONLY, rip2IfStatEntry, 3, {2, 1, 1}},
  {RIP2IFSTATRCVBADPACKETS, COUNTER, RONLY, rip2IfStatEntry, 3, {2, 1, 2}},
  {RIP2IFSTATRCVBADROUTES, COUNTER, RONLY, rip2IfStatEntry, 3, {2, 1, 3}},
  {RIP2IFSTATSENTUPDATES, COUNTER, RONLY, rip2IfStatEntry, 3, {2, 1, 4}},
  {RIP2IFSTATSTATUS, COUNTER, RWRITE, rip2IfStatEntry, 3, {2, 1, 5}},
  {RIP2IFCONFADDRESS, IPADDRESS, RONLY, rip2IfConfAddress, 3, {3, 1, 1}},
  {RIP2IFCONFDOMAIN, STRING, RONLY, rip2IfConfAddress, 3, {3, 1, 2}},
  {RIP2IFCONFAUTHTYPE, COUNTER, RONLY, rip2IfConfAddress, 3, {3, 1, 3}},
  {RIP2IFCONFAUTHKEY, STRING, RONLY, rip2IfConfAddress, 3, {3, 1, 4}},
  {RIP2IFCONFSEND, COUNTER, RONLY, rip2IfConfAddress, 3, {3, 1, 5}},
  {RIP2IFCONFRECEIVE, COUNTER, RONLY, rip2IfConfAddress, 3, {3, 1, 6}},
  {RIP2IFCONFDEFAULTMETRIC, COUNTER, RONLY, rip2IfConfAddress, 3, {3, 1, 7}},
  {RIP2IFCONFSTATUS, COUNTER, RONLY, rip2IfConfAddress, 3, {3, 1, 8}},
  {RIP2IFCONFSRCADDRESS, IPADDRESS, RONLY, rip2IfConfAddress, 3, {3, 1, 9}},
  {RIP2PEERADDRESS, COUNTER, RONLY, rip2PeerTable, 3, {4, 1, 1}},
  {RIP2PEERDOMAIN, COUNTER, RONLY, rip2PeerTable, 3, {4, 1, 2}},
  {RIP2PEERLASTUPDATE, COUNTER, RONLY, rip2PeerTable, 3, {4, 1, 3}},
  {RIP2PEERVERSION, COUNTER, RONLY, rip2PeerTable, 3, {4, 1, 4}},
  {RIP2PEERRCVBADPACKETS, COUNTER, RONLY, rip2PeerTable, 3, {4, 1, 5}},
  {RIP2PEERRCVBADROUTES, COUNTER, RONLY, rip2PeerTable, 3, {4, 1, 6}}
};

u_char *
rip2Globals (struct variable *v, oid objid[], size_t *objid_len,
	     int exact, size_t *val_len, WriteMethod **write_method)
{
  if (smux_header_generic(v, objid, objid_len, exact, val_len, write_method) == MATCH_FAILED)
    return NULL;

  /* Retrun global counter. */
  switch (v->magic)
    {
    case RIP2GLOBALROUTECHANGES:
      *val_len  = sizeof (rip_global_route_changes);
      return (u_char *) &rip_global_route_changes;
      break;
    case RIP2GLOBALQUERIES:
      *val_len  = sizeof (rip_global_queries);
      return (u_char *) &rip_global_queries;
      break;
    default:
      return NULL;
      break;
    }
  return NULL;
}

struct interface *
rip_if_lookup_next (struct in_addr *src)
{
  listnode node;
  listnode cnode;
  struct interface *ifp;
  struct prefix *p;
  struct connected *c;

  for (node = listhead (iflist); node; nextnode (node))
    {
      ifp = getdata (node);

      for (cnode = listhead (ifp->connected); cnode; nextnode (cnode))
	{
	  c = getdata (cnode);

	  p = c->address;

	  if (p && p->family == AF_INET)
	    {
	      if (ntohl (p->u.prefix4.s_addr) > ntohl (src->s_addr))
		{
		  src->s_addr = p->u.prefix4.s_addr;
		  return ifp;
		}
	    }	      
	}
    }
  return NULL;
}

struct interface *
rip2IfLookup (struct variable *v, oid objid[], size_t *objid_len, 
	      struct in_addr *addr, int exact)
{
  int len;
  struct interface *ifp;
  
  if (exact)
    {
      /* Check the length. */
      if (*objid_len - v->namelen != sizeof (struct in_addr))
	return NULL;

      oid2in_addr (objid + v->namelen, sizeof (struct in_addr), addr);

      ifp = if_lookup_exact_address (*addr);
      return ifp;
    }
  else
    {
      len = *objid_len - v->namelen;
      oid2in_addr (objid + v->namelen, len, addr);

      ifp = rip_if_lookup_next (addr);

      if (ifp == NULL)
	return NULL;

      oid_copy_addr (objid + v->namelen, addr, sizeof (struct in_addr));
      *objid_len = sizeof (struct in_addr) + v->namelen;

      return ifp;
    }
  return NULL;
}

struct rip_peer *
rip2PeerLookup (struct variable *v, oid objid[], size_t *objid_len, 
		struct in_addr *addr, int exact)
{
  int len;
  struct rip_peer *peer;
  
  if (exact)
    {
      /* Check the length. */
      if (*objid_len - v->namelen != sizeof (struct in_addr))
	return NULL;

      oid2in_addr (objid + v->namelen, sizeof (struct in_addr), addr);

      return rip_peer_lookup (addr);
    }
  else
    {
      len = *objid_len - v->namelen;
      oid2in_addr (objid + v->namelen, len, addr);

      peer = rip_peer_lookup_next (addr);

      if (! peer)
	return NULL;

      oid_copy_addr (objid + v->namelen, &peer->addr,
		     sizeof (struct in_addr));
      *objid_len = sizeof (struct in_addr) + v->namelen;

      return peer;
    }
  return NULL;
}

u_char *
rip2IfStatEntry (struct variable *v, oid objid[], size_t *objid_len,
	         int exact, size_t *val_len, WriteMethod **write_method)
{
  struct interface *ifp;
  struct rip_interface *ri;
  static struct in_addr addr;
  static long valid = 1;

  memset (&addr, 0, sizeof (struct in_addr));
  
  /* Lookup interface. */
  ifp = rip2IfLookup (v, objid, objid_len, &addr, exact);
  if (! ifp)
    return NULL;

  /* Fetch rip_interface information. */
  ri = ifp->info;

  switch (v->magic)
    {
    case RIP2IFSTATADDRESS:
      *val_len = sizeof (struct in_addr);
      return (u_char *) &addr;
      break;
    case RIP2IFSTATRCVBADPACKETS:
      *val_len = sizeof (long);
      return (u_char *) &ri->recv_badpackets;
      break;
    case RIP2IFSTATRCVBADROUTES:
      *val_len = sizeof (long);
      return (u_char *) &ri->recv_badroutes;
      break;
    case RIP2IFSTATSENTUPDATES:
      *val_len = sizeof (long);
      return (u_char *) &ri->sent_updates;
      break;
    case RIP2IFSTATSTATUS:
      *val_len = sizeof (long);
      return (u_char *) &valid;
      break;
    default:
      return NULL;
      break;
    }
  return NULL;
}

long
rip2IfConfSend (struct rip_interface *ri)
{
#define doNotSend       1
#define ripVersion1     2
#define rip1Compatible  3
#define ripVersion2     4
#define ripV1Demand     5
#define ripV2Demand     6

  if (! ri->running)
    return doNotSend;
    
  if (ri->ri_send & RIPv2)
    return ripVersion2;
  else if (ri->ri_send & RIPv1)
    return ripVersion1;
  else if (rip)
    {
      if (rip->version == RIPv2)
	return ripVersion2;
      else if (rip->version == RIPv1)
	return ripVersion1;
    }
  return doNotSend;
}

long
rip2IfConfReceive (struct rip_interface *ri)
{
#define rip1            1
#define rip2            2
#define rip1OrRip2      3
#define doNotReceive    4

  if (! ri->running)
    return doNotReceive;

  if (ri->ri_receive == RI_RIP_VERSION_1_AND_2)
    return rip1OrRip2;
  else if (ri->ri_receive & RIPv2)
    return ripVersion2;
  else if (ri->ri_receive & RIPv1)
    return ripVersion1;
  else
    return doNotReceive;
}

u_char *
rip2IfConfAddress (struct variable *v, oid objid[], size_t *objid_len,
	           int exact, size_t *val_len, WriteMethod **write_method)
{
  static struct in_addr addr;
  static long valid = 1;
  static long domain = 0;
  static long config = 0;

  struct interface *ifp;
  struct rip_interface *ri;

  memset (&addr, 0, sizeof (struct in_addr));
  
  /* Lookup interface. */
  ifp = rip2IfLookup (v, objid, objid_len, &addr, exact);
  if (! ifp)
    return NULL;

  /* Fetch rip_interface information. */
  ri = ifp->info;

  switch (v->magic)
    {
    case RIP2IFCONFADDRESS:
      *val_len = sizeof (struct in_addr);
      return (u_char *) &addr;
      break;
    case RIP2IFCONFDOMAIN:
      *val_len = 2;
      return (u_char *) &domain;
      break;
    case RIP2IFCONFAUTHTYPE:
      *val_len = sizeof (long);
      return (u_char *) &ri->auth_type;
      break;
    case RIP2IFCONFAUTHKEY:
      *val_len = 0;
      return (u_char *) &domain;
      break;
    case RIP2IFCONFSEND:
      config = rip2IfConfSend (ri);
      *val_len = sizeof (long);
      return (u_char *) &config;
      break;
    case RIP2IFCONFRECEIVE:
      config = rip2IfConfReceive (ri);
      *val_len = sizeof (long);
      return (u_char *) &config;
      break;
    case RIP2IFCONFDEFAULTMETRIC:
      *val_len = sizeof (long);
      return (u_char *) &ifp->metric;
      break;
    case RIP2IFCONFSTATUS:
      *val_len = sizeof (long);
      return (u_char *) &valid;
      break;
    case RIP2IFCONFSRCADDRESS:
      *val_len = sizeof (struct in_addr);
      return (u_char *) &addr;
      break;
    default:
      return NULL;
      break;
    }
  return NULL;
}

u_char *
rip2PeerTable (struct variable *v, oid objid[], size_t *objid_len,
	       int exact, size_t *val_len, WriteMethod **write_method)
{
  static struct in_addr addr;
  struct rip_peer *peer;

  memset (&addr, 0, sizeof (struct in_addr));
  
  /* Lookup interface. */
  peer = rip2PeerLookup (v, objid, objid_len, &addr, exact);
  if (! peer)
    return NULL;

  switch (v->magic)
    {
    case RIP2PEERADDRESS:
      *val_len = sizeof (struct in_addr);
      return (u_char *) &addr;
      break;
    case RIP2PEERDOMAIN:
      *val_len = sizeof (struct in_addr);
      return (u_char *) &addr;
      break;
    case RIP2PEERLASTUPDATE:
      *val_len = sizeof (struct in_addr);
      return (u_char *) &addr;
      break;
    case RIP2PEERVERSION:
      *val_len = sizeof (struct in_addr);
      return (u_char *) &addr;
      break;
    case RIP2PEERRCVBADPACKETS:
      *val_len = sizeof (struct in_addr);
      return (u_char *) &addr;
      break;
    case RIP2PEERRCVBADROUTES:
      *val_len = sizeof (struct in_addr);
      return (u_char *) &addr;
      break;
    default:
      return NULL;
      break;
    }
  return NULL;
}

/* Register RIPv2-MIB. */
void
rip_snmp_init ()
{
  smux_init (ripd_oid, sizeof (ripd_oid) / sizeof (oid));
  REGISTER_MIB("mibII/rip", rip_variables, variable, rip_oid);
  smux_start ();
}

#endif /* HAVE_SNMP */
