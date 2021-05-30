/*
 * snmp_var_route.c - return a pointer to the named variable.
 *
 *
 */
/***********************************************************
	Copyright 1988, 1989 by Carnegie Mellon University
	Copyright 1989	TGV, Incorporated

		      All Rights Reserved

Permission to use, copy, modify, and distribute this software and its
documentation for any purpose and without fee is hereby granted,
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in
supporting documentation, and that the name of CMU and TGV not be used
in advertising or publicity pertaining to distribution of the software
without specific, written prior permission.

CMU AND TGV DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO
EVENT SHALL CMU OR TGV BE LIABLE FOR ANY SPECIAL, INDIRECT OR
CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
******************************************************************/
/*
 * additions, fixes and enhancements for Linux by Erik Schoenfelder
 * (schoenfr@ibr.cs.tu-bs.de) 1994/1995.
 * Linux additions taken from CMU to UCD stack by Jennifer Bray of Origin
 * (jbray@origin-at.co.uk) 1997
 * Support for system({CTL_NET,PF_ROUTE,...) by Simon Leinen
 * (simon@switch.ch) 1997
 */

#include <config.h>

#if !defined(CAN_USE_SYSCTL)

#define GATEWAY			/* MultiNet is always configured this way! */
#include <stdio.h>
#include <sys/types.h>
#if HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#include <sys/socket.h>
#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif
#if HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#if HAVE_SYSLOG_H
#include <syslog.h>
#endif
#if HAVE_MACHINE_PARAM_H
#include <machine/param.h>
#endif
#if HAVE_SYS_MBUF_H
#include <sys/mbuf.h>
#endif
#include <net/if.h>
#ifdef HAVE_NET_IF_VAR_H
#include <net/if_var.h>
#endif
#if HAVE_SYS_HASHING_H
#include <sys/hashing.h>
#endif
#if HAVE_NETINET_IN_VAR_H
#include <netinet/in_var.h>
#endif
#define KERNEL		/* to get routehash and RTHASHSIZ */
#if HAVE_SYS_STREAM_H
#include <sys/stream.h>
#endif
#include <net/route.h>
#undef	KERNEL
#ifdef RTENTRY_4_4
#ifndef STRUCT_RTENTRY_HAS_RT_UNIT
#define rt_unit rt_refcnt	       /* Reuse this field for device # */
#endif
#ifndef STRUCT_RTENTRY_HAS_RT_DST
#define rt_dst rt_nodes->rn_key
#endif
#else /* RTENTRY_4_3 */
#ifndef STRUCT_RTENTRY_HAS_RT_DST
#define rt_dst rt_nodes->rn_key
#endif
#ifndef STRUCT_RTENTRY_HAS_RT_HASH
#define rt_hash rt_pad1
#endif
#ifndef STRUCT_RTENTRY_HAS_RT_REFCNT
#ifndef hpux10
#define rt_refcnt rt_pad2
#endif
#endif
#ifndef STRUCT_RTENTRY_HAS_RT_USE
#define rt_use rt_pad3
#endif
#ifndef STRUCT_RTENTRY_HAS_RT_UNIT
#define rt_unit rt_refcnt	       /* Reuse this field for device # */
#endif
#endif
#ifndef NULL
#define NULL 0
#endif
#if HAVE_KVM_OPENFILES
#include <fcntl.h>
#endif
#if HAVE_KVM_H
#include <kvm.h>
#endif

#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_INET_MIB2_H
#include <inet/mib2.h>
#endif
#if HAVE_SYS_SYSCTL_H
#include <sys/sysctl.h>
#endif
#if HAVE_NET_IF_DL_H
#include <net/if_dl.h>
#endif

#if HAVE_NLIST_H
#include <nlist.h>
#endif
#include "auto_nlist.h"
#if solaris2
#include "kernel_sunos5.h"
#endif
 
#ifdef HAVE_SYS_SYSCTL_H
# ifdef CTL_NET
#  ifdef PF_ROUTE
#   ifdef NET_RT_DUMP
#    define USE_SYSCTL_ROUTE_DUMP
#   endif
#  endif
# endif
#endif

#if HAVE_DMALLOC_H
#include <dmalloc.h>
#endif

#include "asn1.h"
#include "snmp_debug.h"
#include "snmp_logging.h"

#define CACHE_TIME (120)	    /* Seconds */

#include "asn1.h"
#include "snmp_api.h"
#include "snmp_impl.h"
#include "mib.h"
#include "snmp.h"
#include "../snmp_vars.h"
#include "ip.h"
#include "../kernel.h"
#include "interfaces.h"
#include "struct.h"
#include "util_funcs.h"

#ifndef  MIN
#define  MIN(a,b)                     (((a) < (b)) ? (a) : (b))
#endif


extern WriteMethod write_rte;

#ifdef USE_SYSCTL_ROUTE_DUMP

static void Route_Scan_Reload (void);

static unsigned char *all_routes = 0;
static unsigned char *all_routes_end;
static size_t all_routes_size;

extern const struct sockaddr * get_address (const void *, int, int);
extern const struct in_addr * get_in_address (const void *, int, int);

/*
  var_ipRouteEntry(...
  Arguments:
  vp	        IN      - pointer to variable entry that points here
  name          IN/OUT  - IN/name requested, OUT/name found
  length        IN/OUT  - length of IN/OUT oid's 
  exact         IN      - TRUE if an exact match was requested
  var_len       OUT     - length of variable or 0 if function returned
  write_method  out     - pointer to function to set variable, otherwise 0
*/
u_char *
var_ipRouteEntry(struct variable *vp,
		 oid *name,
		 size_t *length,
		 int exact,
		 size_t *var_len,
		 WriteMethod **write_method)
{
  /*
   * object identifier is of form:
   * 1.3.6.1.2.1.4.21.1.1.A.B.C.D,  where A.B.C.D is IP address.
   * IPADDR starts at offset 10.
   */
  struct rt_msghdr *rtp, *saveRtp=0;
  register int Save_Valid, result;
  static int saveNameLen=0, saveExact=0;
  static oid saveName[14], Current[14];
  u_char *cp; u_char *ap;
  oid *op;
#if 0
  /** 
  ** this optimisation fails, if there is only a single route avail.
  ** it is a very special case, but better leave it out ...
  **/
#if 0
  if (rtsize <= 1)
    Save_Valid = 0;
  else
#endif /* 0 */
    /*
     *	OPTIMIZATION:
     *
     *	If the name was the same as the last name, with the possible
     *	exception of the [9]th token, then don't read the routing table
     *
     */

    if ((saveNameLen == *length) && (saveExact == exact)) {
      register int temp=name[9];
      name[9] = 0;
      Save_Valid = (snmp_oid_compare(name, *length, saveName, saveNameLen) == 0);
      name[9] = temp;
    } else
      Save_Valid = 0;

  if (Save_Valid && saveRtp) {
    register int temp=name[9];    /* Fix up 'lowest' found entry */
    memcpy( (char *) name,(char *) Current, 14 * sizeof(oid));
    name[9] = temp;
    *length = 14;
    rtp = saveRtp;
  } else {
#endif /* 0 */
    /* fill in object part of name for current (less sizeof instance part) */

    memcpy( (char *)Current,(char *)vp->name, (int)(vp->namelen) * sizeof(oid));

#if 0
    /*
     *  Only reload if this is the start of a wildcard
     */
    if (*length < 14) {
      Route_Scan_Reload();
    }
#else
    Route_Scan_Reload();
#endif
    for(ap = all_routes; ap < all_routes_end; ap += rtp->rtm_msglen) {
      rtp = (struct rt_msghdr *) ap;
      if (rtp->rtm_type == 0)
	break;
      if (rtp->rtm_version != RTM_VERSION)
	{
	  snmp_log(LOG_ERR, "routing socket message version mismatch (%d instead of %d)\n",
		   rtp->rtm_version, RTM_VERSION);
	  break;
	}
      if (rtp->rtm_type != RTM_GET)
	{
	  snmp_log(LOG_ERR, "routing socket returned message other than GET (%d)\n",
		   rtp->rtm_type);
	  continue;
	}
      if (! (rtp->rtm_addrs & RTA_DST))
	continue;
      cp = (u_char *) get_in_address ((struct sockaddr *) (rtp + 1),
				      rtp->rtm_addrs, RTA_DST);
      if (cp == NULL)
        return NULL;
      
      op = Current + 10;
      *op++ = *cp++;
      *op++ = *cp++;
      *op++ = *cp++;
      *op++ = *cp++;

      result = snmp_oid_compare(name, *length, Current, 14);
      if ((exact && (result == 0)) || (!exact && (result < 0)))
	break;
    }
    if (ap >= all_routes_end || rtp->rtm_type == 0)
      return 0;
    /*
     *  Save in the 'cache'
     */
    memcpy( (char *) saveName,(char *) name, *length * sizeof(oid));
    saveName[9] = '\0';
    saveNameLen = *length;
    saveExact = exact;
    saveRtp = rtp;
    /*
     *  Return the name
     */
    memcpy( (char *) name,(char *) Current, 14 * sizeof(oid));
    *length = 14;
#if 0
  }
#endif /* 0 */

  *write_method = write_rte;
  *var_len = sizeof(long_return);

  switch(vp->magic){
  case IPROUTEDEST:
    return (u_char *)get_in_address ((struct sockaddr *) (rtp + 1),
				     rtp->rtm_addrs, RTA_DST);
  case IPROUTEIFINDEX:
    long_return = (u_long)rtp->rtm_index;
    return (u_char *)&long_return;
  case IPROUTEMETRIC1:
    long_return = (rtp->rtm_flags & RTF_UP) ? 1 : 0;
    return (u_char *)&long_return;
  case IPROUTEMETRIC2:
#if NO_DUMMY_VALUES
    return NULL;
#endif
    long_return = -1;
    return (u_char *)&long_return;
  case IPROUTEMETRIC3:
#if NO_DUMMY_VALUES
    return NULL;
#endif
    long_return = -1;
    return (u_char *)&long_return;
  case IPROUTEMETRIC4:
#if NO_DUMMY_VALUES
    return NULL;
#endif
    long_return = -1;
    return (u_char *)&long_return;
  case IPROUTEMETRIC5:
#if NO_DUMMY_VALUES
    return NULL;
#endif
    long_return = -1;
    return (u_char *)&long_return;
  case IPROUTENEXTHOP:
    return (u_char *)get_in_address ((struct sockaddr *) (rtp + 1),
				     rtp->rtm_addrs, RTA_GATEWAY);
  case IPROUTETYPE:
    long_return = (rtp->rtm_flags & RTF_UP)
      ? (rtp->rtm_flags & RTF_UP) ? 4 : 3
      : 2;
    return (u_char *)&long_return;
  case IPROUTEPROTO:
    long_return = (rtp->rtm_flags & RTF_DYNAMIC)
      ? 10 : (rtp->rtm_flags & RTF_STATIC)
      ? 2 : (rtp->rtm_flags & RTF_DYNAMIC) ? 4 : 1;
    return (u_char *)&long_return;
  case IPROUTEAGE:
#if NO_DUMMY_VALUES
    return NULL;
#endif
    long_return = 0;
    return (u_char *)&long_return;
  case IPROUTEMASK:
    if (rtp->rtm_flags & RTF_HOST)
      {
	long_return = 0x00000001;
	return (u_char *)&long_return;
      }
    else
      {
	return (u_char *)get_in_address ((struct sockaddr *) (rtp + 1),
					 rtp->rtm_addrs, RTA_NETMASK);
      }
  case IPROUTEINFO:
    *var_len = nullOidLen;
    return (u_char *) nullOid;
  default:
    DEBUGMSGTL(("snmpd", "unknown sub-id %d in var_ipRouteEntry\n", vp->magic));
  }
  return NULL;
}

#else /* not USE_SYSCTL_ROUTE_DUMP */

static void Route_Scan_Reload (void);
static RTENTRY **rthead=0;
static int rtsize=0, rtallocate=0;

#if !(defined(linux) || defined(solaris2))
#define NUM_ROUTE_SYMBOLS 2
static char*  route_symbols[] = {
  RTHOST_SYMBOL,
  RTNET_SYMBOL
};
#endif
#endif

#ifdef USE_SYSCTL_ROUTE_DUMP

void
init_var_route (void)
{
}

static void Route_Scan_Reload (void)
{
  size_t size = 0;
  int name[] = { CTL_NET, PF_ROUTE, 0, 0, NET_RT_DUMP, 0 };

  if (sysctl (name, sizeof (name) / sizeof (int),
	      0, &size, 0, 0) == -1)
    {
      snmp_log(LOG_ERR, "sysctl(CTL_NET,PF_ROUTE,0,0,NET_RT_DUMP,0)\n");
    }
  else
    {
      if (all_routes == 0 || all_routes_size < size)
	{
	  if (all_routes != 0)
	    {
	      free (all_routes);
	      all_routes = 0;
	    }
	  if ((all_routes = malloc (size)) == 0)
	    {
	      snmp_log(LOG_ERR, "out of memory allocating route table\n");
	    }
	  all_routes_size = size;
	}
      else
	{
	  size = all_routes_size;
	}
      if (sysctl (name, sizeof (name) / sizeof (int),
		  all_routes, &size, 0, 0) == -1)
	{
	  snmp_log(LOG_ERR, "sysctl(CTL_NET,PF_ROUTE,0,0,NET_RT_DUMP,0)\n");
	}
      all_routes_end = all_routes + size;
    }
}

#else /* not USE_SYSCTL_ROUTE_DUMP */

void init_var_route(void)
{
#ifdef RTTABLES_SYMBOL
  auto_nlist(RTTABLES_SYMBOL,0,0);
#endif
#ifdef RTHASHSIZE_SYMBOL
  auto_nlist(RTHASHSIZE_SYMBOL,0,0);
#endif
#ifdef RTHOST_SYMBOL
  auto_nlist(RTHOST_SYMBOL,0,0);
#endif
#ifdef RTNET_SYMBOL
  auto_nlist(RTNET_SYMBOL,0,0);
#endif
}

#ifndef solaris2

#if NEED_KLGETSA
static union {
    struct  sockaddr_in sin;
    u_short data[128];
} klgetsatmp;

struct sockaddr_in *
klgetsa(struct sockaddr_in *dst)
{
  klookup((u_long)dst, (char *)&klgetsatmp.sin, sizeof klgetsatmp.sin);
  if (klgetsatmp.sin.sin_len > sizeof (klgetsatmp.sin))
    klookup((u_long)dst, (char *)&klgetsatmp.sin, klgetsatmp.sin.sin_len);
  return(&klgetsatmp.sin);
}
#endif

u_char *
var_ipRouteEntry(struct variable *vp,
		oid *name,
		size_t *length,
		int exact,
		size_t *var_len,
		WriteMethod **write_method)
{
    /*
     * object identifier is of form:
     * 1.3.6.1.2.1.4.21.1.1.A.B.C.D,  where A.B.C.D is IP address.
     * IPADDR starts at offset 10.
     */
    register int Save_Valid, result, RtIndex;
    static int saveNameLen=0, saveExact=0, saveRtIndex=0;
    static oid saveName[14], Current[14];
    u_char *cp;
    oid *op;
#if NEED_KLGETSA
    struct sockaddr_in *sa;
#endif
#ifndef linux
    struct ifnet     rt_ifnet;
    struct in_ifaddr rt_ifnetaddr;
#endif
    /** 
     ** this optimisation fails, if there is only a single route avail.
     ** it is a very special case, but better leave it out ...
     **/
#if NO_DUMMY_VALUES
      saveNameLen = 0;
#endif
    if (rtsize <= 1)
      Save_Valid = 0;
    else
    /*
     *	OPTIMIZATION:
     *
     *	If the name was the same as the last name, with the possible
     *	exception of the [9]th token, then don't read the routing table
     *
     */

    if ((saveNameLen == *length) && (saveExact == exact)) {
	register int temp=name[9];
	name[9] = 0;
	Save_Valid = (snmp_oid_compare(name, *length, saveName, saveNameLen) == 0);
	name[9] = temp;
    } else
	Save_Valid = 0;

    if (Save_Valid) {
	register int temp=name[9];    /* Fix up 'lowest' found entry */
	memcpy( (char *) name,(char *) Current, 14 * sizeof(oid));
	name[9] = temp;
	*length = 14;
	RtIndex = saveRtIndex;
    } else {
	/* fill in object part of name for current (less sizeof instance part) */

	memcpy( (char *)Current,(char *)vp->name, (int)(vp->namelen) * sizeof(oid));

#if 0
	/*
	 *  Only reload if this is the start of a wildcard
	 */
	if (*length < 14) {
	    Route_Scan_Reload();
	}
#else
        Route_Scan_Reload();
#endif
	for(RtIndex=0; RtIndex < rtsize; RtIndex++) {
#if NEED_KLGETSA
	    sa = klgetsa((struct sockaddr_in *) rthead[RtIndex]->rt_dst);
	    cp = (u_char *) &(sa->sin_addr.s_addr);
#else
	    cp = (u_char *)&(((struct sockaddr_in *) &(rthead[RtIndex]->rt_dst))->sin_addr.s_addr);
#endif
	    op = Current + 10;
	    *op++ = *cp++;
	    *op++ = *cp++;
	    *op++ = *cp++;
	    *op++ = *cp++;

	    result = snmp_oid_compare(name, *length, Current, 14);
	    if ((exact && (result == 0)) || (!exact && (result < 0)))
		break;
	}
	if (RtIndex >= rtsize)
	    return(NULL);
	/*
	 *  Save in the 'cache'
	 */
	memcpy( (char *) saveName,(char *) name, *length * sizeof(oid));
	saveName[9] = 0;
	saveNameLen = *length;
	saveExact = exact;
	saveRtIndex = RtIndex;
	/*
	 *  Return the name
	 */
	memcpy( (char *) name,(char *) Current, 14 * sizeof(oid));
	*length = 14;
    }

    *write_method = write_rte;
    *var_len = sizeof(long_return);

    switch(vp->magic){
	case IPROUTEDEST:
#if NEED_KLGETSA
	    sa = klgetsa((struct sockaddr_in *) rthead[RtIndex]->rt_dst);
	    return(u_char *) &(sa->sin_addr.s_addr);
#else
	    return(u_char *) &((struct sockaddr_in *) &rthead[RtIndex]->rt_dst)->sin_addr.s_addr;
#endif
	case IPROUTEIFINDEX:
	    long_return = (u_long)rthead[RtIndex]->rt_unit;
	    return (u_char *)&long_return;
	case IPROUTEMETRIC1:
	    long_return = (rthead[RtIndex]->rt_flags & RTF_GATEWAY) ? 1 : 0;
	    return (u_char *)&long_return;
	case IPROUTEMETRIC2:
#if NO_DUMMY_VALUES
	    return NULL;
#endif
	    long_return = -1;
	    return (u_char *)&long_return;
	case IPROUTEMETRIC3:
#if NO_DUMMY_VALUES
	    return NULL;
#endif
	    long_return = -1;
	    return (u_char *)&long_return;
	case IPROUTEMETRIC4:
#if NO_DUMMY_VALUES
	    return NULL;
#endif
	    long_return = -1;
	    return (u_char *)&long_return;
	case IPROUTEMETRIC5:
#if NO_DUMMY_VALUES
	    return NULL;
#endif
	    long_return = -1;
	    return (u_char *)&long_return;
	case IPROUTENEXTHOP:
#if NEED_KLGETSA
	    sa = klgetsa((struct sockaddr_in *) rthead[RtIndex]->rt_gateway);
	    return(u_char *) &(sa->sin_addr.s_addr);
#else
	    return(u_char *) &((struct sockaddr_in *) &rthead[RtIndex]->rt_gateway)->sin_addr.s_addr;
#endif /* *bsd */
	case IPROUTETYPE:
	    long_return = (rthead[RtIndex]->rt_flags & RTF_GATEWAY) ? 4 : 3;
	    return (u_char *)&long_return;
	case IPROUTEPROTO:
	    long_return = (rthead[RtIndex]->rt_flags & RTF_DYNAMIC) ? 4 : 2;
	    return (u_char *)&long_return;
	case IPROUTEAGE:
#if NO_DUMMY_VALUES
	    return NULL;
#endif
	    long_return = 0;
	    return (u_char *)&long_return;
	case IPROUTEMASK:
#if NEED_KLGETSA
		/* XXX - Almost certainly not right
		    but I don't have a suitable system to test this on */
#if NO_DUMMY_VALUES
	    return NULL;
#endif
	    long_return = 0;
#else /*  NEED_KLGETSA */
	    if ( ((struct sockaddr_in *) &rthead[RtIndex]->rt_dst)->sin_addr.s_addr == 0 )
		long_return = 0;	/* Default route */
	    else {
#ifndef linux
		klookup((unsigned long) rthead[RtIndex]->rt_ifp,
			(char *) &rt_ifnet, sizeof(rt_ifnet));
		klookup((unsigned long) rt_ifnet.if_addrlist,
			(char *) &rt_ifnetaddr, sizeof(rt_ifnetaddr));

		long_return = rt_ifnetaddr.ia_subnetmask;
#else /* linux */
	    cp = (u_char *)&(((struct sockaddr_in *) &(rthead[RtIndex]->rt_dst))->sin_addr.s_addr);
                return (u_char *) &(((struct sockaddr_in *) &(rthead[RtIndex]->rt_genmask))->sin_addr.s_addr);
#endif /* linux */
	    }
#endif /* NEED_KLGETSA */
	    return (u_char *)&long_return;
	case IPROUTEINFO:
	    *var_len = nullOidLen;
	    return (u_char *)nullOid;
	default:
	    DEBUGMSGTL(("snmpd", "unknown sub-id %d in var_ipRouteEntry\n", vp->magic));
   }
   return NULL;
}

#else /* solaris2 */

static int
IP_Cmp_Route(void *addr, void *ep)
{
  mib2_ipRouteEntry_t *Ep = ep, *Addr = addr;

  if (
      (Ep->ipRouteDest == Addr->ipRouteDest) &&
      (Ep->ipRouteNextHop == Addr->ipRouteNextHop) &&
      (Ep->ipRouteType == Addr->ipRouteType) &&
      (Ep->ipRouteProto == Addr->ipRouteProto) &&
      (Ep->ipRouteMask == Addr->ipRouteMask) &&
      (Ep->ipRouteInfo.re_max_frag == Addr->ipRouteInfo.re_max_frag) &&
      (Ep->ipRouteInfo.re_rtt == Addr->ipRouteInfo.re_rtt) &&
      (Ep->ipRouteInfo.re_ref == Addr->ipRouteInfo.re_ref) &&
      (Ep->ipRouteInfo.re_frag_flag == Addr->ipRouteInfo.re_frag_flag) &&
      (Ep->ipRouteInfo.re_src_addr == Addr->ipRouteInfo.re_src_addr) &&
      (Ep->ipRouteInfo.re_ire_type == Addr->ipRouteInfo.re_ire_type) &&
      (Ep->ipRouteInfo.re_obpkt == Addr->ipRouteInfo.re_obpkt) &&
      (Ep->ipRouteInfo.re_ibpkt == Addr->ipRouteInfo.re_ibpkt)
      )
    return (0);
  else
    return (1);		/* Not found */
}

u_char *
var_ipRouteEntry(struct variable *vp,
		 oid *name,
		 size_t *length,
		 int exact,
		 size_t *var_len,
		 WriteMethod **write_method)
{
  /*
   * object identifier is of form:
   * 1.3.6.1.2.1.4.21.1.1.A.B.C.D,  where A.B.C.D is IP address.
   * IPADDR starts at offset 10.
   */
#define IP_ROUTENAME_LENGTH	14
#define	IP_ROUTEADDR_OFF	10
  oid 			current[IP_ROUTENAME_LENGTH], lowest[IP_ROUTENAME_LENGTH];
  u_char 		*cp;
  oid 			*op;
  mib2_ipRouteEntry_t	Lowentry, Nextentry, entry;
  int			Found = 0;
  req_e 		req_type;

  /* fill in object part of name for current (less sizeof instance part) */
  
  memcpy( (char *)current,(char *)vp->name, vp->namelen * sizeof(oid));
  if (*length == IP_ROUTENAME_LENGTH) /* Assume that the input name is the lowest */
    memcpy( (char *)lowest,(char *)name, IP_ROUTENAME_LENGTH * sizeof(oid));
  else
    name[IP_ROUTEADDR_OFF] = (oid)-1; /* Grhhh: to prevent accidental comparison :-( */
  for (Nextentry.ipRouteDest = (u_long)-2, req_type = GET_FIRST;
       ;
       Nextentry = entry, req_type = GET_NEXT) {
    if (getMibstat(MIB_IP_ROUTE, &entry, sizeof(mib2_ipRouteEntry_t),
		   req_type, &IP_Cmp_Route, &Nextentry) != 0)
      break;
    COPY_IPADDR(cp, (u_char *)&entry.ipRouteDest, op, current + IP_ROUTEADDR_OFF);
    if (exact){
      if (snmp_oid_compare(current, IP_ROUTENAME_LENGTH, name, *length) == 0){
	memcpy( (char *)lowest,(char *)current, IP_ROUTENAME_LENGTH * sizeof(oid));
	Lowentry = entry;
	Found++;
	break;  /* no need to search further */
      }
    } else {
      if ((snmp_oid_compare(current, IP_ROUTENAME_LENGTH, name, *length) > 0) &&
	  ((Nextentry.ipRouteDest == (u_long)-2)
	   || (snmp_oid_compare(current, IP_ROUTENAME_LENGTH, lowest, IP_ROUTENAME_LENGTH) < 0)
	   || (snmp_oid_compare(name, IP_ROUTENAME_LENGTH, lowest, IP_ROUTENAME_LENGTH) == 0))){

	/* if new one is greater than input and closer to input than
	 * previous lowest, and is not equal to it, save this one as the "next" one.
	 */
	memcpy( (char *)lowest,(char *)current, IP_ROUTENAME_LENGTH * sizeof(oid));
	Lowentry = entry;
	Found++;
      }
    }
  }
  if (Found == 0)
    return(NULL);
  memcpy( (char *) name,(char *)lowest, IP_ROUTENAME_LENGTH * sizeof(oid));
  *length = IP_ROUTENAME_LENGTH;
  *write_method = write_rte;
  *var_len = sizeof(long_return);

  switch(vp->magic){
  case IPROUTEDEST:
    long_return = Lowentry.ipRouteDest;
    return (u_char *)&long_return;
  case IPROUTEIFINDEX:
    long_return = Interface_Index_By_Name(Lowentry.ipRouteIfIndex.o_bytes,
					  Lowentry.ipRouteIfIndex.o_length);
    return (u_char *)&long_return;
  case IPROUTEMETRIC1:
    long_return = Lowentry.ipRouteMetric1;
    return (u_char *)&long_return;
  case IPROUTEMETRIC2:
    long_return = Lowentry.ipRouteMetric2;
    return (u_char *)&long_return;
  case IPROUTEMETRIC3:
    long_return = Lowentry.ipRouteMetric3;
    return (u_char *)&long_return;
  case IPROUTEMETRIC4:
    long_return = Lowentry.ipRouteMetric4;
    return (u_char *)&long_return;
  case IPROUTENEXTHOP:
    long_return = Lowentry.ipRouteNextHop;
    return (u_char *)&long_return;
  case IPROUTETYPE:
    long_return = Lowentry.ipRouteType;
    return (u_char *)&long_return;
  case IPROUTEPROTO:
    long_return = Lowentry.ipRouteProto;
    return (u_char *)&long_return;
  case IPROUTEAGE:
    long_return = Lowentry.ipRouteAge;
    return (u_char *)&long_return;
  case IPROUTEMASK:
    long_return = Lowentry.ipRouteMask;
    return (u_char *)&long_return;
  default:
    DEBUGMSGTL(("snmpd", "unknown sub-id %d in var_ipRouteEntry\n", vp->magic));
  };
  return NULL;
}

#endif /* solaris2 - var_IProute */

#ifndef solaris2
static int qsort_compare (RTENTRY **, RTENTRY **);
#endif

#if defined(RTENTRY_4_4) || defined(RTENTRY_RT_NEXT)

#ifdef RTENTRY_4_4
void
load_rtentries(struct radix_node *pt)
{
  struct radix_node node;
  RTENTRY rt;
  struct ifnet ifnet;
  char name[16], temp[16];
#if !STRUCT_IFNET_HAS_IF_XNAME
  register char *cp;
#endif
  
  if (!klookup((unsigned long)pt , (char *) &node , sizeof (struct radix_node))) {
    DEBUGMSGTL(("mibII/var_route", "Fail\n"));
    return;
  }
  if (node.rn_b >= 0) {
      load_rtentries(node.rn_r);
      load_rtentries(node.rn_l);
  } else {
    if (node.rn_flags & RNF_ROOT) {
      /* root node */
      if (node.rn_dupedkey)
        load_rtentries(node.rn_dupedkey);
      return;
    }
    /* get the route */
    klookup((unsigned long)pt, (char *) &rt, sizeof (RTENTRY));
      
    if (rt.rt_ifp != 0) {
      klookup((unsigned long)rt.rt_ifp, (char *)&ifnet, sizeof (ifnet));
#if STRUCT_IFNET_HAS_IF_XNAME
#if defined(netbsd1) || defined(openbsd2)
      strncpy(name, ifnet.if_xname, sizeof name);
#else
      klookup((unsigned long)ifnet.if_xname, name, sizeof name);
#endif
      name[sizeof (name)-1] = '\0';
#else
      klookup((unsigned long)ifnet.if_name, name, sizeof name);
      name[sizeof (name) - 1] = '\0';
      cp = (char *) strchr(name, '\0');
      string_append_int (cp, ifnet.if_unit);
#endif
      Interface_Scan_Init();
      rt.rt_unit = 0;
      while (Interface_Scan_Next((short *) &(rt.rt_unit), temp, NULL, NULL) != 0) {
        if (strcmp(name, temp) == 0) break;
      }
    }
      
#if CHECK_RT_FLAGS
    if (((rt.rt_flags & RTF_CLONING) != RTF_CLONING)
        && ((rt.rt_flags & RTF_LLINFO) != RTF_LLINFO))
      {
#endif
        /* check for space and malloc */
        if (rtsize >= rtallocate) {
          rthead = (RTENTRY **) realloc((char *)rthead, 2 * rtallocate * sizeof(RTENTRY *));
          memset((char *) &rthead[rtallocate],(0), rtallocate * sizeof(RTENTRY *));
          
          rtallocate *= 2;
        }
        if (!rthead[rtsize])
          rthead[rtsize] = (RTENTRY *) malloc(sizeof(RTENTRY));
        /*
         *	Add this to the database
         */
        memcpy( (char *)rthead[rtsize],(char *) &rt, sizeof(RTENTRY));
        rtsize++;
#if CHECK_RT_FLAGS
      }
#endif

    if (node.rn_dupedkey)
      load_rtentries(node.rn_dupedkey);
  }
}
#endif /* RTENTRY_4_4 */

static void Route_Scan_Reload (void)
{
#if defined(RTENTRY_4_4)
  struct radix_node_head head, *rt_table[AF_MAX+1];
  int i;
#else
  RTENTRY **routehash, mb;
  register RTENTRY *m;
  RTENTRY *rt;
  struct ifnet ifnet;
  int i, table;
  register char *cp;
  char name[16], temp[16];
  int hashsize;
#endif
  static int Time_Of_Last_Reload=0;
  struct timeval now;

  gettimeofday(&now, (struct timezone *)0);
  if (Time_Of_Last_Reload+CACHE_TIME > now.tv_sec)
    return;
  Time_Of_Last_Reload =  now.tv_sec;

  /*
	 *  Makes sure we have SOME space allocated for new routing entries
	 */
  if (!rthead) {
    rthead = (RTENTRY **) malloc(100 * sizeof(RTENTRY *));
    if (!rthead) {
      snmp_log(LOG_ERR,"route table malloc fail\n");
      return;
    }
    memset((char *)rthead,(0), 100 * sizeof(RTENTRY *));
    rtallocate = 100;
  }

  /* reset the routing table size to zero -- was a CMU memory leak */
  rtsize = 0;

#ifdef RTENTRY_4_4 
/* rtentry is a BSD 4.4 compat */

#if !defined(AF_UNSPEC)
#define AF_UNSPEC AF_INET 
#endif

  auto_nlist(RTTABLES_SYMBOL, (char *) rt_table, sizeof(rt_table));
  for(i=0; i <= AF_MAX; i++) {
    if(rt_table[i] == 0)
      continue;
    if (klookup((unsigned long)rt_table[i], (char *) &head, sizeof(head))) {
      load_rtentries(head.rnh_treetop);
    }
  }
        
#else /* rtentry is a BSD 4.3 compat */
  for (table=0; table<NUM_ROUTE_SYMBOLS; table++) {
    auto_nlist(RTHASHSIZE_SYMBOL, (char *)&hashsize, sizeof(hashsize));
    routehash = (RTENTRY **)malloc(hashsize * sizeof(struct mbuf *));
    auto_nlist(route_symbols[table], (char *)routehash,
               hashsize * sizeof(struct mbuf *));
    for (i = 0; i < hashsize; i++) {
      if (routehash[i] == 0)
        continue;
      m = routehash[i];
      while (m) {
        /*
         *	Dig the route out of the kernel...
         */
        klookup(m , (char *)&mb, sizeof (mb));
        m = mb.rt_next;

        rt = &mb;
        if (rt->rt_ifp != 0) {
          klookup( rt->rt_ifp, (char *)&ifnet, sizeof (ifnet));
          klookup( ifnet.if_name, name, 16);
          name[15] = '\0';
          cp = (char *) strchr(name, '\0');
	  string_append_int (cp, ifnet.if_unit);

          Interface_Scan_Init();
          while (Interface_Scan_Next((short *)&rt->rt_unit, temp, NULL, NULL) != 0) {
            if (strcmp(name, temp) == 0) break;
          }
        }
        /*
         *	Allocate a block to hold it and add it to the database
         */
        if (rtsize >= rtallocate) {
          rthead = (RTENTRY **) realloc((char *)rthead, 2 * rtallocate * sizeof(RTENTRY *));
          memset((char *) &rthead[rtallocate],(0), rtallocate * sizeof(RTENTRY *));

          rtallocate *= 2;
        }
        if (!rthead[rtsize])
          rthead[rtsize] = (RTENTRY *) malloc(sizeof(RTENTRY));
        /*
         *	Add this to the database
         */
        memcpy( (char *)rthead[rtsize],(char *)rt, sizeof(RTENTRY));
        rtsize++;
      }
    }
    free(routehash);
  }
#endif
  /*
   *  Sort it!
   */
  qsort((char *) rthead, rtsize, sizeof(rthead[0]),
#ifdef __STDC__
      (int (*)(const void *, const void *))qsort_compare
#else
        qsort_compare
#endif
    );
}

#else

#if HAVE_SYS_MBUF_H
static void Route_Scan_Reload (void)
{
	struct mbuf **routehash, mb;
	register struct mbuf *m;
	struct ifnet ifnet;
	RTENTRY *rt;
	int i, table;
	register char *cp;
	char name[16], temp[16];
	static int Time_Of_Last_Reload=0;
	struct timeval now;
	int hashsize;

	gettimeofday(&now, (struct timezone *)0);
	if (Time_Of_Last_Reload+CACHE_TIME > now.tv_sec)
	  return;
	Time_Of_Last_Reload =  now.tv_sec;
	
	/*
	 *  Makes sure we have SOME space allocated for new routing entries
	 */
	if (!rthead) {
          rthead = (RTENTRY **) malloc(100 * sizeof(RTENTRY *));
          if (!rthead) {
		snmp_log(LOG_ERR,"route table malloc fail\n");
		return;
	    }
          memset((char *)rthead,(0), 100 * sizeof(RTENTRY *));
          rtallocate = 100;
	}

        /* reset the routing table size to zero -- was a CMU memory leak */
        rtsize = 0;
        
	for (table=0; table<NUM_ROUTE_SYMBOLS; table++) {
#ifdef sunV3
	    hashsize = RTHASHSIZ;
#else
	    auto_nlist(RTHASHSIZE_SYMBOL, (char *)&hashsize, sizeof(hashsize));
#endif
	    routehash = (struct mbuf **)malloc(hashsize * sizeof(struct mbuf *));
	    auto_nlist(route_symbols[table], (char *)routehash,
                       hashsize * sizeof(struct mbuf *));
	    for (i = 0; i < hashsize; i++) {
		if (routehash[i] == 0)
			continue;
		m = routehash[i];
		while (m) {
		    /*
		     *	Dig the route out of the kernel...
		     */
		    klookup((unsigned long) m , (char *)&mb, sizeof (mb));
		    m = mb.m_next;
		    rt = mtod(&mb, RTENTRY *);
                    
		    if (rt->rt_ifp != 0) {

			klookup((unsigned long) rt->rt_ifp, (char *)&ifnet,
				sizeof (ifnet));
			klookup((unsigned long) ifnet.if_name, name, 16);
			name[15] = '\0';
			cp = (char *) strchr(name, '\0');
			string_append_int (cp, ifnet.if_unit);
			if (strcmp(name,"lo0") == 0) continue; 

			Interface_Scan_Init();
			while (Interface_Scan_Next((short *)&rt->rt_unit, temp, NULL, NULL) != 0) {
			    if (strcmp(name, temp) == 0) break;
			}
		    }
		    /*
		     *	Allocate a block to hold it and add it to the database
		     */
		    if (rtsize >= rtallocate) {
                      rthead = (RTENTRY **) realloc((char *)rthead, 2 * rtallocate * sizeof(RTENTRY *));
                      memset((char *) &rthead[rtallocate],(0), rtallocate * sizeof(RTENTRY *));

			rtallocate *= 2;
		    }
		    if (!rthead[rtsize])
                      rthead[rtsize] = (RTENTRY *) malloc(sizeof(RTENTRY));
                      /*
		     *	Add this to the database
		     */
		    memcpy( (char *)rthead[rtsize],(char *)rt, sizeof(RTENTRY));
		    rtsize++;
		}
	    }
            free(routehash);
	}
	/*
	 *  Sort it!
	 */
	qsort((char *)rthead,rtsize,sizeof(rthead[0]),

#ifdef __STDC__
              (int (*)(const void *, const void *)) qsort_compare
#else
              qsort_compare
#endif
          );
}
#else
#ifdef linux
static void Route_Scan_Reload (void)
{
	FILE *in;
	char line [256];
	struct rtentry *rt;
	char name[16], temp[16];
	static int Time_Of_Last_Reload=0;
	struct timeval now;

	/* allow 20 seconds in cache: */
	gettimeofday(&now, (struct timezone *)0);
	if (Time_Of_Last_Reload + 20 > now.tv_sec)
	    return;
	Time_Of_Last_Reload =  now.tv_sec;

	/*
	 *  Makes sure we have SOME space allocated for new routing entries
	 */
	if (! rthead) {
	    rthead = (struct rtentry **) calloc(100, sizeof(struct rtentry *));
	    if (! rthead) {
		snmp_log(LOG_ERR,"route table malloc fail\n");
		return;
	    }
	    rtallocate = 100;
	}

	/*
	 * fetch routes from the proc file-system:
	 */

	rtsize = 0;

	if (! (in = fopen ("/proc/net/route", "r")))
	  {
	    snmp_log(LOG_ERR, "cannot open /proc/net/route - burps\n");
	    return;
	  }

	while (fgets (line, sizeof(line), in))
	  {
	    struct rtentry rtent;
	    char rtent_name [32];
	    int refcnt, flags, metric;
	    unsigned use;
	    
	    rt = &rtent;
	    memset ((char *) rt,(0), sizeof(*rt));
	    rt->rt_dev = rtent_name;

	    /*
	     * as with 1.99.14:
	     * Iface Dest GW Flags RefCnt Use Metric Mask MTU Win IRTT
	     * eth0 0A0A0A0A 00000000 05 0 0 0 FFFFFFFF 1500 0 0 
	     */
	    if (8 != sscanf (line, "%s %x %x %x %u %d %d %x %*d %*d %*d\n",
			     rt->rt_dev,
			     &(((struct sockaddr_in *) &(rtent.rt_dst))->sin_addr.s_addr),
			     &(((struct sockaddr_in *) &(rtent.rt_gateway))->sin_addr.s_addr),
/* XXX: fix type of the args */
			     &flags, &refcnt, &use, &metric,
			     &(((struct sockaddr_in *) &(rtent.rt_genmask))->sin_addr.s_addr)))
	      continue;
	    
	    strcpy (name, rt->rt_dev);
	    /* linux says ``lo'', but the interface is stored as ``lo0'': */
	    if (! strcmp (name, "lo"))
	      strcat (name, "0");
	    
	    name[15] = '\0';

	    rt->rt_flags = flags, rt->rt_refcnt = refcnt;
	    rt->rt_use = use, rt->rt_metric = metric;

	    Interface_Scan_Init();
	    while (Interface_Scan_Next((short *)&rt->rt_unit, temp, NULL, NULL) != 0)
		if (strcmp(name, temp) == 0) break;

	    /*
	     *	Allocate a block to hold it and add it to the database
	     */
	    if (rtsize >= rtallocate) {
	      rthead = (struct rtentry **) realloc((char *)rthead, 
				   2 * rtallocate * sizeof(struct rtentry *));
	      memset(&rthead[rtallocate], 0, rtallocate 
		    		   * sizeof(struct rtentry *));
	      rtallocate *= 2;
	    }
	    if (! rthead[rtsize])
	      rthead[rtsize] = (struct rtentry *) malloc(sizeof(struct rtentry));
	    /*
	     *	Add this to the database
	     */
	    memcpy( (char *)rthead[rtsize],(char *)rt, sizeof(struct rtentry));
	    rtsize++;
	  }

	fclose (in);

	/*
	 *  Sort it!
	 */
	qsort((char *)rthead,rtsize,sizeof(rthead[0]),
#ifdef __STDC__
              (int (*)(const void *, const void *)) qsort_compare
#else
              qsort_compare
#endif
          );
}
#endif
#endif
#endif


#ifndef solaris2
/*
 *	Create a host table
 */
static int qsort_compare(RTENTRY **r1, 
			 RTENTRY **r2)
{
#if NEED_KLGETSA
	register u_long dst1 = ntohl(klgetsa((struct sockaddr_in *)(*r1)->rt_dst)->sin_addr.s_addr);
	register u_long dst2 = ntohl(klgetsa((struct sockaddr_in *)(*r2)->rt_dst)->sin_addr.s_addr);
#else
	register u_long dst1 = ntohl(((struct sockaddr_in *) &((*r1)->rt_dst))->sin_addr.s_addr);
	register u_long dst2 = ntohl(((struct sockaddr_in *) &((*r2)->rt_dst))->sin_addr.s_addr);
#endif /* NEED_KLGETSA */

	/*
	 *	Do the comparison
	 */
	if (dst1 == dst2) return(0);
	if (dst1 > dst2) return(1);
	return(-1);
}
#endif /* not USE_SYSCTL_ROUTE_DUMP */

#endif /* solaris2 */

#else /* CAN_USE_SYSCTL */

#include <stddef.h>
#include <stdlib.h>
#include <syslog.h>
#include <time.h>

#include <sys/types.h>
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#if HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#include <net/if_dl.h>
#if HAVE_SYS_STREAM_H
#include <sys/stream.h>
#endif
#include <net/route.h>
#include <netinet/in.h>

#define CACHE_TIME (120)	    /* Seconds */

#include "asn1.h"
#include "snmp_api.h"
#include "snmp_impl.h"
#include "mib.h"
#include "snmp.h"
#include "../snmp_vars.h"
#include "ip.h"
#include "../kernel.h"
#include "interfaces.h"
#include "struct.h"
#include "util_funcs.h"
#include "snmp_logging.h"
#include "snmp_debug.h"

static TAILQ_HEAD(, snmprt) rthead;
static char *rtbuf;
static size_t rtbuflen;
static time_t lasttime;

struct snmprt {
	TAILQ_ENTRY(snmprt) link;
	struct rt_msghdr *hdr;
	struct in_addr dest;
	struct in_addr gateway;
	struct in_addr netmask;
	int index;
	struct in_addr ifa;
};

static void
rtmsg(struct rt_msghdr *rtm)
{
	struct snmprt *rt;
	struct sockaddr *sa;
	int bit, gotdest, gotmask;

	rt = malloc(sizeof *rt);
	if (rt == 0)
		return;
	rt->hdr = rtm;
	rt->ifa.s_addr = 0;
	rt->dest = rt->gateway = rt->netmask = rt->ifa;
	rt->index = rtm->rtm_index;

	gotdest = gotmask = 0;
	sa = (struct sockaddr *)(rtm + 1);
	for (bit = 1; ((char *)sa < (char *)rtm + rtm->rtm_msglen) && bit;
	     bit <<= 1) {
		if ((rtm->rtm_addrs & bit) == 0)
			continue;
		switch (bit) {
		case RTA_DST:
#define satosin(sa) ((struct sockaddr_in *)(sa))
			rt->dest = satosin(sa)->sin_addr;
			gotdest = 1;
			break;
		case RTA_GATEWAY:
			if (sa->sa_family == AF_INET)
				rt->gateway = satosin(sa)->sin_addr;
			break;
		case RTA_NETMASK:
			if (sa->sa_len
			    >= offsetof(struct sockaddr_in, sin_addr))
				rt->netmask = satosin(sa)->sin_addr;
			gotmask = 1;
			break;
		case RTA_IFA:
			if (sa->sa_family == AF_INET)
				rt->ifa = satosin(sa)->sin_addr;
			break;
		}
/* from rtsock.c */
#define ROUNDUP(a) \
        ((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))
		sa = (struct sockaddr *)((char *)sa + ROUNDUP(sa->sa_len));
	}
	if (!gotdest) {
		/* XXX can't happen if code above is correct */
	 snmp_log(LOG_ERR, "route no dest?\n");
		free(rt);
	} else {
		/* If no mask provided, it was a host route. */
		if (!gotmask)
			rt->netmask.s_addr = ~0;
		TAILQ_INSERT_TAIL(&rthead, rt, link);
	}
}

static int
suck_krt(int force)
{
	time_t now;
	struct snmprt *rt, *next;
	size_t len;
	static int name[6] = { CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_DUMP, 0 };
	char *cp;
	struct rt_msghdr *rtm;

	time(&now);
	if (now < (lasttime + CACHE_TIME) && !force)
		return 0;
	lasttime = now;

	for (rt = rthead.tqh_first; rt; rt = next) {
		next = rt->link.tqe_next;
		free(rt);
	}
	TAILQ_INIT(&rthead);

	if (sysctl(name, 6, 0, &len, 0, 0) < 0) {
		syslog(LOG_WARNING, "sysctl net-route-dump: %m");
		return -1;
	}

	if (len > rtbuflen) {
		char *newbuf;
		newbuf = realloc(rtbuf, len);
		if (newbuf == 0)
			return -1;
		rtbuf = newbuf;
		rtbuflen = len;
	}

	if (sysctl(name, 6, rtbuf, &len, 0, 0) < 0) {
		syslog(LOG_WARNING, "sysctl net-route-dump: %m");
		return -1;
	}

	cp = rtbuf;
	while (cp < rtbuf + len) {
		rtm = (struct rt_msghdr *)cp;
		/*
		 * NB:
		 * You might want to exclude routes with RTF_WASCLONED
		 * set.  This keeps the cloned host routes (and thus also
		 * ARP entries) out of the routing table.  Thus, it also
		 * presents management stations with an incomplete view.
		 * I believe that it should be possible for a management
		 * station to examine (and perhaps delete) such routes.
		 */
		if (rtm->rtm_version == RTM_VERSION 
		    && rtm->rtm_type == RTM_GET)
			rtmsg(rtm);
		cp += rtm->rtm_msglen;
	}
	return 0;
}

u_char *
var_ipRouteEntry(struct variable *vp,
		 oid *name,
		 size_t *length,
		 int exact,
		 size_t *var_len,
		 WriteMethod **write_method)
{
	/*
	 * object identifier is of form:
	 * 1.3.6.1.2.1.4.21.1.1.A.B.C.D,  where A.B.C.D is IP address.
	 * IPADDR starts at offset 10.
	 */
	int Save_Valid, result;
	u_char *cp;
	oid *op;
	struct snmprt *rt;
	static struct snmprt *savert;
	static int saveNameLen, saveExact;
	static oid saveName[14], Current[14];

#if 0
	/*
	 *	OPTIMIZATION:
	 *
	 *	If the name was the same as the last name, with the possible
	 *	exception of the [9]th token, then don't read the routing table
	 *
	 */

	if ((saveNameLen == *length) && (saveExact == exact)) {
		int temp = name[9];
		name[9] = 0;
		Save_Valid = !snmp_oid_compare(name, *length, saveName, saveNameLen);
		name[9] = temp;
	} else {
		Save_Valid = 0;
	}
#else
	Save_Valid = 0;
#endif

	if (Save_Valid) {
		int temp = name[9];
		memcpy(name, Current, 14 * sizeof(oid));
		name[9] = temp;
		*length = 14;
		rt = savert;
	} else {
		/* fill in object part of name for current
		   (less sizeof instance part) */

		memcpy(Current, vp->name, (int)(vp->namelen) * sizeof(oid));

		suck_krt(0);

		for (rt = rthead.tqh_first; rt; rt = rt->link.tqe_next) {
			op = Current + 10;
			cp = (u_char *)&rt->dest;
			*op++ = *cp++;
			*op++ = *cp++;
			*op++ = *cp++;
			*op++ = *cp++;
			result = snmp_oid_compare(name, *length, Current, 14);
			if ((exact && (result == 0))
			    || (!exact && (result < 0)))
				break;
		}
		if (rt == NULL)
			return NULL;

		/*
		 *  Save in the 'cache'
		 */
		memcpy(saveName, name, *length * sizeof(oid));
		saveName[9] = 0;
		saveNameLen = *length;
		saveExact = exact;
		savert = rt;

		/*
		 *  Return the name
		 */
		memcpy(name, Current, 14 * sizeof(oid));
		*length = 14;
	}

	*write_method = write_rte;
	*var_len = sizeof long_return;

	switch (vp->magic) {
	case IPROUTEDEST:
		long_return = rt->dest.s_addr;
		return (u_char *)&long_return;

	case IPROUTEIFINDEX:
		long_return = rt->index;
		return (u_char *)&long_return;

	case IPROUTEMETRIC1:
		long_return = (rt->hdr->rtm_flags & RTF_GATEWAY) ? 1 : 0;
		return (u_char *)&long_return;
	case IPROUTEMETRIC2:
		long_return = rt->hdr->rtm_rmx.rmx_rtt;
		return (u_char *)&long_return;
	case IPROUTEMETRIC3:
		long_return = rt->hdr->rtm_rmx.rmx_rttvar;
		return (u_char *)&long_return;
	case IPROUTEMETRIC4:
		long_return = rt->hdr->rtm_rmx.rmx_ssthresh;
		return (u_char *)&long_return;
	case IPROUTEMETRIC5:
		long_return = rt->hdr->rtm_rmx.rmx_mtu;
		return (u_char *)&long_return;

	case IPROUTENEXTHOP:
		if (rt->gateway.s_addr == 0 && rt->ifa.s_addr == 0)
			long_return = 0;
		else if (rt->gateway.s_addr == 0)
			long_return = rt->ifa.s_addr;
		else
			long_return = rt->gateway.s_addr;
		return (u_char *)&long_return;

	case IPROUTETYPE:
		long_return = (rt->hdr->rtm_flags & RTF_GATEWAY) ? 4 : 3;
		return (u_char *)&long_return;

	case IPROUTEPROTO:
		long_return = (rt->hdr->rtm_flags & RTF_DYNAMIC) ? 4 : 2;
		return (u_char *)&long_return;

	case IPROUTEAGE:
#if NO_DUMMY_VALUES
		return NULL;
#endif
		long_return = 0;
		return (u_char *)&long_return;

	case IPROUTEMASK:
		long_return = rt->netmask.s_addr;
		return (u_char *)&long_return;

	case IPROUTEINFO:
		*var_len = nullOidLen;
		return (u_char *)nullOid;
	default:
		DEBUGMSGTL(("snmpd", "unknown sub-id %d in var_ipRouteEntry\n", vp->magic));
	}
	return NULL;
}

void
init_var_route(void)
{
	;
}

#endif /* CAN_USE_SYSCTL */

#if defined(HAVE_SYS_SYSCTL_H) && !defined(linux)
/*
  get_address()

  Traverse the address structures after a routing socket message and
  extract a specific one.

  Some of this is peculiar to IRIX 6.2, which doesn't have sa_len in
  the sockaddr structure yet.  With sa_len, skipping an address entry
  would be much easier.
 */
#include <sys/un.h>

const struct sockaddr *
get_address (const void * _ap, int addresses, int wanted)
{
  const struct sockaddr *ap = (const struct sockaddr *) _ap;
  int iindex;
  int bitmask;

  for (iindex = 0, bitmask = 1;
       iindex < RTAX_MAX;
       ++iindex, bitmask <<= 1)
    {
      if (bitmask == wanted)
	{
	  if (bitmask & addresses)
	    {
	      return ap;
	    }
	  else
	    {
	      return 0;
	    }
	}
      else if (bitmask & addresses)
	{
	  unsigned length = (unsigned)snmp_socket_length(ap->sa_family);
	  while (length % sizeof (long) != 0)
	    ++length;
	  ap = (const struct sockaddr *) ((const char *) ap + length);
	}
    }
  return 0;
}

/*
  get_in_address()

  Convenience function for the special case of get_address where an
  AF_INET address is desired, and we're only interested in the in_addr
  part.
 */
const struct in_addr *
get_in_address (const void * ap, int addresses, int wanted)
{
  const struct sockaddr_in * a;

  a =  (const struct sockaddr_in *)get_address (ap, addresses, wanted);
  if (a == NULL)
    return NULL;

  if (a->sin_family != AF_INET)
    {
      DEBUGMSGTL(("snmpd", "unknown socket family %d [AF_INET expected] in var_ipRouteEntry.\n", a->sin_family));
    }
  return &a->sin_addr;
}
#endif /* HAVE_SYS_SYSCTL_H */
