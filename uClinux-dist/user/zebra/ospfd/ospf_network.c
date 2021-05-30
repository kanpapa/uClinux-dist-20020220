/*
 * OSPF network related functions
 *   Copyright (C) 1999 Toshiaki Takada
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
#include "linklist.h"
#include "prefix.h"
#include "if.h"
#include "sockunion.h"
#include "log.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_network.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_asbr.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_lsdb.h"
#include "ospfd/ospf_neighbor.h"
#include "ospfd/ospf_packet.h"


/* Make ospfd's server socket. */
int
ospf_serv_sock (struct interface *ifp, int family)
{
  int ospf_sock;
  int ret, tos;
  struct ospf_interface *oi;

  ospf_sock = socket (family, SOCK_RAW, IPPROTO_OSPFIGP);
  if (ospf_sock < 0)
    return ospf_sock;

  /*
  sockopt_reuseaddr (ospf_sock);
  sockopt_reuseport (ospf_sock);
  */
  /* Set TTL to 1. */

  oi = ifp->info;
  if (oi == NULL) return -1;

  if (oi->type == OSPF_IFTYPE_VIRTUALLINK)
     ret = sockopt_ttl (AF_INET, ospf_sock, OSPF_VL_IP_TTL);
  else 
     ret = sockopt_ttl (AF_INET, ospf_sock, OSPF_IP_TTL);
  if (ret < 0)
    return ret;

  /* Set precedence field. */
#ifdef IPTOS_PREC_INTERNETCONTROL
  tos = IPTOS_PREC_INTERNETCONTROL;
  ret = setsockopt (ospf_sock, IPPROTO_IP, IP_TOS,
		    (char *) &tos, sizeof (int));
  if (ret < 0)
    {
      zlog_warn ("can't set sockopt IP_TOS %d to socket %d", tos, ospf_sock);
      return ret;
    }
#endif /* IPTOS_PREC_INTERNETCONTROL */

  return ospf_sock;
}

/* Join to the OSPF ALL SPF ROUTERS multicast group. */
int
ospf_if_add_allspfrouters (struct interface *ifp, int sock, struct prefix *p)
{
  struct ip_mreq m;
  int ret;

  bzero (&m, sizeof (m));

  m.imr_multiaddr.s_addr = htonl (OSPF_ALLSPFROUTERS);
  m.imr_interface = p->u.prefix4;

  ret = setsockopt (sock, IPPROTO_IP, IP_ADD_MEMBERSHIP,
		    (char *) &m, sizeof (struct ip_mreq));

  if (ret < 0)
    zlog_warn ("can't setsockopt IP_ADD_MEMBERSHIP: %s", strerror (errno));

  zlog_info ("interface %s join AllSPFRouters Multicast group.", ifp->name);

  return ret;
}

int
ospf_if_drop_allspfrouters (struct interface *ifp, int sock, struct prefix *p)
{
  struct ip_mreq m;
  int ret;

  bzero (&m, sizeof (m));

  m.imr_multiaddr.s_addr = htonl (OSPF_ALLSPFROUTERS);
  m.imr_interface = p->u.prefix4;

  ret = setsockopt (sock, IPPROTO_IP, IP_DROP_MEMBERSHIP,
		    (char *) &m, sizeof (struct ip_mreq));

  if (ret < 0)
    zlog_warn("can't setsockopt IP_DROP_MEMBERSHIP: %s", strerror (errno));

  zlog_info ("interface %s leave AllSPFRouters Multicast group.", ifp->name);

  return ret;
}

/* Join to the OSPF ALL Designated ROUTERS multicast group. */
int
ospf_if_add_alldrouters (struct interface *ifp, int sock, struct prefix *p)
{
  struct ip_mreq m;
  int ret;

  bzero (&m, sizeof (m));

  m.imr_multiaddr.s_addr = htonl (OSPF_ALLDROUTERS);
  m.imr_interface = p->u.prefix4;

  ret = setsockopt (sock, IPPROTO_IP, IP_ADD_MEMBERSHIP,
		    (char *) &m, sizeof (struct ip_mreq));
  if (ret < 0)
    zlog_warn ("can't setsockopt IP_ADD_MEMBERSHIP: %s", strerror (errno));

  zlog_info ("interface %s join AllDRouters Multicast group.", ifp->name);

  return ret;
}

int
ospf_if_drop_alldrouters (struct interface *ifp, int sock, struct prefix *p)
{
  struct ip_mreq m;
  int ret;

  bzero (&m, sizeof (m));

  m.imr_multiaddr.s_addr = htonl (OSPF_ALLDROUTERS);
  m.imr_interface = p->u.prefix4;

  ret = setsockopt (sock, IPPROTO_IP, IP_DROP_MEMBERSHIP,
		    (char *) &m, sizeof (struct ip_mreq));
  if (ret < 0)
    zlog_warn ("can't setsockopt IP_DROP_MEMBERSHIP: %s", strerror (errno));

  zlog_info ("interface %s leave AllDRouters Multicast group.", ifp->name);

  return ret;
}

int
ospf_if_ipmulticast (int sock, struct prefix *p)
{
  int ret;
  struct in_addr addr;

  addr = p->u.prefix4;

  ret = setsockopt (sock, IPPROTO_IP, IP_MULTICAST_IF, (void *)&addr,
		    sizeof (addr));
  if (ret < 0)
    zlog_warn ("can't setsockopt IP_MULTICAST_IF: %s", strerror (errno));

  return ret;
}

/* Setup all sockets for receiving interface. */
int
ospf_serv_sock_init (struct interface *ifp, struct prefix *p)
{
  struct ospf_interface *oi;
  int ret, sock;

  oi = ifp->info;

  /* Create raw socket. */
  sock = ospf_serv_sock (ifp, AF_INET);
  if (sock < 0)
    {
      zlog_warn ("interface %s can't create raw socket", ifp->name);
      return -1;
    }

  oi->fd = sock;

  /* Point-to-Point and Broadcast Network should be joined to
     ALLSPFROUTERS multicast group. */
  if (oi->type == OSPF_IFTYPE_POINTOPOINT ||
      oi->type == OSPF_IFTYPE_BROADCAST)
    {
      /* Join mcast group. */
      ret = ospf_if_add_allspfrouters (ifp, sock, p);
      if (ret < 0)
	return ret;

      /* Create input/output buffer stream. */
      ospf_if_stream_set (oi);
    }

  return 0;
}

