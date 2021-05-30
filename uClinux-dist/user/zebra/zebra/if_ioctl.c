/*
 * Interface looking up by ioctl ().
 * Copyright (C) 1997, 98 Kunihiro Ishiguro
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

#include "if.h"
#include "sockunion.h"
#include "prefix.h"
#include "ioctl.h"
#include "connected.h"
#include "memory.h"
#include "log.h"

#include "zebra/interface.h"

/* Interface looking up using infamous SIOCGIFCONF. */
int
interface_list_ioctl ()
{
  int ret;
  int sock;
#define IFNUM_BASE 32
  int ifnum;
  struct ifreq *ifreq;
  struct ifconf ifconf;
  struct interface *ifp;
  int n;

  /* Normally SIOCGIFCONF works with AF_INET socket. */
  sock = socket (AF_INET, SOCK_DGRAM, 0);
  if (sock < 0) 
    {
      zlog_warn ("Can't make AF_INET socket stream: %s", strerror (errno));
      return -1;
    }

  /* Set initial ifreq count.  This will be double when SIOCGIFCONF
     fail.  Solaris has SIOCGIFNUM. */
#ifdef SIOCGIFNUM
  ret = ioctl (sock, SIOCGIFNUM, &ifnum);
  if (ret < 0)
    ifnum = IFNUM_BASE;
  else
    ifnum++;
#else
  ifnum = IFNUM_BASE;
#endif /* SIOCGIFNUM */

  ifconf.ifc_buf = NULL;

  /* Loop until SIOCGIFCONF success. */
  for (;;) 
    {
      ifconf.ifc_len = sizeof (struct ifreq) * ifnum;
      ifconf.ifc_buf = XREALLOC(MTYPE_TMP, ifconf.ifc_buf, ifconf.ifc_len);

      ret = ioctl(sock, SIOCGIFCONF, &ifconf);
      if (ret < 0) 
	{
	  zlog_warn ("SIOCGIFCONF: %s", strerror(errno));
	  goto end;
	}
      /* When length is same as we prepared, assume it overflowed and
         try again */
      if (ifconf.ifc_len == sizeof (struct ifreq) * ifnum) 
	{
	  ifnum += 10;
	  continue;
	}
      /* Success. */
      break;
    }

  /* Allocate interface. */
  ifreq = ifconf.ifc_req;
  for (n = 0; n < ifconf.ifc_len; n += sizeof(struct ifreq))
    {
      ifp = if_get_by_name (ifreq->ifr_name);
      ifreq++;
    }

 end:
  close (sock);
  XFREE (MTYPE_TMP, ifconf.ifc_buf);

  return ret;
}

/* Get interface's index by ioctl. */
int
if_get_index (struct interface *ifp)
{
  int ret;
  static int if_fake_index = 1;

#ifdef SIOCGIFINDEX
  struct ifreq ifreq;

  ifreq_set_name (&ifreq, ifp);

  ret = if_ioctl (SIOCGIFINDEX, (caddr_t) &ifreq);
  if (ret < 0)
    {
      /* Linux 2.0.X does not have interface index. */
      ifp->ifindex = if_fake_index++;
      return ifp->ifindex;
    }

  /* OK we got interface index. */
#ifdef ifr_ifindex
  ifp->ifindex = ifreq.ifr_ifindex;
#else
  ifp->ifindex = ifreq.ifr_index;
#endif
  return ifp->ifindex;

#else
  ifp->ifindex = if_fake_index++;
  return ifp->ifindex;
#endif /* SIOCGIFINDEX */
}

#ifdef SIOCGIFHWADDR
int
if_get_hwaddr (struct interface *ifp)
{
  int ret;
  struct ifreq ifreq;
  int i;

  strncpy (ifreq.ifr_name, ifp->name, IFNAMSIZ);
  ifreq.ifr_addr.sa_family = AF_INET;

  /* Fetch Hardware address if available. */
  ret = if_ioctl (SIOCGIFHWADDR, (caddr_t) &ifreq);
  if (ret < 0)
    ifp->hw_addr_len = 0;
  else
    {
      memcpy (ifp->hw_addr, ifreq.ifr_hwaddr.sa_data, 8);

      for (i = 0; i < 8; i++)
	if (ifp->hw_addr[i] != 0)
	  break;

      if (i == 8)
	ifp->hw_addr_len = 0;
      else
	ifp->hw_addr_len = 8;
    }
  return 0;
}
#endif /* SIOCGIFHWADDR */

/* Interface address lookup by ioctl.  This function only looks up
   IPv4 address. */
int
if_get_addr (struct interface *ifp)
{
  int ret;
  struct ifreq ifreq;
  struct sockaddr_in addr;
  struct sockaddr_in mask;
  struct sockaddr_in dest;
  struct in_addr *dest_pnt;
  u_char prefixlen;

  /* Interface's name and address family. */
  strncpy (ifreq.ifr_name, ifp->name, IFNAMSIZ);
  ifreq.ifr_addr.sa_family = AF_INET;

  /* Interface's address. */
  ret = if_ioctl (SIOCGIFADDR, (caddr_t) &ifreq);
  if (ret < 0) 
    {
      if (errno != EADDRNOTAVAIL)
	{
	  zlog_warn ("SIOCGIFADDR fail: %s", strerror (errno));
	  return ret;
	}
      return 0;
    }
  memcpy (&addr, &ifreq.ifr_addr, sizeof (struct sockaddr_in));

  /* Interface's network mask. */
  ret = if_ioctl (SIOCGIFNETMASK, (caddr_t) &ifreq);
  if (ret < 0) 
    {
      if (errno != EADDRNOTAVAIL) 
	{
	  zlog_warn ("SIOCGIFNETMASK fail: %s", strerror (errno));
	  return ret;
	}
      return 0;
    }
#ifdef ifr_netmask
  memcpy (&mask, &ifreq.ifr_netmask, sizeof (struct sockaddr_in));
#else
  memcpy (&mask, &ifreq.ifr_addr, sizeof (struct sockaddr_in));
#endif /* ifr_netmask */
  prefixlen = ip_masklen (mask.sin_addr);

  /* Point to point or borad cast address pointer init. */
  dest_pnt = NULL;

  if (ifp->flags & IFF_POINTOPOINT) 
    {
      ret = if_ioctl (SIOCGIFDSTADDR, (caddr_t) &ifreq);
      if (ret < 0) 
	{
	  if (errno != EADDRNOTAVAIL) 
	    {
	      zlog_warn ("SIOCGIFDSTADDR fail: %s", strerror (errno));
	      return ret;
	    }
	  return 0;
	}
      memcpy (&dest, &ifreq.ifr_dstaddr, sizeof (struct sockaddr_in));
      dest_pnt = &dest.sin_addr;
    }
  if (ifp->flags & IFF_BROADCAST)
    {
      ret = if_ioctl (SIOCGIFBRDADDR, (caddr_t) &ifreq);
      if (ret < 0) 
	{
	  if (errno != EADDRNOTAVAIL) 
	    {
	      zlog_warn ("SIOCGIFBRDADDR fail: %s", strerror (errno));
	      return ret;
	    }
	  return 0;
	}
      memcpy (&dest, &ifreq.ifr_broadaddr, sizeof (struct sockaddr_in));
      dest_pnt = &dest.sin_addr;
    }


  /* Set address to the interface. */
  connected_add_ipv4 (ifp, &addr.sin_addr, prefixlen, dest_pnt);

  return 0;
}

/* Fetch interface information via ioctl(). */
static void
interface_info_ioctl ()
{
  listnode node;
  struct interface *ifp;
  
  for (node = listhead (iflist); node; node = nextnode (node))
    {
      ifp = getdata (node);

      if_get_index (ifp);
#ifdef SIOCGIFHWADDR
      if_get_hwaddr (ifp);
#endif /* SIOCGIFHWADDR */
      if_get_flags (ifp);
      if_get_addr (ifp);
      if_get_mtu (ifp);
      if_get_metric (ifp);
    }
}

/* Lookup all interface information. */
void
interface_list ()
{
  /* Linux can do both proc & ioctl, ioctl is the only way to get
     interface aliases in 2.2 series kernels. */
#ifdef HAVE_PROC_NET_DEV
  interface_list_proc ();
#endif /* HAVE_PROC_NET_DEV */
  interface_list_ioctl ();

  /* After listing is done, get index, address, flags and other
     interface's information. */
  interface_info_ioctl ();

#if defined(HAVE_IPV6) && defined(HAVE_PROC_NET_IF_INET6)
  /* Linux provides interface's IPv6 address via
     /proc/net/if_inet6. */
  ifaddr_proc_ipv6 ();
#endif /* HAVE_IPV6 && HAVE_PROC_NET_IF_INET6 */
}
