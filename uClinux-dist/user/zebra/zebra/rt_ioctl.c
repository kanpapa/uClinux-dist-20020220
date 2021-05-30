/*
 * kernel routing table update by ioctl().
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

#include "prefix.h"
#include "log.h"

/* Initialize of kernel interface.  There is no kernel communication
   support under ioctl().  So this is dummy stub function. */
void
kernel_init ()
{
  return;
}

/* Dummy function of routing socket. */
void
kernel_read (int sock)
{
  return;
}

#if 0
/* Initialization prototype of struct sockaddr_in. */
static struct sockaddr_in sin_proto =
{
#ifdef HAVE_SIN_LEN
  sizeof (struct sockaddr_in), 
#endif /* HAVE_SIN_LEN */
  AF_INET, 0, {0}, {0}
};
#endif /* 0 */

/* Solaris has ortentry. */
#ifdef HAVE_OLD_RTENTRY
#define rtentry ortentry
#endif /* HAVE_OLD_RTENTRY */

/* Interface to ioctl route message. */
int
kernel_ioctl_ipv4 (int type, struct prefix_ipv4 *dest, struct in_addr *gate,
		 int index, int flags)
{
  int ret;
  int sock;
  struct rtentry rtentry;
  struct sockaddr_in sin_dest, sin_mask, sin_gate;

  bzero (&rtentry, sizeof (struct rtentry));

  /* Make destination. */
  bzero (&sin_dest, sizeof (struct sockaddr_in));
  sin_dest.sin_family = AF_INET;
#ifdef HAVE_SIN_LEN
  sin_dest.sin_len = sizeof (struct sockaddr_in);
#endif /* HAVE_SIN_LEN */
  sin_dest.sin_addr = dest->prefix;

  /* Make gateway. */
  if (gate)
    {
      bzero (&sin_gate, sizeof (struct sockaddr_in));
      sin_gate.sin_family = AF_INET;
#ifdef HAVE_SIN_LEN
      sin_gate.sin_len = sizeof (struct sockaddr_in);
#endif /* HAVE_SIN_LEN */
      sin_gate.sin_addr = *gate;
    }

  bzero (&sin_mask, sizeof (struct sockaddr_in));
  sin_mask.sin_family = AF_INET;
#ifdef HAVE_SIN_LEN
      sin_gate.sin_len = sizeof (struct sockaddr_in);
#endif /* HAVE_SIN_LEN */
  masklen2ip (dest->prefixlen, &sin_mask.sin_addr);

  /* Set destination address, mask and gateway.*/
  memcpy (&rtentry.rt_dst, &sin_dest, sizeof (struct sockaddr_in));
  if (gate)
    memcpy (&rtentry.rt_gateway, &sin_gate, sizeof (struct sockaddr_in));
#ifndef SUNOS_5
  memcpy (&rtentry.rt_genmask, &sin_mask, sizeof (struct sockaddr_in));
#endif /* SUNOS_5 */

  /* Routing entry flag set. */
  if (dest->prefixlen == 32)
    rtentry.rt_flags |= RTF_HOST;

  if (gate && gate->s_addr != INADDR_ANY)
    rtentry.rt_flags |= RTF_GATEWAY;

  rtentry.rt_flags |= RTF_UP;

  /* Additional flags */
  rtentry.rt_flags |= flags;

  /* For tagging route. */
  /* rtentry.rt_flags |= RTF_DYNAMIC; */

  /* Open socket for ioctl. */
  sock = socket (AF_INET, SOCK_DGRAM, 0);
  if (sock < 0)
    {
      zlog_warn ("can't make socket\n");
      return -1;
    }

  /* Send message by ioctl(). */
  ret = ioctl (sock, type, &rtentry);
  if (ret < 0)
    {
      switch (errno) 
	{
	case EEXIST:
	  close (sock);
	  return ZEBRA_ERR_RTEXIST;
	  break;
	case ENETUNREACH:
	  close (sock);
	  return ZEBRA_ERR_RTUNREACH;
	  break;
	case EPERM:
	  close (sock);
	  return ZEBRA_ERR_EPERM;
	  break;
	}

      close (sock);
      zlog_warn ("write : %s (%d)", strerror (errno), errno);
      return 1;
    }
  close (sock);

  return ret;
}

/* Add a route to the kernel routing table. */
int
kernel_add_ipv4 (struct prefix_ipv4 *dest, struct in_addr *gate,
		 int index, int flags, int table)
{
  return kernel_ioctl_ipv4 (SIOCADDRT, dest, gate, index, flags);
}


/* Delete a route from the kernel routing table. */
int
kernel_delete_ipv4 (struct prefix_ipv4 *dest, struct in_addr *gate,
		    int index, int flags, int table)
{
  return kernel_ioctl_ipv4 (SIOCDELRT, dest, gate, index, flags);
}

#ifdef HAVE_IPV6

/* Below is hack for GNU libc definition and Linux 2.1.X header. */
#undef RTF_DEFAULT
#undef RTF_ADDRCONF

#include <asm/types.h>

#if defined(__GLIBC__) && __GLIBC__ >= 2 && __GLIBC_MINOR__ >= 1
/* struct in6_rtmsg will be declared in net/route.h. */
#else
#include <linux/ipv6_route.h>
#endif

int
kernel_ioctl_ipv6 (int type, struct prefix_ipv6 *dest, struct in6_addr *gate,
		   int index, int flags)
{
  int ret;
  int sock;
  struct in6_rtmsg rtm;
    
  bzero (&rtm, sizeof (struct in6_rtmsg));

  rtm.rtmsg_flags |= RTF_UP;
  rtm.rtmsg_metric = 1;
  memcpy (&rtm.rtmsg_dst, &dest->prefix, sizeof (struct in6_addr));
  rtm.rtmsg_dst_len = dest->prefixlen;

  /* We need link local index. But this should be done caller...
  if (IN6_IS_ADDR_LINKLOCAL(&rtm.rtmsg_gateway))
    {
      index = if_index_address (&rtm.rtmsg_gateway);
      rtm.rtmsg_ifindex = index;
    }
  else
    rtm.rtmsg_ifindex = 0;
  */

  rtm.rtmsg_flags |= RTF_GATEWAY;

  /* For tagging route. */
  /* rtm.rtmsg_flags |= RTF_DYNAMIC; */

  memcpy (&rtm.rtmsg_gateway, gate, sizeof (struct in6_addr));

  if (index)
    rtm.rtmsg_ifindex = index;
  else
    rtm.rtmsg_ifindex = 0;

  rtm.rtmsg_metric = 1;
  
  sock = socket (AF_INET6, SOCK_DGRAM, 0);
  if (sock < 0)
    {
      zlog_warn ("can't make socket\n");
      return -1;
    }

  /* Send message via ioctl. */
  ret = ioctl (sock, type, &rtm);
  if (ret < 0)
    {
      zlog_warn ("can't %s ipv6 route: %s\n", type == SIOCADDRT ? "add" : "delete", 
	   strerror(errno));
      ret = errno;
      close (sock);
      return ret;
    }
  close (sock);

  return ret;
}

/* Add IPv6 route to the kernel. */
int
kernel_add_ipv6 (struct prefix_ipv6 *dest, struct in6_addr *gate,
		 int index, int flags, int table)
{
  return kernel_ioctl_ipv6 (SIOCADDRT, dest, gate, index, flags);
}

/* Delete IPv6 route from the kernel. */
int
kernel_delete_ipv6 (struct prefix_ipv6 *dest, struct in6_addr *gate,
		    int index, int flags, int table)
{
  return kernel_ioctl_ipv6 (SIOCDELRT, dest, gate, index, flags);
}

#endif /* HAVE_IPV6 */
