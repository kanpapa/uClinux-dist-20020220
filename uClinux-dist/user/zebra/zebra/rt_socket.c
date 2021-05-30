/*
 * Kernel routing table updates by routing socket.
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
#include "prefix.h"
#include "sockunion.h"
#include "log.h"
#include "str.h"

int
rtm_write (int message,
	   union sockunion *dest,
	   union sockunion *mask,
	   union sockunion *gate,
	   unsigned int index,
	   int zebra_flags);

/* Adjust netmask socket length. Return value is a adjusted sin_len
   value. */
int
sin_masklen (struct in_addr mask)
{
  char *p, *lim;
  int len;
  struct sockaddr_in sin;

  if (mask.s_addr == 0) 
    return sizeof (long);

  sin.sin_addr = mask;
  len = sizeof (struct sockaddr_in);

  lim = (char *) &sin.sin_addr;
  p = lim + sizeof (sin.sin_addr);

  while (*--p == 0 && p >= lim) 
    len--;
  return len;
}

/* Interface between zebra message and rtm message. */
int
kernel_rtm_ipv4 (int message, struct prefix_ipv4 *dest,
		 struct in_addr *gate, unsigned int index, int flags)
{
  struct sockaddr_in *mask;
  struct sockaddr_in sin_dest, sin_mask, sin_gate;

  memset (&sin_dest, 0, sizeof (struct sockaddr_in));
  sin_dest.sin_family = AF_INET;
#ifdef HAVE_SIN_LEN
  sin_dest.sin_len = sizeof (struct sockaddr_in);
#endif /* HAVE_SIN_LEN */

  memset (&sin_mask, 0, sizeof (struct sockaddr_in));

  memset (&sin_gate, 0, sizeof (struct sockaddr_in));
  sin_gate.sin_family = AF_INET;
#ifdef HAVE_SIN_LEN
  sin_gate.sin_len = sizeof (struct sockaddr_in);
#endif /* HAVE_SIN_LEN */

  sin_dest.sin_addr = dest->prefix;
  if (gate)
    sin_gate.sin_addr = *gate;

  if (gate && dest->prefixlen == 32)
    mask = NULL;
  else
    {
      masklen2ip (dest->prefixlen, &sin_mask.sin_addr);
#ifdef HAVE_SIN_LEN
      sin_mask.sin_len = sin_masklen (sin_mask.sin_addr);
#endif /* HAVE_SIN_LEN */
      sin_mask.sin_family = AF_UNSPEC;
      mask = &sin_mask;
    }

  return rtm_write (message,
		    (union sockunion *)&sin_dest, 
		    (union sockunion *)mask, 
		    gate ? (union sockunion *)&sin_gate : NULL,
		    index,
		    flags);
}

/* Add IPv4 prefix to kernel routing table. */
int
kernel_add_ipv4 (struct prefix_ipv4 *dest, struct in_addr *gate,
		 unsigned int index, int flags, int table)
{
  return kernel_rtm_ipv4 (RTM_ADD, dest, gate, index, flags);
}

/* Delete IPv4 prefix from kernel routing table. */
int
kernel_delete_ipv4 (struct prefix_ipv4 *dest, struct in_addr *gate,
		    unsigned int index, int flags, int table)
{
  return kernel_rtm_ipv4 (RTM_DELETE, dest, gate, index, flags);
}

#ifdef HAVE_IPV6

/* Calculate sin6_len value for netmask socket value. */
int
sin6_masklen (struct in6_addr mask)
{
  struct sockaddr_in6 sin6;
  char *p, *lim;
  int len;

#if defined (INRIA)
  if (IN_ANYADDR6 (mask)) 
    return sizeof (long);
#else /* ! INRIA */
  if (IN6_IS_ADDR_UNSPECIFIED (&mask)) 
    return sizeof (long);
#endif /* ! INRIA */

  sin6.sin6_addr = mask;
  len = sizeof (struct sockaddr_in6);

  lim = (char *) & sin6.sin6_addr;
  p = lim + sizeof (sin6.sin6_addr);

  while (*--p == 0 && p >= lim) 
    len--;

  return len;
}

/* Interface between zebra message and rtm message. */
int
kernel_rtm_ipv6 (int message, struct prefix_ipv6 *dest,
		 struct in6_addr *gate, int index, int flags)
{
  struct sockaddr_in6 *mask;
  struct sockaddr_in6 sin_dest, sin_mask, sin_gate;

  memset (&sin_dest, 0, sizeof (struct sockaddr_in6));
  sin_dest.sin6_family = AF_INET6;
#ifdef SIN6_LEN
  sin_dest.sin6_len = sizeof (struct sockaddr_in6);
#endif /* SIN6_LEN */

  memset (&sin_mask, 0, sizeof (struct sockaddr_in6));

  memset (&sin_gate, 0, sizeof (struct sockaddr_in6));
  sin_gate.sin6_family = AF_INET6;
#ifdef SIN6_LEN
  sin_gate.sin6_len = sizeof (struct sockaddr_in6);
#endif /* SIN6_LEN */

  sin_dest.sin6_addr = dest->prefix;

  if (gate)
    memcpy (&sin_gate.sin6_addr, gate, sizeof (struct in6_addr));

  /* Under kame set interface index to link local address. */
#ifdef KAME

#define SET_IN6_LINKLOCAL_IFINDEX(a, i) \
  do { \
    (a).s6_addr[2] = ((i) >> 8) & 0xff; \
    (a).s6_addr[3] = (i) & 0xff; \
  } while (0)

  if (gate && IN6_IS_ADDR_LINKLOCAL(gate))
    SET_IN6_LINKLOCAL_IFINDEX (sin_gate.sin6_addr, index);
#endif /* KAME */

  if (gate && dest->prefixlen == 128)
    mask = NULL;
  else
    {
      masklen2ip6 (dest->prefixlen, &sin_mask.sin6_addr);
      sin_mask.sin6_family = AF_UNSPEC;
#ifdef SIN6_LEN
      sin_mask.sin6_len = sin6_masklen (sin_mask.sin6_addr);
#endif /* SIN6_LEN */
      mask = &sin_mask;
    }

  return rtm_write (message, 
		    (union sockunion *) &sin_dest,
		    (union sockunion *) mask,
		    gate ? (union sockunion *)&sin_gate : NULL,
		    index,
		    flags);
}

/* Add IPv6 route to the kernel. */
int
kernel_add_ipv6 (struct prefix_ipv6 *dest, struct in6_addr *gate,
		 int index, int flags, int table)
{
  return kernel_rtm_ipv6 (RTM_ADD, dest, gate, index, flags);
}

/* Delete IPv6 route from the kernel. */
int
kernel_delete_ipv6 (struct prefix_ipv6 *dest, struct in6_addr *gate,
		    int index, int flags, int table)
{
  return kernel_rtm_ipv6 (RTM_DELETE, dest, gate, index, flags);
}
#endif /* HAVE_IPV6 */
