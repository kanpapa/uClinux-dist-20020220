/* Zebra's client header.
 * Copyright (C) 1999 Kunihiro Ishiguro
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 * 
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#ifndef _ZEBRA_ZCLIENT_H
#define _ZEBRA_ZCLIENT_H

/* For struct interface and struct connected. */
#include "if.h"

/* Structure for the zebra client. */
struct zebra
{
  /* Socket to zebra daemon. */
  int sock;

  /* Flag of communication to zebra is enabled or not.  Default is on.
     This flag is disabled by `no router zebra' statement. */
  int enable;

  /* Connection failure count. */
  int fail;

  /* Input buffer for zebra message. */
  struct stream *ibuf;

  /* Read and connect thread. */
  struct thread *t_read;
  struct thread *t_connect;

  /* Redistribute information. */
  u_char redist_default;
  u_char redist[ZEBRA_ROUTE_MAX];

  /* Pointer to the callback functions. */
  int (*interface_add) (int, struct zebra *, zebra_size_t);
  int (*interface_delete) (int, struct zebra *, zebra_size_t);
  int (*interface_up) (int, struct zebra *, zebra_size_t);
  int (*interface_down) (int, struct zebra *, zebra_size_t);
  int (*interface_address_add) (int, struct zebra *, zebra_size_t);
  int (*interface_address_delete) (int, struct zebra *, zebra_size_t);
  int (*ipv4_route_add) (int, struct zebra *, zebra_size_t);
  int (*ipv4_route_delete) (int, struct zebra *, zebra_size_t);
  int (*ipv6_route_add) (int, struct zebra *, zebra_size_t);
  int (*ipv6_route_delete) (int, struct zebra *, zebra_size_t);
};

/* For input/output buffer to zebra. */
#define ZEBRA_MAX_PACKET_SIZ          4096

/* Zebra header size. */
#define ZEBRA_HEADER_SIZE                3

/* Prototypes of zebra client service functions. */
struct zebra *zclient_new (void);
void zclient_init (struct zebra *, int);
int zclient_start (struct zebra *);
void zclient_stop (struct zebra *);
void zclient_reset (struct zebra *);

void zclient_redistribute_set (struct zebra *, int);
void zclient_redistribute_unset (struct zebra *, int);

struct zebra *zebra_new ();
int zebra_redistribute_send (int, int, int);
int zebra_interface_add (int, struct interface *);
int zebra_interface_delete (int, struct interface *);
int zebra_interface_up (int sock, struct interface *ifp);
int zebra_interface_down (int sock, struct interface *ifp);
int zebra_interface_address_add (int, struct interface *, struct connected *);
int zebra_interface_address_delete (int, struct interface *, struct connected *);
struct connected *zebra_interface_address_add_read (struct stream *);
struct interface *zebra_interface_add_read (struct stream *);
struct interface *zebra_interface_state_read (struct stream *s);


/* IPv4 prefix add and delete function prototype. */
int
zebra_ipv4_add (int sock, int type, int flags, struct prefix_ipv4 *p,
		struct in_addr *nexthop, unsigned int ifindex);
int
zebra_ipv4_delete (int sock, int type, int flags, struct prefix_ipv4 *p,
		   struct in_addr *nexthop, unsigned int ifindex);

#ifdef HAVE_IPV6
/* IPv6 prefix add and delete function prototype. */
int
zebra_ipv6_add (int sock, int type, int flags, struct prefix_ipv6 *p,
		struct in6_addr *nexthop, unsigned int ifindex);
int
zebra_ipv6_delete (int sock, int type, int flags, struct prefix_ipv6 *p,
		   struct in6_addr *nexthop, unsigned int ifindex);
#endif /* HAVE_IPV6 */

#endif /* _ZEBRA_ZCLIENT_H */
