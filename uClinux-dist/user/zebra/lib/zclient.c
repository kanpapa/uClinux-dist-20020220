/* Zebra's client library.
 * Copyright (C) 1999 Kunihiro Ishiguro
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2, or (at your
 * option) any later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
 * MA 02111-1307, USA.
 */

#include <zebra.h>

#include "prefix.h"
#include "stream.h"
#include "network.h"
#include "roken.h"
#include "if.h"
#include "log.h"
#include "thread.h"
#include "zclient.h"
#include "memory.h"

#include "zebra/zserv.h"

/* Vty events */
enum event {ZCLIENT_SCHEDULE, ZCLIENT_READ, ZCLIENT_CONNECT};

static void zclient_event (enum event, struct zebra *);

int zclient_debug = 0;

/* Make a IPv4 route add/delete packet and send it to zebra. */
static int
zebra_ipv4_route (int sock, int command, int type, int flags,
		  struct prefix_ipv4 *p, struct in_addr *nexthop, 
		  unsigned int ifindex)
{
  int ret;
  struct stream *s;
  u_short psize;

  s = stream_new (ZEBRA_MAX_PACKET_SIZ);

  /* Length place holder. */
  stream_putw (s, 0);

  /* Put command, type and nexthop. */
  stream_putc (s, command);
  stream_putc (s, type);
  stream_putc (s, flags);
  stream_write (s, (u_char *)nexthop, 4);

  /* Put prefix information. */
  stream_putl (s, ifindex);
  psize = PSIZE (p->prefixlen);
  stream_putc (s, p->prefixlen);
  stream_write (s, (u_char *)&p->prefix, psize);

  /* Put length at the first point of the stream. */
  stream_set_putp (s, 0);
  stream_putw (s, stream_get_endp (s));

  ret = writen (sock, s->data, stream_get_endp (s));

  stream_free (s);

  return ret;
}

int
zebra_ipv4_add (int sock, int type, int flags, struct prefix_ipv4 *p,
		struct in_addr *nexthop, unsigned int ifindex)
{
  return zebra_ipv4_route (sock, ZEBRA_IPV4_ROUTE_ADD, type, flags, p, 
			   nexthop, ifindex);
}

int
zebra_ipv4_delete (int sock, int type, int flags, struct prefix_ipv4 *p,
		struct in_addr *nexthop, unsigned int ifindex)
{
  return zebra_ipv4_route (sock, ZEBRA_IPV4_ROUTE_DELETE, type, flags, p,
			   nexthop, ifindex);
}

#ifdef HAVE_IPV6
/* Make a IPv6 route add/delete packet and send it to zebra. */
static int
zebra_ipv6_route (int command, int sock, int type, int flags,
		  struct prefix_ipv6 *p, struct in6_addr *nexthop, 
		  unsigned int ifindex)
{
  int ret;
  struct stream *s;
  u_short psize;

  s = stream_new (ZEBRA_MAX_PACKET_SIZ);

  /* Reserve size area then set command, type and nexthop.  */
  stream_putw (s, 0);
  stream_putc (s, command);
  stream_putc (s, type);
  stream_putc (s, flags);
  stream_write (s, (u_char *)nexthop, 16);

  /* Put prefix information. */
  stream_putl (s, ifindex);
  psize = PSIZE (p->prefixlen);
  stream_putc (s, p->prefixlen);
  stream_write (s, (u_char *)&p->prefix, psize);

  /* Write packet size. */
  stream_set_putp (s, 0);
  stream_putw (s, stream_get_endp (s));

  ret = writen (sock, s->data, stream_get_endp (s));

  stream_free (s);

  return ret;
}

int
zebra_ipv6_add (int sock, int type, int flags, struct prefix_ipv6 *p,
		struct in6_addr *nexthop, unsigned int ifindex)
{
  return zebra_ipv6_route (ZEBRA_IPV6_ROUTE_ADD, sock, type, flags, p, 
			   nexthop, ifindex);
}

int
zebra_ipv6_delete (int sock, int type, int flags, struct prefix_ipv6 *p,
		   struct in6_addr *nexthop, unsigned int ifindex)
{
  return zebra_ipv6_route (ZEBRA_IPV6_ROUTE_DELETE, sock, type, flags, p, 
			   nexthop, ifindex);
}
#endif /* HAVE_IPV6 */

int
zebra_redistribute_send (int command, int sock, int type)
{
  int ret;
  struct stream *s;

  s = stream_new (ZEBRA_MAX_PACKET_SIZ);

  /* Total length of the messages. */
  stream_putw (s, 4);
  
  stream_putc (s, command);
  stream_putc (s, type);

  ret = writen (sock, s->data, 4);

  stream_free (s);

  return ret;
}

/* Interface addition message. */
int
zebra_interface_add (int sock, struct interface *ifp)
{
  int ret;
  struct stream *s;

  s = stream_new (ZEBRA_MAX_PACKET_SIZ);

  /* Place holder for size. */
  stream_putw (s, 0);

  /* Zebra command. */
  stream_putc (s, ZEBRA_INTERFACE_ADD);

  /* Interface name. */
  stream_put (s, ifp->name, INTERFACE_NAMSIZ);

  /* Set interface's index. */
  stream_putw (s, ifp->ifindex);

  /* Set interface's value. */
  stream_putl (s, ifp->flags);
  stream_putl (s, ifp->metric);
  stream_putl (s, ifp->mtu);

  /* Write packet size. */
  stream_set_putp (s, 0);
  stream_putw (s, stream_get_endp (s));

  ret = writen (sock, s->data, stream_get_endp (s));

  stream_free (s);

  return ret;
}

/* Interface addition from zebra daemon. */
struct interface *
zebra_interface_add_read (struct stream *s)
{
  struct interface *ifp;
  u_char ifname_tmp[INTERFACE_NAMSIZ];

  /* Read interface name. */
  stream_get (ifname_tmp, s, INTERFACE_NAMSIZ);

  /* Lookup this by interface index. */
  ifp = if_lookup_by_name (ifname_tmp);

  /* If such interface does not exist, make new one. */
  if (! ifp)
    {
      ifp = if_create ();
      strncpy (ifp->name, ifname_tmp, IFNAMSIZ);
    }

  /* Read interface's index. */
  ifp->ifindex = stream_getw (s);

  /* Read interface's value. */
  ifp->flags = stream_getl (s);
  ifp->metric = stream_getl (s);
  ifp->mtu = stream_getl (s);

  return ifp;
}

/* Interface deletion from zebra daemon. */
int
zebra_interface_delete (int sock, struct interface *ifp)
{
  int ret;
  struct stream *s;

  s = stream_new (ZEBRA_MAX_PACKET_SIZ);

  /* Place holder for size. */
  stream_putw (s, 0);

  /* Zebra command. */
  stream_putc (s, ZEBRA_INTERFACE_DELETE);

  /* Interface name. */
  stream_put (s, ifp->name, INTERFACE_NAMSIZ);

  /* Set interface's index. */
  stream_putw (s, ifp->ifindex);

  /* Write packet size. */
  stream_set_putp (s, 0);
  stream_putw (s, stream_get_endp (s));

  ret = writen (sock, s->data, stream_get_endp (s));

  stream_free (s);

  return ret;
}

int
zebra_interface_up (int sock, struct interface *ifp)
{
  int ret;
  struct stream *s;

  s = stream_new (ZEBRA_MAX_PACKET_SIZ);

  /* Place holder for size. */
  stream_putw (s, 0);

  /* Zebra command. */
  stream_putc (s, ZEBRA_INTERFACE_UP);

  /* Interface name. */
  stream_put (s, ifp->name, INTERFACE_NAMSIZ);

  /* Set interface's index. */
  stream_putw (s, ifp->ifindex);

  /* Set interface's value. */
  stream_putl (s, ifp->flags);
  stream_putl (s, ifp->metric);
  stream_putl (s, ifp->mtu);

  /* Write packet size. */
  stream_set_putp (s, 0);
  stream_putw (s, stream_get_endp (s));

  ret = writen (sock, s->data, stream_get_endp (s));

  stream_free (s);

  return ret;
}


int
zebra_interface_down (int sock, struct interface *ifp)
{
  int ret;
  struct stream *s;

  s = stream_new (ZEBRA_MAX_PACKET_SIZ);

  /* Place holder for size. */
  stream_putw (s, 0);

  /* Zebra command. */
  stream_putc (s, ZEBRA_INTERFACE_DOWN);

  /* Interface name. */
  stream_put (s, ifp->name, INTERFACE_NAMSIZ);

  /* Set interface's index. */
  stream_putw (s, ifp->ifindex);

  /* Set interface's value. */
  stream_putl (s, ifp->flags);
  stream_putl (s, ifp->metric);
  stream_putl (s, ifp->mtu);

  /* Write packet size. */
  stream_set_putp (s, 0);
  stream_putw (s, stream_get_endp (s));

  ret = writen (sock, s->data, stream_get_endp (s));

  stream_free (s);

  return ret;
}


/* Read interface up/down msg from zebra daemon. */
struct interface *
zebra_interface_state_read (struct stream *s)
{
  struct interface *ifp;
  u_char ifname_tmp[INTERFACE_NAMSIZ];

  /* Read interface name. */
  stream_get (ifname_tmp, s, INTERFACE_NAMSIZ);

  /* Lookup this by interface index. */
  ifp = if_lookup_by_name (ifname_tmp);

  /* If such interface does not exist, indicate an error */
  if (! ifp)
     return NULL;

  /* Read interface's index. */
  ifp->ifindex = stream_getw (s);

  /* Read interface's value. */
  ifp->flags = stream_getl (s);
  ifp->metric = stream_getl (s);
  ifp->mtu = stream_getl (s);

  return ifp;
}




int
zebra_interface_address_add (int sock, struct interface *ifp, 
			     struct connected *c)
{
  int ret;
  int blen;
  struct stream *s;
  struct prefix *p;

  s = stream_new (ZEBRA_MAX_PACKET_SIZ);

  /* Place holder for size. */
  stream_putw (s, 0);

  /* Zebra command. */
  stream_putc (s, ZEBRA_INTERFACE_ADDRESS_ADD);

  /* Interface index. */
  stream_putw (s, ifp->ifindex);

  /* Prefix information. */
  p = c->address;
  stream_putc (s, p->family);
  blen = prefix_blen (p);
  stream_put (s, &p->u.prefix, blen);
  stream_putc (s, p->prefixlen);

  /* Destination. */
  p = c->destination;
  if (p)
    stream_put (s, &p->u.prefix, blen);
  else
    stream_put (s, NULL, blen);

  /* Write packet size. */
  stream_set_putp (s, 0);
  stream_putw (s, stream_get_endp (s));

  ret = writen (sock, s->data, stream_get_endp (s));

  stream_free (s);

  return ret;
}

struct connected *
zebra_interface_address_add_read (struct stream *s)
{
  unsigned int ifindex;
  struct interface *ifp;
  struct connected *connected;
  struct prefix *p;
  int family;
  int plen;

  /* Get interface index. */
  ifindex = stream_getw (s);

  /* Lookup index. */
  ifp = if_lookup_by_index (ifindex);
  if (ifp == NULL)
    {
      zlog_warn ("Can't find interface by ifindex: %d ", ifindex);
      return NULL;
    }

  /* Allocate new connected address. */
  connected = connected_new ();

  /* Fetch interface address. */
  p = prefix_new ();
  family = p->family = stream_getc (s);

  plen = prefix_blen (p);
  stream_get (&p->u.prefix, s, plen);
  p->prefixlen = stream_getc (s);
  connected->address = p;

  /* Fetch destination address. */
  p = prefix_new ();
  stream_get (&p->u.prefix, s, plen);
  p->family = family;

  connected->destination = p;

  p = connected->address;

  /* Add connected address to the interface. */
  connected_add (ifp, connected);

  return connected;
}

int
zebra_interface_address_delete (int sock, struct interface *ifp,
				struct connected *c)
{
  int ret;
  int blen;
  struct stream *s;
  struct prefix *p;

  s = stream_new (ZEBRA_MAX_PACKET_SIZ);

  /* Place holder for size. */
  stream_putw (s, 0);

  /* Zebra command. */
  stream_putc (s, ZEBRA_INTERFACE_ADDRESS_DELETE);

  /* Interface index. */
  stream_putw (s, ifp->ifindex);

  /* Prefix information. */
  p = c->address;
  stream_putc (s, p->family);
  blen = prefix_blen (p);
  stream_put (s, &p->u.prefix, blen);

  p = c->destination;
  if (p)
    stream_put (s, &p->u.prefix, blen);
  else
    stream_put (s, NULL, blen);

  /* Write packet size. */
  stream_set_putp (s, 0);
  stream_putw (s, stream_get_endp (s));

  ret = writen (sock, s->data, stream_get_endp (s));

  stream_free (s);

  return ret;
}

/* Allocate zebra structure. */
struct zebra *
zclient_new ()
{
  struct zebra *new;

  new = XMALLOC (MTYPE_ZEBRA, sizeof (struct zebra));
  bzero (new, sizeof (struct zebra));

  return new;
}

void
zclient_free (struct zebra *zebra)
{
  XFREE (MTYPE_ZEBRA, zebra);
}

void
zclient_init (struct zebra *zclient, int redist_default)
{
  int i;
  
  zclient->enable = 1;
  zclient->sock = -1;

  /* Clear redistribution flags. */
  for (i = 0; i < ZEBRA_ROUTE_MAX; i++)
    zclient->redist[i] = 0;
  zclient->redist_default = redist_default;
  zclient->redist[redist_default] = 1;

  /* Schedule first zclient connection. */
  if (zclient_debug)
    zlog_info ("zclient start scheduled");
  zclient_event (ZCLIENT_SCHEDULE, zclient);
}

/* Stop all zebra client services. */
void
zclient_stop (struct zebra *zclient)
{
  if (zclient_debug)
    zlog_info ("zclient stopped");

  /* Stop threads. */
  if (zclient->t_read)
    {
      thread_cancel (zclient->t_read);
      zclient->t_read = NULL;
    }
  if (zclient->t_connect)
    {
      thread_cancel (zclient->t_connect);
      zclient->t_connect = NULL;
    }

  /* Close socket. */
  if (zclient->sock >= 0)
    {
      close (zclient->sock);
      zclient->sock = -1;
    }

  /* Free input buffer. */
  if (zclient->ibuf)
    {
      stream_free (zclient->ibuf);
      zclient->ibuf = NULL;
    }
  zclient->fail = 0;
}

void
zclient_reset (struct zebra *zclient)
{
  zclient_stop (zclient);
  zclient_init (zclient, zclient->redist_default);
}

/* Make socket to zebra daemon. Return zebra socket. */
int
zclient_socket ()
{
  int sock;
  int ret;
  struct sockaddr_in serv;

  /* We should think about IPv6 connection. */
  sock = socket (AF_INET, SOCK_STREAM, 0);
  if (sock < 0)
    return -1;
  
  /* Make server socket. */ 
  memset (&serv, 0, sizeof (struct sockaddr_in));
  serv.sin_family = AF_INET;
  serv.sin_port = htons (ZEBRA_PORT);
#ifdef HAVE_SIN_LEN
  serv.sin_len = sizeof (struct sockaddr_in);
#endif /* HAVE_SIN_LEN */
  serv.sin_addr.s_addr = htonl (INADDR_LOOPBACK);

  /* Connect to zebra. */
  ret = connect (sock, (struct sockaddr *) &serv, sizeof (serv));
  if (ret < 0)
    {
      close (sock);
      return -1;
    }
  return sock;
}

/* Make connection to zebra daemon. */
int
zclient_start (struct zebra *zebra)
{
  int i;

  if (zclient_debug)
    zlog_info ("zclient_start is called");

  /* zebra is disabled. */
  if (! zebra->enable)
    return 0;

  /* If already connected to the zebra. */
  if (zebra->sock >= 0)
    return 0;

  /* Check connect thread. */
  if (zebra->t_connect)
    return 0;

  /* Make socket. */
  zebra->sock = zclient_socket ();
  if (zebra->sock < 0)
    {
      if (zclient_debug)
	zlog_info ("zclient connection fail");
      zebra->fail++;
      zclient_event (ZCLIENT_CONNECT, zebra);
      return -1;
    }

  /* Clear fail count. */
  zebra->fail = 0;
  if (zclient_debug)
    zlog_info ("zclient connect success with socket [%d]", zebra->sock);
      
  /* Input buffer. */
  zebra->ibuf = stream_new (ZEBRA_MAX_PACKET_SIZ);
  
  /* Create read thread. */
  zclient_event (ZCLIENT_READ, zebra);

  /* Flush all redistribute request. */
  for (i = 0; i < ZEBRA_ROUTE_MAX; i++)
    if (i != zebra->redist_default && zebra->redist[i])
      zebra_redistribute_send (ZEBRA_REDISTRIBUTE_ADD, zebra->sock, i);

  return 0;
}

/* This function is a wrapper function for calling zclient_start from
   timer or event thread. */
int
zclient_connect (struct thread *t)
{
  struct zebra *zclient;

  zclient = THREAD_ARG (t);
  zclient->t_connect = NULL;

  if (zclient_debug)
    zlog_info ("zclient_connect is called");

  return zclient_start (zclient);
}

/* Zebra client message read function. */
int
zclient_read (struct thread *thread)
{
  int ret;
  int nbytes;
  int sock;
  zebra_size_t length;
  zebra_command_t command;
  struct zebra *zebra;

  /* Get socket to zebra. */
  sock = THREAD_FD (thread);
  zebra = THREAD_ARG (thread);
  zebra->t_read = NULL;

  /* Clear input buffer. */
  stream_reset (zebra->ibuf);

  /* Read zebra header. */
  nbytes = stream_read (zebra->ibuf, sock, ZEBRA_HEADER_SIZE);

  /* zebra socket is closed. */
  if (nbytes == 0) 
    {
      if (zclient_debug)
	zlog_info ("zclient connection closed socket [%d].", sock);
      zebra->fail++;
      zclient_stop (zebra);
      zclient_event (ZCLIENT_CONNECT, zebra);
      return -1;
    }

  /* zebra read error. */
  if (nbytes < 0 || nbytes != ZEBRA_HEADER_SIZE)
    {
      if (zclient_debug)
	zlog_info ("Can't read all packet (length %d).", nbytes);
      zebra->fail++;
      zclient_stop (zebra);
      zclient_event (ZCLIENT_CONNECT, zebra);
      return -1;
    }

  /* Fetch length and command. */
  length = stream_getw (zebra->ibuf);
  command = stream_getc (zebra->ibuf);

  /* Length check. */
  if (length >= zebra->ibuf->size)
    {
      stream_free (zebra->ibuf);
      zebra->ibuf = stream_new (length + 1);
    }
  length -= ZEBRA_HEADER_SIZE;

  /* Read rest of zebra packet. */
  nbytes = stream_read (zebra->ibuf, sock, length);
 if (nbytes != length)
   {
     if (zclient_debug)
      zlog_info ("zclient connection closed socket [%d].", sock);
     zebra->fail++;
     zclient_stop (zebra);
     zclient_event (ZCLIENT_CONNECT, zebra);
     return -1;
   }

  switch (command)
    {
    case ZEBRA_INTERFACE_ADD:
      if (zebra->interface_add)
	ret = (*zebra->interface_add) (command, zebra, length);
      break;
    case ZEBRA_INTERFACE_DELETE:
      if (zebra->interface_delete)
	ret = (*zebra->interface_delete) (command, zebra, length);
      break;
    case ZEBRA_INTERFACE_UP:
      if (zebra->interface_up)
	ret = (*zebra->interface_up) (command, zebra, length);
      break;
    case ZEBRA_INTERFACE_DOWN:
      if (zebra->interface_down)
	ret = (*zebra->interface_down) (command, zebra, length);
      break;
    case ZEBRA_INTERFACE_ADDRESS_ADD:
      if (zebra->interface_address_add)
	ret = (*zebra->interface_address_add) (command, zebra, length);
      break;
    case ZEBRA_INTERFACE_ADDRESS_DELETE:
      if (zebra->interface_address_delete)
	ret = (*zebra->interface_address_delete) (command, zebra, length);
      break;
    case ZEBRA_IPV4_ROUTE_ADD:
      if (zebra->ipv4_route_add)
	ret = (*zebra->ipv4_route_add) (command, zebra, length);
      break;
    case ZEBRA_IPV4_ROUTE_DELETE:
      if (zebra->ipv4_route_delete)
	ret = (*zebra->ipv4_route_delete) (command, zebra, length);
      break;
    case ZEBRA_IPV6_ROUTE_ADD:
      if (zebra->ipv6_route_add)
	ret = (*zebra->ipv6_route_add) (command, zebra, length);
      break;
    case ZEBRA_IPV6_ROUTE_DELETE:
      if (zebra->ipv6_route_delete)
	ret = (*zebra->ipv6_route_delete) (command, zebra, length);
      break;
    default:
      break;
    }

  /* Register read thread. */
  zclient_event (ZCLIENT_READ, zebra);

  return 0;
}

void
zclient_redistribute_set (struct zebra *zclient, int type)
{
  if (zclient->redist[type])
    return;

  zclient->redist[type] = 1;

  if (zclient->sock > 0)
    zebra_redistribute_send (ZEBRA_REDISTRIBUTE_ADD, zclient->sock, type);
}

extern struct thread_master *master;

static void
zclient_event (enum event event, struct zebra *zebra)
{
  switch (event)
    {
    case ZCLIENT_SCHEDULE:
      if (! zebra->t_connect)
	zebra->t_connect =
	  thread_add_event (master, zclient_connect, zebra, 0);
      break;
    case ZCLIENT_CONNECT:
      if (zebra->fail >= 10)
	return;
      if (zclient_debug)
	zlog_info ("zclient connect schedule interval is %d", 
		   zebra->fail < 3 ? 10 : 60);
      if (! zebra->t_connect)
	zebra->t_connect = 
	  thread_add_timer (master, zclient_connect, zebra,
			    zebra->fail < 3 ? 10 : 60);
      break;
    case ZCLIENT_READ:
      zebra->t_read = 
	thread_add_read (master, zclient_read, zebra, zebra->sock);
      break;
    }
}
