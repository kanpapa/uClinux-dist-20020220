/* 
 * Interface functions.
 * Copyright (C) 1997, 98 Kunihiro Ishiguro
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
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#include <zebra.h>

#include "linklist.h"
#include "vector.h"
#include "vty.h"
#include "command.h"
#include "if.h"
#include "sockunion.h"
#include "prefix.h"
#include "zebra/connected.h"
#include "memory.h"
#include "buffer.h"
#include "str.h"
#include "log.h"

/* One for each program.  This structure is needed to store hooks. */
struct if_master
{
  int (*if_new_hook) (struct interface *);
  int (*if_delete_hook) (struct interface *);
} if_master;

/* Export to user function. */
list iflist;

/* Create new interface structure. */
struct interface *
if_new ()
{
  struct interface *ifp;

  ifp = XMALLOC (MTYPE_IF, sizeof (struct interface));
  bzero (ifp, sizeof (struct interface));
  return ifp;
}

struct interface *
if_create ()
{
  struct interface *ifp;

  ifp = if_new ();
  
  list_add_node (iflist, ifp);
  ifp->connected = list_init ();

  if (if_master.if_new_hook)
    (*if_master.if_new_hook) (ifp);

  return ifp;
}

/* Delete and free interface structure. */
void
if_delete (struct interface *ifp)
{
  list_delete_by_val (iflist, ifp);
  if (if_master.if_delete_hook)
    (*if_master.if_delete_hook) (ifp);
  XFREE (MTYPE_IF, ifp);
}

/* Add hook to interface master. */
void
if_add_hook (int type, int (*func)(struct interface *ifp))
{
  switch (type) {
  case IF_NEW_HOOK:
    if_master.if_new_hook = func;
    break;
  case IF_DELETE_HOOK:
    if_master.if_delete_hook = func;
    break;
  default:
    break;
  }
}

/* Interface existance check by index. */
struct interface *
if_lookup_by_index (int index)
{
  listnode node;
  struct interface *ifp;

  for (node = listhead (iflist); node; nextnode (node))
    {
      ifp = getdata (node);
      if (ifp->ifindex == index)
	return ifp;
    }
  return NULL;
}

char *
ifindex2ifname (unsigned int index)
{
  listnode node;
  struct interface *ifp;

  for (node = listhead (iflist); node; nextnode (node))
    {
      ifp = getdata (node);
      if (ifp->ifindex == index)
	return ifp->name;
    }
  return "unknown";
}

/* Interface existance check by interface name. */
struct interface *
if_lookup_by_name (char *name)
{
  listnode node;
  struct interface *ifp;

  for (node = listhead (iflist); node; nextnode (node))
    {
      ifp = getdata (node);
      if (strncmp (name, ifp->name, sizeof ifp->name) == 0)
	return ifp;
    }
  return NULL;
}

/* Lookup interface by IPv4 address. */
struct interface *
if_lookup_exact_address (struct in_addr src)
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
	      if (IPV4_ADDR_SAME (&p->u.prefix4, &src))
		return ifp;
	    }	      
	}
    }
  return NULL;
}

/* Lookup interface by IPv4 address. */
struct interface *
if_lookup_address (struct in_addr src)
{
  listnode node;
  struct prefix_ipv4 addr;
  listnode cnode;
  struct interface *ifp;
  struct prefix *p;
  struct connected *c;

  addr.family = AF_INET;
  addr.prefix = src;
  addr.prefixlen = IPV4_MAX_BITLEN;

  for (node = listhead (iflist); node; nextnode (node))
    {
      ifp = getdata (node);

      for (cnode = listhead (ifp->connected); cnode; nextnode (cnode))
	{
	  c = getdata (cnode);

	  if (if_is_pointopoint (ifp))
	    {
	      p = c->address;

	      if (p && p->family == AF_INET)
		{
		  if (IPV4_ADDR_SAME (&p->u.prefix4, &src))
		    return ifp;

		  p = c->destination;
		  if (p && IPV4_ADDR_SAME (&p->u.prefix4, &src))
		    return ifp;
		}
	    }
	  else
	    {
	      p = c->address;

	      if (p->family == AF_INET)
		{
		  if (prefix_match (p, (struct prefix *) &addr))
		    return ifp;
		}
	    }
	}
    }
  return NULL;
}

/* Get interface by name if given name interface doesn't exist create
   one. */
struct interface *
if_get_by_name (char *name)
{
  struct interface *ifp;

  ifp = if_lookup_by_name (name);
  if (ifp == NULL)
    {
      ifp = if_create ();
      strncpy (ifp->name, name, IFNAMSIZ);
    }
  return ifp;
}

/* Does interface up ? */
int
if_is_up (struct interface *ifp)
{
  return ifp->flags & IFF_UP;
}

/* Is this loopback interface ? */
int
if_is_loopback (struct interface *ifp)
{
  return ifp->flags & IFF_LOOPBACK;
}

/* Does this interface support broadcast ? */
int
if_is_broadcast (struct interface *ifp)
{
  return ifp->flags & IFF_BROADCAST;
}

/* Does this interface support broadcast ? */
int
if_is_pointopoint (struct interface *ifp)
{
  return ifp->flags & IFF_POINTOPOINT;
}

/* Does this interface support multicast ? */
int
if_is_multicast (struct interface *ifp)
{
  return ifp->flags & IFF_MULTICAST;
}

/* Printout flag information into log */
const char *
if_flag_dump (unsigned long flag)
{
  int separator = 0;
  static char logbuf[BUFSIZ];

#define IFF_OUT_LOG(X,STR) \
  if ((X) && (flag & (X))) \
    { \
      if (separator) \
	strlcat (logbuf, ",", BUFSIZ); \
      else \
	separator = 1; \
      strlcat (logbuf, STR, BUFSIZ); \
    }

  strlcpy (logbuf, "  <", BUFSIZ);
  IFF_OUT_LOG (IFF_UP, "UP");
  IFF_OUT_LOG (IFF_BROADCAST, "BROADCAST");
  IFF_OUT_LOG (IFF_DEBUG, "DEBUG");
  IFF_OUT_LOG (IFF_LOOPBACK, "LOOPBACK");
  IFF_OUT_LOG (IFF_POINTOPOINT, "POINTOPOINT");
  IFF_OUT_LOG (IFF_NOTRAILERS, "NOTRAILERS");
  IFF_OUT_LOG (IFF_RUNNING, "RUNNING");
  IFF_OUT_LOG (IFF_NOARP, "NOARP");
  IFF_OUT_LOG (IFF_PROMISC, "PROMISC");
  IFF_OUT_LOG (IFF_ALLMULTI, "ALLMULTI");
  IFF_OUT_LOG (IFF_OACTIVE, "OACTIVE");
  IFF_OUT_LOG (IFF_SIMPLEX, "SIMPLEX");
  IFF_OUT_LOG (IFF_LINK0, "LINK0");
  IFF_OUT_LOG (IFF_LINK1, "LINK1");
  IFF_OUT_LOG (IFF_LINK2, "LINK2");
  IFF_OUT_LOG (IFF_MULTICAST, "MULTICAST");

  strlcat (logbuf, ">", BUFSIZ);

  return logbuf;
}

/* For debugging */
void
if_dump (struct interface *ifp)
{
  listnode node;

  zlog_info ("Interface %s index %d metric %d mtu %d %s",
	     ifp->name, ifp->ifindex, ifp->metric, ifp->mtu, 
	     if_flag_dump (ifp->flags));
  
  for (node = listhead (ifp->connected); node; nextnode (node))
    ;
}

/* Interface printing for all interface. */
void
if_dump_all ()
{
  listnode node;

  for (node = listhead (iflist); node; nextnode (node))
    if_dump (getdata (node));
}

#ifdef HAVE_IPV6
void
if_index_address (struct in6_addr *addr)
{
  ;
}
#endif /* HAVE_IPV6 */


DEFUN (interface_desc, 
       interface_desc_cmd,
       "description ...",
       "Set interface description\n"
       "Description\n")
{
  int i;
  struct interface *ifp;
  struct buffer *b;

  if (argc == 0)
    return CMD_SUCCESS;

  ifp = vty->index;
  if (ifp->desc)
    XFREE (0, ifp->desc);

  b = buffer_new (BUFFER_STRING, 1024);
  for (i = 0; i < argc; i++)
    {
      buffer_putstr (b, (u_char *)argv[i]);
      buffer_putc (b, ' ');
    }
  buffer_putc (b, '\0');

  ifp->desc = buffer_getstr (b);
  buffer_free (b);

  return CMD_SUCCESS;
}

DEFUN (no_interface_desc, 
       no_interface_desc_cmd,
       "no description [description]",
       NO_STR
       "Delete interface description\n"
       "Description\n")
{
  struct interface *ifp;

  ifp = vty->index;
  if (ifp->desc)
    XFREE (0, ifp->desc);
  ifp->desc = NULL;

  return CMD_SUCCESS;
}

DEFUN (interface,
       interface_cmd,
       "interface IFNAME",
       "Select an interface to configure\n"
       "Interface's name\n")
{
  struct interface *ifp;

  ifp = if_lookup_by_name (argv[0]);

  if (ifp == NULL)
    {
      ifp = if_create ();
      strncpy (ifp->name, argv[0], INTERFACE_NAMSIZ);

      /* Pseudo interface. */
      ifp->ifindex = 0;
    }
  vty->index = ifp;
  vty->node = INTERFACE_NODE;

  return CMD_SUCCESS;
}

/* Initialize interface list. */
void
if_init ()
{
  iflist = list_init ();

  if (iflist)
    return;

  bzero (&if_master, sizeof if_master);
}

/* Allocate connected structure. */
struct connected *
connected_new ()
{
  struct connected *new = XMALLOC (MTYPE_CONNECTED, sizeof (struct connected));
  bzero (new, sizeof (struct connected));
  return new;
}

/* Free connected structure. */
void
connected_free (struct connected *connected)
{
  if (connected->address)
    prefix_free (connected->address);

  if (connected->destination)
    prefix_free (connected->destination);

  XFREE (MTYPE_CONNECTED, connected);
}

/* Print if_addr structure. */
void
connected_log (struct connected *connected)
{
  struct prefix *p;
  struct interface *ifp;
  char logbuf[BUFSIZ];
  char buf[BUFSIZ];
  
  ifp = connected->ifp;
  p = connected->address;

  snprintf (logbuf, BUFSIZ, "interface %s %s %s/%d ", 
       ifp->name, 
       prefix_family_str (p),
       inet_ntop (p->family, &p->u.prefix, buf, BUFSIZ),
       p->prefixlen);
  
  p = connected->destination;
  if (p)
    {
#if 0 /* want v6 connected address to be logged, too. */
      if (p->family == AF_INET)
#endif
	strncat (logbuf, inet_ntop (p->family, &p->u.prefix, buf, BUFSIZ),
		 BUFSIZ - strlen(logbuf));
    }
  zlog (NULL, LOG_INFO, logbuf);
}

/* If two connected address has same prefix return 1. */
int
connected_same_prefix (struct prefix *p1, struct prefix *p2)
{
  if (p1->family == p2->family)
    {
      if (p1->family == AF_INET &&
	  IPV4_ADDR_SAME (&p1->u.prefix4, &p2->u.prefix4))
	return 1;
#ifdef HAVE_IPV6
      if (p1->family == AF_INET6 &&
	  IPV6_ADDR_SAME (&p1->u.prefix6, &p2->u.prefix6))
	return 1;
#endif /* HAVE_IPV6 */
    }
  return 0;
}

void
connected_add (struct interface *ifp, struct connected *connected)
{
  listnode node;
  struct connected *ifc;

  /* In case of same prefix come, replace it with new one. */
  for (node = listhead (ifp->connected); node; node = node->next)
    {
      ifc = getdata (node);
      if (connected_same_prefix (ifc->address, connected->address))
	{
	  list_delete_by_val (ifp->connected, ifc);
	  break;
	}
    }

  /* Link connected address to interface. */
  connected->ifp = ifp;
  list_add_node (ifp->connected, connected);

  /* connected_log (connected); */
}

void
connected_delete_by_prefix (struct interface *ifp, struct prefix *p)
{
  listnode node;
  struct connected *ifc;

  /* In case of same prefix come, replace it with new one. */
  for (node = listhead (ifp->connected); node; node = node->next)
    {
      ifc = getdata (node);
      if (connected_same_prefix (ifc->address, p))
	{
	  list_delete_by_val (ifp->connected, ifc);
	  break;
	}
    }
}

#ifdef NRL
#ifndef HAVE_IF_NAMETOINDEX
unsigned int
if_nametoindex (char *name)
{
  listnode node;
  struct interface *ifp;

  for (node = listhead (iflist); node; nextnode (node))
    {
      ifp = getdata (node);
      if (strcmp (ifp->name, name) == 0)
	return ifp->ifindex;
    }
  return 0;
}
#endif

#ifndef HAVE_IF_INDEXTONAME
char *
if_indextoname (unsigned int ifindex, char *name)
{
  listnode node;
  struct interface *ifp;

  for (node = listhead (iflist); node; nextnode (node))
    {
      ifp = getdata (node);
      if (ifp->ifindex == ifindex)
	{
	  memcpy (name, ifp->name, IFNAMSIZ);
	  return ifp->name;
	}
    }
  return NULL;
}
#endif
#endif /* NRL */
