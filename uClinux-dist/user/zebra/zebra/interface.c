/*
 * Interface function.
 * Copyright (C) 1997, 1999 Kunihiro Ishiguro
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
#include "vty.h"
#include "sockunion.h"
#include "prefix.h"
#include "command.h"
#include "memory.h"
#include "ioctl.h"
#include "connected.h"
#include "log.h"
#include "zclient.h"

#include "zebra/interface.h"
#include "zebra/rtadv.h"
#include "zebra/zserv.h"
#include "zebra/rib.h"

/* Called when new interface is added. */
int
if_zebra_new_hook (struct interface *ifp)
{
  struct zebra_if *zebra_if;

  zebra_if = XMALLOC (MTYPE_TMP, sizeof (struct zebra_if));
  memset (zebra_if, 0, sizeof (struct zebra_if));

  zebra_if->multicast = IF_ZEBRA_MULTICAST_UNSPEC;
  zebra_if->shutdown = IF_ZEBRA_SHUTDOWN_UNSPEC;
  zebra_if->address = list_init ();

#ifdef RTADV
  {
    /* Set default router advertise values. */
    struct rtadvconf *rtadv;

    rtadv = &zebra_if->rtadv;

    rtadv->AdvSendAdvertisements = 0;
    rtadv->MaxRtrAdvInterval = 600;
    rtadv->MinRtrAdvInterval = 0.33 * rtadv->MaxRtrAdvInterval;
    rtadv->AdvManagedFlag = 0;
    rtadv->AdvOtherConfigFlag = 0;
    rtadv->AdvLinkMTU = 0;
    rtadv->AdvReachableTime = 0;
    rtadv->AdvRetransTimer = 0;
    rtadv->AdvCurHopLimit = 0;
    rtadv->AdvDefaultLifetime = 3 * rtadv->MaxRtrAdvInterval;

    rtadv->AdvPrefixList = list_init ();
  }    
#endif /* RTADV */

  ifp->info = zebra_if;
  return 0;
}

/* Called when interface is deleted. */
int
if_zebra_delete_hook (struct interface *ifp)
{
  rib_if_delete(ifp);
  if (ifp->info)
    XFREE (MTYPE_TMP, ifp->info);
  return 0;
}

extern list client_list;

void
zebra_interface_up_update (struct interface *ifp)
{
  listnode node;
  struct zebra_client *client;

  for (node = listhead (client_list); node; nextnode (node))
    if ((client = getdata (node)) != NULL)
      zebra_interface_up (client->fd, ifp);
}

/* Interface is up. */
void
if_up (struct interface *ifp)
{
  listnode node;
  listnode next;
  struct connected *ifc;
  struct prefix *p;

  zlog_info ("Interface %s is up", ifp->name);

  /* Notify the protocol daemons. */
  zebra_interface_up_update (ifp);

  /* Install connected routes to the kernel. */
  if (ifp->connected)
    {
      for (node = listhead (ifp->connected); node; node = next)
	{
	  next = node->next;
	  ifc = getdata (node);
	  p = ifc->address;

	  if (p->family == AF_INET)
	    connected_up_ipv4 (ifp, &p->u.prefix4, p->prefixlen);
#ifdef HAVE_IPV6
	  else if (p->family == AF_INET6)
	    connected_up_ipv6 (ifp, &p->u.prefix6, p->prefixlen);
#endif /* HAVE_IPV6 */
	}
    }

  /* Examine all static routes. */
  rib_if_up (ifp);
}

void
zebra_interface_down_update (struct interface *ifp)
{
  listnode node;
  struct zebra_client *client;

  for (node = listhead (client_list); node; nextnode (node))
    if ((client = getdata (node)) != NULL)
      zebra_interface_down (client->fd, ifp);
}


/* Interface goes down.  We have to manage different behavior of based
   OS. */
void
if_down (struct interface *ifp)
{
  listnode node;
  listnode next;
  struct connected *ifc;
  struct prefix *p;

  zlog_info ("Interface %s is down", ifp->name);

  /* Notify to the protocol daemons. */
  zebra_interface_down_update (ifp);

  /* Delete connected routes from the kernel. */
  if (ifp->connected)
    {
      for (node = listhead (ifp->connected); node; node = next)
	{
	  next = node->next;
	  ifc = getdata (node);
	  p = ifc->address;

	  if (p->family == AF_INET)
	    connected_down_ipv4 (ifp, &p->u.prefix4, p->prefixlen);
#ifdef HAVE_IPV6
	  else if (p->family == AF_INET6)
	    connected_down_ipv6 (ifp, &p->u.prefix6, p->prefixlen);
#endif /* HAVE_IPV6 */
	}
    }

  /* Examine all static routes which direct to the interface. */
  rib_if_down (ifp);
}

int
if_addr_add (struct interface *ifp, struct prefix *p)
{
  struct prefix *addr;
  struct zebra_if *if_data;

  addr = prefix_new ();
  *addr = *p;

  if_data = (struct zebra_if *) ifp->info;
  list_add_node (if_data->address, addr);

  /* Address check. */
  if (addr->family == AF_INET)
    {
      if (connected_check_ipv4 (ifp, p))
	return 0;
      connected_add_ipv4 (ifp, &addr->u.prefix4, addr->prefixlen, NULL);
    }
#ifdef HAVE_IPV6
  if (addr->family == AF_INET6)
    {
      if (connected_check_ipv6 (ifp, p))
	return 0;
      connected_add_ipv6 (ifp, &addr->u.prefix6, addr->prefixlen, NULL);
    }
#endif /* HAVE_IPV6 */

  return 0;
}

int
if_addr_delete (struct interface *ifp, struct prefix *p)
{
  struct zebra_if *if_data;
  listnode node;
  struct prefix *addr = NULL;

  if_data = (struct zebra_if *) ifp->info;

  for (node = listhead (if_data->address); node; node = nextnode (node))
    {
      addr = getdata (node);

      if (addr->family == AF_INET)
	if (IPV4_ADDR_SAME (&addr->u.prefix, &p->u.prefix))
	  {
	    connected_delete_ipv4 (ifp, &addr->u.prefix4, 
				   addr->prefixlen, NULL);
	    list_delete_by_val (if_data->address, addr);
	    return 0;
	  }
	
#ifdef HAVE_IPV6
      if (addr->family == AF_INET6)
	if (IPV6_ADDR_SAME (&addr->u.prefix, &p->u.prefix))
	  {
	    connected_delete_ipv6 (ifp, &addr->u.prefix6, 
				   addr->prefixlen, NULL);
	    list_delete_by_val (if_data->address, addr);
	    return 0;
	  }
#endif /* HAVE_IPV6 */
    }	 
  return -1;
}

#ifdef KAME
int
if_tun_add (struct interface *ifsp, struct interface *ifdp, 
	    struct prefix *sp, struct prefix *dp)
{
#if 0				/* Commented out by Kunihiro. */
  int ret;
  struct prefix *saddr, daddr;
  struct zebra_if *if_sdata, *if_ddata;
    
  ret = if_set_prefix (ifsp, (struct prefix_ipv4 *) sp);
  if (ret < 0)
    return ret;
  ret = if_set_prefix (ifdp, (struct prefix_ipv4 *) dp);
  if (ret < 0)
    return ret;
    
  saddr = prefix_new ();
  daddr = prefix_new ();
  *saddr = *sp;
  *daddr = *dp;
    
  if_sdata = (struct zebra_if *) ifsp->if_data;
  list_add_node (if_sdata->address, saddr);
  if_ddata = (struct zebra_if *) ifdp->if_data;
  list_add_node (if_ddata->address, daddr);
    
  /* Address check. */
  if (addr->family == AF_INET)
    connected_add_ipv4 (ifp, &addr->u.prefix4, addr->prefixlen, NULL);
#ifdef HAVE_IPV6
  if (addr->family == AF_INET6)
    connected_add_ipv6 (ifp, &addr->u.prefix6, addr->prefixlen, NULL);
#endif /* HAVE_IPV6 */
    
#endif /* 0 */
  return 0;
}

int
if_tun_delete (struct interface *ifsp, struct interface *ifdp,
	       struct prefix *sp, struct prefix *dp)
{
  return 0;
}
#endif KAME

/* Printout flag information into vty */
void
if_flag_dump_vty (struct vty *vty, unsigned long flag)
{
  int separator = 0;

#define IFF_OUT_VTY(X, Y) \
  if ((X) && (flag & (X))) \
    { \
      if (separator) \
	vty_out (vty, ","); \
      else \
	separator = 1; \
      vty_out (vty, Y); \
    }

  vty_out (vty, "<");
  IFF_OUT_VTY (IFF_UP, "UP");
  IFF_OUT_VTY (IFF_BROADCAST, "BROADCAST");
  IFF_OUT_VTY (IFF_DEBUG, "DEBUG");
  IFF_OUT_VTY (IFF_LOOPBACK, "LOOPBACK");
  IFF_OUT_VTY (IFF_POINTOPOINT, "POINTOPOINT");
  IFF_OUT_VTY (IFF_NOTRAILERS, "NOTRAILERS");
  IFF_OUT_VTY (IFF_RUNNING, "RUNNING");
  IFF_OUT_VTY (IFF_NOARP, "NOARP");
  IFF_OUT_VTY (IFF_PROMISC, "PROMISC");
  IFF_OUT_VTY (IFF_ALLMULTI, "ALLMULTI");
  IFF_OUT_VTY (IFF_OACTIVE, "OACTIVE");
  IFF_OUT_VTY (IFF_SIMPLEX, "SIMPLEX");
  IFF_OUT_VTY (IFF_LINK0, "LINK0");
  IFF_OUT_VTY (IFF_LINK1, "LINK1");
  IFF_OUT_VTY (IFF_LINK2, "LINK2");
  IFF_OUT_VTY (IFF_MULTICAST, "MULTICAST");
  vty_out (vty, ">");
}

/* Output prefix string to vty. */
int
prefix_vty_out (struct vty *vty, struct prefix *p)
{
  char str[INET6_ADDRSTRLEN];

  inet_ntop (p->family, &p->u.prefix, str, sizeof (str));
  vty_out (vty, "%s", str);
  return strlen (str);
}
/* Dump if address information to vty. */
void
connected_dump_vty (struct vty *vty, struct connected *connected)
{
  struct prefix *p;
  struct interface *ifp;

  /* Set interface pointer. */
  ifp = connected->ifp;

  /* Print interface address. */
  p = connected->address;
  vty_out (vty, "  %s ", prefix_family_str (p));
  prefix_vty_out (vty, p);
  vty_out (vty, "/%d", p->prefixlen);

  /* If there is destination address, print it. */
  p = connected->destination;
  if (p)
    {
      if (p->family == AF_INET)
	if (ifp->flags & IFF_BROADCAST)
	  {
	    vty_out (vty, " broadcast ");
	    prefix_vty_out (vty, p);
	  }

      if (ifp->flags & IFF_POINTOPOINT)
	{
	  vty_out (vty, " pointopoint ");
	  prefix_vty_out (vty, p);
	}
    }
  vty_out (vty, "%s", VTY_NEWLINE);
}


/* Interface's information print out to vty interface. */
void
if_dump_vty (struct vty *vty, struct interface *ifp)
{
  struct connected *connected;
  listnode node;

  vty_out (vty, "Interface %s%s", ifp->name,
	   VTY_NEWLINE);
  if (ifp->desc)
    vty_out (vty, "  Description: %s%s", ifp->desc,
	     VTY_NEWLINE);
  if (ifp->ifindex <= 0)
    {
      vty_out(vty, "  index %d pseudo interface%s", ifp->ifindex, VTY_NEWLINE);
      return;
    }

  vty_out (vty, "  index %d metric %d mtu %d ",
	   ifp->ifindex, ifp->metric, ifp->mtu);
  if_flag_dump_vty (vty, ifp->flags);
  vty_out (vty, "%s", VTY_NEWLINE);

  /* Hardware address. */
#ifdef HAVE_SOCKADDR_DL
#else
  if (ifp->hw_addr_len != 0)
    {
      int i;

      vty_out (vty, "  HWaddr: ");
      for (i = 0; i < ifp->hw_addr_len; i++)
	vty_out (vty, "%s%02x", i == 0 ? "" : ":", ifp->hw_addr[i]);
      vty_out (vty, "%s", VTY_NEWLINE);
    }
#endif /* HAVE_SOCKADDR_DL */
  
  for (node = listhead (ifp->connected); node; nextnode (node))
    {
      connected = getdata (node);
      connected_dump_vty (vty, connected);
    }

#ifdef HAVE_PROC_NET_DEV
  /* Statistics print out using proc file system. */
  vty_out (vty, "    input packets %lu, bytes %lu, dropped %lu,"
	   " multicast packets %lu%s",
	   ifp->stats.rx_packets, ifp->stats.rx_bytes, 
	   ifp->stats.rx_dropped, ifp->stats.rx_multicast, VTY_NEWLINE);

  vty_out (vty, "    input errors %lu, length %lu, overrun %lu,"
	   " CRC %lu, frame %lu, fifo %lu, missed %lu%s",
	   ifp->stats.rx_errors, ifp->stats.rx_length_errors,
	   ifp->stats.rx_over_errors, ifp->stats.rx_crc_errors,
	   ifp->stats.rx_frame_errors, ifp->stats.rx_fifo_errors,
	   ifp->stats.rx_missed_errors, VTY_NEWLINE);

  vty_out (vty, "    output packets %lu, bytes %lu, dropped %lu%s",
	   ifp->stats.tx_packets, ifp->stats.tx_bytes,
	   ifp->stats.tx_dropped, VTY_NEWLINE);

  vty_out (vty, "    output errors %lu, aborted %lu, carrier %lu,"
	   " fifo %lu, heartbeat %lu, window %lu%s",
	   ifp->stats.tx_errors, ifp->stats.tx_aborted_errors,
	   ifp->stats.tx_carrier_errors, ifp->stats.tx_fifo_errors,
	   ifp->stats.tx_heartbeat_errors, ifp->stats.tx_window_errors,
	   VTY_NEWLINE);

  vty_out (vty, "    collisions %lu%s", ifp->stats.collisions, VTY_NEWLINE);
#endif /* HAVE_PROC_NET_DEV */

#ifdef HAVE_NET_RT_IFLIST
#if defined (__bsdi__)
  /* Statistics print out using sysctl (). */
  vty_out (vty, "    input packets %qu, bytes %qu, dropped %qu,"
	   " multicast packets %qu%s",
	   ifp->stats.ifi_ipackets, ifp->stats.ifi_ibytes,
	   ifp->stats.ifi_iqdrops, ifp->stats.ifi_imcasts,
	   VTY_NEWLINE);

  vty_out (vty, "    input errors %qu%s",
	   ifp->stats.ifi_ierrors, VTY_NEWLINE);

  vty_out (vty, "    output packets %qu, bytes %qu, multicast packets %qu%s",
	   ifp->stats.ifi_opackets, ifp->stats.ifi_obytes,
	   ifp->stats.ifi_omcasts, VTY_NEWLINE);

  vty_out (vty, "    output errors %qu%s",
	   ifp->stats.ifi_oerrors, VTY_NEWLINE);

  vty_out (vty, "    collisions %qu%s",
	   ifp->stats.ifi_collisions, VTY_NEWLINE);
#else
  /* Statistics print out using sysctl (). */
  vty_out (vty, "    input packets %lu, bytes %lu, dropped %lu,"
	   " multicast packets %lu%s",
	   ifp->stats.ifi_ipackets, ifp->stats.ifi_ibytes,
	   ifp->stats.ifi_iqdrops, ifp->stats.ifi_imcasts,
	   VTY_NEWLINE);

  vty_out (vty, "    input errors %lu%s",
	   ifp->stats.ifi_ierrors, VTY_NEWLINE);

  vty_out (vty, "    output packets %lu, bytes %lu, multicast packets %lu%s",
	   ifp->stats.ifi_opackets, ifp->stats.ifi_obytes,
	   ifp->stats.ifi_omcasts, VTY_NEWLINE);

  vty_out (vty, "    output errors %lu%s",
	   ifp->stats.ifi_oerrors, VTY_NEWLINE);

  vty_out (vty, "    collisions %lu%s",
	   ifp->stats.ifi_collisions, VTY_NEWLINE);
#endif /* __bsdi__ */
#endif /* HAVE_NET_RT_IFLIST */
}

/* Check supported address family. */
int
if_supported_family (int family)
{
  if (family == AF_INET)
    return 1;
#ifdef HAVE_IPV6
  if (family == AF_INET6)
    return 1;
#endif /* HAVE_IPV6 */
  return 0;
}

struct cmd_node interface_node =
{
  INTERFACE_NODE,
  "%s(config-if)# ",
};

/* Show all or specified interface to vty. */
DEFUN (show_interface, show_interface_cmd,
       "show interface [IFNAME]",  
       SHOW_STR
       "Interface status and configuration\n"
       "Inteface name\n")
{
  listnode node;
  struct interface *ifp;
  
#ifdef HAVE_PROC_NET_DEV
  /* If system has interface statistics via proc file system, update
     statistics. */
  ifstat_update_proc ();
#endif /* HAVE_PROC_NET_DEV */
#ifdef HAVE_NET_RT_IFLIST
  ifstat_update_sysctl ();
#endif /* HAVE_NET_RT_IFLIST */

  /* Specified interface print. */
  if (argc != 0)
    {
      ifp = if_lookup_by_name (argv[0]);
      if (ifp == NULL) 
	{
	  vty_out (vty, "Can't find interface [%s]%s", argv[0],
		   VTY_NEWLINE);
	  return CMD_WARNING;
	}
      if_dump_vty (vty, ifp);
      return CMD_SUCCESS;
    }

  /* All interface print. */
  for (node = listhead (iflist); node; nextnode (node))
    if_dump_vty (vty, getdata (node));

  return CMD_SUCCESS;
}

DEFUN (multicast,
       multicast_cmd,
       "multicast",
       "Set multicast flag to interface\n")
{
  int ret;
  struct interface *ifp;
  struct zebra_if *if_data;

  ifp = (struct interface *) vty->index;
  ret = if_set_flags (ifp, IFF_MULTICAST);
  if (ret < 0)
    {
      vty_out (vty, "Can't set multicast flag%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  if_get_flags (ifp);
  if_data = ifp->info;
  if_data->multicast = IF_ZEBRA_MULTICAST_ON;
  
  return CMD_SUCCESS;
}

DEFUN (no_multicast,
       no_multicast_cmd,
       "no multicast",
       NO_STR
       "Unset multicast flag to interface\n")
{
  int ret;
  struct interface *ifp;
  struct zebra_if *if_data;

  ifp = (struct interface *) vty->index;
  ret = if_unset_flags (ifp, IFF_MULTICAST);
  if (ret < 0)
    {
      vty_out (vty, "Can't unset multicast flag%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  if_get_flags (ifp);
  if_data = ifp->info;
  if_data->multicast = IF_ZEBRA_MULTICAST_OFF;

  return CMD_SUCCESS;
}

DEFUN (shutdown_if,
       shutdown_if_cmd,
       "shutdown",
       "Shutdown the selected interface\n")
{
  int ret;
  struct interface *ifp;
  struct zebra_if *if_data;

  ifp = (struct interface *) vty->index;
  ret = if_unset_flags (ifp, IFF_UP);
  if (ret < 0)
    {
      vty_out (vty, "Can't shutdown interface%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  if_get_flags (ifp);
  if_data = ifp->info;
  if_data->shutdown = IF_ZEBRA_SHUTDOWN_ON;
  if_down (ifp);

  return CMD_SUCCESS;
}

DEFUN (no_shutdown_if,
       no_shutdown_if_cmd,
       "no shutdown",
       "Negate a command or set its defaults\n"
       "Shutdown the selected interface\n")
{
  int ret;
  struct interface *ifp;
  struct zebra_if *if_data;

  ifp = (struct interface *) vty->index;
  ret = if_set_flags (ifp, IFF_UP | IFF_RUNNING);
  if (ret < 0)
    {
      vty_out (vty, "Can't up interface%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  if_get_flags (ifp);
  if_data = ifp->info;
  if_data->shutdown = IF_ZEBRA_SHUTDOWN_OFF;
  if (if_is_up (ifp)) if_up (ifp);

  return CMD_SUCCESS;
}

DEFUN (ip_address, ip_address_cmd,
       "ip address A.B.C.D/M",
       "Interface Internet Protocol config commands\n"
       "Set the IP address of an interface\n"
       "IP address (e.g. 10.0.0.1/8)\n")
{
  int ret;
  struct interface *ifp;
  struct prefix p;

  ifp = (struct interface *) vty->index;

  ret = str2prefix_ipv4 (argv[0], (struct prefix_ipv4 *) &p);
  if (ret <= 0)
    {
      vty_out (vty, "Please specify address by a.b.c.d/mask%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Set interface's flag.  Ignore result for Linux's interface
     alias which can't up. */
  ret = if_set_flags (ifp, IFF_UP | IFF_RUNNING);
#if 0
  if (ret < 0)
    {
      vty_out (vty, "Can't up interface%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
#endif /* 0 */
  if_get_flags (ifp);

  ret = if_set_prefix (ifp, (struct prefix_ipv4 *) &p);
  if (ret < 0)
    {
      vty_out (vty, "Can't set interface's address: %s.%s", strerror(errno),
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Make sure mask is applied and set type to static route. */
  ret = if_addr_add (ifp, &p);
  if (ret < 0)
    {
      vty_out (vty, "Can't set interface's address: %s.%s", strerror(errno),
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  return CMD_SUCCESS;
}

DEFUN (no_ip_address, no_ip_address_cmd,
       "no ip address A.B.C.D/M",
       "Negate a command or set its defaults\n"
       "Interface Internet Protocol config commands\n"
       "Set the IP address of an interface\n"
       "IP Address (e.g. 10.0.0.1/8)")
{
  int ret;
  struct interface *ifp;
  struct prefix p;

  ifp = (struct interface *) vty->index;

  ret = str2prefix_ipv4 (argv[0], (struct prefix_ipv4 *) &p);
  if (ret <= 0)
    {
      vty_out (vty, "Please specify address by a.b.c.d/mask%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  ret = if_unset_prefix (ifp, (struct prefix_ipv4 *) &p);
  if (ret < 0)
    {
      vty_out (vty, "Can't delete interface's address: %s.%s", 
	       strerror(errno),
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  ret = if_addr_delete (ifp, &p);
  if (ret < 0)
    {
      vty_out (vty, "Can't delete interface's address: %s.%s", 
	       strerror(errno),
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  return CMD_SUCCESS;
}

#ifdef HAVE_IPV6
DEFUN (ipv6_address, ipv6_address_cmd,
       "ipv6 address IPV6PREFIX/M",
       "Interface Internet Protocol config commands\n"
       "Set the IP address of an interface\n"
       "IPv6 address (e.g. 3ffe:506::1/48)\n")
{
  int ret;
  struct interface *ifp;
  struct prefix p;

  ifp = (struct interface *) vty->index;

  ret = str2prefix_ipv6 (argv[0],(struct prefix_ipv6 *) &p);
  if (ret <= 0)
    {
      vty_out (vty, "Please specify IPv6 prefix with prefixlen%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Set interface's flag. */
  ret = if_set_flags (ifp, IFF_UP | IFF_RUNNING);
#if 0
  if (ret < 0)
    {
      vty_out (vty, "Can't up interface%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
#endif /* 0 */
  if_get_flags (ifp);

  /* Make sure mask is applied and set type to static route*/
  ret = if_prefix_add_ipv6 (ifp, (struct prefix_ipv6 *)&p);
  if (ret < 0)
    {
      vty_out (vty, "Can't set interface's address: %s.%s", strerror(errno),
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  if_addr_add (ifp, &p);

  return CMD_SUCCESS;
}

DEFUN (no_ipv6_address, no_ipv6_address_cmd,
       "no ipv6 address IPV6PREFIX/M",
       NO_STR
       "Interface Internet Protocol config commands\n"
       "Set the IP address of an interface\n"
       "IPv6 address (e.g. 3ffe:506::1/48)\n")
{
  int ret;
  struct interface *ifp;
  struct prefix p;

  ifp = (struct interface *) vty->index;

  ret = str2prefix_ipv6 (argv[0],(struct prefix_ipv6 *) &p);
  if (ret <= 0)
    {
      vty_out (vty, "Please specify IPv6 prefix with prefixlen%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  ret = if_prefix_delete_ipv6 (ifp, (struct prefix_ipv6 *)&p);
  if (ret < 0)
    {
      vty_out (vty, "Can't delete interface's address: %s.%s",
	       strerror(errno),
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  if_addr_delete (ifp, &p);

  return CMD_SUCCESS;
}
#endif /* HAVE_IPV6 */

#ifdef KAME
DEFUN (ip_tunnel, ip_tunnel_cmd,
       "ip tunnel IP_address IP_address",
       "KAME ip tunneling configuration commands\n"
       "Set FROM IP address and TO IP address\n")
{
  /* variable define */
  int ret;
  struct interface *ifsp, *ifdp;
  struct prefix sp, dp;

  ifsp = (struct interface *) vty->index;
  ifdp = (struct interface *) vty->index;
  ret = str2prefix (argv[0], &sp);
  if (!ret)
    {
      vty_out (vty, "Please specify address by a.b.c.d/mask%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  ret = str2prefix (argv[1], &dp);
  if (!ret)
    {
      vty_out (vty, "Please specify address by a.b.c.d/mask%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  ret = if_tun_add (ifsp, ifdp, &sp, &dp);
  if (ret < 0)
    {
      vty_out (vty, "Can't set tunnel address: %s.%s", 
	       strerror(errno),
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  return CMD_SUCCESS;
}

DEFUN (no_ip_tunnel, no_ip_tunnel_cmd,
       "no ip tunnel",
       "Negate KAME ip tunneling configuration commands\n"
       "Set FROM IP address and TO IP address\n")
{
  /* variable define */
  int ret;
  struct interface *ifp;
  struct interface *ifsp = NULL;
  struct prefix sp, dp;

  ifp = (struct interface *) vty->index;
  ret = str2prefix (argv[0], &sp);
  if (!ret)
    {
      vty_out (vty, "Please specify address by a.b.c.d/mask%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  ret = str2prefix (argv[1], &dp);
  if (!ret)
    {
      vty_out (vty, "Please specify address by a.b.c.d/mask%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  ret = if_tun_delete (ifsp, ifp, &sp, &dp);
  if (ret < 0)
    {
      vty_out (vty, "Can't set tunnel address: %s.%s", 
	       strerror(errno),
	       VTY_NEWLINE);
      return CMD_WARNING;
    }
    
  return CMD_SUCCESS;
}
#endif /* KAME */

int
if_config_write (struct vty *vty)
{
  listnode node;
  struct interface *ifp;
  char buf[BUFSIZ];

  for (node = listhead (iflist); node; nextnode (node))
    {
      struct zebra_if *if_data;
      listnode addrnode;
      struct prefix *p;

      ifp = getdata (node);
      if_data = ifp->info;
      
      vty_out (vty, "interface %s%s", ifp->name,
	       VTY_NEWLINE);

      if (ifp->desc)
	vty_out (vty, " description %s%s", ifp->desc,
		 VTY_NEWLINE);

      if (if_data && if_data->address)
	for (addrnode = listhead (if_data->address); addrnode; 
	     nextnode (addrnode))
	  {
	    p = getdata (addrnode);
	    vty_out (vty, " ip%s address %s/%d%s",
		     p->family == AF_INET ? "" : "v6",
		     inet_ntop (p->family, &p->u.prefix, buf, BUFSIZ),
		     p->prefixlen,
		     VTY_NEWLINE);
	  }

      if (if_data)
	{
	  if (if_data->shutdown == IF_ZEBRA_SHUTDOWN_ON)
	    vty_out (vty, " shutdown%s", VTY_NEWLINE);

	  if (if_data->multicast != IF_ZEBRA_MULTICAST_UNSPEC)
	    vty_out (vty, " %smulticast%s",
		     if_data->multicast == IF_ZEBRA_MULTICAST_ON ? "" : "no ",
		     VTY_NEWLINE);
	}

#ifdef RTADV
      rtadv_config_write (vty, ifp);
#endif /* RTADV */

      vty_out (vty, "!%s", VTY_NEWLINE);
    }
  return 0;
}

/* Allocate and initialize interface vector. */
void
zebra_if_init ()
{
  /* Initialize interface and new hook. */
  if_init ();
  if_add_hook (IF_NEW_HOOK, if_zebra_new_hook);
  if_add_hook (IF_DELETE_HOOK, if_zebra_delete_hook);
  
  /* Install configuration write function. */
  install_node (&interface_node, if_config_write);

  install_element (VIEW_NODE, &show_interface_cmd);
  install_element (ENABLE_NODE, &show_interface_cmd);
  install_element (CONFIG_NODE, &interface_cmd);
  install_element (INTERFACE_NODE, &config_end_cmd);
  install_element (INTERFACE_NODE, &config_exit_cmd);
  install_element (INTERFACE_NODE, &config_help_cmd);
  install_element (INTERFACE_NODE, &interface_desc_cmd);
  install_element (INTERFACE_NODE, &no_interface_desc_cmd);
  install_element (INTERFACE_NODE, &multicast_cmd);
  install_element (INTERFACE_NODE, &no_multicast_cmd);
  install_element (INTERFACE_NODE, &shutdown_if_cmd);
  install_element (INTERFACE_NODE, &no_shutdown_if_cmd);
  install_element (INTERFACE_NODE, &ip_address_cmd);
  install_element (INTERFACE_NODE, &no_ip_address_cmd);
#ifdef HAVE_IPV6
  install_element (INTERFACE_NODE, &ipv6_address_cmd);
  install_element (INTERFACE_NODE, &no_ipv6_address_cmd);
#endif /* HAVE_IPV6 */
#ifdef KAME
  install_element (INTERFACE_NODE, &ip_tunnel_cmd);
  install_element (INTERFACE_NODE, &no_ip_tunnel_cmd);
#endif /* KAME */
}
