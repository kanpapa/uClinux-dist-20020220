/*
 * Copyright (C) 1999 Yasuhiro Ohara
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
 * along with GNU Zebra; see the file COPYING.  If not, write to the 
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330, 
 * Boston, MA 02111-1307, USA.  
 */

#ifndef OSPF6D_H
#define OSPF6D_H

#include <zebra.h>

/* Include other stuffs */
#include "version.h"
#include "log.h"
#include "getopt.h"
#include "linklist.h"
#include "thread.h"
#include "command.h"
#include "memory.h"
#include "sockunion.h"
#include "if.h"
#include "prefix.h"
#include "stream.h"
#include "thread.h"
#include "filter.h"
#include "zclient.h"
#include "table.h"
#include "plist.h"

#define HASHVAL 64
#define MAXIOVLIST 1024

/* OSPF stuffs */
#include "ospf6_types.h"
#include "ospf6_prefix.h"
#include "ospf6_mesg.h"
#include "ospf6_spf.h"
#include "ospf6_rtable.h"
#include "ospf6_proto.h"
#include "ospf6_redistribute.h"
#include "ospf6_top.h"
#include "ospf6_area.h"
#include "ospf6_interface.h"
#include "ospf6_neighbor.h"
#include "ospf6_ism.h"
#include "ospf6_nsm.h"
#include "ospf6_lsa.h"
#include "ospf6_lsdb.h"
#include "ospf6_dbex.h"
#include "ospf6_network.h"
#include "ospf6_zebra.h"
#include "ospf6_dump.h"
#include "ospf6_routemap.h"

/* Old Kame of FreeBSD crashes when tring to use IPV6_CHECKSUM. */
/* #define DISABLE_IPV6_CHECKSUM */

/* global variables */
extern char *progname;
extern int errno;
extern int daemon_mode;
extern struct thread_master *master;
extern list iflist;
extern list nexthoplist;
extern struct sockaddr_in6 allspfrouters6;
extern struct sockaddr_in6 alldrouters6;
extern int ospf6_sock;
extern struct ospf6 *ospf6;
extern char *recent_reason;

/* Default configuration file name for ospfd. */
#define OSPF6_DEFAULT_CONFIG       "ospf6d.conf"

/* Default port values. */
#define OSPF6_VTY_PORT             2606
#define OSPF6_VTYSH_PATH           "/tmp/ospf6d"

#ifdef INRIA_IPV6
#ifndef IPV6_PKTINFO
#define IPV6_PKTINFO IPV6_RECVPKTINFO
#endif /* IPV6_PKTINFO */
#endif /* INRIA_IPV6 */

/* historycal for KAME */
#ifndef IPV6_JOIN_GROUP
#ifdef IPV6_ADD_MEMBERSHIP
#define IPV6_JOIN_GROUP IPV6_ADD_MEMBERSHIP
#endif /* IPV6_ADD_MEMBERSHIP. */
#ifdef IPV6_JOIN_MEMBERSHIP  /* I'm not sure this really exist. -- kunihiro. */
#define IPV6_JOIN_GROUP  IPV6_JOIN_MEMBERSHIP
#endif /* IPV6_JOIN_MEMBERSHIP. */
#endif

#ifndef IPV6_LEAVE_GROUP
#ifdef  IPV6_DROP_MEMBERSHIP
#define IPV6_LEAVE_GROUP IPV6_DROP_MEMBERSHIP
#endif
#endif


/* Command Description */
#define V4NOTATION_STR     "specify by IPv4 address notation(e.g. 0.0.0.0)\n"
#define OSPF6_NUMBER_STR    "Specify by number\n"

#define INTERFACE_STR       "Interface infomation\n"
#define IFNAME_STR          "Interface name(e.g. ep0)\n"
#define IP6_STR             "IPv6 Information\n"
#define OSPF6_STR           "Open Shortest Path First (OSPF) for IPv6\n"
#define OSPF6_ROUTER_STR    "Enable a routing process\n"
#define OSPF6_INSTANCE_STR  "<1-65535> Instance ID\n"
#define SECONDS_STR         "<1-65535> Seconds\n"
#define ROUTE_STR           "Routing Table\n"


/* Function Prototypes */
void ospf6_init ();
void ospf6_terminate ();

#endif /* OSPF6D_H */
