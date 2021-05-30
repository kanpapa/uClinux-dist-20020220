/* BGP message definition header.
 * Copyright (C) 1996, 97, 98, 99 Kunihiro Ishiguro
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

#ifndef _ZEBRA_BGPD_H
#define _ZEBRA_BGPD_H

#include "sockunion.h"

/* Declare Some BGP specific types. */
typedef u_int16_t as_t;
typedef u_int16_t bgp_size_t;

/* BGP message header and packet size. */
#define BGP_MARKER_SIZE		16
#define BGP_HEADER_SIZE		19
#define BGP_MAX_PACKET_SIZE   4096

/* BGP filter direction. */
#define BGP_FILTER_IN  0
#define BGP_FILTER_OUT 1
#define BGP_FILTER_MAX 2

/* BGP filter structure. */
struct bgp_filter
{
  /* distribute-list */
  struct 
  {
    char *name;
    struct access_list *v4;
    struct access_list *v6;
  } dlist[BGP_FILTER_MAX];

  /* prefix-list */
  struct
  {
    char *name;
    struct prefix_list *v4;
    struct prefix_list *v6;
  } plist[BGP_FILTER_MAX];

  /* filter-list */
  struct
  {
    char *name;
    struct as_list *aslist;
  } aslist[BGP_FILTER_MAX];

  /* route-map */
  struct
  {
    char *name;
    struct route_map *map;
  } map[BGP_FILTER_MAX];
};

/* Route server enabled new bgp structure.  Full IPv4/IPv6
   unicast/multicast configuration are supported. */
struct bgp 
{
  /* AS number of this BGP instance. */
  as_t as;

  /* Name of this BGP instance. */
  char *name;

  /* BGP configuration. */
#define BGP_CONFIG_ROUTER_ID          0x01
#define BGP_CONFIG_CLUSTER_ID         0x02
#define BGP_CONFIG_CONFEDERATION      0x04
#define BGP_CONFIG_ALWAYS_COMPARE_MED 0x08
#define BGP_CONFIG_MISSING_AS_WORST   0x10
#define BGP_CONFIG_NO_DEFAULT_IPV4    0x20
  u_int16_t config;

  /* BGP identifier. */
  struct in_addr id;

  /* BGP route reflector cluster ID. */
  struct in_addr cluster;

  /* BGP route reflector neighbor count. */
  int reflector_cnt;

  /* BGP Confederation Information */
  as_t confederation_id;
  int confederation_peers_cnt;
  as_t *confederation_peers;

  /* BGP peer */
  struct newlist *peer_group;

  /* BGP peer-conf. */
  struct newlist *peer_conf;

  /* Static route configuration.  This configuration includes both
     unicast and multicast.  */
  struct route_table *route[AFI_MAX];

  /* Aggregate address configuration.  As same as static route
     configuration, both unicast and multicast configuration are
     included.  */
  struct route_table *aggregate[AFI_MAX];

  /* Routing information base. */
  struct route_table *rib[AFI_MAX][SAFI_MAX];

  /* BGP redistribute configuration. */
  u_char redist[AFI_MAX][ZEBRA_ROUTE_MAX];

  /* BGP redistribute route-map. */
  struct
  {
    char *name;
    struct route_map *map;
  } rmap[AFI_MAX][ZEBRA_ROUTE_MAX];
};

/* BGP peer-group support. */
struct peer_group
{
  /* Name of the peer-group. */
  char *name;
  
  /* Address family configuration. */
  int afi;
  int safi;

  /* AS configuration. */
  as_t as;

  /* Peer-group client list. */
  struct newlist *peer_conf;
};

/* BGP peer configuration. */
struct peer_conf
{
  /* Pointer to BGP structure. */
  struct bgp *bgp;

  /* Pointer to peer. */
  struct peer *peer;

  /* Pointer to peer-group. */
  struct peer_group *group;

  /* Address Family Configuration. */
  u_char afc[AFI_MAX][SAFI_MAX];

  /* Prefix count. */
  unsigned long pcount[AFI_MAX][SAFI_MAX];

  /* Max prefix count. */
  unsigned long pmax[AFI_MAX][SAFI_MAX];

  /* Filter structure. */
  struct bgp_filter filter;
};

/* Next hop self address. */
struct bgp_nexthop
{
  struct interface *ifp;
  struct in_addr v4;
#ifdef HAVE_IPV6
  struct in6_addr v6_global;
  struct in6_addr v6_local;
#endif /* HAVE_IPV6 */  
};

/* Store connection information. */
struct peer_connection
{
  /* Peer is on the connected link. */
  int shared;

  /* Socket's remote and local address. */
  union sockunion remote;
  union sockunion local;

  /* For next-hop-self detemination. */
  struct interface *ifp;
  struct in_addr v4;
#ifdef HAVE_IPV6
  struct in6_addr v6_global;
  struct in6_addr v6_local;
#endif /* HAVE_IPV6 */  
};

/* Update source configuration. */
struct peer_source
{
  unsigned int ifindex;
  char *ifname;
  char *update_if;
  union sockunion *update_source;
};

/* BGP Notify message format. */
struct bgp_notify 
{
  u_char code;
  u_char subcode;
  char *data;
  bgp_size_t length;
};

/* BGP neighbor structure. */
struct peer
{
  /* Peer's remote AS number. */
  as_t as;			

  /* Peer's local AS number. */
  as_t local_as;

  /* Remote router ID. */
  struct in_addr remote_id;

  /* Local router ID. */
  struct in_addr local_id;

  /* Packet receive and send buffer. */
  struct stream *ibuf;
  struct stream_fifo *obuf;

  /* Status of the peer. */
  int status;
  int ostatus;

  /* Peer information */
  int fd;			/* File descriptor */
  int ttl;			/* TTL of TCP connection to the peer. */
  char *desc;			/* Description of the peer. */
  unsigned short port;          /* Destination port for peer */
  char *host;			/* Printable address of the peer. */
  union sockunion su;		/* Sockunion address of the peer. */
  time_t uptime;		/* Last Up/Down time */
  safi_t translate_update;       
  
  unsigned int ifindex;		/* ifindex of the BGP connection. */
  char *ifname;			/* bind interface name. */
  char *update_if;
  union sockunion *update_source;
  struct zlog *log;
  u_char version;		/* Peer BGP version. */

  union sockunion *su_local;	/* Sockunion of local address.  */
  union sockunion *su_remote;	/* Sockunion of remote address.  */
  int shared_network;		/* Is this peer shared same network. */
  struct bgp_nexthop nexthop;	/* Nexthop */

  /* Peer address family configuration. */
  u_char afc[AFI_MAX][SAFI_MAX];
  u_char afc_nego[AFI_MAX][SAFI_MAX];

  /* Route refresh capability. */
  u_char refresh;

  /* User configuration flags. */
  u_int16_t flags;
#define PEER_FLAG_PASSIVE             0x0001 /* passive mode */
#define PEER_FLAG_SHUTDOWN            0x0002 /* shutdown */
#define PEER_FLAG_NEXTHOP_SELF        0x0004 /* next-hop-self */
#define PEER_FLAG_SOFT_RECONFIG       0x0008 /* soft-reconfiguration */
#define PEER_FLAG_SEND_COMMUNITY      0x0010 /* send-community */
#define PEER_FLAG_REFLECTOR_CLIENT    0x0020 /* reflector-client */
#define PEER_FLAG_RSERVER_CLIENT      0x0040 /* route-server-client */
#define PEER_FLAG_DEFAULT_ORIGINATE   0x0080 /* default-originate */
#define PEER_FLAG_DONT_CAPABILITY     0x0100 /* dont-capability */
#define PEER_FLAG_OVERRIDE_CAPABILITY 0x0200 /* override-capability */
#define PEER_FLAG_STRICT_CAP_MATCH    0x0400 /* strict-capability-match */
#define PEER_FLAG_ROUTE_REFRESH       0x0800 /* route-refresh */
#define PEER_FLAG_TRANSPARENT_AS      0x1000 /* transparent-as */
#define PEER_FLAG_TRANSPARENT_NEXTHOP 0x2000 /* transparent-next-hop */
#define PEER_FLAG_SEND_EXT_COMMUNITY  0x4000 /* send-community extended */

  /* Peer status flags. */
  u_int16_t sflags;
#define PEER_STATUS_ACCEPT_PEER	      0x0001 /* accept peer */
#define PEER_STATUS_PREFIX_OVERFLOW   0x0002 /* prefix-overflow */
#define PEER_STATUS_CAPABILITY_OPEN   0x0004 /* capability open send */

  /* Default attribute value for the peer. */
  u_int32_t config;
#define PEER_CONFIG_WEIGHT            0x0001 /* Default weight. */
#define PEER_CONFIG_HOLDTIME          0x0002 /* holdtime */
#define PEER_CONFIG_KEEPALIVE         0x0004 /* keepalive */
#define PEER_CONFIG_CONNECT           0x0008 /* connect */
  u_int32_t weight;
  u_int32_t holdtime;
  u_int32_t keepalive;
  u_int32_t connect;

  /* Timer values. */
  u_int32_t v_start;
  u_int32_t v_connect;
  u_int32_t v_holdtime;
  u_int32_t v_keepalive;
  u_int32_t v_asorig;
  u_int32_t v_routeadv;

  /* Threads. */
  struct thread *t_read;
  struct thread *t_write;
  struct thread *t_start;
  struct thread *t_connect;
  struct thread *t_holdtime;
  struct thread *t_keepalive;
  struct thread *t_asorig;
  struct thread *t_routeadv;

  /* Statistics field */
  u_int32_t open_in;		/* Open message input count */
  u_int32_t open_out;		/* Open message output count */
  u_int32_t update_in;		/* Update message input count */
  u_int32_t update_out;		/* Update message ouput count */
  u_int32_t keepalive_in;	/* Keepalive input count */
  u_int32_t keepalive_out;	/* Keepalive output count */
  u_int32_t notify_in;		/* Notify input count */
  u_int32_t notify_out;		/* Notify output count */

  /* Adj-RIBs-In.  */
  struct route_table *adj_in[AFI_MAX][SAFI_MAX];
  struct route_table *adj_out[AFI_MAX][SAFI_MAX];

  /* Linked peer configuration. */
  struct newlist *conf;

  /* Notify data. */
  struct bgp_notify notify;
};

/* This structure's member directly points incoming packet data
   stream. */
struct bgp_nlri
{
  afi_t afi;
  safi_t safi;
  u_char *nlri;
  bgp_size_t length;
};

/* BGP Versions. */
#define BGP_VERSION_2		  2    /* Obsoletes. */
#define BGP_VERSION_3		  3    /* Obsoletes. */
#define BGP_VERSION_4		  4    /* bgpd supports this version. */
#define BGP_VERSION_MP_4_DRAFT_00 40   /* bgpd supports this version. */
#define BGP_VERSION_MP_4	  41   /* bgpd supports this version. */

/* BGP messages. */
#define	BGP_MSG_OPEN		    1
#define	BGP_MSG_UPDATE		    2
#define	BGP_MSG_NOTIFY		    3
#define	BGP_MSG_KEEPALIVE	    4
#define BGP_MSG_ROUTE_REFRESH	  128

/* BGP message minimum size. */
#define BGP_MSG_OPEN_MIN_SIZE           (BGP_HEADER_SIZE + 10)
#define BGP_MSG_UPDATE_MIN_SIZE         (BGP_HEADER_SIZE + 4)
#define BGP_MSG_NOTIFY_MIN_SIZE         (BGP_HEADER_SIZE + 2)
#define BGP_MSG_KEEPALIVE_MIN_SIZE      (BGP_HEADER_SIZE + 0)
#define BGP_MSG_ROUTE_REFRESH_MIN_SIZE  (BGP_HEADER_SIZE + 4)

/* BGP open option message. */
#define BGP_OPEN_OPT_AUTH       1
#define BGP_OPEN_OPT_CAP        2

/* BGP4 Attribute Type Codes. */
#define BGP_ATTR_ORIGIN             1
#define BGP_ATTR_AS_PATH            2
#define BGP_ATTR_NEXT_HOP           3
#define BGP_ATTR_MULTI_EXIT_DISC    4
#define BGP_ATTR_LOCAL_PREF         5
#define BGP_ATTR_ATOMIC_AGGREGATE   6
#define BGP_ATTR_AGGREGATOR         7
#define BGP_ATTR_COMMUNITIES        8
#define BGP_ATTR_ORIGINATOR_ID      9
#define BGP_ATTR_CLUSTER_LIST      10
#define BGP_ATTR_DPA               11
#define BGP_ATTR_ADVERTISER        12
#define BGP_ATTR_RCID_PATH         13
#define BGP_ATTR_MP_REACH_NLRI     14
#define BGP_ATTR_MP_UNREACH_NLRI   15
#define BGP_ATTR_EXT_COMMUNITIES   16

/* BGP Update ORIGIN */
#define BGP_ORIGIN_IGP              0
#define BGP_ORIGIN_EGP              1
#define BGP_ORIGIN_INCOMPLETE       2

/* BGP Notify message format */
#define BGP_NOTIFY_HEADER_ERR         1
#define BGP_NOTIFY_OPEN_ERR           2
#define BGP_NOTIFY_UPDATE_ERR         3
#define BGP_NOTIFY_HOLD_ERR           4
#define BGP_NOTIFY_FSM_ERR            5
#define BGP_NOTIFY_CEASE              6
#define BGP_NOTIFY_MAX	              7

/* BGP_NOTIFY_HEADER_ERR sub code */
#define BGP_NOTIFY_HEADER_NOT_SYNC    1
#define BGP_NOTIFY_HEADER_BAD_MESLEN  2
#define BGP_NOTIFY_HEADER_BAD_MESTYPE 3
#define BGP_NOTIFY_HEADER_MAX         4

/* BGP_NOTIFY_OPEN_ERR sub code */
#define BGP_NOTIFY_OPEN_UNSUP_VERSION   1
#define BGP_NOTIFY_OPEN_BAD_PEER_AS     2
#define BGP_NOTIFY_OPEN_BAD_BGP_IDENT   3
#define BGP_NOTIFY_OPEN_UNSUP_PARAM     4
#define BGP_NOTIFY_OPEN_AUTH_FAILURE    5
#define BGP_NOTIFY_OPEN_UNACEP_HOLDTIME 6
#define BGP_NOTIFY_OPEN_UNSUP_CAPBL     7
#define BGP_NOTIFY_OPEN_MAX             8

/* BGP_NOTIFY_UPDATE_ERR sub code */
#define BGP_NOTIFY_UPDATE_MAL_ATTR       1
#define BGP_NOTIFY_UPDATE_UNREC_ATTR     2
#define BGP_NOTIFY_UPDATE_MISS_ATTR      3
#define BGP_NOTIFY_UPDATE_ATTR_FLAG_ERR  4
#define BGP_NOTIFY_UPDATE_ATTR_LENG_ERR  5
#define BGP_NOTIFY_UPDATE_INVAL_ORIGIN   6
#define BGP_NOTIFY_UPDATE_AS_ROUTE_LOOP  7
#define BGP_NOTIFY_UPDATE_INVAL_NEXT_HOP 8
#define BGP_NOTIFY_UPDATE_OPT_ATTR_ERR   9
#define BGP_NOTIFY_UPDATE_INVAL_NETWORK 10
#define BGP_NOTIFY_UPDATE_MAL_AS_PATH   11
#define BGP_NOTIFY_UPDATE_MAX           12

/* Finite State Machine Status */
#define Idle                          1
#define Connect                       2
#define Active                        3
#define OpenSent                      4
#define OpenConfirm                   5
#define Established                   6
#define BGP_STATUS_MAX                7

/* Finite State Machine Event */
#define BGP_Start                     1
#define BGP_Stop                      2
#define TCP_connection_open           3
#define TCP_connection_closed         4
#define TCP_connection_open_failed    5
#define TCP_fatal_error               6
#define ConnectRetry_timer_expired    7
#define Hold_Timer_expired            8
#define KeepAlive_timer_expired       9
#define Receive_OPEN_message         10
#define Receive_KEEPALIVE_message    11
#define Receive_UPDATE_message       12
#define Receive_NOTIFICATION_message 13
#define BGP_EVENTS_MAX               14

/* Default port values. */
#define BGP_PORT_DEFAULT   179
#define BGP_VTY_PORT      2605
#define BGP_VTYSH_PATH    "/tmp/bgpd"

/* Default configuration file name for bgpd. */
#define BGP_DEFAULT_CONFIG "bgpd.conf"

/* Time in second to start bgp connection. */
#define BGP_INIT_START_TIMER        5
#define BGP_ERROR_START_TIMER      30
#define BGP_DEFAULT_HOLDTIME      180
#define BGP_DEFAULT_KEEPALIVE      30
#define BGP_CLEAR_CONNECT_RETRY    20
#define BGP_DEFAULT_CONNECT_RETRY 120

/* SAFI which used in open capability negotiation. */
#define BGP_SAFI_VPNV4            128

/* Macros. */
#define BGP_INPUT(P)         ((P)->ibuf)
#define BGP_INPUT_PNT(P)     (STREAM_PNT(BGP_INPUT(P)))

/* Count prefix size from mask length */
#define PSIZE(a) (((a) + 7) / (8))

/* Flag manipulation macros. */
#define CHECK_FLAG(V,F)      ((V) & (F))
#define SET_FLAG(V,F)        (V) = (V) | (F)
#define UNSET_FLAG(V,F)      (V) = (V) & ~(F)

/* IBGP/EBGP identifier */
/* We also have a CONFED peer, which is to say, a peer who's
   AS is part of our Confederation */
enum
{
  BGP_PEER_IBGP,
  BGP_PEER_EBGP,
  BGP_PEER_INTERNAL,
  BGP_PEER_CONFED
};

/* IPv4 only machine should not accept IPv6 address for peer's IP
   address.  So we replace VTY command string like below. */
#ifdef HAVE_IPV6
#define NEIGHBOR_CMD       "neighbor (A.B.C.D|X:X::X:X) "
#define NO_NEIGHBOR_CMD    "no neighbor (A.B.C.D|X:X::X:X) "
#define NEIGHBOR_ADDR_STR  "IP address\nIPv6 address\n"
#else
#define NEIGHBOR_CMD       "neighbor A.B.C.D "
#define NO_NEIGHBOR_CMD    "no neighbor A.B.C.D "
#define NEIGHBOR_ADDR_STR  "IP address\n"
#endif /* HAVE_IPV6 */

/* Description of the command. */
#define ROUTER_STR  "Enable a routing process\n"
#define AS_STR      "AS number\n"
#define MBGP_STR    "MBGP information\n"

/* Default max TTL. */
#define TTL_MAX 255

/* Prototypes. */
void bgp_init ();
void zebra_init ();
void bgp_terminate (void);
void bgp_reset (void);
void bgp_route_map_init ();
int peer_sort (struct peer *peer);
void bgp_filter_init ();
void bgp_zclient_start ();
void bgp_zclient_reset ();
void bgp_snmp_init ();

struct bgp *bgp_new (as_t);
struct bgp *bgp_lookup_by_as (as_t);
int bgp_collision_detect (struct peer *);

struct peer *peer_lookup_by_su (union sockunion *);
struct peer *peer_lookup_from_bgp (struct bgp *bgp, char *addr);
struct peer *peer_lookup_by_host (char *host);
struct peer *peer_new (void);
void event_add (struct peer *peer, int event);
void bgp_clear(struct peer *peer, int error);
void peer_delete_all ();
void peer_delete (struct peer *peer);
void bgp_open_recv (struct peer *peer, u_int16_t size);
void bgp_notify_print (struct peer *, struct bgp_notify *, char *);

int bgp_nexthop_set (union sockunion *, union sockunion *, 
		     struct bgp_nexthop *, struct peer *);
int bgp_confederation_peers_check(struct bgp *, as_t);
struct bgp *bgp_get_default ();
struct bgp *bgp_lookup_by_name (char *);
struct peer *peer_lookup_with_open (union sockunion *, as_t, struct in_addr *);
struct peer *peer_create_accept ();

int peer_active (struct peer *);

extern struct message bgp_status_msg[];
extern int bgp_status_msg_max;

extern char *progname;

extern struct thread_master *master;

/* All BGP instance. */
extern struct newlist *bgp_list;

/* All peer instance.  This linked list is rarely used.  Usually
   bgp_list is used to walk down peer's list.  */
extern struct newlist *peer_list;

#endif /* _ZEBRA_BGPD_H */
