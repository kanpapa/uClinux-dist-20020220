/*
 * OSPFd main header.
 * Copyright (C) 1998, 99, 2000 Kunihiro Ishiguro, Toshiaki Takada
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

#ifndef _ZEBRA_OSPFD_H
#define _ZEBRA_OSPFD_H

#include "filter.h"

#define OSPF_VERSION            2

/* Default protocol, port number. */
#ifndef IPPROTO_OSPFIGP
#define IPPROTO_OSPFIGP         89
#endif /* IPPROTO_OSPFIGP */

/* VTY port number. */
#define OSPF_VTY_PORT          2604
#define OSPF_VTYSH_PATH        "/tmp/ospfd"

/* IP TTL for OSPF protocol. */
#define OSPF_IP_TTL             1
#define OSPF_VL_IP_TTL          100

/* Default configuration file name for ospfd. */
#define OSPF_DEFAULT_CONFIG   "ospfd.conf"

#if 0
enum
{
  /* Debug option. */
  DEBUG_OSPF_ISM = 0x01,
  DEBUG_OSPF_NSM = 0x02,
};
#endif

/* Architectual Constants */
#ifdef DEBUG
#define OSPF_LS_REFRESH_TIME                   300
#else
#define OSPF_LS_REFRESH_TIME                  1800
#endif
#define OSPF_MIN_LS_INTERVAL                     5
#define OSPF_MIN_LS_ARRIVAL                      1
#define OSPF_LSA_MAX_AGE                      3600
#define OSPF_CHECK_AGE                         300
#define OSPF_LSA_MAX_AGE_DIFF                  900
#define OSPF_LS_INFINITY                  0xffffff
#define OSPF_DEFAULT_DESTINATION        0x00000000      /* 0.0.0.0 */
#define OSPF_INITIAL_SEQUENCE_NUMBER    0x80000001
#define OSPF_MAX_SEQUENCE_NUMBER        0x7fffffff

#define OSPF_LSA_MAX_AGE_CHECK_INTERVAL         30

#define OSPF_ALLSPFROUTERS              0xe0000005      /* 224.0.0.5 */
#define OSPF_ALLDROUTERS                0xe0000006      /* 224.0.0.6 */

#define OSPF_AREA_BACKBONE              0x00000000      /* 0.0.0.0 */

/* OSPF Authentication Type. */
#define OSPF_AUTH_NULL                      0
#define OSPF_AUTH_SIMPLE                    1
#define OSPF_AUTH_CRYPTOGRAPHIC             2

/* OSPF SPF timer values. */
#define OSPF_SPF_DELAY_DEFAULT              5
#define OSPF_SPF_HOLDTIME_DEFAULT          30

/* OSPF interface default values. */
#define OSPF_OUTPUT_COST_DEFAULT           10
#define OSPF_ROUTER_DEAD_INTERVAL_DEFAULT  40
#define OSPF_HELLO_INTERVAL_DEFAULT        10
#define OSPF_ROUTER_PRIORITY_DEFAULT        1
#define OSPF_RETRANSMIT_INTERVAL_DEFAULT    5
#define OSPF_TRANSMIT_DELAY_DEFAULT         1

/* Area External Routing Capability. */

/* OSPF options. */
#define OSPF_OPTION_T                    0x01  /* TOS. */
#define OSPF_OPTION_E                    0x02
#define OSPF_OPTION_MC                   0x04
#define OSPF_OPTION_NP                   0x08
#define OSPF_OPTION_EA                   0x10
#define OSPF_OPTION_DC                   0x20

/* OSPF Database Description flags. */
#define OSPF_DD_FLAG_MS                  0x01
#define OSPF_DD_FLAG_M                   0x02
#define OSPF_DD_FLAG_I                   0x04
#define OSPF_DD_FLAG_ALL                 0x07

/* Timer value. */
#define OSPF_ROUTER_ID_UPDATE_DELAY             1

/* OSPF instance structure. */
struct ospf
{
  /* OSPF Router ID. */
  struct in_addr router_id;		/* Configured automatically. */
  struct in_addr router_id_static;	/* Configured manually. */

  /* ABR/ASBR internal flags. */
  u_char flags;
#define OSPF_FLAG_ABR           0x0001
#define OSPF_FLAG_ASBR          0x0002

  /* ABR type. */
  u_char abr_type;
#define OSPF_ABR_UNKNOWN	0
#define OSPF_ABR_STAND          1
#define OSPF_ABR_IBM            2
#define OSPF_ABR_CISCO          3
#define OSPF_ABR_SHORTCUT       4

  /* Configured variables. */
  u_char RFC1583Compat;			/* RFC1583Compatibility flag. */
#define RFC1583_COMPATIBLE_NO		0
#define RFC1583_COMPATIBLE_YES		1
  int spf_delay;			/* SPF delay time. */
  int spf_holdtime;			/* SPF hold time. */
  int default_information;		/* Default information originate. */
#define DEFAULT_ORIGINATE_NONE		0
#define DEFAULT_ORIGINATE_ZEBRA		1
#define DEFAULT_ORIGINATE_ALWAYS	2
  struct route_table *networks;         /* OSPF config networks. */
  list vlinks;                          /* Configured Virtual-Links. */
  list areas;                           /* OSPF areas. */
  struct ospf_area *backbone;           /* Pointer to the Backbone Area. */

  list iflist;                          /* Zebra derived interfaces. */

  /* LSDB of AS-external-LSAs. */
  struct new_lsdb *external_lsa;

  /* Redistributed external information. */
  struct route_table *external_info[ZEBRA_ROUTE_MAX];
#define EXTERNAL_INFO(T)      ospf_top->external_info[T]

  /* Flags. */
  int external_origin;			/* AS-external-LSA origin flag. */
  int ase_calc;				/* ASE calculation flag. */

  /* Routing tables. */
  struct route_table *old_table;        /* Old routing table. */
  struct route_table *new_table;        /* Current routing table. */

  struct route_table *old_rtrs;         /* Old ABR/ASBR RT. */
  struct route_table *new_rtrs;         /* New ABR/ASBR RT. */

  struct route_table *external_route;   /* External Route. */
  struct route_table *rtrs_external;	/* Table for Looking up AS-external-LSA
					   related to an ASBR route. */

  /* Time stamps. */
  time_t ts_spf;			/* SPF calculation time stamp. */

  list maxage_lsa;                      /* List of MaxAge LSA for deletion. */
  int redistribute;                     /* Num of redistributed protocols. */

  /* Threads. */
  struct thread *t_router_id_update;	/* Router ID update timer. */
  struct thread *t_rlsa_update;         /* router-LSA update timer. */
  struct thread *t_abr_task;            /* ABR task timer. */
  struct thread *t_asbr_check;          /* ASBR check timer. */
  struct thread *t_distribute_update;   /* Distirbute list update timer. */
  struct thread *t_spf_calc;	        /* SPF calculation timer. */
  struct thread *t_ase_calc;		/* ASE calculation timer. */
  struct thread *t_external_origin;	/* AS-external-LSA origin timer. */
  struct thread *t_maxage;              /* MaxAge LSA remover timer. */
  struct thread *t_maxage_walker;       /* MaxAge LSA checking timer. */

  /* Distribute lists out of other route sources. */
  struct 
  {
    char *name;
    struct access_list *list;
  } dlist[ZEBRA_ROUTE_MAX];
#define DISTRIBUTE_NAME(T)    ospf_top->dlist[T].name
#define DISTRIBUTE_LIST(T)    ospf_top->dlist[T].list

  /* Redistribute metric info. */
  struct 
  {
    u_char type;                /* External metric type (E1 or E2).  */
    u_char method;              /* How external metric is specified. */
#define OSPF_EXT_METRIC_AUTO    0
#define OSPF_EXT_METRIC_STATIC  1
    u_int32_t value;            /* Value for static metric (24-bit). */
  } dmetric [ZEBRA_ROUTE_MAX];

  /* Refresh queue. */
  list            refresh_queue;          /* LSA Refreshment Queue. */
  struct thread * t_lsa_refresher;        /* Refreshment Queue Server. */
  int             refresh_queue_interval; /* How often the is served. */
  int             refresh_queue_limit;    /* How many LSAs per interval. */
  int             refresh_queue_count;    /* How many updated. */

  list            refresh_group;        /* LSA Refresh Group. */
  struct thread * t_refresh_group;      /* Refresh Group Checker. */
  u_int16_t       group_age;            /* Min AGE in the LSA Group. */
};

/* OSPF refresher related variables. */
#define OSPF_REFRESH_QUEUE_INTERVAL 1
#define OSPF_REFRESH_QUEUE_RATE     70
#define OSPF_REFRESH_PER_SLICE      5

#ifdef DEBUG
#define OSPF_LS_REFRESH_SHIFT       30
#else
#define OSPF_LS_REFRESH_SHIFT       (60 * 15)
#endif
#define OSPF_LS_REFRESH_JITTER      10

#define OSPF_REFRESH_GROUP_TIME    1
#define OSPF_REFRESH_GROUP_AGE_DIF 3    /* We don't care if age is +-1 sec. */
#define OSPF_REFRESH_GROUP_LIMIT   10   

/* OSPF area structure. */
struct ospf_area
{
  /* OSPF instance. */
  struct ospf *top;

  /* Reference count by ospf_network. */
  int count;

  /* Zebra interface list belonging to the area. */
  list iflist;

  /* Area ID. */
  struct in_addr area_id;

  /* Area ID format. */
  char format;
#define OSPF_AREA_ID_FORMAT_ADDRESS         1
#define OSPF_AREA_ID_FORMAT_DECIMAL         2

  /* Address range. */
  list address_range;

  /* Configured variables. */
  int external_routing;                 /* ExternalRoutingCapability. */
#define OSPF_AREA_DEFAULT       0
#define OSPF_AREA_STUB          1
#define OSPF_AREA_NSSA          2
#define OSPF_AREA_TYPE_MAX	3
  int no_summary;                       /* Don't inject summaries into stub.*/
  int shortcut_configured;              /* Area configured as shortcut. */
#define OSPF_SHORTCUT_DEFAULT	0
#define OSPF_SHORTCUT_ENABLE	1
#define OSPF_SHORTCUT_DISABLE	2
  int shortcut_capability;              /* Other ABRs agree on S-bit */
  u_int32_t default_cost;               /* StubDefaultCost. */
  int auth_type;                        /* Authentication type. */

  u_char transit;			/* TransitCapability. */
#define OSPF_TRANSIT_FALSE      0
#define OSPF_TRANSIT_TRUE       1
  struct route_table *ranges;		/* Configured Area Ranges. */

  /* Area related LSDBs[Type1-4]. */
  /* struct ospf_lsdb *lsa[4]; */	/* To be obsoleted. */ 
  struct new_lsdb *lsdb;		/* New structure. */

  /* Self-originated LSAs. */
  struct ospf_lsa *router_lsa_self;

  /* Area announce list. */
  struct 
  {
    char *name;
    struct access_list *list;
  } export;
#define EXPORT_NAME(A)  (A)->export.name
#define EXPORT_LIST(A)  (A)->export.list

  /* Area acceptance list. */
  struct 
  {
    char *name;
    struct access_list *list;
  } import;
#define IMPORT_NAME(A)  (A)->import.name
#define IMPORT_LIST(A)  (A)->import.list

  /* Shortest Path Tree. */
  struct vertex *spf;

  /* Threads. */
  struct thread *t_router_lsa_self;	/* Self-originated router-LSA timer. */

  /* Statistics field. */
  u_int32_t spf_calculation;		/* SPF Calculation Count. */

  /* Counters. */
  u_int  act_ints;                      /* Active interfaces. */
  u_int  full_nbrs;                     /* Fully adjacent neighbors. */
  u_int  full_vls;                      /* Fully adjacent virtual neighbors. */
};

#if 0
#define ROUTER_LSA(a)                   (a)->lsa[0]
#define NETWORK_LSA(a)                  (a)->lsa[1]
#define SUMMARY_LSA(a)                  (a)->lsa[2]
#define SUMMARY_LSA_ASBR(a)             (a)->lsa[3]
#endif

/* OSPF config network structure. */
struct ospf_network
{
  /* Area ID. */
  struct in_addr area_id;

  /* Interface associated with network. */
  struct interface *ifp;
};

/* Macro. */
#define OSPF_AREA_SAME(X,Y) \
        (memcmp ((X->area_id), (Y->area_id), IPV4_MAX_BYTELEN) == 0)

#define OSPF_IS_ABR		(ospf_top->flags & OSPF_FLAG_ABR)
#define OSPF_IS_ASBR		(ospf_top->flags & OSPF_FLAG_ASBR)

#define OSPF_IS_AREA_BACKBONE(A) \
	((A)->area_id.s_addr == OSPF_AREA_BACKBONE)

#define CHECK_FLAG(V,F)        ((V) & (F))
#define SET_FLAG(V,F)          (V) = (V) | (F)
#define UNSET_FLAG(V,F)        (V) = (V) & ~(F)

#define LIST_ITERATOR(L, N) \
      for ((N) = listhead ((L)); (N); nextnode(N))

#define RT_ITERATOR(R, N) \
      for ((N) = route_top ((R)); (N); (N) = route_next ((N)))

#define OSPF_AREA_TIMER_ON(T,F,V) \
      if (!(T)) \
        (T) = thread_add_timer (master, (F), area, (V))

#define OSPF_TIMER_OFF(X) \
      do { \
       if (X) \
         { \
           thread_cancel (X); \
           (X) = NULL; \
         } \
      } while (0)

#define OSPF_SCHEDULE_MAXAGE(T, F) \
      if (!(T)) \
        (T) = thread_add_timer (master, (F), 0, 2)

/* Messages */
extern struct message ospf_ism_status_msg[];
extern struct message ospf_nsm_status_msg[];
extern struct message ospf_lsa_type_msg[];
extern struct message ospf_link_state_id_type_msg[];
extern struct message ospf_redistributed_proto[];
extern struct message ospf_network_type_msg[];
extern int ospf_ism_status_msg_max;
extern int ospf_nsm_status_msg_max;
extern int ospf_lsa_type_msg_max;
extern int ospf_link_state_id_type_msg_max;
extern int ospf_redistributed_proto_max;
extern int ospf_network_type_msg_max;

extern char *progname;

/* Prototypes. */
void ospf_init (void);
void ospf_if_update (void);
void ospf_terminate (void);
void ospf_route_init (void);
void ospf_init_end (void);

extern struct thread_master *master;
extern struct ospf *ospf_top;

struct ospf_area *ospf_area_new (struct in_addr);
struct ospf_area *ospf_area_lookup_by_area_id (struct in_addr);
void ospf_interface_down (struct ospf *, struct prefix *, struct ospf_area *);

extern int ospf_zlog;

#endif /* _ZEBRA_OSPFD_H */
