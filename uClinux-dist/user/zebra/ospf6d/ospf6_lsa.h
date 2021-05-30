/*
 * LSA function
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

#ifndef OSPF6_LSA_H
#define OSPF6_LSA_H

#define THIS_IS_REFRESH  ((struct thread *)0xffffffff)

/* LSA definition */

/* Type */
#define LST_ROUTER_LSA                  0x2001
#define OSPF6_LSA_TYPE_ROUTER           0x2001

#define LST_NETWORK_LSA                 0x2002
#define OSPF6_LSA_TYPE_NETWORK          0x2002

#define LST_INTER_AREA_PREFIX_LSA       0x2003
#define OSPF6_LSA_TYPE_INTER_PREFIX     0x2003

#define LST_INTER_AREA_ROUTER_LSA       0x2004
#define OSPF6_LSA_TYPE_INTER_ROUTER     0x2004

#define LST_AS_EXTERNAL_LSA             0x4005
#define OSPF6_LSA_TYPE_AS_EXTERNAL      0x4005

#define LST_GROUP_MEMBERSHIP_LSA        0x2006
#define OSPF6_LSA_TYPE_GROUP_MEMBERSHIP 0x2006

#define LST_TYPE_7_LSA                  0x2007
#define OSPF6_LSA_TYPE_TYPE_7           0x2007

#define LST_LINK_LSA                    0x0008
#define OSPF6_LSA_TYPE_LINK             0x0008

#define LST_INTRA_AREA_PREFIX_LSA       0x2009
#define OSPF6_LSA_TYPE_INTRA_PREFIX     0x2009

/* lsa scope */
#define SCOPE_MASK       0x6000
#define SCOPE_LINKLOCAL  0x0000
#define SCOPE_AREA       0x2000
#define SCOPE_AS         0x4000
#define SCOPE_RESERVED   0x6000
#define GET_LSASCOPE(x) ((ntohs(x)) & SCOPE_MASK)

/* NOTE that all lsa is left NETWORK BYTE ORDER */

struct router_lsa
{
  u_char rlsa_bits;
  u_char rlsa_options[3];
  /* followed by router_lsd(s) */
};
#define ROUTER_LSA_BIT_B     (1 << 0)
#define ROUTER_LSA_BIT_E     (1 << 1)
#define ROUTER_LSA_BIT_V     (1 << 2)
#define ROUTER_LSA_BIT_W     (1 << 3)

#define ROUTER_LSA_SET(x,y)    ((x)->rlsa_bits |=  (y))
#define ROUTER_LSA_ISSET(x,y)  ((x)->rlsa_bits &   (y))
#define ROUTER_LSA_CLEAR(x,y)  ((x)->rlsa_bits &= ~(y))

struct router_lsd
{
  u_char    rlsd_type;
  u_char    rlsd_reserved;
  u_int16_t rlsd_metric;                /* output cost */
  u_int32_t rlsd_interface_id;
  u_int32_t rlsd_neighbor_interface_id;
  u_int32_t rlsd_neighbor_router_id;
};

#define LSDT_POINTTOPOINT       1
#define LSDT_TRANSIT_NETWORK    2
#define LSDT_STUB_NETWORK       3
#define LSDT_VIRTUAL_LINK       4

struct network_lsa
{
  u_char nlsa_reserved;
  u_char nlsa_options[3];
  /* followed by router_id(s) */
};

struct link_lsa
{
  u_char          llsa_rtr_pri;
  u_char          llsa_options[3];
  struct in6_addr llsa_linklocal;
  u_int32_t       llsa_prefix_num;
  /* followed by prefix(es) */
};
struct ospf6_link_lsa
{
  u_char          llsa_rtr_pri;
  u_char          llsa_options[3];
  struct in6_addr llsa_linklocal;
  u_int32_t       llsa_prefix_num;
  /* followed by prefix(es) */
};

struct intra_area_prefix_lsa
{
  u_int16_t intra_prefix_num;
  u_int16_t intra_prefix_refer_lstype;
  u_int32_t intra_prefix_refer_lsid;
  u_int32_t intra_prefix_refer_advrtr;
};

struct as_external_lsa
{
  u_char    ase_bits;
  u_char    ase_pre_metric; /* 1st byte of metric */
  u_int16_t ase_metric;     /* 2nd, 3rd byte of metric */
  u_char    ase_prefix_len;
  u_char    ase_prefix_opt;
  u_int16_t ase_refer_lstype;
  /* followed by one address prefix */
  /* followed by none or one forwarding address */
  /* followed by none or one external route tag */
  /* followed by none or one referenced LS-ID */
};
#define ASE_LSA_BIT_T     (1 << 0)
#define ASE_LSA_BIT_F     (1 << 1)
#define ASE_LSA_BIT_E     (1 << 2)

#define ASE_LSA_SET(x,y)    ((x)->ase_bits |=  (y))
#define ASE_LSA_ISSET(x,y)  ((x)->ase_bits &   (y))
#define ASE_LSA_CLEAR(x,y)  ((x)->ase_bits &= ~(y))

/* new */
struct ospf6_lsa_hdr
{
  u_int16_t lsh_age;      /* LS age */
  u_int16_t lsh_type;     /* LS type */
  u_int32_t lsh_id;       /* Link State ID */
  u_int32_t lsh_advrtr;   /* Advertising Router */
  u_int32_t lsh_seqnum;   /* LS sequence number */
  u_int16_t lsh_cksum;    /* LS checksum */
  u_int16_t lsh_len;      /* length */
};

#define LSH_NEXT(x) ((x) + 1)
#define LSA_NEXT(x) ((struct ospf6_lsa_hdr *) \
                       ((char *)(x) + ntohs ((x)->lsh_len)))
#define lsa_issame(x,y) ((x)->lsh_type == (y)->lsh_type && \
                         (x)->lsh_id == (y)->lsh_id && \
                         (x)->lsh_advrtr == (y)->lsh_advrtr)

struct ospf6_lsa
{
  char                   str[256];  /* dump string */

  unsigned long          lock;      /* reference counter */
  int                    summary;   /* indicate this is LS header only */
  struct ospf6_lsa_hdr  *lsa_hdr;
  void                  *scope;     /* pointer of scoped data structure */
  unsigned char          flags;     /* use this to decide ack type */
  unsigned long          birth;     /* tv_sec when LS age 0 */
  unsigned long          installed; /* tv_sec when installed */
  struct thread         *expire;
  struct thread         *refresh;   /* For self-originated LSA */
  struct neighbor       *from;      /* from which neighbor */
  list                  summary_nbr;
  list                  request_nbr;
  list                  retrans_nbr;
  list                  delayed_ack_if;
};
#define OSPF6_LSA_FLOODBACK   (1 << 0)
#define OSPF6_LSA_DUPLICATE   (1 << 1)
#define OSPF6_LSA_IMPLIEDACK  (1 << 2)


/* Back pointer check, Is X's reference field bound to Y? */
#define x_ipl(x) ((struct intra_area_prefix_lsa *)LSH_NEXT((x)->lsa_hdr))
#define is_reference_network_ok(x,y) \
          ((x_ipl(x))->intra_prefix_refer_lstype == (y)->lsa_hdr->lsh_type &&\
           (x_ipl(x))->intra_prefix_refer_lsid == (y)->lsa_hdr->lsh_id &&\
           (x_ipl(x))->intra_prefix_refer_advrtr == (y)->lsa_hdr->lsh_advrtr)
  /* referencing router's ifid must be 0,
     see draft-ietf-ospf-ospfv6-06.txt */
#define is_reference_router_ok(x,y) \
          ((x_ipl(x))->intra_prefix_refer_lstype == (y)->lsa_hdr->lsh_type &&\
           (x_ipl(x))->intra_prefix_refer_lsid == htonl (0) &&\
           (x_ipl(x))->intra_prefix_refer_advrtr == (y)->lsa_hdr->lsh_advrtr)

/* Function Prototypes */
void originating_lsa (struct ospf6_lsa *);
int show_router_lsa (struct vty *, void *);
int show_network_lsa (struct vty *, void *);
int show_link_lsa (struct vty *, void *);
int show_intra_prefix_lsa (struct vty *, void *);
int vty_lsa (struct vty *, struct ospf6_lsa *);

struct router_lsd *
get_router_lsd (rtr_id_t, struct ospf6_lsa *);
unsigned long get_ifindex_to_router (rtr_id_t, struct ospf6_lsa *);
void get_referencing_lsa (list, struct ospf6_lsa *);
int is_self_originated (struct ospf6_lsa *);
struct ospf6_lsa *reconstruct_lsa (struct ospf6_lsa *);

int ospf6_lsa_check_recent (struct ospf6_lsa *, struct ospf6_lsa *);
void ospf6_lsa_lock (struct ospf6_lsa *);
void ospf6_lsa_unlock (struct ospf6_lsa *);
void ospf6_maxage_remove (struct ospf6_lsa *);
int ospf6_lsa_expire (struct thread *);
int ospf6_lsa_refresh (struct thread *);
unsigned short ospf6_age_current (struct ospf6_lsa *);
void ospf6_age_update_to_send (struct ospf6_lsa *, struct ospf6_interface *);
void ospf6_premature_aging (struct ospf6_lsa *);
struct ospf6_lsa_hdr *make_ospf6_lsa_data (struct ospf6_lsa_hdr *, int);
struct ospf6_lsa *make_ospf6_lsa (struct ospf6_lsa_hdr *);
struct ospf6_lsa *make_ospf6_lsa_summary (struct ospf6_lsa_hdr *);
unsigned short ospf6_lsa_get_scope_type (unsigned short);
void ospf6_lsa_clear_flag (struct ospf6_lsa *);
void ospf6_lsa_set_flag (struct ospf6_lsa *, unsigned char);
int ospf6_lsa_test_flag (struct ospf6_lsa *, unsigned char);
int ospf6_lsa_issame (struct ospf6_lsa_hdr *, struct ospf6_lsa_hdr *);

struct ospf6_lsa *ospf6_make_router_lsa (struct area *);
struct ospf6_lsa *ospf6_make_network_lsa (struct ospf6_interface *);
struct ospf6_lsa *ospf6_make_link_lsa (struct ospf6_interface *);
struct ospf6_lsa *ospf6_make_intra_prefix_lsa (struct ospf6_interface *);

struct ospf6_lsa *
ospf6_lsa_create_as_external (struct ospf6_redistribute_info *,
                              struct prefix_ipv6 *);

void ospf6_lsa_originate_link (struct ospf6_interface *);
void ospf6_lsa_originate_intraprefix (struct ospf6_interface *);

unsigned long ospf6_as_external_lsid (struct prefix_ipv6 *, struct ospf6 *);
struct ospf6_lsa *ospf6_make_as_external_lsa (struct route_node *);

void ospf6_lsa_maxage_remove (struct ospf6_lsa *);

void ospf6_lsa_hdr_id_str (struct ospf6_lsa_hdr *, char *, size_t);
void ospf6_lsa_hdr_str (struct ospf6_lsa_hdr *, char *, size_t);
void ospf6_lsa_str (struct ospf6_lsa *, char *, size_t);

unsigned short ospf6_lsa_checksum (struct ospf6_lsa_hdr *);

int
ospf6_lsa_is_known (struct ospf6_lsa_hdr *);

/*xxx*/
void ospf6_lsa_update_link (struct ospf6_interface *);

#endif /* OSPF6_LSA_H */

