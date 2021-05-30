/*
 * OSPF Interface functions.
 * Copyright (C) 1999 Toshiaki Takada
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

#ifndef _ZEBRA_OSPF_INTERFACE_H
#define _ZEBRA_OSPF_INTERFACE_H

#define OSPF_AUTH_SIMPLE_SIZE           8
#define OSPF_AUTH_MD5_SIZE             16

struct ospf_interface;

struct ospf_vl_data
{
  struct in_addr    vl_peer;	   /* Router-ID of the peer for VLs. */
  struct ospf_area *vl_area;	   /* Transit area for this VL. */	
  struct ospf_interface *vl_oi;	   /* Interface data structure for the VL. */
  struct ospf_interface *out_oi;   /* The interface to go out. */
  struct in_addr    peer_addr;	   /* Address used to reach the peer. */
  u_char flags;
};


#define OSPF_VL_MAX_COUNT 256
#define OSPF_VL_MTU	  1500

#define OSPF_VL_FLAG_APPROVED 0x01

struct crypt_key
{
  u_char key_id;
  u_char auth_key[OSPF_AUTH_MD5_SIZE + 1];
};

/* OSPF interface structure */
struct ospf_interface
{
  /* This interface's parent ospf instance. */
  struct ospf *ospf;

  /* Packet receive and send buffer. */
  struct stream *ibuf;			/* Input buffer */
  struct ospf_fifo *obuf;		/* Output queue */

  /* Interface data from zebra. */
  struct interface *ifp;

  /* Interface related socket fd. */
  int fd;				/* Input socket fd */

  /* OSPF Specific interface data. */
  u_char flag;			        /* OSPF is enabled on this */
#define OSPF_IF_DISABLE                 0
#define OSPF_IF_ENABLE                  1
  u_char type;				/* OSPF Network Type */
#define OSPF_IFTYPE_NONE		0
#define OSPF_IFTYPE_POINTOPOINT		1
#define OSPF_IFTYPE_BROADCAST		2
#define OSPF_IFTYPE_NBMA		3
#define OSPF_IFTYPE_POINTOMULTIPOINT	4
#define OSPF_IFTYPE_VIRTUALLINK		5
#define OSPF_IFTYPE_MAX			6
  int status;				/* OSPF Interface State */

  struct prefix *address;		/* Interface prefix */
  struct ospf_vl_data *vl_data;		/* Data for Virtual Link */
  struct ospf_area *area;		/* OSPF Area */

  /* Configured varables. */
  u_int32_t transmit_delay;		/* Interface Transmisson Delay */
  u_int32_t output_cost;		/* Interface Output Cost */
  u_int32_t retransmit_interval;	/* Retransmission Interval */
  u_char passive_interface;             /* OSPF Interface is passive */
#define OSPF_IF_ACTIVE                  0
#define OSPF_IF_PASSIVE		        1

  /* Authentication data. */
  u_char auth_simple[OSPF_AUTH_SIMPLE_SIZE + 1];       /* Simple password. */
  list auth_crypt;			/* List of Auth cryptographic data. */
  u_int32_t crypt_seqnum;		/* Cryptographic Sequence Number */ 

  /* Neighbor information. */
  struct route_table *nbrs;             /* OSPF Neighbor List */
  struct ospf_neighbor *nbr_self;	/* Neighbor Self */
#define DR(I)			((I)->nbr_self->d_router)
#define BDR(I)			((I)->nbr_self->bd_router)
#define OPTIONS(I)		((I)->nbr_self->options)
#define PRIORITY(I)		((I)->nbr_self->priority)

  /* self-originated LSAs. */
  struct ospf_lsa *network_lsa_self;	/* network-LSA. */
  struct ospf_lsa *summary_lsa_self;	/* summary-LSA. */

  list ls_ack;				/* Link State Acknowledgment list. */

  /* Timer values. */
  u_int32_t v_hello;			/* Hello Interval */
  u_int32_t v_wait;			/* Router Dead Interval */
  u_int32_t v_ls_ack;			/* Delayed Link State Acknowledgment */

  /* Threads. */
  struct thread *t_read;
  struct thread *t_write;
  struct thread *t_hello;
  struct thread *t_wait;
  struct thread *t_ls_ack;
  struct thread *t_network_lsa_self;    /* self-originated network-LSA
                                           reflesh thread. */

  /* Statistics fields. */
  u_int32_t hello_in;	        /* Hello message input count. */
  u_int32_t hello_out;	        /* Hello message output count. */
  u_int32_t db_desc_in;         /* database desc. message input count. */
  u_int32_t db_desc_out;        /* database desc. message output count. */
  u_int32_t ls_req_in;          /* LS request message input count. */
  u_int32_t ls_req_out;         /* LS request message output count. */
  u_int32_t ls_upd_in;          /* LS update message input count. */
  u_int32_t ls_upd_out;         /* LS update message output count. */
  u_int32_t ls_ack_in;          /* LS Ack message input count. */
  u_int32_t ls_ack_out;         /* LS Ack message output count. */
  u_int32_t discarded;		/* discarded input count by error. */

  u_int full_nbrs;
};

/* Prototypes. */
struct ospf_interface *ospf_if_new ();
int ospf_if_up (struct interface *ifp);
int ospf_if_down (struct interface *ifp);
struct ospf_interface *ospf_if_lookup_by_name (char *);
struct ospf_interface *ospf_if_lookup_by_addr (struct in_addr *);
struct ospf_interface *ospf_if_lookup_by_prefix (struct prefix_ipv4 *);
int ospf_if_new_hook (struct interface *);
void ospf_if_init ();
void ospf_if_stream_set (struct ospf_interface *);
void ospf_if_stream_unset (struct ospf_interface *);
void ospf_if_reset_variables (struct ospf_interface *oi);
int ospf_if_is_enable (struct interface *);

struct ospf_interface *ospf_vl_new (struct ospf_vl_data *);
struct ospf_vl_data *ospf_vl_data_new (struct ospf_area *, struct in_addr);
struct ospf_vl_data *ospf_vl_lookup (struct ospf_area *, struct in_addr);
void ospf_vl_data_free (struct ospf_vl_data *);
void ospf_vl_add (struct ospf_vl_data *);
void ospf_vl_delete (struct ospf_vl_data *);
void ospf_vl_up_check (struct ospf_area *, struct in_addr, struct vertex *);
void ospf_vl_unapprove ();
void ospf_vl_shut_unapproved ();
int ospf_full_virtual_nbrs (struct ospf_area *);
int ospf_vls_in_area (struct ospf_area *);

struct crypt_key *ospf_crypt_key_lookup (struct ospf_interface *, u_char);

#endif /* _ZEBRA_OSPF_INTERFACE_H */
