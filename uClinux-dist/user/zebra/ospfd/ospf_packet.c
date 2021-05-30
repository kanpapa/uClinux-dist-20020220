/*
 * OSPF Sending and Receiving OSPF Packets.
 * Copyright (C) 1999, 2000 Toshiaki Takada
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

#include "thread.h"
#include "memory.h"
#include "linklist.h"
#include "prefix.h"
#include "if.h"
#include "table.h"
#include "sockunion.h"
#include "stream.h"
#include "log.h"
#include "md5-gnu.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_network.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_ism.h"
#include "ospfd/ospf_asbr.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_lsdb.h"
#include "ospfd/ospf_neighbor.h"
#include "ospfd/ospf_nsm.h"
#include "ospfd/ospf_packet.h"
#include "ospfd/ospf_spf.h"
#include "ospfd/ospf_flood.h"
#include "ospfd/ospf_dump.h"

/* Packet Type String. */
char *ospf_packet_type_str[] =
{
  "unknown",
  "Hello",
  "Database Description",
  "Link State Request",
  "Link State Update",
  "Link State Acknowledgment",
};

extern int in_cksum (void *ptr, int nbytes);

/* debug flag. */
extern unsigned long term_debug_ospf_packet[];

/* forward output pointer. */
void
ospf_output_forward (struct stream *s, int size)
{
  s->putp += size;
}

struct ospf_packet *
ospf_packet_new (size_t size)
{
  struct ospf_packet *new;

  new = XMALLOC (MTYPE_OSPF_PACKET, sizeof (struct ospf_packet));
  bzero (new, sizeof (struct ospf_packet));

  new->s = stream_new (size);

  return new;
}

void
ospf_packet_free (struct ospf_packet *op)
{
  if (op->s)
    stream_free (op->s);

  XFREE (MTYPE_OSPF_PACKET, op);

  op = NULL;
}

struct ospf_fifo *
ospf_fifo_new ()
{
  struct ospf_fifo *new;

  new = XMALLOC (MTYPE_OSPF_FIFO, sizeof (struct ospf_fifo));
  bzero (new, sizeof (struct ospf_fifo));

  return new;
}

/* Add new packet to fifo. */
void
ospf_fifo_push (struct ospf_fifo *fifo, struct ospf_packet *op)
{
  if (fifo->tail)
    fifo->tail->next = op;
  else
    fifo->head = op;

  fifo->tail = op;

  fifo->count++;
}

/* Delete first packet from fifo. */
struct ospf_packet *
ospf_fifo_pop (struct ospf_fifo *fifo)
{
  struct ospf_packet *op;

  op = fifo->head;

  if (op)
    {
      fifo->head = op->next;

      if (fifo->head == NULL)
	fifo->tail = NULL;

      fifo->count--;
    }

  return op;
}

/* Return first fifo entry. */
struct ospf_packet *
ospf_fifo_head (struct ospf_fifo *fifo)
{
  return fifo->head;
}

/* Flush ospf packet fifo. */
void
ospf_fifo_flush (struct ospf_fifo *fifo)
{
  struct ospf_packet *op;
  struct ospf_packet *next;

  for (op = fifo->head; op; op = next)
    {
      next = op->next;
      ospf_packet_free (op);
    }
  fifo->head = fifo->tail = NULL;
  fifo->count = 0;
}

/* Free ospf packet fifo. */
void
ospf_fifo_free (struct ospf_fifo *fifo)
{
  ospf_fifo_flush (fifo);

  XFREE (MTYPE_OSPF_FIFO, fifo);
}

#if 0
void
ospf_fifo_debug (struct ospf_fifo *fifo)
{
  int i = 0;
  struct ospf_packet *op;

  printf ("OSPF fifo count %ld\n", fifo->count);

  for (op = fifo->head; op; op = op->next)
    {
      printf (" fifo %d: stream: size %d putp %ld getp %ld\n", i, op->s->size,
	      op->s->getp, op->s->putp);
      i++;
    }
}
#endif

void
ospf_packet_add (struct ospf_interface *oi, struct ospf_packet *op)
{
  /* Add packet to end of queue. */
  ospf_fifo_push (oi->obuf, op);

  /* Debug of packet fifo*/
  /* ospf_fifo_debug (oi->obuf); */
}

void
ospf_packet_delete (struct ospf_interface *oi)
{
  struct ospf_packet *op;
  
  op = ospf_fifo_pop (oi->obuf);

  if (op)
    ospf_packet_free (op);
}

struct stream *
ospf_stream_copy (struct stream *new, struct stream *s)
{
  new->endp = s->endp;
  new->putp = s->putp;
  new->getp = s->getp;

  memcpy (new->data, s->data, stream_get_endp (s));

  return new;
}

#if 0
struct stream *
ospf_stream_dup (struct stream *s)
{
  struct stream *new;

  new = stream_new (stream_get_endp (s));

  new->endp = s->endp;
  new->putp = s->putp;
  new->getp = s->getp;

  memcpy (new->data, s->data, stream_get_endp (s));

  return new;
}
#endif

struct ospf_packet *
ospf_packet_dup (struct ospf_packet *op)
{
  struct ospf_packet *new;

  new = ospf_packet_new (op->length);
  ospf_stream_copy (new->s, op->s);

  new->dst = op->dst;
  new->length = op->length;

  return new;
}

int
ospf_packet_max (struct ospf_interface *oi)
{
  int max;

  if (oi->area->auth_type == OSPF_AUTH_CRYPTOGRAPHIC)
    max = oi->ifp->mtu - OSPF_AUTH_MD5_SIZE - 88;
  else
    max = oi->ifp->mtu - 88;

  return max;
}


int
ospf_check_md5_digest (struct ospf_interface *oi, struct stream *s,
                       u_int16_t length)
{
  void *ibuf;
  struct md5_ctx ctx;
  unsigned char digest[OSPF_AUTH_MD5_SIZE];
  unsigned char *pdigest;
  struct crypt_key *ck;
  struct ospf_header *ospfh;

  ibuf = STREAM_PNT (s);
  ospfh = (struct ospf_header *) ibuf;

  /* Get pointer to the end of the packet. */
  pdigest = ibuf + length;

  /* Get secret key. */
  ck = ospf_crypt_key_lookup (oi, ospfh->u.crypt.key_id);
  if (ck == NULL)
    return 0;

  /* Generate a digest for the ospf packet - their digest + our digest. */
  md5_init_ctx (&ctx);
  md5_process_bytes (ibuf, length, &ctx);
  md5_process_bytes (ck->auth_key, OSPF_AUTH_MD5_SIZE, &ctx);
  md5_finish_ctx (&ctx, digest);

  /* compare the two */
  if (memcmp (pdigest, digest, OSPF_AUTH_MD5_SIZE))
    return 0;

  return 1;
}

/* This function is called from ospf_write(), it will detect the
   authentication scheme and if it is MD5, it will change the sequence
   and update the MD5 digest. */
int
ospf_make_md5_digest (struct ospf_interface *oi, struct ospf_packet *op)
{
  struct ospf_header *ospfh;
  unsigned char digest[OSPF_AUTH_MD5_SIZE];
  struct md5_ctx ctx;
  void *ibuf;
  unsigned long oldputp;
  struct crypt_key *ck;
  char *auth_key;

  ibuf = STREAM_DATA (op->s);
  ospfh = (struct ospf_header *) ibuf;

  if (ntohs (ospfh->auth_type) != OSPF_AUTH_CRYPTOGRAPHIC)
    return 0;

  /* We do this here so when we dup a packet, we don't have to
     waste CPU rewriting other headers. */
  ospfh->u.crypt.crypt_seqnum = htonl (oi->crypt_seqnum++);

  /* Get MD5 Authentication key from auth_key list. */
  if (list_isempty (oi->auth_crypt))
    auth_key = "";
  else
    {
      ck = getdata (oi->auth_crypt->tail);
      auth_key = ck->auth_key;
    }

  /* Generate a digest for the entire packet + our secret key. */
  md5_init_ctx (&ctx);
  md5_process_bytes (ibuf, ntohs (ospfh->length), &ctx);
  md5_process_bytes (auth_key, OSPF_AUTH_MD5_SIZE, &ctx);
  md5_finish_ctx (&ctx, digest);

  /* Append md5 digest to the end of the stream. */
  oldputp = stream_get_putp (op->s);
  stream_set_putp (op->s, ntohs (ospfh->length));
  stream_put (op->s, digest, OSPF_AUTH_MD5_SIZE);
  stream_set_putp (op->s, oldputp);

  /* We do *NOT* increment the OSPF header length. */
  op->length += OSPF_AUTH_MD5_SIZE;

  return OSPF_AUTH_MD5_SIZE;
}


int
ospf_ls_req_timer (struct thread *thread)
{
  struct ospf_neighbor *nbr;

  nbr = THREAD_ARG (thread);
  nbr->t_ls_req = NULL;

  /* Send Link State Request. */
  if (ospf_ls_request_count (nbr))
    ospf_ls_req_send (nbr);

  /* Set Link State Request retransmission timer. */
  OSPF_NSM_TIMER_ON (nbr->t_ls_req, ospf_ls_req_timer, nbr->v_ls_req);

  return 0;
}

void
ospf_ls_req_event (struct ospf_neighbor *nbr)
{
  if (nbr->t_ls_req)
    {
      thread_cancel (nbr->t_ls_req);
      nbr->t_ls_req = NULL;
    }
  nbr->t_ls_req = thread_add_event (master, ospf_ls_req_timer, nbr, 0);
}

/* Cyclic timer function.  Fist registered in ospf_nbr_new () in
   ospf_neighbor.c  */
int
ospf_ls_upd_timer (struct thread *thread)
{
  struct ospf_neighbor *nbr;

  nbr = THREAD_ARG (thread);
  nbr->t_ls_upd = NULL;

  /* Send Link State Update. */
  if (ospf_ls_retransmit_count (nbr) > 0)
    {
      list update;
      struct new_lsdb *lsdb;
      int i;

      lsdb = &nbr->ls_rxmt;
      update = list_init ();

      for (i = OSPF_MIN_LSA; i < OSPF_MAX_LSA; i++)
	{
	  struct route_table *table = lsdb->type[i].db;
	  struct route_node *rn;

	  for (rn = route_top (table); rn; rn = route_next (rn))
	    if (rn->info)
	      list_add_node (update, rn->info);
	}

      ospf_ls_upd_send (nbr, update, OSPF_SEND_PACKET_DIRECT);
      list_delete_all (update);
    }

  /* Set LS Update retransmission timer. */
  OSPF_NSM_TIMER_ON (nbr->t_ls_upd, ospf_ls_upd_timer, nbr->v_ls_upd);

  return 0;
}

int
ospf_ls_ack_timer (struct thread *thread)
{
  struct ospf_interface *oi;

  oi = THREAD_ARG (thread);
  oi->t_ls_ack = NULL;

  /* Send Link State Acknowledgment. */
  if (listcount (oi->ls_ack) > 0)
    ospf_ls_ack_send_delayed (oi);

  /* Set LS Ack timer. */
  OSPF_ISM_TIMER_ON (oi->t_ls_ack, ospf_ls_ack_timer, oi->v_ls_ack);

  return 0;
}

int
ospf_write (struct thread *thread)
{
  struct ospf_interface *oi;
  struct ospf_packet *op;
  struct sockaddr_in sa_src, sa_dst;
  u_char type;
  int sock, ret;
  int flags = 0;

  oi = THREAD_ARG (thread);
  oi->t_write = NULL;

  /* Open outgoing socket. */
  sock = ospf_serv_sock (oi->ifp, AF_INET);
  if (sock < 0)
    {
      zlog_warn ("ospf_write: interface %s can't create raw socket",
		 oi->ifp->name);
      return -1;
    }

  /* Get one packet from queue. */
  op = ospf_fifo_head (oi->obuf);
  assert (op);
  assert (op->length >= OSPF_HEADER_SIZE);

  /* Select outgoing interface by destination address. */
  if (op->dst.s_addr == htonl (OSPF_ALLSPFROUTERS) ||
      op->dst.s_addr == htonl (OSPF_ALLDROUTERS))
    ospf_if_ipmulticast (sock, oi->address);
  else
    {
      bzero (&sa_src, sizeof (sa_src));
      sa_src.sin_family = AF_INET;
      sa_src.sin_addr = oi->address->u.prefix4;
      sa_src.sin_port = htons (0);

      ret = bind (sock, (struct sockaddr *) &sa_src, sizeof (sa_src));
      if (ret < 0)
	{
	  zlog_warn ("*** bind error");
	  return 0;
	}
    }

  /* Rewrite the md5 signature & update the seq */
  ospf_make_md5_digest (oi, op);

  bzero (&sa_dst, sizeof (sa_dst));
  sa_dst.sin_family = AF_INET;
  sa_dst.sin_addr = op->dst;
  sa_dst.sin_port = htons (0);

  /* Set DONTROUTE flag if dst is unicast. */
  if (oi->type != OSPF_IFTYPE_VIRTUALLINK)
    if (!IN_MULTICAST (htonl (op->dst.s_addr)))
      flags = MSG_DONTROUTE;

  /* Now send packet. */
  ret = sendto (sock, STREAM_DATA (op->s), op->length, flags,
		(struct sockaddr *) &sa_dst, sizeof (sa_dst));
  /* Immediately close socket. */
  close (sock);

  if (ret < 0)
    {
      zlog_warn ("*** sendto in ospf_write failed with %s", strerror (errno));
      return -1;
    }

  /* Retrieve OSPF packet type. */
  stream_set_getp (op->s, 1);
  type = stream_getc (op->s);

  /* Show debug sending packet. */
  if (IS_DEBUG_OSPF_PACKET (type - 1, SEND))
    {
      if (IS_DEBUG_OSPF_PACKET (type - 1, DETAIL))
	{
	  zlog_info ("-----------------------------------------------------");
	  stream_set_getp (op->s, 0);
	  ospf_packet_dump (op->s);
	}

      zlog_info ("%s sent to [%s] via [%s].",
		 ospf_packet_type_str[type], inet_ntoa (op->dst),
		 oi->ifp->name);

      if (IS_DEBUG_OSPF_PACKET (type - 1, DETAIL))
	zlog_info ("-----------------------------------------------------");
    }

  /* Now delete packet from queue. */
  ospf_packet_delete (oi);

  /* If packets still remain in queue, call write thread. */
  if (ospf_fifo_head (oi->obuf))
    OSPF_ISM_WRITE_ON (oi->t_write, ospf_write, oi->fd);

  return 0;
}

/* OSPF Hello message read -- RFC2328 Section 10.5. */
void
ospf_hello (struct ip *iph, struct ospf_header *ospfh,
	    struct stream * s, struct ospf_interface *oi, int size)
{
  struct ospf_hello *hello;
  struct ospf_neighbor *nbr;
  struct route_node *rn;
  struct prefix p, key;
  char buf[24];

  /* increment statistics. */
  oi->hello_in++;

#if 0
  zlog_info ("Packet[Hello:RECV]: %s %s", oi->ifp->name,
	     LOOKUP (ospf_network_type_msg, oi->type));
#endif

  hello = (struct ospf_hello *) STREAM_PNT (s);

  /* If Hello is myself, silently discard. */
  if (IPV4_ADDR_SAME (&ospfh->router_id, &ospf_top->router_id))
    return;

  /* If incoming interface is passive one, ignore Hello. */
  if (oi->passive_interface == OSPF_IF_PASSIVE)
    return;

  /* get neighbor prefix. */
  p.family = AF_INET;
  p.prefixlen = ip_masklen (hello->network_mask);
  p.u.prefix4 = iph->ip_src;

  /* Compare network mask. */
  /* Checking is ignored for Point-to-Point and Virtual link. */
  if (oi->type != OSPF_IFTYPE_POINTOPOINT 
      && oi->type != OSPF_IFTYPE_VIRTUALLINK)
    if (oi->address->prefixlen != p.prefixlen)
      {
	zlog_warn ("neighbor[%s]: NetworkMask mismatch.",
		   inet_ntoa (ospfh->router_id));
	return;
      }

  /* Compare Hello Interval. */
  if (oi->v_hello != ntohs (hello->hello_interval))
    {
      zlog_warn ("neighbor[%s]: HelloInterval mismatch.",
		 inet_ntoa (ospfh->router_id));
      return;
    }

  /* Compare Router Dead Interval. */
  if (oi->v_wait != ntohl (hello->dead_interval))
    {
      zlog_warn ("neighbor[%s]: RouterDeadInterval mismatch.",
		 inet_ntoa (ospfh->router_id));
      return;
    }

  zlog_warn ("Packet[Hello:RECV]: Options %s",
	     ospf_option_dump (hello->options, buf, 24));

#if 0
  /* Compare options. */
  if (OPTIONS (oi) != hello->options)
    {
      zlog_warn ("Packet[Hello:RECV]: my options: %x, his options %x",
		 OPTIONS (oi), hello->options);
      if (!CHECK_FLAG (hello->options, OSPF_OPTION_DC))
         return; /* Hack !!! For Cisco VLs, Zinin */
      zlog_warn ("Allowing Cisco VLs");
    }
#endif

  /* Get neighbor information from table. */
  key.family = AF_INET;
  key.prefixlen = IPV4_MAX_BITLEN;
  key.u.prefix4 = iph->ip_src;

  rn = route_node_get (oi->nbrs, &key);
  if (rn->info)
    {
      route_unlock_node (rn);
      nbr = rn->info;

      /* Reset the flags after shutdown and no shutdown interface. */
      if (nbr->status <= NSM_Down)
	nbr->dd_flags = nbr->dd_flags|OSPF_DD_FLAG_I|OSPF_DD_FLAG_M;
    }
  else
    {
      /* Create new OSPF Neighbor structure. */
      nbr = ospf_nbr_new (oi);
      nbr->status = NSM_Down;
      nbr->src = iph->ip_src;
      nbr->address = p;

      rn->info = nbr;

      zlog_info ("NSM[%s:%s]: start", nbr->oi->ifp->name,
		 inet_ntoa (nbr->router_id));
    }
  
  nbr->router_id = ospfh->router_id;

  /* Add event to thread. */
  OSPF_NSM_EVENT_EXECUTE (nbr, NSM_HelloReceived);

  if (ospf_nbr_bidirectional (&ospf_top->router_id, hello->neighbors,
			      size - OSPF_HELLO_MIN_SIZE))
    OSPF_NSM_EVENT_EXECUTE (nbr, NSM_TwoWayReceived);
  else
    {
      OSPF_NSM_EVENT_EXECUTE (nbr, NSM_OneWayReceived);
      /* Set neighbor information. */
      nbr->priority = hello->priority;
      nbr->options = hello->options;
      nbr->d_router = hello->d_router;
      nbr->bd_router = hello->bd_router;
      return;
    }

  /* If neighbor itself declares DR and no BDR exists,
     cause event BackupSeen */
  if (IPV4_ADDR_SAME (&nbr->address.u.prefix4, &hello->d_router))
    if (hello->bd_router.s_addr == 0 && oi->status == ISM_Waiting)
  /*
  if (IPV4_ADDR_SAME (&nbr->address.u.prefix4, &hello->d_router))
    if (oi->status == ISM_Waiting)
  */
      OSPF_ISM_EVENT_SCHEDULE (oi, ISM_BackupSeen);

  /* neighbor itself declares BDR. */
  if (oi->status == ISM_Waiting &&
      IPV4_ADDR_SAME (&nbr->address.u.prefix4, &hello->bd_router))
    OSPF_ISM_EVENT_SCHEDULE (oi, ISM_BackupSeen);

  /* had not previously. */
  if ((IPV4_ADDR_SAME (&nbr->address.u.prefix4, &hello->d_router) &&
       IPV4_ADDR_CMP (&nbr->address.u.prefix4, &nbr->d_router)) ||
      (IPV4_ADDR_CMP (&nbr->address.u.prefix4, &hello->d_router) &&
       IPV4_ADDR_SAME (&nbr->address.u.prefix4, &nbr->d_router)))
    OSPF_ISM_EVENT_SCHEDULE (oi, ISM_NeighborChange);

  /* had not previously. */
  if ((IPV4_ADDR_SAME (&nbr->address.u.prefix4, &hello->bd_router) &&
       IPV4_ADDR_CMP (&nbr->address.u.prefix4, &nbr->bd_router)) ||
      (IPV4_ADDR_CMP (&nbr->address.u.prefix4, &hello->bd_router) &&
       IPV4_ADDR_SAME (&nbr->address.u.prefix4, &nbr->bd_router)))
    OSPF_ISM_EVENT_SCHEDULE (oi, ISM_NeighborChange);

  /* Neighbor priority check. */
  if (nbr->priority >= 0 && nbr->priority != hello->priority)
    OSPF_ISM_EVENT_SCHEDULE (oi, ISM_NeighborChange);

  /* Set neighbor information. */
  nbr->priority = hello->priority;
  nbr->options = hello->options;
  nbr->d_router = hello->d_router;
  nbr->bd_router = hello->bd_router;
}

/* Save DD flags/options/Seqnum received. */
void
ospf_db_desc_save_current (struct ospf_neighbor *nbr,
			   struct ospf_db_desc *dd)
{
  nbr->last_recv.flags = dd->flags;
  nbr->last_recv.options = dd->options;
  nbr->last_recv.dd_seqnum = ntohl (dd->dd_seqnum);
}

/* Process rest of DD packet */
void
ospf_db_desc_proc (struct stream *s, struct ospf_interface *oi,
		   struct ospf_neighbor *nbr, struct ospf_db_desc *dd,
		   u_int16_t size)
{
  struct ospf_lsa *new, *find;
  struct lsa_header *lsah;

  stream_forward (s, OSPF_DB_DESC_MIN_SIZE);
  for (size -= OSPF_DB_DESC_MIN_SIZE; size > 0; size -= OSPF_LSA_HEADER_SIZE) 
    {
      lsah = (struct lsa_header *) STREAM_PNT (s);
      stream_forward (s, OSPF_LSA_HEADER_SIZE);

      /* Unknown LS type. */
      if (lsah->type < OSPF_MIN_LSA || lsah->type >= OSPF_MAX_LSA)
	{
	  zlog_warn ("DD: Unknown LS type %d.", lsah->type);
	  OSPF_NSM_EVENT_SCHEDULE (nbr, NSM_SeqNumberMismatch);
	  continue;
	}

      /* */
      if ((lsah->type == OSPF_AS_EXTERNAL_LSA) &&
          (oi->area->external_routing != OSPF_AREA_DEFAULT))
	{
	  zlog_warn ("DD: AS-external-LSA from stub area, ID: %s.",
		     inet_ntoa (lsah->id));
	  OSPF_NSM_EVENT_SCHEDULE (nbr, NSM_SeqNumberMismatch);
	  continue;
	}

      /* Create LS-request object. */
      new = ospf_ls_request_new (lsah);

      /* Lookup received LSA, then add LS request list. */
      find = ospf_lsa_lookup_by_header (oi->area, lsah);
      if (!find || ospf_lsa_more_recent (find, new) < 0)
	ospf_ls_request_add (nbr, new);
      else
	{
	  /* Received LSA is not recent. */
	  zlog_info ("DD: LSA received Type %d, ID %s is not recent.",
		     lsah->type, inet_ntoa (lsah->id));
	  ospf_ls_request_free (new);
	  continue;
	}
    }

  /* Cancel DD retransmission timer before send new DD. */
  OSPF_NSM_TIMER_OFF (nbr->t_db_desc);

  /* Master */
  if (IS_SET_DD_MS (nbr->dd_flags))
    {
      nbr->dd_seqnum++;
      /* Entire DD packet sent. */
      if (!IS_SET_DD_M (dd->flags) && !IS_SET_DD_M (nbr->dd_flags))
	OSPF_NSM_EVENT_SCHEDULE (nbr, NSM_ExchangeDone);
      else
	/* Send new DD packet. */
	ospf_db_desc_send (nbr);
    }
  /* Slave */
  else
    {
      nbr->dd_seqnum = ntohl (dd->dd_seqnum);

      /* When master's more flags is not set. */
      if (!IS_SET_DD_M (dd->flags) && ospf_db_summary_isempty (nbr))
	{
	  nbr->dd_flags &= ~(OSPF_DD_FLAG_M);
	  OSPF_NSM_EVENT_SCHEDULE (nbr, NSM_ExchangeDone);
	}

      /* Send DD pakcet in reply. */
      ospf_db_desc_send (nbr);
    }

  /* Save received neighbor values from DD. */
  ospf_db_desc_save_current (nbr, dd);
}

int
ospf_db_desc_is_dup (struct ospf_db_desc *dd, struct ospf_neighbor *nbr)
{
  /* Is DD duplicated? */
  if (dd->options == nbr->last_recv.options &&
      dd->flags == nbr->last_recv.flags &&
      dd->dd_seqnum == htonl (nbr->last_recv.dd_seqnum))
    return 1;

  return 0;
}

/* OSPF Database Description message read -- RFC2328 Section 10.6. */
void
ospf_db_desc (struct ip *iph, struct ospf_header *ospfh,
	      struct stream *s, struct ospf_interface *oi, u_int16_t size)
{
  struct ospf_db_desc *dd;
  struct ospf_neighbor *nbr;

  /* Increment statistics. */
  oi->db_desc_in++;

  dd = (struct ospf_db_desc *) STREAM_PNT (s);

  nbr = ospf_nbr_lookup_by_addr (oi->nbrs, &iph->ip_src);
  if (nbr == NULL)
    {
      zlog_warn ("DD: Unknown Neighbor %s", inet_ntoa (ospfh->router_id));
      return;
    }

  /* Check MTU. */
  if (ntohs (dd->mtu) > oi->ifp->mtu)
    {
      zlog_warn ("DD: MTU is larger than [%s]'s MTU", oi->ifp->name);
      return;
    }

  /* Process DD packet by neighbor status. */
 REDO_DD_PROCESS:
  switch (nbr->status)
    {
    case NSM_Down:
    case NSM_Attempt:
      zlog_warn ("DD: Neighbor state is %s, packet discarded.",
		 LOOKUP (ospf_nsm_status_msg, nbr->status));
      break;
    case NSM_Init:
      OSPF_NSM_EVENT_EXECUTE (nbr, NSM_TwoWayReceived);
      if (nbr->status == NSM_ExStart)
	goto REDO_DD_PROCESS;
      break;
    case NSM_TwoWay:
      zlog_warn ("DD: Neighbor state is %s, packet discarded.",
		 LOOKUP (ospf_nsm_status_msg, nbr->status));
      break;
    case NSM_ExStart:
      /* Slave. */
      if ((IS_SET_DD_ALL (dd->flags) == OSPF_DD_FLAG_ALL) &&
	  size == OSPF_DB_DESC_MIN_SIZE &&
	  IPV4_ADDR_CMP (&nbr->router_id, &ospf_top->router_id) > 0)
	{
	  nbr->dd_seqnum = ntohl (dd->dd_seqnum);
	  nbr->dd_flags &= ~(OSPF_DD_FLAG_MS|OSPF_DD_FLAG_I); /* Reset I/MS */

	  OSPF_NSM_EVENT_EXECUTE (nbr, NSM_NegotiationDone);
	  zlog_warn ("DD: Negotiation done (Slave).");

	  /* continue processing rest of packet. */
	  ospf_db_desc_proc (s, oi, nbr, dd, size);
	}
      /* Master. */
      else if (!IS_SET_DD_MS (dd->flags) && !IS_SET_DD_I (dd->flags) &&
	       ntohl (dd->dd_seqnum) == nbr->dd_seqnum &&
	       IPV4_ADDR_CMP (&nbr->router_id, &ospf_top->router_id) < 0)
	{
	  nbr->dd_flags &= ~OSPF_DD_FLAG_I;

	  OSPF_NSM_EVENT_EXECUTE (nbr, NSM_NegotiationDone);
	  zlog_warn ("DD: Negotiation done (Master).");

	  /* Continue processing rest of packet. */
	  ospf_db_desc_proc (s, oi, nbr, dd, size);
	}
      else
	zlog_warn ("DD: Negotiation fails, packet discarded.");
      break;
    case NSM_Exchange:
      if (ospf_db_desc_is_dup (dd, nbr))
	{
	  if (IS_SET_DD_MS (nbr->dd_flags))
	    /* Master: discard duplicated DD packet. */
	    zlog_warn ("DD [Master]: packet duplicated.");
	  else
	    /* Slave: cause to retransmit the last Database Description. */
	    {
	      zlog_warn ("DD [Slave]: packet duplicated.");
	      ospf_db_desc_resend (nbr);
	    }
	  break;
	}

      /* Otherwise DD packet should be checked. */
      /* Check Master/Slave bit mismatch */
      if (IS_SET_DD_MS (dd->flags) != IS_SET_DD_MS (nbr->last_recv.flags))
	{
	  zlog_warn ("DD: MS-bit mismatch.");
	  OSPF_NSM_EVENT_SCHEDULE (nbr, NSM_SeqNumberMismatch);
	  zlog_info ("dd->flags=%d, nbr->dd_flags=%d",
		     dd->flags, nbr->dd_flags);
	  break;
	}

      /* Check initialize bit is set. */
      if (IS_SET_DD_I (dd->flags))
	{
	  zlog_warn ("DD: I-bit set.");
	  OSPF_NSM_EVENT_SCHEDULE (nbr, NSM_SeqNumberMismatch);
	  break;
	}

      /* Check DD Options. */
      if (dd->options != nbr->last_recv.options)
	{
	  zlog_warn ("DD: options mismatch.");
	  OSPF_NSM_EVENT_SCHEDULE (nbr, NSM_SeqNumberMismatch);
	  break;
	}

      /* Check DD sequence number. */
      if ((IS_SET_DD_MS (nbr->dd_flags) &&
	   ntohl (dd->dd_seqnum) != nbr->dd_seqnum) ||
	  (!IS_SET_DD_MS (nbr->dd_flags) &&
	   ntohl (dd->dd_seqnum) != nbr->dd_seqnum + 1))
	{
	  zlog_warn ("DD: sequence number mismatch.");
	  OSPF_NSM_EVENT_SCHEDULE (nbr, NSM_SeqNumberMismatch);
	  break;
	}

      /* Continue processing rest of packet. */
      ospf_db_desc_proc (s, oi, nbr, dd, size);
      break;
    case NSM_Loading:
    case NSM_Full:
      if (ospf_db_desc_is_dup (dd, nbr))
	{
	  if (IS_SET_DD_MS (nbr->dd_flags))
	    /* Master should discard duplicate DD packet. */
	    zlog_warn ("DD: DD is dup, packet discarded.");
	  else
	    /* Resend last DD packet. */
	    ospf_db_desc_resend (nbr);
	  break;
	}

      OSPF_NSM_EVENT_SCHEDULE (nbr, NSM_SeqNumberMismatch);
      break;
    default:
      zlog_warn ("DD: NSM illegal status.");
      break;
    }
}

/* OSPF Link State Request Read -- RFC2328 Section 10.7. */
void
ospf_ls_req (struct ip *iph, struct ospf_header *ospfh,
	     struct stream *s, struct ospf_interface *oi, u_int16_t size)
{
  struct ospf_neighbor *nbr;
  u_int32_t ls_type;
  struct in_addr ls_id;
  struct in_addr adv_router;
  struct ospf_lsa *find;
  list ls_upd;
  int length;

  /* Increment statistics. */
  oi->ls_req_in++;

  nbr = ospf_nbr_lookup_by_addr (oi->nbrs, &iph->ip_src);
  if (nbr == NULL)
    {
      zlog_warn ("Link State Request: Unknown Neighbor %s.",
		 inet_ntoa (ospfh->router_id));
      return;
    }

  /* Neighbor State should be Exchange or later. */
  if (nbr->status != NSM_Exchange &&
      nbr->status != NSM_Loading &&
      nbr->status != NSM_Full)
    {
      zlog_warn ("Link State Request: Neighbor state is %s, packet discarded.",
		 LOOKUP (ospf_nsm_status_msg, nbr->status));
      return;
    }

  /* Send Link State Update for ALL requested LSAs. */
  ls_upd = list_init ();
  length = OSPF_HEADER_SIZE + OSPF_LS_UPD_MIN_SIZE;
  while (size > 0)
    {
      /* Get one slice of Link State Request. */
      ls_type = stream_getl (s);
      ls_id.s_addr = stream_get_ipv4 (s);
      adv_router.s_addr = stream_get_ipv4 (s);

      /* Search proper LSA in LSDB. */
      find = ospf_lsa_lookup (oi->area, ls_type, ls_id, adv_router);
      if (find == NULL)
	{
	  OSPF_NSM_EVENT_SCHEDULE (nbr, NSM_BadLSReq);
	  return;
	}

      /* Packet overflows MTU size, send immediatly. */
      if (length + ntohs (find->data->length) > OSPF_PACKET_MAX (oi))
	{
	  ospf_ls_upd_send (nbr, ls_upd, OSPF_SEND_PACKET_INDIRECT);
	  list_delete_all_node (ls_upd);
	  length = OSPF_HEADER_SIZE + OSPF_LS_UPD_MIN_SIZE;
	}

      /* Append LSA to update list. */
      list_add_node (ls_upd, find);
      length += ntohs (find->data->length);

      size -= 12;
    }

  /* Send rest of Link State Update. */
  if (listcount (ls_upd) > 0)
    {
      ospf_ls_upd_send (nbr, ls_upd, OSPF_SEND_PACKET_INDIRECT);
      list_delete_all (ls_upd);
      /*      list_free (ls_upd); */
    }
}

/* Get the list of LSAs from Link State Update packet.
   And process some validation -- Section 13. (1)-(3). */
list
ospf_ls_upd_list_lsa (struct stream *s, struct ospf_interface *oi, size_t size)
{
  u_int16_t count, sum;
  u_int32_t length;
  struct lsa_header *lsah;
  struct ospf_lsa *lsa;
  list lsas;

  lsas = list_init ();

  count = stream_getl (s);
  size -= 4;

  for (; size > 0 && count > 0;
       size -= length, stream_forward (s, length), count--)
    {
      lsah = (struct lsa_header *) STREAM_PNT (s);
      length = ntohs (lsah->length);

      if (length > size)
	{
	  zlog_warn ("Link State Update: LSA length exceeds packet size.");
	  break;
	}

      /* Validate the LSA's LS checksum. */
      sum = lsah->checksum;
      if (sum != ospf_lsa_checksum (lsah))
	{
	  zlog_warn ("Link State Update: LSA checksum error %x, %x.",
		     sum, lsah->checksum);
	  continue;
	}

      /* Examine the LSA's LS type. */
      if (lsah->type < OSPF_MIN_LSA || lsah->type >= OSPF_MAX_LSA)
	{
	  zlog_warn ("Link State Update: Unknown LS type %d", lsah->type);
	  continue;
	}

      /* If this is an AS-external-LSA, and the area has been configured
	 as  a stub area, discard the LSA. */
      if (lsah->type == OSPF_AS_EXTERNAL_LSA)
	{
	  ; /* If the area is configured as stub are, discard this LSA. */ 
	}

      /* Create OSPF LSA instance. */
      lsa = ospf_lsa_new ();
      lsa->area = oi->area;
      zlog_info("Z: ospf_lsa_new() in ospf_ls_upd_list_lsa(): %x", lsa);

      lsa->data = ospf_lsa_data_new (length);
      memcpy (lsa->data, lsah, length);

      list_add_node (lsas, lsa);
    }

  return lsas;
}

/* Cleanup Update list. */
void
ospf_upd_list_clean (list lsas)
{
  listnode node;
  struct ospf_lsa *lsa;

  for (node = listhead (lsas); node; nextnode (node))
    if ((lsa = getdata (node)) != NULL)
      ospf_lsa_free (lsa);

  list_delete_all (lsas);
}

/* OSPF Link State Update message read -- RFC2328 Section 13. */
void
ospf_ls_upd (struct ip *iph, struct ospf_header *ospfh,
	     struct stream *s, struct ospf_interface *oi, u_int16_t size)
{
  struct ospf_neighbor *nbr;
  list lsas;
  listnode node, next;
  struct ospf_lsa *lsa = NULL;
  /* unsigned long ls_req_found = 0; */

  /* Increment statistics. */
  oi->ls_upd_in++;

  /* Check neighbor. */
  nbr = ospf_nbr_lookup_by_addr (oi->nbrs, &iph->ip_src);
  if (nbr == NULL)
    {
      zlog_warn ("Link State Update: Unknown Neighbor %s on int: %s",
		 inet_ntoa (ospfh->router_id), oi->ifp->name);
      return;
    }

  /* Check neighbor status. */
  if (nbr->status < NSM_Exchange)
    {
      zlog_warn ("Link State Update: Neighbor[%s] state is less than Exchange",
		 inet_ntoa (ospfh->router_id));
      return;
    }

  /* Get list of LSAs from Link State Update packet. */
  lsas = ospf_ls_upd_list_lsa (s, oi, size);

#define DISCARD_LSA(L) {\
        ospf_lsa_free (L);\
        zlog_info("Z: ospf_lsa_free() in ospf_ls_upd(): %x", lsa);\
	continue; }

  /* Process each LSA received. */
  for (node = listhead (lsas); node; node = next)
    {
      struct ospf_lsa *ls_ret, *current;
      int ret = 1;

      next = node->next;

      lsa = getdata (node);

      list_delete_by_val (lsas, lsa); /* We don't need it anymore */

      /* Validate Checksum */

      /* LSA Type */
      if (lsa->data->type < OSPF_MIN_LSA ||
	  lsa->data->type > OSPF_MAX_LSA)
	DISCARD_LSA (lsa);

      if (lsa->data->type == OSPF_AS_EXTERNAL_LSA &&
	  nbr->oi->area->external_routing != OSPF_AREA_DEFAULT)
	DISCARD_LSA (lsa);

      /* Find the LSA in the current database. */

      current = ospf_lsa_lookup_by_header (oi->area, lsa->data);

      /* If the LSA's LS age is equal to MaxAge, and there is currently
	 no instance of the LSA in the router's link state database,
	 and none of router's neighbors are in states Exchange or Loading,
	 then take the following actions. */

      if (LS_AGE (lsa) == OSPF_LSA_MAX_AGE && !current &&
	  (ospf_nbr_count (oi->nbrs, NSM_Exchange) +
	   ospf_nbr_count (oi->nbrs, NSM_Loading)) == 0)
	{
	  /* Response Link State Acknowledgment. */
	  ospf_ls_ack_send (nbr, lsa);

	  /* Discard LSA. */	  
	  zlog_warn ("Link State Update: LS age is equal to MaxAge.");
          DISCARD_LSA (lsa);
	}

      /* (5) Find the instance of this LSA that is currently contained
	 in the router's link state database.  If there is no
	 database copy, or the received LSA is more recent than
	 the database copy the following steps must be performed. */

      if (current == NULL ||
	  (ret = ospf_lsa_more_recent (current, lsa)) < 0)
	{
	  /* Actual flooding procedure. */
	  ospf_flood (nbr, current, lsa);
	  continue;
	}

      /* This need careful treatment, we have to check an error which
         occurred. -- kunihiro 1999/08/30. 
         Now below part works correctly -- kunihiro 2000/01/31. */

      /* (6) Else, If there is an instance of the LSA on the sending
	 neighbor's Link state request list, an error has occurred in
	 the Database Exchange process.  In this case, restart the
	 Database Exchange process by generating the neighbor event
	 BadLSReq for the sending neighbor and stop processing the
	 Link State Update packet. */

      if (ospf_ls_request_lookup (nbr, lsa))
	{
	  OSPF_NSM_EVENT_SCHEDULE (nbr, NSM_BadLSReq);
	  zlog_warn ("LSA instance exists on Link state request list");

	  /* Clean list of LSAs. */
          ospf_upd_list_clean (lsas);
	  /* this lsa is not on lsas list already. */
	  ospf_lsa_free (lsa);
	  return;
	}

      /* If the received LSA is the same instance as the database copy
	 (i.e., neither one is more recent) the following two steps
	 should be performed: */

      if (ret == 0)
	{
	  /* If the LSA is listed in the Link state retransmission list
	     for the receiving adjacency, the router itself is expecting
	     an acknowledgment for this LSA.  The router should treat the
	     received LSA as an acknowledgment by removing the LSA from
	     the Link state retransmission list.  This is termed an
	     "implied acknowledgment". */

	  ls_ret = ospf_ls_retransmit_lookup (nbr, lsa);

	  if (ls_ret != NULL)
	    {
	      ospf_ls_retransmit_delete (nbr, ls_ret);

	      /* Delayed acknowledgment sent if advertisement received
		 from Designated Router, otherwise do nothing. */

	      if (oi->status == ISM_Backup)
		if (NBR_IS_DR (nbr))
		  list_add_node (oi->ls_ack, ospf_lsa_dup (lsa));

              DISCARD_LSA (lsa);
	    }
	  else
	    /* Acknowledge the receipt of the LSA by sending a
	       Link State Acknowledgment packet back out the receiving
	       interface. */
	    {
	      ospf_ls_ack_send (nbr, lsa);
	      DISCARD_LSA (lsa);
	    }
	}

      /* The database copy is more recent.  If the database copy
	 has LS age equal to MaxAge and LS sequence number equal to
	 MaxSequenceNumber, simply discard the received LSA without
	 acknowledging it. (In this case, the LSA's LS sequence number is
	 wrapping, and the MaxSequenceNumber LSA must be completely
	 flushed before any new LSA instance can be introduced). */

      else if (LS_AGE (current) == OSPF_LSA_MAX_AGE &&
	       current->data->ls_seqnum == htonl (OSPF_MAX_SEQUENCE_NUMBER))
	{
	  DISCARD_LSA (lsa);
	}
      /* Otherwise, as long as the database copy has not been sent in a
	 Link State Update within the last MinLSArrival seconds, send the
	 database copy back to the sending neighbor, encapsulated within
	 a Link State Update Packet. The Link State Update Packet should
	 be sent directly to the neighbor. In so doing, do not put the
	 database copy of the LSA on the neighbor's link state
	 retransmission list, and do not acknowledge the received (less
	 recent) LSA instance. */
      else
	{
	  /* MinLSArrival Check should be performed. */
	  ospf_ls_upd_send_lsa (nbr, current, OSPF_SEND_PACKET_DIRECT);
	  DISCARD_LSA (lsa);
	}
    }
  
  assert (listcount (lsas) == 0);
  list_delete_all (lsas);
}

/* OSPF Link State Acknowledgment message read -- RFC2328 Section 13.7. */
void
ospf_ls_ack (struct ip *iph, struct ospf_header *ospfh,
	     struct stream *s, struct ospf_interface *oi, u_int16_t size)
{
  struct ospf_neighbor *nbr;

  /* increment statistics. */
  oi->ls_ack_in++;

  nbr = ospf_nbr_lookup_by_addr (oi->nbrs, &iph->ip_src);
  if (nbr == NULL)
    {
      zlog_warn ("Link State Acknowledgment: Unknown Neighbor %s.",
		 inet_ntoa (ospfh->router_id));
      return;
    }

  if (nbr->status < NSM_Exchange)
    {
      zlog_warn ("Link State Acknowledgment: State is less than Exchange.");
      return;
    }

  while (size > 0)
    {
      struct ospf_lsa *lsa, *lsr;

      lsa = ospf_lsa_new ();
      lsa->data = (struct lsa_header *) STREAM_PNT (s);

      /* lsah = (struct lsa_header *) STREAM_PNT (s); */
      size -= OSPF_LSA_HEADER_SIZE;
      stream_forward (s, OSPF_LSA_HEADER_SIZE);

      lsr = ospf_ls_retransmit_lookup (nbr, lsa);

      if (lsr != NULL && lsr->data->ls_seqnum == lsa->data->ls_seqnum)
	ospf_ls_retransmit_delete (nbr, lsr);

      lsa->data = NULL;
      ospf_lsa_free (lsa);
    }
}

int
ospf_recv_packet (struct ospf_interface *oi)
{
  int ret;

  ret = recvfrom (oi->fd, STREAM_DATA (oi->ibuf), STREAM_SIZE (oi->ibuf),
		  0, NULL, 0);

  return ret;
}

struct ospf_interface *
ospf_associate_packet_vl (struct ospf_area *area, struct in_addr router_id)
{
  listnode node;
  struct ospf_vl_data *vl_data;

  LIST_ITERATOR (ospf_top->vlinks, node)
    {
      if ((vl_data = getdata (node)) == NULL)
	continue;

      if (OSPF_AREA_SAME (&vl_data->vl_area, &area) &&
	  IPV4_ADDR_SAME (&vl_data->vl_peer, &router_id))
	{
	  zlog_info ("Z: associating packet with %s",
		     vl_data->vl_oi->ifp->name);

	  if (! CHECK_FLAG (vl_data->vl_oi->ifp->flags, IFF_UP))
	    {
	      zlog_info ("Z: This VL is not up yet, sorry");
	      return NULL;
	    }

	  return vl_data->vl_oi;
	}
    }

  zlog_info ("Z: couldn't find any VL to associate the packet with");
  return NULL;
}

int
ospf_check_area_id (struct ospf_interface *oi, struct ospf_header *ospfh,
		    struct ospf_interface **asoi)
{
  /* Check match the Area ID of the receiving interface. */
  if (OSPF_AREA_SAME (&oi->area, &ospfh))
    return 1;

  /* If Backbone, check Virtual Link relation. */
  if (OSPF_IS_AREA_BACKBONE (ospfh))
    {
      /* We cannot check whether the sending router is an ABR or not
         when we receive first packets, so skip this test */

      (*asoi) = ospf_associate_packet_vl (oi->area, ospfh->router_id);

      if ((*asoi) == NULL)
	{
	  zlog_info ("Z: receive a VL-packet from %s, area %s, "
		     "while VL is not configured",
		     inet_ntoa (ospfh->router_id),
		     inet_ntoa (oi->area->area_id));
	  return 0;
	}

      return 1;
    }

  return 0;
}

/* Unbound socket will accept any Raw IP packets if proto is matched.
   To prevent it, compare src IP address and i/f address with masking
   i/f network mask. */
int
ospf_check_network_mask (struct ospf_interface *oi, struct in_addr ip_src)
{
  struct in_addr mask, me, him;

  if (oi->type == OSPF_IFTYPE_POINTOPOINT ||
      oi->type == OSPF_IFTYPE_VIRTUALLINK)
    return 1;

  masklen2ip (oi->address->prefixlen, &mask);

  me.s_addr = oi->address->u.prefix4.s_addr & mask.s_addr;
  him.s_addr = ip_src.s_addr & mask.s_addr;

 if (IPV4_ADDR_SAME (&me, &him))
   return 1;

 return 0;
}

int
ospf_check_auth (struct ospf_interface *oi, struct ospf_header *ospfh)
{
  int ret = 0;
  struct crypt_key *ck;

  switch (ntohs (ospfh->auth_type))
    {
    case OSPF_AUTH_NULL:
      ret = 1;
      break;
    case OSPF_AUTH_SIMPLE:
      if (!memcmp (oi->auth_simple, ospfh->u.auth_data, OSPF_AUTH_SIMPLE_SIZE))
	ret = 1;
      else
	ret = 0;
      break;
    case OSPF_AUTH_CRYPTOGRAPHIC:
      /* XXX - we are supposed to save the sequence & do a check */

      ck = getdata (oi->auth_crypt->tail);

      /* This is very basic, the digest processing is elsewhere */
      if (ospfh->u.crypt.auth_data_len == OSPF_AUTH_MD5_SIZE && 
          ospfh->u.crypt.key_id == ck->key_id &&
          ntohs (ospfh->length) + OSPF_AUTH_SIMPLE_SIZE <= stream_get_size (oi->ibuf))
        ret = 1;
      else
        ret = 0;
      break;
    default:
      ret = 0;
      break;
    }

  return ret;
}

int
ospf_check_sum (struct ospf_header *ospfh)
{
  u_int32_t ret;
  u_int16_t sum;
  int in_cksum (void *ptr, int nbytes);

  /* clear auth_data for checksum. */
  bzero (ospfh->u.auth_data, OSPF_AUTH_SIMPLE_SIZE);

  /* keep checksum and clear. */
  sum = ospfh->checksum;
  bzero (&ospfh->checksum, sizeof (u_int16_t));

  /* calculate checksum. */
  ret = in_cksum (ospfh, ntohs (ospfh->length));

  if (ret != sum)
    {
      zlog_info ("ospf_check_sum(): checksum mismatch, my %lX, his %X",
		 ret, sum);
      return 0;
    }

  return 1;
}

/* OSPF Header verification. */
int
ospf_verify_header (struct ospf_interface *oi,
		    struct ip *iph, struct ospf_header *ospfh,
		    struct ospf_interface **asoi)
{
  /* check version. */
  if (ospfh->version != OSPF_VERSION)
    {
      zlog_warn ("interface %s: ospf_read version number mismatch.",
		 oi->ifp->name);
      return -1;
    }

  /* Check Area ID. */
  if (!ospf_check_area_id (oi, ospfh, asoi))
    {
      zlog_warn ("interface %s: ospf_read invalid Area ID %s.",
		 oi->ifp->name, inet_ntoa (ospfh->area_id));
      return -1;
    }

  if (*asoi)
    {
      zlog_info ("Z: packet was assoiciated with a VL");
      oi = (*asoi);
    }

  /* Check network mask, Silently discarded. */
  if (! ospf_check_network_mask (oi, iph->ip_src))
    {
      /*
      zlog_warn ("interface %s: ospf_read network address is not same [%s]",
		 oi->ifp->name, inet_ntoa (iph->ip_src));
      */
      return -1;
    }

  /* Check authentication. */
  if (oi->area->auth_type != ntohs (ospfh->auth_type))
    {
      zlog_warn ("interface %s: ospf_read authentication type mismatch.",
		 oi->ifp->name);
      return -1;
    }

  if (! ospf_check_auth (oi, ospfh))
    {
      zlog_warn ("interface %s: ospf_read authentication failed.",
		 oi->ifp->name);
      return -1;
    }

  /* if check sum is invalid, packet is discarded. */
  if (ntohs (ospfh->auth_type) != OSPF_AUTH_CRYPTOGRAPHIC)
    {
      if (! ospf_check_sum (ospfh))
	{
	  zlog_warn ("interface %s: ospf_read packet checksum error %s",
		     oi->ifp->name, inet_ntoa (ospfh->router_id));
	  return -1;
	}
    }
  else
    {
      if (ospfh->checksum != 0)
	return -1;
    }

  return 0;
}

/* Starting point of packet process function. */
int
ospf_read (struct thread *thread)
{
  int ret;
  struct ospf_interface *oi, *asoi = NULL;
  struct ip *iph;
  struct ospf_header *ospfh;
  u_int16_t ip_len, length;

  /* first of all get interface pointer. */
  oi = THREAD_ARG (thread);
  oi->t_read = NULL;

  /* Clear input buffer. */
  stream_reset (oi->ibuf);
  iph = (struct ip *) STREAM_DATA (oi->ibuf);

  /* read OSPF packet. */
  ret = ospf_recv_packet (oi);
  if (ret < 0)
    return ret;

  /* prepare for next packet. */
  OSPF_ISM_READ_ON (oi->t_read, ospf_read, oi->fd);

  /* IP Header dump. */
  /*
  if (ospf_debug_packet & OSPF_DEBUG_RECV)
    ospf_ip_header_dump (oi->ibuf);
  */

  /* get total ip length. */
#ifdef GNU_LINUX
  ip_len = ntohs (iph->ip_len);
#else /* GNU_LINUX */
  ip_len = iph->ip_len;
#endif /* GNU_LINUX */

  /* Packet size check. */
  if (ip_len > oi->ifp->mtu)
    {
      zlog (NULL, LOG_WARNING,
	    "interface %s: ospf_read packet buffer overflow. ip_len %d if MTU %d from %s", oi->ifp->name, ip_len, oi->ifp->mtu, inet_ntoa (iph->ip_src));
      return 0;
    }

  /* Self-originated packet should be discarded silently. */
  if (IPV4_ADDR_SAME (&iph->ip_src, &oi->address->u.prefix4))
    return 0;

  /* XXX Check is this packet comes from the interface.  We will need
     unnumbered link treatment. -- kunihiro */
  {
    struct interface *ifp;

    ifp = if_lookup_address (iph->ip_src);

    if (ifp && ifp != oi->ifp)
      {
	/*
	zlog_info ("Packet from %s read from wrong interface %s",
		   inet_ntoa (iph->ip_src), ifp ? ifp->name : "unknown");
	*/
	return 0;
      }
  }

  /* Adjust size to message length. */
  stream_forward (oi->ibuf, iph->ip_hl * 4);

  /* Get ospf packet header. */
  ospfh = (struct ospf_header *) STREAM_PNT (oi->ibuf);

  /* Show debug receiving packet. */
  if (IS_DEBUG_OSPF_PACKET (ospfh->type - 1, RECV))
    {
      if (IS_DEBUG_OSPF_PACKET (ospfh->type - 1, DETAIL))
	{
	  zlog_info ("-----------------------------------------------------");
	  ospf_packet_dump (oi->ibuf);
	}

      zlog_info ("%s received from [%s] via [%s]",
		 ospf_packet_type_str[ospfh->type],
		 inet_ntoa (ospfh->router_id), oi->ifp->name);

      if (IS_DEBUG_OSPF_PACKET (ospfh->type - 1, DETAIL))
	zlog_info ("-----------------------------------------------------");
    }

  /* if check sum is invalid, packet is discarded. */
  if (ntohs (ospfh->auth_type) == OSPF_AUTH_CRYPTOGRAPHIC)
    {
      if (ospf_check_md5_digest (oi, oi->ibuf, ntohs (ospfh->length)) == 0)
	{
	  zlog_warn ("interface %s: ospf_read md5 authentication failed.",
		     oi->ifp->name);
	  return -1;
	}
    }

  /* Some header verification. */
  ret = ospf_verify_header (oi, iph, ospfh, &asoi);
  if (ret < 0)
    return ret;

  if (asoi == NULL)
    asoi = oi;

  stream_forward (oi->ibuf, OSPF_HEADER_SIZE);

  /* Adjust size to message length. */
  length = ntohs (ospfh->length) - OSPF_HEADER_SIZE;

  /* Read rest of the packet and call each sort of packet routine. */
  switch (ospfh->type)
    {
    case OSPF_MSG_HELLO:
      ospf_hello (iph, ospfh, oi->ibuf, asoi, length);
      break;
    case OSPF_MSG_DB_DESC:
      ospf_db_desc (iph, ospfh, oi->ibuf, asoi, length);
      break;
    case OSPF_MSG_LS_REQ:
      ospf_ls_req (iph, ospfh, oi->ibuf, asoi, length);
      break;
    case OSPF_MSG_LS_UPD:
      ospf_ls_upd (iph, ospfh, oi->ibuf, asoi, length);
      break;
    case OSPF_MSG_LS_ACK:
      ospf_ls_ack (iph, ospfh, oi->ibuf, asoi, length);
      break;
    default:
      zlog (NULL, LOG_WARNING,
	    "interface %s: OSPF packet header type %d is illegal",
	    oi->ifp->name, ospfh->type);
      break;
    }

  return 0;
}

/* Make OSPF header. */
void
ospf_make_header (int type, struct ospf_interface *oi, struct stream *s)
{
  struct ospf_header *ospfh;

  ospfh = (struct ospf_header *) STREAM_DATA (s);

  ospfh->version = (u_char) OSPF_VERSION;
  ospfh->type = (u_char) type;

  ospfh->router_id = ospf_top->router_id;

  ospfh->checksum = 0;
  ospfh->area_id = oi->area->area_id;
  ospfh->auth_type = htons (oi->area->auth_type);

  bzero (ospfh->u.auth_data, OSPF_AUTH_SIMPLE_SIZE);

  ospf_output_forward (s, OSPF_HEADER_SIZE);
}

/* Make Authentication Data. */
int
ospf_make_auth (struct ospf_interface *oi, struct ospf_header *ospfh)
{
  struct crypt_key *ck;

  switch (oi->area->auth_type)
    {
    case OSPF_AUTH_NULL:
      /* bzero (ospfh->u.auth_data, sizeof (ospfh->u.auth_data)); */
      break;
    case OSPF_AUTH_SIMPLE:
      memcpy (ospfh->u.auth_data, oi->auth_simple, OSPF_AUTH_SIMPLE_SIZE);
      break;
    case OSPF_AUTH_CRYPTOGRAPHIC:
      /* If key is not set, then set 0. */
      if (list_isempty (oi->auth_crypt))
	{
	  ospfh->u.crypt.zero = 0;
	  ospfh->u.crypt.key_id = 0;
	  ospfh->u.crypt.auth_data_len = OSPF_AUTH_MD5_SIZE;
	}
      else
	{
	  ck = getdata (oi->auth_crypt->tail);
	  ospfh->u.crypt.zero = 0;
	  ospfh->u.crypt.key_id = ck->key_id;
	  ospfh->u.crypt.auth_data_len = OSPF_AUTH_MD5_SIZE;
	}
      /* note: the seq is done in ospf_make_md5_digest() */
      break;
    default:
      /* bzero (ospfh->u.auth_data, sizeof (ospfh->u.auth_data)); */
      break;
    }

  return 0;
}

/* Fill rest of OSPF header. */
void
ospf_fill_header (struct ospf_interface *oi,
		  struct stream *s, u_int16_t length)
{
  struct ospf_header *ospfh;

  ospfh = (struct ospf_header *) STREAM_DATA (s);

  /* Fill length. */
  ospfh->length = htons (length);

  /* Calculate checksum. */
  if (ntohs (ospfh->auth_type) != OSPF_AUTH_CRYPTOGRAPHIC)
    ospfh->checksum = in_cksum (ospfh, length);
  else
    ospfh->checksum = 0;

  /* Add Authentication Data. */
  ospf_make_auth (oi, ospfh);
}

int
ospf_make_hello (struct ospf_interface *oi, struct stream *s)
{
  struct ospf_neighbor *nbr;
  struct route_node *node;
  u_int16_t length = OSPF_HELLO_MIN_SIZE;
  struct in_addr mask;
  unsigned long p;
  int flag = 0;

  /* Set netmask of interface. */
  if (oi->type != OSPF_IFTYPE_POINTOPOINT &&
      oi->type != OSPF_IFTYPE_VIRTUALLINK)
    masklen2ip (oi->address->prefixlen, &mask);
  else
    bzero ((char *) &mask, sizeof (struct in_addr));
  stream_put_ipv4 (s, mask.s_addr);

  /* Set Hello Interval. */
  stream_putw (s, oi->v_hello);

  zlog_info ("Z: make_hello: options: %x, int: %s",
	     OPTIONS(oi), oi->ifp->name);

  /* Set Options. */
  stream_putc (s, OPTIONS (oi));

  /* Set Router Priority. */
  stream_putc (s, PRIORITY (oi));

  /* Set Router Dead Interval. */
  stream_putl (s, oi->v_wait);

  /* Set Designated Router. */
  stream_put_ipv4 (s, DR (oi).s_addr);

  p = s->putp;

  /* Set Backup Designated Router. */
  stream_put_ipv4 (s, BDR (oi).s_addr);

  /* Add neighbor seen. */
  for (node = route_top (oi->nbrs); node; node = route_next (node))
    {
      if (node->info == NULL)
	continue;

      nbr = (struct ospf_neighbor *) node->info;

      /* ignore 0.0.0.0 node. */
      if (nbr->router_id.s_addr == 0)
	continue;

      /* ignore Down neighbor. */
      if (nbr->status == NSM_Down)
	continue;

      /* this is myself for DR election. */
      if (IPV4_ADDR_SAME (&nbr->router_id, &ospf_top->router_id))
	continue;

      /* Check neighbor is sane? */
      if (nbr->d_router.s_addr != 0 &&
	  IPV4_ADDR_SAME (&nbr->d_router, &oi->address->u.prefix4) &&
	  IPV4_ADDR_SAME (&nbr->bd_router, &oi->address->u.prefix4))
	flag = 1;

      stream_put_ipv4 (s, nbr->router_id.s_addr);
      length += 4;
    }

  /* Let neighbor generate BackupSeen. */
  if (flag == 1)
    {
      stream_set_putp (s, p);
      stream_put_ipv4 (s, 0);
    }

  return length;
}

int
ospf_make_db_desc (struct ospf_interface *oi, struct ospf_neighbor *nbr,
		   struct stream *s)
{
  struct ospf_lsa *lsa;
  u_int16_t length = OSPF_DB_DESC_MIN_SIZE;
  unsigned long pp;
  int i;
  struct new_lsdb *lsdb;
  
  /* Set Interface MTU. */
  if (oi->type == OSPF_IFTYPE_VIRTUALLINK)
    stream_putw (s, 0);
  else
    stream_putw (s, oi->ifp->mtu);

  /* Set Options. */
  stream_putc (s, OPTIONS (oi));

  /* Keep pointer to flags. */
  pp = stream_get_putp (s);
  stream_putc (s, nbr->dd_flags);

  /* Set DD Sequence Number. */
  stream_putl (s, nbr->dd_seqnum);

  if (ospf_db_summary_isempty (nbr))
    return length;

  /* Describe LSA Header from Database Summary List. */
  lsdb = &nbr->db_sum;

  /* while ((node = listhead (nbr->db_summary)) != NULL) */
  for (i = OSPF_MIN_LSA; i < OSPF_MAX_LSA; i++)
    {
      struct route_table *table = lsdb->type[i].db;
      struct route_node *rn;

      for (rn = route_top (table); rn; rn = route_next (rn))
	if ((lsa = rn->info) != NULL)
	  {
	    struct lsa_header *lsah;
	    u_int16_t ls_age;

	    /* DD packet overflows interface MTU. */
	    if (length + OSPF_LSA_HEADER_SIZE > OSPF_PACKET_MAX (oi))
	      break;

	    /* Keep pointer to LS age. */
	    lsah = (struct lsa_header *) (STREAM_DATA (s) +
					  stream_get_putp (s));

	    /* Proceed stream pointer. */
	    stream_put (s, lsa->data, OSPF_LSA_HEADER_SIZE);
	    length += OSPF_LSA_HEADER_SIZE;

	    /* Set LS age. */
	    ls_age = LS_AGE (lsa);
	    lsah->ls_age = htons (ls_age);

	    /* Remove LSA from DB summary list. */
	    new_lsdb_delete (lsdb, lsa);
	  }
    }

  /* There is no LSAs to describe, then set M-bit off. */
  if (IS_SET_DD_MS (nbr->dd_flags) && nbr->status >= NSM_Exchange &&
      ospf_db_summary_isempty (nbr))
    {
      nbr->dd_flags &= ~OSPF_DD_FLAG_M;
      /* Set DD flags again */
      stream_set_putp (s, pp);
      stream_putc (s, nbr->dd_flags);
    }

  return length;
}

#if 1
int
ospf_make_ls_req_func (struct stream *s, u_int16_t *length,
		       unsigned long delta, struct ospf_neighbor *nbr,
		       struct ospf_lsa *lsa)
{
  struct ospf_interface *oi;

  oi = nbr->oi;

  /* LS Request packet overflows interface MTU. */
  if (*length + delta > OSPF_PACKET_MAX(oi))
    return 0;

  stream_putl (s, lsa->data->type);
  stream_put_ipv4 (s, lsa->data->id.s_addr);
  stream_put_ipv4 (s, lsa->data->adv_router.s_addr);
  nbr->ls_req_last = lsa;

  *length += 12;
  return 1;
}

int
ospf_make_ls_req (struct ospf_neighbor *nbr, struct stream *s)
{
  struct ospf_lsa *lsa;
  u_int16_t length = OSPF_LS_REQ_MIN_SIZE;
  unsigned long delta = stream_get_putp(s)+12;
  struct route_table *table;
  struct route_node *rn;
  int i;
  struct new_lsdb *lsdb;

  lsdb = &nbr->ls_req;

  for (i = OSPF_MIN_LSA; i < OSPF_MAX_LSA; i++)
    {
      table = lsdb->type[i].db;
      for (rn = route_top (table); rn; rn = route_next (rn))
	if ((lsa = (rn->info)) != NULL)
	  if (ospf_make_ls_req_func (s, &length, delta, nbr, lsa) == 0)
	    {
	      route_unlock_node (rn);
	      break;
	    }
    }
  return length;
}
#else
int
ospf_make_ls_req (struct ospf_neighbor *nbr, struct stream *s)
{
  struct ospf_interface *oi;
  struct ospf_lsa *lsa;
  listnode node;
  u_int16_t length = OSPF_LS_REQ_MIN_SIZE;
  unsigned long delta = stream_get_putp(s)+12;

  oi = nbr->oi;

  for (node = listhead (nbr->ls_request); node; nextnode (node))
    {
      /* LS Request packet overflows interface MTU. */
      if (length + delta > OSPF_PACKET_MAX(oi))
	break;

      lsa = (struct ospf_lsa *) getdata (node);

      stream_putl (s, lsa->data->type);
      stream_put_ipv4 (s, lsa->data->id.s_addr);
      stream_put_ipv4 (s, lsa->data->adv_router.s_addr);

      length += 12;
    }

  return length;
}
#endif /* NEW_LS_REQUEST */

void
debug_list (list list)
{
  listnode node;

  zlog_info("Z: LIST DEBUG: ------ Start ------");
  zlog_info("Z: LIST DEBUG: list: %x", list);
  zlog_info("Z: LIST DEBUG: list->count: %u", list->count);
  zlog_info("Z: LIST DEBUG: list->head: %x", list->head);
  zlog_info("Z: LIST DEBUG: list->tail: %x", list->tail);
  zlog_info("Z: LIST DEBUG: list->up: %x", list->up);
  zlog_info("Z: LIST DEBUG: ------ List Items ------");

  LIST_ITERATOR(list, node)
    {
      zlog_info("Z: LIST DEBUG: node: %x", node);
      zlog_info("Z: LIST DEBUG: node->next: %x", node->next);
      zlog_info("Z: LIST DEBUG: node->prev: %x", node->prev);
      zlog_info("Z: LIST DEBUG: node->data: %x", node->data);
    }

  zlog_info("Z: LIST DEBUG: ------ Stop -------");
}

int
ospf_make_ls_upd (struct ospf_interface *oi, list update, struct stream *s)
{
  struct ospf_lsa *lsa;
  listnode node;
  u_int16_t length = OSPF_LS_UPD_MIN_SIZE;
  unsigned long delta = stream_get_putp (s);
  unsigned long pp;
  int count = 0;

  zlog_info("Z: ospf_make_ls_upd: Start");
  
  pp = stream_get_putp (s);
  ospf_output_forward (s, 4);

  for (node = listhead (update); node; nextnode (node))
    {
      struct lsa_header *lsah;
      u_int16_t ls_age;

      /* zlog_info("Z: ospf_make_ls_upd: List Iteration"); */

      lsa = getdata (node);
      assert (lsa);
      assert (lsa->data);

      /* Check packet size. */
      /* XXX: Hope to be performed precisely -- takada. */
      if (length + delta + ntohs (lsa->data->length) > OSPF_PACKET_MAX (oi))
	break;

      /* Keep pointer to LS age. */
      lsah = (struct lsa_header *) (STREAM_DATA (s) + stream_get_putp (s));

      /* Put LSA to Link State Request. */
      stream_put (s, lsa->data, ntohs (lsa->data->length));

      /* Set LS age. */
      /* each hop must increment an lsa_age by transmit_delay 
         of OSPF interface */
      ls_age = (LS_AGE (lsa) == OSPF_LSA_MAX_AGE ?
	         OSPF_LSA_MAX_AGE : LS_AGE(lsa) + oi->transmit_delay);
      if (ls_age > OSPF_LSA_MAX_AGE)
	      ls_age = OSPF_LSA_MAX_AGE ;
      lsah->ls_age = htons (ls_age);

      length += ntohs (lsa->data->length);
      count++;
    }

  /* Now set #LSAs. */
  stream_set_putp (s, pp);
  stream_putl (s, count);

  stream_set_putp (s, s->endp);

  zlog_info("Z: ospf_make_ls_upd: Stop");
  return length;
}

int
ospf_make_ls_ack (struct ospf_interface *oi, struct ospf_lsa *d_lsa,
		  struct stream *s)
{
  list rm_list;
  listnode node;
  u_int16_t length = OSPF_LS_ACK_MIN_SIZE;
  unsigned long delta = stream_get_putp(s) + 24;
  struct ospf_lsa *lsa;

  /* Direct Ack. */
  if (d_lsa != NULL)
    {
      stream_put (s, d_lsa->data, OSPF_LSA_HEADER_SIZE);
      length += OSPF_LSA_HEADER_SIZE;
    }
  /* Delayed Ack. */
  else
    {
      rm_list = list_init ();

      for (node = listhead (oi->ls_ack); node; nextnode (node))
	{
	  lsa = getdata (node);
	  assert (lsa);

	  if (length + delta > OSPF_PACKET_MAX (oi))
	    break;

	  stream_put (s, lsa->data, OSPF_LSA_HEADER_SIZE);
	  length += OSPF_LSA_HEADER_SIZE;

	  list_add_node (rm_list, lsa);
	}

      /* Remove LSA from LS-Ack list. */
      for (node = listhead (rm_list); node; nextnode (node))
	{
	  lsa = (struct ospf_lsa *) getdata (node);

	  ospf_lsa_free (lsa);
          zlog_info("Z: ospf_lsa_free() in ospf_make_ls_ack(): %x", lsa);

	  list_delete_by_val (oi->ls_ack, lsa);
	}

      list_delete_all (rm_list);
    }

  return length;
}

/* Send OSPF Hello. */
void
ospf_hello_send (struct ospf_interface *oi)
{
  struct ospf_packet *op;
  u_int16_t length = OSPF_HEADER_SIZE;

  /* If this is passive interface, do not send OSPF Hello. */
  if (oi->passive_interface == OSPF_IF_PASSIVE)
    return;

  op = ospf_packet_new (oi->ifp->mtu);

  /* Prepare OSPF common header. */
  ospf_make_header (OSPF_MSG_HELLO, oi, op->s);

  /* Prepare OSPF Hello body. */
  length += ospf_make_hello (oi, op->s);

  /* Fill OSPF header. */
  ospf_fill_header (oi, op->s, length);

  /* Set packet length. */
  op->length = length;

  /* Decide destination address. */
  if (oi->type == OSPF_IFTYPE_VIRTUALLINK)
    op->dst.s_addr = oi->vl_data->peer_addr.s_addr;
  else 
    op->dst.s_addr = htonl (OSPF_ALLSPFROUTERS);

  /* Add packet to the interface output queue. */
  ospf_packet_add (oi, op);

  /* Hook thread to write packet. */
  OSPF_ISM_WRITE_ON (oi->t_write, ospf_write, oi->fd);
}

/* Send OSPF Database Description. */
void
ospf_db_desc_send (struct ospf_neighbor *nbr)
{
  struct ospf_interface *oi;
  struct ospf_packet *op;
  u_int16_t length = OSPF_HEADER_SIZE;

  oi = nbr->oi;
  op = ospf_packet_new (oi->ifp->mtu);

  /* Prepare OSPF common header. */
  ospf_make_header (OSPF_MSG_DB_DESC, oi, op->s);

  /* Prepare OSPF Database Description body. */
  length += ospf_make_db_desc (oi, nbr, op->s);

  /* Fill OSPF header. */
  ospf_fill_header (oi, op->s, length);

  /* Set packet length. */
  op->length = length;

  /* Decide destination address. */
  op->dst = nbr->address.u.prefix4;

  /* Add packet to the interface output queue. */
  ospf_packet_add (oi, op);

  /* Hook thread to write packet. */
  OSPF_ISM_WRITE_ON (oi->t_write, ospf_write, oi->fd);

  /* Remove old DD packet, then copy new one and keep in neighbor structure. */
  if (nbr->last_send)
    ospf_packet_free (nbr->last_send);
  nbr->last_send = ospf_packet_dup (op);
}

/* Re-send Database Description. */
void
ospf_db_desc_resend (struct ospf_neighbor *nbr)
{
  struct ospf_interface *oi;

  oi = nbr->oi;

  /* Add packet to the interface output queue. */
  ospf_packet_add (oi, ospf_packet_dup (nbr->last_send));

  /* Hook thread to write packet. */
  OSPF_ISM_WRITE_ON (oi->t_write, ospf_write, oi->fd);
}

/* Send Link State Request. */
void
ospf_ls_req_send (struct ospf_neighbor *nbr)
{
  struct ospf_interface *oi;
  struct ospf_packet *op;
  u_int16_t length = OSPF_HEADER_SIZE;

  oi = nbr->oi;
  op = ospf_packet_new (oi->ifp->mtu);

  /* Prepare OSPF common header. */
  ospf_make_header (OSPF_MSG_LS_REQ, oi, op->s);

  /* Prepare OSPF Link State Request body. */
  length += ospf_make_ls_req (nbr, op->s);
  if (length == OSPF_HEADER_SIZE)
    {
      ospf_packet_free (op);
      return;
    }

  /* Fill OSPF header. */
  ospf_fill_header (oi, op->s, length);

  /* Set packet length. */
  op->length = length;

  /* Decide destination address. */
  op->dst = nbr->address.u.prefix4;

  /* Add packet to the interface output queue. */
  ospf_packet_add (oi, op);

  /* Hook thread to write packet. */
  OSPF_ISM_WRITE_ON (oi->t_write, ospf_write, oi->fd);

  /* Add Link State Request Retransmission Timer. */
  OSPF_NSM_TIMER_ON (nbr->t_ls_req, ospf_ls_req_timer, nbr->v_ls_req);
}

/* Send Link State Update with an LSA. */
void
ospf_ls_upd_send_lsa (struct ospf_neighbor *nbr, struct ospf_lsa *lsa,
		      int flag)
{
  list update;

  update = list_init ();

  list_add_node (update, lsa);
  ospf_ls_upd_send (nbr, update, flag);

  list_free (update);
}

/* Send Link State Update. */
void
ospf_ls_upd_send (struct ospf_neighbor *nbr, list update, int flag)
{
  struct ospf_interface *oi;
  struct ospf_packet *op;
  u_int16_t length = OSPF_HEADER_SIZE;

  oi = nbr->oi;
  op = ospf_packet_new (oi->ifp->mtu);

  /* Prepare OSPF common header. */
  ospf_make_header (OSPF_MSG_LS_UPD, oi, op->s);

  /* Prepare OSPF Link State Update body. */
  length += ospf_make_ls_upd (oi, update, op->s);

  /* Fill OSPF header. */
  ospf_fill_header (oi, op->s, length);

  /* Set packet length. */
  op->length = length;

  /* Decide destination address. */
  if (oi->type == OSPF_IFTYPE_VIRTUALLINK)
    op->dst = oi->vl_data->peer_addr;
  else if (flag == OSPF_SEND_PACKET_DIRECT)
    op->dst = nbr->address.u.prefix4;
  else if (oi->status == ISM_DR || oi->status == ISM_Backup)
    op->dst.s_addr = htonl (OSPF_ALLSPFROUTERS);
  else if ((oi->type == OSPF_IFTYPE_POINTOPOINT) 
	   && (flag == OSPF_SEND_PACKET_INDIRECT))
    op->dst.s_addr = htonl (OSPF_ALLSPFROUTERS);
  else
    op->dst.s_addr = htonl (OSPF_ALLDROUTERS);

  /* Add packet to the interface output queue. */
  ospf_packet_add (oi, op);

  /* Hook thread to write packet. */
  OSPF_ISM_WRITE_ON (oi->t_write, ospf_write, oi->fd);
}

/* Send Link State Acknowledgment directly. */
void
ospf_ls_ack_send (struct ospf_neighbor *nbr, struct ospf_lsa *lsa)
{
  struct ospf_interface *oi;
  struct ospf_packet *op;
  u_int16_t length = OSPF_HEADER_SIZE;

  oi = nbr->oi;
  op = ospf_packet_new (oi->ifp->mtu);

  /* Prepare OSPF common header. */
  ospf_make_header (OSPF_MSG_LS_ACK, oi, op->s);

  /* Prepare OSPF Link State Acknowledgment body. */
  length += ospf_make_ls_ack (oi, lsa, op->s);

  /* Fill OSPF header. */
  ospf_fill_header (oi, op->s, length);

  /* Set packet length. */
  op->length = length;

  /* Decide destination address. */
  op->dst = nbr->address.u.prefix4;

  /* Add packet to the interface output queue. */
  ospf_packet_add (oi, op);

  /* Hook thread to write packet. */
  OSPF_ISM_WRITE_ON (oi->t_write, ospf_write, oi->fd);
}

/* Send Link State Acknowledgment delayed. */
void
ospf_ls_ack_send_delayed (struct ospf_interface *oi)
{
  struct ospf_packet *op;
  u_int16_t length = OSPF_HEADER_SIZE;

  op = ospf_packet_new (oi->ifp->mtu);

  /* Prepare OSPF common header. */
  ospf_make_header (OSPF_MSG_LS_ACK, oi, op->s);

  /* Prepare OSPF Link State Acknowledgment body. */
  length += ospf_make_ls_ack (oi, NULL, op->s);

  /* Fill OSPF header. */
  ospf_fill_header (oi, op->s, length);

  /* Set packet length. */
  op->length = length;

  /* Decide destination address. */
  if (oi->type == OSPF_IFTYPE_VIRTUALLINK)
    op->dst.s_addr = oi->vl_data->peer_addr.s_addr;
  else if (oi->status == ISM_DR || oi->status == ISM_Backup)
    op->dst.s_addr = htonl (OSPF_ALLSPFROUTERS);
  else if (oi->type == OSPF_IFTYPE_POINTOPOINT)
    op->dst.s_addr = htonl (OSPF_ALLSPFROUTERS);
  else
    op->dst.s_addr = htonl (OSPF_ALLDROUTERS);

  /* Add packet to the interface output queue. */
  ospf_packet_add (oi, op);

  /* Hook thread to write packet. */
  OSPF_ISM_WRITE_ON (oi->t_write, ospf_write, oi->fd);
}
