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

#ifndef OSPF6_MESG_H
#define OSPF6_MESG_H

/* Message Definition */

#define IS_OVER_MTU(message,mtu,addsize) \
          (iov_totallen(message)+(addsize) >= \
            (mtu)-sizeof(struct ospf6_header))

/* Type */
#define MSGT_NONE                 0x0  /* Unknown message */
#define MSGT_UNKNOWN              0x0
#define MSGT_HELLO                0x1  /* Discover/maintain neighbors */
#define MSGT_DATABASE_DESCRIPTION 0x2  /* Summarize database contents */
#define MSGT_DBDESC               0x2  /* Summarize database contents */
#define MSGT_LINKSTATE_REQUEST    0x3  /* Database download */
#define MSGT_LSREQ                0x3  /* Database download */
#define MSGT_LINKSTATE_UPDATE     0x4  /* Database update */
#define MSGT_LSUPDATE             0x4  /* Database update */
#define MSGT_LINKSTATE_ACK        0x5  /* Flooding acknowledgment */
#define MSGT_LSACK                0x5  /* Flooding acknowledgment */
#define MSGT_MAX                  0x6

/* OSPFv3 packet header */
struct ospf6_header
{
  u_char    version;
  u_char    type;
  u_int16_t len;
  u_int32_t router_id;
  u_int32_t area_id;
  u_int16_t cksum;
  u_char    instance_id;
  u_char    reserved;
};

/* HELLO */
#define MAXLISTEDNBR     64
struct ospf6_hello
{
  u_int32_t interface_id;
  u_char    rtr_pri;
  u_char    options[3];
  u_int16_t hello_interval;
  u_int16_t router_dead_interval;
  u_int32_t dr;
  u_int32_t bdr;
};

/* new Database Description (name changed) */
struct ospf6_dbdesc
{
  u_char    mbz1;
  u_char    options[3];
  u_int16_t ifmtu;
  u_char    mbz2;
  u_char    bits;
  u_int32_t seqnum;
  /* Followed by LSAs */
};
#define DEFAULT_INTERFACE_MTU 1500

#define DD_IS_MSBIT_SET(x) ((x) & (1 << 0))
#define DD_MSBIT_SET(x) ((x) |= (1 << 0))
#define DD_MSBIT_CLEAR(x) ((x) &= ~(1 << 0))
#define DD_IS_MBIT_SET(x) ((x) & (1 << 1))
#define DD_MBIT_SET(x) ((x) |= (1 << 1))
#define DD_MBIT_CLEAR(x) ((x) &= ~(1 << 1))
#define DD_IS_IBIT_SET(x) ((x) & (1 << 2))
#define DD_IBIT_SET(x) ((x) |= (1 << 2))
#define DD_IBIT_CLEAR(x) ((x) &= ~(1 << 2))

#define DDBIT_IS_MASTER(x)   ((x) &   (1 << 0))
#define DDBIT_IS_SLAVE(x)  (!((x) &   (1 << 0)))
#define DDBIT_SET_MASTER(x)  ((x) |=  (1 << 0))
#define DDBIT_SET_SLAVE(x)   ((x) |= ~(1 << 0))
#define DDBIT_IS_MORE(x)     ((x) &   (1 << 1))
#define DDBIT_SET_MORE(x)    ((x) |=  (1 << 1))
#define DDBIT_CLR_MORE(x)    ((x) |= ~(1 << 1))
#define DDBIT_IS_INITIAL(x)  ((x) &   (1 << 2))
#define DDBIT_SET_INITIAL(x) ((x) |=  (1 << 2))
#define DDBIT_CLR_INITIAL(x) ((x) |= ~(1 << 2))

/* Link State Request */
struct ospf6_lsreq
{
  u_int16_t lsreq_age_zero;     /* MBZ */
  u_int16_t lsreq_type;         /* LS type */
  u_int32_t lsreq_id;           /* Link State ID */
  u_int32_t lsreq_advrtr;       /* Advertising Router */
};

/* Link State Update */
struct ospf6_lsupdate
{
  u_int32_t lsupdate_num;
};

/* Link State Acknowledgement will include only LSA header.*/

/* Function Prototypes */
struct ospf6_lsa_hdr *
ospf6_message_get_lsa_hdr (struct iovec *);

int ospf6_receive (struct thread *);
int ospf6_receive_new (struct thread *);

int ospf6_send_hello (struct thread *);
int ospf6_send_dbdesc_retrans (struct thread *);
int ospf6_send_dbdesc (struct thread *);
int ospf6_send_lsreq (struct thread *);
int ospf6_send_lsupdate_retrans (struct thread *);
int ospf6_send_lsack_delayed (struct thread *);

void ospf6_message_send (unsigned char, struct iovec *,
                         struct in6_addr *, u_int);

#endif /* OSPF6_MESG_H */

