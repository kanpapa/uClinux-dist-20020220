/*
 * OSPFd dump routine.
 * Copyright (C) 1999 Toshiaki Takada
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

#ifndef _ZEBRA_OSPF_DUMP_H
#define _ZEBRA_OSPF_DUMP_H

/* Debug Flags. */
#define OSPF_DEBUG_HELLO	0x01
#define OSPF_DEBUG_DB_DESC	0x02
#define OSPF_DEBUG_LS_REQ	0x04
#define OSPF_DEBUG_LS_UPD	0x08
#define OSPF_DEBUG_LS_ACK	0x10
#define OSPF_DEBUG_ALL		0x1f

#define OSPF_DEBUG_SEND		0x01
#define OSPF_DEBUG_RECV		0x02
#define OSPF_DEBUG_SEND_RECV    0x03
#define OSPF_DEBUG_DETAIL	0x04

#define OSPF_DEBUG_ISM_STATUS	0x01
#define OSPF_DEBUG_ISM_EVENTS	0x02
#define OSPF_DEBUG_ISM_TIMERS	0x04
#define OSPF_DEBUG_ISM		0x07
#define OSPF_DEBUG_NSM_STATUS	0x01
#define OSPF_DEBUG_NSM_EVENTS	0x02
#define OSPF_DEBUG_NSM_TIMERS   0x04
#define OSPF_DEBUG_NSM		0x07

#define OSPF_DEBUG_LSA_GENERATE 0x01
#define OSPF_DEBUG_LSA_FLOODING	0x02
#define OSPF_DEBUG_LSA		0x03

#define OSPF_DEBUG_ZEBRA_INTERFACE     0x01
#define OSPF_DEBUG_ZEBRA_REDISTRIBUTE  0x02
#define OSPF_DEBUG_ZEBRA	       0x03

/* Macro for setting debug option. */
#define CONF_DEBUG_PACKET_ON(a, b)	    conf_debug_ospf_packet[a] |= (b)
#define CONF_DEBUG_PACKET_OFF(a, b)	    conf_debug_ospf_packet[a] &= ~(b)
#define TERM_DEBUG_PACKET_ON(a, b)	    term_debug_ospf_packet[a] |= (b)
#define TERM_DEBUG_PACKET_OFF(a, b)	    term_debug_ospf_packet[a] &= ~(b)
#define DEBUG_PACKET_ON(a, b) \
    do { \
      CONF_DEBUG_PACKET_ON(a, b); \
      TERM_DEBUG_PACKET_ON(a, b); \
    } while (0)
#define DEBUG_PACKET_OFF(a, b) \
    do { \
      CONF_DEBUG_PACKET_OFF(a, b); \
      TERM_DEBUG_PACKET_OFF(a, b); \
    } while (0)

#define CONF_DEBUG_ON(a, b)	 conf_debug_ospf_ ## a |= (OSPF_DEBUG_ ## b)
#define CONF_DEBUG_OFF(a, b)	 conf_debug_ospf_ ## a &= ~(OSPF_DEBUG_ ## b)
#define TERM_DEBUG_ON(a, b)	 term_debug_ospf_ ## a |= (OSPF_DEBUG_ ## b)
#define TERM_DEBUG_OFF(a, b)	 term_debug_ospf_ ## a &= ~(OSPF_DEBUG_ ## b)
#define DEBUG_ON(a, b) \
     do { \
       CONF_DEBUG_ON(a, b); \
       TERM_DEBUG_ON(a, b); \
     } while (0)
#define DEBUG_OFF(a, b) \
     do { \
       CONF_DEBUG_OFF(a, b); \
       TERM_DEBUG_OFF(a, b); \
     } while (0)

/* Macro for checking debug option. */
#define IS_DEBUG_OSPF_PACKET(a, b) \
	(term_debug_ospf_packet[a] & OSPF_DEBUG_ ## b)
#define IS_DEBUG_OSPF(a, b) \
	(term_debug_ospf_ ## a & OSPF_DEBUG_ ## b)

#define IS_CONF_DEBUG_OSPF_PACKET(a, b) \
	(conf_debug_ospf_packet[a] & OSPF_DEBUG_ ## b)
#define IS_CONF_DEBUG_OSPF(a, b) \
	(conf_debug_ospf_ ## a & OSPF_DEBUG_ ## b)

/* Message Strings. */
extern char *ospf_packet_type_str[];
extern char *ospf_lsa_type_str[];

/* Prototypes. */
void ospf_nbr_state_message (struct ospf_neighbor *, char *, size_t);
char *ospf_option_dump (u_char, char *, size_t);
char *ospf_timer_dump (struct thread *, char *, size_t);
void ospf_ip_header_dump (struct stream *);
void ospf_packet_dump (struct stream *);
void ospf_lsa_header_dump (struct lsa_header *);
void debug_init ();

#endif /* _ZEBRA_OSPF_DUMP_H */
