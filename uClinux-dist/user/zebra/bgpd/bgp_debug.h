/* BGP message debug header.
 * Copyright (C) 1996, 97, 98 Kunihiro Ishiguro
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

#ifndef _ZEBRA_BGP_DEBUG_H
#define _ZEBRA_BGP_DEBUG_H

#define IS_SET(x, y)  ((x) & (y))

/* sort of packet direction */
#define DUMP_ON        1
#define DUMP_SEND      2
#define DUMP_RECV      4

/* for dump_update */
#define DUMP_WITHDRAW  8
#define DUMP_NLRI     16

/* dump detail */
#define DUMP_DETAIL   32

extern int dump_open;
extern int dump_update;
extern int dump_keepalive;
extern int dump_notify;

extern int Debug_Event;
extern int Debug_Keepalive;
extern int Debug_Update;
extern int Debug_Radix;

#define	NLRI	 1
#define	WITHDRAW 2
#define	NO_OPT	 3
#define	SEND	 4
#define	RECV	 5
#define	DETAIL	 6

/* Prototypes. */
void bgp_debug_init ();
void bgp_packet_dump (struct stream *);

int debug (unsigned int option);

unsigned long bgp_debug_fsm;
unsigned long bgp_debug_events;
unsigned long bgp_debug_packet;

#define BGP_DEBUG_FSM                 0x01
#define BGP_DEBUG_EVENTS              0x01
#define BGP_DEBUG_PACKET              0x01

#define BGP_DEBUG_PACKET_SEND         0x01
#define BGP_DEBUG_PACKET_SEND_DETAIL  0x02

#define BGP_DEBUG_PACKET_RECV         0x01
#define BGP_DEBUG_PACKET_RECV_DETAIL  0x02

#define DEBUG_ON(a, b)		(bgp_debug_ ## a |= (BGP_DEBUG_ ## b))
#define DEBUG_OFF(a, b)		(bgp_debug_ ## a &= ~(BGP_DEBUG_ ## b))

#define BGP_DEBUG(a, b)		(bgp_debug_ ## a & BGP_DEBUG_ ## b)

extern char *bgp_type_str[];

void bgp_dump_attr (struct peer *, struct attr *, char *, size_t);

#endif /* _ZEBRA_BGP_DEBUG_H */
