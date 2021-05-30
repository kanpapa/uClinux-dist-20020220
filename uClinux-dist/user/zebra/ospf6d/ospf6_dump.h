/*
 * Logging function
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

#ifndef OSPF6_DUMP_H
#define OSPF6_DUMP_H

#include "ospf6_lsa.h"
#include "ospf6_mesg.h"

struct ospf6_log
{
  void (*err)       (const char *format, ...);
  void (*warn)      (const char *format, ...);
  void (*notice)    (const char *format, ...);
  void (*interface) (const char *format, ...);
  void (*neighbor)  (const char *format, ...);
  void (*ism)       (const char *format, ...);
  void (*nsm)       (const char *format, ...);
  void (*lsa)       (const char *format, ...);
  void (*lsdb)      (const char *format, ...);
  void (*dbex)      (const char *format, ...);
  void (*packet)    (const char *format, ...);
  void (*network)   (const char *format, ...);
  void (*spf)       (const char *format, ...);
  void (*rtable)    (const char *format, ...);
  void (*zebra)     (const char *format, ...);
  void (*debug)     (const char *format, ...);
  void (*pointer)   (const char *format, ...);
};

/* Global logging buffer */
extern char strbuf[1024];

/* Logging function switch */
extern struct ospf6_log o6log;

/* Strings for logging */
extern char   *ifs_name[];
extern char   *nbs_name[];
extern char   *mesg_name[];
extern char   *lstype_name[];
extern char   *rlsatype_name[];

#define typeindex(x)     (((ntohs (x)) & 0x000f) - 1)

/* Function Prototypes */
char *print_lsreq (struct ospf6_lsreq *);
char *print_ls_reference (struct ospf6_lsa_hdr *);
char *print_lsahdr (struct ospf6_lsa_hdr *);
char *inet4str(unsigned long);
void ospf6_log_init ();

/* new */
extern unsigned char ospf6_message_hello_dump;
extern unsigned char ospf6_message_dbdesc_dump;
extern unsigned char ospf6_message_lsreq_dump;
extern unsigned char ospf6_message_lsupdate_dump;
extern unsigned char ospf6_message_lsack_dump;
extern unsigned char ospf6_neighbor_dump;
extern unsigned char ospf6_interface_dump;
extern unsigned char ospf6_area_dump;
extern unsigned char ospf6_lsa_dump;
extern unsigned char ospf6_zebra_dump;
extern unsigned char ospf6_config_dump;
extern unsigned char ospf6_dbex_dump;
extern unsigned char ospf6_spf_dump;
extern unsigned char ospf6_route_dump;

#define IS_OSPF6_DUMP_HELLO (ospf6_message_hello_dump)
#define IS_OSPF6_DUMP_DBDESC (ospf6_message_dbdesc_dump)
#define IS_OSPF6_DUMP_LSREQ (ospf6_message_lsreq_dump)
#define IS_OSPF6_DUMP_LSUPDATE (ospf6_message_lsupdate_dump)
#define IS_OSPF6_DUMP_LSACK (ospf6_message_lsack_dump)
#define IS_OSPF6_DUMP_MESSAGE(x) (is_ospf6_message_dump(x))
#define IS_OSPF6_DUMP_MESSAGE_ALL (IS_OSPF6_DUMP_HELLO && \
                                   IS_OSPF6_DUMP_DBDESC && \
                                   IS_OSPF6_DUMP_LSREQ && \
                                   IS_OSPF6_DUMP_LSUPDATE && \
                                   IS_OSPF6_DUMP_LSACK)

#define IS_OSPF6_DUMP_NEIGHBOR (ospf6_neighbor_dump)
#define IS_OSPF6_DUMP_INTERFACE (ospf6_interface_dump)
#define IS_OSPF6_DUMP_AREA (ospf6_area_dump)
#define IS_OSPF6_DUMP_LSA (ospf6_lsa_dump)
#define IS_OSPF6_DUMP_ZEBRA (ospf6_zebra_dump)
#define IS_OSPF6_DUMP_CONFIG (ospf6_config_dump)
#define IS_OSPF6_DUMP_DBEX (ospf6_dbex_dump)
#define IS_OSPF6_DUMP_SPF (ospf6_spf_dump)
#define IS_OSPF6_DUMP_ROUTE (ospf6_route_dump)

char *ospf6_message_name (unsigned char);
void ospf6_dump_message (struct iovec *);
void ospf6_dump_lsa_hdr (struct ospf6_lsa_hdr *);
void ospf6_dump_lsa (struct ospf6_lsa *);
void ospf6_debug_init ();
int is_ospf6_message_dump(char);
void ospf6_dump_ddbit (unsigned char, char *, size_t);

#endif /* OSPF6_DUMP_H */

