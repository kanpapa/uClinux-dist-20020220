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

#include "ospf6d.h"

/* Global logging buf */
char strbuf[1024];

/* Logging function switch */
struct ospf6_log o6log;

/* Strings for logging */
char *ifs_name[] =
{
  "None",
  "Down",
  "Loopback",
  "Waiting",
  "PtoP",
  "DROther",
  "BDR",
  "DR",
  NULL
};

char *nbs_name[] =
{
  "None",
  "Down",
  "Attempt",
  "Init",
  "Twoway",
  "ExStart",
  "ExChange",
  "Loading",
  "Full",
  NULL
};

char *mesg_name[] = 
{
  "None",
  "Hello",
  "DBDesc",
  "LSReq",
  "LSUpdate",
  "LSAck",
  NULL
};

char *lstype_name[] =
{
  "Router-LSA",
  "Network-LSA",
  "Inter-Area-Prefix-LSA",
  "Inter-Area-Router-LSA",
  "AS-External-LSA",
  "Group-Membership-LSA",
  "Type-7-LSA",
  "Link-LSA",
  "Intra-Area-Prefix-LSA",
  NULL
};

char *rlsatype_name[] =
{
  "PtoP",
  "Transit",
  "Stub",
  "virtual",
  NULL
};

char *print_lsreq (struct ospf6_lsreq *lsreq)
{
  static char buf[256];
  char advrtr[64], id[64];
  char *type, unknown[64];

  inet_ntop (AF_INET, &lsreq->lsreq_advrtr, advrtr, sizeof (advrtr));
  snprintf (id, sizeof (id), "%u", (u_int32_t)ntohl (lsreq->lsreq_id));
  switch (ntohs (lsreq->lsreq_type))
    {
      case LST_ROUTER_LSA:
      case LST_NETWORK_LSA:
      case LST_LINK_LSA:
      case LST_INTRA_AREA_PREFIX_LSA:
      case LST_AS_EXTERNAL_LSA:
        type = lstype_name[typeindex(lsreq->lsreq_type)];
        break;
      default:
        snprintf (unknown, sizeof (unknown),
                  "Unknown(%#x)", ntohs (lsreq->lsreq_type));
        type = unknown;
        break;
    }

  snprintf (buf, sizeof (buf), "%s[id:%s,adv:%s]",
            type, id, advrtr);
  return buf;
}

char *print_ls_reference (struct ospf6_lsa_hdr *lsh)
{
  static char buf[256];
  char advrtr[64], id[64];
  char *type, unknown[64];

  inet_ntop (AF_INET, &lsh->lsh_advrtr, advrtr, sizeof (advrtr));
  snprintf (id, sizeof (id), "%u", (u_int32_t)ntohl (lsh->lsh_id));
  switch (ntohs (lsh->lsh_type))
    {
      case LST_ROUTER_LSA:
      case LST_NETWORK_LSA:
      case LST_LINK_LSA:
      case LST_INTRA_AREA_PREFIX_LSA:
      case LST_AS_EXTERNAL_LSA:
        type = lstype_name[typeindex(lsh->lsh_type)];
        break;
      default:
        snprintf (unknown, sizeof (unknown),
                  "Unknown(%#x)", ntohs (lsh->lsh_type));
        type = unknown;
        break;
    }

  snprintf (buf, sizeof (buf), "%s[id:%s,adv:%s]",
            type, id, advrtr);
  return buf;
}

char *print_lsahdr (struct ospf6_lsa_hdr *lsh)
{
  static char buf[256];
  char advrtr[64], id[64], seqnum[64];
  char *type, unknown[64];

  inet_ntop (AF_INET, &lsh->lsh_advrtr, advrtr, sizeof (advrtr));
  snprintf (id, sizeof (id), "%u", (u_int32_t)ntohl (lsh->lsh_id));
  snprintf (seqnum, sizeof (seqnum), "%x", (u_int32_t)ntohl (lsh->lsh_seqnum));
  switch (ntohs (lsh->lsh_type))
    {
      case LST_ROUTER_LSA:
      case LST_NETWORK_LSA:
      case LST_LINK_LSA:
      case LST_INTRA_AREA_PREFIX_LSA:
      case LST_AS_EXTERNAL_LSA:
        type = lstype_name[typeindex(lsh->lsh_type)];
        break;
      default:
        snprintf (unknown, sizeof (unknown),
                  "Unknown(%#x)", ntohs (lsh->lsh_type));
        type = unknown;
        break;
    }

  snprintf (buf, sizeof (buf), "%s[id:%s,adv:%s,seq:%s]",
            type, id, advrtr, seqnum);
  return buf;
}

char *
inet4str (unsigned long id)
{
  inet_ntop (AF_INET, &id, strbuf, sizeof (strbuf));
  return(strbuf);
}

void
o6log_err (const char *format, ...)
{
  va_list args;

  va_start (args, format);
  zlog (NULL, LOG_ERR, format, args);
  return;
}

void
o6log_warn (const char *format, ...)
{
  va_list args;

  va_start (args, format);
  zlog (NULL, LOG_WARNING, format, args);
  return;
}

void
o6log_notice (const char *format, ...)
{
  va_list args;

  va_start (args, format);
  zlog (NULL, LOG_NOTICE, format, args);
  return;
}

void
o6log_off (const char *format, ...)
{
  return;
}

void
o6log_on (const char *format, ...)
{
  va_list args;

  va_start (args, format);
  zlog (NULL, LOG_INFO, format, args);
  return;
}

void
ospf6_log_init ()
{
  int flag = 0;

  if (!daemon_mode)
    flag |= ZLOG_STDOUT;

  zlog_default = openzlog (progname, flag, ZLOG_OSPF6,
                 LOG_CONS|LOG_NDELAY|LOG_PERROR|LOG_PID,
                 LOG_DAEMON);

  /* default logging */
  o6log.interface = o6log_off;
  o6log.neighbor = o6log_off;
  o6log.ism = o6log_off;
  o6log.nsm = o6log_off;
  o6log.lsa = o6log_off;
  o6log.lsdb = o6log_off;
  o6log.dbex = o6log_off;
  o6log.network = o6log_off;
  o6log.packet = o6log_off;
  o6log.spf = o6log_off;
  o6log.rtable = o6log_off;
  o6log.zebra = o6log_off;
  /* for debug */
  o6log.debug = o6log_off;
  o6log.pointer = o6log_off;
  return;
}


/* new */
unsigned char ospf6_message_hello_dump;
unsigned char ospf6_message_dbdesc_dump;
unsigned char ospf6_message_lsreq_dump;
unsigned char ospf6_message_lsupdate_dump;
unsigned char ospf6_message_lsack_dump;
unsigned char ospf6_neighbor_dump;
unsigned char ospf6_interface_dump;
unsigned char ospf6_area_dump;
unsigned char ospf6_lsa_dump;
unsigned char ospf6_zebra_dump;
unsigned char ospf6_config_dump;
unsigned char ospf6_dbex_dump;
unsigned char ospf6_spf_dump;
unsigned char ospf6_route_dump;

char *
ospf6_message_name (unsigned char type)
{
  if (type >= MSGT_MAX)
    type = 0;
  return mesg_name [type];
}

static void
ospf6_dump_hello (struct iovec *message)
{
  struct ospf6_hello *hello;
  char dr_str[16], bdr_str[16];

  hello = (struct ospf6_hello *) (*message).iov_base;

  inet_ntop (AF_INET, &hello->dr, dr_str, sizeof (dr_str));
  inet_ntop (AF_INET, &hello->bdr, bdr_str, sizeof (bdr_str));

  zlog_info ("  Hello: IFID:%lu Priority:%d Option:%s",
             ntohl (hello->interface_id), hello->rtr_pri, "xxx");
  zlog_info ("         HelloInterval:%hu Deadinterval:%hu",
             ntohs (hello->hello_interval),
             ntohs (hello->router_dead_interval));
  zlog_info ("         DR:%s BDR:%s", dr_str, bdr_str);
}

static void
ospf6_dump_dbdesc (struct iovec *message)
{
  struct ospf6_dbdesc *dbdesc;
  char dbdesc_bit[4], *p;

  dbdesc = (struct ospf6_dbdesc *) (*message).iov_base;
  p = dbdesc_bit;

  /* Initialize bit */
  if (DD_IS_IBIT_SET (dbdesc->bits))
    *p++ = 'I';
  /* More bit */
  if (DD_IS_MBIT_SET (dbdesc->bits))
    *p++ = 'M';
  /* Master/Slave bit */
  if (DD_IS_MSBIT_SET (dbdesc->bits))
    *p++ = 'm';
  else
    *p++ = 's';
  *p = '\0';

  zlog_info ("  DbDesc: Option:%s IFMTU:%hu Bit:%s",
             "xxx", ntohs (dbdesc->ifmtu), dbdesc_bit);
  zlog_info ("          SequeceNum:%lu", ntohl (dbdesc->seqnum));
}

static void
ospf6_dump_lsreq (struct iovec *message)
{
  int i;
  zlog_info ("  LSReq:");
  for (i = 1; message[i].iov_base; i++)
    zlog_info ("        %s",
               print_lsreq ((struct ospf6_lsreq *) message[i].iov_base));
}

static void
ospf6_dump_lsupdate (struct iovec *message)
{
  int i;
  struct ospf6_lsupdate *lsupdate;

  lsupdate = (struct ospf6_lsupdate *) (*message).iov_base;
  zlog_info ("  LSUpdate: #%lu", ntohl (lsupdate->lsupdate_num));
  for (i = 1; message[i].iov_base; i++)
    ospf6_dump_lsa_hdr ((struct ospf6_lsa_hdr *) message[i].iov_base);
}

static void
ospf6_dump_lsack (struct iovec *message)
{
  int i;
  zlog_info ("  LSAck:");
  for (i = 0; message[i].iov_base; i++)
    ospf6_dump_lsa_hdr ((struct ospf6_lsa_hdr *) message[i].iov_base);
}

void
ospf6_dump_message (struct iovec *message)
{
  struct ospf6_header *o6hdr;
  char rtrid_str[16], areaid_str[16];

  assert (message[0].iov_len == sizeof (struct ospf6_header));
  o6hdr = (struct ospf6_header *) message[0].iov_base;

  inet_ntop (AF_INET, &o6hdr->router_id, rtrid_str, sizeof (rtrid_str));
  inet_ntop (AF_INET, &o6hdr->area_id, areaid_str, sizeof (areaid_str));

  zlog_info ("  OSPFv%d Type:%d Len:%hu RouterID:%s",
             o6hdr->version, o6hdr->type, ntohs (o6hdr->len), rtrid_str);
  zlog_info ("  AreaID:%s Cksum:%hx InstanceID:%d",
             areaid_str, ntohs (o6hdr->cksum), o6hdr->instance_id);

  switch (o6hdr->type)
    {
      case MSGT_HELLO:
        ospf6_dump_hello (&message[1]);
        break;
      case MSGT_DATABASE_DESCRIPTION:
        ospf6_dump_dbdesc (&message[1]);
        break;
      case MSGT_LINKSTATE_REQUEST:
        ospf6_dump_lsreq (&message[1]);
        break;
      case MSGT_LINKSTATE_UPDATE:
        ospf6_dump_lsupdate (&message[1]);
        break;
      case MSGT_LINKSTATE_ACK:
        ospf6_dump_lsack (&message[1]);
        break;
      default:
        break;
    }
}

void
ospf6_dump_lsa_hdr (struct ospf6_lsa_hdr *lsa_hdr)
{
  char advrtr[64];

  inet_ntop (AF_INET, &lsa_hdr->lsh_advrtr, advrtr, sizeof (advrtr));
  zlog_info ("  %s AdvRtr:%s LS-ID:%lu",
             lstype_name[typeindex (lsa_hdr->lsh_type)],
             advrtr, ntohl (lsa_hdr->lsh_id));
  zlog_info ("    Age:%hu SeqNum:%#x Cksum:%#hx Len:%hu",
             ntohs (lsa_hdr->lsh_age), ntohl (lsa_hdr->lsh_seqnum),
             ntohs (lsa_hdr->lsh_cksum), ntohs (lsa_hdr->lsh_len));
}

void
ospf6_dump_lsa (struct ospf6_lsa *lsa)
{
  ospf6_age_current (lsa);
  ospf6_dump_lsa_hdr (lsa->lsa_hdr);
}

int
is_ospf6_message_dump (char type)
{
  switch (type)
    {
      case MSGT_HELLO:
        if (IS_OSPF6_DUMP_HELLO)
          return 1;
        break;
      case MSGT_DATABASE_DESCRIPTION:
        if (IS_OSPF6_DUMP_DBDESC)
          return 1;
        break;
      case MSGT_LINKSTATE_REQUEST:
        if (IS_OSPF6_DUMP_LSREQ)
          return 1;
        break;
      case MSGT_LINKSTATE_UPDATE:
        if (IS_OSPF6_DUMP_LSUPDATE)
          return 1;
        break;
      case MSGT_LINKSTATE_ACK:
        if (IS_OSPF6_DUMP_LSACK)
          return 1;
        break;
      default:
        break;
    }
  return 0;
}

DEFUN (debug_ospf6_message,
       debug_ospf6_message_cmd,
       "debug ospf6 message (hello|dbdesc|lsreq|lsupdate|lsack|all)",
       "Debugging infomation\n"
       OSPF6_STR
       "OSPF6 messages\n"
       "OSPF6 Hello\n"
       "OSPF6 Database Description\n"
       "OSPF6 Link State Request\n"
       "OSPF6 Link State Update\n"
       "OSPF6 Link State Acknowledgement\n"
       "OSPF6 all messages\n"
       )
{
  assert (argc);
  if (!strcmp (argv[0], "hello"))
    ospf6_message_hello_dump = 1;
  else if (!strcmp (argv[0], "dbdesc"))
    ospf6_message_dbdesc_dump = 1;
  else if (!strcmp (argv[0], "lsreq"))
    ospf6_message_lsreq_dump = 1;
  else if (!strcmp (argv[0], "lsupdate"))
    ospf6_message_lsupdate_dump = 1;
  else if (!strcmp (argv[0], "lsack"))
    ospf6_message_lsack_dump = 1;
  else if (!strcmp (argv[0], "all"))
    ospf6_message_hello_dump = ospf6_message_dbdesc_dump =
    ospf6_message_lsreq_dump = ospf6_message_lsupdate_dump =
    ospf6_message_lsack_dump = 1;
  else
    return CMD_ERR_NO_MATCH;

  return CMD_SUCCESS;
}


/* commands */
DEFUN (no_debug_ospf6_message,
       no_debug_ospf6_message_cmd,
       "no debug ospf6 message (hello|dbdesc|lsreq|lsupdate|lsack|all)",
       NO_STR
       "Debugging infomation\n"
       OSPF6_STR
       "OSPF6 messages\n"
       "OSPF6 Hello\n"
       "OSPF6 Database Description\n"
       "OSPF6 Link State Request\n"
       "OSPF6 Link State Update\n"
       "OSPF6 Link State Acknowledgement\n"
       "OSPF6 all messages\n"
       )
{
  assert (argc);
  if (!strcmp (argv[0], "hello"))
    ospf6_message_hello_dump = 0;
  else if (!strcmp (argv[0], "dbdesc"))
    ospf6_message_dbdesc_dump = 0;
  else if (!strcmp (argv[0], "lsreq"))
    ospf6_message_lsreq_dump = 0;
  else if (!strcmp (argv[0], "lsupdate"))
    ospf6_message_lsupdate_dump = 0;
  else if (!strcmp (argv[0], "lsack"))
    ospf6_message_lsack_dump = 0;
  else if (!strcmp (argv[0], "all"))
    ospf6_message_hello_dump = ospf6_message_dbdesc_dump =
    ospf6_message_lsreq_dump = ospf6_message_lsupdate_dump =
    ospf6_message_lsack_dump = 0;
  else
    return CMD_ERR_NO_MATCH;

  return CMD_SUCCESS;
}

DEFUN (debug_ospf6_spf,
       debug_ospf6_spf_cmd,
       "debug ospf6 spf",
       "Debugging infomation\n"
       OSPF6_STR
       "OSPF6 Calculation event\n"
       )
{
  ospf6_spf_dump = 1;
  return CMD_SUCCESS;
}

DEFUN (no_debug_ospf6_spf,
       no_debug_ospf6_spf_cmd,
       "no debug ospf6 spf",
       NO_STR
       "Debugging infomation\n"
       OSPF6_STR
       "OSPF6 Calculation event\n"
       )
{
  ospf6_spf_dump = 0;
  return CMD_SUCCESS;
}

DEFUN (debug_ospf6_neighbor,
       debug_ospf6_neighbor_cmd,
       "debug ospf6 neighbor",
       "Debugging infomation\n"
       OSPF6_STR
       "OSPF6 Neighbor event\n"
       )
{
  ospf6_neighbor_dump = 1;
  return CMD_SUCCESS;
}

DEFUN (no_debug_ospf6_neighbor,
       no_debug_ospf6_neighbor_cmd,
       "no debug ospf6 neighbor",
       NO_STR
       "Debugging infomation\n"
       OSPF6_STR
       "OSPF6 Neighbor event\n"
       )
{
  ospf6_neighbor_dump = 0;
  return CMD_SUCCESS;
}

DEFUN (debug_ospf6_interface,
       debug_ospf6_interface_cmd,
       "debug ospf6 interface",
       "Debugging infomation\n"
       OSPF6_STR
       "OSPF6 Interface event\n"
       )
{
  ospf6_interface_dump = 1;
  return CMD_SUCCESS;
}

DEFUN (no_debug_ospf6_interface,
       no_debug_ospf6_interface_cmd,
       "no debug ospf6 interface",
       NO_STR
       "Debugging infomation\n"
       OSPF6_STR
       "OSPF6 Interface event\n"
       )
{
  ospf6_interface_dump = 0;
  return CMD_SUCCESS;
}

DEFUN (debug_ospf6_area,
       debug_ospf6_area_cmd,
       "debug ospf6 area",
       "Debugging infomation\n"
       OSPF6_STR
       "OSPF6 Area event\n"
       )
{
  ospf6_area_dump = 1;
  return CMD_SUCCESS;
}

DEFUN (no_debug_ospf6_area,
       no_debug_ospf6_area_cmd,
       "no debug ospf6 area",
       NO_STR
       "Debugging infomation\n"
       OSPF6_STR
       "OSPF6 Area event\n"
       )
{
  ospf6_area_dump = 0;
  return CMD_SUCCESS;
}

DEFUN (debug_ospf6_lsa,
       debug_ospf6_lsa_cmd,
       "debug ospf6 lsa",
       "Debugging infomation\n"
       OSPF6_STR
       "OSPF6 LSA event\n"
       )
{
  ospf6_lsa_dump = 1;
  return CMD_SUCCESS;
}

DEFUN (no_debug_ospf6_lsa,
       no_debug_ospf6_lsa_cmd,
       "no debug ospf6 lsa",
       NO_STR
       "Debugging infomation\n"
       OSPF6_STR
       "OSPF6 LSA event\n"
       )
{
  ospf6_lsa_dump = 0;
  return CMD_SUCCESS;
}

DEFUN (debug_ospf6_zebra,
       debug_ospf6_zebra_cmd,
       "debug ospf6 zebra",
       "Debugging infomation\n"
       OSPF6_STR
       "OSPF6 Zebra event\n"
       )
{
  ospf6_zebra_dump = 1;
  return CMD_SUCCESS;
}

DEFUN (no_debug_ospf6_zebra,
       no_debug_ospf6_zebra_cmd,
       "no debug ospf6 zebra",
       NO_STR
       "Debugging infomation\n"
       OSPF6_STR
       "OSPF6 Zebra event\n"
       )
{
  ospf6_zebra_dump = 0;
  return CMD_SUCCESS;
}

DEFUN (debug_ospf6_config,
       debug_ospf6_config_cmd,
       "debug ospf6 (config|dbex|route)",
       "Debugging infomation\n"
       OSPF6_STR
       "OSPF6 Config event\n"
       "OSPF6 LSA Database exchange event\n"
       "OSPF6 route trace\n"
       )
{
  if (!strcmp ("config", argv[0]))
    ospf6_config_dump = 1;
  else if (!strcmp ("dbex", argv[0]))
    ospf6_dbex_dump = 1;
  else if (!strcmp ("route", argv[0]))
    ospf6_route_dump = 1;
  else
    return CMD_ERR_NO_MATCH;
  return CMD_SUCCESS;
}

DEFUN (no_debug_ospf6_config,
       no_debug_ospf6_config_cmd,
       "no debug ospf6 (config|dbex|route)",
       NO_STR
       "Debugging infomation\n"
       OSPF6_STR
       "OSPF6 Configuration event\n"
       "OSPF6 LSA Database exchange event\n"
       "OSPF6 route trace\n"
       )
{
  if (!strcmp ("config", argv[0]))
    ospf6_config_dump = 0;
  else if (!strcmp ("dbex", argv[0]))
    ospf6_dbex_dump = 0;
  else if (!strcmp ("route", argv[0]))
    ospf6_route_dump = 0;
  else
    return CMD_ERR_NO_MATCH;
  return CMD_SUCCESS;
}

DEFUN (show_debugging_ospf6,
       show_debugging_ospf6_cmd,
       "show debugging ospf6",
       SHOW_STR
       "Debugging infomation\n"
       OSPF6_STR)
{
  vty_out (vty, "OSPF6 debugging status:%s", VTY_NEWLINE);

  /* messages */
  /* hello */
  if (IS_OSPF6_DUMP_HELLO)
    vty_out (vty, "  OSPF6 Hello Message: on%s", VTY_NEWLINE);
  else
    vty_out (vty, "  OSPF6 Hello Message: off%s", VTY_NEWLINE);
  /* dbdesc */
  if (IS_OSPF6_DUMP_DBDESC)
    vty_out (vty, "  OSPF6 Database Description Message: on%s", VTY_NEWLINE);
  else
    vty_out (vty, "  OSPF6 Database Description Message: off%s", VTY_NEWLINE);
  /* lsreq */
  if (IS_OSPF6_DUMP_LSREQ)
    vty_out (vty, "  OSPF6 Link State Request Message: on%s", VTY_NEWLINE);
  else
    vty_out (vty, "  OSPF6 Link State Request Message: off%s", VTY_NEWLINE);
  /* lsupdate */
  if (IS_OSPF6_DUMP_LSUPDATE)
    vty_out (vty, "  OSPF6 Link State Update Message: on%s", VTY_NEWLINE);
  else
    vty_out (vty, "  OSPF6 Link State Update Message: off%s", VTY_NEWLINE);
  /* lsack */
  if (IS_OSPF6_DUMP_LSACK)
    vty_out (vty, "  OSPF6 Link State Acknowledgement Message: on%s", VTY_NEWLINE);
  else
    vty_out (vty, "  OSPF6 Link State Acknowledgement Message: off%s", VTY_NEWLINE);

  /* neighbor */
  if (IS_OSPF6_DUMP_NEIGHBOR)
    vty_out (vty, "  OSPF6 Neighbor: on%s", VTY_NEWLINE);
  else
    vty_out (vty, "  OSPF6 Neighbor: off%s", VTY_NEWLINE);

  /* interface */
  if (IS_OSPF6_DUMP_INTERFACE)
    vty_out (vty, "  OSPF6 Interface: on%s", VTY_NEWLINE);
  else
    vty_out (vty, "  OSPF6 Interface: off%s", VTY_NEWLINE);

  /* area */
  if (IS_OSPF6_DUMP_AREA)
    vty_out (vty, "  OSPF6 Area: on%s", VTY_NEWLINE);
  else
    vty_out (vty, "  OSPF6 Area: off%s", VTY_NEWLINE);

  /* lsa */
  if (IS_OSPF6_DUMP_LSA)
    vty_out (vty, "  OSPF6 LSA: on%s", VTY_NEWLINE);
  else
    vty_out (vty, "  OSPF6 LSA: off%s", VTY_NEWLINE);

  /* zebra */
  if (IS_OSPF6_DUMP_ZEBRA)
    vty_out (vty, "  OSPF6 Zebra: on%s", VTY_NEWLINE);
  else
    vty_out (vty, "  OSPF6 Zebra: off%s", VTY_NEWLINE);

  /* config */
  if (IS_OSPF6_DUMP_CONFIG)
    vty_out (vty, "  OSPF6 Config: on%s", VTY_NEWLINE);
  else
    vty_out (vty, "  OSPF6 Config: off%s", VTY_NEWLINE);

  /* lsa database exchange */
  if (IS_OSPF6_DUMP_DBEX)
    vty_out (vty, "  OSPF6 DbEx: on%s", VTY_NEWLINE);
  else
    vty_out (vty, "  OSPF6 DbEx: off%s", VTY_NEWLINE);

  /* route */
  if (IS_OSPF6_DUMP_ROUTE)
    vty_out (vty, "  OSPF6 Route: on%s", VTY_NEWLINE);
  else
    vty_out (vty, "  OSPF6 Route: off%s", VTY_NEWLINE);

  return CMD_SUCCESS;
}

struct cmd_node debug_node =
{
  DEBUG_NODE,
  ""
};

int
ospf6_config_write_debug (struct vty *vty)
{
  if (IS_OSPF6_DUMP_MESSAGE_ALL)
    vty_out (vty, "debug ospf6 message all%s", VTY_NEWLINE);
  else
    {
      if (IS_OSPF6_DUMP_HELLO)
        vty_out (vty, "debug ospf6 message hello%s", VTY_NEWLINE);
      if (IS_OSPF6_DUMP_DBDESC)
        vty_out (vty, "debug ospf6 message dbdesc%s", VTY_NEWLINE);
      if (IS_OSPF6_DUMP_LSREQ)
        vty_out (vty, "debug ospf6 message lsreq%s", VTY_NEWLINE);
      if (IS_OSPF6_DUMP_LSUPDATE)
        vty_out (vty, "debug ospf6 message lsupdate%s", VTY_NEWLINE);
      if (IS_OSPF6_DUMP_LSACK)
        vty_out (vty, "debug ospf6 message lsack%s", VTY_NEWLINE);
    }

  if (IS_OSPF6_DUMP_NEIGHBOR)
    vty_out (vty, "debug ospf6 neighbor%s", VTY_NEWLINE);
  if (IS_OSPF6_DUMP_SPF)
    vty_out (vty, "debug ospf6 spf%s", VTY_NEWLINE);
  if (IS_OSPF6_DUMP_INTERFACE)
    vty_out (vty, "debug ospf6 interface%s", VTY_NEWLINE);
  if (IS_OSPF6_DUMP_AREA)
    vty_out (vty, "debug ospf6 area%s", VTY_NEWLINE);
  if (IS_OSPF6_DUMP_LSA)
    vty_out (vty, "debug ospf6 lsa%s", VTY_NEWLINE);
  if (IS_OSPF6_DUMP_ZEBRA)
    vty_out (vty, "debug ospf6 zebra%s", VTY_NEWLINE);
  if (IS_OSPF6_DUMP_CONFIG)
    vty_out (vty, "debug ospf6 config%s", VTY_NEWLINE);
  if (IS_OSPF6_DUMP_DBEX)
    vty_out (vty, "debug ospf6 dbex%s", VTY_NEWLINE);
  if (IS_OSPF6_DUMP_ROUTE)
    vty_out (vty, "debug ospf6 route%s", VTY_NEWLINE);

  vty_out (vty, "!%s", VTY_NEWLINE);

  return 0;
}

void
ospf6_debug_init ()
{
  install_node (&debug_node, ospf6_config_write_debug);

  install_element (VIEW_NODE, &show_debugging_ospf6_cmd);
  install_element (ENABLE_NODE, &show_debugging_ospf6_cmd);

  install_element (CONFIG_NODE, &debug_ospf6_message_cmd);
  install_element (CONFIG_NODE, &debug_ospf6_neighbor_cmd);
  install_element (CONFIG_NODE, &debug_ospf6_spf_cmd);
  install_element (CONFIG_NODE, &debug_ospf6_interface_cmd);
  install_element (CONFIG_NODE, &debug_ospf6_area_cmd);
  install_element (CONFIG_NODE, &debug_ospf6_lsa_cmd);
  install_element (CONFIG_NODE, &debug_ospf6_zebra_cmd);
  install_element (CONFIG_NODE, &debug_ospf6_config_cmd);
  install_element (CONFIG_NODE, &no_debug_ospf6_message_cmd);
  install_element (CONFIG_NODE, &no_debug_ospf6_neighbor_cmd);
  install_element (CONFIG_NODE, &no_debug_ospf6_spf_cmd);
  install_element (CONFIG_NODE, &no_debug_ospf6_interface_cmd);
  install_element (CONFIG_NODE, &no_debug_ospf6_area_cmd);
  install_element (CONFIG_NODE, &no_debug_ospf6_lsa_cmd);
  install_element (CONFIG_NODE, &no_debug_ospf6_zebra_cmd);
  install_element (CONFIG_NODE, &no_debug_ospf6_config_cmd);
}

void
ospf6_dump_ddbit (unsigned char dd_bit, char *buf, size_t size)
{
  memset (buf, 0, size);
  if (DDBIT_IS_MASTER (dd_bit))
    strncat (buf, "Master", size - strlen (buf));
  else
    strncat (buf, "Slave", size - strlen (buf));
  if (DDBIT_IS_MORE (dd_bit))
    strncat (buf, ",More", size - strlen (buf));
  if (DDBIT_IS_INITIAL (dd_bit))
    strncat (buf, ",Initial", size - strlen (buf));
}

