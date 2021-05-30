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

#include "ospf6d.h"

struct ospf6_lsa_hdr *
ospf6_message_get_lsa_hdr (struct iovec *iov)
{
  struct ospf6_lsa_hdr *lsa_hdr;
  lsa_hdr = (struct ospf6_lsa_hdr *) iov_detach_first (iov);
  return lsa_hdr;
}


/* used only when failed to allocate buffer for receive */
static void
ospf6_message_lsa_hdr_clear_buffer (struct iovec *iov)
{
  iov_free_all (MTYPE_OSPF6_LSA, iov);
  return;
}

/* allocate space for ospf6_lsa_hdr */
static int
ospf6_message_lsa_hdr_set_buffer (struct iovec *iov, size_t len)
{
  int i, lsa_hdr_num;

  /* assert len is multiple of ospf6_lsa_hdr size */
  assert (len % sizeof (struct ospf6_lsa_hdr) == 0);

  /* count LSA header number and make space for each of them */
  lsa_hdr_num = len / sizeof (struct ospf6_lsa_hdr);
  for (i = 0; i < lsa_hdr_num; i++)
    {
      if (!iov_prepend (MTYPE_OSPF6_LSA, iov,
                        sizeof (struct ospf6_lsa_hdr)))
        {
          ospf6_message_lsa_hdr_clear_buffer (iov);
          return -1;
        }
    }
  return 0;
}

/* free temporary space after LSAs are cut in pieces */
static void
ospf6_message_lsa_clear_buffer (struct iovec *iov)
{
  iov_trim_head (MTYPE_OSPF6_MESSAGE, iov);
  return;
}

/* allocate space for catch LSAs. this space is used temporary
   until LSAs are cut in pieces */
static int
ospf6_message_lsa_set_buffer (struct iovec *iov, size_t len)
{
  if (!iov_prepend (MTYPE_OSPF6_MESSAGE, iov, len))
    return -1;
  return 0;
}

/* used only when failed to receive packet */
static void
ospf6_message_clear_buffer (unsigned char msgtype, struct iovec *iov)
{
  switch (msgtype)
    {
      case MSGT_HELLO:
        iov_trim_head (MTYPE_OSPF6_MESSAGE, iov);
        break;

      case MSGT_DATABASE_DESCRIPTION:
        iov_trim_head (MTYPE_OSPF6_MESSAGE, iov);
        ospf6_message_lsa_hdr_clear_buffer (iov);
        break;

      case MSGT_LINKSTATE_REQUEST:
        iov_free_all (MTYPE_OSPF6_MESSAGE, iov);
        break;

      case MSGT_LINKSTATE_UPDATE:
        iov_trim_head (MTYPE_OSPF6_MESSAGE, iov);
        ospf6_message_lsa_clear_buffer (iov);
        break;

      case MSGT_LINKSTATE_ACK:
        ospf6_message_lsa_hdr_clear_buffer (iov);
        break;

      default:
        return;
    }
  assert (iov_count (iov) == 0);
  return;
}

/* if failed, return -1. in this case, free all buffer */
static int
ospf6_message_set_buffer (unsigned char msgtype, unsigned short msglen,
                          struct iovec *iov)
{
  unsigned short left;

  /* substract ospf6_header size from left space to allocate */
  left = msglen - sizeof (struct ospf6_header);

  switch (msgtype)
    {
      case MSGT_HELLO:
        if (!iov_prepend (MTYPE_OSPF6_MESSAGE, iov, left))
          return -1;
        break;

      case MSGT_DATABASE_DESCRIPTION:
        left -= sizeof (struct ospf6_dbdesc);
        if (ospf6_message_lsa_hdr_set_buffer (iov, left) < 0)
          return -1;
        if (!iov_prepend (MTYPE_OSPF6_MESSAGE, iov,
                          sizeof (struct ospf6_dbdesc)))
          {
            ospf6_message_lsa_hdr_clear_buffer (iov);
            return -1;
          }
        break;

      case MSGT_LINKSTATE_REQUEST:
        assert (left % sizeof (struct ospf6_lsreq) == 0);
        while (left)
          {
            if (!iov_prepend (MTYPE_OSPF6_MESSAGE, iov,
                              sizeof (struct ospf6_lsreq)))
              {
                iov_free_all (MTYPE_OSPF6_MESSAGE, iov);
                return -1;
              }
            left -= sizeof (struct ospf6_lsreq);
          }
        break;

      case MSGT_LINKSTATE_UPDATE:
        left -= sizeof (struct ospf6_lsupdate);
        if (ospf6_message_lsa_set_buffer (iov, left) < 0)
          return -1;
        if (!iov_prepend (MTYPE_OSPF6_MESSAGE, iov,
                          sizeof (struct ospf6_lsupdate)))
          {
            ospf6_message_lsa_clear_buffer (iov);
            return -1;
          }
        break;

      case MSGT_LINKSTATE_ACK:
        if (ospf6_message_lsa_hdr_set_buffer (iov, left) < 0)
          return -1;
        break;

      default:
        return -1;
    }

  if (!iov_prepend (MTYPE_OSPF6_MESSAGE, iov, sizeof (struct ospf6_header)))
    {
      ospf6_message_clear_buffer (msgtype, iov);
      return -1;
    }

  return 0;
}

int
ospf6_opt_is_mismatch (unsigned char opt, char *options1, char *options2)
{
  return (V3OPT_ISSET (options1, opt) ^ V3OPT_ISSET (options2, opt));
}


static void
ospf6_process_hello (struct iovec *iov, struct ospf6_interface *o6if,
                     struct sockaddr_in6 *src, unsigned long router_id)
{
  struct ospf6_hello *hello;
  char *my_options;
  char changes = 0;
#define CHANGE_RTRPRI (1 << 0)
#define CHANGE_DR     (1 << 1)
#define CHANGE_BDR    (1 << 2)
  int twoway = 0, backupseen = 0, nbchange = 0;
  unsigned long *router_id_ptr, my_router_id;
  int i, seenrtrnum = 0, router_id_space = 0;
  char rtrid_str[64];
  struct neighbor *nbr = NULL;

  /* assert interface */
  assert (o6if);

  /* router id strings */
  inet_ntop (AF_INET, &router_id, rtrid_str, sizeof (rtrid_str));

  /* set hello pointer */
  hello = (struct ospf6_hello *) iov[0].iov_base;

  /* HelloInterval check */
  if (ntohs (hello->hello_interval)
      != o6if->hello_interval)
    {
      zlog_warn ("HelloInterval mismatch with %s", rtrid_str);
      ospf6_message_clear_buffer (MSGT_HELLO, iov);
      return;
    }

  /* RouterDeadInterval check */
  if (ntohs (hello->router_dead_interval)
      != o6if->dead_interval)
    {
      zlog_warn ("RouterDeadInterval mismatch with %s", rtrid_str);
      ospf6_message_clear_buffer (MSGT_HELLO, iov);
      return;
    }

  /* check options */
  /* Ebit */
  my_options = o6if->area->options;
  if (ospf6_opt_is_mismatch (V3OPT_E, hello->options, my_options))
    {
      zlog_warn ("Ebit mismatch with %s", rtrid_str);
      ospf6_message_clear_buffer (MSGT_HELLO, iov);
      return;
    }

  /* find neighbor. if cannot be found, create */
  nbr = nbr_lookup (router_id, o6if);
  if (!nbr)
    {
      nbr = make_neighbor (router_id, o6if);
      nbr->ifid = ntohl (hello->interface_id);
      nbr->prevdr = nbr->dr = hello->dr;
      nbr->prevbdr = nbr->bdr = hello->bdr;
      nbr->rtr_pri = hello->rtr_pri;
      memcpy (&nbr->hisaddr, src, sizeof (struct sockaddr_in6));
    }

  /* RouterPriority set */
  if (nbr->rtr_pri != hello->rtr_pri)
    {
      nbr->rtr_pri = hello->rtr_pri;
      if (IS_OSPF6_DUMP_HELLO)
        zlog_info ("%s: RouterPriority changed", nbr->str);
      changes |= CHANGE_RTRPRI;
    }

  /* DR set */
  if (nbr->dr != hello->dr)
    {
      /* save previous dr, set current */
      nbr->prevdr = nbr->dr;
      nbr->dr = hello->dr;
      if (IS_OSPF6_DUMP_HELLO)
        zlog_info ("%s declare %s as DR", nbr->str, inet4str (nbr->dr));
      changes |= CHANGE_DR;
    }

  /* BDR set */
  if (nbr->bdr != hello->bdr)
    {
      /* save previous bdr, set current */
      nbr->prevbdr = nbr->bdr;
      nbr->bdr = hello->bdr;
      if (IS_OSPF6_DUMP_HELLO)
        zlog_info ("%s declare %s as BDR", nbr->str, inet4str (nbr->bdr));
      changes |= CHANGE_BDR;
    }

  /* TwoWay check */
  router_id_space = iov[0].iov_len - sizeof (struct ospf6_hello);
  assert (router_id_space % sizeof (unsigned long) == 0);
  seenrtrnum = router_id_space / sizeof (unsigned long);
  my_router_id = nbr->ospf6_interface->area->ospf6->router_id;
  router_id_ptr = (unsigned long *) (hello + 1);
  for (i = 0; i < seenrtrnum; i++)
    {
      if (*router_id_ptr == my_router_id)
        twoway++;
      router_id_ptr++;
    }

  /* execute neighbor events */
  thread_execute (master, hello_received, nbr, 0);
  if (twoway)
    thread_execute (master, twoway_received, nbr, 0);
  else
    thread_execute (master, oneway_received, nbr, 0);

  /* BackupSeen check */
  if (nbr->ospf6_interface->state == IFS_WAITING)
    {
      if (hello->dr == hello->bdr == nbr->rtr_id)
        assert (0);
      else if (hello->bdr == nbr->rtr_id)
        backupseen++;
      else if (hello->dr == nbr->rtr_id && hello->bdr == 0)
        backupseen++;
    }

  /* NeighborChange check */
  if (changes & CHANGE_RTRPRI)
    nbchange++;
  if (changes & CHANGE_DR)
    if (nbr->prevdr == nbr->rtr_id || nbr->dr == nbr->rtr_id)
      nbchange++;
  if (changes & CHANGE_BDR)
    if (nbr->prevbdr == nbr->rtr_id || nbr->bdr == nbr->rtr_id)
      nbchange++;

  /* schedule interface events */
  if (backupseen)
    thread_add_event (master, backup_seen, nbr->ospf6_interface, 0);
  if (nbchange)
    thread_add_event (master, neighbor_change, nbr->ospf6_interface, 0);

  /* free hello space */
  iov_trim_head (MTYPE_OSPF6_MESSAGE, iov);

  return;
}

static int
ospf6_dbdesc_is_master (struct neighbor *nbr)
{
  if (nbr->rtr_id == ospf6->router_id)
    {
      zlog_warn ("*** neighbor router id is the same of mine");
      return -1;
    }
  else if (nbr->rtr_id > ospf6->router_id)
    return 0;
  return 1;
}

int
ospf6_dbdesc_is_duplicate (struct ospf6_dbdesc *received,
                           struct ospf6_dbdesc *last_received)
{
  if (memcmp (received->options, last_received->options, 3) != 0)
    return 0;
  if (received->ifmtu != last_received->ifmtu)
    return 0;
  if (received->bits != last_received->bits)
    return 0;
  if (received->seqnum != last_received->seqnum)
    return 0;
  return 1;
}

static void
ospf6_process_dbdesc_master (struct iovec *iov, struct neighbor *nbr)
{
  struct ospf6_dbdesc *dbdesc;

  /* set database description pointer */
  dbdesc = (struct ospf6_dbdesc *) iov[0].iov_base;

  switch (nbr->state)
    {
      case NBS_DOWN:
      case NBS_ATTEMPT:
      case NBS_TWOWAY:
        if (IS_OSPF6_DUMP_DBDESC)
          zlog_info ("DbDesc from %s Ignored: state less than Init",
                     nbr->str);
        ospf6_message_clear_buffer (MSGT_DATABASE_DESCRIPTION, iov);
        return;

      case NBS_INIT:
        thread_execute (master, twoway_received, nbr, 0);
        if (nbr->state != NBS_EXSTART)
          {
            if (IS_OSPF6_DUMP_DBDESC)
              zlog_info ("DbDesc from %s Ignored: state less than ExStart",
                         nbr->str);
            ospf6_message_clear_buffer (MSGT_DATABASE_DESCRIPTION, iov);
            return;
          }
        /* else fall through to ExStart */
      case NBS_EXSTART:
        if (DDBIT_IS_SLAVE (dbdesc->bits) &&
            !DDBIT_IS_INITIAL (dbdesc->bits) &&
            ntohl (dbdesc->seqnum) == nbr->seqnum)
          {
            prepare_neighbor_lsdb (nbr);

            if (nbr->thread_dbdesc_retrans)
              thread_cancel (nbr->thread_dbdesc_retrans);
            nbr->thread_dbdesc_retrans = (struct thread *) NULL;

            thread_add_event (master, negotiation_done, nbr, 0);
          }
        else
          {
            if (IS_OSPF6_DUMP_DBDESC)
              zlog_info ("  negotiation failed with %s", nbr->str);
            ospf6_message_clear_buffer (MSGT_DATABASE_DESCRIPTION, iov);
            return;
          }
        break;

      case NBS_EXCHANGE:
        /* duplicate dbdesc dropped by master */
        if (!memcmp (dbdesc, &nbr->last_dd,
                     sizeof (struct ospf6_dbdesc)))
          {
            if (IS_OSPF6_DUMP_DBDESC)
              zlog_info ("  duplicate dbdesc, drop");
            ospf6_message_clear_buffer (MSGT_DATABASE_DESCRIPTION, iov);
            return;
          }

        /* check Initialize bit and Master/Slave bit */
        if (DDBIT_IS_INITIAL (dbdesc->bits))
          {
            if (IS_OSPF6_DUMP_DBDESC)
              zlog_info ("Initialize bit mismatch");
            thread_add_event (master, seqnumber_mismatch, nbr, 0);
            ospf6_message_clear_buffer (MSGT_DATABASE_DESCRIPTION, iov);
            return;
          }
        if (DDBIT_IS_MASTER (dbdesc->bits))
          {
            if (IS_OSPF6_DUMP_DBDESC)
              zlog_info ("Master/Slave bit mismatch");
            thread_add_event (master, seqnumber_mismatch, nbr, 0);
            ospf6_message_clear_buffer (MSGT_DATABASE_DESCRIPTION, iov);
            return;
          }

        /* dbdesc option check */
        if (memcmp (dbdesc->options, nbr->last_dd.options,
                    sizeof (dbdesc->options)))
          {
            if (IS_OSPF6_DUMP_DBDESC)
              zlog_info ("dbdesc option field changed");
            thread_add_event (master, seqnumber_mismatch, nbr, 0);
            ospf6_message_clear_buffer (MSGT_DATABASE_DESCRIPTION, iov);
            return;
          }

        /* dbdesc sequence number check */
        if (ntohl (dbdesc->seqnum) != nbr->seqnum)
          {
            if (IS_OSPF6_DUMP_DBDESC)
              zlog_warn ("*** dbdesc seqnumber mismatch: %lu expected",
                         nbr->seqnum);
            thread_add_event (master, seqnumber_mismatch, nbr, 0);
            ospf6_message_clear_buffer (MSGT_DATABASE_DESCRIPTION, iov);
            return;
          }
        break;

      case NBS_LOADING:
      case NBS_FULL:
        /* duplicate dbdesc dropped by master */
        if (ospf6_dbdesc_is_duplicate (dbdesc, &nbr->last_dd))
          {
            if (IS_OSPF6_DUMP_DBDESC)
              zlog_info ("  duplicate dbdesc, drop");
            ospf6_message_clear_buffer (MSGT_DATABASE_DESCRIPTION, iov);
            return;
          }
        else
          {
            if (IS_OSPF6_DUMP_DBDESC)
              zlog_info ("  not duplicate dbdesc in state %s",
                         nbs_name[nbr->state]);
            thread_add_event (master, seqnumber_mismatch, nbr, 0);
            ospf6_message_clear_buffer (MSGT_DATABASE_DESCRIPTION, iov);
            return;
          }
        break; /* not reached */

      default:
        assert (0);
        break; /* not reached */
    }

  /* take dbdesc header from message */
  iov_detach_first (iov);

  /* process LSA headers */
  if (check_neighbor_lsdb (iov, nbr) < 0)
    {
      /* one possible situation to come here is to find as-external
      lsa found when this area is stub */
      thread_add_event (master, seqnumber_mismatch, nbr, 0);
      iov_free_all (MTYPE_OSPF6_LSA, iov);
      return;
    }

  /* increment dbdesc seqnum */
  nbr->seqnum++;

  /* more bit check */
  if (!DD_IS_MBIT_SET (dbdesc->bits) && !DD_IS_MBIT_SET (nbr->dd_bits))
    {
      thread_add_event (master, exchange_done, nbr, 0);

      if (nbr->thread_dbdesc_retrans)
        thread_cancel (nbr->thread_dbdesc_retrans);
      nbr->thread_dbdesc_retrans = (struct thread *) NULL;
    }
  else
    thread_add_event (master, ospf6_send_dbdesc, nbr, 0);

  /* save last received dbdesc , and free */
  memcpy (&nbr->last_dd, dbdesc, sizeof (struct ospf6_dbdesc));
  XFREE (MTYPE_OSPF6_MESSAGE, dbdesc);

  return;
}

static void
ospf6_process_dbdesc_slave (struct iovec *iov, struct neighbor *nbr)
{
  struct ospf6_dbdesc *dbdesc;

  /* set database description pointer */
  dbdesc = (struct ospf6_dbdesc *) iov[0].iov_base;

  switch (nbr->state)
    {
      case NBS_DOWN:
      case NBS_ATTEMPT:
      case NBS_TWOWAY:
        ospf6_message_clear_buffer (MSGT_DATABASE_DESCRIPTION, iov);
        return;
      case NBS_INIT:
        thread_execute (master, twoway_received, nbr, 0);
        if (nbr->state != NBS_EXSTART)
          {
            ospf6_message_clear_buffer (MSGT_DATABASE_DESCRIPTION, iov);
            return;
          }
        /* else fall through to ExStart */
      case NBS_EXSTART:
        if (DD_IS_IBIT_SET (dbdesc->bits) &&
            DD_IS_MBIT_SET (dbdesc->bits) &&
            DD_IS_MSBIT_SET (dbdesc->bits) &&
            iov_count (iov) == 1)
          {
            /* Master/Slave bit set to slave */
            DD_MSBIT_CLEAR (nbr->dd_bits);
            /* Initialize bit clear */
            DD_IBIT_CLEAR (nbr->dd_bits);
            /* sequence number set to master's */
            nbr->seqnum = ntohl (dbdesc->seqnum);
            prepare_neighbor_lsdb (nbr);

            if (nbr->thread_dbdesc_retrans)
              thread_cancel (nbr->thread_dbdesc_retrans);
            nbr->thread_dbdesc_retrans = (struct thread *) NULL;

            thread_add_event (master, negotiation_done, nbr, 0);
          }
        else
          {
            if (IS_OSPF6_DUMP_DBDESC)
              zlog_info ("negotiation failed");
            ospf6_message_clear_buffer (MSGT_DATABASE_DESCRIPTION, iov);
            return;
          }
        break;

      case NBS_EXCHANGE:
        /* duplicate dbdesc dropped by master */
        if (!memcmp (dbdesc, &nbr->last_dd,
                     sizeof (struct ospf6_dbdesc)))
          {
            if (IS_OSPF6_DUMP_DBDESC)
              zlog_info ("  duplicate dbdesc, retransmit dbdesc");

            thread_add_event (master, ospf6_send_dbdesc_retrans, nbr, 0);

            ospf6_message_clear_buffer (MSGT_DATABASE_DESCRIPTION, iov);
            return;
          }

        /* check Initialize bit and Master/Slave bit */
        if (DDBIT_IS_INITIAL (dbdesc->bits))
          {
            if (IS_OSPF6_DUMP_DBDESC)
              zlog_info ("Initialize bit mismatch");
            thread_add_event (master, seqnumber_mismatch, nbr, 0);
            ospf6_message_clear_buffer (MSGT_DATABASE_DESCRIPTION, iov);
            return;
          }
        if (DDBIT_IS_SLAVE (dbdesc->bits))
          {
            if (IS_OSPF6_DUMP_DBDESC)
              zlog_info ("Master/Slave bit mismatch");
            thread_add_event (master, seqnumber_mismatch, nbr, 0);
            ospf6_message_clear_buffer (MSGT_DATABASE_DESCRIPTION, iov);
            return;
          }

        /* dbdesc option check */
        if (memcmp (dbdesc->options, nbr->last_dd.options,
                    sizeof (dbdesc->options)))
          {
            if (IS_OSPF6_DUMP_DBDESC)
              zlog_info ("dbdesc option field changed");
            thread_add_event (master, seqnumber_mismatch, nbr, 0);
            ospf6_message_clear_buffer (MSGT_DATABASE_DESCRIPTION, iov);
            return;
          }

        /* dbdesc sequence number check */
        if (ntohl (dbdesc->seqnum) != nbr->seqnum + 1)
          {
            if (IS_OSPF6_DUMP_DBDESC)
              zlog_warn ("*** dbdesc seqnumber mismatch: %lu expected",
                         nbr->seqnum + 1);
            thread_add_event (master, seqnumber_mismatch, nbr, 0);
            ospf6_message_clear_buffer (MSGT_DATABASE_DESCRIPTION, iov);
            return;
          }
        break;

      case NBS_LOADING:
      case NBS_FULL:
        /* duplicate dbdesc cause slave to retransmit */
        if (ospf6_dbdesc_is_duplicate (dbdesc, &nbr->last_dd))
          {
            if (IS_OSPF6_DUMP_DBDESC)
              zlog_info ("  duplicate dbdesc, retransmit");

            thread_add_event (master, ospf6_send_dbdesc_retrans, nbr, 0);

            ospf6_message_clear_buffer (MSGT_DATABASE_DESCRIPTION, iov);
            return;
          }
        else
          {
            if (IS_OSPF6_DUMP_DBDESC)
              zlog_info ("  not duplicate dbdesc in state %s",
                         nbs_name[nbr->state]);
            thread_add_event (master, seqnumber_mismatch, nbr, 0);
            ospf6_message_clear_buffer (MSGT_DATABASE_DESCRIPTION, iov);
            return;
          }
        break; /* not reached */

      default:
        assert (0);
        break; /* not reached */
    }

  /* take dbdesc header from message */
  iov_detach_first (iov);

  /* process LSA headers */
  if (check_neighbor_lsdb (iov, nbr) < 0)
    {
      /* one possible situation to come here is to find as-external
      lsa found when this area is stub */
      thread_add_event (master, seqnumber_mismatch, nbr, 0);
      iov_free_all (MTYPE_OSPF6_LSA, iov);
      return;
    }

  /* set dbdesc seqnum to master's */
  nbr->seqnum = ntohl (dbdesc->seqnum);

  thread_add_event (master, ospf6_send_dbdesc, nbr, 0);

  /* save last received dbdesc , and free */
  memcpy (&nbr->last_dd, dbdesc, sizeof (struct ospf6_dbdesc));
  XFREE (MTYPE_OSPF6_MESSAGE, dbdesc);

  ospf6_message_clear_buffer (MSGT_DATABASE_DESCRIPTION, iov);
  return;
}

static void
ospf6_process_dbdesc (struct iovec *iov, struct ospf6_interface *o6if,
                     struct sockaddr_in6 *src, unsigned long router_id)
{
  struct neighbor *nbr;
  struct ospf6_dbdesc *dbdesc;
  int Im_master = 0;

  /* assert interface */
  assert (o6if);

  /* set database description pointer */
  dbdesc = (struct ospf6_dbdesc *) iov[0].iov_base;

  /* find neighbor. if cannot be found, reject this message */
  nbr = nbr_lookup (router_id, o6if);
  if (!nbr)
    {
      ospf6_message_clear_buffer (MSGT_DATABASE_DESCRIPTION, iov);
      if (IS_OSPF6_DUMP_DBDESC)
        zlog_info ("neighbor not found, reject");
      return;
    }

  /* interface mtu check */
    /* xxx */

  /* check am I master */
  Im_master = ospf6_dbdesc_is_master (nbr);
  if (Im_master < 0)
    {
      ospf6_message_clear_buffer (MSGT_DATABASE_DESCRIPTION, iov);
      return; /* can't decide which is master, return */
    }

  if (Im_master)
    ospf6_process_dbdesc_master (iov, nbr);
  else
    ospf6_process_dbdesc_slave (iov, nbr);

  return;
}

static void
ospf6_process_lsreq (struct iovec *iov, struct ospf6_interface *o6if,
                     struct sockaddr_in6 *src, unsigned long router_id)
{
  struct neighbor *nbr;
  struct ospf6_lsreq *lsreq;
  struct iovec response[MAXIOVLIST];
  struct ospf6_lsa *lsa;
  void *scope;
  unsigned long lsanum = 0;
  struct ospf6_lsupdate *lsupdate;

  /* assert interface */
  assert (o6if);

  /* find neighbor. if cannot be found, reject this message */
  nbr = nbr_lookup (router_id, o6if);
  if (!nbr)
    {
      ospf6_message_clear_buffer (MSGT_LINKSTATE_REQUEST, iov);
      if (IS_OSPF6_DUMP_LSREQ)
        zlog_info ("  neighbor not found, reject");
      return;
    }

  /* if neighbor state less than ExChange, reject this message */
  if (nbr->state < NBS_EXCHANGE)
    {
      ospf6_message_clear_buffer (MSGT_LINKSTATE_REQUEST, iov);
      if (IS_OSPF6_DUMP_LSREQ)
        zlog_info ("  neighbor state less than Exchange, reject");
      return;
    }

  /* clear buffer for response LSUpdate packet */
  iov_clear (response, MAXIOVLIST);

  /* process each request */
  lsreq = (struct ospf6_lsreq *) iov_detach_first (iov);
  while (lsreq)
    {
      /* get scope from request type */
      switch (ospf6_lsa_get_scope_type (lsreq->lsreq_type))
        {
          case SCOPE_LINKLOCAL:
            scope = (void *) nbr->ospf6_interface;
            break;
          case SCOPE_AREA:
            scope = (void *) nbr->ospf6_interface->area;
            break;
          case SCOPE_AS:
            scope = (void *) nbr->ospf6_interface->area->ospf6;
            break;
          case SCOPE_RESERVED:
          default:
            zlog_warn ("unsupported type requested, ignore");
            XFREE (MTYPE_OSPF6_MESSAGE, lsreq);
            lsreq = (struct ospf6_lsreq *) iov_detach_first (iov);
            continue;
        }

      if (IS_OSPF6_DUMP_LSREQ)
        zlog_info ("  %s", print_lsreq (lsreq));

      /* find instance of database copy */
      lsa = ospf6_lsdb_lookup (lsreq->lsreq_type, lsreq->lsreq_id,
                               lsreq->lsreq_advrtr, scope);
      if (!lsa)
        {
          if (IS_OSPF6_DUMP_LSREQ)
            zlog_info ("requested %s not found, BadLSReq",
                       print_lsreq (lsreq));
          thread_add_event (master, bad_lsreq, nbr, 0);
          XFREE (MTYPE_OSPF6_MESSAGE, lsreq);
          ospf6_message_clear_buffer (MSGT_LINKSTATE_REQUEST, iov);
          return;
        }

      attach_lsa_to_iov (lsa, response);
      lsanum++;
      lsreq = (struct ospf6_lsreq *) iov_detach_first (iov);
    }

  /* send response LSUpdate to this request */
  assert (lsanum == iov_count (response));
  if (iov_count (response))
    {
      lsupdate = (struct ospf6_lsupdate *)
                 iov_prepend (MTYPE_OSPF6_MESSAGE, response,
                              sizeof (struct ospf6_lsupdate));
      assert (lsupdate);
      lsupdate->lsupdate_num = htonl (lsanum);

      ospf6_message_send (MSGT_LSUPDATE, response,
                          &nbr->hisaddr.sin6_addr, nbr->ospf6_interface->if_id);
      iov_trim_head (MTYPE_OSPF6_MESSAGE, response);
      iov_clear (iov, MAXIOVLIST);
    }

  return;
}

static void
ospf6_process_lsupdate (struct iovec *iov, struct ospf6_interface *o6if,
                        struct sockaddr_in6 *src, unsigned long router_id)
{
  struct ospf6_lsupdate *lsupdate;
  struct neighbor *nbr;
  unsigned long lsanum;
  struct ospf6_lsa_hdr *lsa_hdr;

  /* assert interface */
  assert (o6if);

  /* find neighbor. if cannot be found, reject this message */
  nbr = nbr_lookup (router_id, o6if);
  if (!nbr)
    {
      ospf6_message_clear_buffer (MSGT_LINKSTATE_UPDATE, iov);
      if (IS_OSPF6_DUMP_LSUPDATE)
        zlog_info ("  neighbor not found, reject");
      return;
    }

  /* if neighbor state less than ExChange, reject this message */
  if (nbr->state < NBS_EXCHANGE)
    {
      ospf6_message_clear_buffer (MSGT_LINKSTATE_UPDATE, iov);
      if (IS_OSPF6_DUMP_LSUPDATE)
        zlog_info ("  neighbor state less than Exchange, reject");
      return;
    }

  /* set linkstate update pointer */
  lsupdate = (struct ospf6_lsupdate *) iov[0].iov_base;

  /* save linkstate update info */
  lsanum = ntohl (lsupdate->lsupdate_num);

  /* statistics */
  nbr->ospf6_stat_received_lsa += lsanum;
  nbr->ospf6_stat_received_lsupdate++;

  /* decapsulation */
  lsupdate = (struct ospf6_lsupdate *) NULL;
  iov_trim_head (MTYPE_OSPF6_MESSAGE, iov);

  /* process LSAs */
  for (lsa_hdr = (struct ospf6_lsa_hdr *) iov[0].iov_base;
       lsanum; lsanum--)
    {
      lsa_receive (lsa_hdr, nbr);
      lsa_hdr = LSA_NEXT (lsa_hdr);
    }

  /* free LSA space */
  iov_trim_head (MTYPE_OSPF6_MESSAGE, iov);

  return;
}

static void
ospf6_process_lsack (struct iovec *iov, struct ospf6_interface *o6if,
                     struct sockaddr_in6 *src, unsigned long router_id)
{
  struct neighbor *nbr;
  struct ospf6_lsa_hdr *lsa_hdr;
  struct ospf6_lsa *lsa, *copy;
  void *scope;

  /* assert interface */
  assert (o6if);

  /* find neighbor. if cannot be found, reject this message */
  nbr = nbr_lookup (router_id, o6if);
  if (!nbr)
    {
      ospf6_message_clear_buffer (MSGT_LINKSTATE_ACK, iov);
      if (IS_OSPF6_DUMP_LSACK)
        zlog_info ("  neighbor not found, reject");
      return;
    }

  /* if neighbor state less than ExChange, reject this message */
  if (nbr->state < NBS_EXCHANGE)
    {
      ospf6_message_clear_buffer (MSGT_LINKSTATE_ACK, iov);
      if (IS_OSPF6_DUMP_LSACK)
        zlog_info ("  neighbor state less than Exchange, reject");
      return;
    }

  /* process each LSA header */
  while (iov[0].iov_base)
    {
      /* make each LSA header treated as LSA */
      lsa_hdr = (struct ospf6_lsa_hdr *) iov[0].iov_base;
      lsa = make_ospf6_lsa (lsa_hdr);
      lsa->from = nbr;

      /* detach from message */
      iov_detach_first (iov);

      /* set scope for this LSA */
      switch (ospf6_lsa_get_scope_type (lsa_hdr->lsh_type))
        {
          case SCOPE_LINKLOCAL:
            scope = (void *) nbr->ospf6_interface;
            break;
          case SCOPE_AREA:
            scope = (void *) nbr->ospf6_interface->area;
            break;
          case SCOPE_AS:
            scope = (void *) nbr->ospf6_interface->area->ospf6;
            break;
          case SCOPE_RESERVED:
          default:
            zlog_warn ("unsupported scope acknowledge, ignore");
            ospf6_lsa_unlock (lsa);
            continue;
        }

      /* dump acknowledged LSA */
      if (IS_OSPF6_DUMP_LSACK)
        ospf6_dump_lsa_hdr (lsa_hdr);

      /* find database copy */
      copy = ospf6_lsdb_lookup (lsa_hdr->lsh_type, lsa_hdr->lsh_id,
                                lsa_hdr->lsh_advrtr, scope);

      /* if no database copy */
      if (!copy)
        {
          if (IS_OSPF6_DUMP_LSACK)
            zlog_info ("no database copy, ignore");
          ospf6_lsa_unlock (lsa);
          continue;
        }

      /* if not on his retrans list */
      if (!ospf6_lookup_retrans (copy, nbr))
        {
          if (IS_OSPF6_DUMP_LSACK)
            zlog_info ("not on %s's retranslist, ignore", nbr->str);
          ospf6_lsa_unlock (lsa);
          continue;
        }

      /* if the same instance, remove from retrans list.
         else, log and ignore */
      if (ospf6_lsa_check_recent (lsa, copy) == 0)
        ospf6_remove_retrans (copy, nbr);
      else
        {
          /* Log the questionable acknowledgement,
             and examine the next one. */
          zlog_warn ("*** questionable acknowledge: "
                     "differ database copy by %s",
                     recent_reason);
        }

      /* release temporary LSA from Ack message */
      ospf6_lsa_unlock (lsa);
    }

  return;
}

/* process ospf6 protocol header. then, call next process function
   for each message type */
static void 
ospf6_message_process (struct iovec *iov, struct ospf6_interface *o6if,
                       struct sockaddr_in6 *src)
{
  struct ospf6_header *ospf6_hdr = NULL;
  unsigned char type;
  unsigned long router_id;

  assert (iov);
  assert (o6if);
  assert (src);

  /* set ospf6_hdr pointer to head of buffer */
  ospf6_hdr = (struct ospf6_header *) iov[0].iov_base;

  /* version check */
  if (ospf6_hdr->version != OSPF6_VERSION)
    {
      if (IS_OSPF6_DUMP_MESSAGE (ospf6_hdr->type))
        zlog_info ("version mismatch, drop");
      return;
    }

  /* area id check */
  if (ospf6_hdr->area_id != o6if->area->area_id)
    {
      if (ospf6_hdr->area_id == 0)
        {
          if (IS_OSPF6_DUMP_MESSAGE (ospf6_hdr->type))
            zlog_info ("virtual link not yet, drop");
          return;
        }

      if (IS_OSPF6_DUMP_MESSAGE (ospf6_hdr->type))
        zlog_info ("area id mismatch, drop");
      return;
    }

  /* checksum */
    /* XXX */

  /* instance id check */
  if (ospf6_hdr->instance_id != o6if->instance_id)
    {
      if (IS_OSPF6_DUMP_MESSAGE (ospf6_hdr->type))
        zlog_info ("instance id mismatch, drop");
      return;
    }

  /* save message type and router id */
  type = ospf6_hdr->type;
  router_id = ospf6_hdr->router_id;

  /* trim ospf6_hdr */
  iov_trim_head (MTYPE_OSPF6_MESSAGE, iov);

  /* futher process */
  switch (type)
    {
      case MSGT_HELLO:
        ospf6_process_hello (iov, o6if, src, router_id);
        break;
      case MSGT_DATABASE_DESCRIPTION:
        ospf6_process_dbdesc (iov, o6if, src, router_id);
        break;
      case MSGT_LINKSTATE_REQUEST:
        ospf6_process_lsreq (iov, o6if, src, router_id);
        break;
      case MSGT_LINKSTATE_UPDATE:
        ospf6_process_lsupdate (iov, o6if, src, router_id);
        break;
      case MSGT_LINKSTATE_ACK:
        ospf6_process_lsack (iov, o6if, src, router_id);
        break;
      default:
        zlog_warn ("unknown message type, drop");
        ospf6_message_clear_buffer (type, iov);
        break;
    }

  /* check for memory leak */
  assert (iov_count (iov) == 0);

  return;
}

/* peek only ospf6_header to get message type, message len,
   received interface and sending neighbor */
static void
ospf6_peek_hdr (int sockfd, struct msghdr *rmsghdrp,
                unsigned char *msgtype, unsigned short *msglen,
                struct ospf6_interface **o6if)
{
  struct ospf6_header *ospf6_hdr = NULL;
  struct sockaddr_in6 *src = NULL;
  struct in6_pktinfo *pktinfo = NULL;
  struct interface *ifp;
  unsigned long router_id;

  /* set default to fail */
  *msgtype = MSGT_NONE;
  *msglen = 0;
  *o6if = NULL;

  /* set pointer to get ifindex and source ip address */
  pktinfo = (struct in6_pktinfo *)
    (CMSG_DATA ((struct cmsghdr *)rmsghdrp->msg_control));
  src = (struct sockaddr_in6 *)rmsghdrp->msg_name;

  /* prepare buffer for ospf6 header */
  iov_prepend (MTYPE_OSPF6_MESSAGE, rmsghdrp->msg_iov,
               sizeof (struct ospf6_header));
  rmsghdrp->msg_iovlen = iov_count (rmsghdrp->msg_iov);

  /* peek ospf6 header */
  if (recvmsg (sockfd, rmsghdrp, MSG_PEEK) < 0)
    {
      zlog_warn ("can't peek ospf6_hdr: %s", strerror (errno));
      return;
    }

  /* set ospf6_hdr pointer to head of buffer */
  ospf6_hdr = (struct ospf6_header *) rmsghdrp->msg_iov[0].iov_base;

  /* set message type and len */
  *msgtype = ospf6_hdr->type;
  *msglen = ntohs (ospf6_hdr->len);

  /* save router id */
  router_id = ospf6_hdr->router_id;

  /* clear buffer for ospf6 header */
  iov_trim_head (MTYPE_OSPF6_MESSAGE, rmsghdrp->msg_iov);
  rmsghdrp->msg_iovlen = iov_count (rmsghdrp->msg_iov);

  /* find received ospf6 interface */
  ifp = if_lookup_by_index (pktinfo->ipi6_ifindex);
  if (!ifp || !ifp->info)
    return;
  *o6if = (struct ospf6_interface *)ifp->info;
  if (!(*o6if)->area)
    {
      zlog_info ("received interface %s not attached to area",
                 ifp->name);
      return;
    }

  return;
}

/* failed before allocate buffer, before really read packet. */
static void
ospf6_receive_fail (int sockfd, struct msghdr *rmsghdrp)
{
  assert (iov_count (rmsghdrp->msg_iov) == 0);

  /* prepare buffer for ospf6 packet */
  iov_prepend (MTYPE_OSPF6_MESSAGE, rmsghdrp->msg_iov,
               sizeof (struct ospf6_header));
  rmsghdrp->msg_iovlen = iov_count (rmsghdrp->msg_iov);

  /* read ospf6 packet to drop */
  recvmsg (sockfd, rmsghdrp, 0);

  /* clear buffer for ospf6 packet */
  iov_trim_head (MTYPE_OSPF6_MESSAGE, rmsghdrp->msg_iov);
  rmsghdrp->msg_iovlen = iov_count (rmsghdrp->msg_iov);

  /* add thread next read */
  thread_add_read (master, ospf6_receive, NULL, sockfd);

  return;
}


int
ospf6_receive (struct thread *thread)
{
  struct iovec iov[MAXIOVLIST];
  int sockfd;
  struct msghdr rmsghdr;
  struct cmsghdr *rcmsgp = NULL;
  struct in6_pktinfo *dst_pktinfo;
  u_char cmsgbuf[CMSG_SPACE (sizeof (struct in6_pktinfo))];
  union {
    struct sockaddr sa;
    char data[sizeof (struct sockaddr_in6)];
  } unsa;
  struct sockaddr_in6 *src;
  unsigned char msgtype = MSGT_NONE;
  unsigned short msglen = 0;
  struct ospf6_interface *o6if = NULL;

  /* get socket */
  sockfd = THREAD_FD (thread);

  /* clear buffers */
  iov_clear (iov, MAXIOVLIST);
  memset (&rmsghdr, 0, sizeof (struct msghdr));
  memset (&cmsgbuf, 0, sizeof (cmsgbuf));
  memset (&unsa.data, 0, sizeof (unsa.data));

  /* ancillary data set up */
  rcmsgp = (struct cmsghdr *)&cmsgbuf;
  rcmsgp->cmsg_level = IPPROTO_IPV6;
  rcmsgp->cmsg_type = IPV6_PKTINFO;
  rcmsgp->cmsg_len = CMSG_LEN (sizeof (struct in6_pktinfo));

  /* set src/dst pointer */
  src = (struct sockaddr_in6 *)&unsa.sa;
  dst_pktinfo = (struct in6_pktinfo *)(CMSG_DATA(rcmsgp));

  /* msghdr for receive set up */
  rmsghdr.msg_name = (caddr_t) src;
  rmsghdr.msg_namelen = sizeof (struct sockaddr_in6);
  rmsghdr.msg_iov = iov;
  rmsghdr.msg_iovlen = iov_count (iov); /* will be update later */
  rmsghdr.msg_control = (caddr_t) rcmsgp;
  rmsghdr.msg_controllen = sizeof (cmsgbuf);

  /* peek ospf6_header to get message type, sending neighbor
     and  received ospf6 interface */
  ospf6_peek_hdr (sockfd, &rmsghdr, &msgtype, &msglen, &o6if);
  if (msgtype == MSGT_NONE || msglen == 0 || o6if == NULL)
    {
      zlog_warn ("ospf6_header peek failed, drop");
      ospf6_receive_fail (sockfd, &rmsghdr);
      return -1;
    }

  /* prepare buffer for each type */
  if (ospf6_message_set_buffer (msgtype, msglen, iov) < 0)
    {
      zlog_warn ("set buffer failed, drop %s len %hu",
                 mesg_name[msgtype], msglen);
      ospf6_receive_fail (sockfd, &rmsghdr);
      return -1;
    }

  /* update iovlen */
  rmsghdr.msg_iovlen = iov_count (iov);

  /* receive message */
  if (recvmsg (sockfd, &rmsghdr, 0) != msglen)
    {
      zlog_warn ("recvmsg () failed: %s", strerror (errno));
      /* add thread next read */
      thread_add_read (master, ospf6_receive, NULL, sockfd);
      /* clear buffer for ospf6_header */
      iov_trim_head (MTYPE_OSPF6_MESSAGE, iov);
      /* clear buffer for each message type */
      ospf6_message_clear_buffer (msgtype, iov);
      return -1;
    }

  /* process message received */
  ospf6_message_process (iov, o6if, src);

  /* add thread next read */
  thread_add_read (master, ospf6_receive, NULL, sockfd);

  return 0;
}

int
ospf6_receive_new (struct thread *thread)
{
  int sockfd;
  struct in6_addr src, dst;
  struct sockaddr_in6 src_sin6;
  unsigned int ifindex;
  struct iovec message[MAXIOVLIST];
  struct ospf6_header *o6h;
  struct ospf6_interface *o6i;
  char srcname[64], dstname[64];
  unsigned char type;
  unsigned short len;

  /* get socket */
  sockfd = THREAD_FD (thread);

  iov_clear (message, MAXIOVLIST);

  /* peek ospf6 header */
  o6h = (struct ospf6_header *) iov_append (MTYPE_OSPF6_MESSAGE, message,
                                         sizeof (struct ospf6_header));
  ospf6_recvmsg_peek (&src, &dst, &ifindex, message);
  type = o6h->type;
  len = ntohs (o6h->len);
  iov_trim_head (MTYPE_OSPF6_MESSAGE, message);

  /* allocate buffer for this message */
  ospf6_message_set_buffer (type, len, message);

  /* receive message */
  ospf6_recvmsg (&src, &dst, &ifindex, message);

  src_sin6.sin6_family = AF_INET6;
  memcpy (&src_sin6.sin6_addr, &src, sizeof (struct in6_addr));

  o6i = ospf6_interface_lookup_by_index (ifindex, ospf6);
  if (!o6i || !o6i->area)
    {
      zlog_warn ("*** received interface ospf6 disabled");
      return 0;
    }

  /* log */
  if (IS_OSPF6_DUMP_MESSAGE (type))
    {
      inet_ntop (AF_INET6, &dst, dstname, sizeof (dstname));
      inet_ntop (AF_INET6, &src, srcname, sizeof (srcname));
      zlog_info ("");
      zlog_info ("Receive %s on %s", mesg_name[type], o6i->interface->name);
      zlog_info ("  From:%s", srcname);
      zlog_info ("  To  :%s", dstname);
      ospf6_dump_message (message);
    }

  /* process message */
  ospf6_message_process (message, o6i, &src_sin6);

  /* add next read thread */
  thread_add_read (master, ospf6_receive_new, NULL, sockfd);

  return 0;
}


/* send section */
void
ospf6_message_send (unsigned char type, struct iovec *message,
                    struct in6_addr *dst, u_int ifindex)
{
  struct ospf6_header *ospf6_hdr;
  struct ospf6_interface *o6i;
  char dstname[64], srcname[64];

  /* ospf6 interface lookup */
  o6i = ospf6_interface_lookup_by_index (ifindex, ospf6);
  assert (o6i);

  /* memory allocate for protocol header */
  ospf6_hdr = (struct ospf6_header *)
              iov_prepend (MTYPE_OSPF6_MESSAGE, message,
                           sizeof (struct ospf6_header));
  if (!ospf6_hdr)
    {
      zlog_warn ("*** protocol header alloc failed: %s",
                 strerror (errno));
      return;
    }

  /* set each field, checksum xxx */
  ospf6_hdr->instance_id = o6i->instance_id;
  ospf6_hdr->version = OSPF6_VERSION;
  ospf6_hdr->type = type;
  ospf6_hdr->router_id = ospf6->router_id;
  ospf6_hdr->area_id = o6i->area->area_id;
  ospf6_hdr->len = htons (iov_totallen (message));

  /* log */
  if (IS_OSPF6_DUMP_MESSAGE (type))
    {
      inet_ntop (AF_INET6, dst, dstname, sizeof (dstname));
      if (o6i->lladdr)
        inet_ntop (AF_INET6, o6i->lladdr, srcname, sizeof (srcname));
      else
        memcpy (srcname, "\"auto choose\"", sizeof (srcname));
      zlog_info ("");
      zlog_info ("Send %s on %s", mesg_name[type], o6i->interface->name);
      zlog_info ("  From:%s", srcname);
      zlog_info ("  To  :%s", dstname);
      ospf6_dump_message (message);
    }

  /* send message */
  ospf6_sendmsg (o6i->lladdr, dst, &ifindex, message);

  /* free protocol header */
  iov_trim_head (MTYPE_OSPF6_MESSAGE, message);
}

int
ospf6_send_hello (struct thread *thread)
{
  struct ospf6_interface *o6if;
  struct iovec message[MAXIOVLIST];
  struct in6_addr dst;
  listnode n;
  struct neighbor *nbr;
  struct ospf6_hello *hello;

  /* which ospf6 interface to send */
  o6if = (struct ospf6_interface *) THREAD_ARG (thread);
  assert (o6if);

  /* check interface is up */
  if (o6if->state <= IFS_DOWN)
    {
      zlog_warn ("*** %s not enabled, stop send hello",
                 o6if->interface->name); 
      o6if->thread_send_hello = (struct thread *) NULL;
      return 0;
    }

  /* clear message buffer */
  iov_clear (message, MAXIOVLIST);

  /* set destionation */
  inet_pton (AF_INET6, ALLSPFROUTERS6, &dst);

  /* set neighbor router id */
  for (n = listhead (o6if->neighbor_list); n; nextnode (n))
    {
      nbr = (struct neighbor *) getdata (n);
      if (nbr->state < NBS_INIT)
        continue;
      iov_attach_last (message, &nbr->rtr_id, sizeof (unsigned long));
    }

  /* allocate hello header */
  hello = (struct ospf6_hello *)
            iov_prepend (MTYPE_OSPF6_MESSAGE, message,
                         sizeof (struct ospf6_hello));
  if (!hello)
    {
      zlog_warn ("*** hello alloc failed to %s: %s",
                 o6if->interface->name, strerror (errno));
      return -1;
    }

  /* set fields */
  hello->interface_id = htonl (o6if->if_id);
  hello->rtr_pri = o6if->priority;
  memcpy (hello->options, o6if->area->options, sizeof (hello->options));
  hello->hello_interval = htons (o6if->hello_interval);
  hello->router_dead_interval = htons (o6if->dead_interval);
  hello->dr = o6if->dr;
  hello->bdr = o6if->bdr;

  /* send hello */
  ospf6_message_send (MSGT_HELLO, message, &dst, o6if->interface->ifindex);

  /* free hello header */
  iov_trim_head (MTYPE_OSPF6_MESSAGE, message);

  /* set next timer thread */
  o6if->thread_send_hello = thread_add_timer (master, ospf6_send_hello,
                                              o6if, o6if->hello_interval);

  return 0;
}

void
ospf6_dbdesc_seqnum_init (struct neighbor *nbr)
{
  struct timeval tv;

  if (gettimeofday (&tv, (struct timezone *) NULL) < 0)
    tv.tv_sec = 1;

  nbr->seqnum = tv.tv_sec;

  if (IS_OSPF6_DUMP_DBDESC)
    zlog_info ("set dbdesc seqnum %lu for %s", nbr->seqnum, nbr->str);
}

int
ospf6_send_dbdesc_retrans (struct thread *thread)
{
  struct neighbor *nbr;

  nbr = (struct neighbor *) THREAD_ARG (thread);
  assert (nbr);

  /* statistics */
  nbr->ospf6_stat_retrans_dbdesc++;

  nbr->thread_dbdesc_retrans = (struct thread *) NULL;

  /* if state less than ExStart, do nothing */
  if (nbr->state < NBS_EXSTART)
    return 0;

  /* send dbdesc */
  ospf6_message_send (MSGT_DBDESC, nbr->dbdesc_last_send,
                      &nbr->hisaddr.sin6_addr,
                      nbr->ospf6_interface->interface->ifindex);

  /* if master, set futher retransmission */
  if (DD_IS_MSBIT_SET (nbr->dd_bits))
    nbr->thread_dbdesc_retrans =
      thread_add_timer (master, ospf6_send_dbdesc_retrans,
                          nbr, nbr->ospf6_interface->rxmt_interval);
  else
    nbr->thread_dbdesc_retrans = (struct thread *) NULL;

  return 0;
}

int
ospf6_send_dbdesc (struct thread *thread)
{
  struct neighbor *nbr;
  unsigned short leftlen;
  struct ospf6_lsa *lsa;
  struct ospf6_lsa_hdr *lsa_hdr;
  listnode n;
  struct iovec message[MAXIOVLIST];
  struct ospf6_dbdesc *dbdesc;

  nbr = (struct neighbor *) THREAD_ARG (thread);
  assert (nbr);

  /* if state less than ExStart, do nothing */
  if (nbr->state < NBS_EXSTART)
    return 0;

  /* clear message buffer */
  iov_clear (message, MAXIOVLIST);

  /* xxx, how to limit packet length correctly? */
  /* use leftlen to make empty initial dbdesc */
  if (DD_IS_IBIT_SET (nbr->dd_bits))
    leftlen = 0;
  else
    leftlen = DEFAULT_INTERFACE_MTU - sizeof (struct ospf6_header)
              - sizeof (struct ospf6_dbdesc);

  /* move LSA from summary list to message buffer */
  while (leftlen > sizeof (struct ospf6_lsa_hdr))
    {

      /* get first LSA from summary list */
      n = listhead (nbr->summarylist);
      if (n)
        lsa = (struct ospf6_lsa *) getdata (n);
      else
        {
          /* no more DbDesc to transmit */
          assert (list_isempty (nbr->summarylist));
          DD_MBIT_CLEAR (nbr->dd_bits);
          if (IS_OSPF6_DUMP_DBDESC)
            zlog_info ("  More bit cleared");

          /* slave must schedule ExchangeDone on sending, here */
          if (!DD_IS_MSBIT_SET (nbr->dd_bits))
            {
              if (!DD_IS_MBIT_SET (nbr->dd_bits) &&
                  !DD_IS_MBIT_SET (nbr->last_dd.bits))
                thread_add_event (master, exchange_done, nbr, 0);
            }
          break;
        }

      /* allocate one message buffer piece */
      lsa_hdr = (struct ospf6_lsa_hdr *) iov_prepend (MTYPE_OSPF6_MESSAGE,
                message, sizeof (struct ospf6_lsa_hdr));
      if (!lsa_hdr)
        {
          zlog_warn ("*** allocate lsa_hdr failed, continue sending dbdesc");
          break;
        }

      /* take LSA from summary list */
      ospf6_remove_summary (lsa, nbr);

      /* set age and add InfTransDelay */
      ospf6_age_update_to_send (lsa, nbr->ospf6_interface);

      /* copy LSA header */
      memcpy (lsa_hdr, lsa->lsa_hdr, sizeof (struct ospf6_lsa_hdr));

      /* left packet size */
      leftlen -= sizeof (struct ospf6_lsa_hdr);
    }

  /* make dbdesc */
  dbdesc = (struct ospf6_dbdesc *) iov_prepend (MTYPE_OSPF6_MESSAGE,
           message, sizeof (struct ospf6_dbdesc));
  if (!dbdesc)
    {
      zlog_warn ("*** allocate dbdesc failed, can't send new dbdesc");
      iov_free_all (MTYPE_OSPF6_MESSAGE, message);
      return 0;
    }

  /* if this is initial, set seqnum */
  if (DDBIT_IS_INITIAL (nbr->dd_bits))
    ospf6_dbdesc_seqnum_init (nbr);

  /* set dbdesc */
  memcpy (dbdesc->options, nbr->ospf6_interface->area->options,
          sizeof (dbdesc->options));
  dbdesc->ifmtu = htons (DEFAULT_INTERFACE_MTU);
  dbdesc->bits = nbr->dd_bits;
  dbdesc->seqnum = htonl (nbr->seqnum);

  /* cancel previous dbdesc retransmission thread */
  if (nbr->thread_dbdesc_retrans)
    thread_cancel (nbr->thread_dbdesc_retrans);
  nbr->thread_dbdesc_retrans = (struct thread *) NULL;

  /* clear previous dbdesc packet to send */
  iov_free_all (MTYPE_OSPF6_MESSAGE, nbr->dbdesc_last_send);

  /* send dbdesc */
  ospf6_message_send (MSGT_DBDESC, message, &nbr->hisaddr.sin6_addr,
                      nbr->ospf6_interface->interface->ifindex);

  /* set new dbdesc packet to send */
  iov_copy_all (nbr->dbdesc_last_send, message, MAXIOVLIST);

  /* if master, set retransmission */
  if (DD_IS_MSBIT_SET (nbr->dd_bits))
    nbr->thread_dbdesc_retrans =
      thread_add_timer (master, ospf6_send_dbdesc_retrans,
                          nbr, nbr->ospf6_interface->rxmt_interval);
  else
    nbr->thread_dbdesc_retrans = (struct thread *) NULL;

  return 0;
}

int
ospf6_send_lsreq_retrans (struct thread *thread)
{
  struct neighbor *nbr;
  struct iovec message[MAXIOVLIST];
  struct ospf6_lsreq *lsreq;
  struct ospf6_lsa *lsa;
  listnode n;

  nbr = (struct neighbor *) THREAD_ARG (thread);
  assert (nbr);

  nbr->thread_lsreq_retrans = (struct thread *)NULL;

  /* if state less than ExStart, do nothing */
  if (nbr->state < NBS_EXCHANGE)
    return 0;

  /* schedule loading_done if request list is empty */
  if (list_isempty (nbr->requestlist))
    {
      thread_add_event (master, loading_done, nbr, 0);
      return 0;
    }

  /* statistics */
  nbr->ospf6_stat_retrans_lsreq++;

  /* clear message buffer */
  iov_clear (message, MAXIOVLIST);

  /* xxx, invalid access to requestlist */
  for (n = listhead (nbr->requestlist); n; nextnode (n))
    {
      lsa = (struct ospf6_lsa *) getdata (n);
      assert (lsa->lsa_hdr);
      lsreq = (struct ospf6_lsreq *) iov_append
                  (MTYPE_OSPF6_MESSAGE, message,
                   sizeof (struct ospf6_lsreq));
      lsreq->lsreq_age_zero = 0;
      lsreq->lsreq_type = lsa->lsa_hdr->lsh_type;
      lsreq->lsreq_id = lsa->lsa_hdr->lsh_id;
      lsreq->lsreq_advrtr = lsa->lsa_hdr->lsh_advrtr;
      if (IS_OVER_MTU (message, nbr->ospf6_interface->ifmtu,
                       sizeof (struct ospf6_lsreq)))
        break;
    }

  ospf6_message_send (MSGT_LSREQ, message, &nbr->hisaddr.sin6_addr,
                      nbr->ospf6_interface->interface->ifindex);
      
  nbr->thread_lsreq_retrans =
    thread_add_timer (master, ospf6_send_lsreq_retrans,
                      nbr, nbr->ospf6_interface->rxmt_interval);
  return 0;
}

int
ospf6_send_lsreq (struct thread *thread)
{
  struct neighbor *nbr;
  struct iovec message[MAXIOVLIST];
  struct ospf6_lsreq *lsreq;
  struct ospf6_lsa *lsa;
  listnode n;

  nbr = (struct neighbor *) THREAD_ARG (thread);
  assert (nbr);

  /* if state less than ExStart, do nothing */
  if (nbr->state < NBS_EXCHANGE)
    return 0;

  /* clear message buffer */
  iov_clear (message, MAXIOVLIST);

  assert (!list_isempty (nbr->requestlist));

  /* xxx, invalid access to requestlist */
  for (n = listhead (nbr->requestlist); n; nextnode (n))
    {
      lsa = (struct ospf6_lsa *) getdata (n);
      assert (lsa->lsa_hdr);
      lsreq = (struct ospf6_lsreq *) iov_append
              (MTYPE_OSPF6_MESSAGE, message, sizeof (struct ospf6_lsreq));
      lsreq->lsreq_age_zero = 0;
      lsreq->lsreq_type = lsa->lsa_hdr->lsh_type;
      lsreq->lsreq_id = lsa->lsa_hdr->lsh_id;
      lsreq->lsreq_advrtr = lsa->lsa_hdr->lsh_advrtr;
      if (IS_OVER_MTU (message, nbr->ospf6_interface->ifmtu,
                       sizeof (struct ospf6_lsreq)))
        break;
    }

  ospf6_message_send (MSGT_LSREQ, message, &nbr->hisaddr.sin6_addr,
                      nbr->ospf6_interface->interface->ifindex);
      
  if (nbr->thread_lsreq_retrans != NULL)
    thread_cancel (nbr->thread_lsreq_retrans);
  nbr->thread_lsreq_retrans =
    thread_add_timer (master, ospf6_send_lsreq_retrans,
                      nbr, nbr->ospf6_interface->rxmt_interval);
  return 0;
}

int
ospf6_send_lsupdate_retrans (struct thread *thread)
{
  struct neighbor *o6n;
  struct iovec message[MAXIOVLIST];
  struct ospf6_lsupdate *lsupdate;
  int lsanum = 0;
  listnode n;
  struct ospf6_lsa *lsa;

  o6n = THREAD_ARG (thread);
  assert (o6n);

  o6n->send_update = (struct thread *) NULL;
  iov_clear (message, MAXIOVLIST);

  if (o6n->ospf6_interface->state <= IFS_WAITING)
    return -1;

  for (n = listhead (o6n->retranslist); n; nextnode (n))
    {
      lsa = (struct ospf6_lsa *) getdata (n);
      if (IS_OVER_MTU (message, o6n->ospf6_interface->ifmtu,
                       ntohs (lsa->lsa_hdr->lsh_len)))
        break;
      attach_lsa_to_iov (lsa, message);
      lsanum++;
    }

  if (lsanum == 0)
    return 0;

  lsupdate = (struct ospf6_lsupdate *)
               iov_prepend (MTYPE_OSPF6_MESSAGE, message,
                           sizeof (struct ospf6_lsupdate));
  if (!lsupdate)
    {
      zlog_warn ("*** iov_append () failed in lsupdate_retrans");
      return -1;
    }
  lsupdate->lsupdate_num = htonl (lsanum);

  /* statistics */
  o6n->ospf6_stat_retrans_lsupdate++;

  ospf6_message_send (MSGT_LSUPDATE, message,
                      &o6n->hisaddr.sin6_addr, o6n->ospf6_interface->if_id);

  iov_trim_head (MTYPE_OSPF6_MESSAGE, message);
  iov_clear (message, MAXIOVLIST);

  o6n->send_update = thread_add_timer (master, ospf6_send_lsupdate_retrans,
                                       o6n, o6n->ospf6_interface->rxmt_interval);
  return 0;
}

int
ospf6_send_lsack_delayed (struct thread *thread)
{
  struct ospf6_interface *o6i;
  struct iovec message[MAXIOVLIST];
  listnode node, next;
  struct ospf6_lsa *lsa;

  o6i = THREAD_ARG (thread);
  assert (o6i);

  o6i->thread_send_lsack_delayed = (struct thread *) NULL;

  if (o6i->state <= IFS_WAITING)
    return 0;

  iov_clear (message, MAXIOVLIST);

  for (node = listhead (o6i->lsa_delayed_ack); node; node = next)
    {
      next = node->next;
      lsa = (struct ospf6_lsa *) getdata (node);
      if (IS_OVER_MTU (message, o6i->ifmtu, sizeof (struct ospf6_lsa_hdr)))
        break;
      attach_lsa_hdr_to_iov (lsa, message);
      ospf6_remove_delayed_ack (lsa, o6i);
    }

  if (iov_count (message) == 0)
    return 0;

  /* statistics */
  o6i->ospf6_stat_delayed_lsack++;

  switch (o6i->state)
    {
    case IFS_DR:
    case IFS_BDR:
      ospf6_message_send (MSGT_LSACK, message,
                          &allspfrouters6.sin6_addr, o6i->if_id);
      break;
    default:
      ospf6_message_send (MSGT_LSACK, message,
                          &alldrouters6.sin6_addr, o6i->if_id);
      break;
    }

  iov_clear (message, MAXIOVLIST);
  return 0;
}

int
ospf6_send_lsack (struct thread *thread)
{
  struct ospf6_interface *o6i;
  struct iovec message[MAXIOVLIST];
  listnode node, next;
  struct ospf6_lsa *lsa;

  o6i = THREAD_ARG (thread);
  assert (o6i);

  o6i->thread_send_lsack_delayed = (struct thread *) NULL;

  if (o6i->state <= IFS_WAITING)
    return 0;

  iov_clear (message, MAXIOVLIST);

  for (node = listhead (o6i->lsa_delayed_ack); node; node = next)
    {
      next = node->next;
      lsa = (struct ospf6_lsa *) getdata (node);
      if (IS_OVER_MTU (message, o6i->ifmtu, sizeof (struct ospf6_lsa_hdr)))
        break;
      attach_lsa_hdr_to_iov (lsa, message);
      ospf6_remove_delayed_ack (lsa, o6i);
    }

  if (iov_count (message) == 0)
    return 0;

  /* statistics */
  o6i->ospf6_stat_delayed_lsack++;

  switch (o6i->state)
    {
    case IFS_DR:
    case IFS_BDR:
      ospf6_message_send (MSGT_LSACK, message,
                          &allspfrouters6.sin6_addr, o6i->if_id);
      break;
    default:
      ospf6_message_send (MSGT_LSACK, message,
                          &alldrouters6.sin6_addr, o6i->if_id);
      break;
    }

  iov_clear (message, MAXIOVLIST);
  return 0;
}

