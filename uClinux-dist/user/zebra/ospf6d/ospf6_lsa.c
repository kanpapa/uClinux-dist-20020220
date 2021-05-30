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

#include "ospf6d.h"

#include "ospf6_redistribute.h"

/* check which is more recent. if a is more recent, return -1;
   if the same, return 0; otherwise(b is more recent), return 1 */
int
ospf6_lsa_check_recent (struct ospf6_lsa *a, struct ospf6_lsa *b)
{
  signed long seqnuma, seqnumb;
  unsigned short agea, ageb;

  assert (a && a->lsa_hdr);
  assert (b && b->lsa_hdr);
  assert (ospf6_lsa_issame (a->lsa_hdr, b->lsa_hdr));

  seqnuma = ((signed long) ntohl (a->lsa_hdr->lsh_seqnum))
             - (signed long)INITIAL_SEQUENCE_NUMBER;
  seqnumb = ((signed long) ntohl (b->lsa_hdr->lsh_seqnum))
             - (signed long)INITIAL_SEQUENCE_NUMBER;

  /* compare by sequence number */
    /* xxx, care about LS sequence number wrapping */
  recent_reason = "SeqNum";
  if (seqnuma > seqnumb)
    return -1;
  else if (seqnuma < seqnumb)
    return 1;

  /* xxx, Checksum */
  recent_reason = "Cksum";

  /* MaxAge check */
  recent_reason = "MaxAge";
  if (ospf6_age_current (a) == MAXAGE
      && ospf6_age_current (b) != MAXAGE)
    return -1;
  else if (ospf6_age_current (a) != MAXAGE
           && ospf6_age_current (b) == MAXAGE)
    return 1;

  /* Age check */
  recent_reason = "Age";
  agea = ospf6_age_current (a);
  ageb = ospf6_age_current (b);
  if (agea > ageb && agea - ageb >= MAX_AGE_DIFF)
    return 1;
  else if (agea < ageb && ageb - agea >= MAX_AGE_DIFF)
    return -1;

  /* neither recent */
  recent_reason = "Same";
  return 0;
}

int show_router_lsa (struct vty *vty, void *data)
{
  int lsdnum;
  struct ospf6_lsa_hdr *lshp;
  struct router_lsa *rlsap;
  struct router_lsd *rlsdp;

  assert (data);
  lshp = (struct ospf6_lsa_hdr *)data;
  rlsap = (struct router_lsa *)(lshp + 1);
  rlsdp = (struct router_lsd *)(rlsap + 1);

  lsdnum = (ntohs (lshp->lsh_len) - sizeof (struct ospf6_lsa_hdr)
            - sizeof (struct router_lsa)) / sizeof (struct router_lsd);
  assert (lsdnum >= 0);

  for (; lsdnum; lsdnum --)
    {
      vty_out (vty, "     type[%s] cost[%hu] interface_id[%s]%s",
               rlsatype_name[rlsdp->rlsd_type - 1],
               ntohs(rlsdp->rlsd_metric),
               inet4str (rlsdp->rlsd_interface_id),
	       VTY_NEWLINE);
      vty_out (vty, "     NeighborIFID[%s]",
               inet4str (rlsdp->rlsd_neighbor_interface_id));
      vty_out (vty, "     NeighborRouter-ID[%s]%s",
               inet4str (rlsdp->rlsd_neighbor_router_id),
	       VTY_NEWLINE);
      rlsdp++;
    }
  return 0;
}

int show_network_lsa (struct vty *vty, void *data)
{
  int lsdnum;
  struct ospf6_lsa_hdr *lshp;
  struct network_lsa *nlsap;
  rtr_id_t *attached;

  assert (data);
  lshp = (struct ospf6_lsa_hdr *)data;
  nlsap = (struct network_lsa *)(lshp + 1);
  attached = (rtr_id_t *)(nlsap + 1);

  lsdnum = (ntohs (lshp->lsh_len) - sizeof (struct ospf6_lsa_hdr)
            - sizeof (struct network_lsa)) / sizeof (rtr_id_t);
  assert (lsdnum >= 0);

  for (; lsdnum; lsdnum --)
    {
      vty_out (vty, "     Attached Router[%s]%s", inet4str (*attached++),
	       VTY_NEWLINE);
    }
  return 0;
}

int
show_link_lsa (struct vty *vty, void *data)
{
  struct ospf6_lsa_hdr *lshp;
  struct link_lsa *llsap;
  int prefixnum;
  struct ospf6_prefix *prefix;
  char o6p_str[128], linklocal_str[128];

  assert (data);
  lshp = (struct ospf6_lsa_hdr *)data;
  llsap = (struct link_lsa *)(lshp + 1);
  prefixnum = ntohl (llsap->llsa_prefix_num);

  inet_ntop (AF_INET6, (void *)&llsap->llsa_linklocal, linklocal_str,
             sizeof (linklocal_str));
  vty_out (vty, "     linklocal[%s] #prefix[%d]%s",
           linklocal_str,
	   prefixnum,
	   VTY_NEWLINE);
  prefix = (struct ospf6_prefix *)(llsap + 1);
  for (; prefixnum; prefixnum--)
    {
      ospf6_prefix_str (prefix, o6p_str, sizeof (o6p_str));
      vty_out (vty, "     Prefix [%s]%s", o6p_str,
	       VTY_NEWLINE);
      prefix = OSPF6_NEXT_PREFIX (prefix);
    }
  return 0;
}

int show_intra_prefix_lsa (struct vty *vty, void *data)
{
  struct ospf6_lsa_hdr *lshp;
  struct intra_area_prefix_lsa *iap_lsa;
  struct ospf6_prefix *prefix;
  unsigned short prefixnum;
  char o6p_str[128];

  assert (data);
  lshp = (struct ospf6_lsa_hdr *)data;
  iap_lsa = (struct intra_area_prefix_lsa *)(lshp + 1);
  prefixnum = ntohs (iap_lsa->intra_prefix_num);

  vty_out (vty, "     # prefix [%d]%s", prefixnum,
	   VTY_NEWLINE);
  vty_out (vty, "     Referenced[%s]%s",
           print_ls_reference ((struct ospf6_lsa_hdr *)iap_lsa),
	   VTY_NEWLINE);

  prefix = (struct ospf6_prefix *)(iap_lsa + 1);
  for (; prefixnum; prefixnum--)
    {
      ospf6_prefix_str (prefix, o6p_str, sizeof (o6p_str));
      vty_out (vty, "     Prefix [%s]%s", o6p_str,
	       VTY_NEWLINE);
      prefix = OSPF6_NEXT_PREFIX (prefix);
    }
  return 0;
}

int show_as_external_lsa (struct vty *vty, void *data)
{
  struct ospf6_lsa_hdr *lsa_hdr;
  struct as_external_lsa *aselsa;
  struct in6_addr in6;
  char o6p_str[128];
  char ase_bits_str[8], *bitsp;

  assert (data);
  lsa_hdr = (struct ospf6_lsa_hdr *)data;
  aselsa = (struct as_external_lsa *)(lsa_hdr + 1);

  /* bits */
  bitsp = ase_bits_str;
  if (ASE_LSA_ISSET (aselsa, ASE_LSA_BIT_E))
    *bitsp++ = 'E';
  if (ASE_LSA_ISSET (aselsa, ASE_LSA_BIT_F))
    *bitsp++ = 'F';
  if (ASE_LSA_ISSET (aselsa, ASE_LSA_BIT_T))
    *bitsp++ = 'T';
  *bitsp = '\0';

  vty_out (vty, "     bits:%s, metric:%hu%s",
           ase_bits_str, ntohs (aselsa->ase_metric),
	   VTY_NEWLINE);

  memset (&in6, 0, sizeof (in6));
  memcpy (&in6, (void *)(aselsa + 1),
          OSPF6_PREFIX_SPACE (aselsa->ase_prefix_len));
  inet_ntop (AF_INET6, &in6, o6p_str, sizeof (o6p_str));

  vty_out (vty, "     opt:xxx, %s/%d%s", o6p_str, aselsa->ase_prefix_len,
	   VTY_NEWLINE);
  return 0;
}

int
vty_lsa (struct vty *vty, struct ospf6_lsa *lsa)
{
  struct ospf6_lsa_hdr *lsh;
  char advrtr[64];

  assert (lsa);
  lsh = lsa->lsa_hdr;
  assert (lsh);

  inet_ntop (AF_INET, &lsh->lsh_advrtr, advrtr, sizeof (advrtr));
  vty_out (vty, "%s AdvRtr:%s LS ID:%lu%s",
           lstype_name[typeindex (lsh->lsh_type)],
           advrtr, ntohl (lsh->lsh_id), VTY_NEWLINE);
  vty_out (vty, "    LS age:%d LS SeqNum:%#x LS Cksum:%#hx%s",
           ospf6_age_current (lsa),
           ntohl(lsh->lsh_seqnum),
           lsh->lsh_cksum,
	   VTY_NEWLINE);
  switch (ntohs (lsh->lsh_type))
    {
      case LST_ROUTER_LSA:
        show_router_lsa (vty, (void *)lsh);
        break;
      case LST_NETWORK_LSA:
        show_network_lsa (vty, (void *)lsh);
        break;
      case LST_LINK_LSA:
        show_link_lsa (vty, (void *)lsh);
        break;
      case LST_INTRA_AREA_PREFIX_LSA:
        show_intra_prefix_lsa (vty, (void *)lsh);
        break;
      case LST_AS_EXTERNAL_LSA:
        show_as_external_lsa (vty, (void *)lsh);
        break;
      default:
        break;
    }
  vty_out (vty, "%s", VTY_NEWLINE);
  return 0;
}

struct router_lsd *
get_router_lsd (rtr_id_t rtrid, struct ospf6_lsa *lsa)
{
  unsigned short lsh_len;
  struct router_lsa *rlsa;
  struct router_lsd *rlsd;

  if (ntohs (lsa->lsa_hdr->lsh_type) != LST_ROUTER_LSA)
    return NULL;

  lsh_len = ntohs (lsa->lsa_hdr->lsh_len);
  rlsa = (struct router_lsa *)(lsa->lsa_hdr + 1);
  rlsd = (struct router_lsd *)(rlsa + 1);

  for ( ; (char *)rlsd < (char *)(lsa->lsa_hdr) + lsh_len; rlsd++)
    if (rtrid == rlsd->rlsd_neighbor_router_id)
      return rlsd;

  return NULL;
}

/* xxx, messy, strange function name */
unsigned long
get_ifindex_to_router (rtr_id_t rtrid, struct ospf6_lsa *lsa)
{
  struct router_lsd *rlsd;
  char rtrid_str[64];

  assert (lsa);
  switch (ntohs (lsa->lsa_hdr->lsh_type))
    {
      case LST_ROUTER_LSA:
        rlsd = get_router_lsd (rtrid, lsa);
        if (!rlsd)
          {
            inet_ntop (AF_INET, &rtrid, rtrid_str, sizeof (rtrid_str));
            zlog_warn ("*** can't find ifindex to %s", rtrid_str); 
            return 0;
          }
        else
          return (ntohl (rlsd->rlsd_interface_id));
      case LST_NETWORK_LSA:
        return (ntohl (lsa->lsa_hdr->lsh_id));
      default:
        return 0;
    }
  return 0;
}



/* return list of LSAs that referencing this LSA(internal to area) */
void
get_referencing_lsa (list l, struct ospf6_lsa *lsa)
{
  list m;
  listnode n;
  struct ospf6_lsa *x;
  struct area *area;

  assert (lsa->scope);
  m = list_init ();
  switch (ntohs (lsa->lsa_hdr->lsh_type))
    {
      case LST_ROUTER_LSA:
        area = (struct area *) lsa->scope;
        ospf6_lsdb_collect_type_advrtr (m, htons (LST_INTRA_AREA_PREFIX_LSA),
                                        lsa->lsa_hdr->lsh_advrtr,
                                        (void *) area);
        for (n = listhead (m); n; nextnode (n))
          {
            x = getdata (n);
            if (is_reference_router_ok (x, lsa))
              {
                list_add_node (l, x);
              }
          }
        break;

      case LST_NETWORK_LSA:
        area = (struct area *) lsa->scope;
        x = ospf6_lsdb_lookup (htons (LST_INTRA_AREA_PREFIX_LSA),
                               lsa->lsa_hdr->lsh_id,
                               lsa->lsa_hdr->lsh_advrtr, (void *)area);
        if (x && is_reference_network_ok (x, lsa))
          {
            list_add_node (l, x);
          }
        break;

      default:
        break;
    }

  list_delete_all (m);

  return;
}

int
is_self_originated (struct ospf6_lsa *p)
{
  /* check router id */
  if (p->lsa_hdr->lsh_advrtr == ospf6->router_id)
    return 1;
  return 0;
}

struct ospf6_lsa *
reconstruct_lsa (struct ospf6_lsa *lsa)
{
  struct area *area;
  struct ospf6_interface *o6if;
  unsigned long ifindex;
  struct interface *ifp;
  struct route_node *rn;
  struct ospf6_redistribute_info *info;
  struct ospf6_lsa *new = NULL;

  switch (ntohs (lsa->lsa_hdr->lsh_type))
    {
      case LST_ROUTER_LSA:
        area = (struct area *) lsa->scope;
        assert (area);
        new = ospf6_make_router_lsa (area);
        if (!new)
          break;
        ospf6_lsa_flood (new);
        ospf6_lsdb_install (new);
        ospf6_lsa_unlock (new);
        break;

      case LST_NETWORK_LSA:
        ifindex = ntohl (lsa->lsa_hdr->lsh_id);
        ifp = if_lookup_by_index (ifindex);
        if (!ifp)
          {
            zlog_warn ("interface not found: index %d, "
                       "can't reconstruct", ifindex);
            return (struct ospf6_lsa *) NULL;
          }
        o6if = (struct ospf6_interface *) ifp->info;
        assert (o6if);
        new = ospf6_make_network_lsa (o6if);
        if (!new)
          break;
        ospf6_lsa_flood (new);
        ospf6_lsdb_install (new);
        ospf6_lsa_unlock (new);
        break;

      case LST_INTRA_AREA_PREFIX_LSA:
        /* XXX, assume LS-ID has addressing semantics */
        ifindex = ntohl (lsa->lsa_hdr->lsh_id);
        ifp = if_lookup_by_index (ifindex);
        if (!ifp)
          {
            zlog_warn ("interface not found: index %d, "
                       "can't reconstruct", ifindex);
            return (struct ospf6_lsa *) NULL;
          }
        o6if = (struct ospf6_interface *) ifp->info;
        assert (o6if);
        new = ospf6_make_intra_prefix_lsa (o6if);
        if (!new)
          break;
        ospf6_lsa_flood (new);
        ospf6_lsdb_install (new);
        ospf6_lsa_unlock (new);
        break;

      case LST_LINK_LSA:
        o6if = (struct ospf6_interface *) lsa->scope;
        assert (o6if);

#if 1
        ospf6_lsa_update_link (o6if);
        new = (struct ospf6_lsa *)1; /* xxx */
#else
        new = ospf6_make_link_lsax (o6if);
        if (!new)
          break;
        ospf6_lsa_flood (new);
        ospf6_lsdb_install (new);
        ospf6_lsa_unlock (new);
#endif
        break;

      case LST_AS_EXTERNAL_LSA:
        zlog_info ("Reconstruct ASExternal LSA:");
        ospf6_dump_lsa (lsa);

        new = NULL;
        for (rn = route_top (ospf6->redistribute_map);
             rn; rn = route_next (rn))
          {
            info = (struct ospf6_redistribute_info *) rn->info;
            if (! info || ntohl(lsa->lsa_hdr->lsh_id) != info->ls_id)
              continue;

            new = ospf6_lsa_create_as_external
                    (info, (struct prefix_ipv6 *) &rn->p);
          }
        if (! new)
          return NULL;

        ospf6_lsa_flood (new);
        ospf6_lsdb_install (new);
        ospf6_lsa_unlock (new);
        break;

      default:
        break;
    }

  return new;
}


/* new */

/* allocate memory for lsa data */
static struct ospf6_lsa_hdr *
malloc_ospf6_lsa_data (unsigned int size)
{
  struct ospf6_lsa_hdr *new;

  new = (struct ospf6_lsa_hdr *) XMALLOC (MTYPE_OSPF6_LSA, size);
  if (new)
    memset (new, 0, size);

  return new;
}

/* free memory of lsa data */
static void
free_ospf6_lsa_data (struct ospf6_lsa_hdr *data)
{
  XFREE (MTYPE_OSPF6_LSA, data);
  return;
}

/* allocate memory for struct ospf6_lsa */
static struct ospf6_lsa *
malloc_ospf6_lsa ()
{
  struct ospf6_lsa *new;

  new = (struct ospf6_lsa *) XMALLOC (MTYPE_OSPF6_LSA,
                                      sizeof (struct ospf6_lsa));
  if (new)
    memset (new, 0, sizeof (struct ospf6_lsa));

  return new;
}

/* free memory of struct ospf6_lsa */
static void
free_ospf6_lsa (struct ospf6_lsa *lsa)
{
  XFREE (MTYPE_OSPF6_LSA, lsa);
  return;
}

/* increment reference counter of  struct ospf6_lsa */
void
ospf6_lsa_lock (struct ospf6_lsa *lsa)
{
  lsa->lock++;
  return;
}

/* decrement reference counter of  struct ospf6_lsa */
void
ospf6_lsa_unlock (struct ospf6_lsa *lsa)
{
  /* decrement reference counter */
  lsa->lock--;

  /* if no reference, do delete */
  if (lsa->lock == 0)
    {
      /* threads */
      if (lsa->expire)
        thread_cancel (lsa->expire);
      if (lsa->refresh)
        thread_cancel (lsa->refresh);

      /* lists */
      assert (list_isempty (lsa->summary_nbr));
      list_delete_all (lsa->summary_nbr);
      assert (list_isempty (lsa->request_nbr));
      list_delete_all (lsa->request_nbr);
      assert (list_isempty (lsa->retrans_nbr));
      list_delete_all (lsa->retrans_nbr);
      assert (list_isempty (lsa->delayed_ack_if));
      list_delete_all (lsa->delayed_ack_if);

      /* do free */
      free_ospf6_lsa_data (lsa->lsa_hdr);
      free_ospf6_lsa (lsa);
    }

  return;
}


/* ospf6_lsa expired */
void
ospf6_lsa_maxage_remove (struct ospf6_lsa *lsa)
{
  /* assert MaxAge */
  assert (ospf6_age_current (lsa) == MAXAGE);

  /* assert this LSA is still on database */
  assert (ospf6_lsdb_lookup (lsa->lsa_hdr->lsh_type, lsa->lsa_hdr->lsh_id,
                             lsa->lsa_hdr->lsh_advrtr, lsa->scope));

  /* if still included in someone's retrans list */
  if (lsa->lock != 1)
    return;

  /* log */
  if (IS_OSPF6_DUMP_LSA)
    {
      zlog_info ("LSA: Remove MaxAge LSA:");
      ospf6_dump_lsa (lsa);
    }

  /* remove from lsdb. this will free lsa */
  ospf6_lsdb_remove (lsa);
}

int
ospf6_lsa_expire (struct thread *thread)
{
  struct ospf6_lsa *lsa;

  lsa = (struct ospf6_lsa *) THREAD_ARG (thread);
  assert (lsa && lsa->lsa_hdr);

  /* assertion */
  assert (ospf6_age_current (lsa) >= MAXAGE);
  assert (!lsa->refresh);

  lsa->expire = (struct thread *) NULL;

  /* log */
  if (IS_OSPF6_DUMP_LSA)
    {
      zlog_info ("LSA: Expire:");
      ospf6_dump_lsa (lsa);
    }

  /* reflood lsa */
  ospf6_lsa_flood (lsa);

  /* do nothing about lslists. wait event */
  return 0;
}

int
ospf6_lsa_refresh (struct thread *thread)
{
  struct ospf6_lsa *lsa;

  assert (thread);
  lsa = (struct ospf6_lsa *) THREAD_ARG  (thread);
  assert (lsa && lsa->lsa_hdr);

  /* this will be used later as flag to decide really originate */
  lsa->refresh = (struct thread *)NULL;

  /* log */
  if (IS_OSPF6_DUMP_LSA)
    {
      zlog_info ("LSA: Refresh:");
      ospf6_dump_lsa (lsa);
    }

  if (reconstruct_lsa (lsa) == NULL)
    zlog_warn ("*** Refresh LSA failed");

  return 0;
}


/* ospf6 ages */
/* calculate birth and set expire timer */
static void
ospf6_age_set (struct ospf6_lsa *lsa)
{
  struct timeval now;

  assert (lsa && lsa->lsa_hdr);

  if (gettimeofday (&now, (struct timezone *)NULL) < 0)
    zlog_warn ("*** gettimeofday failed, may fail ages: %s",
               strerror (errno));

  lsa->birth = now.tv_sec - ntohs (lsa->lsa_hdr->lsh_age);
  lsa->expire = thread_add_timer (master, ospf6_lsa_expire, lsa,
                                  lsa->birth + MAXAGE - now.tv_sec);
  return;
}

/* get current age */
unsigned short
ospf6_age_current (struct ospf6_lsa *lsa)
{
  struct timeval now;
  unsigned long ulage;
  unsigned short age;

  assert (lsa && lsa->lsa_hdr);

  /* current time */
  if (gettimeofday (&now, (struct timezone *)NULL) < 0)
    zlog_warn ("*** gettimeofday failed, may fail ages: %s",
               strerror (errno));

  /* calculate age */
  ulage = now.tv_sec - lsa->birth;

  /* if over MAXAGE, set to it */
  if (ulage > MAXAGE)
    age = MAXAGE;
  else
    age = ulage;

  lsa->lsa_hdr->lsh_age = htons (age);
  return age;
}

/* update age field of lsa_hdr, add InfTransDelay */
void
ospf6_age_update_to_send (struct ospf6_lsa *lsa, struct ospf6_interface *o6if)
{
  unsigned short age;
  age = ospf6_age_current (lsa) + o6if->transdelay;
  if (age > MAXAGE)
    age = MAXAGE;
  lsa->lsa_hdr->lsh_age = htons (age);
  return;
}

void
ospf6_premature_aging (struct ospf6_lsa *lsa)
{
  /* log */
  /* if (IS_OSPF6_DUMP_LSA) */
    {
      zlog_info ("LSA: Premature aging");
      ospf6_dump_lsa (lsa);
    }

  if (lsa->expire)
    thread_cancel (lsa->expire);
  lsa->expire = (struct thread *) NULL;
  if (lsa->refresh)
    thread_cancel (lsa->refresh);
  lsa->refresh = (struct thread *) NULL;

  lsa->birth = 0;
  thread_execute (master, ospf6_lsa_expire, lsa, 0);
}


/* make data of ospf6_lsa(copy buffer) */
struct ospf6_lsa_hdr *
make_ospf6_lsa_data (struct ospf6_lsa_hdr *hdr, int size)
{
  struct ospf6_lsa_hdr *lsa_hdr = malloc_ospf6_lsa_data (size);
  if (lsa_hdr)
    memcpy (lsa_hdr, hdr, size);
  return lsa_hdr;
}

/* make ospf6_lsa */
struct ospf6_lsa *
make_ospf6_lsa (struct ospf6_lsa_hdr *hdr)
{
  char buf[128];
  struct ospf6_lsa *lsa = malloc_ospf6_lsa ();

  /* increment reference counter */
  ospf6_lsa_lock (lsa);

  /* dump string */
  snprintf (lsa->str, sizeof (lsa->str), "%s AdvRtr:%s LS-ID:%lu",
            lstype_name[typeindex (hdr->lsh_type)],
            inet_ntop (AF_INET, &hdr->lsh_advrtr, buf, sizeof (buf)),
            (unsigned long) ntohl (hdr->lsh_id));

  /* body set */
  lsa->lsa_hdr = hdr;

  /* calculate birth and expire of this lsa */
  ospf6_age_set (lsa);

  /* list init */
  lsa->summary_nbr = list_init ();
  lsa->request_nbr = list_init ();
  lsa->retrans_nbr = list_init ();
  lsa->delayed_ack_if = list_init ();

  /* leave other members */
  return lsa;
}

struct ospf6_lsa *
make_ospf6_lsa_summary (struct ospf6_lsa_hdr *hdr)
{
  struct ospf6_lsa *lsa;
  lsa = make_ospf6_lsa (hdr);
  lsa->summary = 1;
  return lsa;
}

unsigned short
ospf6_lsa_get_scope_type (unsigned short type)
{
  return (ntohs (type) & SCOPE_MASK);
}

void
ospf6_lsa_clear_flag (struct ospf6_lsa *lsa)
{
  assert (lsa && lsa->lsa_hdr);
  lsa->flags = 0;
  return;
}

void
ospf6_lsa_set_flag (struct ospf6_lsa *lsa, unsigned char flag)
{
  assert (lsa && lsa->lsa_hdr);
  lsa->flags |= flag;
  return;
}

int
ospf6_lsa_test_flag (struct ospf6_lsa *lsa, unsigned char flag)
{
  assert (lsa && lsa->lsa_hdr);
  return (lsa->flags & flag);
}

/* test LSAs identity */
int
ospf6_lsa_issame (struct ospf6_lsa_hdr *lsh1, struct ospf6_lsa_hdr *lsh2)
{
  assert (lsh1 && lsh2);
  if (lsh1->lsh_advrtr != lsh2->lsh_advrtr)
    return 0;
  if (lsh1->lsh_id != lsh2->lsh_id)
    return 0;
  if (lsh1->lsh_type != lsh2->lsh_type)
    return 0;
  return 1;
}

/* calculate LS sequence number for my new LSA.
   return value is network byte order */
static signed long
ospf6_seqnum_new (unsigned short type, unsigned long id,
                  unsigned long advrtr, void *scope)
{
  struct ospf6_lsa *lsa;
  signed long seqnum;

  /* get current database copy */
  lsa = ospf6_lsdb_lookup (type, id, advrtr, scope);

  /* if current database copy not found, return InitialSequenceNumber */
  if (!lsa)
    seqnum = INITIAL_SEQUENCE_NUMBER;
  else
    seqnum = (signed long) ntohl (lsa->lsa_hdr->lsh_seqnum) + 1;

  return (htonl (seqnum));
}


/* make lsa functions */
/* these "make lsa" functions bellow returns lsa that has one empty lock.
   so unlock within caller function */

/* set field of rlsd from ospf6_interface */
static void
ospf6_router_lsd_set (struct router_lsd *rlsd, struct ospf6_interface *o6if)
{
  assert (o6if);

  /* common field for each link type */
  rlsd->rlsd_metric = htons (o6if->cost);
  rlsd->rlsd_interface_id = htonl (o6if->if_id);

  /* set LS description for each link type */
  if (if_is_pointopoint (o6if->interface))
    {
      struct neighbor *nbr;

      /* pointopoint specific assertion */
      assert (listcount (o6if->neighbor_list) == 1);
      nbr = (struct neighbor *) getdata (listhead (o6if->neighbor_list));
      assert (nbr && nbr->state == NBS_FULL);

      rlsd->rlsd_type = LSDT_POINTTOPOINT;
      rlsd->rlsd_neighbor_interface_id = htonl (nbr->ifid);
      rlsd->rlsd_neighbor_router_id = nbr->rtr_id;
    }
  else /* if (if_is_broadcast (o6if->interface)) */
    {
      /* else, assume this is broadcast. other types not supported */
      rlsd->rlsd_type = LSDT_TRANSIT_NETWORK;

      /* different neighbor field between DR and others */
      if (o6if->state == IFS_DR)
        {
          rlsd->rlsd_neighbor_interface_id = htonl (o6if->if_id);
          rlsd->rlsd_neighbor_router_id = o6if->area->ospf6->router_id;
        }
      else
        {
          /* find DR */
          struct neighbor *dr;
          dr = nbr_lookup (o6if->dr, o6if);
          assert (dr);
          rlsd->rlsd_neighbor_interface_id = htonl (dr->ifid);
          rlsd->rlsd_neighbor_router_id = dr->rtr_id;
        }
    }
  return;
}

struct ospf6_lsa *
ospf6_make_router_lsa (struct area *area)
{
  struct ospf6_lsa *lsa;
  struct ospf6_lsa_hdr *lsa_hdr;
  struct router_lsa *rlsa;
  struct router_lsd *rlsd;
  struct ospf6_interface *o6if;
  listnode i;
  list described_link = list_init ();
  size_t space;

  /* get links to describe */
  for (i = listhead (area->if_list); i; nextnode (i))
    {
      o6if = (struct ospf6_interface *) getdata (i);
      assert (o6if);

      /* if interface is not enabled, ignore */
      if (o6if->state <= IFS_LOOPBACK)
        continue;

      /* if interface is stub, ignore */
      if (ospf6_interface_count_full_nbr (o6if))
        list_add_node (described_link, o6if);
    }

  /* get space needed for my RouterLSA */
  space = sizeof (struct ospf6_lsa_hdr) + sizeof (struct router_lsa)
          + (sizeof (struct router_lsd) * listcount (described_link));

  /* malloc buffer */
  lsa_hdr = malloc_ospf6_lsa_data (space);

  /* set lsa header */
    /* xxx, multiple (seperate) Router-LSA not yet,
       LS-ID of Router-LSA will be always the same */
  lsa_hdr->lsh_age = 0;
  lsa_hdr->lsh_type = htons (LST_ROUTER_LSA);
  lsa_hdr->lsh_id = htonl (MY_ROUTER_LSA_ID);
  lsa_hdr->lsh_advrtr = area->ospf6->router_id;
  lsa_hdr->lsh_seqnum = ospf6_seqnum_new (lsa_hdr->lsh_type,
                                          lsa_hdr->lsh_id,
                                          lsa_hdr->lsh_advrtr,
                                          (void *)area);
  /* xxx, checksum */
  lsa_hdr->lsh_len = htons (space);

  /* set router_lsa */
  rlsa = (struct router_lsa *) (lsa_hdr + 1);
    /* options */
  V3OPT_SET (rlsa->rlsa_options, V3OPT_V6);  /* V6bit set */
  V3OPT_SET (rlsa->rlsa_options, V3OPT_R);   /* Rbit set */
  V3OPT_SET (rlsa->rlsa_options, V3OPT_E);   /* Ebit set */
    /* router lsa bits, xxx not yet */
  ROUTER_LSA_CLEAR (rlsa, ROUTER_LSA_BIT_W);
  ROUTER_LSA_CLEAR (rlsa, ROUTER_LSA_BIT_V);
  ROUTER_LSA_CLEAR (rlsa, ROUTER_LSA_BIT_B);
  if (area->ospf6->redist_static || area->ospf6->redist_kernel ||
      area->ospf6->redist_ripng || area->ospf6->redist_bgp)
    ROUTER_LSA_SET (rlsa, ROUTER_LSA_BIT_E);
  else
    ROUTER_LSA_CLEAR (rlsa, ROUTER_LSA_BIT_E);

  /* set LS description for each link */
  rlsd = (struct router_lsd *) (rlsa + 1);
  for (i = listhead (described_link); i; nextnode (i))
    {
      o6if = (struct ospf6_interface *) getdata (i);
      assert (o6if);
      ospf6_router_lsd_set (rlsd++, o6if);
    }

  /* age calculation, scope, etc */
  ospf6_lsa_checksum (lsa_hdr);
  lsa = make_ospf6_lsa (lsa_hdr);
  lsa->scope = (void *) area;
  lsa->from = (struct neighbor *) NULL;
  lsa->refresh = thread_add_timer (master, ospf6_lsa_refresh, lsa,
                                   OSPF6_LS_REFRESH_TIME);

  /* free temporary list */
  list_delete_all (described_link);

  return lsa;
}

struct ospf6_lsa *
ospf6_make_network_lsa (struct ospf6_interface *o6if)
{
  struct ospf6_lsa *lsa;
  struct ospf6_lsa_hdr *lsa_hdr;
  struct network_lsa *nlsa;
  rtr_id_t *nlsd; /* LS description of NetworkLSA is Router ID */
  listnode i;
  size_t space;
  int fullnbrnum;
  struct neighbor *nbr;

  assert (o6if);

  /* If not DR, return NULL */
  if (o6if->state != IFS_DR)
    {
      zlog_warn ("*** %s is not DR, don't make NetworkLSA",
                 o6if->interface->name);
      return (struct ospf6_lsa *) NULL;
    }

  /* count full neighbor */
  fullnbrnum = ospf6_interface_count_full_nbr (o6if);

  /* if this link is stub, return NULL */
  if (!fullnbrnum)
    return (struct ospf6_lsa *) NULL;

  /* get space needed for my NetworkLSA */
    /* + 1 for my router id */
  space = sizeof (struct ospf6_lsa_hdr) + sizeof (struct network_lsa)
          + (sizeof (rtr_id_t) * (fullnbrnum + 1));

  /* malloc buffer */
  lsa_hdr = malloc_ospf6_lsa_data (space);

  /* set lsa header */
  lsa_hdr->lsh_age = 0;
  lsa_hdr->lsh_type = htons (LST_NETWORK_LSA);
  lsa_hdr->lsh_id = htonl (o6if->if_id);
  lsa_hdr->lsh_advrtr = o6if->area->ospf6->router_id;
  lsa_hdr->lsh_seqnum = ospf6_seqnum_new (lsa_hdr->lsh_type,
                                          lsa_hdr->lsh_id,
                                          lsa_hdr->lsh_advrtr,
                                          (void *)o6if->area);
  /* xxx, checksum */
  lsa_hdr->lsh_len = htons (space);

  /* set network_lsa */
  nlsa = (struct network_lsa *) (lsa_hdr + 1);
    /* xxx, set options to logical OR of all link lsa's options.
       this not yet, currently copy from mine */
  memcpy (nlsa->nlsa_options, o6if->area->options,
          sizeof (nlsa->nlsa_options));

  /* set router id for each full neighbor */
  nlsd = (rtr_id_t *) (nlsa + 1);
  for (i = listhead (o6if->neighbor_list); i; nextnode (i))
    {
      nbr = (struct neighbor *) getdata (i);
      assert (nbr);
      if (nbr->state == NBS_FULL)
        *nlsd++ = nbr->rtr_id;
    }
  /* set my router id */
  *nlsd = o6if->area->ospf6->router_id;

  /* age calculation, scope, etc */
  ospf6_lsa_checksum (lsa_hdr);
  lsa = make_ospf6_lsa (lsa_hdr);
  lsa->scope = (void *) o6if->area;
  lsa->from = (struct neighbor *) NULL;
  lsa->refresh = thread_add_timer (master, ospf6_lsa_refresh, lsa,
                                   OSPF6_LS_REFRESH_TIME);

  return lsa;
}

struct ospf6_lsa *
ospf6_make_link_lsa (struct ospf6_interface *o6if)
{

  struct ospf6_lsa *lsa;
  struct ospf6_lsa_hdr *lsa_hdr;
  struct link_lsa *llsa;
  struct ospf6_prefix *p1, *p2; /* LS description is ospf6 prefix */
  listnode i;
  size_t space;
  unsigned long prefixnum;
  struct route_node *rn;
  struct ospf6_route_node_info *info;
  list prefix_connected;
  struct ospf6_nexthop *nh;

  assert (o6if);

  /* can't make LinkLSA if linklocal address not set */
  if (!o6if->lladdr)
    return (struct ospf6_lsa *) NULL;

  /* get prefix number */
  prefix_connected = list_init ();
  for (rn = route_top (ospf6->table_connected); rn;
       rn = route_next (rn))
    {
      info = (struct ospf6_route_node_info *) rn->info;
      if (!info)
        continue;
      for (i = listhead (info->nhlist); i; nextnode (i))
        {
          nh = (struct ospf6_nexthop *) getdata (i);
          if (nh->ifindex != o6if->if_id)
            continue;
          p1 = ospf6_prefix_make (0, 0, (struct prefix_ipv6 *) &rn->p);
          ospf6_prefix_add (prefix_connected, p1);
        }
    }
  prefixnum = listcount (prefix_connected);

  /* get space needed for my LinkLSA */
  space = 0;
  for (i = listhead (prefix_connected); i; nextnode (i))
    {
      p1 = (struct ospf6_prefix *) getdata (i);
      space += OSPF6_PREFIX_SIZE (p1);
    }
  space += sizeof (struct ospf6_lsa_hdr) + sizeof (struct link_lsa);

  /* malloc buffer */
  lsa_hdr = malloc_ospf6_lsa_data (space);

  /* set lsa header */
  lsa_hdr->lsh_age = 0;
  lsa_hdr->lsh_type = htons (LST_LINK_LSA);
  lsa_hdr->lsh_id = htonl (o6if->if_id);
  lsa_hdr->lsh_advrtr = o6if->area->ospf6->router_id;
  lsa_hdr->lsh_seqnum = ospf6_seqnum_new (lsa_hdr->lsh_type,
                                          lsa_hdr->lsh_id,
                                          lsa_hdr->lsh_advrtr,
                                          (void *)o6if);
  /* xxx, checksum */
  lsa_hdr->lsh_len = htons (space);

  /* set link_lsa pointer */
  llsa = (struct link_lsa *) (lsa_hdr + 1);

  /* set router priority */
  llsa->llsa_rtr_pri = o6if->priority;

  /* set options same as options stored in area */
  memcpy (llsa->llsa_options, o6if->area->options,
          sizeof (llsa->llsa_options));

  /* set linklocal address */
  memcpy (&llsa->llsa_linklocal, o6if->lladdr, sizeof (struct in6_addr));

  /* if KAME, clear ifindex included in linklocal address */
#ifdef KAME
  if (llsa->llsa_linklocal.s6_addr[3] & 0x0f)
    {
      /* clear ifindex */
      llsa->llsa_linklocal.s6_addr[3] &= ~((char)0x0f);
    }
#endif /* KAME */

  /* set prefix num */
  llsa->llsa_prefix_num = htonl (prefixnum);

  /* set ospf6 prefixes */
  p1 = (struct ospf6_prefix *)(llsa + 1);
  space -= sizeof (struct link_lsa) + sizeof (struct ospf6_lsa_hdr);
  for (i = listhead (prefix_connected); i; nextnode (i))
    {
      p2 = (struct ospf6_prefix *) getdata (i);

      /* copy p2 to p1 */
      ospf6_prefix_copy (p1, p2, space);
      space -= OSPF6_PREFIX_SIZE(p2);

      p1 = OSPF6_NEXT_PREFIX (p1);
    }

  /* delete temporary prefix_connected list */
  for (i = listhead (prefix_connected); i; nextnode (i))
    {
      p1 = (struct ospf6_prefix *) getdata (i);
      ospf6_prefix_free (p1);
    }
  list_delete_all (prefix_connected);

  /* age calculation, scope, etc */
  ospf6_lsa_checksum (lsa_hdr);
  lsa = make_ospf6_lsa (lsa_hdr);
  lsa->scope = (void *) o6if;
  lsa->from = (struct neighbor *) NULL;
  lsa->refresh = thread_add_timer (master, ospf6_lsa_refresh, lsa,
                                   OSPF6_LS_REFRESH_TIME);

  return lsa;
}

struct ospf6_lsa *
ospf6_make_intra_prefix_lsa (struct ospf6_interface *o6if)
{
  struct ospf6_lsa *lsa;
  struct ospf6_lsa_hdr *lsa_hdr;
  struct intra_area_prefix_lsa *iaplsa;
  struct ospf6_prefix *p1, *p2; /* LS description is ospf6 prefix */
  listnode n;
  size_t space;
  list advertise = list_init ();
  struct link_lsa *llsa;
  unsigned short prefixnum;
  int i;
  struct neighbor *nbr;

  assert (o6if);

  /* if not stub and not DR, don't make IntraAreaPrefixLSA */
  if (ospf6_interface_count_full_nbr (o6if) != 0 && o6if->state != IFS_DR)
    {
      list_delete_all (advertise);
      return (struct ospf6_lsa *)NULL;
    }

  /* get all prefix that is to be advertised for this interface */
  if (o6if->state == IFS_DR)
    {
      /* if DR, care about prefix advertised with LinkLSA
         by another router */
      for (n = listhead (o6if->neighbor_list); n; nextnode (n))
        {
          nbr = (struct neighbor *) getdata (n);

          /* if not full, ignore this neighbor */
          if (nbr->state != NBS_FULL)
            continue;

          /* get LinkLSA of this neighbor.
             if not found, log and ignore */
          lsa = ospf6_lsdb_lookup (htons (LST_LINK_LSA),
                                   htonl (nbr->ifid),
                                   nbr->rtr_id, (void *)o6if);
          if (!lsa)
            {
              zlog_warn ("*** LinkLSA not found for full neighbor %s",
                         nbr->str);
              continue;
            }

          llsa = (struct link_lsa *)(lsa->lsa_hdr + 1);
          p1 = (struct ospf6_prefix *)(llsa + 1);
          /* for each prefix listed in this LinkLSA */
          for (i = 0; i < ntohl (llsa->llsa_prefix_num); i++)
            {
              /* add to advertise list. duplicate won't be added */
              ospf6_prefix_add (advertise, p1);
              p1 = OSPF6_NEXT_PREFIX (p1);
            }
        }
    }

  /* add prefixes in my LinkLSA to advertise list */
  lsa = ospf6_lsdb_lookup (htons (LST_LINK_LSA), htonl (o6if->if_id),
                           o6if->area->ospf6->router_id, (void *)o6if);
  if (!lsa)
    zlog_warn ("*** My LinkLSA not found for %s", o6if->interface->name);
  else
    {
      llsa = (struct link_lsa *)(lsa->lsa_hdr + 1);
      p1 = (struct ospf6_prefix *)(llsa + 1);
      /* for each prefix listed in my LinkLSA */
      for (i = 0; i < ntohl (llsa->llsa_prefix_num); i++)
        {
          /* add to advertise list. duplicate won't be added */
          ospf6_prefix_add (advertise, p1);
          p1 = OSPF6_NEXT_PREFIX (p1);
        }
    }

  /* get prefix number */
  prefixnum = listcount (advertise);

  /* if no prefix, no need to make IntraAreaPrefixLSA */
  if (!prefixnum)
    {
      list_delete_all (advertise);
      return (struct ospf6_lsa *)NULL;
    }

  /* get space needed for my IntraAreaPrefixLSA */
  space = 0;
  for (n = listhead (advertise); n; nextnode (n))
    {
      p1 = (struct ospf6_prefix *) getdata (n);
      space += OSPF6_PREFIX_SIZE (p1);
    }
  space += sizeof (struct ospf6_lsa_hdr)
          + sizeof (struct intra_area_prefix_lsa);

  /* malloc buffer */
  lsa_hdr = malloc_ospf6_lsa_data (space);

  /* set lsa header */
  lsa_hdr->lsh_age = 0;
  lsa_hdr->lsh_type = htons (LST_INTRA_AREA_PREFIX_LSA);
  lsa_hdr->lsh_id = htonl (o6if->if_id);
  lsa_hdr->lsh_advrtr = o6if->area->ospf6->router_id;
  lsa_hdr->lsh_seqnum = ospf6_seqnum_new (lsa_hdr->lsh_type,
                                          lsa_hdr->lsh_id,
                                          lsa_hdr->lsh_advrtr,
                                          (void *)o6if->area);
  /* xxx, checksum */
  lsa_hdr->lsh_len = htons (space);

  /* set intra_area_prefix_lsa */
  iaplsa = (struct intra_area_prefix_lsa *) (lsa_hdr + 1);
    /* set prefix num */
  iaplsa->intra_prefix_num = htons (prefixnum);
    /* set referrenced lsa */
  if (o6if->state == IFS_DR && ospf6_interface_count_full_nbr (o6if))
    {
      /* refer to NetworkLSA */
      iaplsa->intra_prefix_refer_lstype = htons (LST_NETWORK_LSA);
      iaplsa->intra_prefix_refer_lsid = htonl (o6if->if_id);
    }
  else
    {
      /* refer to RouterLSA */
      iaplsa->intra_prefix_refer_lstype = htons (LST_ROUTER_LSA);
      iaplsa->intra_prefix_refer_lsid = htonl (0);
    }
  iaplsa->intra_prefix_refer_advrtr = o6if->area->ospf6->router_id;

  /* set ospf6 prefixes */
  p1 = (struct ospf6_prefix *)(iaplsa + 1);
  space -= sizeof (struct intra_area_prefix_lsa)
           + sizeof (struct ospf6_lsa_hdr);
  for (n = listhead (advertise); n; nextnode (n))
    {
      p2 = (struct ospf6_prefix *) getdata (n);

      /* copy p2 to p1 */
      ospf6_prefix_copy (p1, p2, space);
      space -= OSPF6_PREFIX_SIZE(p2);

      p1 = OSPF6_NEXT_PREFIX (p1);
    }

  /* age calculation, scope, etc */
  ospf6_lsa_checksum (lsa_hdr);
  lsa = make_ospf6_lsa (lsa_hdr);
  lsa->scope = (void *) o6if->area;
  lsa->from = (struct neighbor *) NULL;
  lsa->refresh = thread_add_timer (master, ospf6_lsa_refresh, lsa,
                                   OSPF6_LS_REFRESH_TIME);

  list_delete_all (advertise);
  return lsa;
}

struct ospf6_lsa *
ospf6_make_as_external_lsa (struct route_node *rn)
{
  struct ospf6_route_node_info *info;
  struct ospf6_lsa *lsa;
  struct ospf6_lsa_hdr *lsa_hdr;
  struct as_external_lsa *aselsa;
  char *prefix_start;
  size_t space;

  /* info */
  info = (struct ospf6_route_node_info *) rn->info;
  assert (info);

  /* get space needed for my ASExternalLSA */
  space = sizeof (struct ospf6_lsa_hdr)
          + sizeof (struct as_external_lsa)
          + OSPF6_PREFIX_SPACE (rn->p.prefixlen);

  /* malloc buffer */
  lsa_hdr = malloc_ospf6_lsa_data (space);

  /* if this if first time, set LS ID */
  if (!info->ase_lsid)
    {
      ospf6->ase_ls_id++;
      info->ase_lsid = htonl (ospf6->ase_ls_id);
      zlog_info ("ASEx-LSA LSA ID set to %lu(%lu)",
                 ntohl (info->ase_lsid), ospf6->ase_ls_id);
    }

  /* set lsa header */
  lsa_hdr->lsh_age = 0;
  lsa_hdr->lsh_type = htons (LST_AS_EXTERNAL_LSA);
  lsa_hdr->lsh_id = info->ase_lsid;
  lsa_hdr->lsh_advrtr = ospf6->router_id;
  lsa_hdr->lsh_seqnum = ospf6_seqnum_new (lsa_hdr->lsh_type,
                                          lsa_hdr->lsh_id,
                                          lsa_hdr->lsh_advrtr,
                                          (void *)ospf6);
  /* xxx, checksum */
  lsa_hdr->lsh_len = htons (space);

  /* set as_external_lsa */
  aselsa = (struct as_external_lsa *) (lsa_hdr + 1);

  /* xxx, set ase_bits */
  if (info->path_type == PTYPE_TYPE1_EXTERNAL)
    ASE_LSA_CLEAR (aselsa, ASE_LSA_BIT_E); /* type1 */
  else
    ASE_LSA_SET (aselsa, ASE_LSA_BIT_E); /* type2 */
  ASE_LSA_CLEAR (aselsa, ASE_LSA_BIT_F); /* forwarding address */
  ASE_LSA_CLEAR (aselsa, ASE_LSA_BIT_T); /* external route tag */

  /* xxx, don't know how to use ase_pre_metric */
  aselsa->ase_pre_metric = 0;

  /* set metric. related to E bit */
  aselsa->ase_metric = htons (info->cost);

  /* prefixlen */
  aselsa->ase_prefix_len = rn->p.prefixlen;

  /* xxx, opt */

  /* set ase_refer_lstype */
  aselsa->ase_refer_lstype = 0;

  /* set ospf6 prefix */
  prefix_start = (char *)(aselsa + 1);
  memcpy (prefix_start, &rn->p.u.prefix,
          OSPF6_PREFIX_SPACE (rn->p.prefixlen));

  /* age calculation, scope, etc */
  ospf6_lsa_checksum (lsa_hdr);
  lsa = make_ospf6_lsa (lsa_hdr);
  lsa->scope = (void *) ospf6;
  lsa->from = (struct neighbor *) NULL;
  lsa->refresh = thread_add_timer (master, ospf6_lsa_refresh, lsa,
                                   OSPF6_LS_REFRESH_TIME);

  /* set ls origin here for as external */
  info->ls_origin = lsa;

  return lsa;
}

struct ospf6_lsa *
ospf6_lsa_create_as_external (struct ospf6_redistribute_info *info,
                              struct prefix_ipv6 *p)
{
  size_t space;

  struct ospf6_lsa *lsa;
  struct ospf6_lsa_hdr *lsa_hdr;
  struct as_external_lsa *aselsa;
  char *prefix_start;

  /* get space needed for my ASExternalLSA */
  space = sizeof (struct ospf6_lsa_hdr) + sizeof (struct as_external_lsa)
          + OSPF6_PREFIX_SPACE (p->prefixlen);

  /* malloc buffer */
  lsa_hdr = malloc_ospf6_lsa_data (space);

  /* set lsa header */
  lsa_hdr->lsh_age = 0;
  lsa_hdr->lsh_type = htons (LST_AS_EXTERNAL_LSA);
  lsa_hdr->lsh_id = htonl (info->ls_id);
  lsa_hdr->lsh_advrtr = ospf6->router_id;
  lsa_hdr->lsh_seqnum = ospf6_seqnum_new (lsa_hdr->lsh_type,
                                          lsa_hdr->lsh_id,
                                          lsa_hdr->lsh_advrtr,
                                          (void *)ospf6);

  /* xxx, checksum */
  lsa_hdr->lsh_len = htons (space);

  /* set as_external_lsa */
  aselsa = (struct as_external_lsa *) (lsa_hdr + 1);

  if (info->metric_type == 2)
    ASE_LSA_SET (aselsa, ASE_LSA_BIT_E);   /* type2 */
  else
    ASE_LSA_CLEAR (aselsa, ASE_LSA_BIT_E);   /* type1 */

  ASE_LSA_CLEAR (aselsa, ASE_LSA_BIT_F); /* forwarding address */
  ASE_LSA_CLEAR (aselsa, ASE_LSA_BIT_T); /* external route tag */

  /* xxx, don't know how to use ase_pre_metric */
  aselsa->ase_pre_metric = 0;

  /* set metric. related to E bit */
  aselsa->ase_metric = htons (info->metric);

  /* prefixlen */
  aselsa->ase_prefix_len = p->prefixlen;

  /* xxx, opt */

  /* set ase_refer_lstype */
  aselsa->ase_refer_lstype = 0;

  /* set ospf6 prefix */
  prefix_start = (char *)(aselsa + 1);
  memcpy (prefix_start, &p->prefix,
          OSPF6_PREFIX_SPACE (p->prefixlen));

  /* age calculation, scope, etc */
  ospf6_lsa_checksum (lsa_hdr);
  lsa = make_ospf6_lsa (lsa_hdr);
  lsa->scope = (void *) ospf6;
  lsa->from = (struct neighbor *) NULL;
  lsa->refresh = thread_add_timer (master, ospf6_lsa_refresh, lsa,
                                   OSPF6_LS_REFRESH_TIME);

  return lsa;
}

void
ospf6_lsa_originate_intraprefix (struct ospf6_interface *o6if)
{
  struct ospf6_lsa *lsa;
  lsa = ospf6_make_intra_prefix_lsa (o6if);
  if (lsa)
    {
      ospf6_lsa_flood (lsa);
      ospf6_lsdb_install (lsa);
      ospf6_lsa_unlock (lsa);

      /* log */
      if (IS_OSPF6_DUMP_LSA)
        zlog_info ("Originate Intra-Area-Prefix-LSA");
    }
}

void
ospf6_lsa_originate_network (struct ospf6_interface *o6if)
{
}

void
ospf6_lsa_originate_router (struct area *o6a)
{
}

void
ospf6_lsa_originate_asexternal ()
{
}

void
ospf6_lsa_hdr_id_str (struct ospf6_lsa_hdr *lsa_hdr, char *buf, size_t bufsize)
{
  char *type, unknown[16], advrtr[16];

  assert (lsa_hdr);

  /* LS type */
  switch (ntohs (lsa_hdr->lsh_type))
    {
      case LST_ROUTER_LSA:
        type = "Router-LSA";
        break;
      case LST_NETWORK_LSA:
        type = "Network-LSA";
        break;
      case LST_AS_EXTERNAL_LSA:
        type = "AS-external-LSA";
        break;
      case LST_LINK_LSA:
        type = "Link-LSA";
        break;
      case LST_INTRA_AREA_PREFIX_LSA:
        type = "Intra-Area-Prefix-LSA";
        break;
      default:
        snprintf (unknown, sizeof (unknown), "unknown(%#x)",
                  ntohs(lsa_hdr->lsh_type));
        type = unknown;
        break;
    }

  /* LS advrtr */
  inet_ntop (AF_INET, &lsa_hdr->lsh_advrtr, advrtr, sizeof (advrtr));

  snprintf (buf, bufsize, "%s: id:%lu advrtr:%s",
            type, (unsigned long) ntohl (lsa_hdr->lsh_id), advrtr);
}

void
ospf6_lsa_hdr_str (struct ospf6_lsa_hdr *lsa_hdr, char *buf, size_t bufsize)
{
  char *cp;
  size_t leftsize;

  assert (lsa_hdr);

  /* LSA identifier */
  ospf6_lsa_hdr_id_str (lsa_hdr, buf, bufsize);

  /* left bufsize */
  leftsize = bufsize - strlen (buf);

  /* current pointer */
  cp = buf + strlen (buf);

  snprintf (cp, leftsize, " seqnum:%#lx cksum:%#x len:%hd",
            (unsigned long) ntohl (lsa_hdr->lsh_seqnum),
	    ntohs (lsa_hdr->lsh_cksum),
            ntohs (lsa_hdr->lsh_len));
}

void
ospf6_lsa_str (struct ospf6_lsa *lsa, char *buf, size_t bufsize)
{
  char *cp;
  size_t leftsize;

  assert (lsa);
  assert (lsa->lsa_hdr);

  /* LSA identifier */
  ospf6_lsa_hdr_str (lsa->lsa_hdr, buf, bufsize);

  /* left bufsize */
  leftsize = bufsize - strlen (buf);

  /* current pointer */
  cp = buf + strlen (buf);

  snprintf (cp, leftsize, " lock:%lu age:%hu",
            lsa->lock, ospf6_age_current (lsa));
}

/* enhanced Fletcher checksum algorithm, RFC1008 7.2 */
#define MODX                4102
#define LSA_CHECKSUM_OFFSET   15

/* XXX, this function assumes that the machine is little endian */
unsigned short
ospf6_lsa_checksum (struct ospf6_lsa_hdr *lsh)
{
  u_char *sp, *ep, *p, *q;
  int c0 = 0, c1 = 0;
  int x, y;
  u_int16_t length;

  lsh->lsh_cksum = 0;
  length = ntohs (lsh->lsh_len) - 2;
  sp = (char *) &lsh->lsh_type;

  for (ep = sp + length; sp < ep; sp = q)
    {
      q = sp + MODX;
      if (q > ep)
        q = ep;
      for (p = sp; p < q; p++)
        {
          c0 += *p;
          c1 += c0;
        }
      c0 %= 255;
      c1 %= 255;
    }

  /* r = (c1 << 8) + c0; */
  x = ((length - LSA_CHECKSUM_OFFSET) * c0 - c1) % 255;
  if (x <= 0)
    x += 255;
  y = 510 - c0 - x;
  if (y > 255)
    y -= 255;

  lsh->lsh_cksum = x + (y << 8);

  return (lsh->lsh_cksum);
}

/* RFC905 ANNEX B */
unsigned short
ospf6_lsa_checksum_set (struct ospf6_lsa_hdr *lsh)
{
#if 0
  int    i, L, c0, c1;
  u_char X, Y;

  L = ntohs (lsh->lsh_len) - 2;
#endif
  return 0;
}

int
ospf6_lsa_checksum_ok (struct ospf6_lsa_hdr *lsh)
{
  return 0;
}

int
ospf6_lsa_is_known (struct ospf6_lsa_hdr *lsh)
{
  switch (ntohs (lsh->lsh_type))
    {
      case LST_ROUTER_LSA:
        return 1;
      case LST_NETWORK_LSA:
        return 1;
      case LST_INTER_AREA_PREFIX_LSA:
        return 0;
      case LST_INTER_AREA_ROUTER_LSA:
        return 0;
      case LST_AS_EXTERNAL_LSA:
        return 1;
      case LST_GROUP_MEMBERSHIP_LSA:
        return 0;
      case LST_TYPE_7_LSA:
        return 0;
      case LST_LINK_LSA:
        return 1;
      case LST_INTRA_AREA_PREFIX_LSA:
        return 1;
      default:
        return 0;
    }
  return 0;
}

/* xxx */

void
ospf6_lsa_warn_unknown_type (type)
{
  switch (type)
    {
    case OSPF6_LSA_TYPE_ROUTER:
    case OSPF6_LSA_TYPE_NETWORK:
    case OSPF6_LSA_TYPE_LINK:
    case OSPF6_LSA_TYPE_INTRA_PREFIX:
    case OSPF6_LSA_TYPE_AS_EXTERNAL:
      break;
    case OSPF6_LSA_TYPE_INTER_PREFIX:
    case OSPF6_LSA_TYPE_INTER_ROUTER:
    case OSPF6_LSA_TYPE_GROUP_MEMBERSHIP:
    case OSPF6_LSA_TYPE_TYPE_7:
      zlog_warn ("Not supported LSA: type %#x", type);
      break;
    default:
      zlog_warn ("Unknown LSA: type %#x", type);
      break;
    }
}

void *
ospf6_lsa_find_scope (u_int16_t type, u_int32_t advrtr, u_int32_t ls_id)
{
  listnode n;
  struct ospf6_interface *o6i;
  struct area *o6a;
  void *scope = NULL;

  o6a = (struct area *) getdata (listhead (ospf6->area_list));
  if (o6a == NULL)
    return NULL;

  switch (type)
    {
    case OSPF6_LSA_TYPE_ROUTER:
      scope = o6a;
      break;

    case OSPF6_LSA_TYPE_NETWORK:
    case OSPF6_LSA_TYPE_LINK:
    case OSPF6_LSA_TYPE_INTRA_PREFIX:
      for (n = listhead (o6a->if_list); n; nextnode (n))
        {
          o6i = (struct ospf6_interface *) getdata (n);
          if (o6i->if_id == ls_id)
            scope = o6i;
        }
      break;

    case OSPF6_LSA_TYPE_AS_EXTERNAL:
      scope = ospf6;
      break;

    default:
      break;
    }

  return scope;
}

struct ospf6_lsa *
ospf6_lsa_create (u_int16_t type, u_int32_t advrtr, u_int32_t ls_id,
                  void *body, int bodysize, void *scope)
{
  struct ospf6_lsa *lsa = NULL;
  struct ospf6_lsa_hdr *lsa_header = NULL;
  u_int16_t lsa_size = 0;
  char buf[128];

  ospf6_lsa_warn_unknown_type (type);

  assert (body);
  assert (bodysize);
  assert (scope);

  /* whole length of this LSA */
  lsa_size = bodysize + sizeof (struct ospf6_lsa_hdr);

  /* allocate memory for this LSA */
  lsa_header = (struct ospf6_lsa_hdr *) XMALLOC (MTYPE_OSPF6_LSA, lsa_size);
  memset (lsa_header, 0, lsa_size);

  /* fill LSA header */
  lsa_header->lsh_age = 0;
  lsa_header->lsh_type = htons (type);
  lsa_header->lsh_id = htonl (ls_id);
  lsa_header->lsh_advrtr = advrtr;
  lsa_header->lsh_seqnum =
    ospf6_seqnum_new (lsa_header->lsh_type, lsa_header->lsh_id,
                      lsa_header->lsh_advrtr, scope);
  lsa_header->lsh_len = htons (lsa_size);

  /* copy body */
  memcpy (lsa_header + 1, body, bodysize);

  /* LSA checksum */
  ospf6_lsa_checksum (lsa_header);

  /* LSA information structure */
  /* allocate memory */
  lsa = (struct ospf6_lsa *)
          XMALLOC (MTYPE_OSPF6_LSA, sizeof (struct ospf6_lsa));
  memset (lsa, 0, sizeof (struct ospf6_lsa));

  /* dump string */
  snprintf (lsa->str, sizeof (lsa->str),
            "%s Advertise:%s LSID:%lu",
            lstype_name[typeindex (lsa_header->lsh_type)],
            inet_ntop (AF_INET, &lsa_header->lsh_advrtr, buf, sizeof (buf)),
            (unsigned long) ntohl (lsa_header->lsh_id));

  lsa->lsa_hdr = lsa_header;
  lsa->summary_nbr = list_init ();
  lsa->request_nbr = list_init ();
  lsa->retrans_nbr = list_init ();
  lsa->delayed_ack_if = list_init ();
  lsa->scope = scope;
  lsa->from = (struct neighbor *) NULL;

  /* calculate birth, expire and refresh of this lsa */
  ospf6_age_set (lsa);
  lsa->refresh = thread_add_timer (master, ospf6_lsa_refresh, lsa,
                                   OSPF6_LS_REFRESH_TIME);

  ospf6_lsa_flood (lsa);
  ospf6_lsdb_install (lsa);

  return lsa;
}

void
ospf6_lsa_update_link (struct ospf6_interface *o6i)
{
  char *cp, buffer [MAXLSASIZE];
  u_int16_t size;
  struct ospf6_prefix *p;
  struct ospf6_link_lsa *llsa;
  list prefix_connected;
  listnode n;
  struct connected *c;
  struct ospf6_lsa *prev_lsa;
  void *scope;

  /* find scope */
  scope = ospf6_lsa_find_scope (OSPF6_LSA_TYPE_LINK, ospf6->router_id,
                                o6i->if_id);
  if (scope == NULL)
    {
      zlog_warn ("Can't find scope in ospf6_lsa_update_link ()");
      return;
    }

  /* find previous LSA */
  prev_lsa = ospf6_lsdb_lookup_new (htons (OSPF6_LSA_TYPE_LINK),
                                    ospf6->router_id, o6i->if_id, ospf6);
  if (! prev_lsa)
    zlog_info ("Previous LSA Not found;");

  /* can't make Link-LSA if linklocal address not set */
  if (!o6i->lladdr)
    {
      if (prev_lsa)
        ospf6_premature_aging (prev_lsa);
      return;
    }

  /* check connected prefix */
  prefix_connected = list_init ();
  for (n = listhead (o6i->interface->connected); n; nextnode (n))
    {
      c = (struct connected *) getdata (n);

      /* filter prefix not IPv6 */
      if (c->address->family != AF_INET6)
        continue;

      /* filter linklocal prefix */
      if (IN6_IS_ADDR_LINKLOCAL (&c->address->u.prefix6))
        continue;

      /* filter unspecified(default) prefix */
      if (IN6_IS_ADDR_UNSPECIFIED (&c->address->u.prefix6))
        continue;

      /* filter loopback prefix */
      if (IN6_IS_ADDR_LOOPBACK (&c->address->u.prefix6))
        continue;

      /* filter IPv4 compatible prefix */
      if (IN6_IS_ADDR_V4COMPAT (&c->address->u.prefix6))
        continue;

      /* filter IPv4 Mapped prefix */
      if (IN6_IS_ADDR_V4MAPPED (&c->address->u.prefix6))
        continue;

      /* hold prefix in list. duplicate is filtered in ospf6_prefix_add() */
      p = ospf6_prefix_make (0, 0, (struct prefix_ipv6 *) c->address);
      ospf6_prefix_add (prefix_connected, p);
    }

  /* We have to create Link-LSA for next-hop resolution */
#if 0
  /* if no prefix, can't make Link-LSA */
  if (listcount (prefix_connected) == 0)
    {
      list_delete_all (prefix_connected);
      if (prev_lsa)
        ospf6_premature_aging (prev_lsa);
      return;
    }
#endif

  /* fill Link LSA and calculate size */
  size = sizeof (struct ospf6_link_lsa);
  llsa = (struct ospf6_link_lsa *) buffer;
  llsa->llsa_rtr_pri = o6i->priority;
  llsa->llsa_options[0] = o6i->area->options[0];
  llsa->llsa_options[1] = o6i->area->options[1];
  llsa->llsa_options[2] = o6i->area->options[2];

  /* linklocal address */
  memcpy (&llsa->llsa_linklocal, o6i->lladdr, sizeof (struct in6_addr));
#ifdef KAME /* clear ifindex */
  if (llsa->llsa_linklocal.s6_addr[3] & 0x0f)
    llsa->llsa_linklocal.s6_addr[3] &= ~((char)0x0f);
#endif /* KAME */

  llsa->llsa_prefix_num = htonl (listcount (prefix_connected));
  cp = (char *)(llsa + 1);
  for (n = listhead (prefix_connected); n; nextnode (n))
    {
      p = (struct ospf6_prefix *) getdata (n);
      size += OSPF6_PREFIX_SIZE (p);
      memcpy (cp, p, OSPF6_PREFIX_SIZE (p));
      cp += OSPF6_PREFIX_SIZE (p);
    }

  ospf6_lsa_create (OSPF6_LSA_TYPE_LINK, ospf6->router_id, o6i->if_id,
                    buffer, size, scope);
}

#if 0
void
ospf6_lsa_update_intra_area_prefix_transit (struct ospf6_interface *o6i)
{
  char *cp, buffer [MAXLSASIZE];
  u_int16_t size;
  struct ospf6_prefix *p;
  struct ospf6_link_lsa *llsa;
  list prefix_connected;
  listnode n;
  struct connected *c;
  struct ospf6_lsa *prev_lsa;
  void *scope;
  struct neighbor *nbr;

  /* find scope */
  scope = ospf6_lsa_find_scope (OSPF6_LSA_TYPE_LINK, ospf6->router_id,
                                o6i->if_id);
  if (scope == NULL)
    {
      zlog_warn ("Can't find scope in ospf6_lsa_update_link ()");
      return;
    }

  /* find previous LSA */
  prev_lsa = ospf6_lsdb_lookup_new (htons (OSPF6_LSA_TYPE_INTRA_PREFIX),
                                    ospf6->router_id, o6i->if_id, ospf6);
  if (! prev_lsa)
    zlog_info ("Previous LSA Not found;");


  struct ospf6_lsa *lsa;
  struct ospf6_lsa_hdr *lsa_hdr;
  struct intra_area_prefix_lsa *iaplsa;
  struct ospf6_prefix *p1, *p2; /* LS description is ospf6 prefix */
  size_t space;
  list advertise = list_init ();
  struct link_lsa *llsa;
  unsigned short prefixnum;
  int i;

  assert (o6if);

  /* if not stub and not DR, don't make IntraAreaPrefixLSA */
  if (ospf6_interface_count_full_nbr (o6i) != 0)
    {
      if (prev_lsa)
        ospf6_premature_aging (prev_lsa);
      return (struct ospf6_lsa *) NULL;
    }

  /* DR must care about prefix advertised with LinkLSA
     by another router */
  for (n = listhead (o6i->neighbor_list); n; nextnode (n))
    {
      nbr = (struct neighbor *) getdata (n);

      /* if not full, ignore this neighbor */
      if (nbr->state != NBS_FULL)
        continue;

      /* get LinkLSA of this neighbor.
         if not found, log and ignore */
      lsa = ospf6_lsdb_lookup_new (htons (OSPF6_LSA_TYPE_LINK),
                                   htonl (nbr->ifid), nbr->rtr_id, ospf6);
      if (!lsa)
        {
          zlog_warn ("*** LinkLSA not found for full neighbor %s",
                     nbr->str);
          continue;
        }

          llsa = (struct link_lsa *)(lsa->lsa_hdr + 1);
          p1 = (struct ospf6_prefix *)(llsa + 1);
          /* for each prefix listed in this LinkLSA */
          for (i = 0; i < ntohl (llsa->llsa_prefix_num); i++)
            {
              /* add to advertise list. duplicate won't be added */
              ospf6_prefix_add (advertise, p1);
              p1 = OSPF6_NEXT_PREFIX (p1);
            }
        }
    }

  /* add prefixes in my LinkLSA to advertise list */
  lsa = ospf6_lsdb_lookup (htons (LST_LINK_LSA), htonl (o6if->if_id),
                           o6if->area->ospf6->router_id, (void *)o6if);
  if (!lsa)
    zlog_warn ("*** My LinkLSA not found for %s", o6if->interface->name);
  else
    {
      llsa = (struct link_lsa *)(lsa->lsa_hdr + 1);
      p1 = (struct ospf6_prefix *)(llsa + 1);
      /* for each prefix listed in my LinkLSA */
      for (i = 0; i < ntohl (llsa->llsa_prefix_num); i++)
        {
          /* add to advertise list. duplicate won't be added */
          ospf6_prefix_add (advertise, p1);
          p1 = OSPF6_NEXT_PREFIX (p1);
        }
    }

  /* get prefix number */
  prefixnum = listcount (advertise);

  /* if no prefix, no need to make IntraAreaPrefixLSA */
  if (!prefixnum)
    {
      list_delete_all (advertise);
      return (struct ospf6_lsa *)NULL;
    }

  /* get space needed for my IntraAreaPrefixLSA */
  space = 0;
  for (n = listhead (advertise); n; nextnode (n))
    {
      p1 = (struct ospf6_prefix *) getdata (n);
      space += OSPF6_PREFIX_SIZE (p1);
    }
  space += sizeof (struct ospf6_lsa_hdr)
          + sizeof (struct intra_area_prefix_lsa);

  /* malloc buffer */
  lsa_hdr = malloc_ospf6_lsa_data (space);

  /* set lsa header */
  lsa_hdr->lsh_age = 0;
  lsa_hdr->lsh_type = htons (LST_INTRA_AREA_PREFIX_LSA);
  lsa_hdr->lsh_id = htonl (o6if->if_id);
  lsa_hdr->lsh_advrtr = o6if->area->ospf6->router_id;
  lsa_hdr->lsh_seqnum = ospf6_seqnum_new (lsa_hdr->lsh_type,
                                          lsa_hdr->lsh_id,
                                          lsa_hdr->lsh_advrtr,
                                          (void *)o6if->area);
  /* xxx, checksum */
  lsa_hdr->lsh_len = htons (space);

  /* set intra_area_prefix_lsa */
  iaplsa = (struct intra_area_prefix_lsa *) (lsa_hdr + 1);
    /* set prefix num */
  iaplsa->intra_prefix_num = htons (prefixnum);
    /* set referrenced lsa */
  if (o6if->state == IFS_DR && ospf6_interface_count_full_nbr (o6if))
    {
      /* refer to NetworkLSA */
      iaplsa->intra_prefix_refer_lstype = htons (LST_NETWORK_LSA);
      iaplsa->intra_prefix_refer_lsid = htonl (o6if->if_id);
    }
  else
    {
      /* refer to RouterLSA */
      iaplsa->intra_prefix_refer_lstype = htons (LST_ROUTER_LSA);
      iaplsa->intra_prefix_refer_lsid = htonl (0);
    }
  iaplsa->intra_prefix_refer_advrtr = o6if->area->ospf6->router_id;

  /* set ospf6 prefixes */
  p1 = (struct ospf6_prefix *)(iaplsa + 1);
  space -= sizeof (struct intra_area_prefix_lsa)
           + sizeof (struct ospf6_lsa_hdr);
  for (n = listhead (advertise); n; nextnode (n))
    {
      p2 = (struct ospf6_prefix *) getdata (n);

      /* copy p2 to p1 */
      ospf6_prefix_copy (p1, p2, space);
      space -= OSPF6_PREFIX_SIZE(p2);

      p1 = OSPF6_NEXT_PREFIX (p1);
    }

  /* age calculation, scope, etc */
  ospf6_lsa_checksum (lsa_hdr);
  lsa = make_ospf6_lsa (lsa_hdr);
  lsa->scope = (void *) o6if->area;
  lsa->from = (struct neighbor *) NULL;
  lsa->refresh = thread_add_timer (master, ospf6_lsa_refresh, lsa,
                                   OSPF6_LS_REFRESH_TIME);

  list_delete_all (advertise);
  return lsa;





  /* check connected prefix */
  prefix_connected = list_init ();
  for (n = listhead (o6i->interface->connected); n; nextnode (n))
    {
      c = (struct connected *) getdata (n);

      /* filter prefix not IPv6 */
      if (c->address->family != AF_INET6)
        continue;

      /* filter linklocal prefix */
      if (IN6_IS_ADDR_LINKLOCAL (&c->address->u.prefix6))
        continue;

      /* filter unspecified(default) prefix */
      if (IN6_IS_ADDR_UNSPECIFIED (&c->address->u.prefix6))
        continue;

      /* filter loopback prefix */
      if (IN6_IS_ADDR_LOOPBACK (&c->address->u.prefix6))
        continue;

      /* filter IPv4 compatible prefix */
      if (IN6_IS_ADDR_V4COMPAT (&c->address->u.prefix6))
        continue;

      /* filter IPv4 Mapped prefix */
      if (IN6_IS_ADDR_V4MAPPED (&c->address->u.prefix6))
        continue;

      /* hold prefix in list. duplicate is filtered in ospf6_prefix_add() */
      p = ospf6_prefix_make (0, 0, (struct prefix_ipv6 *) c->address);
      ospf6_prefix_add (prefix_connected, p);
    }

  /* fill Link LSA and calculate size */
  size = sizeof (struct ospf6_link_lsa);
  llsa = (struct ospf6_link_lsa *) buffer;
  llsa->llsa_rtr_pri = o6i->priority;
  llsa->llsa_options[0] = o6i->area->options[0];
  llsa->llsa_options[1] = o6i->area->options[1];
  llsa->llsa_options[2] = o6i->area->options[2];

  /* linklocal address */
  memcpy (&llsa->llsa_linklocal, o6i->lladdr, sizeof (struct in6_addr));
#ifdef KAME /* clear ifindex */
  if (llsa->llsa_linklocal.s6_addr[3] & 0x0f)
    llsa->llsa_linklocal.s6_addr[3] &= ~((char)0x0f);
#endif /* KAME */

  llsa->llsa_prefix_num = htonl (listcount (prefix_connected));
  cp = (char *)(llsa + 1);
  for (n = listhead (prefix_connected); n; nextnode (n))
    {
      p = (struct ospf6_prefix *) getdata (n);
      size += OSPF6_PREFIX_SIZE (p);
      memcpy (cp, p, OSPF6_PREFIX_SIZE (p));
      cp += OSPF6_PREFIX_SIZE (p);
    }

  ospf6_lsa_create (OSPF6_LSA_TYPE_LINK, ospf6->router_id, o6i->if_id,
                    buffer, size, scope);
}

void
ospf6_lsa_update_intra_area_prefix_stub ()
{
}

void
ospf6_lsa_update_intra_area_prefix (struct ospf6_interface *o6i)
{
  if (! o6i)
    ospf6_lsa_update_intra_area_prefix_stub ();
  else if (o6i->state == IFS_DR)
    ospf6_lsa_update_intra_area_prefix_transit (o6i);
  else
    zlog_info ("ZZZ: no prefix LSA to create");
}

#endif
