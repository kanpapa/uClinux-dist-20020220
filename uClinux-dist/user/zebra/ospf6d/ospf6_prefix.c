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

static struct ospf6_prefix *
ospf6_prefix_new (size_t size)
{
  struct ospf6_prefix *new;
  new = (struct ospf6_prefix *) XMALLOC (MTYPE_OSPF6_PREFIX, size);
  if (!new)
    zlog_warn ("prefix_new failed, size:%d", size);
  else
    memset (new, 0, size);
  return new;
}

void
ospf6_prefix_free (struct ospf6_prefix *p)
{
  XFREE (MTYPE_OSPF6_PREFIX, p);
}

struct ospf6_prefix *
ospf6_prefix_make (u_int8_t opt, u_int16_t metric, struct prefix_ipv6 *p)
{
  struct prefix_ipv6 netp;
  struct ospf6_prefix *o6p;
  size_t o6psize;

  /* copy prefix and apply mask */
  prefix_copy ((struct prefix *)&netp, (struct prefix *)p);
  apply_mask_ipv6 (&netp);

  o6psize = OSPF6_PREFIX_SPACE (netp.prefixlen) + sizeof (struct ospf6_prefix);
  o6p = ospf6_prefix_new (o6psize);

  o6p->o6p_prefix_len = netp.prefixlen;
  o6p->o6p_prefix_opt = opt;
  o6p->o6p_prefix_metric = htons (metric);

  memcpy (o6p + 1, &netp.prefix, OSPF6_PREFIX_SPACE (netp.prefixlen));

  return o6p;
}

static int
ospf6_prefix_issame (struct ospf6_prefix *p1, struct ospf6_prefix *p2)
{
  if (p1->o6p_prefix_len != p2->o6p_prefix_len)
    return 0;
  if (memcmp (p1 + 1, p2 + 1, OSPF6_PREFIX_SPACE (p1->o6p_prefix_len)))
    return 0;
  return 1;
}

void
ospf6_prefix_add (list l, struct ospf6_prefix *add)
{
  listnode n;
  struct ospf6_prefix *p;
  int already = 0;

  for (n = listhead (l); n; nextnode (n))
    {
      p = (struct ospf6_prefix *) getdata (n);
      if (ospf6_prefix_issame (add, p))
        {
          already++;
          break;
        }
    }

  if (already)
    return;

  list_add_node (l, add);
}

#if 0
static void
ospf6_prefix_delete (list l, struct ospf6_prefix *del)
{
  listnode n;
  struct ospf6_prefix *p;

  for (n = listhead (l); n; nextnode (n))
    {
      p = (struct ospf6_prefix *) getdata (n);
      if (ospf6_prefix_issame (p, del))
        break;
    }

  if (!n)
    {
      zlog_err ("no such prefix");
      assert (0);
    }

  ospf6_prefix_free (getdata (n));
  list_delete_node (l, n);
}
#endif /* 0 */

void
ospf6_prefix_in6_addr (struct ospf6_prefix *o6p, struct in6_addr *in6)
{
  memset (in6, 0, sizeof (struct in6_addr));
  memcpy (in6, o6p + 1, OSPF6_PREFIX_SPACE (o6p->o6p_prefix_len));
  return;
}

void
ospf6_prefix_str (struct ospf6_prefix *p, char *buf, size_t bufsize)
{
  struct in6_addr in6;
  char tmpbuf[128];

  ospf6_prefix_in6_addr (p, &in6);
  memset (tmpbuf, 0, sizeof (tmpbuf));
  inet_ntop (AF_INET6, &in6, tmpbuf, sizeof (tmpbuf));

  snprintf (buf, bufsize, "opt:%s metric:%d %s/%d",
            "xxx", ntohs (p->o6p_prefix_metric),
            tmpbuf, p->o6p_prefix_len);
  return;
}

void
ospf6_prefix_copy (struct ospf6_prefix *dst, struct ospf6_prefix *src,
                   size_t dstsize)
{
  size_t srcsize;

  memset (dst, 0, dstsize);

  srcsize = OSPF6_PREFIX_SIZE (src);
  if (dstsize < srcsize)
    memcpy (dst, src, dstsize);
  else
    memcpy (dst, src, srcsize);

  return;
}

void
ospf6_prefix_list_add (struct in6_addr *prefix, u_int8_t prefix_len,
                       u_int8_t prefix_opt, u_int16_t prefix_metric)
{
}



