/* New linked list.
 * Copyright (C) 1999 Kunihiro Ishiguro
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

#ifndef _ZEBRA_NEWLIST_H
#define _ZEBRA_NEWLIST_H

struct newlist
{
  struct newnode *head;
  struct newnode *tail;
  unsigned long count;
  int (*cmp) (void *val1, void *val2);
  void (*del) (void *val);
};

struct newnode
{
  struct newnode *next;
  struct newnode *prev;
  void *data;
};

struct newlist *newlist_new ();
void newlist_delete (struct newlist *);
void newnode_add (struct newlist *, void *);
void *newnode_delete (struct newlist *, void *);
void *newlist_first (struct newlist *);

#define NEWLIST_LOOP(L,V,N) \
  for ((N) = (L)->head; (N); (N) = (N)->next) \
    if (((V) = (N)->data) != NULL)

#endif /* _ZEBRA_NEWLIST_H */
