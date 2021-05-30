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

#include <zebra.h>

#include "newlist.h"
#include "memory.h"

struct newlist *
newlist_new ()
{
  struct newlist *new;

  new = XMALLOC (MTYPE_NEWLIST, sizeof (struct newlist));
  memset (new, 0, sizeof (struct newlist));
  return new;
}

void
newlist_free (struct newlist *newlist)
{
  XFREE (MTYPE_NEWLIST, newlist);
}

struct newnode *
newnode_new ()
{
  struct newnode *new;

  new = XMALLOC (MTYPE_NEWNODE, sizeof (struct newnode));
  memset (new, 0, sizeof (struct newnode));
  return new;
}

void
newnode_free (struct newnode *newnode)
{
  XFREE (MTYPE_NEWNODE, newnode);
}

void
newnode_add (struct newlist *list, void *val)
{
  struct newnode *n;
  struct newnode *new;

  new = newnode_new ();
  new->data = val;

  if (list->cmp)
    {
      for (n = list->head; n; n = n->next)
	{
	  if ((*list->cmp) (val, n->data) < 0)
	    {	    
	      new->next = n;
	      new->prev = n->prev;

	      if (n->prev)
		n->prev->next = new;
	      else
		list->head = new;
	      n->prev = new;
	      list->count++;
	      return;
	    }
	}
    }
  new->prev = list->tail;
  if (list->tail)
    list->tail->next = new;
  else
    list->head = new;
  list->tail = new;
  list->count++;
}

void *
newnode_delete (struct newlist *list, void *val)
{
  struct newnode *n;

  for (n = list->head; n; n = n->next)
    {
      if (n->data == val)
	{
	  if (n->prev)
	    n->prev->next = n->next;
	  else
	    list->head = n->next;

	  if (n->next)
	    n->next->prev = n->prev;
	  else
	    list->tail = n->prev;

	  list->count--;
	  newnode_free (n);
	  return val;
	}
    }
  return NULL;
}

void
newlist_delete (struct newlist *list)
{
  struct newnode *n;
  struct newnode *next;

  for (n = list->head; n; n = next)
    {
      next = n->next;
      if (list->del)
	(list->del) (n->data);
      newnode_free (n);
    }
  newlist_free (list);
}

void *
newlist_first (struct newlist *list)
{
  if (list->head)
    return list->head->data;
  return NULL;
}
