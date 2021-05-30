/*
 * Generic linked list routine.
 * Copyright (C) 1997 Kunihiro Ishiguro
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

#include "linklist.h"
#include "memory.h"

/* For memory leak debug. */
unsigned long list_alloc = 0;
unsigned long node_alloc = 0;

/* Initialize linked list : allocate memory and return list */
list
list_init ()
{
  list l = XMALLOC (MTYPE_LINK_LIST, sizeof (struct _list));
  l->head = l->tail = l->up = NULL;
  l->count = 0;
  list_alloc++;
  
  return l;
}

/* Free given list and decrement allocation counter. */
void list_free (list list)
{
  XFREE (MTYPE_LINK_LIST, list);
  list_alloc--;
}

/* Internal function to create new listnode structure. */
static listnode
listnode_new ()
{
  listnode node = XMALLOC (MTYPE_LINK_NODE, sizeof (struct _listnode));
  node->next = node->prev = node->data = NULL;
  node_alloc++;
  return node;
}

/* Free given listnode and decrement allocation counter. */
static void
listnode_free (listnode n)
{
  XFREE (MTYPE_LINK_NODE, n);
  node_alloc--;
}

/* Add a new data to the top of the list. */
void
list_add_node_head (list list, void *val)
{
  listnode node = listnode_new ();

  node->next = list->head;
  node->prev = NULL;
  node->data = val;

  if (list_isempty (list))
    list->tail = node;
  else
    list->head->prev = node;
  list->head = node;
  list->count++;
}

/* Add a new data to the end of the list. */
void
list_add_node_tail (list list, void *val)
{
  listnode node = listnode_new ();
  
  node->next = NULL;
  node->prev = list->tail;
  node->data = val;

  if (list_isempty (list))
    list->head = node;
  else
    list->tail->next = node;
  list->tail = node;
  list->count++;
}

void
list_add_node_prev (list list, listnode current, void *val)
{
  listnode node = listnode_new ();

  node->next = current;
  node->data = val;

  if (current->prev == NULL)
    list->head = node;
  else
    current->prev->next = node;

  node->prev = current->prev;
  current->prev = node;
  list->count++;
}

void
list_add_node_next (list list, listnode current, void *val)
{
  listnode node = listnode_new ();

  node->prev = current;
  node->data = val;

  if (current->next == NULL)
    list->tail = node;
  else
    current->next->prev = node;

  node->next = current->next;
  current->next = node;
  list->count++;
}

void
list_add_list (list l, list m)
{
  listnode n;

  for (n = listhead (m); n; nextnode (n))
    list_add_node (l, n->data);
}

/* Add new data to the list. */
void
list_add_node (list list, void *val)
{
  list_add_node_tail (list, val);
}

/* Delete all listnode from the list. */
void
list_delete_all_node (list list)
{
  listnode n;

  for (n = listhead (list); n; n = listhead (list))
    {
      list_delete_node (list, n);
    }
}

/* Delete all node from the list. */
void
list_delete_all (list list)
{
  list_delete_all_node (list);
  list_free (list);
}

/* Delete the node from list. */
void
list_delete_node (list list, listnode node)
{
  listnode n;

  for (n = list->head; n; n = n->next)
    if (n == node)
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
	listnode_free (n);
	return;
      }
}

/* Delete the node which has the val argument from list. */
void
list_delete_by_val (list list, void *val)
{
  listnode n;

  for (n = list->head; n; n = n->next)
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
	listnode_free (n);

	return;
      }
}

/* Lookup the node which has given data. */
listnode
list_lookup_node (list list, void *data)
{
  listnode n;

  for (n = list->head; n; nextnode (n))
    if (data == getdata (n))
      return n;
  return NULL;
}

/* Only for debug. */
void
list_alloc_print ()
{
  printf ("list_alloc: %ld\n", list_alloc);
  printf ("node_alloc: %ld\n", node_alloc);
}

#ifdef TEST
main ()
{
  list l;
  listnode n;
  char *kuni = "kuni";
  char *mio = "mio";

  l = list_init ();
  list_add_node (l, kuni);
  list_add_node (l, mio);
  for (n = l->head; n; nextnode (n))
    {
      printf ("%s\n", getdata(n));
    }
  n = list_lookup_node (l, mio);

  list_delete_node (l, n);
  for (n = l->head; n; nextnode (n))
    {
      printf ("%s\n", getdata(n));
    }
  n = list_lookup_node (l, kuni);

  list_delete_node (l, n);
  for (n = l->head; n; nextnode (n))
    {
      printf ("%s\n", getdata(n));
    }
  list_alloc_print ();
  if (list_isempty (l))
    list_free (l);
  list_alloc_print ();
}
#endif /* TEST */
