/* Prefix list functions.
 * Copyright (C) 1999 Kunihiro Ishiguro
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2, or (at your
 * option) any later version.
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

#include <zebra.h>

#include "prefix.h"
#include "command.h"
#include "memory.h"
#include "plist.h"
#include "sockunion.h"
#include "buffer.h"

/* Each prefix-list's entry. */
struct prefix_list_entry
{
  int seq;

  int le;
  int ge;

  enum prefix_list_type type;

  int any;
  struct prefix prefix;

  unsigned long refcnt;
  unsigned long hitcnt;

  struct prefix_list_entry *next;
  struct prefix_list_entry *prev;
};

/* List of struct prefix_list. */
struct prefix_list_list
{
  struct prefix_list *head;
  struct prefix_list *tail;
};

/* Master structure of prefix_list. */
struct prefix_master
{
  /* List of prefix_list which name is number. */
  struct prefix_list_list num;

  /* List of prefix_list which name is string. */
  struct prefix_list_list str;

  /* Whether sequential number is used. */
  int seqnum;

  /* The latest update. */
  struct prefix_list *recent;

  /* Hook function which is executed when new prefix_list is added. */
  void (*add_hook) ();

  /* Hook function which is executed when prefix_list is deleted. */
  void (*delete_hook) ();
};

/* Static structure of IPv4 prefix_list's master. */
static struct prefix_master prefix_master_ipv4 = 
{ 
  {NULL, NULL},
  {NULL, NULL},
  1,
  NULL,
  NULL,
};

#ifdef HAVE_IPV6
/* Static structure of IPv6 prefix-list's master. */
static struct prefix_master prefix_master_ipv6 = 
{ 
  {NULL, NULL},
  {NULL, NULL},
  1,
  NULL,
  NULL,
};
#endif /* HAVE_IPV6*/

struct prefix_master *
prefix_master_get (int family)
{
  struct prefix_master *master = NULL;

  if (family == AF_INET)
    master = &prefix_master_ipv4;
#ifdef HAVE_IPV6
  else if (family == AF_INET6)
    master = &prefix_master_ipv6;
#endif /* HAVE_IPV6 */
  return master;
}

/* Lookup prefix_list from list of prefix_list by name. */
struct prefix_list *
prefix_list_lookup (int family, char *name)
{
  struct prefix_list *plist;
  struct prefix_master *master;

  if (name == NULL)
    return NULL;

  master = prefix_master_get (family);
  if (master == NULL)
    return NULL;

  for (plist = master->num.head; plist; plist = plist->next)
    if (strcmp (plist->name, name) == 0)
      return plist;

  for (plist = master->str.head; plist; plist = plist->next)
    if (strcmp (plist->name, name) == 0)
      return plist;

  return NULL;
}

struct prefix_list *
prefix_list_new ()
{
  struct prefix_list *new;

  new = XMALLOC (MTYPE_PREFIX_LIST, sizeof (struct prefix_list));
  bzero (new, sizeof (struct prefix_list));
  return new;
}

void
prefix_list_free (struct prefix_list *plist)
{
  XFREE (MTYPE_PREFIX_LIST, plist);
}

struct prefix_list_entry *
prefix_list_entry_new ()
{
  struct prefix_list_entry *new;

  new = XMALLOC (MTYPE_PREFIX_LIST_ENTRY, sizeof (struct prefix_list_entry));
  bzero (new, sizeof (struct prefix_list_entry));
  return new;
}

void
prefix_list_entry_free (struct prefix_list_entry *pentry)
{
  XFREE (MTYPE_PREFIX_LIST_ENTRY, pentry);
}

/* Insert new prefix list to list of prefix_list.  Each prefix_list
   is sorted by the name. */
struct prefix_list *
prefix_list_insert (int family, char *name)
{
  int i;
  long number;
  struct prefix_list *plist;
  struct prefix_list *point;
  struct prefix_list_list *list;
  struct prefix_master *master;

  master = prefix_master_get (family);
  if (master == NULL)
    return NULL;

  /* Allocate new prefix_list and copy given name. */
  plist = prefix_list_new ();
  plist->name = strdup (name);
  plist->master = master;

  /* If name is made by all digit character.  We treat it as
     number. */
  for (number = 0, i = 0; i < strlen (name); i++)
    {
      if (isdigit ((int) name[i]))
	number = (number * 10) + (name[i] - '0');
      else
	break;
    }

  /* In case of name is all digit character */
  if (i == strlen (name))
    {
      plist->type = PREFIX_TYPE_NUMBER;

      /* Set prefix_list to number list. */
      list = &master->num;

      for (point = list->head; point; point = point->next)
	if (atol (point->name) >= number)
	  break;
    }
  else
    {
      plist->type = PREFIX_TYPE_STRING;

      /* Set prefix_list to string list. */
      list = &master->str;
  
      /* Set point to insertion point. */
      for (point = list->head; point; point = point->next)
	if (strcmp (point->name, name) >= 0)
	  break;
    }

  /* In case of this is the first element of master. */
  if (list->head == NULL)
    {
      list->head = list->tail = plist;
      return plist;
    }

  /* In case of insertion is made at the tail of access_list. */
  if (point == NULL)
    {
      plist->prev = list->tail;
      list->tail->next = plist;
      list->tail = plist;
      return plist;
    }

  /* In case of insertion is made at the head of access_list. */
  if (point == list->head)
    {
      plist->next = list->head;
      list->head->prev = plist;
      list->head = plist;
      return plist;
    }

  /* Insertion is made at middle of the access_list. */
  plist->next = point;
  plist->prev = point->prev;

  if (point->prev)
    point->prev->next = plist;
  point->prev = plist;

  return plist;
}

struct prefix_list *
prefix_list_get (int family, char *name)
{
  struct prefix_list *plist;

  plist = prefix_list_lookup (family, name);

  if (plist == NULL)
    plist = prefix_list_insert (family, name);
  return plist;
}

/* Delete prefix-list from prefix_list_master and free it. */
void
prefix_list_delete (struct prefix_list *plist)
{
  struct prefix_list_list *list;
  struct prefix_master *master;
  struct prefix_list_entry *pentry;
  struct prefix_list_entry *next;

  /* If prefix-list contain prefix_list_entry free all of it. */
  for (pentry = plist->head; pentry; pentry = next)
    {
      next = pentry->next;
      prefix_list_entry_free (pentry);
      plist->count--;
    }

  master = plist->master;

  if (plist->type == PREFIX_TYPE_NUMBER)
    list = &master->num;
  else
    list = &master->str;

  if (plist->next)
    plist->next->prev = plist->prev;
  else
    list->tail = plist->prev;

  if (plist->prev)
    plist->prev->next = plist->next;
  else
    list->head = plist->next;

  if (plist->desc)
    XFREE (MTYPE_TMP, plist->desc);

  /* Make sure master's recent changed prefix-list information is
     cleared. */
  master->recent = NULL;

  prefix_list_free (plist);

  if (master->delete_hook)
    (*master->delete_hook) ();
}

struct prefix_list_entry *
prefix_list_entry_make (struct prefix *prefix, enum prefix_list_type type,
			int seq, int le, int ge)
{
  struct prefix_list_entry *pentry;

  pentry = prefix_list_entry_new ();

  /* If prefix is NULL then this is "any" match directive. */
  if (prefix == NULL)
    pentry->any = 1;
  else
    prefix_copy (&pentry->prefix, prefix);

  pentry->type = type;
  pentry->seq = seq;
  pentry->le = le;
  pentry->ge = ge;

  return pentry;
}

/* Add hook function. */
void
prefix_list_add_hook (void (*func) ())
{
  prefix_master_ipv4.add_hook = func;
#ifdef HAVE_IPV6
  prefix_master_ipv6.add_hook = func;
#endif /* HAVE_IPV6 */
}

/* Delete hook function. */
void
prefix_list_delete_hook (void (*func) ())
{
  prefix_master_ipv4.delete_hook = func;
#ifdef HAVE_IPV6
  prefix_master_ipv6.delete_hook = func;
#endif /* HAVE_IPVt6 */
}

/* Calculate new sequential number. */
int
prefix_new_seq_get (struct prefix_list *plist)
{
  int maxseq;
  int newseq;
  struct prefix_list_entry *pentry;

  maxseq = newseq = 0;

  for (pentry = plist->head; pentry; pentry = pentry->next)
    {
      if (maxseq < pentry->seq)
	maxseq = pentry->seq;
    }

  newseq = ((maxseq / 5) * 5) + 5;
  
  return newseq;
}

/* Return prefix list entry which has same seq number. */
struct prefix_list_entry *
prefix_seq_check (struct prefix_list *plist, int seq)
{
  struct prefix_list_entry *pentry;

  for (pentry = plist->head; pentry; pentry = pentry->next)
    if (pentry->seq == seq)
      return pentry;
  return NULL;
}

struct prefix_list_entry *
prefix_list_entry_lookup (struct prefix_list *plist, struct prefix *prefix,
			  enum prefix_list_type type, int seq, int le, int ge)
{
  struct prefix_list_entry *pentry;

  for (pentry = plist->head; pentry; pentry = pentry->next)
    {
      if (prefix == NULL)
	{
	  if (pentry->any == 1 && pentry->type == type)
	    {
	      if (seq >= 0 && pentry->seq != seq)
		continue;

	      if (pentry->le != le)
		continue;
	      if (pentry->ge != ge)
		continue;

	      return pentry;
	    }
	}
      else
	{
	  if (prefix_same (&pentry->prefix, prefix) && pentry->type == type)
	    {
	      if (seq >= 0 && pentry->seq != seq)
		continue;

	      if (pentry->le != le)
		continue;
	      if (pentry->ge != ge)
		continue;

	      return pentry;
	    }
	}
    }

  return NULL;
}

void
prefix_list_entry_delete (struct prefix_list *plist, 
			  struct prefix_list_entry *pentry)
{
  if (plist == NULL || pentry == NULL)
    return;
  if (pentry->prev)
    pentry->prev->next = pentry->next;
  else
    plist->head = pentry->next;
  if (pentry->next)
    pentry->next->prev = pentry->prev;
  else
    plist->tail = pentry->prev;

  prefix_list_entry_free (pentry);

  plist->count--;

  if (plist->master->delete_hook)
    (*plist->master->delete_hook) ();

  if (plist->head == NULL && plist->tail == NULL && plist->desc == NULL)
    prefix_list_delete (plist);
  else
    plist->master->recent = plist;
}

void
prefix_list_entry_add (struct prefix_list *plist,
		       struct prefix_list_entry *pentry)
{
  struct prefix_list_entry *replace;
  struct prefix_list_entry *point;

  /* Automatic asignment of seq no. */
  if (pentry->seq == -1)
    pentry->seq = prefix_new_seq_get (plist);

  /* Is there any same seq prefix list entry? */
  replace = prefix_seq_check (plist, pentry->seq);
  if (replace)
    prefix_list_entry_delete (plist, replace);

  /* Check insert point. */
  for (point = plist->head; point; point = point->next)
    if (point->seq >= pentry->seq)
      break;

  /* In case of this is the first element of the list. */
  pentry->next = point;

  if (point)
    {
      if (point->prev)
	point->prev->next = pentry;
      else
	plist->head = pentry;

      pentry->prev = point->prev;
      point->prev = pentry;
    }
  else
    {
      if (plist->tail)
	plist->tail->next = pentry;
      else
	plist->head = pentry;

      pentry->prev = plist->tail;
      plist->tail = pentry;
    }

  /* Increment count. */
  plist->count++;

  /* Run hook function. */
  if (plist->master->add_hook)
    (*plist->master->add_hook) ();

  plist->master->recent = plist;
}

/* Return string of prefix_list_type. */
static char *
prefix_list_type_str (struct prefix_list_entry *pentry)
{
  switch (pentry->type)
    {
    case PREFIX_PERMIT:
      return "permit";
      break;
    case PREFIX_DENY:
      return "deny";
      break;
    default:
      return "";
      break;
    }
}

int
prefix_list_entry_match (struct prefix_list_entry *pentry, struct prefix *p)
{
  int ret;

  /* This is any entry. */
  if (pentry->any)
    return 1;

  ret = prefix_match (&pentry->prefix, p);
  if (! ret)
    return 0;
  
  /* In case of le nor ge is specified, exact match is performed. */
  if (pentry->le < 0 && pentry->ge < 0)
    {
      if (pentry->prefix.prefixlen != p->prefixlen)
	return 0;
    }
  else
    {  
      if (pentry->le >= 0)
	if (p->prefixlen > pentry->le)
	  return 0;

      if (pentry->ge >= 0)
	if (p->prefixlen < pentry->ge)
	  return 0;
    }
  return 1;
}

enum prefix_list_type
prefix_list_apply (struct prefix_list *plist, void *object)
{
  struct prefix_list_entry *pentry;
  struct prefix *p;

  p = (struct prefix *) object;

  if (plist == NULL)
    return PREFIX_DENY;

  if (plist->count == 0)
    return PREFIX_PERMIT;

  for (pentry = plist->head; pentry; pentry = pentry->next)
    {
      pentry->refcnt++;
      if (prefix_list_entry_match (pentry, p))
	{
	  pentry->hitcnt++;
	  return pentry->type;
	}
    }

  return PREFIX_DENY;
}

void
prefix_list_print (struct prefix_list *plist)
{
  struct prefix_list_entry *pentry;

  if (plist == NULL)
    return;

  printf ("ip prefix-list %s: %d entries\n", plist->name, plist->count);

  for (pentry = plist->head; pentry; pentry = pentry->next)
    {
      if (pentry->any)
	printf ("any %s\n", prefix_list_type_str (pentry));
      else
	{
	  struct prefix *p;
	  char buf[BUFSIZ];
	  
	  p = &pentry->prefix;
	  
	  printf ("  seq %d %s %s/%d", 
		  pentry->seq,
		  prefix_list_type_str (pentry),
		  inet_ntop (p->family, &p->u.prefix, buf, BUFSIZ),
		  p->prefixlen);
	  if (pentry->ge >= 0)
	    printf (" ge %d", pentry->ge);
	  if (pentry->le >= 0)
	    printf (" le %d", pentry->le);
	  printf ("\n");
	}
    }
}

/* Description of the `prefix-list' statement.  */
#define PREFIX_LIST_STR "Build a prefix list\n"

/* Retrun 1 when plist already include pentry policy. */
struct prefix_list_entry *
prefix_entry_dup_check (struct prefix_list *plist,
			struct prefix_list_entry *new)
{
  struct prefix_list_entry *pentry;
  int seq = 0;

  if (new->seq == -1)
    seq = prefix_new_seq_get (plist);
  else
    seq = new->seq;

  for (pentry = plist->head; pentry; pentry = pentry->next)
    {
      if ((pentry->any == new->any)
	  && prefix_same (&pentry->prefix, &new->prefix)
	  && pentry->type == new->type
	  && pentry->le == new->le
	  && pentry->ge == new->ge
	  && pentry->seq != seq)
	return pentry;
    }
  return NULL;
}

int
vty_prefix_list_install (struct vty *vty, int family,
			 char *name, char *seq, char *typestr,
			 char *prefix, char *ge, char *le)
{
  int ret;
  enum prefix_list_type type;
  struct prefix_list *plist;
  struct prefix_list_entry *pentry;
  struct prefix_list_entry *dup;
  struct prefix p;
  int any = 0;
  int seqnum = -1;
  int lenum = -1;
  int genum = -1;

  /* Get prefix_list with name. */
  plist = prefix_list_get (family, name);

  /* Sequential number. */
  if (seq)
    seqnum = atoi (seq);

  /* Check filter type. */
  if (strncmp ("permit", typestr, 1) == 0)
    type = PREFIX_PERMIT;
  else if (strncmp ("deny", typestr, 1) == 0)
    type = PREFIX_DENY;
  else
    {
      vty_out (vty, "prefix type must be permit or deny%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* "any" is special token for matching any IPv4 addresses.  */
  if (strncmp ("any", prefix, strlen (prefix)) == 0)
    any = 1;
  else
    {
      if (family == AF_INET)
	{
	  ret = str2prefix_ipv4 (prefix, (struct prefix_ipv4 *) &p);
	  if (ret <= 0)
	    {
	      vty_out (vty, "Malformed IPv4 prefix%s", VTY_NEWLINE);
	      return CMD_WARNING;
	    }
	}
#ifdef HAVE_IPV6
      else if (family == AF_INET6)
	{
	  ret = str2prefix_ipv6 (prefix, (struct prefix_ipv6 *) &p);
	  if (ret <= 0)
	    {
	      vty_out (vty, "Malformed IPv6 prefix%s", VTY_NEWLINE);
	      return CMD_WARNING;
	    }
	}
#endif /* HAVE_IPV6 */
    }

  /* ge and le check. */
  if (ge)
    {
      genum = atoi (ge);
      if (! any && genum < p.prefixlen)
	{
	  vty_out (vty, "ge value must be greater than or equal to prefix length%s", VTY_NEWLINE);
	  return CMD_WARNING;
	}
    }

  if (le)
    {
      lenum = atoi (le);
      if (! any && lenum < p.prefixlen)
	{
	  vty_out (vty, "le value must be lesser than or equal to prefix length%s", VTY_NEWLINE);
	  return CMD_WARNING;
	}
    }

  if (ge && le)
    {
      if (genum > lenum)
	{
	  vty_out (vty, "le or ge value error; please make it sure le >= ge%s",
		   VTY_NEWLINE);
	  return CMD_WARNING;
	}
    }

  /* Make prefix entry. */
  if (any)
    pentry = prefix_list_entry_make (NULL, type, seqnum, lenum, genum);
  else
    pentry = prefix_list_entry_make (&p, type, seqnum, lenum, genum);
    
  /* Check same policy. */
  dup = prefix_entry_dup_check (plist, pentry);

  if (dup)
    {
      prefix_list_entry_free (pentry);
      vty_out (vty, "%Insertion failed - prefix-list entry %d exists%s",
	       dup->seq, VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Install new filter to the access_list. */
  prefix_list_entry_add (plist, pentry);

  return CMD_SUCCESS;
}

int
vty_prefix_list_uninstall (struct vty *vty, int family,
			   char *name, char *seq, char *typestr,
			   char *prefix, char *ge, char *le)
{
  int ret;
  enum prefix_list_type type;
  struct prefix_list *plist;
  struct prefix_list_entry *pentry;
  struct prefix p;
  int any = 0;
  int seqnum = -1;
  int lenum = -1;
  int genum = -1;

  /* Check prefix list name. */
  plist = prefix_list_lookup (family, name);
  if (! plist)
    {
      vty_out (vty, "Can't find specified prefix-list%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Only prefix-list name specified, delete the entire prefix-list. */
  if (seq == NULL && typestr == NULL && prefix == NULL && 
      ge == NULL && le == NULL)
    {
      prefix_list_delete (plist);
      return CMD_SUCCESS;
    }

  /* Check sequence number. */
  if (seq)
    seqnum = atoi (seq);

  /* Check of filter type. */
  if (strncmp ("permit", typestr, 1) == 0)
    type = PREFIX_PERMIT;
  else if (strncmp ("deny", typestr, 1) == 0)
    type = PREFIX_DENY;
  else
    {
      vty_out (vty, "prefix type must be permit or deny%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* "any" is special token of matching IP addresses.  */
  if (strncmp ("any", prefix, strlen (prefix)) == 0)
    any = 1;
  else
    {
      if (family == AF_INET)
	{
	  ret = str2prefix_ipv4 (prefix, (struct prefix_ipv4 *) &p);
	  if (ret <= 0)
	    {
	      vty_out (vty, "Malformed IPv4 prefix%s", VTY_NEWLINE);
	      return CMD_WARNING;
	    }
	}
#ifdef HAVE_IPV6
      else if (family == AF_INET6)
	{
	  ret = str2prefix_ipv6 (prefix, (struct prefix_ipv6 *) &p);
	  if (ret <= 0)
	    {
	      vty_out (vty, "Malformed IPv6 prefix%s", VTY_NEWLINE);
	      return CMD_WARNING;
	    }
	}
#endif /* HAVE_IPV6 */
    }
  /* ge and le check. */
  if (ge)
    genum = atoi (ge);

  if (le)
    lenum = atoi (le);

  /* Lookup prefix entry. */
  if (any)
    pentry = prefix_list_entry_lookup(plist, NULL, type, seqnum, lenum, genum);
  else
    pentry = prefix_list_entry_lookup(plist, &p, type, seqnum, lenum, genum);

  if (pentry == NULL)
    {
      vty_out (vty, "Can't find specified prefix-list%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Install new filter to the access_list. */
  prefix_list_entry_delete (plist, pentry);

  return CMD_SUCCESS;
}

int
vty_prefix_list_desc_unset (struct vty *vty, int family, char *name)
{
  struct prefix_list *plist;

  plist = prefix_list_lookup (family, name);
  if (! plist)
    {
      vty_out (vty, "Can't find specified prefix-list%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (plist->desc)
    {
      XFREE (MTYPE_TMP, plist->desc);
      plist->desc = NULL;
    }

  if (plist->head == NULL && plist->tail == NULL && plist->desc == NULL)
    prefix_list_delete (plist);

  return CMD_SUCCESS;
}

enum display_type
{
  normal_display,
  summary_display,
  detail_display,
  sequential_display,
  longer_display,
  first_match_display
};

void
vty_show_prefix_entry (struct vty *vty, int family, struct prefix_list *plist,
		       struct prefix_master *master, enum display_type dtype,
		       int seqnum)
{
  struct prefix_list_entry *pentry;

  if (dtype == normal_display)
    {
      vty_out (vty, "ip%s prefix-list %s: %d entries%s",
	       family == AF_INET ? "" : "v6",
	       plist->name, plist->count, VTY_NEWLINE);
      if (plist->desc)
	vty_out (vty, "   Description: %s%s", plist->desc, VTY_NEWLINE);
    }
  else if (dtype == summary_display || dtype == detail_display)
    {
      vty_out (vty, "ip%s prefix-list %s:%s",
	       family == AF_INET ? "" : "v6", plist->name, VTY_NEWLINE);

      if (plist->desc)
	vty_out (vty, "   Description: %s%s", plist->desc, VTY_NEWLINE);

      vty_out (vty, "   count: %d, range entries: %d, sequences: %d - %d%s",
	       plist->count, plist->rangecount, 
	       plist->head ? plist->head->seq : 0, 
	       plist->tail ? plist->tail->seq : 0,
	       VTY_NEWLINE);
    }

  if (dtype != summary_display)
    {
      for (pentry = plist->head; pentry; pentry = pentry->next)
	{
	  if (dtype == sequential_display && pentry->seq != seqnum)
	    continue;
	    
	  vty_out (vty, "   ");

	  if (master->seqnum)
	    vty_out (vty, "seq %d ", pentry->seq);

	  vty_out (vty, "%s ", prefix_list_type_str (pentry));

	  if (pentry->any)
	    vty_out (vty, "any");
	  else
	    {
	      struct prefix *p = &pentry->prefix;
	      char buf[BUFSIZ];

	      vty_out (vty, "%s/%d",
		       inet_ntop (p->family, &p->u.prefix, buf, BUFSIZ),
		       p->prefixlen);
	    }

	  if (pentry->le >= 0)
	    vty_out (vty, " le %d", pentry->le);
	  if (pentry->ge >= 0)
	    vty_out (vty, " ge %d", pentry->ge);

	  if (dtype == detail_display || dtype == sequential_display)
	    vty_out (vty, " (hit count: %d, refcount: %d)", 
		     pentry->hitcnt, pentry->refcnt);
	  
	  vty_out (vty, "%s", VTY_NEWLINE);
	}
    }
}

int
vty_show_prefix_list (struct vty *vty, int family, char *name,
		      char *seq, enum display_type dtype)
{
  struct prefix_list *plist;
  struct prefix_master *master;
  int seqnum = 0;

  master = prefix_master_get (family);
  if (master == NULL)
    return CMD_WARNING;

  if (seq)
    seqnum = atoi (seq);

  if (name)
    {
      plist = prefix_list_lookup (family, name);
      if (! plist)
	{
	  vty_out (vty, "Can't find specified prefix-list%s", VTY_NEWLINE);
	  return CMD_WARNING;
	}
      vty_show_prefix_entry (vty, family, plist, master, dtype, seqnum);
    }
  else
    {
      if (dtype == detail_display || dtype == summary_display)
	{
	  if (master->recent)
	    vty_out (vty, "Prefix-list with the last deletion/insertion: %s%s",
		     master->recent->name, VTY_NEWLINE);
	}

      for (plist = master->num.head; plist; plist = plist->next)
	vty_show_prefix_entry (vty, family, plist, master, dtype, seqnum);

      for (plist = master->str.head; plist; plist = plist->next)
	vty_show_prefix_entry (vty, family, plist, master, dtype, seqnum);
    }

  return CMD_SUCCESS;
}

int
vty_show_prefix_list_prefix (struct vty *vty, int family, char *name, 
			     char *prefix, enum display_type type)
{
  struct prefix_list *plist;
  struct prefix_list_entry *pentry;
  struct prefix p;
  int ret;
  int match;

  plist = prefix_list_lookup (family, name);
  if (! plist)
    {
      vty_out (vty, "Can't find specified prefix-list%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  ret = str2prefix (prefix, &p);
  if (ret <= 0)
    {
      vty_out (vty, "prefix is malformed%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  for (pentry = plist->head; pentry; pentry = pentry->next)
    {
      match = 0;

      if (type == normal_display || type == first_match_display)
	if (prefix_same (&p, &pentry->prefix))
	  match = 1;

      if (type == longer_display)
	if (prefix_match (&p, &pentry->prefix))
	  match = 1;

      if (match)
	{
	  vty_out (vty, "   seq %d %s ", 
		   pentry->seq,
		   prefix_list_type_str (pentry));

	  if (pentry->any)
	    vty_out (vty, "any");
	  else
	    {
	      struct prefix *p = &pentry->prefix;
	      char buf[BUFSIZ];
	      
	      vty_out (vty, "%s/%d",
		       inet_ntop (p->family, &p->u.prefix, buf, BUFSIZ),
		       p->prefixlen);
	    }
	  
	  if (pentry->le >= 0)
	    vty_out (vty, " le %d", pentry->le);
	  if (pentry->ge >= 0)
	    vty_out (vty, " ge %d", pentry->ge);

	  if (type == normal_display || type == first_match_display)
	    vty_out (vty, " (hit count: %d, refcount: %d)", 
		     pentry->hitcnt, pentry->refcnt);

	  vty_out (vty, "%s", VTY_NEWLINE);

	  if (type == first_match_display)
	    return CMD_SUCCESS;
	}
    }
  return CMD_SUCCESS;
}

int
vty_clear_prefix_list (struct vty *vty, int family, char *name, char *prefix)
{
  struct prefix_master *master;
  struct prefix_list *plist;
  struct prefix_list_entry *pentry;
  int ret;
  struct prefix p;

  master = prefix_master_get (family);
  if (master == NULL)
    return CMD_WARNING;

  if (name == NULL && prefix == NULL)
    {
      for (plist = master->num.head; plist; plist = plist->next)
	for (pentry = plist->head; pentry; pentry = pentry->next)
	  pentry->hitcnt = 0;

      for (plist = master->str.head; plist; plist = plist->next)
	for (pentry = plist->head; pentry; pentry = pentry->next)
	  pentry->hitcnt = 0;
    }
  else
    {
      plist = prefix_list_lookup (family, name);
      if (! plist)
	{
	  vty_out (vty, "Can't find specified prefix-list%s", VTY_NEWLINE);
	  return CMD_WARNING;
	}

      if (prefix)
	{
	  ret = str2prefix (prefix, &p);
	  if (ret <= 0)
	    {
	      vty_out (vty, "prefix is malformed%s", VTY_NEWLINE);
	      return CMD_WARNING;
	    }
	}

      for (pentry = plist->head; pentry; pentry = pentry->next)
	{
	  if (prefix)
	    {
	      if (prefix_match (&pentry->prefix, &p))
		pentry->hitcnt = 0;
	    }
	  else
	    pentry->hitcnt = 0;
	}
    }
  return CMD_SUCCESS;
}

DEFUN (ip_prefix_list,
       ip_prefix_list_cmd,
       "ip prefix-list WORD (deny|permit) (A.B.C.D/M|any)",
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Any prefix match. Same as \"0.0.0.0/0 le 32\"\n")
{
  return vty_prefix_list_install (vty, AF_INET, argv[0], NULL, 
				  argv[1], argv[2], NULL, NULL);
}

DEFUN (ip_prefix_list_ge,
       ip_prefix_list_ge_cmd,
       "ip prefix-list WORD (deny|permit) A.B.C.D/M ge <0-32>",
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n")
{
  return vty_prefix_list_install (vty, AF_INET, argv[0], NULL, argv[1], 
				 argv[2], argv[3], NULL);
}

DEFUN (ip_prefix_list_ge_le,
       ip_prefix_list_ge_le_cmd,
       "ip prefix-list WORD (deny|permit) A.B.C.D/M ge <0-32> le <0-32>",
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n")
{
  return vty_prefix_list_install (vty, AF_INET, argv[0], NULL, argv[1], 
				  argv[2], argv[3], argv[4]);
}

DEFUN (ip_prefix_list_le,
       ip_prefix_list_le_cmd,
       "ip prefix-list WORD (deny|permit) A.B.C.D/M le <0-32>",
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n")
{
  return vty_prefix_list_install (vty, AF_INET, argv[0], NULL, argv[1],
				  argv[2], NULL, argv[3]);
}

DEFUN (ip_prefix_list_le_ge,
       ip_prefix_list_le_ge_cmd,
       "ip prefix-list WORD (deny|permit) A.B.C.D/M le <0-32> ge <0-32>",
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n")
{
  return vty_prefix_list_install (vty, AF_INET, argv[0], NULL, argv[1],
				  argv[2], argv[4], argv[3]);
}

DEFUN (ip_prefix_list_seq,
       ip_prefix_list_seq_cmd,
       "ip prefix-list WORD seq <1-4294967295> (deny|permit) (A.B.C.D/M|any)",
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Any prefix match. Same as \"0.0.0.0/0 le 32\"\n")
{
  return vty_prefix_list_install (vty, AF_INET, argv[0], argv[1], argv[2],
				  argv[3], NULL, NULL);
}

DEFUN (ip_prefix_list_seq_ge,
       ip_prefix_list_seq_ge_cmd,
       "ip prefix-list WORD seq <1-4294967295> (deny|permit) A.B.C.D/M ge <0-32>",
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n")
{
  return vty_prefix_list_install (vty, AF_INET, argv[0], argv[1], argv[2],
				  argv[3], argv[4], NULL);
}

DEFUN (ip_prefix_list_seq_ge_le,
       ip_prefix_list_seq_ge_le_cmd,
       "ip prefix-list WORD seq <1-4294967295> (deny|permit) A.B.C.D/M ge <0-32> le <0-32>",
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n")
{
  return vty_prefix_list_install (vty, AF_INET, argv[0], argv[1], argv[2],
				  argv[3], argv[4], argv[5]);
}

DEFUN (ip_prefix_list_seq_le,
       ip_prefix_list_seq_le_cmd,
       "ip prefix-list WORD seq <1-4294967295> (deny|permit) A.B.C.D/M le <0-32>",
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n")
{
  return vty_prefix_list_install (vty, AF_INET, argv[0], argv[1], argv[2],
				  argv[3], NULL, argv[4]);
}

DEFUN (ip_prefix_list_seq_le_ge,
       ip_prefix_list_seq_le_ge_cmd,
       "ip prefix-list WORD seq <1-4294967295> (deny|permit) A.B.C.D/M le <0-32> ge <0-32>",
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n")
{
  return vty_prefix_list_install (vty, AF_INET, argv[0], argv[1], argv[2],
				  argv[3], argv[5], argv[4]);
}

DEFUN (no_ip_prefix_list,
       no_ip_prefix_list_cmd,
       "no ip prefix-list WORD",
       NO_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n")
{
  return vty_prefix_list_uninstall (vty, AF_INET, argv[0], NULL, NULL,
				    NULL, NULL, NULL);
}

DEFUN (no_ip_prefix_list_prefix,
       no_ip_prefix_list_prefix_cmd,
       "no ip prefix-list WORD (deny|permit) (A.B.C.D/M|any)",
       NO_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Any prefix match.  Same as \"0.0.0.0/0 le 32\"\n")
{
  return vty_prefix_list_uninstall (vty, AF_INET, argv[0], NULL, argv[1],
				    argv[2], NULL, NULL);
}

DEFUN (no_ip_prefix_list_ge,
       no_ip_prefix_list_ge_cmd,
       "no ip prefix-list WORD (deny|permit) A.B.C.D/M ge <0-32>",
       NO_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n")
{
  return vty_prefix_list_uninstall (vty, AF_INET, argv[0], NULL, argv[1],
				    argv[2], argv[3], NULL);
}

DEFUN (no_ip_prefix_list_ge_le,
       no_ip_prefix_list_ge_le_cmd,
       "no ip prefix-list WORD (deny|permit) A.B.C.D/M ge <0-32> le <0-32>",
       NO_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n")
{
  return vty_prefix_list_uninstall (vty, AF_INET, argv[0], NULL, argv[1],
				    argv[2], argv[3], argv[4]);
}

DEFUN (no_ip_prefix_list_le,
       no_ip_prefix_list_le_cmd,
       "no ip prefix-list WORD (deny|permit) A.B.C.D/M le <0-32>",
       NO_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n")
{
  return vty_prefix_list_uninstall (vty, AF_INET, argv[0], NULL, argv[1],
				    argv[2], NULL, argv[3]);
}

DEFUN (no_ip_prefix_list_le_ge,
       no_ip_prefix_list_le_ge_cmd,
       "no ip prefix-list WORD (deny|permit) A.B.C.D/M le <0-32> ge <0-32>",
       NO_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n")
{
  return vty_prefix_list_uninstall (vty, AF_INET, argv[0], NULL, argv[1],
				    argv[2], argv[4], argv[3]);
}

DEFUN (no_ip_prefix_list_seq,
       no_ip_prefix_list_seq_cmd,
       "no ip prefix-list WORD seq <1-4294967295> (deny|permit) (A.B.C.D/M|any)",
       NO_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Any prefix match.  Same as \"0.0.0.0/0 le 32\"\n")
{
  return vty_prefix_list_uninstall (vty, AF_INET, argv[0], argv[1], argv[2],
				    argv[3], NULL, NULL);
}

DEFUN (no_ip_prefix_list_seq_ge,
       no_ip_prefix_list_seq_ge_cmd,
       "no ip prefix-list WORD seq <1-4294967295> (deny|permit) A.B.C.D/M ge <0-32>",
       NO_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n")
{
  return vty_prefix_list_uninstall (vty, AF_INET, argv[0], argv[1], argv[2],
				    argv[3], argv[4], NULL);
}

DEFUN (no_ip_prefix_list_seq_ge_le,
       no_ip_prefix_list_seq_ge_le_cmd,
       "no ip prefix-list WORD seq <1-4294967295> (deny|permit) A.B.C.D/M ge <0-32> le <0-32>",
       NO_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n")
{
  return vty_prefix_list_uninstall (vty, AF_INET, argv[0], argv[1], argv[2],
				    argv[3], argv[4], argv[5]);
}

DEFUN (no_ip_prefix_list_seq_le,
       no_ip_prefix_list_seq_le_cmd,
       "no ip prefix-list WORD seq <1-4294967295> (deny|permit) A.B.C.D/M le <0-32>",
       NO_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n")
{
  return vty_prefix_list_uninstall (vty, AF_INET, argv[0], argv[1], argv[2],
				    argv[3], NULL, argv[4]);
}

DEFUN (no_ip_prefix_list_seq_le_ge,
       no_ip_prefix_list_seq_le_ge_cmd,
       "no ip prefix-list WORD seq <1-4294967295> (deny|permit) A.B.C.D/M le <0-32> ge <0-32>",
       NO_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n")
{
  return vty_prefix_list_uninstall (vty, AF_INET, argv[0], argv[1], argv[2],
				    argv[3], argv[5], argv[4]);
}

DEFUN (ip_prefix_list_sequence_number,
       ip_prefix_list_sequence_number_cmd,
       "ip prefix-list sequence-number",
       IP_STR
       PREFIX_LIST_STR
       "Include/exclude sequence numbers in NVGEN\n")
{
  prefix_master_ipv4.seqnum = 1;
  return CMD_SUCCESS;
}

DEFUN (no_ip_prefix_list_sequence_number,
       no_ip_prefix_list_sequence_number_cmd,
       "no ip prefix-list sequence-number",
       NO_STR
       IP_STR
       PREFIX_LIST_STR
       "Include/exclude sequence numbers in NVGEN\n")
{
  prefix_master_ipv4.seqnum = 0;
  return CMD_SUCCESS;
}

DEFUN (ip_prefix_list_description,
       ip_prefix_list_description_cmd,
       "ip prefix-list WORD description .LINE",
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Prefix-list specific description\n"
       "Up to 80 characters describing this prefix-list\n")
{
  struct prefix_list *plist;
  struct buffer *b;
  int i;

  plist = prefix_list_get (AF_INET, argv[0]);
  
  if (plist->desc)
    {
      XFREE (MTYPE_TMP, plist->desc);
      plist->desc = NULL;
    }

  /* Below is description get codes. */
  b = buffer_new (BUFFER_STRING, 1024);
  for (i = 1; i < argc; i++)
    {
      buffer_putstr (b, (u_char *)argv[i]);
      buffer_putc (b, ' ');
    }
  buffer_putc (b, '\0');

  plist->desc = buffer_getstr (b);

  buffer_free (b);

  return CMD_SUCCESS;
}       

DEFUN (no_ip_prefix_list_description,
       no_ip_prefix_list_description_cmd,
       "no ip prefix-list WORD description",
       NO_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Prefix-list specific description\n")
{
  return vty_prefix_list_desc_unset (vty, AF_INET, argv[0]);
}

ALIAS (no_ip_prefix_list_description,
       no_ip_prefix_list_description_arg_cmd,
       "no ip prefix-list WORD description .LINE",
       NO_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Prefix-list specific description\n"
       "Up to 80 characters describing this prefix-list\n")

DEFUN (show_ip_prefix_list,
       show_ip_prefix_list_cmd,
       "show ip prefix-list",
       SHOW_STR
       IP_STR
       PREFIX_LIST_STR)
{
  return vty_show_prefix_list (vty, AF_INET, NULL, NULL, normal_display);
}

DEFUN (show_ip_prefix_list_name,
       show_ip_prefix_list_name_cmd,
       "show ip prefix-list WORD",
       SHOW_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n")
{
  return vty_show_prefix_list (vty, AF_INET, argv[0], NULL, normal_display);
}

DEFUN (show_ip_prefix_list_name_seq,
       show_ip_prefix_list_name_seq_cmd,
       "show ip prefix-list WORD seq <1-4294967295>",
       SHOW_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n")
{
  return vty_show_prefix_list (vty, AF_INET, argv[0], argv[1], sequential_display);
}

DEFUN (show_ip_prefix_list_prefix,
       show_ip_prefix_list_prefix_cmd,
       "show ip prefix-list WORD A.B.C.D/M",
       SHOW_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")
{
  return vty_show_prefix_list_prefix (vty, AF_INET, argv[0], argv[1], normal_display);
}

DEFUN (show_ip_prefix_list_prefix_longer,
       show_ip_prefix_list_prefix_longer_cmd,
       "show ip prefix-list WORD A.B.C.D/M longer",
       SHOW_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Lookup longer prefix\n")
{
  return vty_show_prefix_list_prefix (vty, AF_INET, argv[0], argv[1], longer_display);
}

DEFUN (show_ip_prefix_list_prefix_first_match,
       show_ip_prefix_list_prefix_first_match_cmd,
       "show ip prefix-list WORD A.B.C.D/M first-match",
       SHOW_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "First matched prefix\n")
{
  return vty_show_prefix_list_prefix (vty, AF_INET, argv[0], argv[1], first_match_display);
}

DEFUN (show_ip_prefix_list_summary,
       show_ip_prefix_list_summary_cmd,
       "show ip prefix-list summary",
       SHOW_STR
       IP_STR
       PREFIX_LIST_STR
       "Summary of prefix lists\n")
{
  return vty_show_prefix_list (vty, AF_INET, NULL, NULL, summary_display);
}

DEFUN (show_ip_prefix_list_summary_name,
       show_ip_prefix_list_summary_name_cmd,
       "show ip prefix-list summary WORD",
       SHOW_STR
       IP_STR
       PREFIX_LIST_STR
       "Summary of prefix lists\n"
       "Name of a prefix list\n")
{
  return vty_show_prefix_list (vty, AF_INET, argv[0], NULL, summary_display);
}


DEFUN (show_ip_prefix_list_detail,
       show_ip_prefix_list_detail_cmd,
       "show ip prefix-list detail",
       SHOW_STR
       IP_STR
       PREFIX_LIST_STR
       "Detail of prefix lists\n")
{
  return vty_show_prefix_list (vty, AF_INET, NULL, NULL, detail_display);
}

DEFUN (show_ip_prefix_list_detail_name,
       show_ip_prefix_list_detail_name_cmd,
       "show ip prefix-list detail WORD",
       SHOW_STR
       IP_STR
       PREFIX_LIST_STR
       "Detail of prefix lists\n"
       "Name of a prefix list\n")
{
  return vty_show_prefix_list (vty, AF_INET, argv[0], NULL, detail_display);
}

DEFUN (clear_ip_prefix_list,
       clear_ip_prefix_list_cmd,
       "clear ip prefix-list",
       CLEAR_STR
       IP_STR
       PREFIX_LIST_STR)
{
  return vty_clear_prefix_list (vty, AF_INET, NULL, NULL);
}

DEFUN (clear_ip_prefix_list_name,
       clear_ip_prefix_list_name_cmd,
       "clear ip prefix-list WORD",
       CLEAR_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n")
{
  return vty_clear_prefix_list (vty, AF_INET, argv[0], NULL);
}

DEFUN (clear_ip_prefix_list_name_prefix,
       clear_ip_prefix_list_name_prefix_cmd,
       "clear ip prefix-list WORD A.B.C.D/M",
       CLEAR_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")
{
  return vty_clear_prefix_list (vty, AF_INET, argv[0], argv[1]);
}

#ifdef HAVE_IPV6
DEFUN (ipv6_prefix_list,
       ipv6_prefix_list_cmd,
       "ipv6 prefix-list WORD (deny|permit) (X:X::X:X/M|any)",
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "Any prefix match.  Same as \"::0/0 le 128\"\n")
{
  return vty_prefix_list_install (vty, AF_INET6, argv[0], NULL, 
				  argv[1], argv[2], NULL, NULL);
}

DEFUN (ipv6_prefix_list_ge,
       ipv6_prefix_list_ge_cmd,
       "ipv6 prefix-list WORD (deny|permit) X:X::X:X/M ge <0-128>",
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n")
{
  return vty_prefix_list_install (vty, AF_INET6, argv[0], NULL, argv[1], 
				 argv[2], argv[3], NULL);
}

DEFUN (ipv6_prefix_list_ge_le,
       ipv6_prefix_list_ge_le_cmd,
       "ipv6 prefix-list WORD (deny|permit) X:X::X:X/M ge <0-128> le <0-128>",
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n")

{
  return vty_prefix_list_install (vty, AF_INET6, argv[0], NULL, argv[1], 
				  argv[2], argv[3], argv[4]);
}

DEFUN (ipv6_prefix_list_le,
       ipv6_prefix_list_le_cmd,
       "ipv6 prefix-list WORD (deny|permit) X:X::X:X/M le <0-128>",
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n")
{
  return vty_prefix_list_install (vty, AF_INET6, argv[0], NULL, argv[1],
				  argv[2], NULL, argv[3]);
}

DEFUN (ipv6_prefix_list_le_ge,
       ipv6_prefix_list_le_ge_cmd,
       "ipv6 prefix-list WORD (deny|permit) X:X::X:X/M le <0-128> ge <0-128>",
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n")
{
  return vty_prefix_list_install (vty, AF_INET6, argv[0], NULL, argv[1],
				  argv[2], argv[4], argv[3]);
}

DEFUN (ipv6_prefix_list_seq,
       ipv6_prefix_list_seq_cmd,
       "ipv6 prefix-list WORD seq <1-4294967295> (deny|permit) (X:X::X:X/M|any)",
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "Any prefix match.  Same as \"::0/0 le 128\"\n")
{
  return vty_prefix_list_install (vty, AF_INET6, argv[0], argv[1], argv[2],
				  argv[3], NULL, NULL);
}

DEFUN (ipv6_prefix_list_seq_ge,
       ipv6_prefix_list_seq_ge_cmd,
       "ipv6 prefix-list WORD seq <1-4294967295> (deny|permit) X:X::X:X/M ge <0-128>",
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n")
{
  return vty_prefix_list_install (vty, AF_INET6, argv[0], argv[1], argv[2],
				  argv[3], argv[4], NULL);
}

DEFUN (ipv6_prefix_list_seq_ge_le,
       ipv6_prefix_list_seq_ge_le_cmd,
       "ipv6 prefix-list WORD seq <1-4294967295> (deny|permit) X:X::X:X/M ge <0-128> le <0-128>",
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n")
{
  return vty_prefix_list_install (vty, AF_INET6, argv[0], argv[1], argv[2],
				  argv[3], argv[4], argv[5]);
}

DEFUN (ipv6_prefix_list_seq_le,
       ipv6_prefix_list_seq_le_cmd,
       "ipv6 prefix-list WORD seq <1-4294967295> (deny|permit) X:X::X:X/M le <0-128>",
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n")
{
  return vty_prefix_list_install (vty, AF_INET6, argv[0], argv[1], argv[2],
				  argv[3], NULL, argv[4]);
}

DEFUN (ipv6_prefix_list_seq_le_ge,
       ipv6_prefix_list_seq_le_ge_cmd,
       "ipv6 prefix-list WORD seq <1-4294967295> (deny|permit) X:X::X:X/M le <0-128> ge <0-128>",
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n")
{
  return vty_prefix_list_install (vty, AF_INET6, argv[0], argv[1], argv[2],
				  argv[3], argv[5], argv[4]);
}

DEFUN (no_ipv6_prefix_list,
       no_ipv6_prefix_list_cmd,
       "no ipv6 prefix-list WORD",
       NO_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n")
{
  return vty_prefix_list_uninstall (vty, AF_INET6, argv[0], NULL, NULL,
				    NULL, NULL, NULL);
}

DEFUN (no_ipv6_prefix_list_prefix,
       no_ipv6_prefix_list_prefix_cmd,
       "no ipv6 prefix-list WORD (deny|permit) (X:X::X:X/M|any)",
       NO_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "Any prefix match.  Same as \"::0/0 le 128\"\n")
{
  return vty_prefix_list_uninstall (vty, AF_INET6, argv[0], NULL, argv[1],
				    argv[2], NULL, NULL);
}

DEFUN (no_ipv6_prefix_list_ge,
       no_ipv6_prefix_list_ge_cmd,
       "no ipv6 prefix-list WORD (deny|permit) X:X::X:X/M ge <0-128>",
       NO_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n")
{
  return vty_prefix_list_uninstall (vty, AF_INET6, argv[0], NULL, argv[1],
				    argv[2], argv[3], NULL);
}

DEFUN (no_ipv6_prefix_list_ge_le,
       no_ipv6_prefix_list_ge_le_cmd,
       "no ipv6 prefix-list WORD (deny|permit) X:X::X:X/M ge <0-128> le <0-128>",
       NO_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n")
{
  return vty_prefix_list_uninstall (vty, AF_INET6, argv[0], NULL, argv[1],
				    argv[2], argv[3], argv[4]);
}

DEFUN (no_ipv6_prefix_list_le,
       no_ipv6_prefix_list_le_cmd,
       "no ipv6 prefix-list WORD (deny|permit) X:X::X:X/M le <0-128>",
       NO_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n")
{
  return vty_prefix_list_uninstall (vty, AF_INET6, argv[0], NULL, argv[1],
				    argv[2], NULL, argv[3]);
}

DEFUN (no_ipv6_prefix_list_le_ge,
       no_ipv6_prefix_list_le_ge_cmd,
       "no ipv6 prefix-list WORD (deny|permit) X:X::X:X/M le <0-128> ge <0-128>",
       NO_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n")
{
  return vty_prefix_list_uninstall (vty, AF_INET6, argv[0], NULL, argv[1],
				    argv[2], argv[4], argv[3]);
}

DEFUN (no_ipv6_prefix_list_seq,
       no_ipv6_prefix_list_seq_cmd,
       "no ipv6 prefix-list WORD seq <1-4294967295> (deny|permit) (X:X::X:X/M|any)",
       NO_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "Any prefix match.  Same as \"::0/0 le 128\"\n")
{
  return vty_prefix_list_uninstall (vty, AF_INET6, argv[0], argv[1], argv[2],
				    argv[3], NULL, NULL);
}

DEFUN (no_ipv6_prefix_list_seq_ge,
       no_ipv6_prefix_list_seq_ge_cmd,
       "no ipv6 prefix-list WORD seq <1-4294967295> (deny|permit) X:X::X:X/M ge <0-128>",
       NO_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n")
{
  return vty_prefix_list_uninstall (vty, AF_INET6, argv[0], argv[1], argv[2],
				    argv[3], argv[4], NULL);
}

DEFUN (no_ipv6_prefix_list_seq_ge_le,
       no_ipv6_prefix_list_seq_ge_le_cmd,
       "no ipv6 prefix-list WORD seq <1-4294967295> (deny|permit) X:X::X:X/M ge <0-128> le <0-128>",
       NO_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n")
{
  return vty_prefix_list_uninstall (vty, AF_INET6, argv[0], argv[1], argv[2],
				    argv[3], argv[4], argv[5]);
}

DEFUN (no_ipv6_prefix_list_seq_le,
       no_ipv6_prefix_list_seq_le_cmd,
       "no ipv6 prefix-list WORD seq <1-4294967295> (deny|permit) X:X::X:X/M le <0-128>",
       NO_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n")
{
  return vty_prefix_list_uninstall (vty, AF_INET6, argv[0], argv[1], argv[2],
				    argv[3], NULL, argv[4]);
}

DEFUN (no_ipv6_prefix_list_seq_le_ge,
       no_ipv6_prefix_list_seq_le_ge_cmd,
       "no ipv6 prefix-list WORD seq <1-4294967295> (deny|permit) X:X::X:X/M le <0-128> ge <0-128>",
       NO_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n")
{
  return vty_prefix_list_uninstall (vty, AF_INET6, argv[0], argv[1], argv[2],
				    argv[3], argv[5], argv[4]);
}

DEFUN (ipv6_prefix_list_sequence_number,
       ipv6_prefix_list_sequence_number_cmd,
       "ipv6 prefix-list sequence-number",
       IPV6_STR
       PREFIX_LIST_STR
       "Include/exclude sequence numbers in NVGEN\n")
{
  prefix_master_ipv6.seqnum = 1;
  return CMD_SUCCESS;
}

DEFUN (no_ipv6_prefix_list_sequence_number,
       no_ipv6_prefix_list_sequence_number_cmd,
       "no ipv6 prefix-list sequence-number",
       NO_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Include/exclude sequence numbers in NVGEN\n")
{
  prefix_master_ipv6.seqnum = 0;
  return CMD_SUCCESS;
}

DEFUN (ipv6_prefix_list_description,
       ipv6_prefix_list_description_cmd,
       "ipv6 prefix-list WORD description .LINE",
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Prefix-list specific description\n"
       "Up to 80 characters describing this prefix-list\n")
{
  struct prefix_list *plist;
  struct buffer *b;
  int i;

  plist = prefix_list_get (AF_INET6, argv[0]);
  
  if (plist->desc)
    {
      XFREE (MTYPE_TMP, plist->desc);
      plist->desc = NULL;
    }

  /* Below is description get codes. */
  b = buffer_new (BUFFER_STRING, 1024);
  for (i = 1; i < argc; i++)
    {
      buffer_putstr (b, (u_char *)argv[i]);
      buffer_putc (b, ' ');
    }
  buffer_putc (b, '\0');

  plist->desc = buffer_getstr (b);

  buffer_free (b);

  return CMD_SUCCESS;
}       

DEFUN (no_ipv6_prefix_list_description,
       no_ipv6_prefix_list_description_cmd,
       "no ipv6 prefix-list WORD description",
       NO_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Prefix-list specific description\n")
{
  return vty_prefix_list_desc_unset (vty, AF_INET6, argv[0]);
}

ALIAS (no_ipv6_prefix_list_description,
       no_ipv6_prefix_list_description_arg_cmd,
       "no ipv6 prefix-list WORD description .LINE",
       NO_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Prefix-list specific description\n"
       "Up to 80 characters describing this prefix-list\n")

DEFUN (show_ipv6_prefix_list,
       show_ipv6_prefix_list_cmd,
       "show ipv6 prefix-list",
       SHOW_STR
       IPV6_STR
       PREFIX_LIST_STR)
{
  return vty_show_prefix_list (vty, AF_INET6, NULL, NULL, normal_display);
}

DEFUN (show_ipv6_prefix_list_name,
       show_ipv6_prefix_list_name_cmd,
       "show ipv6 prefix-list WORD",
       SHOW_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n")
{
  return vty_show_prefix_list (vty, AF_INET6, argv[0], NULL, normal_display);
}

DEFUN (show_ipv6_prefix_list_name_seq,
       show_ipv6_prefix_list_name_seq_cmd,
       "show ipv6 prefix-list WORD seq <1-4294967295>",
       SHOW_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n")
{
  return vty_show_prefix_list (vty, AF_INET6, argv[0], argv[1], sequential_display);
}

DEFUN (show_ipv6_prefix_list_prefix,
       show_ipv6_prefix_list_prefix_cmd,
       "show ipv6 prefix-list WORD X:X::X:X/M",
       SHOW_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n")
{
  return vty_show_prefix_list_prefix (vty, AF_INET6, argv[0], argv[1], normal_display);
}

DEFUN (show_ipv6_prefix_list_prefix_longer,
       show_ipv6_prefix_list_prefix_longer_cmd,
       "show ipv6 prefix-list WORD X:X::X:X/M longer",
       SHOW_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "Lookup longer prefix\n")
{
  return vty_show_prefix_list_prefix (vty, AF_INET6, argv[0], argv[1], longer_display);
}

DEFUN (show_ipv6_prefix_list_prefix_first_match,
       show_ipv6_prefix_list_prefix_first_match_cmd,
       "show ipv6 prefix-list WORD X:X::X:X/M first-match",
       SHOW_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "First matched prefix\n")
{
  return vty_show_prefix_list_prefix (vty, AF_INET6, argv[0], argv[1], first_match_display);
}

DEFUN (show_ipv6_prefix_list_summary,
       show_ipv6_prefix_list_summary_cmd,
       "show ipv6 prefix-list summary",
       SHOW_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Summary of prefix lists\n")
{
  return vty_show_prefix_list (vty, AF_INET6, NULL, NULL, summary_display);
}

DEFUN (show_ipv6_prefix_list_summary_name,
       show_ipv6_prefix_list_summary_name_cmd,
       "show ipv6 prefix-list summary WORD",
       SHOW_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Summary of prefix lists\n"
       "Name of a prefix list\n")
{
  return vty_show_prefix_list (vty, AF_INET6, argv[0], NULL, summary_display);
}

DEFUN (show_ipv6_prefix_list_detail,
       show_ipv6_prefix_list_detail_cmd,
       "show ipv6 prefix-list detail",
       SHOW_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Detail of prefix lists\n")
{
  return vty_show_prefix_list (vty, AF_INET6, NULL, NULL, detail_display);
}

DEFUN (show_ipv6_prefix_list_detail_name,
       show_ipv6_prefix_list_detail_name_cmd,
       "show ipv6 prefix-list detail WORD",
       SHOW_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Detail of prefix lists\n"
       "Name of a prefix list\n")
{
  return vty_show_prefix_list (vty, AF_INET6, argv[0], NULL, detail_display);
}

DEFUN (clear_ipv6_prefix_list,
       clear_ipv6_prefix_list_cmd,
       "clear ipv6 prefix-list",
       CLEAR_STR
       IPV6_STR
       PREFIX_LIST_STR)
{
  return vty_clear_prefix_list (vty, AF_INET6, NULL, NULL);
}

DEFUN (clear_ipv6_prefix_list_name,
       clear_ipv6_prefix_list_name_cmd,
       "clear ipv6 prefix-list WORD",
       CLEAR_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n")
{
  return vty_clear_prefix_list (vty, AF_INET6, argv[0], NULL);
}

DEFUN (clear_ipv6_prefix_list_name_prefix,
       clear_ipv6_prefix_list_name_prefix_cmd,
       "clear ipv6 prefix-list WORD X:X::X:X/M",
       CLEAR_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n")
{
  return vty_clear_prefix_list (vty, AF_INET6, argv[0], argv[1]);
}
#endif /* HAVE_IPV6 */

/* Configuration write function. */
int
config_write_prefix_family (int family, struct vty *vty)
{
  struct prefix_list *plist;
  struct prefix_list_entry *pentry;
  struct prefix_master *master;
  int write = 0;

  master = prefix_master_get (family);
  if (master == NULL)
    return 0;

  if (! master->seqnum)
    {
      vty_out (vty, "no ip%s prefix-list sequence-number%s", 
	       family == AF_INET ? "" : "v6", VTY_NEWLINE);
      vty_out (vty, "!%s", VTY_NEWLINE);
    }

  for (plist = master->num.head; plist; plist = plist->next)
    {
      if (plist->desc)
	{
	  vty_out (vty, "ip%s prefix-list %s description %s%s",
		   family == AF_INET ? "" : "v6",
		   plist->name, plist->desc, VTY_NEWLINE);
	  write++;
	}

      for (pentry = plist->head; pentry; pentry = pentry->next)
	{
	  vty_out (vty, "ip%s prefix-list %s ",
		   family == AF_INET ? "" : "v6",
		   plist->name);

	  if (master->seqnum)
	    vty_out (vty, "seq %d ", pentry->seq);
	
	  vty_out (vty, "%s ", prefix_list_type_str (pentry));

	  if (pentry->any)
	    vty_out (vty, "any");
	  else
	    {
	      struct prefix *p = &pentry->prefix;
	      char buf[BUFSIZ];

	      vty_out (vty, "%s/%d",
		       inet_ntop (p->family, &p->u.prefix, buf, BUFSIZ),
		       p->prefixlen);
	    }

	  if (pentry->le >= 0)
	    vty_out (vty, " le %d", pentry->le);
	  if (pentry->ge >= 0)
	    vty_out (vty, " ge %d", pentry->ge);
	  vty_out (vty, "%s", VTY_NEWLINE);
	  write++;
	}
      /* vty_out (vty, "!%s", VTY_NEWLINE); */
    }

  for (plist = master->str.head; plist; plist = plist->next)
    {
      if (plist->desc)
	{
	  vty_out (vty, "ip%s prefix-list %s description %s%s",
		   family == AF_INET ? "" : "v6",
		   plist->name, plist->desc, VTY_NEWLINE);
	  write++;
	}

      for (pentry = plist->head; pentry; pentry = pentry->next)
	{
	  vty_out (vty, "ip%s prefix-list %s ",
		   family == AF_INET ? "" : "v6",
		   plist->name);

	  if (master->seqnum)
	    vty_out (vty, "seq %d ", pentry->seq);

	  vty_out (vty, "%s", prefix_list_type_str (pentry));

	  if (pentry->any)
	    vty_out (vty, " any");
	  else
	    {
	      struct prefix *p = &pentry->prefix;
	      char buf[BUFSIZ];

	      vty_out (vty, " %s/%d",
		       inet_ntop (p->family, &p->u.prefix, buf, BUFSIZ),
		       p->prefixlen);
	    }
	  if (pentry->le >= 0)
	    vty_out (vty, " le %d", pentry->le);
	  if (pentry->ge >= 0)
	    vty_out (vty, " ge %d", pentry->ge);
	  vty_out (vty, "%s", VTY_NEWLINE);
	  write++;
	}
      /* vty_out (vty, "!%s", VTY_NEWLINE); */
    }
  
  return write;
}

/* Prefix-list node. */
struct cmd_node prefix_node =
{
  PREFIX_NODE,
  ""				/* Prefix list has no interface. */
};

int
config_write_prefix_ipv4 (struct vty *vty)
{
  return config_write_prefix_family (AF_INET, vty);
}

void
prefix_list_reset_ipv4 ()
{
  struct prefix_list *plist;
  struct prefix_list *next;
  struct prefix_master *master;

  master = prefix_master_get (AF_INET);
  if (master == NULL)
    return;

  for (plist = master->num.head; plist; plist = next)
    {
      next = plist->next;
      prefix_list_delete (plist);
    }
  for (plist = master->str.head; plist; plist = next)
    {
      next = plist->next;
      prefix_list_delete (plist);
    }

  assert (master->num.head == NULL);
  assert (master->num.tail == NULL);

  assert (master->str.head == NULL);
  assert (master->str.tail == NULL);

  master->seqnum = 1;
  master->recent = NULL;
}

void
prefix_list_init_ipv4 ()
{
  install_node (&prefix_node, config_write_prefix_ipv4);

  install_element (CONFIG_NODE, &ip_prefix_list_cmd);
  install_element (CONFIG_NODE, &ip_prefix_list_ge_cmd);
  install_element (CONFIG_NODE, &ip_prefix_list_ge_le_cmd);
  install_element (CONFIG_NODE, &ip_prefix_list_le_cmd);
  install_element (CONFIG_NODE, &ip_prefix_list_le_ge_cmd);
  install_element (CONFIG_NODE, &ip_prefix_list_seq_cmd);
  install_element (CONFIG_NODE, &ip_prefix_list_seq_ge_cmd);
  install_element (CONFIG_NODE, &ip_prefix_list_seq_ge_le_cmd);
  install_element (CONFIG_NODE, &ip_prefix_list_seq_le_cmd);
  install_element (CONFIG_NODE, &ip_prefix_list_seq_le_ge_cmd);

  install_element (CONFIG_NODE, &no_ip_prefix_list_cmd);
  install_element (CONFIG_NODE, &no_ip_prefix_list_prefix_cmd);
  install_element (CONFIG_NODE, &no_ip_prefix_list_ge_cmd);
  install_element (CONFIG_NODE, &no_ip_prefix_list_ge_le_cmd);
  install_element (CONFIG_NODE, &no_ip_prefix_list_le_cmd);
  install_element (CONFIG_NODE, &no_ip_prefix_list_le_ge_cmd);
  install_element (CONFIG_NODE, &no_ip_prefix_list_seq_cmd);
  install_element (CONFIG_NODE, &no_ip_prefix_list_seq_ge_cmd);
  install_element (CONFIG_NODE, &no_ip_prefix_list_seq_ge_le_cmd);
  install_element (CONFIG_NODE, &no_ip_prefix_list_seq_le_cmd);
  install_element (CONFIG_NODE, &no_ip_prefix_list_seq_le_ge_cmd);

  install_element (CONFIG_NODE, &ip_prefix_list_description_cmd);
  install_element (CONFIG_NODE, &no_ip_prefix_list_description_cmd);
  install_element (CONFIG_NODE, &no_ip_prefix_list_description_arg_cmd);

  install_element (CONFIG_NODE, &ip_prefix_list_sequence_number_cmd);
  install_element (CONFIG_NODE, &no_ip_prefix_list_sequence_number_cmd);

  install_element (VIEW_NODE, &show_ip_prefix_list_cmd);
  install_element (VIEW_NODE, &show_ip_prefix_list_name_cmd);
  install_element (VIEW_NODE, &show_ip_prefix_list_name_seq_cmd);
  install_element (VIEW_NODE, &show_ip_prefix_list_prefix_cmd);
  install_element (VIEW_NODE, &show_ip_prefix_list_prefix_longer_cmd);
  install_element (VIEW_NODE, &show_ip_prefix_list_prefix_first_match_cmd);
  install_element (VIEW_NODE, &show_ip_prefix_list_summary_cmd);
  install_element (VIEW_NODE, &show_ip_prefix_list_summary_name_cmd);
  install_element (VIEW_NODE, &show_ip_prefix_list_detail_cmd);
  install_element (VIEW_NODE, &show_ip_prefix_list_detail_name_cmd);

  install_element (ENABLE_NODE, &show_ip_prefix_list_cmd);
  install_element (ENABLE_NODE, &show_ip_prefix_list_name_cmd);
  install_element (ENABLE_NODE, &show_ip_prefix_list_name_seq_cmd);
  install_element (ENABLE_NODE, &show_ip_prefix_list_prefix_cmd);
  install_element (ENABLE_NODE, &show_ip_prefix_list_prefix_longer_cmd);
  install_element (ENABLE_NODE, &show_ip_prefix_list_prefix_first_match_cmd);
  install_element (ENABLE_NODE, &show_ip_prefix_list_summary_cmd);
  install_element (ENABLE_NODE, &show_ip_prefix_list_summary_name_cmd);
  install_element (ENABLE_NODE, &show_ip_prefix_list_detail_cmd);
  install_element (ENABLE_NODE, &show_ip_prefix_list_detail_name_cmd);

  install_element (ENABLE_NODE, &clear_ip_prefix_list_cmd);
  install_element (ENABLE_NODE, &clear_ip_prefix_list_name_cmd);
  install_element (ENABLE_NODE, &clear_ip_prefix_list_name_prefix_cmd);
}

#ifdef HAVE_IPV6
/* Prefix-list node. */
struct cmd_node prefix_ipv6_node =
{
  PREFIX_IPV6_NODE,
  ""				/* Prefix list has no interface. */
};

int
config_write_prefix_ipv6 (struct vty *vty)
{
  return config_write_prefix_family (AF_INET6, vty);
}

void
prefix_list_reset_ipv6 ()
{
  struct prefix_list *plist;
  struct prefix_list *next;
  struct prefix_master *master;

  master = prefix_master_get (AF_INET6);
  if (master == NULL)
    return;

  for (plist = master->num.head; plist; plist = next)
    {
      next = plist->next;
      prefix_list_delete (plist);
    }
  for (plist = master->str.head; plist; plist = next)
    {
      next = plist->next;
      prefix_list_delete (plist);
    }

  assert (master->num.head == NULL);
  assert (master->num.tail == NULL);

  assert (master->str.head == NULL);
  assert (master->str.tail == NULL);

  master->seqnum = 1;
  master->recent = NULL;
}

void
prefix_list_init_ipv6 ()
{
  install_node (&prefix_ipv6_node, config_write_prefix_ipv6);

  install_element (CONFIG_NODE, &ipv6_prefix_list_cmd);
  install_element (CONFIG_NODE, &ipv6_prefix_list_ge_cmd);
  install_element (CONFIG_NODE, &ipv6_prefix_list_ge_le_cmd);
  install_element (CONFIG_NODE, &ipv6_prefix_list_le_cmd);
  install_element (CONFIG_NODE, &ipv6_prefix_list_le_ge_cmd);
  install_element (CONFIG_NODE, &ipv6_prefix_list_seq_cmd);
  install_element (CONFIG_NODE, &ipv6_prefix_list_seq_ge_cmd);
  install_element (CONFIG_NODE, &ipv6_prefix_list_seq_ge_le_cmd);
  install_element (CONFIG_NODE, &ipv6_prefix_list_seq_le_cmd);
  install_element (CONFIG_NODE, &ipv6_prefix_list_seq_le_ge_cmd);

  install_element (CONFIG_NODE, &no_ipv6_prefix_list_cmd);
  install_element (CONFIG_NODE, &no_ipv6_prefix_list_prefix_cmd);
  install_element (CONFIG_NODE, &no_ipv6_prefix_list_ge_cmd);
  install_element (CONFIG_NODE, &no_ipv6_prefix_list_ge_le_cmd);
  install_element (CONFIG_NODE, &no_ipv6_prefix_list_le_cmd);
  install_element (CONFIG_NODE, &no_ipv6_prefix_list_le_ge_cmd);
  install_element (CONFIG_NODE, &no_ipv6_prefix_list_seq_cmd);
  install_element (CONFIG_NODE, &no_ipv6_prefix_list_seq_ge_cmd);
  install_element (CONFIG_NODE, &no_ipv6_prefix_list_seq_ge_le_cmd);
  install_element (CONFIG_NODE, &no_ipv6_prefix_list_seq_le_cmd);
  install_element (CONFIG_NODE, &no_ipv6_prefix_list_seq_le_ge_cmd);

  install_element (CONFIG_NODE, &ipv6_prefix_list_description_cmd);
  install_element (CONFIG_NODE, &no_ipv6_prefix_list_description_cmd);
  install_element (CONFIG_NODE, &no_ipv6_prefix_list_description_arg_cmd);

  install_element (CONFIG_NODE, &ipv6_prefix_list_sequence_number_cmd);
  install_element (CONFIG_NODE, &no_ipv6_prefix_list_sequence_number_cmd);

  install_element (VIEW_NODE, &show_ipv6_prefix_list_cmd);
  install_element (VIEW_NODE, &show_ipv6_prefix_list_name_cmd);
  install_element (VIEW_NODE, &show_ipv6_prefix_list_name_seq_cmd);
  install_element (VIEW_NODE, &show_ipv6_prefix_list_prefix_cmd);
  install_element (VIEW_NODE, &show_ipv6_prefix_list_prefix_longer_cmd);
  install_element (VIEW_NODE, &show_ipv6_prefix_list_prefix_first_match_cmd);
  install_element (VIEW_NODE, &show_ipv6_prefix_list_summary_cmd);
  install_element (VIEW_NODE, &show_ipv6_prefix_list_summary_name_cmd);
  install_element (VIEW_NODE, &show_ipv6_prefix_list_detail_cmd);
  install_element (VIEW_NODE, &show_ipv6_prefix_list_detail_name_cmd);

  install_element (ENABLE_NODE, &show_ipv6_prefix_list_cmd);
  install_element (ENABLE_NODE, &show_ipv6_prefix_list_name_cmd);
  install_element (ENABLE_NODE, &show_ipv6_prefix_list_name_seq_cmd);
  install_element (ENABLE_NODE, &show_ipv6_prefix_list_prefix_cmd);
  install_element (ENABLE_NODE, &show_ipv6_prefix_list_prefix_longer_cmd);
  install_element (ENABLE_NODE, &show_ipv6_prefix_list_prefix_first_match_cmd);
  install_element (ENABLE_NODE, &show_ipv6_prefix_list_summary_cmd);
  install_element (ENABLE_NODE, &show_ipv6_prefix_list_summary_name_cmd);
  install_element (ENABLE_NODE, &show_ipv6_prefix_list_detail_cmd);
  install_element (ENABLE_NODE, &show_ipv6_prefix_list_detail_name_cmd);

  install_element (ENABLE_NODE, &clear_ipv6_prefix_list_cmd);
  install_element (ENABLE_NODE, &clear_ipv6_prefix_list_name_cmd);
  install_element (ENABLE_NODE, &clear_ipv6_prefix_list_name_prefix_cmd);
}
#endif /* HAVE_IPV6 */

void
prefix_list_init ()
{
  prefix_list_init_ipv4 ();
#ifdef HAVE_IPV6
  prefix_list_init_ipv6 ();
#endif /* HAVE_IPV6 */
}

void
prefix_list_reset ()
{
  prefix_list_reset_ipv4 ();
#ifdef HAVE_IPV6
  prefix_list_reset_ipv6 ();
#endif /* HAVE_IPV6 */
}
