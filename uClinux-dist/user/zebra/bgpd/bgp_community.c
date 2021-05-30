/*
 * Community attribute related functions.
 * Copyright (C) 1998 Kunihiro Ishiguro
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

#include "hash.h"
#include "memory.h"
#include "vector.h"
#include "vty.h"
#include "roken.h"
#include "str.h"

#include "bgpd/bgp_community.h"

/* Hash of community attribute. */
struct Hash *comhash;

/* Create new community attribute. */
struct community *
community_parse (char *pnt, u_short length)
{
  struct community tmp;
  struct community *find;
  struct community *new;

  /* If length is malformed return NULL. */
  if (length % 4)
    return NULL;

  /* Make temporary community for hash look up. */
  tmp.size = length / 4;
  tmp.val = (u_int32_t *) pnt;

  /* Looking up hash of community attribute. */
  find = (struct community *) hash_search (comhash, &tmp);
  if (find)
    {
      find->refcnt++;
      return find;
    }

  /* Make new community attribute and intern it into hash. */
  new = XMALLOC (MTYPE_COMMUNITY, sizeof (struct community));

  /* new->refcnt = 1; */
  new->refcnt = 1;
  new->size = length / 4;
  new->val = (u_int32_t *) XMALLOC (MTYPE_COMMUNITY_VAL, length);
  memcpy (new->val, pnt, length);

  hash_push (comhash, new);

  return new;
}

struct community *
community_new ()
{
  struct community *new;

  new = XMALLOC (MTYPE_COMMUNITY, sizeof (struct community));
  bzero (new, sizeof (struct community));
  return new;
}

void
community_free (struct community *com)
{
  if (com->val)
    XFREE (MTYPE_COMMUNITY_VAL, com->val);
  XFREE (MTYPE_COMMUNITY, com);
}

struct community *
community_dup (struct community *com)
{
  struct community *new;

  new = XMALLOC (MTYPE_COMMUNITY, sizeof (struct community));
  bzero (new, sizeof (struct community));
  new->size = com->size;
  if (new->size)
    {
      new->val = XMALLOC (MTYPE_COMMUNITY_VAL, com->size * 4);
      memcpy (new->val, com->val, com->size * 4);
    }
  else
    new->val = NULL;
  return new;
}

struct community *
community_intern (struct community *com)
{
  struct community *find;

  /* Assert this community structure is not interned. */
  assert (com->refcnt == 0);

  /* Lookup community hash. */
  find = (struct community *) hash_search (comhash, com);
  if (find)
    {
      community_free (com);
      find->refcnt++;
      return find;
    }

  /* Push new community to hash bucket. */
  com->refcnt = 1;
  hash_push (comhash, com);
  return com;
}

/* Free community attribute. */
void
community_unintern (struct community *com)
{
  if (com->refcnt)
    com->refcnt--;

  if (com->refcnt == 0)
    {
      struct community *ret;
  
      /* Community value com must exist in hash. */
      ret = (struct community *) hash_pull (comhash, com);
      assert (ret != NULL);

      community_free (com);
    }
}

/* Pretty printing of community.  For debug and logging purpose. */
const char *
community_print (struct community *com)
{
  /* XXX non-re-entrant warning */
  static char buf[BUFSIZ];
  int i;
  u_int32_t comval;
  u_int16_t as;
  u_int16_t val;

  bzero(buf, BUFSIZ);

  for (i = 0; i < com->size; i++) 
    {
      comval = ntohl (com_nthval (com, i));
      switch (comval) 
	{
	case COMMUNITY_NO_EXPORT:
	  strlcat (buf, " no-export", BUFSIZ);
	  break;
	case COMMUNITY_NO_ADVERTISE:
	  strlcat (buf, " no-advertise", BUFSIZ);
	  break;
	case COMMUNITY_LOCAL_AS:
	  strlcat (buf, " local-AS", BUFSIZ);
	  break;
	default:
	  as = (comval >> 16) & 0xFFFF;
	  val = comval & 0xFFFF;
	  snprintf (buf + strlen (buf), BUFSIZ - strlen (buf), 
		    " %d:%d", as, val);
	  break;
	}
    }
  return buf;
}

/* Make hash value of community attribute. This function is used by
   hash package.*/
unsigned int
community_hash_make (struct community *com)
{
  int c;
  unsigned int key;
  unsigned char *pnt;

  key = 0;
  pnt = (unsigned char *)com->val;
  
  for(c = 0; c < com->size * 4; c++)
    key += pnt[c];
      
  return key %= HASHTABSIZE;
}

int
community_match (struct community *com1, struct community *com2)
{
  int i;

  if (com1->size < com2->size)
    return 0;

  for (i = 0; i <= com1->size - com2->size; i++)
    if (memcmp (com1->val + i, com2->val, com2->size * 4) == 0)
      return 1;
  return 0;
}

int
community_include (struct community *com, u_int32_t val)
{
  int i;

  for (i = 0; i < com->size; i++)
    if (com_nthval (com, i) == ntohl (val))
      return 1;
  return 0;
}

/* If two aspath have same value then return 1 else return 0. This
   function is used by hash package. */
int
community_cmp (struct community *com1, struct community *com2)
{
  if (com1->size == com2->size)
    if (memcmp (com1->val, com2->val, com1->size * 4) == 0)
      return 1;
  return 0;
}

/* Add com2 to the end of com1. */
struct community *
community_merge (struct community *com1, struct community *com2)
{
  if (com1->val)
    com1->val = XREALLOC (MTYPE_COMMUNITY_VAL, com1->val, 
			  (com1->size + com2->size) * 4);
  else
    com1->val = XMALLOC (MTYPE_COMMUNITY_VAL, (com1->size + com2->size) * 4);

  memcpy (com1->val + com1->size, com2->val, com2->size * 4);
  com1->size += com2->size;

  return com1;
}

/* Initialize comminity related hash. */
void
community_init ()
{
  comhash = hash_new (HASHTABSIZE);
  comhash->hash_key = community_hash_make;
  comhash->hash_cmp = community_cmp;
}

/* Below is vty related function which needs some header include. */

/* Pretty printing of community attribute. */
void
community_print_vty (struct vty *vty, struct community *com)
{
  int i;
  u_int32_t comval;
  u_int16_t as;
  u_int16_t val;

  for (i = 0; i < com->size; i++) 
    {
      comval = ntohl (com_nthval (com, i));
      switch (comval) 
	{
	case COMMUNITY_NO_EXPORT:
	  vty_out (vty, " no-export");
	  break;
	case COMMUNITY_NO_ADVERTISE:
	  vty_out (vty, " no-advertise");
	  break;
	case COMMUNITY_LOCAL_AS:
	  vty_out (vty, " local-AS");
	  break;
	default:
	  as = (comval >> 16) & 0xFFFF ;
	  val = comval & 0xFFFF;
	  vty_out (vty, " %d:%d", as, val);
	  break;
	}
    }
}

/* For `show ip bgp community' command. */
void
community_print_all_vty (struct vty *vty)
{
  int i;
  HashBacket *mp;

  for (i = 0; i < HASHTABSIZE; i++)
    if ((mp = (HashBacket *) hash_head (comhash, i)) != NULL)
      while (mp) 
	{
	  struct community *com;

	  com = (struct community *) mp->data;

	  vty_out (vty, "[%x:%d] (%d)", mp, i, com->refcnt);
	  community_print_vty (vty, com);
	  vty_out (vty, "%s", VTY_NEWLINE);
	  mp = mp->next;
	}
}

/* Community token enum. */
enum community_token
{
  community_token_val,
  community_token_no_export,
  community_token_no_advertise,
  community_token_local_as,
  community_token_unknown
};

/* Get next community token from string. */
u_char *
community_gettoken (char *buf, enum community_token *token, u_int32_t *val)
{
  char *p = buf;

  /* Skip white space. */
  while (isspace ((int) *p))
    p++;

  /* Check the end of the line. */
  if (*p == '\0')
    return NULL;

  /* Well known community string check. */
  if (isalpha ((int) *p)) 
    {
      if (strncmp (p, "no-export", strlen ("no-export")) == 0)
	{
	  *val = COMMUNITY_NO_EXPORT;
	  *token = community_token_no_export;
	  p += strlen ("no-export");
	  return p;
	}
      if (strncmp (p, "no-advertise", strlen ("no-advertise")) == 0)
	{
	  *val = COMMUNITY_NO_ADVERTISE;
	  *token = community_token_no_advertise;
	  p += strlen ("no-advertise");
	  return p;
	}
      if (strncmp (p, "local-AS", strlen ("local-AS")) == 0)
	{
	  *val = COMMUNITY_LOCAL_AS;
	  *token = community_token_local_as;
	  p += strlen ("local-AS");
	  return p;
	}

      /* Unknown string. */
      *token = community_token_unknown;
      return p;
    }

  /* Community value. */
  if (isdigit ((int) *p)) 
    {
      int separator = 0;
      u_int32_t community_low = 0;
      u_int32_t community_high = 0;

      while (isdigit ((int) *p) || *p == ':') 
	{
	  if (*p == ':') 
	    {
	      if (separator)
		{
		  *token = community_token_unknown;
		  return p;
		}
	      else
		{
		  separator = 1;
		  community_high = community_low << 16;
		  community_low = 0;
		}
	    }
	  else 
	    {
	      community_low *= 10;
	      community_low += (*p - '0');
	    }
	  p++;
	}
      *val = community_high + community_low;
      *token = community_token_val;
      return p;
    }
  *token = community_token_unknown;
  return p;
}

/* Add one community value to the community. */
void
community_add_val (struct community *com, u_int32_t val)
{
  com->size++;
  if (com->val)
    com->val = XREALLOC (MTYPE_COMMUNITY_VAL, com->val, com_length (com));
  else
    com->val = XMALLOC (MTYPE_COMMUNITY_VAL, com_length (com));
  com_lastval (com) = htonl (val);
}

/* convert string to community structure */
struct community *
community_str2com (char *str)
{
  struct community *com = NULL;
  u_int32_t val;
  enum community_token token;

  while ((str = community_gettoken (str, &token, &val))) 
    {
      switch (token)
	{
	case community_token_val:
	case community_token_no_export:
	case community_token_no_advertise:
	case community_token_local_as:
	  if (com == NULL)
	    com = community_new();
	  community_add_val (com, val);
	  break;
	case community_token_unknown:
	default:
	  if (com)
	    community_free (com);
	  return NULL;
	  break;
	}
    }
  return com;
}

void
community_test ()
{
  struct community *com1;
  struct community *com2;

  com1 = community_str2com ("no-export local-AS 7675:1");
  com2 = community_str2com ("3651:1 2");
  community_merge (com1, com2);
  printf ("%s\n", community_print (com1));
}
