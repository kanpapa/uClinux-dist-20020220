/* AS path management routines.
 * Copyright (C) 1996, 97, 98, 99 Kunihiro Ishiguro
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
#include "roken.h"
#include "vector.h"
#include "vty.h"
#include "str.h"
#include "log.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_aspath.h"

/* Minimum size of aspath header and AS value. */

/* Attr. Flags and Attr. Type Code. */
#define AS_HEADER_SIZE        2	 

/* Two octet is used for AS value. */
#define AS_VALUE_SIZE         sizeof (as_t)

/* To fetch and store as segment value. */
struct assegment
{
  u_char type;
  u_char length;
  as_t asval[1];
};

/* Hash for aspath.  This is the top level structure of AS path. */
struct Hash *ashash;

static struct aspath *
aspath_new ()
{
  struct aspath *aspath;

  aspath = XMALLOC (MTYPE_AS_PATH, sizeof (struct aspath));
  bzero (aspath, sizeof (struct aspath));
  return aspath;
}

/* Free AS path structure. */
void
aspath_free (struct aspath *aspath)
{
  if (!aspath)
    return;
  if (aspath->data)
    XFREE (MTYPE_AS_SEG, aspath->data);
  if (aspath->str)
    XFREE (MTYPE_AS_STR, aspath->str);
  XFREE (MTYPE_AS_PATH, aspath);
}

/* Unintern aspath from AS path bucket. */
void
aspath_unintern (struct aspath *aspath)
{
  struct aspath *ret;

  if (aspath->refcnt)
    aspath->refcnt--;

  if (aspath->refcnt == 0)
    {
      /* This aspath must exist in aspath hash table. */
      ret = hash_pull (ashash, aspath);
      assert (ret != NULL);
      aspath_free (aspath);
    }
}

/* Return the start or end delimiters for a particular Segment type */
#define AS_SEG_START 0
#define AS_SEG_END 1
static char
aspath_delimiter_char (u_char type, u_char which)
{
  int i;
  struct
  {
    int type;
    char start;
    char end;
  } aspath_delim_char [] =
    {
      { AS_SET,             '{', '}' },
      { AS_SEQUENCE,        ' ', ' ' },
      { AS_CONFED_SET,      '[', ']' },
      { AS_CONFED_SEQUENCE, '(', ')' },
      { 0 }
    };

  for (i = 0; aspath_delim_char[i].type != 0; i++)
    {
      if (aspath_delim_char[i].type == type)
	{
	  if (which == AS_SEG_START)
	    return aspath_delim_char[i].start;
	  else if (which == AS_SEG_END)
	    return aspath_delim_char[i].end;
	}
    }
  return ' ';
}

/* Convert aspath structure to string expression. */
static char *
aspath_make_str_count (struct aspath *as)
{
  int space;
  u_char type;
  caddr_t pnt;
  caddr_t end;
  struct assegment *assegment;
  int str_size = ASPATH_STR_DEFAULT_LEN;
  int str_pnt;
  u_char *str_buf;
  int count = 0;

  /* Empty aspath. */
  if (as->length == 0)
    {
      str_buf = XMALLOC (MTYPE_AS_STR, 1);
      str_buf[0] = '\0';
      as->count = count;
      return str_buf;
    }

  /* Set default value. */
  space = 0;
  type = AS_SEQUENCE;

  /* Set initial pointer. */
  pnt = as->data;
  end = pnt + as->length;

  str_buf = XMALLOC (MTYPE_AS_STR, str_size);
  str_pnt = 0;

  assegment = (struct assegment *) pnt;

  while (pnt < end)
    {
      int i;
      int estimate_len;

      /* For fetch value. */
      assegment = (struct assegment *) pnt;

      /* Check AS type validity. */
      if ((assegment->type != AS_SET) && 
	  (assegment->type != AS_SEQUENCE) &&
	  (assegment->type != AS_CONFED_SET) && 
	  (assegment->type != AS_CONFED_SEQUENCE))
	{
	  XFREE (MTYPE_AS_STR, str_buf);
	  return NULL;
	}

      /* Check AS length. */
      if ((pnt + (assegment->length * AS_VALUE_SIZE) + AS_HEADER_SIZE) > end)
	{
	  XFREE (MTYPE_AS_STR, str_buf);
	  return NULL;
	}

      /* Buffer length check. */
      estimate_len = ((assegment->length * 6) + 4);
      
      /* String length check. */
      while (str_pnt + estimate_len >= str_size)
	{
	  str_size *= 2;
	  str_buf = XREALLOC (MTYPE_AS_STR, str_buf, str_size);
	}

      /* If assegment type is changed, print previous type's end
         character. */
      if (type != AS_SEQUENCE)
	str_buf[str_pnt++] = aspath_delimiter_char (type, AS_SEG_END);
      if (space)
	str_buf[str_pnt++] = ' ';

      if (assegment->type != AS_SEQUENCE)
	str_buf[str_pnt++] = aspath_delimiter_char (assegment->type, AS_SEG_START);

      space = 0;

      /* Increment count - ignoring CONFED SETS/SEQUENCES */
      if(assegment->type != AS_CONFED_SEQUENCE && assegment->type != AS_CONFED_SET)
        {
          count += assegment->length;
        }

      for (i = 0; i < assegment->length; i++)
	{
	  int len;

	  if (space)
	    str_buf[str_pnt++] = ' ';
	  else
	    space = 1;

	  len = sprintf (str_buf + str_pnt, "%d", ntohs (assegment->asval[i]));
	  str_pnt += len;
	}

      type = assegment->type;
      pnt += (assegment->length * AS_VALUE_SIZE) + AS_HEADER_SIZE;
    }

  if (assegment->type != AS_SEQUENCE)
    str_buf[str_pnt++] = aspath_delimiter_char (assegment->type, AS_SEG_END);

  str_buf[str_pnt] = '\0';

  as->count = count;

  return str_buf;
}

/* Intern allocated AS path. */
struct aspath *
aspath_intern (struct aspath *aspath)
{
  struct aspath *find;
  
  /* Assert this AS path structure is not interned. */
  assert (aspath->refcnt == 0);
  assert (aspath->str == NULL);

  /* Check AS path hash. */
  find = hash_search (ashash, aspath);
  if (find)
    {
      aspath_free (aspath);
      find->refcnt++;
      return find;
    }

  /* Push new AS path to AS path hash. */
  aspath->refcnt = 1;
  aspath->str = aspath_make_str_count (aspath);
  hash_push (ashash, aspath);

  return aspath;
}

/* Duplicate aspath structure.  Created same aspath structure but
   reference count and AS path string is cleared. */
struct aspath *
aspath_dup (struct aspath *aspath)
{
  struct aspath *new;

  new = XMALLOC (MTYPE_AS_PATH, sizeof (struct aspath));
  memset (new, 0, sizeof (struct aspath));

  new->length = aspath->length;

  if (new->length)
    {
      new->data = XMALLOC (MTYPE_AS_SEG, aspath->length);
      memcpy (new->data, aspath->data, aspath->length);
    }
  else
    new->data = NULL;

  /* new->str = aspath_make_str_count (aspath); */

  return new;
}

/* AS path parse function.  pnt is a pointer to byte stream and length
   is length of byte stream.  If there is same AS path in the the AS
   path hash then return it else make new AS path structure. */
struct aspath *
aspath_parse (caddr_t pnt, int length)
{
  struct aspath as;
  struct aspath *find;
  struct aspath *aspath;

  /* If length is odd it's malformed AS path. */
  if (length % 2)
    return NULL;

  /* Looking up aspath hash entry. */
  as.data = pnt;
  as.length = length;

  /* If already same aspath exist then return it. */
  find = hash_search (ashash, &as);
  if (find)
    {
      find->refcnt++;
      return find;
    }

  /* New aspath strucutre is needed. */
  aspath = XMALLOC (MTYPE_AS_PATH, sizeof (struct aspath));
  memset ((void *)aspath, 0, sizeof (struct aspath));
  aspath->length = length;

  /* In case of IBGP connection aspath's length can be zero. */
  if (length)
    {
      aspath->data = XMALLOC (MTYPE_AS_SEG, length);
      memcpy (aspath->data, pnt, length);
    }
  else
    aspath->data = NULL;

  /* Make AS path string. */
  aspath->str = aspath_make_str_count (aspath);

  /* Malformed AS path value. */
  if (! aspath->str)
    {
      aspath_free (aspath);
      return NULL;
    }

  /* Reference count set to 1. */
  aspath->refcnt = 1;

  /* Everyting OK, push this AS path to the AS path hash backet. */
  hash_push (ashash, aspath);

  return aspath;
}

/* Merge two AS for aggregation. */
struct aspath *
aspath_aggregate (struct aspath *as1, struct aspath *as2)
{
  caddr_t cp1;
  caddr_t cp2;
  caddr_t end1;
  caddr_t end2;
  int match;

  match = 0;
  cp1 = as1->data;
  end1 = as1->data + as1->length;
  cp2 = as2->data;
  end2 = as2->data + as2->length;

  /* First of all common element search. */
  while ((cp1 < end1) && (cp2 < end2))
    {
      int i;
      int min_len;
      struct assegment *seg1 = (struct assegment *) cp1;
      struct assegment *seg2 = (struct assegment *) cp2;

      if (seg1->type != seg2->type)
	break;

      /* Minimum segment length. */
      min_len = seg1->length;
      if (min_len > seg2->length)
	min_len = seg2->length;

      for (i = 0; i < min_len; i++)
	{
	  if (seg1->asval[i] != seg2->asval[i])
	    {
	      match = i;
	      break;
	    }
	}
      cp1 += ((seg1->length * AS_VALUE_SIZE) + AS_HEADER_SIZE);
      cp2 += ((seg2->length * AS_VALUE_SIZE) + AS_HEADER_SIZE);
    }

  while (cp1 < end1)
    {
      ;
    }

  while (cp2 < end2)
    {
      ;
    }

  return NULL;
}

/* AS path loop check.  If aspath contains asno then return 1. */
int
aspath_loop_check (struct aspath *aspath, as_t asno)
{
  caddr_t pnt;
  caddr_t end;
  struct assegment *assegment;

  if (aspath == NULL)
    return 0;

  pnt = aspath->data;
  end = aspath->data + aspath->length;

  while (pnt < end)
    {
      int i;
      assegment = (struct assegment *) pnt;
      
      for (i = 0; i < assegment->length; i++)
	if (assegment->asval[i] == htons(asno))
	  return 1;

      pnt += (assegment->length * AS_VALUE_SIZE) + AS_HEADER_SIZE;
    }
  return 0;
}

/* Merge as1 to as2.  as2 should be uninterned aspath. */
struct aspath *
aspath_merge (struct aspath *as1, struct aspath *as2)
{
  caddr_t data;

  if (! as1 || ! as2)
    return NULL;

  data = XMALLOC (MTYPE_AS_SEG, as1->length + as2->length);
  memcpy (data, as1->data, as1->length);
  memcpy (data + as1->length, as2->data, as2->length);

  XFREE (MTYPE_AS_SEG, as2->data);
  as2->data = data;
  as2->length += as1->length;
  as2->count += as1->count;
  return as2;
}

/* Prepend as1 to as2.  as2 should be uninterned aspath. */
struct aspath *
aspath_prepend (struct aspath *as1, struct aspath *as2)
{
  caddr_t pnt;
  caddr_t end;
  struct assegment *seg1 = NULL;
  struct assegment *seg2 = NULL;

  if (! as1 || ! as2)
    return NULL;

  seg2 = (struct assegment *) as2->data;

  /* In case of as2 is empty AS. */
  if (seg2 == NULL)
    {
      as2->length = as1->length;
      as2->data = XMALLOC (MTYPE_AS_SEG, as1->length);
      as2->count = as1->count;
      memcpy (as2->data, as1->data, as1->length);
      return as2;
    }

  /* assegment points last segment of as1. */
  pnt = as1->data;
  end = as1->data + as1->length;
  while (pnt < end)
    {
      seg1 = (struct assegment *) pnt;
      pnt += (seg1->length * AS_VALUE_SIZE) + AS_HEADER_SIZE;
    }

  /* In case of as1 is empty AS. */
  if (seg1 == NULL)
    return as2;

  /* Compare last segment type of as1 and first segment type of as2. */
  if (seg1->type != seg2->type)
    return aspath_merge (as1, as2);

  if (seg1->type == AS_SEQUENCE)
    {
      caddr_t newdata;
      struct assegment *seg = NULL;
      
      newdata = XMALLOC (MTYPE_AS_SEG, 
			 as1->length + as2->length - AS_HEADER_SIZE);
      memcpy (newdata, as1->data, as1->length);
      seg = (struct assegment *) (newdata + ((caddr_t)seg1 - as1->data));
      seg->length += seg2->length;
      memcpy (newdata + as1->length, as2->data + AS_HEADER_SIZE,
	      as2->length - AS_HEADER_SIZE);

      XFREE (MTYPE_AS_SEG, as2->data);
      as2->data = newdata;
      as2->length += (as1->length - AS_HEADER_SIZE);
      as2->count += as1->count;

      return as2;
    }
  else
    {
      /* AS_SET merge code is needed at here. */
      return aspath_merge (as1, as2);
    }

  /* Not reached */
}

/* Add specified AS to the leftmost of aspath. */
struct aspath *
aspath_add_left (struct aspath *aspath, as_t asno)
{
  struct assegment *assegment;

  assegment = (struct assegment *) aspath->data;

  /* In case of empty aspath. */
  if (assegment == NULL || assegment->length == 0)
    {
      aspath->length = AS_HEADER_SIZE + AS_VALUE_SIZE;

      if (assegment)
	aspath->data = XREALLOC (MTYPE_AS_SEG, aspath->data, aspath->length);
      else
	aspath->data = XMALLOC (MTYPE_AS_SEG, aspath->length);

      assegment = (struct assegment *) aspath->data;
      assegment->type = AS_SEQUENCE;
      assegment->length = 1;
      assegment->asval[0] = htons (asno);

      return aspath;
    }

  /* First segment is AS_SEQUENCE*/
  if (assegment->type == AS_SEQUENCE)
    {
      caddr_t newdata;
      struct assegment *newsegment;

      newdata = XMALLOC (MTYPE_AS_SEG, aspath->length + AS_VALUE_SIZE);
      newsegment = (struct assegment *) newdata;

      newsegment->type = AS_SEQUENCE;
      newsegment->length = assegment->length + 1;
      newsegment->asval[0] = htons (asno);

      memcpy (newdata + AS_HEADER_SIZE + AS_VALUE_SIZE,
	      aspath->data + AS_HEADER_SIZE, 
	      aspath->length - AS_HEADER_SIZE);

      XFREE (MTYPE_AS_SEG, aspath->data);

      aspath->data = newdata;
      aspath->length += AS_VALUE_SIZE;
    } else {

      /* We need to add an AS_SEQUENCE here */
      caddr_t newdata;
      struct assegment *newsegment;

      newdata = XMALLOC (MTYPE_AS_SEG, aspath->length + AS_VALUE_SIZE + AS_HEADER_SIZE);
      newsegment = (struct assegment *) newdata;

      newsegment->type = AS_SEQUENCE;
      newsegment->length = 1;
      newsegment->asval[0] = htons (asno);

      memcpy (newdata + AS_HEADER_SIZE + AS_VALUE_SIZE,
	      aspath->data,
	      aspath->length);

      XFREE (MTYPE_AS_SEG, aspath->data);

      aspath->data = newdata;
      aspath->length += AS_HEADER_SIZE + AS_VALUE_SIZE;
    }

  return aspath;
}

/* Compare leftmost AS value for MED check.  If as1's leftmost AS and
   as2's leftmost AS is same return 1. */
int
aspath_cmp_left (struct aspath *aspath1, struct aspath *aspath2)
{
  struct assegment *seg1;
  struct assegment *seg2;
  as_t as1;
  as_t as2;

  seg1 = (struct assegment *) aspath1->data;
  seg2 = (struct assegment *) aspath2->data;

  /* Check as1's */
  if (seg1 == NULL || seg1->length == 0 || seg1->type != AS_SEQUENCE)
    return 0;
  as1 = seg1->asval[0];

  if (seg2 == NULL || seg2->length == 0 || seg2->type != AS_SEQUENCE)
    return 0;
  as2 = seg2->asval[0];

  if (as1 == as2)
    return 1;

  return 0;
}

/* Strip the CONFED stuff from the front of an AS Path */
struct aspath *
aspath_strip_confed (struct aspath *aspath)
{
  int bytes;
  struct assegment *assegment;

  assegment = (struct assegment *) aspath->data;

  /* In case of empty aspath, just return. */
  if (assegment == NULL)
    return aspath;

  if (assegment->type != AS_CONFED_SEQUENCE)
    return aspath;

  /* Strip the first element from the path */
  bytes = AS_HEADER_SIZE + (assegment->length * AS_VALUE_SIZE);
  memcpy(aspath->data,
	 aspath->data + bytes,
	 aspath->length - bytes);
  if(aspath->length - bytes == 0)
    {
      XFREE(MTYPE_AS_SEG, aspath->data);
      aspath->data = NULL;
    }
  else
    {
      aspath->data = XREALLOC (MTYPE_AS_SEG, aspath->data, aspath->length - bytes);
    }
  aspath->length -= bytes;
  assegment = (struct assegment *)aspath->data;

  while(assegment && assegment->type == AS_CONFED_SET)
    {
      /* Strip the first element from the path */
      bytes = AS_HEADER_SIZE + (assegment->length * AS_VALUE_SIZE);
      memcpy(aspath->data,
	     aspath->data + bytes,
	     aspath->length - bytes);

      if(aspath->length - bytes == 0)
	{
	  XFREE(MTYPE_AS_SEG, aspath->data);
	  aspath->data = NULL;
	}
      else
	{ 
	  aspath->data = XREALLOC (MTYPE_AS_SEG, aspath->data, aspath->length - bytes);
	}
      aspath->length -= bytes;
      assegment = (struct assegment *)aspath->data;
    }

  return aspath;
}

/* Add specified AS to the leftmost AS_CONFED_SEQUENCE. */
struct aspath *
aspath_add_left_confed (struct aspath *aspath, as_t asno)
{
  struct assegment *assegment;

  assegment = (struct assegment *) aspath->data;

  /* In case of empty aspath. */
  if (assegment == NULL || assegment->length == 0)
    {
      aspath->length = AS_HEADER_SIZE + AS_VALUE_SIZE;

      if (assegment)
	aspath->data = XREALLOC (MTYPE_AS_SEG, aspath->data, aspath->length);
      else
	aspath->data = XMALLOC (MTYPE_AS_SEG, aspath->length);

      assegment = (struct assegment *) aspath->data;
      assegment->type = AS_CONFED_SEQUENCE;
      assegment->length = 1;
      assegment->asval[0] = htons (asno);

      return aspath;
    }

  /* First segment is AS_SEQUENCE*/
  if (assegment->type == AS_CONFED_SEQUENCE)
    {
      caddr_t newdata;
      struct assegment *newsegment;

      newdata = XMALLOC (MTYPE_AS_SEG, aspath->length + AS_VALUE_SIZE);
      newsegment = (struct assegment *) newdata;

      newsegment->type = AS_CONFED_SEQUENCE;
      newsegment->length = assegment->length + 1;
      newsegment->asval[0] = htons (asno);

      memcpy (newdata + AS_HEADER_SIZE + AS_VALUE_SIZE,
	      aspath->data + AS_HEADER_SIZE, 
	      aspath->length - AS_HEADER_SIZE);

      XFREE (MTYPE_AS_SEG, aspath->data);

      aspath->data = newdata;
      aspath->length += AS_VALUE_SIZE;
    }
  else
    {
      /* We need to add an AS_CONFED_SEQUENCE here */
      caddr_t newdata;
      struct assegment *newsegment;

      newdata = XMALLOC (MTYPE_AS_SEG, aspath->length + AS_VALUE_SIZE + AS_HEADER_SIZE);
      newsegment = (struct assegment *) newdata;

      newsegment->type = AS_CONFED_SEQUENCE;
      newsegment->length = 1;
      newsegment->asval[0] = htons (asno);

      memcpy (newdata + AS_HEADER_SIZE + AS_VALUE_SIZE,
	      aspath->data,
	      aspath->length);

      XFREE (MTYPE_AS_SEG, aspath->data);

      aspath->data = newdata;
      aspath->length += AS_HEADER_SIZE + AS_VALUE_SIZE;
    }

  return aspath;
}

/* Add new as value to as path structure. */
void
aspath_as_add (struct aspath *as, as_t asno)
{
  caddr_t pnt;
  caddr_t end;
  struct assegment *assegment;

  /* Increase as->data for new as value. */
  as->data = XREALLOC (MTYPE_AS_SEG, as->data, as->length + 2);
  as->length += 2;

  pnt = as->data;
  end = as->data + as->length;
  assegment = (struct assegment *) pnt;

  /* Last segment search procedure. */
  while (pnt + 2 < end)
    {
      assegment = (struct assegment *) pnt;

      /* We add 2 for segment_type and segment_length and segment
         value assegment->length * 2. */
      pnt += (AS_HEADER_SIZE + (assegment->length * AS_VALUE_SIZE));
    }

  assegment->asval[assegment->length] = htons (asno);
  assegment->length++;
}

/* Add new as segment to the as path. */
void
aspath_segment_add (struct aspath *as, int type)
{
  struct assegment *assegment;

  if (as->data == NULL)
    {
      as->data = XMALLOC (MTYPE_AS_SEG, 2);
      assegment = (struct assegment *) as->data;
      as->length = 2;
    }
  else
    {
      as->data = XREALLOC (MTYPE_AS_SEG, as->data, as->length + 2);
      assegment = (struct assegment *) (as->data + as->length);
      as->length += 2;
    }

  assegment->type = type;
  assegment->length = 0;
}

struct aspath *
aspath_empty ()
{
  return aspath_parse (NULL, 0);
}

/* 
   Theoretically, one as path can have:

   One BGP packet size should be less than 4096.
   One BGP attribute size should be less than 4096 - BGP header size.
   One BGP aspath size should be less than 4096 - BGP header size -
       BGP mandantry attribute size.
*/

/* AS path string lexical token enum. */
enum as_token
{
  as_token_asval,
  as_token_set_start,
  as_token_set_end,
  as_token_confed_start,
  as_token_confed_end,
  as_token_unknown
};

/* Return next token and point for string parse. */
char *
aspath_gettoken (char *buf, enum as_token *token, u_short *asno)
{
  char *p = buf;

  /* Skip space. */
  while (isspace ((int) *p))
    p++;

  /* Check the end of the string and type specify characters
     (e.g. {}()). */
  switch (*p)
    {
    case '\0':
      return NULL;
      break;
    case '{':
      *token = as_token_set_start;
      p++;
      return p;
      break;
    case '}':
      *token = as_token_set_end;
      p++;
      return p;
      break;
    case '(':
      *token = as_token_confed_start;
      p++;
      return p;
      break;
    case ')':
      *token = as_token_confed_end;
      p++;
      return p;
      break;
    }

  /* Check actual AS value. */
  if (isdigit ((int) *p)) 
    {
      u_short asval;

      *token = as_token_asval;
      asval = (*p - '0');
      p++;
      while (isdigit ((int) *p)) 
	{
	  asval *= 10;
	  asval += (*p - '0');
	  p++;
	}
      *asno = asval;
      return p;
    }
  
  /* There is no match then return unknown token. */
  *token = as_token_unknown;
  return  p++;
}

struct aspath *
aspath_str2aspath (char *str)
{
  enum as_token token;
  u_short as_type;
  u_short asno;
  struct aspath *aspath;
  int needtype;

  aspath = aspath_new ();

  /* We start default type as AS_SEQUENCE. */
  as_type = AS_SEQUENCE;
  needtype = 1;

  while ((str = aspath_gettoken (str, &token, &asno)) != NULL)
    {
      switch (token)
	{
	case as_token_asval:
	  if (needtype)
	    {
	      aspath_segment_add (aspath, as_type);
	      needtype = 0;
	    }
	  aspath_as_add (aspath, asno);
	  break;
	case as_token_set_start:
	  as_type = AS_SET;
	  aspath_segment_add (aspath, as_type);
	  needtype = 0;
	  break;
	case as_token_set_end:
	  as_type = AS_SEQUENCE;
	  needtype = 1;
	  break;
	case as_token_confed_start:
	  as_type = AS_CONFED_SEQUENCE;
	  aspath_segment_add (aspath, as_type);
	  needtype = 0;
	  break;
	case as_token_confed_end:
	  as_type = AS_SEQUENCE;
	  needtype = 1;
	  break;
	case as_token_unknown:
	default:
	  return NULL;
	  break;
	}
    }

  aspath->str = aspath_make_str_count (aspath);

  return aspath;
}

/* Make hash value by raw aspath data. */
unsigned int
aspath_key_make (struct aspath *aspath)
{
  unsigned int key = 0;
  int length;
  caddr_t pnt;

  length = aspath->length;
  pnt = aspath->data;

  while (length)
    key += pnt[--length];

  return key %= HASHTABSIZE;
}

/* If two aspath have same value then return 1 else return 0 */
int
aspath_cmp (struct aspath *as1, struct aspath *as2)
{
  if (as1->length == as2->length 
      && !memcmp (as1->data, as2->data, as1->length))
    return 1;
  else
    return 0;
}

/* AS path hash initialize. */
void
aspath_init ()
{
  ashash = hash_new (HASHTABSIZE);
  ashash->hash_key = aspath_key_make;
  ashash->hash_cmp = aspath_cmp;
}

/* return and as path value */
const char *
aspath_print (struct aspath *as)
{
  return as->str;
}

/* Printing functions */
void
aspath_print_vty (struct vty *vty, struct aspath *as)
{
  vty_out (vty, "%s", as->str);
}

/* Print all aspath and hash information.  This function is used from
   `show ip bgp paths' command. */
void
aspath_print_all_vty (struct vty *vty)
{
  int i;
  HashBacket *mp;

  for (i = 0; i < HASHTABSIZE; i++)
    if ((mp = hash_head (ashash, i)) != NULL)
      while (mp) 
	{
	  vty_out (vty, "[%x:%d] (%d) ", 
		   mp, i, ((struct aspath *)mp->data)->refcnt);
	  aspath_print_vty (vty, mp->data);
	  vty_out (vty, "%s", VTY_NEWLINE);
	  mp = mp->next;
	}
}

#ifdef ASPATH_TEST

#include "regex-gnu.h"

/* For test aspath functions. */
void
aspath_test ()
{
  struct aspath *as1;
  struct aspath *as2;
  int ret;

  /* as1 = aspath_empty (); */
  as1 = aspath_str2aspath ("");
  as2 = aspath_str2aspath ("7675 1 2 3");

  printf("%s (%d)\n", aspath_print (as1), as1->count);
  printf("%s (%d)\n", aspath_print (as2), as2->count);

  ret =  aspath_cmp_left (as1, as2);
  printf ("result: %d\n", ret);
}
#endif /* ASPATH_TEST */
