/*
 * generic vector interface routine
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

#include "vector.h"
#include "memory.h"

/* For statistics */
int vector_alloc = 0;
int vector_data_alloc = 0;

/* Initialize vector : allocate memory and return vector. */
vector
vector_init (unsigned int size)
{
  vector v = XMALLOC (MTYPE_VECTOR, sizeof (struct _vector));
  vector_alloc++;

  /* allocate at least one slot */
  if (size == 0)
    size = 1;

  v->alloced = size;
  v->max = 0;
  v->index = XMALLOC (MTYPE_VECTOR_INDEX, sizeof (void *) * size);
  vector_data_alloc++;
  bzero (v->index, sizeof (void *) * size);
  return v;
}

void
vector_only_wrapper_free (vector v)
{
  XFREE (MTYPE_VECTOR, v);
  vector_alloc--;
}

void
vector_only_index_free (void *index)
{
  XFREE (MTYPE_VECTOR_INDEX, index);
  vector_data_alloc--;
}

void
vector_free (vector v)
{
  XFREE (MTYPE_VECTOR_INDEX, v->index);
  XFREE (MTYPE_VECTOR, v);
  vector_alloc--;
  vector_data_alloc--;
}

vector
vector_copy (vector v)
{
  unsigned int size;
  vector new = XMALLOC (MTYPE_VECTOR, sizeof (struct _vector));
  vector_alloc++;

  new->max = v->max;
  new->alloced = v->alloced;

  size = sizeof (void *) * (v->alloced);
#ifdef DEBUG
  printf ("vector_copy max [%d] alloc [%d]  size [%d]\n", new->max, new->alloced, size);
#endif /* DEBUG */
  new->index = XMALLOC (MTYPE_VECTOR_INDEX, size);
  vector_data_alloc++;
  bcopy (v->index, new->index, size);

  return new;
}

/* Check assigned index, and if it runs short double index pointer */
void
vector_ensure (vector v, unsigned int num)
{
  if (v->alloced > num)
    return;

  v->index = XREALLOC (MTYPE_VECTOR_INDEX, 
		       v->index, sizeof (void *) * (v->alloced * 2));
  bzero (&v->index[v->alloced], sizeof (void *) * v->alloced);
  v->alloced *= 2;
  
  if (v->alloced <= num) {
    vector_ensure (v, num);
  }
}

/* This function only returns next empty slot index.  It dose not mean
   the slot's index memory is assigned, please call vector_ensure()
   after calling this function. */
int
vector_empty_slot (vector v)
{
  unsigned int i;

  if (v->max == 0)
    return 0;

  for (i = 0; i < v->max; i++) {
    if (v->index[i] == 0) {
      return i;
    }
  }
  return i;
}

/* Set value to the smallest empty slot. */
int
vector_set (vector v, void *val)
{
  unsigned int i;

  i = vector_empty_slot (v);
  vector_ensure (v, i);

  v->index[i] = val;
  if (v->max <= i) {
    v->max = i + 1;
  }
  return i;
}

/* Set value to specified index slot. */
int
vector_set_index (vector v, unsigned int i, void *val)
{
  vector_ensure (v, i);

  v->index[i] = val;
  if (v->max <= i) {
    v->max = i + 1;
  }
  return i;
}

/* Lookup vector, ensure it. */
void *
vector_lookup_index (vector v, unsigned int i)
{
  vector_ensure (v, i);
  return v->index[i];
}

/* Unset value at specified index slot. */
void
vector_unset (vector v, unsigned int i)
{
  if (i >= v->alloced)
    return;

  v->index[i] = NULL;

  if (i + 1 == v->max) {
    v->max--;
    while (v->index[--i] == NULL && v->max-- && i) 
      ;				/* Is this ugly ? */
  }
}

/* Count the number of not emplty slot. */
unsigned int
vector_count (vector v)
{
  unsigned int i;
  unsigned count = 0;

  for (i = 0; i < v->max; i++) {
    if (v->index[i] != NULL)
      count++;
  }
  return count;
}

/* For debug, display  contents of vector */
void
vector_describe (FILE *fp, vector v)
{
  int i;
  
  fprintf (fp, "vecotor max : %d\n", v->max);
  fprintf (fp, "vecotor alloced : %d\n", v->alloced);

  for (i = 0; i < v->max; i++) {
    if (v->index[i] != NULL) {
      fprintf (fp, "vector [%d]: %p\n", i, vector_slot (v, i));
    }
  }
}

#ifdef TEST
#define INTERFACE_INIT_SIZE 1

main ()
{
  int i;
  char kuni[] = "kuni";
  char mio[] = "mio";
  char *p;

  vector ifvec;

  ifvec = vector_init (INTERFACE_INIT_SIZE);

  vector_describe (stdout, ifvec);
  vector_set_index (ifvec, 1023, kuni);

  vector_set_index (ifvec, 1, kuni);
  vector_set_index (ifvec, 2, mio);
  vector_set_index (ifvec, 3, kuni);
  vector_set_index (ifvec, 4, mio);

  vector_unset (ifvec, 1023);

  vector_describe (stdout, ifvec);
  for (i = 0; i <= ifvec->max; i++) {
    if (ifvec->index[i] != NULL) {
      printf ("slot %d: %s\n", i, vector_slot (ifvec, i));
    }
  }
}
#endif /* TEST */
