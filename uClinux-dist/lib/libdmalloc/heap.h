/*
 * defines for the system specific memory routines
 *
 * Copyright 2000 by Gray Watson
 *
 * This file is part of the dmalloc package.
 *
 * Permission to use, copy, modify, and distribute this software for
 * any purpose and without fee is hereby granted, provided that the
 * above copyright notice and this permission notice appear in all
 * copies, and that the name of Gray Watson not be used in advertising
 * or publicity pertaining to distribution of the document or software
 * without specific, written prior permission.
 *
 * Gray Watson makes no representations about the suitability of the
 * software described herein for any purpose.  It is provided "as is"
 * without express or implied warranty.
 *
 * The author may be contacted via http://dmalloc.com/
 *
 * $Id: heap.h,v 1.1 2000/11/01 01:19:04 pauli Exp $
 */

#ifndef __HEAP_H__
#define __HEAP_H__

#include "dmalloc_loc.h"			/* for LOCAL and BLOCK_SIZE */

/*
 * error code returned by heap allocation routine
 */
#define HEAP_ALLOC_ERROR	0L

/*
 * probably machine specific defines used for certain calculations
 */
#if HEAP_GROWS_UP

/* test whether pointer PNT is in the heap space */
#define IS_IN_HEAP(pnt)		\
  ((char *)(pnt) >= (char *)_heap_base && (char *)(pnt) < (char *)_heap_last)

/* turn pointer PNT into a block index */
#define WHICH_BLOCK(pnt)	\
  (((char *)(pnt) - (char *)_heap_base) / BLOCK_SIZE)

/* get a pointer to the memory block number BLOCKN */
#define BLOCK_POINTER(block_n)	((char *)_heap_base + (block_n) * BLOCK_SIZE)

/* test whether pointer PNT is on a block boundary */
#define ON_BLOCK(pnt)		\
  (((char *)(pnt) - (char *)_heap_base) % BLOCK_SIZE == 0)

/* calculate the size of heap */
#define HEAP_SIZE	((char *)_heap_last - (char *)_heap_base)

/* how many blocks between the BEFORE pointer and the NOW pointer */
#define BLOCKS_BETWEEN(now, before)	(((char *)now - (char *)before) / \
					 BLOCK_SIZE)

/* is the heap growing?  is the NEW pointer ahead of the OLD */
#define IS_GROWTH(new, old)	((char *)(new) > (char *)(old))

/* increment the heap point PNT by SIZE */
#define HEAP_INCR(pnt, size)	((char *)(pnt) + (size))

/* round the pointer to the block pointer */
#define BLOCK_ROUND(pnt)	((char *)(pnt) - \
				 ((unsigned long)(pnt) % BLOCK_SIZE))

#else /* ! HEAP_GROWS_UP */

/* test whether pointer PNT is in the heap space */
#define IS_IN_HEAP(pnt)		\
  ((char *)(pnt) <= (char *)_heap_base && (char *)(pnt) > (char *)_heap_last)

/* turn pointer PNT into a block index */
#define WHICH_BLOCK(pnt)		\
  (((char *)(_heap_base) - (char *)pnt) / BLOCK_SIZE)

/* get a pointer to the memory block number BLOCKN */
#define BLOCK_POINTER(block_n)	((char *)_heap_base - (block_n) * BLOCK_SIZE)

/* test whether pointer P is on a block boundary */
#define ON_BLOCK(pnt)		\
  (((char *)(_heap_base) - (char *)(pnt)) % BLOCK_SIZE == 0)

/* is the heap growing?  is the NEW pointer ahead of the OLD */
#define HEAP_SIZE	((char *)_heap_base - (char *)_heap_last)

/* how many blocks between the BEFORE pointer and the NOW pointer */
#define BLOCKS_BETWEEN(now, before)	(((char *)before - (char *)now) / \
					 BLOCK_SIZE)

/* is the heap growing? */
#define IS_GROWTH(new, old)	((char *)(new) < (char *)(old))

/* increment the heap point PNT by SIZE */
#define HEAP_INCR(pnt, size)	((char *)(pnt) - (size))

/* round the pointer to the block pointer */
#define BLOCK_ROUND(pnt)	((char *)(pnt) + \
				 ((unsigned long)(pnt) % BLOCK_SIZE))

#endif /* ! HEAP_GROWS_UP */

/*<<<<<<<<<<  The below prototypes are auto-generated by fillproto */

extern
void	*_heap_base;			/* base of our heap */

extern
void	*_heap_last;			/* end of our heap */

/*
 * int _heap_startup
 *
 * DESCRIPTION:
 *
 * Initialize heap pointers.
 *
 * RETURNS:
 *
 * Success - 1
 *
 * Failure - 0
 *
 * ARGUMENTS:
 *
 * None.
 */
extern
int	_heap_startup(void);

/*
 * Function to get SIZE memory bytes from the end of the heap.  it
 * returns a pointer to any external blocks in EXTERN_P and the number
 * of blocks in EXTERN_CP.
 */
extern
void	*_heap_alloc(const unsigned int size, void **extern_p,
		     int *extern_cp);

/*<<<<<<<<<<   This is end of the auto-generated output from fillproto. */

#endif /* ! __HEAP_H__ */
