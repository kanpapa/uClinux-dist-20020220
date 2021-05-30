/*
 * Debug values for DMALLOC_DEBUG and _dmalloc_flags
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
 * $Id: debug_val.h,v 1.1 2000/11/01 01:19:03 pauli Exp $
 */

#ifndef __DEBUG_VAL_H__
#define __DEBUG_VAL_H__

#include "dmalloc_loc.h"			/* for BIT_FLAG */

/*
 * special debug codes which detail what debug features are enabled
 * NOTE: need to change debug_tok.h, mallocrc, and malloc.texi if any
 * capabilities are added/removed/updated
 */

/* logging */
#define DEBUG_LOG_STATS		BIT_FLAG(0)	/* generally log statistics */
#define DEBUG_LOG_NONFREE	BIT_FLAG(1)	/* report non-freed pointers */
/* 2 available */
#define DEBUG_LOG_TRANS		BIT_FLAG(3)	/* log memory transactions */
/* 4 available */
#define DEBUG_LOG_ADMIN		BIT_FLAG(5)	/* log background admin info */
#define DEBUG_LOG_BLOCKS	BIT_FLAG(6)	/* log blocks when heap-map */
#define DEBUG_LOG_UNKNOWN	BIT_FLAG(7)	/* report unknown non-freed */
#define DEBUG_LOG_BAD_SPACE	BIT_FLAG(8)	/* dump space from bad pnt */
#define DEBUG_LOG_NONFREE_SPACE	BIT_FLAG(9)	/* dump space from non-freed */

#define DEBUG_LOG_ELAPSED_TIME	BIT_FLAG(18)	/* log pnt elapsed time info */
#define DEBUG_LOG_CURRENT_TIME	BIT_FLAG(19)	/* log pnt current time info */

/* checking */
#define DEBUG_CHECK_FENCE	BIT_FLAG(10)	/* check fence-post errors  */
#define DEBUG_CHECK_HEAP	BIT_FLAG(11)	/* examine heap adm structs */
#define DEBUG_CHECK_LISTS	BIT_FLAG(12)	/* check the free lists */
#define DEBUG_CHECK_BLANK	BIT_FLAG(13)	/* check blank sections */
#define DEBUG_CHECK_FUNCS	BIT_FLAG(14)	/* check functions */
/* 15 available */

/* misc */
#define DEBUG_FORCE_LINEAR	BIT_FLAG(16)	/* force linear heap */
#define DEBUG_CATCH_SIGNALS	BIT_FLAG(17)	/* catch HUP, INT, and TERM */
/* 18,19 used above */
#define DEBUG_REALLOC_COPY	BIT_FLAG(20)	/* copy all reallocations */
#define DEBUG_FREE_BLANK	BIT_FLAG(21)	/* write over free'd memory */
#define DEBUG_ERROR_ABORT	BIT_FLAG(22)	/* abort on error else exit */
#define DEBUG_ALLOC_BLANK	BIT_FLAG(23)	/* write over to-be-alloced */
#define DEBUG_HEAP_CHECK_MAP	BIT_FLAG(24)	/* heap-map on heap-check */
#define DEBUG_PRINT_MESSAGES	BIT_FLAG(25)	/* write messages to STDERR */
#define DEBUG_CATCH_NULL	BIT_FLAG(26)	/* quit before return null */
#define DEBUG_NEVER_REUSE	BIT_FLAG(27)	/* never reuse memory */
/* 28 available */
#define DEBUG_ALLOW_FREE_NULL	BIT_FLAG(29)	/* allow free(0)*/
#define DEBUG_ERROR_DUMP	BIT_FLAG(30)	/* dump core on error */
/* 31 is the high bit and off-limits */

/*
 * flags that after being set or not/set at process start-up, cannot
 * be reset.
 *
 * NOTE: CHECK_FENCE _can_ be removed since the pnt_below/above_adm
 * values are never reset in chunk.
 */
#define DEBUG_NOT_CHANGEABLE	(DEBUG_CATCH_SIGNALS)

/*
 * flags that cannot be added after process start-up.
 */
#define DEBUG_NOT_ADDABLE	(DEBUG_CHECK_FENCE | DEBUG_CHECK_BLANK)

#endif /* ! __DEBUG_VAL_H__ */
