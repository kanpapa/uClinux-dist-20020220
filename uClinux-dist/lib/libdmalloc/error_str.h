/*
 * array of error messages for the malloc internal errors.
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
 * $Id: error_str.h,v 1.1 2000/11/01 01:19:04 pauli Exp $
 */

#ifndef __ERROR_STR_H__
#define __ERROR_STR_H__

#include "error_val.h" 

#define INVALID_ERROR		"errno value is not valid"

typedef struct {
  int		es_error;		/* error number */
  char		*es_string;		/* assocaited string */
} error_str_t;

/* string error codes which apply to error codes in error_val.h */
static	error_str_t	error_list[] = {
  { ERROR_NONE,			"no error" },
  
  /* administrative errors */
  { ERROR_BAD_SETUP,		"initialization and setup failed" },
  { ERROR_IN_TWICE,		"malloc library has gone recursive" },
  { ERROR_BAD_ERRNO,		"errno value from user is out-of-bounds" },
  { ERROR_LOCK_NOT_CONFIG,	"thread locking has not been configured" },
  
  /* pointer verification errors */
  { ERROR_IS_NULL,		"pointer is null" },
  { ERROR_NOT_IN_HEAP,		"pointer is not pointing to heap data space" },
  { ERROR_NOT_FOUND,		"cannot locate pointer in heap" },
  { ERROR_IS_FOUND,		"found pointer the user was looking for" },
  { ERROR_BAD_FILEP,		"possibly bad .c filename pointer" },
  { ERROR_BAD_LINE,		"possibly bad .c file line-number" },
  { ERROR_UNDER_FENCE,	       "failed UNDER picket-fence magic-number check"},
  { ERROR_OVER_FENCE,		"failed OVER picket-fence magic-number check"},
  { ERROR_WOULD_OVERWRITE,	"use of pointer would exceed allocation" },
  { ERROR_IS_FREE,		"pointer is on free list" },
  
  /* allocation errors */
  { ERROR_BAD_SIZE,		"invalid allocation size" },
  { ERROR_TOO_BIG,		"largest maximum allocation size exceeded" },
  { ERROR_USER_NON_CONTIG,	"user allocated space contiguous block error"},
  { ERROR_ALLOC_FAILED,		"could not grow heap by allocating memory" },
  { ERROR_ALLOC_NONLINEAR,	"heap failed to produce linear address space"},
  { ERROR_BAD_SIZE_INFO,	"bad size in information structure" },
  { ERROR_EXTERNAL_HUGE,	"external sbrk too large, cannot be handled" },
  
  /* free errors */
  { ERROR_NOT_ON_BLOCK,	 	"pointer is not on block boundary" },
  { ERROR_ALREADY_FREE,		"tried to free previously freed pointer" },
  { ERROR_NOT_START_USER,	"pointer does not start at user-alloc space" },
  { ERROR_NOT_USER,		"pointer does not point to user-alloc space" },
  { ERROR_BAD_FREE_LIST,	"inconsistency with free linked-list" },
  { ERROR_FREE_NON_CONTIG,	"free space contiguous block error" },
  { ERROR_BAD_FREE_MEM,		"bad basic-block mem pointer in free-list" },
  { ERROR_FREE_NON_BLANK,	"free space has been overwritten" },
  
  /* dblock errors */
  { ERROR_BAD_DBLOCK_SIZE,	"bad divided-block chunk size" },
  { ERROR_BAD_DBLOCK_POINTER,	"bad divided-block pointer" },
  { ERROR_BAD_DBLOCK_MEM,     "bad basic-block mem pointer in dblock struct" },
  { ERROR_BAD_DBADMIN_POINTER,	"bad divided-block admin pointer" },
  { ERROR_BAD_DBADMIN_MAGIC,	"bad divided-block admin magic numbers" },
  { ERROR_BAD_DBADMIN_SLOT,	"bad divided-block chunk admin info struct" },
  
  /* administrative errors */
  { ERROR_BAD_ADMIN_P,		"admin structure pointer out of bounds" },
  { ERROR_BAD_ADMIN_LIST,	"bad admin structure list" },
  { ERROR_BAD_ADMIN_MAGIC,	"bad magic number in admin structure" },
  { ERROR_BAD_ADMIN_COUNT,	"bad basic-block count value in admin struct"},
  { ERROR_BAD_BLOCK_ADMIN_P,	"bad basic-block administration pointer" },
  { ERROR_BAD_BLOCK_ADMIN_C,	"bad basic-block administration counter" },
  
  /* heap check verification */
  { ERROR_BAD_BLOCK_ORDER,	"bad basic-block allocation order" },
  { ERROR_BAD_FLAG,		"basic-block has bad flag value" },
  
  /* memory table errors */
  { ERROR_TABLE_CORRUPT,	"internal memory table corruption" }
};

#endif /* ! __ERROR_STR_H__ */
