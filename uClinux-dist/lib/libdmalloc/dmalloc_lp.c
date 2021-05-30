/*
 * Leap-frog point to allow dmalloc on/off via relink.
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
 * $Id: dmalloc_lp.c,v 1.1 2000/11/01 01:19:04 pauli Exp $
 */

/*
 * If anyone can think of a better way to do this *please* let me
 * know.
 *
 * The goal of the routines in this file is to allow people to use the
 * debug library during development by including the dmalloc.h file in
 * their C source files, and then disable and return to the system (or
 * more efficient) malloc functions easily.
 *
 * The dmalloc.h file provides the library with file/line information
 * with each call.  Backtracing the stack-frame is neither portable or
 * necessarily easy so the cpp __FILE__ and __LINE__ directives are
 * used instead to do this.
 *
 * dmalloc.h contains macros which override the malloc, calloc, free,
 * etc. functions so that they call _malloc_leap passing the file and
 * line information to these routines.  But we need to provide a
 * "quick-release" functionality so that people will not have to
 * remove the dmalloc.h includes and recompile to use other malloc
 * libraries.
 *
 * I have decided on the leap-frog routines in this file that will have
 * to *always* be compiled in if you include dmalloc.h in your source.
 * When your source wants to call malloc, it will first make a call to
 * _malloc_leap which will in turn call the malloc of your choice.
 * This does mean that an extra function call per memory interaction
 * will occur, but on most systems this is reasonably cheap.  To fully
 * disable the library, you will need to remove the dmalloc.h include
 * and recompile your source files.
 *
 * Please mail me with any reasonable ideas.
 */

#include <stdio.h>				/* for sprintf */

#if HAVE_STDARG_H
# include <stdarg.h>				/* for ... */
#endif
#if HAVE_STRING_H
# include <string.h>				/* for strlen, strcpy */
#endif
#if HAVE_UNISTD_H
# include <unistd.h>				/* for write */
#endif

#define DMALLOC_DISABLE

#include "dmalloc.h"				/* for DMALLOC_SIZE... */
#include "conf.h"				/* for const */

#include "error_val.h"
#include "dmalloc_loc.h"
#include "dmalloc_lp.h"
#if USE_DMALLOC_LEAP == 0
#include "malloc.h"				/* for _loc_[m]alloc funcs */
#include "error.h"				/* for dmalloc_vmessage */
#endif
#include "return.h"

#if INCLUDE_RCS_IDS
#ifdef __GNUC__
#ident "$Id: dmalloc_lp.c,v 1.1 2000/11/01 01:19:04 pauli Exp $";
#else
static	char	*rcs_id =
  "$Id: dmalloc_lp.c,v 1.1 2000/11/01 01:19:04 pauli Exp $";
#endif
#endif

/*
 * exported variables
 */
/* internal dmalloc error number for reference purposes only */
int	dmalloc_errno = ERROR_NONE;

/* pre-set dmalloc_debug() value before the library is setup */
int	_dmalloc_debug_preset = DEBUG_PRE_NONE;

#if USE_DMALLOC_LEAP
/* pointers to shutdown function to allow calls without linked routine */
dmalloc_shutdown_func_t		_dmalloc_shutdown_func = NULL;

/* pointers to the standard malloc function */
dmalloc_malloc_func_t		_dmalloc_malloc_func = NULL;

/* pointers to the standard realloc function */
dmalloc_realloc_func_t		_dmalloc_realloc_func = NULL;

/* pointers to the standard free function */
dmalloc_free_func_t		_dmalloc_free_func = NULL;

/* pointers to log_heap_map function to allow calls without linked routine */
dmalloc_log_heap_map_func_t	_dmalloc_log_heap_map_func = NULL;

/* pointers to log_stats function to allow calls without linked routine */
dmalloc_log_stats_func_t	_dmalloc_log_stats_func = NULL;

/* pointers to log_unfreed function to allow calls without linked routine */
dmalloc_log_unfreed_func_t	_dmalloc_log_unfreed_func = NULL;

/* pointers to verify function to allow calls without linked routine */
dmalloc_verify_func_t		_dmalloc_verify_func = NULL;

/* pointers to debug function to allow calls without linked routine */
dmalloc_debug_func_t		_dmalloc_debug_func = NULL;

/* pointers to debug_current function to allow calls without linked routine */
dmalloc_debug_current_func_t	_dmalloc_debug_current_func = NULL;

/* pointers to examine function to allow calls without linked routine */
dmalloc_examine_func_t		_dmalloc_examine_func = NULL;

/* pointers to message function to allow calls without linked routine */
dmalloc_vmessage_func_t		_dmalloc_vmessage_func = NULL;

/* pointers to track function to allow calls without linked routine */
dmalloc_track_func_t		_dmalloc_track_func = NULL;

/* pointers to track function to allow calls without linked routine */
dmalloc_mark_func_t		_dmalloc_mark_func = NULL;

/* pointers to track function to allow calls without linked routine */
dmalloc_log__func_t		_dmalloc_mark_func = NULL;

/* pointers to strerror function to allow calls without linked routine */
dmalloc_strerror_func_t		_dmalloc_strerror_func = NULL;
#endif

#undef malloc
/*
 * leap routine to malloc
 */
DMALLOC_PNT	_malloc_leap(const char *file, const int line,
			     DMALLOC_SIZE size)
{
  void	*ret;
  
#if USE_DMALLOC_LEAP
  if (_dmalloc_malloc_func == NULL) {
    ret = malloc(size);
  }
  else {
    ret = _dmalloc_malloc_func(file, line, size, DMALLOC_FUNC_MALLOC, 0);
  }
#else
  ret = _loc_malloc(file, line, size, DMALLOC_FUNC_MALLOC, 0);
#endif
  
  return ret;
}

#undef calloc
/*
 * leap routine to calloc
 */
DMALLOC_PNT	_calloc_leap(const char *file, const int line,
			     DMALLOC_SIZE ele_n, DMALLOC_SIZE size)
{
  DMALLOC_SIZE	len;
  void		*ret;
  
  len = ele_n * size;
  
#if USE_DMALLOC_LEAP
  if (_dmalloc_malloc_func == NULL) {
    ret = calloc(ele_n, size);
  }
  else {
    ret = _dmalloc_malloc_func(file, line, len, DMALLOC_FUNC_CALLOC, 0);
  }
#else
  ret = _loc_malloc(file, line, len, DMALLOC_FUNC_CALLOC, 0);
#endif
  
  return ret;
}

#undef realloc
/*
 * leap routine to realloc
 */
DMALLOC_PNT	_realloc_leap(const char *file, const int line,
			      DMALLOC_PNT old_p, DMALLOC_SIZE new_size)
{
  void	*ret;
  
#if USE_DMALLOC_LEAP
  if (_dmalloc_realloc_func == NULL) {
    ret = realloc(old_p, new_size);
  }
  else {
    ret = _dmalloc_realloc_func(file, line, old_p, new_size,
				DMALLOC_FUNC_REALLOC);
  }
#else
  ret = _loc_realloc(file, line, old_p, new_size, DMALLOC_FUNC_REALLOC);
#endif
  
  return ret;
}

#undef recalloc
/*
 * leap routine to recalloc
 */
DMALLOC_PNT	_recalloc_leap(const char *file, const int line,
			       DMALLOC_PNT old_p, DMALLOC_SIZE new_size)
{
  void	*ret;
  
#if USE_DMALLOC_LEAP
  if (_dmalloc_realloc_func == NULL) {
#if HAVE_RECALLOC
    ret = recalloc(old_p, new_size);
#else
    ret = REALLOC_ERROR;
#endif
  }
  else {
    ret = _dmalloc_realloc_func(file, line, old_p, new_size,
				DMALLOC_FUNC_RECALLOC);
  }
#else
  ret = _loc_realloc(file, line, old_p, new_size, DMALLOC_FUNC_RECALLOC);
#endif
  
  return ret;
}

#undef memalign
/*
 * leap routine to memalign
 */
DMALLOC_PNT	_memalign_leap(const char *file, const int line,
			       DMALLOC_SIZE alignment, DMALLOC_SIZE size)
{
  void		*ret;
  
#if USE_DMALLOC_LEAP
  if (_dmalloc_malloc_func == NULL) {
#if HAVE_MEMALIGN
    ret = memalign(alignment, size);
#else
    ret = MALLOC_ERROR;
#endif
  }
  else {
    ret = _dmalloc_malloc_func(file, line, size, DMALLOC_FUNC_MEMALIGN,
			       alignment);
  }
#else
  ret = _loc_malloc(file, line, size, DMALLOC_FUNC_MEMALIGN, alignment);
#endif
  
  return ret;
}

#undef valloc
/*
 * leap routine to valloc
 */
DMALLOC_PNT	_valloc_leap(const char *file, const int line,
			     DMALLOC_SIZE size)
{
  void	*ret;
  
#if USE_DMALLOC_LEAP
  if (_dmalloc_malloc_func == NULL) {
#if HAVE_VALLOC
    ret = valloc(size);
#else
    ret = MALLOC_ERROR;
#endif
  }
  else {
    ret = _dmalloc_malloc_func(file, line, size, DMALLOC_FUNC_VALLOC,
			       BLOCK_SIZE);
  }
#else
  ret = _loc_malloc(file, line, size, DMALLOC_FUNC_VALLOC, BLOCK_SIZE);
#endif
  
  return ret;
}

#undef strdup
/*
 * leap routine to strdup
 */
char	*_strdup_leap(const char *file, const int line, const char *str)
{
  int	len;
  char	*buf;
  
  /* len + \0 */
  len = strlen(str) + 1;
  
  buf = (char *)_malloc_leap(file, line, len);
  if (buf != NULL) {
    (void)strcpy(buf, str);
  }
  
  return buf;
}

#undef free
/*
 * leap routine to free
 */
DMALLOC_FREE_RET	_free_leap(const char *file, const int line,
				   DMALLOC_PNT pnt)
{
  int	ret = FREE_NOERROR;
  
#if USE_DMALLOC_LEAP
  if (_dmalloc_free_func == NULL) {
#if (defined(__STDC__) && __STDC__ == 1) || defined(__cplusplus)
    free(pnt);
#else
    ret = free(pnt);
#endif
  }
  else {
    ret = _dmalloc_free_func(file, line, pnt);
  }
#else
  ret = _loc_free(file, line, pnt);
#endif
  
#if (defined(__STDC__) && __STDC__ == 1) || defined(__cplusplus)
#else
  return ret;
#endif
}

/***************************** xmalloc functions *****************************/

/*
 * leap routine to malloc with error checking
 */
DMALLOC_PNT	_xmalloc_leap(const char *file, const int line,
			      DMALLOC_SIZE size)
{
  void	*ret;
  
  ret = _malloc_leap(file, line, size);
  if (ret == NULL) {
    char	mess[256];
    (void)sprintf(mess,
		  "Out of memory while malloc-ing %d bytes from '%s:%d'\n",
		  size, file, line);
    (void)write(STDERR, mess, strlen(mess));
    _exit(1);
  }
  
  return ret;
}

/*
 * leap routine to calloc with error checking
 */
DMALLOC_PNT	_xcalloc_leap(const char *file, const int line,
			      DMALLOC_SIZE ele_n, DMALLOC_SIZE size)
{
  void	*ret;
  
  ret = _calloc_leap(file, line, ele_n, size);
  if (ret == NULL) {
    char	mess[256];
    (void)sprintf(mess,
		  "Out of memory while calloc-ing %d bytes from '%s:%d'\n",
		  size, file, line);
    (void)write(STDERR, mess, strlen(mess));
    _exit(1);
  }
  
  return ret;
}

/*
 * leap routine to realloc with error checking
 */
DMALLOC_PNT	_xrealloc_leap(const char *file, const int line,
			       DMALLOC_PNT old_p, DMALLOC_SIZE new_size)
{
  void	*ret;
  
  ret = _realloc_leap(file, line, old_p, new_size);
  if (ret == NULL) {
    char	mess[256];
    (void)sprintf(mess,
		  "Out of memory while realloc-ing %d bytes from '%s:%d'\n",
		  new_size, file, line);
    (void)write(STDERR, mess, strlen(mess));
    _exit(1);
  }
  
  return ret;
}

/*
 * leap routine to recalloc with error checking
 */
DMALLOC_PNT	_xrecalloc_leap(const char *file, const int line,
				DMALLOC_PNT old_p, DMALLOC_SIZE new_size)
{
  void	*ret;
  
  ret = _recalloc_leap(file, line, old_p, new_size);
  if (ret == NULL) {
    char	mess[256];
    (void)sprintf(mess,
		  "Out of memory while recalloc-ing %d bytes from '%s:%d'\n",
		  new_size, file, line);
    (void)write(STDERR, mess, strlen(mess));
    _exit(1);
  }
  
  return ret;
}

/*
 * leap routine to memalign with error checking
 */
DMALLOC_PNT	_xmemalign_leap(const char *file, const int line,
				DMALLOC_SIZE alignment, DMALLOC_SIZE size)
{
  void	*ret;
  
  ret = _memalign_leap(file, line, alignment, size);
  if (ret == NULL) {
    char	mess[256];
    (void)sprintf(mess,
		  "Out of memory while memalign-ing %d bytes from '%s:%d'\n",
		  size, file, line);
    (void)write(STDERR, mess, strlen(mess));
    _exit(1);
  }
  
  return ret;
}

/*
 * leap routine to valloc with error checking
 */
DMALLOC_PNT	_xvalloc_leap(const char *file, const int line,
			      DMALLOC_SIZE size)
{
  void	*ret;
  
  ret = _valloc_leap(file, line, size);
  if (ret == NULL) {
    char	mess[256];
    (void)sprintf(mess,
		  "Out of memory while valloc-ing %d bytes from '%s:%d'\n",
		  size, file, line);
    (void)write(STDERR, mess, strlen(mess));
    _exit(1);
  }
  
  return ret;
}

/*
 * leap routine for strdup with error checking
 */
char 	*_xstrdup_leap(const char *file, const int line,
		       const char *str)
{
  char 	*buf;
  int	len;
  
  /* len + \0 */
  len = strlen(str) + 1;
  
  buf = (char *)_malloc_leap(file, line, len);
  if (buf == NULL) {
    char	mess[256];
    (void)sprintf(mess,
		  "Out of memory while strdup-ing %d bytes from '%s:%d'\n",
		  len, file, line);
    (void)write(STDERR, mess, strlen(mess));
    _exit(1);
  }
  
  (void)strcpy(buf, str);
  
  return buf;
}

/*
 * leap routine to free
 */
DMALLOC_FREE_RET	_xfree_leap(const char *file, const int line,
				    DMALLOC_PNT pnt)
{
#if (defined(__STDC__) && __STDC__ == 1) || defined(__cplusplus)
  _free_leap(file, line, pnt);
#else
  return _free_leap(file, line, pnt);
#endif
}

/*********************** routines when running dmalloc ***********************/

/*
 * routine to call dmalloc_shutdown when linked in
 */
void	dmalloc_shutdown(void)
{
#if USE_DMALLOC_LEAP
  if (_dmalloc_shutdown_func != NULL) {
    _dmalloc_shutdown_func();
  }
#else
  _dmalloc_shutdown();
#endif
}

/*
 * routine to call dmalloc_log_heap_map when linked in
 */
void	dmalloc_log_heap_map(void)
{
  char	*file;
  
  GET_RET_ADDR(file);
  
#if USE_DMALLOC_LEAP
  if (_dmalloc_log_heap_map_func != NULL) {
    _dmalloc_log_heap_map_func(file, DMALLOC_DEFAULT_LINE);
  }
#else
  _dmalloc_log_heap_map(file, DMALLOC_DEFAULT_LINE);
#endif
}

/*
 * routine to call dmalloc_log_stats when linked in
 */
void	dmalloc_log_stats(void)
{
  char	*file;
  
  GET_RET_ADDR(file);
  
#if USE_DMALLOC_LEAP
  if (_dmalloc_log_stats_func != NULL) {
    _dmalloc_log_stats_func(file, DMALLOC_DEFAULT_LINE);
  }
#else
  _dmalloc_log_stats(file, DMALLOC_DEFAULT_LINE);
#endif
}

/*
 * routine to call dmalloc_log_unfreed when linked in
 */
void	dmalloc_log_unfreed(void)
{
  char	*file;
  
  GET_RET_ADDR(file);
  
#if USE_DMALLOC_LEAP
  if (_dmalloc_log_unfreed_func != NULL) {
    _dmalloc_log_unfreed_func(file, DMALLOC_DEFAULT_LINE);
  }
#else
  _dmalloc_log_unfreed(file, DMALLOC_DEFAULT_LINE);
#endif
}

/*
 * routine to call dmalloc_verify when linked in
 */
int	dmalloc_verify(const DMALLOC_PNT pnt)
{
#if USE_DMALLOC_LEAP
  if (_dmalloc_verify_func == NULL) {
    return DMALLOC_VERIFY_NOERROR;
  }
  else {
    return _dmalloc_verify_func(pnt);
  }
#else
  return _dmalloc_verify(pnt);
#endif
}

/*
 * routine to call malloc_verify when linked in
 */
int	malloc_verify(const DMALLOC_PNT pnt)
{
#if USE_DMALLOC_LEAP
  if (_dmalloc_verify_func == NULL) {
    return DMALLOC_VERIFY_NOERROR;
  }
  else {
    return _dmalloc_verify_func(pnt);
  }
#else
  return _dmalloc_verify(pnt);
#endif
}

/*
 * routine to call dmalloc_debug when linked in
 */
void	dmalloc_debug(const int flags)
{
#if USE_DMALLOC_LEAP
  if (_dmalloc_debug_func == NULL) {
    _dmalloc_debug_preset = flags;
  }
  else {
    _dmalloc_debug_func(flags);
  }
#else
  _dmalloc_debug(flags);
#endif
}

/*
 * routine to call dmalloc_debug_current when linked in
 */
int	dmalloc_debug_current(void)
{
#if USE_DMALLOC_LEAP
  if (_dmalloc_debug_current_func == NULL) {
    return 0;
  }
  else {
    return _dmalloc_debug_current_func();
  }
#else
  return _dmalloc_debug_current();
#endif
}

/*
 * routine to call dmalloc_examine when linked in
 */
int	dmalloc_examine(const DMALLOC_PNT pnt, DMALLOC_SIZE *size_p,
			char **file_p, unsigned int *line_p,
			DMALLOC_PNT *ret_attr_p)
{
  char	*file;
  
  GET_RET_ADDR(file);
  
#if USE_DMALLOC_LEAP
  if (_dmalloc_examine_func == NULL) {
    return ERROR;
  }
  else {
    return _dmalloc_examine_func(file, DMALLOC_DEFAULT_LINE, pnt, size_p,
				 file_p, line_p, ret_attr_p);
  }
#else
  return _dmalloc_examine(file, DMALLOC_DEFAULT_LINE, pnt, size_p,
			  file_p, line_p, ret_attr_p);
#endif
}

#if HAVE_STDARG_H
/*
 * routine to call dmalloc_vmessage when linked in
 */
void	dmalloc_message(const char *format, ...)
{
  va_list	args;
  
  va_start(args, format);
#if USE_DMALLOC_LEAP
  if (_dmalloc_vmessage_func != NULL) {
    _dmalloc_vmessage_func(format, args);
  }
#else
  _dmalloc_vmessage(format, args);
#endif
  va_end(args);
}

/*
 * routine to call dmalloc_vmessage when linked in
 */
void	dmalloc_vmessage(const char *format, va_list args)
{
#if USE_DMALLOC_LEAP
  if (_dmalloc_vmessage_func != NULL) {
    _dmalloc_vmessage_func(format, args);
  }
#else
  _dmalloc_vmessage(format, args);
#endif
}
#endif

/*
 * routine to call dmalloc_track when linked in
 */
void	dmalloc_track(const dmalloc_track_t track_func)
{
#if USE_DMALLOC_LEAP
  if (_dmalloc_track_func != NULL) {
    _dmalloc_track_func(track_func);
  }
#else
  _dmalloc_track(track_func);
#endif
}

/*
 * routine to call dmalloc_mark when linked in
 */
unsigned long	dmalloc_mark(void)
{
#if USE_DMALLOC_LEAP
  if (_dmalloc_mark_func != NULL) {
    return _dmalloc_mark_func();
  }
  else {
    return 0;
  }
#else
  return _dmalloc_mark();
#endif
}

/*
 * routine to call dmalloc_log_changed when linked in
 */
void	dmalloc_log_changed(const unsigned long mark, const int not_freed_b,
			    const int free_b, const int details_b)
{
  char	*file;
  
  GET_RET_ADDR(file);
  
#if USE_DMALLOC_LEAP
  if (_dmalloc_mark_func != NULL) {
    _dmalloc_log_changed(file, DMALLOC_DEFAULT_LINE, mark, not_freed_b,
			 free_b, details_b);
  }
#else
  _dmalloc_log_changed(file, DMALLOC_DEFAULT_LINE, mark, not_freed_b,
		       free_b, details_b);
#endif
}

/*
 * routine to call dmalloc_strerror when linked in
 */
const char	*dmalloc_strerror(const int error_num)
{
#if USE_DMALLOC_LEAP
  if (_dmalloc_strerror_func == NULL) {
    return "unknown";
  }
  else {
    return _dmalloc_strerror_func(error_num);
  }
#else
  return _dmalloc_strerror(error_num);
#endif
}
