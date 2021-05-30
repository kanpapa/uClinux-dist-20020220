/*
 * WARNING: this file was produced from settings.dist
 * by the configure program.  The configure script, when
 * run again, will overwrite changed made here.
 */

/*
 * manual configuration flags
 *
 * Copyright 2000 by Gray Watson
 *
 * This file is part of the dmalloc package.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose and without fee is hereby granted, provided
 * that the above copyright notice and this permission notice appear
 * in all copies, and that the name of Gray Watson not be used in
 * advertising or publicity pertaining to distribution of the document
 * or software without specific, written prior permission.
 *
 * Gray Watson makes no representations about the suitability of the
 * software described herein for any purpose.  It is provided "as is"
 * without express or implied warranty.
 *
 * The author may be contacted via http://dmalloc.com/
 *
 * $Id: settings.h,v 1.2 2001/07/27 06:35:16 philipc Exp $
 */

/*
 * PROGRAMMING NOTE: this file cannot be included before conf.h, so
 * you might as well only include conf.h and never this file.
 */

#ifndef __SETTINGS_H__
#define __SETTINGS_H__

#ifdef EMBED
/* This one defines how we fake memory allocation via sbrk.
 * We allocate ourselves a block of memory this big and pray that
 * it doesn't run out :-)
 */
#define SBRK_SIZE 1048576
#endif

/*
 * should we include the RCS ids in the .c files and the installed
 * library?
 */
#define INCLUDE_RCS_IDS 0

/*
 * Should we allow zero length allocations?  This will generate the
 * smallest possible allocation.
 *
 * FYI: if fence post checking is requested, the top and bottom of the
 * fence post information will be touching.
 */
#define ALLOW_ALLOC_ZERO_SIZE 0

/*
 * Should we allow realloc of a NULL pointer?  If set to one, this
 * will call malloc when 0L is realloc-ed.  This is useful when you
 * are extending an array in a loop and do not want to allocate it
 * specially the first time.
 */
#define ALLOW_REALLOC_NULL 1

/*
 * Should we allow realloc to a 0 size to cause the pointer to be
 * freed?  If set to one, this will call free when a pointer is
 * realloc-ed to a size of 0.  Thanks to Stefan Froehlich
 * for patiently pointing that the realloc in just about every Unix
 * has this functionality.
 */
#define ALLOW_REALLOC_SIZE_ZERO 1

/*
 * Should we allow the free of a NULL pointer and if it happens,
 * should a message be generated to that effect.  Most (if not all)
 * POSIX C libraries allow you to free() or delete() a NULL pointer
 * and a number of programming reference manuals mention that freeing
 * of NULL is ``allowed''.  However, I believe that it is bad form,
 * promotes lazy pointer handling, and can often hide program bugs.
 * As the author of dmalloc, I reserve the right to determine the
 * default action of the library to encourage code similar to the
 * following: if (pnt != NULL) { free(pnt); }
 *
 * The default is to generate an exception whenever a free of NULL is
 * encountered allowing the user to determine where s/he is freeing a
 * possibly random pointer.  Setting ALLOW_FREE_NULL to 1 will cause
 * this not to happen.  I recommend at least logging a message with
 * the ALLOW_FREE_NULL_MESSAGE set to 1.
 *
 * Even with ALLOW_FREE_NULL set to 0, you can enable the
 * 'allow-free-null' token at runtime for specific programs.  It will
 * not cause an error when the user asks for 0 bytes and will not
 * generate an exception when it sees a free(0L).
 */
#define ALLOW_FREE_NULL 0
#define ALLOW_FREE_NULL_MESSAGE 1

/*
 * Should we use the ra-address macros in return.h.  These are system
 * specific macros designed to return the return-address for logging
 * callers (i.e. possible offenders) of malloc routines.  Please mail
 * me if you have any questions with this functionality.
 */
#define USE_RETURN_MACROS 1

/*
 * Write this character into memory when it is allocated and not
 * calloc-ed if the alloc-blank token is enabled and when it has been
 * freed if the free-blank token is enabled.  You can verify that
 * these sections have not been overwritten with the check-blank
 * token.
 */
#define BLANK_CHAR		'\305'

/*
 * The following information sets limits on the size of the source
 * file name and line numbers returned by the __FILE__ and __LINE__
 * compiler macros.  You may need to tune then to fit your environment
 * although I would argue that if you have filenames longer than 40
 * characters or files longer than 10,000 lines, you are doing
 * something wrong.
 */
#define MIN_FILE_LENGTH		    3		/* min "[a-zA-Z].c" length */
#define MAX_FILE_LENGTH		  100		/* max __FILE__ length */
#define MAX_LINE_NUMBER		10000		/* max __LINE__ value */

/*
 * The largest allowable allocations in bits.  This is only for
 * verification purposes.  Any allocation larger than this (in bits)
 * will generate a ERROR_TOO_BIG error (#15).  The default
 * indicates that an allocation of more than 64mb (2^26) will generate
 * an error.
 */
#define LARGEST_BLOCK 20

/*
 * Although I don't know why you would want to tune this since this is
 * pretty dependent on my general heap mechanisms, here are some
 * options to use general first, best, and worst fit algorithms.  If
 * you don't know what these are, then DON'T TOUCH.
 *
 * NOTES: they may go away in the future and/or be replaced by
 * debug-tokens.  I've tested all three and have not noticed any large
 * differences.  Also, they only apply for allocations > basic-block
 * (page) size.
 */
#define FIRST_FIT 1
#define BEST_FIT 0
#define WORST_FIT 0

/*
 * Automatically call dmalloc_shutdown if on_exit or atexit is
 * available.  See conf.h for whether configure found on_exit or
 * atexit calls.  If neither is available, your program will have to
 * call dmalloc_shutdown yourself before it exits.  You can also take
 * a look at atexit.c in the contrib directory which may provide this
 * useful functionality for your system.
 *
 * NOTE: If you are having problems with the library going recursive (see
 * LOCK_THREADS below if you are using pthreads), you might want to
 * try setting this to 0.  Because the library makes a call to on_exit
 * or atexit to register itself, it may cause memory transactions by
 * the system causing the dreaded recursive message.  You may then be
 * forced to register dmalloc_shutdown yourself via on_exit or atexit
 * in main() or call dmalloc_shutdown directly before you exit().
 */
#define AUTO_SHUTDOWN 1

/*
 * The ABORT_OKAY is auto-configured but may have to be adjusted by
 * forcing the USE_ABORT to be 1 or 0.  On some OS's, abort calls
 * fclose() which may want to free memory making the library go
 * recursive when it is aborting.  See ABORT_OKAY in the conf.h file
 * for more information.
 *
 * If you need to override it or if ABORT_OKAY is 0, set KILL_PROCESS to
 * the proper way to stop the program.  Killing the current process
 * (id 0) with SIGABRT works on a number of Unix systems.  You may
 * have to define some include file to get the value for the signal
 * that is used.
 */
#if ABORT_OKAY
#define USE_ABORT		1
#else
#define USE_ABORT		0
#endif
#if SIGNAL_OKAY
#define KILL_INCLUDE		<signal.h>
#define KILL_PROCESS		(void)kill(0, SIGABRT)
#endif

/*
 * Define the signals that are to be caught by the catch-signals
 * token.  When caught, these signals will cause an automatic shutdown
 * of the library so that the not-freed memory and other statistics will
 * be displayed.  Thanks Marty.
 */
#if SIGNAL_OKAY
#define SIGNAL1		SIGHUP
#define SIGNAL2		SIGINT
#define SIGNAL3		SIGTERM
#undef SIGNAL4
#undef SIGNAL5
#undef SIGNAL6
#endif

/*
 * Number of bytes to write at the top of allocations (if fence-post
 * checking is enabled).  A larger number means more memory space used
 * up but better protection against fence overruns.  See the manual
 * for more information.
 */
#define FENCE_TOP_SIZE 4

/*
 * Number of bytes to write at the bottom of allocations. See the
 * FENCE_TOP_SIZE setting above or the manual for more information.
 *
 * WARNING: this should changed with caution and probably should only be
 * increased.  If you need to change it, use (ALLOCATION_ALIGNMENT *
 * X) or some such.  For more information see ALLOCATION_ALIGNMENT in
 * conf.h.
 */
#define FENCE_BOTTOM_SIZE ALLOCATION_ALIGNMENT

/*
 * Amount of space that we are to display whenever we need to dump a
 * pointer's contents to a log file or stream.  This should be more
 * than FENCE_BOTTOM_SIZE and FENCE_TOP_SIZE.
 */
#define DUMP_SPACE 20

/*
 * Write the iteration count at the start of every log entry.  This is
 * handy when you are using the DMALLOC_START variable and want to
 * begin the tough debugging at a certain point.
 */
#define LOG_ITERATION_COUNT 1

/*
 * Store the number of times a pointer is "seen" being allocated or
 * freed -- it shows up as a s# (for seen) in the logfile.  This is
 * useful for tracking of not-freed memory.  See the documents for more
 * information.
 *
 * NOTE: This creates a certain amount of memory overhead.
 */
#define STORE_SEEN_COUNT 1

/*
 * Store the iteration count when a pointer is allocated -- it
 * shows up as a i# (for iteration) in the logfile.  This is to give
 * you some idea when during program execution, a pointer was
 * allocated but not freed.
 *
 * NOTE: This creates a certain amount of memory overhead.
 */
#define STORE_ITERATION_COUNT 0

/*
 * At the front of each log message, print the output from the time()
 * call as a number.  This requires that the time function be defined.
 */
#define LOG_TIME_NUMBER		1
#define TIME_INCLUDE		<time.h>

/*
 * At the front of each log message, print the output from the ctime()
 * function (not including the \n).  The TIME_NUMBER_TYPE is the type
 * that will store the output of time() and whose address we will pass
 * into ctime.  This requires that the ctime and time functions both
 * be defined.
 */
#if LOG_TIME_NUMBER == 0
#define LOG_CTIME_STRING	1
#define TIME_TYPE		unsigned int
#endif

/*
 * Store the time (in seconds) or timeval (in seconds and
 * microseconds) when a pointer is allocated -- it shows up as a w#
 * (for when) in the logfile.  This is to give you some idea when a
 * pointer was allocated but not freed.  The library will log the
 * starting and the ending time if either of these flags is set.
 * TIMEVAL_INCLUDE is the include file to define struct timeval and
 * GET_TIMEVAL does the actual reading of the current time of day.
 *
 * WARNING: only TIME _or_ TIMEVAL can be defined at one time.
 *
 * NOTE: This creates a certain amount of memory overhead.
 */
#define STORE_TIME		0
#ifndef TIME_INCLUDE
#define TIME_INCLUDE		<time.h>
#endif
#ifndef TIME_TYPE
#define TIME_TYPE		unsigned int
#endif
#define STORE_TIMEVAL		0
#define TIMEVAL_INCLUDE		<sys/time.h>
#define TIMEVAL_TYPE		struct timeval
#define GET_TIMEVAL(timeval)	(void)gettimeofday(&(timeval), NULL)

/*
 * In OSF (anyone else?) you can setup __fini_* functions in each
 * module which will be called automagically at shutdown of the
 * program.  If you enable this variable, dmalloc will shut itself
 * down and log statistics when the program closes on its own.  Pretty
 * cool OS feature.
 */
#define FINI_DMALLOC 0

/* If you enable this, you probably want the AUTO_SHUTDOWN flag turned off */
#if FINI_DMALLOC
#undef AUTO_SHUTDOWN
#define AUTO_SHUTDOWN 0
#endif

/*
 * Keep addresses that are freed from recycling back into the used
 * queue for a certain number of memory transactions.  For instance,
 * if this is set to 10 then after you free a pointer, it cannot be
 * reused until after 10 additional calls to malloc, free, realloc,
 * etc..  Define to 0 to disable.  NOTE: setting to 1 does nothing.
 *
 * For more drastic debugging, you can enable the never-reuse flag
 * which will cause the library to never reuse previously allocated
 * memory.  This may significantly expand the memory requirements of
 * your system however.
 */
#define FREED_POINTER_DELAY 20

/*
 * Size of the table of file and line number memory entries.  This
 * memory table records the top locations by file/line or
 * return-address of all pointers allocated.  It also tabulates the
 * freed memory pointers so you can easily locate the large memory
 * leaks.  See the MEMORY_TABLE_LOG value below to 0 to disable the
 * table.
 *
 * NOTE: the library will actually allocated 2 times this many
 * entries for speed reasons.
 */
#define MEMORY_TABLE_SIZE 4096

/*
 * This indicates how many of the top entries from the memory table
 * you want to log by default to the log file.
 *
 * NOTE: to display the top entries correctly, your OS must support
 * the quicksort function.
 */
#define MEMORY_TABLE_LOG 10

/*
 * Define this to 1 to only display the memory table summary of the
 * dumped table pointers.  The default is to display the summary as
 * well as the individual pointers so the individual leaks can be
 * tracked down.
 */
#define DUMP_UNFREED_SUMMARY_ONLY 0

/*
 * If you are including the dmalloc.h include file, define this to 1
 * to be able to disable the library by linking in the libdmalloc_lp.a
 * library.  The alternative is to have to recompile your source files
 * without including dmalloc.h.  With the libdmalloc_lp.a you can use
 * the system's or another set of malloc functions without having to
 * recompile.
 *
 * During a poll on the dmalloc mailing list, very few people
 * showed that they cared at all about this and only 1 (one) said that
 * they actually used it.
 */
#define USE_DMALLOC_LEAP 0

/*
 * Set to 0 if you don't want dmalloc to be using mprotect to restrict
 * accesses to memory blocks.  This is a newer part of the library and
 * still may have bugs.  Protection will only be on if the
 * auto-configuration scripts find the mprotect function and the
 * PROT_NONE, PROT_READ, and PROT_WRITE defines.
 */
#define PROTECT_BLOCKS 1

/****************************** thread settings ******************************/

/*
 * The following definition allows use of the library in threaded
 * programs.  The most common package is MIT's pthreads so this is the
 * default.  Please send me mail if these definitions are configurable
 * enough to work with your thread package.
 */

#ifndef LOCK_THREADS
#define LOCK_THREADS 0
#endif

#if LOCK_THREADS

/*
 * Which threads library header to include when needed.  It is assumed
 * that the types and functions in the THREAD_TYPE and THREAD_GET_ID
 * macros below are defined in this include file.  In addition, the
 * thread mutex init, lock, and unlock functions in malloc.c should
 * also be prototyped here.
 */
#define THREAD_INCLUDE			<pthread.h>

/*
 * As we approach the time when we start mutex locking the library, we
 * need to init the mutex variable.  This sets how many times before
 * we start locking should we init the variable taking in account that
 * the init itself might generate a call into the library.  Ugh.
 */
#define THREAD_INIT_LOCK	2

/*
 * For those threaded programs, the following settings allow the
 * library to log the identity of the thread that allocated a specific
 * pointer.  The thread-id will show up as a ``t'' followed by a
 * string identifying the thread.  The LOG_THREAD_ID macro says
 * whether the thread-id is logged at the front of all log messages.
 * The THREAD_TYPE macro defines the variable type of the id.  The
 * THREAD_GET_ID macro is what function to call to get the currently
 * running thread.  The THREAD_ID_TO_STRING defines how the thread-id
 * value is translated to the string necessary to be included with the
 * ``t'' in the logfile.
 */
#define LOG_THREAD_ID			0
#define THREAD_TYPE			pthread_t
#define THREAD_GET_ID()			pthread_self()
#if HAVE_SNPRINTF
#define THREAD_ID_TO_STRING(buf, buf_size, thread_id)	\
				(void)snprintf((buf), (buf_size), "%#lx", \
					       (long)(thread_id))
#else
#define THREAD_ID_TO_STRING(buf, buf_size, thread_id)	\
				(void)sprintf((buf), "%#lx", (long)(thread_id))
#endif

#endif /* LOCK_THREADS */

#endif /* ! __SETTINGS_H__ */
