/* conf.h.  Generated automatically by configure.  */
/*
 * Automatic configuration flags
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
 * $Id: conf.h,v 1.1 2000/11/01 01:19:03 pauli Exp $
 */

#ifndef __CONF_H__
#define __CONF_H__

/* please see settings.h for manual configuration options */

/*
 * NOTE: The following settings should not need to be tuned by hand.
 */

/*
 * Set to 1 if the mprotect function was found and the PROT_NONE,
 * PROT_READ, and PROT_WRITE defines were found in sys/mman.h.  This
 * is so that we can restrict access to certain blocks of memory.
 */
#define PROTECT_ALLOWED 0

/*
 * (char *)sbrk(const int incr) is the main heap-memory allocation
 * routine that most systems employ.  This extends the program's data
 * space by INCR number of bytes.
 *
 * NOTE: please mail me if your system does not have this function.
 */
#define HAVE_SBRK 1

/*
 * Does your heap grow up?  Hopefully it does because there is not too
 * much support for growing-down heaps because I do not have a system
 * to test it on.
 *
 * NOTE: please send me mail if configure generates a 0 for this on
 * your system.
 */
#define HEAP_GROWS_UP 1

/*
 * This is the basic block size in bits.  If possible, the configure
 * script will set this to be the value returned by the getpagesize()
 * function.  If not then some sort of best guess will be necessary.
 * 14 (meaning basic block size of 16k) will probably be good.
 *
 * NOTE: some sbrk functions round to the correct page-size.  If this
 * value is too low, the dmalloc library may think someone is using
 * sbrk behind its back and return a ERROR_ALLOC_NONLINEAR error
 * (#18).  No problems aside from a possible small increase in the
 * administration overhead should happen if this value is too high.
 */
#define BASIC_BLOCK 10

/*
 * The alignment value of all allocations in number of bytes for
 * loading admin information before an allocation.  If possible, the
 * configure script will set this to be the value returned by
 * sizeof(long) which in most systems is the register width.
 *
 * NOTE: the value will never be auto-configured to be less than 8
 * because some system (like sparc for instance) report the sizeof(long)
 * == 4 while the register size is 8 bytes.  Certain memory needs to be of
 * the same base as the register size (stack frames, code, etc.).  Any
 * ideas how I can determine the register size in a better (and portable)
 * fashion?
 *
 * NOTE: larger the number the more memory may be wasted by certain
 * debugging settings like fence-post checking.
 */
#define ALLOCATION_ALIGNMENT 8

/*
 * This checks to see if the abort routine does extensive cleaning up
 * before halting a program.  If so then it may call malloc functions
 * making the library go recursive.  If abort is set to not okay then
 * you should tune the KILL_PROCESS and SIGNAL_INCLUDE options in
 * settings.h if you want the library to be able to dump core.
 */
#define ABORT_OKAY 1

/*
 * This checks to see if we can include signal.h and get SIGHUP,
 * SIGINT, and SIGTERM for the catch-signals token.  With this token,
 * you can have the library do an automatic shutdown if we see the
 * above signals.
 */
#define SIGNAL_OKAY 1
#define RETSIGTYPE void

/*
 * This checks to see if we can include return.h and use the assembly
 * macros there to call the callers address for logging.  If you do
 * not want this behavior, then set the USE_RETURN_MACROS to 0 in the
 * settings.h file.
 */
#define RETURN_MACROS_WORK 1

/*
 * Which pthread include file to use.
 */
#define HAVE_PTHREAD_H 0
#define HAVE_PTHREADS_H 0

/*
 * What pthread functions do we have?
 */
#define HAVE_PTHREAD_MUTEX_INIT 0
#define HAVE_PTHREAD_MUTEX_LOCK 0
#define HAVE_PTHREAD_MUTEX_UNLOCK 0

/*
 * What is the pthread mutex type?  Usually (always?) it is
 * pthread_mutex_t.
 */
#define THREAD_MUTEX_T pthread_mutex_t

/*
 * On some systems, you initialize mutex variables with NULL.  Others
 * require various stupid non-portable incantations.  The OSF 3.2 guys
 * should be ashamed of themselves.  This only is used if the
 * LOCK_THREADS setting is enabled in the settings.h.
 */
#define THREAD_LOCK_INIT_VAL 0L

/*
 * LIBRARY DEFINES:
 */

/*
 * Some systems have functions which can register routines to be
 * called by exit(3) (or when the program returns from main).  This
 * functionality allows the dmalloc_shutdown() routine to be called
 * automatically upon program completion so that the library can log
 * statistics.  Use the AUTO_SHUTDOWN define above to disable this.
 * Please send me mail if this functionality exists on your system but
 * in another name.
 *
 * NOTE: If neither is available, take a look at atexit.c in the
 * contrib directory which may provide this useful functionality for
 * your system.
 */
#define HAVE_ATEXIT 0
#define HAVE_ON_EXIT 0

/* Is the DMALLOC_SIZE type unsigned? */
#define DMALLOC_SIZE_UNSIGNED 1

/*
 * The dmalloc library provides its own versions of the following
 * functions, or knows how to work around their absence.
 */
/* bells and whistles */
#define HAVE_FORK 0
#define HAVE_GETPID 1
#define HAVE_TIME 1
#define HAVE_CTIME 1
#define HAVE_RANDOM 1
#define HAVE_VPRINTF 0
#define HAVE_SNPRINTF 0
#define HAVE_VSNPRINTF 0

#define HAVE_RECALLOC 0
#define HAVE_MEMALIGN 0
#define HAVE_VALLOC 0

#define HAVE_BCMP 1
#define HAVE_BCOPY 1
#define HAVE_MEMSET 1

#define HAVE_STRCHR 1
#define HAVE_STRRCHR 1

#define HAVE_STRCAT 1
#define HAVE_STRLEN 1
#define HAVE_STRCMP 1
#define HAVE_STRCPY 1
#define HAVE_STRSEP 1

/* for argv files */
#define HAVE_STRNCMP 1
#define HAVE_STRNCPY 1

/*
 * The below functions are here to provide function argument checking
 * only.  The library only has stubs for these and does not use them
 * internally.
 */
#define HAVE_BZERO 1

#define HAVE_MEMCPY 1
#define HAVE_MEMCCPY 1
#define HAVE_MEMCHR 1
#define HAVE_MEMCMP 1

#define HAVE_INDEX 1
#define HAVE_RINDEX 1
#define HAVE_STRCASECMP 1
#define HAVE_STRNCASECMP 1
#define HAVE_STRDUP 1
#define HAVE_STRSPN 1
#define HAVE_STRCSPN 1
#define HAVE_STRNCAT 1
#define HAVE_STRPBRK 1
#define HAVE_STRSTR 1
#define HAVE_STRTOK 1

/* manual settings */
#include "settings.h"

#endif /* ! __CONF_H__ */
