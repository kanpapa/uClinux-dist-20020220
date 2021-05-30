/* logging definitions
 * Copyright (C) 1998, 1999  D. Hugh Redelmeier.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 * RCSID $Id: log.h,v 1.26 2001/05/05 17:20:01 dhr Exp $
 */

#include <freeswan.h>

extern bool
    log_to_stderr,	/* should log go to stderr? */
    log_to_syslog;	/* should log go to syslog? */

/* Context for logging.
 *
 * Global variables: must be carefully adjusted at transaction boundaries!
 * If the context provides a whack file descriptor, messages
 * should be copied to it -- see whack_log()
 */
extern int whack_log_fd;	/* only set during whack_handle() */
extern struct state *cur_state;	/* current state, for diagnostics */
extern struct connection *cur_connection;	/* current connection, for diagnostics */
extern const ip_address *cur_from;	/* source of current current message */
extern u_int16_t cur_from_port;	/* host order */

#ifdef DEBUG

extern unsigned int cur_debugging;	/* current debugging level */

#define GLOBALS_ARE_RESET() (whack_log_fd == NULL_FD \
    && cur_state == NULL \
    && cur_connection == NULL \
    && cur_from == NULL \
    && cur_debugging == base_debugging)

#define RESET_GLOBALS() { whack_log_fd = NULL_FD; \
    cur_state = NULL; \
    cur_connection = NULL; \
    cur_from = NULL; \
    cur_debugging = base_debugging; }

#define SET_CUR_CONNECTION(c) { \
    cur_connection = (c); \
    extra_debugging(c); \
    }

#define UNSET_CUR_CONNECTION() { \
    cur_connection = NULL; \
    cur_debugging = base_debugging; \
    }

#else

#define GLOBALS_ARE_RESET() (whack_log_fd == NULL_FD \
    && cur_state == NULL \
    && cur_connection == NULL \
    && cur_from == NULL)

#define RESET_GLOBALS() { whack_log_fd = NULL_FD; \
    cur_state = NULL; \
    cur_connection = NULL; \
    cur_from = NULL; }

#define SET_CUR_CONNECTION(c) { cur_connection = (c); }

#define UNSET_CUR_CONNECTION() {cur_connection = NULL; }

#endif

extern void init_log(void);
extern void close_log(void);
extern void log(const char *message, ...) PRINTF_LIKE(1);
extern void exit_log(const char *message, ...) PRINTF_LIKE(1) NEVER_RETURNS;

/* the following routines do a dance to capture errno before it is changed
 * A call must doubly parenthesize the argument list (no varargs macros).
 * The first argument must be "e", the local variable that captures errno.
 */
#define log_errno(a) { int e = errno; log_errno_routine a; }
extern void log_errno_routine(int e, const char *message, ...) PRINTF_LIKE(2);
#define exit_log_errno(a) { int e = errno; exit_log_errno_routine a; }
extern void exit_log_errno_routine(int e, const char *message, ...) PRINTF_LIKE(2) NEVER_RETURNS NEVER_RETURNS;

extern void whack_log(int mess_no, const char *message, ...) PRINTF_LIKE(2);

/* Log to both main log and whack log
 * Much like log, actually, except for specifying mess_no.
 */
extern void loglog(int mess_no, const char *message, ...) PRINTF_LIKE(2);

/* Build up a diagnostic in a static buffer.
 * Although this would be a generally useful function, it is very
 * hard to come up with a discipline that prevents different uses
 * from interfering.  It is intended that by limiting it to building
 * diagnostics, we will avoid this problem.
 * Juggling is performed to allow an argument to be a previous
 * result: the new string may safely depend on the old one.  This
 * restriction is not checked in any way: violators will produce
 * confusing results (without crashing!).
 */
extern err_t builddiag(const char *fmt, ...) PRINTF_LIKE(1);

#ifdef DEBUG

extern unsigned int base_debugging;	/* bits selecting what to report */
extern void extra_debugging(const struct connection *c);
#define DBG(cond, action)   { if (cur_debugging & (cond)) { action ; } }

extern void DBG_log(const char *message, ...) PRINTF_LIKE(1);
extern void DBG_dump(const char *label, const void *p, size_t len);
#define DBG_dump_chunk(label, ch) DBG_dump(label, (ch).ptr, (ch).len)

#else

#define DBG(cond, action)	/* do nothing */

#endif

#define DBG_cond_dump(cond, label, p, len) DBG(cond, DBG_dump(label, p, len))
#define DBG_cond_dump_chunk(cond, label, ch) DBG(cond, DBG_dump_chunk(label, ch))


/* ip_str: a simple to use variant of addrtot.
 * It stores its result in a static buffer.
 * This means that newer calls overwrite the storage of older calls.
 * Note: this is not used in any of the logging functions, so their
 * callers may use it.
 */
extern const char *ip_str(const ip_address *src);
