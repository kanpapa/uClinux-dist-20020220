
/*
 * $Id: debug.c,v 1.75.2.3 2000/02/09 23:29:55 wessels Exp $
 *
 * DEBUG: section 0     Debug Routines
 * AUTHOR: Harvest Derived
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by the
 *  National Science Foundation.  Squid is Copyrighted (C) 1998 by
 *  the Regents of the University of California.  Please see the
 *  COPYRIGHT file for full details.  Squid incorporates software
 *  developed and/or copyrighted by other sources.  Please see the
 *  CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */

#include "squid.h"

static char *debug_log_file = NULL;
static int Ctx_Lock = 0;
static const char *debugLogTime(time_t);
static void ctx_print();

#if STDC_HEADERS
void
_db_print(const char *format,...)
{
#if defined(__QNX__)
    va_list eargs;
#endif
    va_list args;
#else
void
_db_print(va_alist)
     va_dcl
{
    va_list args;
    const char *format = NULL;
#endif
    LOCAL_ARRAY(char, f, BUFSIZ);
#if HAVE_SYSLOG
    LOCAL_ARRAY(char, tmpbuf, BUFSIZ);
#endif

#if STDC_HEADERS
    va_start(args, format);
#if defined(__QNX__)
    va_start(eargs, format);
#endif
#else
    va_start(args);
    format = va_arg(args, const char *);
#endif

    if (debug_log == NULL)
	return;
    /* give a chance to context-based debugging to print current context */
    if (!Ctx_Lock)
	ctx_print();
    snprintf(f, BUFSIZ, "%s| %s",
	debugLogTime(squid_curtime),
	format);
#if HAVE_SYSLOG
    /* level 0,1 go to syslog */
    if (_db_level <= 1 && opt_syslog_enable) {
	tmpbuf[0] = '\0';
	vsnprintf(tmpbuf, BUFSIZ, format, args);
	tmpbuf[BUFSIZ - 1] = '\0';
	syslog(_db_level == 0 ? LOG_WARNING : LOG_NOTICE, "%s", tmpbuf);
    }
#endif /* HAVE_SYSLOG */
    /* write to log file */
#if defined(__QNX__)
    vfprintf(debug_log, f, eargs);
#else
    vfprintf(debug_log, f, args);
#endif
    if (!Config.onoff.buffered_logs)
	fflush(debug_log);
    if (opt_debug_stderr >= _db_level && debug_log != stderr) {
#if defined(__QNX__)
	vfprintf(stderr, f, eargs);
#else
	vfprintf(stderr, f, args);
#endif
    }
#if defined(__QNX__)
    va_end(eargs);
#endif
    va_end(args);
}

static void
debugArg(const char *arg)
{
    int s = 0;
    int l = 0;
    int i;
    if (!strncasecmp(arg, "ALL", 3)) {
	s = -1;
	arg += 4;
    } else {
	s = atoi(arg);
	while (*arg && *arg++ != ',');
    }
    l = atoi(arg);
    assert(s >= -1);
    assert(s < MAX_DEBUG_SECTIONS);
    if (l < 0)
	l = 0;
    if (l > 10)
	l = 10;
    if (s >= 0) {
	debugLevels[s] = l;
	return;
    }
    for (i = 0; i < MAX_DEBUG_SECTIONS; i++)
	debugLevels[i] = l;
}

static void
debugOpenLog(const char *logfile)
{
    if (logfile == NULL) {
	debug_log = stderr;
	return;
    }
    if (debug_log_file)
	xfree(debug_log_file);
    debug_log_file = xstrdup(logfile);	/* keep a static copy */
    if (debug_log && debug_log != stderr)
	fclose(debug_log);
    debug_log = fopen(logfile, "a+");
    if (!debug_log) {
	fprintf(stderr, "WARNING: Cannot write log file: %s\n", logfile);
	perror(logfile);
	fprintf(stderr, "         messages will be sent to 'stderr'.\n");
	fflush(stderr);
	debug_log = stderr;
    }
}

void
_db_init(const char *logfile, const char *options)
{
    int i;
    char *p = NULL;
    char *s = NULL;

    for (i = 0; i < MAX_DEBUG_SECTIONS; i++)
	debugLevels[i] = -1;

    if (options) {
	p = xstrdup(options);
	for (s = strtok(p, w_space); s; s = strtok(NULL, w_space))
	    debugArg(s);
	xfree(p);
    }
    debugOpenLog(logfile);

#if HAVE_SYSLOG && defined(LOG_LOCAL4)
    if (opt_syslog_enable)
	openlog(appname, LOG_PID | LOG_NDELAY | LOG_CONS, LOG_LOCAL4);
#endif /* HAVE_SYSLOG */

}

void
_db_rotate_log(void)
{
    int i;
    LOCAL_ARRAY(char, from, MAXPATHLEN);
    LOCAL_ARRAY(char, to, MAXPATHLEN);
#ifdef S_ISREG
    struct stat sb;
#endif

    if (debug_log_file == NULL)
	return;
#ifdef S_ISREG
    if (stat(debug_log_file, &sb) == 0)
	if (S_ISREG(sb.st_mode) == 0)
	    return;
#endif

    /*
     * NOTE: we cannot use xrename here without having it in a
     * separate file -- tools.c has too many dependencies to be
     * used everywhere debug.c is used.
     */
    /* Rotate numbers 0 through N up one */
    for (i = Config.Log.rotateNumber; i > 1;) {
	i--;
	snprintf(from, MAXPATHLEN, "%s.%d", debug_log_file, i - 1);
	snprintf(to, MAXPATHLEN, "%s.%d", debug_log_file, i);
	rename(from, to);
    }
    /* Rotate the current log to .0 */
    if (Config.Log.rotateNumber > 0) {
	snprintf(to, MAXPATHLEN, "%s.%d", debug_log_file, 0);
	rename(debug_log_file, to);
    }
    /* Close and reopen the log.  It may have been renamed "manually"
     * before HUP'ing us. */
    if (debug_log != stderr)
	debugOpenLog(Config.Log.log);
}

static const char *
debugLogTime(time_t t)
{
    struct tm *tm;
    static char buf[128];
    static time_t last_t = 0;
    if (t != last_t) {
	tm = localtime(&t);
	strftime(buf, 127, "%Y/%m/%d %H:%M:%S", tm);
	last_t = t;
    }
    return buf;
}

void
xassert(const char *msg, const char *file, int line)
{
    debug(0, 0) ("assertion failed: %s:%d: \"%s\"\n", file, line, msg);
    if (!shutting_down)
	abort();
}

/*
 * Context-based Debugging
 *
 * Rationale
 * ---------
 * 
 * When you have a long nested processing sequence, it is often impossible
 * for low level routines to know in what larger context they operate. If a
 * routine coredumps, one can restore the context using debugger trace.
 * However, in many case you do not want to coredump, but just want to report
 * a potential problem. A report maybe useless out of problem context.
 * 
 * To solve this potential problem, use the following approach:
 * 
 * int
 * top_level_foo(const char *url)
 * {
 *      // define current context
 *      // note: we stack but do not dup ctx descriptions!
 *      Ctx ctx = ctx_enter(url);
 *      ...
 *      // go down; middle_level_bar will eventually call bottom_level_boo
 *      middle_level_bar(method, protocol);
 *      ...
 *      // exit, clean after yourself
 *      ctx_exit(ctx);
 * }
 * 
 * void
 * bottom_level_boo(int status, void *data)
 * {
 *      // detect exceptional condition, and simply report it, the context
 *      // information will be available somewhere close in the log file
 *      if (status == STRANGE_STATUS)
 *      debug(13, 6) ("DOS attack detected, data: %p\n", data);
 *      ...
 * }
 * 
 * Current implementation is extremely simple but still very handy. It has a
 * negligible overhead (descriptions are not duplicated).
 * 
 * When the _first_ debug message for a given context is printed, it is
 * prepended with the current context description. Context is printed with
 * the same debugging level as the original message.
 * 
 * Note that we do not print context every type you do ctx_enter(). This
 * approach would produce too many useless messages.  For the same reason, a
 * context description is printed at most _once_ even if you have 10
 * debugging messages within one context.
 * 
 * Contexts can be nested, of course. You must use ctx_enter() to enter a
 * context (push it onto stack).  It is probably safe to exit several nested
 * contexts at _once_ by calling ctx_exit() at the top level (this will pop
 * all context till current one). However, as in any stack, you cannot start
 * in the middle.
 * 
 * Analysis: 
 * i)   locate debugging message,
 * ii)  locate current context by going _upstream_ in your log file,
 * iii) hack away.
 *
 *
 * To-Do: 
 * -----
 *
 *       decide if we want to dup() descriptions (adds overhead) but allows to
 *       add printf()-style interface
 *
 * implementation:
 * ---------------
 *
 * descriptions for contexts over CTX_MAX_LEVEL limit are ignored, you probably
 * have a bug if your nesting goes that deep.
 */

#define CTX_MAX_LEVEL 255

/*
 * produce a warning when nesting reaches this level and then double
 * the level
 */
static int Ctx_Warn_Level = 32;
/* all descriptions has been printed up to this level */
static int Ctx_Reported_Level = -1;
/* descriptions are still valid or active up to this level */
static int Ctx_Valid_Level = -1;
/* current level, the number of nested ctx_enter() calls */
static int Ctx_Current_Level = -1;
/* saved descriptions (stack) */
static const char *Ctx_Descrs[CTX_MAX_LEVEL + 1];
/* "safe" get secription */
static const char *ctx_get_descr(Ctx ctx);


Ctx
ctx_enter(const char *descr)
{
    Ctx_Current_Level++;

    if (Ctx_Current_Level <= CTX_MAX_LEVEL)
	Ctx_Descrs[Ctx_Current_Level] = descr;

    if (Ctx_Current_Level == Ctx_Warn_Level) {
	debug(0, 0) ("# ctx: suspiciously deep (%d) nesting:\n", Ctx_Warn_Level);
	Ctx_Warn_Level *= 2;
    }
    return Ctx_Current_Level;
}

void
ctx_exit(Ctx ctx)
{
    assert(ctx >= 0);
    Ctx_Current_Level = (ctx >= 0) ? ctx - 1 : -1;
    if (Ctx_Valid_Level > Ctx_Current_Level)
	Ctx_Valid_Level = Ctx_Current_Level;
}

/*
 * the idea id to print each context description at most once but provide enough
 * info for deducing the current execution stack
 */
static void
ctx_print(void)
{
    /* lock so _db_print will not call us recursively */
    Ctx_Lock++;
    /* ok, user saw [0,Ctx_Reported_Level] descriptions */
    /* first inform about entries popped since user saw them */
    if (Ctx_Valid_Level < Ctx_Reported_Level) {
	if (Ctx_Reported_Level != Ctx_Valid_Level + 1)
	    _db_print("ctx: exit levels from %2d down to %2d\n",
		Ctx_Reported_Level, Ctx_Valid_Level + 1);
	else
	    _db_print("ctx: exit level %2d\n", Ctx_Reported_Level);
	Ctx_Reported_Level = Ctx_Valid_Level;
    }
    /* report new contexts that were pushed since last report */
    while (Ctx_Reported_Level < Ctx_Current_Level) {
	Ctx_Reported_Level++;
	Ctx_Valid_Level++;
	_db_print("ctx: enter level %2d: '%s'\n", Ctx_Reported_Level,
	    ctx_get_descr(Ctx_Reported_Level));
    }
    /* unlock */
    Ctx_Lock--;
}

/* checks for nulls and overflows */
static const char *
ctx_get_descr(Ctx ctx)
{
    if (ctx < 0 || ctx > CTX_MAX_LEVEL)
	return "<lost>";
    return Ctx_Descrs[ctx] ? Ctx_Descrs[ctx] : "<null>";
}
