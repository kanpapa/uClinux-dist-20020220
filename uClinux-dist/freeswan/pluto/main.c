/* Pluto main program
 * Copyright (C) 1997 Angelos D. Keromytis.
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
 * RCSID $Id: main.c,v 1.44 2001/06/12 21:40:38 dhr Exp $
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <fcntl.h>
#include <getopt.h>

#include <freeswan.h>

#include "constants.h"
#include "defs.h"
#include "id.h"
#include "connections.h"	/* needs id.h */
#include "packet.h"
#include "demux.h"  /* needs packet.h */
#include "server.h"
#include "kernel.h"
#include "log.h"
#include "preshared.h"
#include "rnd.h"
#include "state.h"

#include "sha1.h"
#include "md5.h"
#include "crypto.h"	/* requires sha1.h and md5.h */
#include "version.c"

static void
usage(const char *mess)
{
    if (mess != NULL && *mess != '\0')
	fprintf(stderr, "%s\n", mess);
    fprintf(stderr,
	"Usage: pluto"
	    " [--help]"
	    " [--version]"
	    " [--optionsfrom <filename>]"
	    " \\\n\t"
	    "[--nofork]"
	    " [--stderrlog]"
	    " [--noklips]"
	    " [--uniqueids]"
	    " \\\n\t"
	    "[--ikeport <port-number>]"
	    " \\\n\t"
	    "[--ctlbase <path>]"
	    " \\\n\t"
	    "[--secretsfile <secrets-file>]"
#ifdef DEBUG
	    " \\\n\t"
	    "[--debug-none]"
	    " [--debug-all]"
	    " [--debug-raw]"
	    " [--debug-crypt]"
	    " \\\n\t"
	    "[--debug-parsing]"
	    " [--debug-emitting]"
	    " [--debug-control]"
	    " \\\n\t"
	    "[--debug-klips]"
	    "[ --debug-private]"
#endif
	    "\n"
	"FreeS/WAN %s\n",
	freeswan_version);
    exit_pluto(mess == NULL? 0 : 1);
}

char copyright[] =
"Copyright (C) 1999 Henry Spencer, Richard Guy Briggs, D. Hugh Redelmeier,\n"
"	Sandy Harris, Angelos D. Keromytis, John Ioannidis.\n"
"\n"
"   This program is free software; you can redistribute it and/or modify it\n"
"   under the terms of the GNU General Public License as published by the\n"
"   Free Software Foundation; either version 2 of the License, or (at your\n"
"   option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.\n"
"\n"
"   This program is distributed in the hope that it will be useful, but\n"
"   WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY\n"
"   or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License\n"
"   (file COPYING in the distribution) for more details.\n";


/* lock file support
 * - provides convenient way for scripts to find Pluto's pid
 * - prevents multiple Plutos competing for the same port
 * - same basename as unix domain control socket
 * NOTE: will not take account of sharing LOCK_DIR with other systems.
 */

static char pluto_lock[sizeof(ctl_addr.sun_path)] = DEFAULT_CTLBASE LOCK_SUFFIX;
static bool pluto_lock_created = FALSE;

/* create lockfile, or die in the attempt */
static int
create_lock(void)
{
    int fd = open(pluto_lock, O_WRONLY | O_CREAT | O_EXCL | O_TRUNC,
	S_IRUSR | S_IRGRP | S_IROTH);

    if (fd < 0)
    {
	if (errno == EEXIST)
	{
	    fprintf(stderr, "pluto: lock file \"%s\" already exists\n"
		, pluto_lock);
	    exit_pluto(10);
	}
	else
	{
	    fprintf(stderr
		, "pluto: unable to create lock file \"%s\" (%d %s)\n"
		, pluto_lock, errno, strerror(errno));
	    exit_pluto(1);
	}
    }
    pluto_lock_created = TRUE;
    return fd;
}

static bool
fill_lock(int lockfd, pid_t pid)
{
    char buf[30];	/* holds "<pid>\n" */
    int len = snprintf(buf, sizeof(buf), "%u\n", (unsigned int) pid);

    return len > 0 && write(lockfd, buf, len) == len;
}

static void
delete_lock(void)
{
    if (pluto_lock_created)
    {
	delete_ctl_socket();
	unlink(pluto_lock);	/* is noting failure useful? */
    }
}

int
main(int argc, char **argv)
{
    bool fork_desired = TRUE;
    bool log_to_stderr_desired = FALSE;
    int lockfd;

    /* handle arguments */
    for (;;)
    {
	static const struct option long_opts[] = {
	    /* name, has_arg, flag, val */
	    { "help", no_argument, NULL, 'h' },
	    { "version", no_argument, NULL, 'v' },
	    { "optionsfrom", required_argument, NULL, '+' },
	    { "nofork", no_argument, NULL, 'd' },
	    { "stderrlog", no_argument, NULL, 'e' },
	    { "noklips", no_argument, NULL, 'n' },
	    { "uniqueids", no_argument, NULL, 'u' },
	    { "ikeport", required_argument, NULL, 'p' },
	    { "ctlbase", required_argument, NULL, 'b' },
	    { "secretsfile", required_argument, NULL, 's' },
#ifdef DEBUG
	    { "debug-none", no_argument, NULL, 'N' },
	    { "debug-all]", no_argument, NULL, 'A' },
	    { "debug-raw", no_argument, NULL, 'R' },
	    { "debug-crypt", no_argument, NULL, 'X' },
	    { "debug-parsing", no_argument, NULL, 'P' },
	    { "debug-emitting", no_argument, NULL, 'E' },
	    { "debug-control", no_argument, NULL, 'C' },
	    { "debug-klips", no_argument, NULL, 'K' },
	    { "debug-private", no_argument, NULL, 'Z' },
#endif
	    { 0,0,0,0 }
	    };
	/* Note: we don't like the way short options get parsed
	 * by getopt_long, so we simply pass an empty string as
	 * the list.  It could be "hvdenp:l:s:" "NARXPECK".
	 */
	int c = getopt_long(argc, argv, "", long_opts, NULL);

	/* Note: "breaking" from case terminates loop */
	switch (c)
	{
	case EOF:	/* end of flags */
	    break;

	case 0: /* long option already handled */
	    continue;

	case ':':	/* diagnostic already printed by getopt_long */
	case '?':	/* diagnostic already printed by getopt_long */
	    usage("");
	    break;   /* not actually reached */

	case 'h':	/* --help */
	    usage(NULL);
	    break;	/* not actually reached */

	case 'v':	/* --version */
	    printf("Linux FreeS/WAN %s\n", freeswan_version);
	    fputs(copyright, stdout);
	    exit_pluto(0);
	    break;	/* not actually reached */

	case '+':	/* --optionsfrom <filename> */
	    optionsfrom(optarg, &argc, &argv, optind, stderr);
	    /* does not return on error */
	    continue;

	case 'd':	/* --nofork*/
	    fork_desired = FALSE;
	    continue;

	case 'e':	/* --stderrlog */
	    log_to_stderr_desired = TRUE;
	    continue;

	case 'n':	/* --noklips */
	    no_klips = TRUE;
	    continue;

	case 'u':	/* --uniquids */
	    uniqueIDs = TRUE;
	    continue;

	case 'p':	/* --port <portnumber> */
	    if (optarg == NULL || !isdigit(optarg[0]))
		usage("missing port number");
	    {
		char *endptr;
		long port = strtol(optarg, &endptr, 0);

		if (*endptr != '\0' || endptr == optarg
		|| port <= 0 || port > 0x10000)
		    usage("<port-number> must be a number between 1 and 65535");
		pluto_port = port;
	    }
	    continue;

	case 'b':	/* --ctlbase <path> */
	    if (snprintf(ctl_addr.sun_path, sizeof(ctl_addr.sun_path)
	    , "%s%s", optarg, CTL_SUFFIX) == -1)
		usage("<path>" CTL_SUFFIX " too long for sun_path");
	    if (snprintf(pluto_lock, sizeof(pluto_lock)
	    , "%s%s", optarg, LOCK_SUFFIX) == -1)
		usage("<path>" LOCK_SUFFIX " must fit");
	    continue;

	case 's':	/* --secretsfile <secrets-file> */
	    shared_secrets_file = optarg;
	    continue;

#ifdef DEBUG
	case 'N':	/* --debug-none */
	    base_debugging = DBG_NONE;
	    continue;

	case 'A':	/* --debug-all */
	    base_debugging = DBG_ALL;
	    continue;

	case 'R':	/* --debug-raw */
	    base_debugging |= DBG_RAW;
	    continue;

	case 'X':	/* --debug-crypt */
	    base_debugging |= DBG_CRYPT;
	    continue;

	case 'P':	/* --debug-parsing */
	    base_debugging |= DBG_PARSING;
	    continue;

	case 'E':	/* --debug-emitting */
	    base_debugging |= DBG_EMITTING;
	    continue;

	case 'C':	/* --debug-control */
	    base_debugging |= DBG_CONTROL;
	    continue;

	case 'K':	/* --debug-klips */
	    base_debugging |= DBG_KLIPS;
	    continue;

	case 'Z':	/* --debug-private */
	    base_debugging |= DBG_PRIVATE;
	    continue;
#endif
	default:
	    passert(FALSE);
	}
	break;
    }
    if (optind != argc)
	usage("unexpected argument");
#ifdef DEBUG
    cur_debugging = base_debugging;
#endif
    lockfd = create_lock();

    /* select between logging methods */

    if (log_to_stderr_desired)
	log_to_syslog = FALSE;
    else
	log_to_stderr = FALSE;

    /* create control socket.
     * We must create it before the parent process returns so that
     * there will be no race condition in using it.  The easiest
     * place to do this is before the daemon fork.
     */
    {
	err_t ugh = init_ctl_socket();

	if (ugh != NULL)
	{
	    fprintf(stderr, "pluto: %s", ugh);
	    exit_pluto(1);
	}
    }

    /* If not suppressed, do daemon fork */

#ifndef EMBED
    if (fork_desired)
    {
	{
	    pid_t pid = fork();

	    if (pid < 0)
	    {
		int e = errno;

		fprintf(stderr, "pluto: fork failed (%d %s)\n",
		    errno, strerror(e));
		exit_pluto(1);
	    }

	    if (pid != 0)
	    {
		/* parent: die, after filling PID into lock file.
		 * must not use exit_pluto: lock would be removed!
		 */
		exit(fill_lock(lockfd, pid)? 0 : 1);
	    }
	}

	if (setsid() < 0)
	{
	    int e = errno;

	    fprintf(stderr, "setsid() failed in main(). Errno %d: %s\n",
		errno, strerror(e));
	    exit_pluto(1);
	}
    }
    else
#endif
    {
	/* no daemon fork: we have to fill in lock file */
	(void) fill_lock(lockfd, getpid());
	fprintf(stdout, "Pluto initialized\n");
	fflush(stdout);
    }

    /* Close everything but ctl_fd and (if needed) stderr.
     * Subsumed: close(lockfd);
     */
    {
	int i;

	for (i = getdtablesize() - 1; i >= 0; i--)  /* Bad hack */
	    if ((!log_to_stderr || i != 2)
	    && i != ctl_fd)
		close(i);

	/* make sure that stdin, stdout, stderr are reserved */
	if (open("/dev/null", O_RDONLY) != 0)
	    abort();
	if (dup2(0, 1) != 1)
	    abort();
	if (!log_to_stderr && dup2(0, 2) != 2)
	    abort();
    }

    init_constants();
    init_log();
    /* Note: some scripts may look for this exact message -- don't change */
    log("Starting Pluto (FreeS/WAN Version %s)", freeswan_version);
    init_rnd_pool();
    init_secret();
    init_states();
    init_crypto();
    init_demux();
    init_kernel();
    call_server();
    return -1;        /* Shouldn't ever reach this */
}

/* leave pluto, with status.
 * Once child is launched, parent must not exit this way because
 * the lock would be released.
 *
 *  0 OK
 *  1 general discomfort
 * 10 lock file exists
 */
void
exit_pluto(int status)
{
    RESET_GLOBALS();	/* needed because we may be called in odd state */
    free_preshared_secrets();
    free_public_keys();
    delete_every_connection();
    free_ifaces();
    delete_lock();
#ifdef LEAK_DETECTIVE
    report_leaks();
#endif /* LEAK_DETECTIVE */
    close_log();
    exit(status);
}
