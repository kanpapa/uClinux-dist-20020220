/*
 * RIPd main routine.
 * Copyright (C) 1997, 98 Kunihiro Ishiguro
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

#include "version.h"
#include "getopt.h"
#include "thread.h"
#include "vector.h"
#include "vty.h"
#include "command.h"
#include "memory.h"
#include "prefix.h"
#include "log.h"
#include "filter.h"

#include "ripd/ripd.h"

/* ripd options. */
static struct option longopts[] = 
{
  { "daemon",      no_argument,       NULL, 'd'},
  { "config_file", required_argument, NULL, 'f'},
  { "help",        no_argument,       NULL, 'h'},
  { "vty_port",    required_argument, NULL, 'P'},
  { "retain",      no_argument,       NULL, 'r'},
  { "version",     no_argument,       NULL, 'v'},
  { 0 }
};

/* Configuration file and directory. */
char config_current[] = RIPD_DEFAULT_CONFIG;
char config_default[] = SYSCONFDIR RIPD_DEFAULT_CONFIG;
char *config_file = NULL;

/* ripd program name */
char *progname;

/* Route retain mode flag. */
int retain_mode = 0;

int vty_port = 0;

/* Master of threads. */
struct thread_master *master;
struct thread thread;

/* Help information display. */
static void
usage (int status)
{
  if (status != 0)
    fprintf (stderr, "Try `%s --help' for more information.\n", progname);
  else
    {    
      printf ("Usage : %s [OPTION...]\n\
Daemon which manages RIP version 1 and 2.\n\n\
-d, --daemon       Runs in daemon mode\n\
-f, --config_file  Set configuration file name\n\
-P, --vty_port     Set vty's port number\n\
-r, --retain       When program terminates, retain added route by ripd.\n\
-v, --version      Print program version\n\
-h, --help         Display this help and exit\n\
\n\
Report bugs to %s\n", progname, ZEBRA_BUG_ADDRESS);
    }

  exit (status);
}

/* Signale wrapper. */
RETSIGTYPE *
signal_set (int signo, void (*func)(int))
{
  int ret;
  struct sigaction sig;
  struct sigaction osig;

  sig.sa_handler = func;
  sigemptyset (&sig.sa_mask);
  sig.sa_flags = 0;
#ifdef SA_RESTART
  sig.sa_flags |= SA_RESTART;
#endif /* SA_RESTART */

  ret = sigaction (signo, &sig, &osig);

  if (ret < 0) 
    return (SIG_ERR);
  else
    return (osig.sa_handler);
}

/* SIGHUP handler. */
void 
sighup (int sig)
{
  zlog_info ("SIGHUP received");
  rip_clean ();
  rip_reset ();
  zlog_info ("ripd restarting!");

  /* Reload config file. */
  vty_read_config (config_file, config_current, config_default);

  /* Create VTY's socket */
  vty_serv_sock (vty_port ? vty_port : RIP_VTY_PORT, RIP_VTYSH_PATH);

  /* Try to return to normal operation. */
}

/* SIGINT handler. */
void
sigint (int sig)
{
  zlog (NULL, LOG_INFO, "Terminating on signal");

  if (! retain_mode)
    rip_clean ();

  exit (0);
}

/* SIGUSR1 handler. */
void
sigusr1 (int sig)
{
  zlog_rotate (NULL);
}

/* Initialization of signal handles. */
void
signal_init ()
{
  signal_set (SIGHUP, sighup);
  signal_set (SIGINT, sigint);
  signal_set (SIGTERM, sigint);
  signal_set (SIGPIPE, SIG_IGN);
  signal_set (SIGUSR1, sigusr1);
}

/* Main routine of ripd. */
int
main (int argc, char **argv)
{
  char *p;
  int daemon_mode = 0;

  /* Get program name. */
  progname = ((p = strrchr (argv[0], '/')) ? ++p : argv[0]);

  /* First of all we need logging init. */
  zlog_default = openzlog (progname, ZLOG_SYSLOG, ZLOG_RIP,
			   LOG_CONS|LOG_NDELAY|LOG_PID, LOG_DAEMON);

  while (1) 
    {
      int opt;

      opt = getopt_long (argc, argv, "df:hP:rv", longopts, 0);
    
      if (opt == EOF)
	break;

      switch (opt) 
	{
	case 0:
	  break;
	case 'd':
	  daemon_mode = 1;
	  break;
	case 'f':
	  config_file = optarg;
	  break;
	case 'P':
	  vty_port = atoi (optarg);
	  break;
	case 'r':
	  retain_mode = 1;
	  break;
	case 'v':
	  print_version ();
	  exit (0);
	  break;
	case 'h':
	  usage (0);
	  break;
	default:
	  usage (1);
	  break;
	}
    }

  /* Initializations. */
  master = thread_make_master ();

  signal_init ();
  cmd_init ();
  vty_init ();
  memory_init ();

  /* RIP related initialization. */
  rip_init ();
  rip_if_init ();
  rip_zclient_init ();
  rip_peer_init ();
  sort_node ();

  /* Get configuration file. */
  vty_read_config (config_file, config_current, config_default);

  /* Change to the daemon program. */
  if (daemon_mode)
    daemon (0, 0);

  /* Pid file create. */
  pid_output (PATH_RIPD_PID);

  /* Create VTY's socket */
  vty_serv_sock (vty_port ? vty_port : RIP_VTY_PORT, RIP_VTYSH_PATH);

  /* Execute each thread. */
  while (thread_fetch (master, &thread))
    thread_call (&thread);

  /* Not reached. */
  exit (0);
}
