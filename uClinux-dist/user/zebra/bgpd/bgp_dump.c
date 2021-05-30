/* BGP-4 dump routine
 * Copyright (C) 1999 Kunihiro Ishiguro
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

#include "log.h"
#include "stream.h"
#include "sockunion.h"
#include "command.h"
#include "prefix.h"
#include "thread.h"
#include "table.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_dump.h"

enum bgp_dump_type
{
  BGP_DUMP_ALL,
  BGP_DUMP_UPDATES,
  BGP_DUMP_ROUTES
};

struct bgp_dump
{
  enum bgp_dump_type type;

  char *filename;

  FILE *fp;

  unsigned int interval;

  char *interval_str;

  struct thread *t_interval;
};

/* BGP packet dump output buffer. */
struct stream *bgp_dump_obuf;

/* BGP dump strucuture for 'dump bgp all' */
struct bgp_dump bgp_dump_all;

/* BGP dump structure for 'dump bgp updates' */
struct bgp_dump bgp_dump_updates;

/* BGP dump structure for 'dump bgp routes' */
struct bgp_dump bgp_dump_routes;

/* Some define for BGP packet dump. */
FILE *
bgp_dump_open_file (struct bgp_dump *bgp_dump)
{
  int ret;
  time_t clock;
  struct tm *tm;
  char fullpath[MAXPATHLEN];
  char realpath[MAXPATHLEN];

  time (&clock);
  tm = localtime (&clock);

#ifndef HAVE_STRFTIME
#define strftime(a, b, c, d)	(strncpy(a, c, b) ? 1 : 0)
#endif

  if (bgp_dump->filename[0] != DIRECTORY_SEP)
    {
      sprintf (fullpath, "%s/%s", vty_get_cwd (), bgp_dump->filename);
      ret = strftime (realpath, MAXPATHLEN, fullpath, tm);
    }
  else
    ret = strftime (realpath, MAXPATHLEN, bgp_dump->filename, tm);

  if (ret == 0)
    {
      zlog_warn ("bgp_dump_open_file: strftime error");
      return NULL;
    }

  if (bgp_dump->fp)
    fclose (bgp_dump->fp);


  bgp_dump->fp = fopen (realpath, "w");

  if (bgp_dump->fp == NULL)
    return NULL;

  return bgp_dump->fp;
}

int
bgp_dump_interval_add (struct bgp_dump *bgp_dump, int interval)
{
  int bgp_dump_interval_func (struct thread *);

  bgp_dump->t_interval = thread_add_timer (master, bgp_dump_interval_func, 
					   bgp_dump, interval);
  return 0;
}

/* Dump common header. */
void
bgp_dump_header (struct stream *obuf, int subtype)
{
  time_t now;

  /* Set header. */
  time (&now);

  /* Put dump packet header. */
  stream_putl (obuf, now);	
  stream_putw (obuf, MSG_PROTOCOL_BGP4MP);
  stream_putw (obuf, subtype);

  /* Placeholder for length. */
  stream_putl (obuf, 0);
}

void
bgp_dump_routes_entry (struct bgp_info *info, int afi)
{
  struct stream *obuf;
  int safi = 0;

  /* Make dump stream. */
  obuf = bgp_dump_obuf;
  stream_reset (obuf);

  bgp_dump_header (obuf, BGP4MP_ENTRY);

  stream_putw (obuf, 0);	/* View # */
  stream_putw (obuf, 0);	/* Status */
  stream_putl (obuf, info->uptime); /* Time Last Change */
  stream_putw (obuf, afi);	/* Address Family */
  stream_putc (obuf, safi);	/* SAFI */

  if (afi == AFI_IP)
    {
      stream_putc (obuf, IPV4_MAX_BYTELEN);
      /* info->attr->; */
    }
#ifdef HAVE_IPV6
  else if (afi == AFI_IP6)
    {
      stream_putc (obuf, 0);
      ;
    }
#endif /* HAVE_IPV6 */
}

/* Runs under child process. */
void
bgp_dump_routes_func ()
{
  struct route_node *rn;
  struct bgp_info *info;
  struct bgp *bgp;
  struct route_table *table;

  bgp = bgp_get_default ();
  if (!bgp)
    return;

  table = bgp->rib[AFI_IP][SAFI_UNICAST];

  for (rn = route_top (table); rn; rn = route_next (rn))
    for (info = rn->info; info; info = info->next)
      bgp_dump_routes_entry (info, AFI_IP);

#ifdef HAVE_IPV6
  table = bgp->rib[AFI_IP6][SAFI_UNICAST];
  
  for (rn = route_top (table); rn; rn = route_next (rn))
    for (info = rn->info; info; info = info->next)
      bgp_dump_routes_entry (info, AFI_IP6);
#endif /* HAVE_IPV6 */

  /*  Close file pointer ?*/
}

/* Dump all routing table to the file. */
void
bgp_dump_routes_fork ()
{
  pid_t pid;

#ifdef EMBED
  pid = vfork ();
#else
  pid = fork ();
#endif

  if (pid < 0)
    {
      zlog_info ("bgp_dump_routes_fork: fork error %s", strerror (errno));
      return;
    }
  else if (pid > 0)
    {
      /* Parent. */
      /* waidpid ? */
      /* close fd ? */
      return;
    }

  /* Real job. */
  bgp_dump_routes_func ();

  exit (0);
}

int
bgp_dump_interval_func (struct thread *t)
{
  struct bgp_dump *bgp_dump;

  bgp_dump = THREAD_ARG (t);
  bgp_dump->t_interval = NULL;

  if (bgp_dump_open_file (bgp_dump) == NULL)
    return 0;

  /* In case of bgp_dump_routes, we need special route dump function. */
  if (bgp_dump->type == BGP_DUMP_ROUTES)
    bgp_dump_routes_fork ();

  bgp_dump_interval_add (bgp_dump, bgp_dump->interval);
  
  return 0;
}

void
bgp_dump_set_size (struct stream *s)
{
  /* If size is specifed use it. */
  stream_putl_at (s, 8, stream_get_putp (s) - BGP_DUMP_HEADER_SIZE);
  return;
}

/* Dump common information. */
void
bgp_dump_common (struct stream *obuf, struct peer *peer)
{
  char empty[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

  /* Source AS number and Destination AS number. */
  stream_putw (obuf, peer->as);
  stream_putw (obuf, peer->local_as);

  if (peer->afc[AFI_IP][SAFI_UNICAST])
    {
      stream_putw (obuf, peer->ifindex);
      stream_putw (obuf, AFI_IP);

      stream_put (obuf, &peer->su.sin.sin_addr, IPV4_MAX_BYTELEN);

      if (peer->su_local)
	stream_put (obuf, &peer->su_local->sin.sin_addr, IPV4_MAX_BYTELEN);
      else
	stream_put (obuf, empty, IPV4_MAX_BYTELEN);
    }
#ifdef HAVE_IPV6
  else if (peer->afc[AFI_IP6][SAFI_UNICAST])
    {
      /* Interface Index and Address family. */
      stream_putw (obuf, peer->ifindex);
      stream_putw (obuf, AFI_IP6);

      /* Source IP Address and Destination IP Address. */
      stream_put (obuf, &peer->su.sin6.sin6_addr, IPV6_MAX_BYTELEN);

      if (peer->su_local)
	stream_put (obuf, &peer->su_local->sin6.sin6_addr, IPV6_MAX_BYTELEN);
      else
	stream_put (obuf, empty, IPV6_MAX_BYTELEN);
    }
#endif /* HAVE_IPV6 */
}

/* Dump BGP status change. */
void
bgp_dump_state (struct peer *peer, int status_old, int status_new)
{
  struct stream *obuf;

  /* If dump file pointer is disabled return immediately. */
  if (bgp_dump_all.fp == NULL)
    return;

  /* Make dump stream. */
  obuf = bgp_dump_obuf;
  stream_reset (obuf);

  bgp_dump_header (obuf, BGP4MP_STATE_CHANGE);
  bgp_dump_common (obuf, peer);

  stream_putw (obuf, status_old);
  stream_putw (obuf, status_new);

  /* Set length. */
  bgp_dump_set_size (obuf);

  /* Write to the stream. */
  fwrite (STREAM_DATA (obuf), stream_get_putp (obuf), 1, bgp_dump_all.fp);
  fflush (bgp_dump_all.fp);
}

void
bgp_dump_packet_func (struct bgp_dump *bgp_dump, struct peer *peer,
		      struct stream *packet)
{
  struct stream *obuf;

  /* If dump file pointer is disabled return immediately. */
  if (bgp_dump->fp == NULL)
    return;

  /* Make dump stream. */
  obuf = bgp_dump_obuf;
  stream_reset (obuf);

  /* Dump header and common part. */
  bgp_dump_header (obuf, BGP4MP_MESSAGE);
  bgp_dump_common (obuf, peer);

  /* Packet contents. */
  stream_put (obuf, STREAM_DATA (packet), stream_get_endp (packet));
  
  /* Set length. */
  bgp_dump_set_size (obuf);

  /* Write to the stream. */
  fwrite (STREAM_DATA (obuf), stream_get_putp (obuf), 1, bgp_dump->fp);
  fflush (bgp_dump->fp);
}

void
bgp_dump_packet (struct peer *peer, int type, struct stream *packet)
{
  /* bgp_dump_all. */
  bgp_dump_packet_func (&bgp_dump_all, peer, packet);

  /* bgp_dump_updates. */
  if (type == BGP_MSG_UPDATE)
    bgp_dump_packet_func (&bgp_dump_updates, peer, packet);
}

unsigned int
bgp_dump_parse_time (char *str)
{
  int i;
  int len;
  int seen_h;
  int seen_m;
  int time;
  unsigned int total;

  time = 0;
  total = 0;
  seen_h = 0;
  seen_m = 0;
  len = strlen (str);

  for (i = 0; i < len; i++)
    {
      if (isdigit ((int) str[i]))
	{
	  time *= 10;
	  time += str[i] - '0';
	}
      else if (str[i] == 'H' || str[i] == 'h')
	{
	  if (seen_h)
	    return 0;
	  if (seen_m)
	    return 0;
	  total += time * 60 *60;
	  time = 0;
	  seen_h = 1;
	}
      else if (str[i] == 'M' || str[i] == 'm')
	{
	  if (seen_m)
	    return 0;
	  total += time * 60;
	  time = 0;
	  seen_h = 1;
	}
      else
	return 0;
    }
  return total + time;
}

int
bgp_dump_set (struct vty *vty, struct bgp_dump *bgp_dump, int type,
	      char *path, char *interval_str)
{
  if (interval_str)
    {
      unsigned int interval;

      /* Check interval string. */
      interval = bgp_dump_parse_time (interval_str);
      if (interval == 0)
	{
	  vty_out (vty, "Malformed interval string%s", VTY_NEWLINE);
	  return CMD_WARNING;
	}
      /* Set interval. */
      bgp_dump->interval = interval;
      if (bgp_dump->interval_str)
	free (bgp_dump->interval_str);
      bgp_dump->interval_str = strdup (interval_str);

      /* Create interval thread. */
      bgp_dump_interval_add (bgp_dump, interval);
    }

  /* Set type. */
  bgp_dump->type = type;

  /* Set file name. */
  if (bgp_dump->filename)
    free (bgp_dump->filename);
  bgp_dump->filename = strdup (path);

  /* This should be called when interval is expired. */
  bgp_dump_open_file (bgp_dump);

  return CMD_SUCCESS;
}

int
bgp_dump_unset (struct vty *vty, struct bgp_dump *bgp_dump)
{
  /* Set file name. */
  if (bgp_dump->filename)
    {
      free (bgp_dump->filename);
      bgp_dump->filename = NULL;
    }

  /* This should be called when interval is expired. */
  if (bgp_dump->fp)
    {
      fclose (bgp_dump->fp);
      bgp_dump->fp = NULL;
    }

  /* Create interval thread. */
  if (bgp_dump->t_interval)
    {
      thread_cancel (bgp_dump->t_interval);
      bgp_dump->t_interval = NULL;
    }

  bgp_dump->interval = 0;

  if (bgp_dump->interval_str)
    {
      free (bgp_dump->interval_str);
      bgp_dump->interval_str = NULL;
    }
  

  return CMD_SUCCESS;
}

DEFUN (dump_bgp_all,
       dump_bgp_all_cmd,
       "dump bgp all PATH",
       "Dump packet\n"
       "BGP packet dump\n"
       "Dump all BGP packets\n"
       "Output filename\n")
{
  return bgp_dump_set (vty, &bgp_dump_all, BGP_DUMP_ALL, argv[0], NULL);
}

DEFUN (dump_bgp_all_interval,
       dump_bgp_all_interval_cmd,
       "dump bgp all PATH INTERVAL",
       "Dump packet\n"
       "BGP packet dump\n"
       "Dump all BGP packets\n"
       "Output filename\n"
       "Interval of output\n")
{
  return bgp_dump_set (vty, &bgp_dump_all, BGP_DUMP_ALL, argv[0], argv[1]);
}

DEFUN (no_dump_bgp_all,
       no_dump_bgp_all_cmd,
       "no dump bgp all [PATH] [INTERVAL]",
       NO_STR
       "Dump packet\n"
       "BGP packet dump\n"
       "Dump all BGP packets\n")
{
  return bgp_dump_unset (vty, &bgp_dump_all);
}

DEFUN (dump_bgp_updates,
       dump_bgp_updates_cmd,
       "dump bgp updates PATH",
       "Dump packet\n"
       "BGP packet dump\n"
       "Dump BGP updates only\n"
       "Output filename\n")
{
  return bgp_dump_set (vty, &bgp_dump_updates, BGP_DUMP_UPDATES, argv[0], NULL);
}

DEFUN (dump_bgp_updates_interval,
       dump_bgp_updates_interval_cmd,
       "dump bgp updates PATH INTERVAL",
       "Dump packet\n"
       "BGP packet dump\n"
       "Dump BGP updates only\n"
       "Output filename\n"
       "Interval of output\n")
{
  return bgp_dump_set (vty, &bgp_dump_updates, BGP_DUMP_UPDATES, argv[0], argv[1]);
}

DEFUN (no_dump_bgp_updates,
       no_dump_bgp_updates_cmd,
       "no dump bgp updates [PATH] [INTERVAL]",
       NO_STR
       "Dump packet\n"
       "BGP packet dump\n"
       "Dump BGP updates only\n")
{
  return bgp_dump_unset (vty, &bgp_dump_updates);
}

DEFUN (dump_bgp_routes,
       dump_bgp_routes_cmd,
       "dump bgp routes PATH",
       "Dump packet\n"
       "BGP packet dump\n"
       "Dump whole BGP routing table\n"
       "Output filename\n")
{
  return bgp_dump_set (vty, &bgp_dump_routes, BGP_DUMP_ROUTES, argv[0], NULL);
}

DEFUN (dump_bgp_routes_interval,
       dump_bgp_routes_interval_cmd,
       "dump bgp routes PATH INTERVAL",
       "Dump packet\n"
       "BGP packet dump\n"
       "Dump whole BGP routing table\n"
       "Output filename\n"
       "Interval of output\n")
{
  return bgp_dump_set (vty, &bgp_dump_routes, BGP_DUMP_ROUTES, argv[0], argv[1]);
}

DEFUN (no_dump_bgp_routes,
       no_dump_bgp_routes_cmd,
       "no dump bgp routes [PATH] [INTERVAL]",
       NO_STR
       "Dump packet\n"
       "BGP packet dump\n"
       "Dump whole BGP routing table\n")
{
  return bgp_dump_unset (vty, &bgp_dump_routes);
}

/* BGP node structure. */
struct cmd_node bgp_dump_node =
{
  DUMP_NODE,
  "",
};

#if 0
char *
config_time2str (unsigned int interval)
{
  static char buf[BUFSIZ];

  buf[0] = '\0';

  if (interval / 3600)
    {
      sprintf (buf, "%dh", interval / 3600);
      interval %= 3600;
    }
  if (interval / 60)
    {
      sprintf (buf + strlen (buf), "%dm", interval /60);
      interval %= 60;
    }
  if (interval)
    {
      sprintf (buf + strlen (buf), "%d", interval);
    }
  return buf;
}
#endif

int
config_write_bgp_dump (struct vty *vty)
{
  if (bgp_dump_all.filename)
    {
      if (bgp_dump_all.interval_str)
	vty_out (vty, "dump bgp all %s %s%s", 
		 bgp_dump_all.filename, bgp_dump_all.interval_str,
		 VTY_NEWLINE);
      else
	vty_out (vty, "dump bgp all %s%s", 
		 bgp_dump_all.filename, VTY_NEWLINE);
    }
  if (bgp_dump_updates.filename)
    {
      if (bgp_dump_updates.interval_str)
	vty_out (vty, "dump bgp updates %s %s%s", 
		 bgp_dump_updates.filename, bgp_dump_updates.interval_str,
		 VTY_NEWLINE);
      else
	vty_out (vty, "dump bgp updates %s%s", 
		 bgp_dump_updates.filename, VTY_NEWLINE);
    }
  if (bgp_dump_routes.filename)
    {
      if (bgp_dump_routes.interval_str)
	vty_out (vty, "dump bgp routes %s %s%s", 
		 bgp_dump_routes.filename, bgp_dump_routes.interval_str,
		 VTY_NEWLINE);
      else
	vty_out (vty, "dump bgp routes %s%s", 
		 bgp_dump_routes.filename, VTY_NEWLINE);
    }
  return 0;
}

/* Initialize BGP packet dump functionality. */
void
bgp_dump_init ()
{
  memset (&bgp_dump_all, 0, sizeof (struct bgp_dump));
  memset (&bgp_dump_updates, 0, sizeof (struct bgp_dump));
  memset (&bgp_dump_routes, 0, sizeof (struct bgp_dump));

  bgp_dump_obuf = stream_new (BGP_MAX_PACKET_SIZE + BGP_DUMP_HEADER_SIZE);

  install_node (&bgp_dump_node, config_write_bgp_dump);

  install_element (CONFIG_NODE, &dump_bgp_all_cmd);
  install_element (CONFIG_NODE, &dump_bgp_all_interval_cmd);
  install_element (CONFIG_NODE, &no_dump_bgp_all_cmd);
  install_element (CONFIG_NODE, &dump_bgp_updates_cmd);
  install_element (CONFIG_NODE, &dump_bgp_updates_interval_cmd);
  install_element (CONFIG_NODE, &no_dump_bgp_updates_cmd);
  install_element (CONFIG_NODE, &dump_bgp_routes_cmd);
  install_element (CONFIG_NODE, &dump_bgp_routes_interval_cmd);
  install_element (CONFIG_NODE, &no_dump_bgp_routes_cmd);
}
