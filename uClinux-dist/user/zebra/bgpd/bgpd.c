/* BGP-4, BGP-4+ daemon program
 * Copyright (C) 1996, 97, 98, 99, 2000 Kunihiro Ishiguro
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

#include "prefix.h"
#include "thread.h"
#include "buffer.h"
#include "stream.h"
#include "table.h"
#include "command.h"
#include "sockunion.h"
#include "network.h"
#include "memory.h"
#include "roken.h"
#include "filter.h"
#include "routemap.h"
#include "str.h"
#include "log.h"
#include "plist.h"
#include "newlist.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_dump.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_community.h"
#include "bgpd/bgp_clist.h"
#include "bgpd/bgp_fsm.h"
#include "bgpd/bgp_packet.h"
#include "bgpd/bgp_zebra.h"
#include "bgpd/bgp_open.h"
#include "bgpd/bgp_filter.h"

#define min(a, b) ((a) < (b) ? (a) : (b))

/* All BGP instance. */
struct newlist *bgp_list;

/* All peer instance. */
struct newlist *peer_list;

/* BGP multiple instance flag. */
int bgp_multiple_instance;

/* Enable BGP mutliple instance configuration. */
DEFUN (bgp_multiple_instance_func,
       bgp_multiple_instance_cmd,
       "bgp multiple-instance",
       BGP_STR
       "Enable bgp multiple instance\n")
{
  bgp_multiple_instance = 1;
  return CMD_SUCCESS;
}

/* Disable BGP multiple instance. */
DEFUN (no_bgp_multiple_instance,
       no_bgp_multiple_instance_cmd,
       "no bgp multiple-instance",
       NO_STR
       BGP_STR
       "BGP multiple instance\n")
{
  if (bgp_list->count > 1)
    {
      vty_out (vty, "There are more than two BGP instances%s",
	       VTY_NEWLINE);
      return CMD_WARNING;
    }
  bgp_multiple_instance = 0;
  return CMD_SUCCESS;
}

/* Peer group cofiguration. */
struct peer_group *
peer_group_new ()
{
  struct peer_group *group;

  group = XMALLOC (MTYPE_PEER_GROUP, sizeof (struct peer_group));
  memset (group, 0, sizeof (struct peer_group));
  return group;
}

void
peer_group_free (struct peer_group *group)
{
  XFREE (MTYPE_PEER_GROUP, group);
}

struct peer_group *
peer_group_lookup (struct newlist *list, char *name)
{
  struct peer_group *group;
  struct newnode *nn;

  NEWLIST_LOOP (list, group, nn)
    {
      if (strcmp(group->name, name) == 0)
	return group;
    }
  return NULL;
}

int
peer_group_get (struct vty *vty, char *name, int afi, int safi)
{
  struct bgp *bgp;
  struct peer_group *group;

  bgp = vty->index;
  group = peer_group_lookup (bgp->peer_group, name);

  if (group)
    {
      vty_out (vty, "Same name peer-group already exists%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  group = peer_group_new ();
  group->name = strdup (name);
  group->peer_conf = newlist_new ();
  newnode_add (bgp->peer_group, group);

  return CMD_SUCCESS;
}

int
peer_conf_peer_group (struct vty *vty, char *peer_str, char *group_str)
{
  struct bgp *bgp;
  struct peer_group *group;

  bgp = vty->index;

  /* */
  group = peer_group_lookup (bgp->peer_group, group_str);

  return CMD_SUCCESS;
}

DEFUN (neighbor_peer_group,
       neighbor_peer_group_cmd,
       "neighbor WORD peer-group",
       NEIGHBOR_STR
       "Neighbor tag\n"
       "Configure peer-group\n")
{
  return peer_group_get (vty, argv[0], 0, 0);
}

DEFUN (neighbor_peer_group_remote_as,
       neighbor_peer_group_remote_as_cmd,
       "neighbor WORD remote-as <1-65535>",
       NEIGHBOR_STR
       "Neighbor tag\n"
       "Specify a BGP neighbor\n"
       "AS of remote neighbor\n")
{
  struct bgp *bgp;
  struct peer_group *group;
  char *endptr = NULL;
  as_t as;

  bgp = vty->index;
  group = peer_group_lookup (bgp->peer_group, argv[0]);

  if (!group)
    {
      vty_out (vty, "Please configure peer-group first%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  if (group->peer_conf->count)
    {
      vty_out (vty, "Can't configure AS number for existance peer%s",
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Convert string to number. */
  as = strtoul (argv[1], &endptr, 10);
  if (as == ULONG_MAX || *endptr != '\0' || as < 1 || as > 65535)
    {
      vty_out (vty, "AS value error%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  group->as = as;

  return CMD_SUCCESS;
}

DEFUN (neighbor_set_peer_group,
       neighbor_set_peer_group_cmd,
       NEIGHBOR_CMD "peer-group WORD",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Member of the peer-group"
       "peer-group name\n")
{
  return peer_conf_peer_group (vty, argv[0], argv[1]);
}

/* Set BGP's router identifier. */
int
bgp_router_id_set (struct vty *vty, char *id_str)
{
  struct bgp *bgp;
  struct in_addr id;
  int ret;
  struct peer_conf *conf;
  struct newnode *nn;

  ret = inet_aton (id_str, &id);
  if (!ret)
    {
      vty_out (vty, "Malformed bgp router identifier%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Set identifier to BGP structure. */
  bgp = vty->index;
  bgp->id = id;
  SET_FLAG (bgp->config, BGP_CONFIG_ROUTER_ID);

  /* Set all peer's local identifier with this value. */
  NEWLIST_LOOP (bgp->peer_conf, conf, nn)
    {
      conf->peer->local_id = id;
    }

  return CMD_SUCCESS;
}

/* Unset BGP router identifier. */
int
bgp_router_id_unset (struct vty *vty, char *id_str)
{
  int ret;
  struct bgp *bgp;
  struct in_addr id;
  struct peer_conf *conf;
  struct newnode *nn;

  bgp = vty->index;
  
  if (id_str)
    {
      ret = inet_aton (id_str, &id);
      if (!ret)
	{
	  vty_out (vty, "Malformed bgp router identifier%s", VTY_NEWLINE);
	  return CMD_WARNING;
	}

      if (!IPV4_ADDR_SAME (&bgp->id, &id))
	{
	  vty_out (vty, "bgp router-id doesn't match%s", VTY_NEWLINE);
	  return CMD_WARNING;
	}
    }
  bgp->id.s_addr = 0;
  UNSET_FLAG (bgp->config, BGP_CONFIG_ROUTER_ID);

  NEWLIST_LOOP (bgp->peer_conf, conf, nn)
    {
      conf->peer->local_id.s_addr = 0;
    }

  /* Set router-id from interface's address. */
  bgp_if_update_all ();

  return CMD_SUCCESS;
}

DEFUN (bgp_router_id, bgp_router_id_cmd,
       "bgp router-id A.B.C.D",
       BGP_STR
       "Override configured router identifier\n"
       "Manually configured router identifier\n")
{
  return bgp_router_id_set (vty, argv[0]);
}

DEFUN (no_bgp_router_id, no_bgp_router_id_cmd,
       "no bgp router-id A.B.C.D",
       NO_STR
       BGP_STR
       "Override configured router identifier\n"
       "Manually configured router identifier\n")
{
  return bgp_router_id_unset (vty, argv[0]);
}

/* BGP's cluster-id control. */
int
bgp_cluster_id_set (struct vty *vty, char *cluster_str)
{
  int ret;
  struct bgp *bgp;
  struct in_addr cluster;

  ret = inet_aton (cluster_str, &cluster);
  if (!ret)
    {
      vty_out (vty, "Malformed bgp cluster identifier%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  bgp = vty->index;
  bgp->cluster = cluster;
  bgp->config |= BGP_CONFIG_CLUSTER_ID;

  return CMD_SUCCESS;
}

int
bgp_cluster_id_unset (struct vty *vty, char *cluster_str)
{
  int ret;
  struct bgp *bgp;
  struct in_addr cluster;

  bgp = vty->index;

  if (cluster_str)
    {
      ret = inet_aton (cluster_str, &cluster);
      if (!ret)
	{
	  vty_out (vty, "Malformed bgp cluster identifier%s", VTY_NEWLINE);
	  return CMD_WARNING;
	}
      if (! IPV4_ADDR_SAME (&bgp->cluster, &cluster))
	{
	  vty_out (vty, "bgp cluster-id doesn't match%s", VTY_NEWLINE);
	  return CMD_WARNING;
      }
    }
  bgp->cluster.s_addr = 0;
  bgp->config &= ~BGP_CONFIG_CLUSTER_ID;

  return CMD_SUCCESS;
}

DEFUN (bgp_cluster_id, bgp_cluster_id_cmd,
       "bgp cluster-id A.B.C.D",
       BGP_STR
       "Configure Route-Reflector Cluster-id\n"
       "Route-Reflector Cluster-id in IP address format\n")
{
  return bgp_cluster_id_set (vty, argv[0]);
}

DEFUN (no_bgp_cluster_id, no_bgp_cluster_id_cmd,
       "no bgp cluster-id A.B.C.D",
       NO_STR
       BGP_STR
       "Configure Route-Reflector Cluster-id\n"
       "Route-Reflector Cluster-id in IP address format\n")
{
  return bgp_cluster_id_unset (vty, argv[0]);
}

int
bgp_confederation_id_set (struct vty *vty, char *id_str)
{
  struct bgp *bgp;
  as_t as = 0;
  char *endptr = NULL;
  struct peer *peer;
  struct newnode *nn;
  int old_confed_flag;  /* Old Confederations status */

  bgp = vty->index;

  if (id_str)
    {
      as = strtoul (id_str, &endptr, 10);
      if (as == ULONG_MAX || *endptr != '\0' || as < 1 || as > 65535)
	{
	  vty_out (vty, "AS value error%s", VTY_NEWLINE);
	  return CMD_WARNING;
	}

      /* Remember - were we doing CONFEDs before? */
      old_confed_flag = CHECK_FLAG (bgp->config, BGP_CONFIG_CONFEDERATION);
      bgp->confederation_id = as;
      SET_FLAG (bgp->config, BGP_CONFIG_CONFEDERATION);

      /*
       * how to handle already setup peers?
       * Answer - If we were doing CONFEDs already 
       *               - this is just an external AS change
       *               - just Reset EBGP sessions, not CONFED sessions
       *          If we were not doing CONFEDs before
       *               - Reset all EBGP sessions
       */
      NEWLIST_LOOP (peer_list, peer, nn)
	{
	  /* We're looking for peers who's AS is not local or part of
             our CONFED*/
	  if(old_confed_flag)
	    {
	      if (peer->as != bgp->as 
		  && ! bgp_confederation_peers_check(bgp, peer->as))
		{
		  peer->local_as = as;
		  BGP_EVENT_ADD (peer, BGP_Stop);
		}
	    }
	  else
	    {
	      /* Not doign CONFEDs before, so reset every non-local
                 session */
	      if (peer->as != bgp->as)
		{
		  /* Reset the local_as to be our EBGP one */
		  if (! bgp_confederation_peers_check(bgp, peer->as))
		    peer->local_as = as;
		  BGP_EVENT_ADD (peer, BGP_Stop);
		}
	    }
	}
      return CMD_SUCCESS;
    }
  else
    {
      vty_out (vty, "No AS Number provided%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  return CMD_WARNING;
}

int
bgp_confederation_id_unset (struct vty *vty, char *id_str)
{
  struct bgp *bgp;
  as_t as;
  char *endptr = NULL;
  struct peer *peer;
  struct newnode *nn;

  bgp = vty->index;

  if (id_str)
    {
      as = strtoul (id_str, &endptr, 10);
      if (as == ULONG_MAX || *endptr != '\0' || as < 1 || as > 65535)
	{
	  vty_out (vty, "AS value error%s", VTY_NEWLINE);
	  return CMD_WARNING;
	}
      
      if (bgp->confederation_id != as)
	{
	  vty_out (vty, "AS value does not match%s", VTY_NEWLINE);
	  return CMD_WARNING;
	}
      
      bgp->confederation_id = 0;
      UNSET_FLAG (bgp->config, BGP_CONFIG_CONFEDERATION);
      
      /*
       * How do we handle all EBGP peers if we have no external AS?
       * Assumption - No Confed ID == no CONFEDERATIONS, so
       * clear all EBGP *AND* CONFED peers and bring up with no spoofing.
       */
      NEWLIST_LOOP (peer_list, peer, nn)
	{
	  /* We're looking for peers who's AS is not local */
	  if (peer->as != bgp->as)
	    BGP_EVENT_ADD (peer, BGP_Stop);
	}   
      return CMD_SUCCESS;
    }
  else
    {
      vty_out (vty, "No AS Number provided%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  return CMD_WARNING;     
}

/* Is an AS part of the confed or not? */
int
bgp_confederation_peers_check (struct bgp *bgp, as_t as)
{
  int i;

  if (bgp == NULL)
    return 0;

  for(i = 0; i < bgp->confederation_peers_cnt; i++)
    {
      if (bgp->confederation_peers[i] == as)
	return 1;
    }

  return 0;
}

/* Add an AS to the CONFED set */
void
bgp_confederation_peers_add (struct bgp *bgp, as_t as)
{
  bgp->confederation_peers = XREALLOC (MTYPE_BGP_CONFED_LIST, 
				       bgp->confederation_peers,
				       bgp->confederation_peers_cnt + 1);
  bgp->confederation_peers[bgp->confederation_peers_cnt] = as;
  bgp->confederation_peers_cnt++;
}

void
bgp_confederation_peers_remove (struct bgp *bgp, as_t as)
{
  int i;
  int j;

  for(i = 0; i < bgp->confederation_peers_cnt; i++)
    {
      if(bgp->confederation_peers[i] == as)
	{
	  /* Remove this entry */
	  for(j = i+1; j < bgp->confederation_peers_cnt; j++)
	    {
	      bgp->confederation_peers[j-1] = bgp->confederation_peers[j];
	    }
	}
    }

  bgp->confederation_peers_cnt--;

  if (bgp->confederation_peers_cnt == 0)
    {
      bgp->confederation_peers = NULL;
    }
  else
    {
      bgp->confederation_peers = XREALLOC(MTYPE_BGP_CONFED_LIST,
					  bgp->confederation_peers,
					  bgp->confederation_peers_cnt);
    }
}

int
bgp_confederation_peers_set (struct vty *vty, int argc, char *argv[])
{
  struct bgp *bgp;
  as_t as;
  int i;
  char *endptr = NULL;

  bgp = vty->index;

  for(i = 0; i < argc; i++)
    {
      as = strtoul (argv[i], &endptr, 10);
      if (as == ULONG_MAX || as < 1 || as > 65535)
	{
	  vty_out (vty, "AS Value error (%s), ignoring%s",
		   argv[i], VTY_NEWLINE);
	}
      else
	{
	  if (! bgp_confederation_peers_check (bgp, as))
	    {
	      struct peer *peer;
	      struct newnode *nn;

	      /* Its not there already, so add it */
	      bgp_confederation_peers_add (bgp, as);

	      /* Now reset any peer who's remote AS has just joined
		 the CONFED unless its an iBGP peer */
	      NEWLIST_LOOP (peer_list, peer, nn)
		{
		  if (peer->as == as && peer->local_as != as)
		    {
		      if (! CHECK_FLAG (peer->flags, PEER_FLAG_SHUTDOWN))
			{
			  BGP_EVENT_ADD (peer, BGP_Stop);
			}
		      /* If the AS added to the list */
		      if(peer->local_as != as)
			{
			  peer->local_as = bgp->as;
			}
		    }
		}
	    }
	  else
	    {
	      /* Silently ignore repeated ASs */
	    }
	}
    }
  return CMD_SUCCESS;
}

int
bgp_confederation_peers_unset (struct vty *vty, int argc, char *argv[])
{
  struct bgp *bgp;
  as_t as;
  int i;
  char *endptr = NULL;

  bgp = vty->index;

  for(i = 0; i < argc; i++)
    {
      as = strtoul (argv[i], &endptr, 10);
      if (as == ULONG_MAX || as < 1 || as > 65535)
	{
	  vty_out(vty, "AS Value error (%), ignoring%s", argv[i], VTY_NEWLINE);
	}
      else
	{
	  if (! bgp_confederation_peers_check(bgp, as))
	    {
	      /* Its not there already, so silently ignore this*/
	    }
	  else
	    {
	      struct peer *peer;
	      struct newnode *nn;

	      /* Its there - we need to remove it */
	      bgp_confederation_peers_remove (bgp, as);

	      /* Now reset any peer who's remote AS has just been
                 removed from the CONFED */
	      NEWLIST_LOOP (peer_list, peer, nn)
		{
		  if (peer->as == as && peer->local_as != as)
		    {
		      if (! CHECK_FLAG (peer->flags, PEER_FLAG_SHUTDOWN))
			{
			  BGP_EVENT_ADD (peer, BGP_Stop);
			}
		      /* Set the peer's local-as correctly */
		      if(peer->local_as != as)
			{
			  peer->local_as = bgp->confederation_id;
			}
		    }
		}
	    }
	}
    }
  return CMD_SUCCESS;
}

void
bgp_confederation_peers_print (struct vty *vty, struct bgp *bgp)
{
  int i;

  for(i = 0; i < bgp->confederation_peers_cnt; i++)
    {
      vty_out(vty, " ");

      vty_out(vty, "%d", bgp->confederation_peers[i]);
    }
}

DEFUN (bgp_confederation_peers, bgp_confederation_peers_cmd,
       "bgp confederation peers .<1-65535>",
       BGP_STR
       "AS confederation parameters\n"
       "Peer ASs in BGP confederation\n"
       AS_STR)
{
  return bgp_confederation_peers_set(vty, argc, argv);
}

DEFUN (bgp_confederation_identifier, bgp_confederation_identifier_cmd,
       "bgp confederation identifier <1-65535>",
       BGP_STR
       "AS confederation parameters\n"
       "as number\n"
       "Set routing domain confederation AS\n")
{
  return bgp_confederation_id_set(vty, argv[0]);
}

DEFUN (no_bgp_confederation_peers, no_bgp_confederation_peers_cmd,
       "no bgp confederation peers .<1-65535>",
       NO_STR
       BGP_STR
       "AS confederation parameters\n"
       "Peer ASs in BGP confederation\n"
       AS_STR)
{
  return bgp_confederation_peers_unset(vty, argc, argv);
}

DEFUN (no_bgp_confederation_identifier, no_bgp_confederation_identifier_cmd,
       "no bgp confederation identifier <1-65535>",
       NO_STR
       BGP_STR
       "AS confederation parameters\n"
       "as number\n"
       "Set routing domain confederation AS\n")
{
  return bgp_confederation_id_unset(vty, argv[0]);
}

/* "bgp always-compare-med" configuration. */
DEFUN (bgp_always_compare_med,
       bgp_always_compare_med_cmd,
       "bgp always-compare-med",
       BGP_STR
       "Allow comparing MED from different neighbors\n")
{
  struct bgp *bgp;

  bgp = vty->index;
  SET_FLAG (bgp->config, BGP_CONFIG_ALWAYS_COMPARE_MED);
  return CMD_SUCCESS;
}

DEFUN (no_bgp_always_compare_med,
       no_bgp_always_compare_med_cmd,
       "no bgp always-compare-med",
       NO_STR
       BGP_STR
       "Allow comparing MED from different neighbors\n")
{
  struct bgp *bgp;

  bgp = vty->index;
  UNSET_FLAG (bgp->config, BGP_CONFIG_ALWAYS_COMPARE_MED);
  return CMD_SUCCESS;
}

/* "bgp bestpath missing-as-worst" configuration. */
DEFUN (bgp_bestpath_missing_as_worst,
       bgp_bestpath_missing_as_worst_cmd,
       "bgp bestpath missing-as-worst",
       BGP_STR
       "Change the default bestpath selection\n"
       "Missing MED value is compared as worst value\n")
{
  struct bgp *bgp;

  bgp = vty->index;
  SET_FLAG (bgp->config, BGP_CONFIG_MISSING_AS_WORST);
  return CMD_SUCCESS;
}

DEFUN (no_bgp_bestpath_missing_as_worst,
       no_bgp_bestpath_missing_as_worst_cmd,
       "no bgp bestpath missing-as-worst",
       NO_STR
       BGP_STR
       "Change the default bestpath selection\n"
       "Missing MED value is compared as worst value\n")
{
  struct bgp *bgp;

  bgp = vty->index;
  UNSET_FLAG (bgp->config, BGP_CONFIG_MISSING_AS_WORST);
  return CMD_SUCCESS;
}

DEFUN (no_bgp_default_ipv4_unicast,
       no_bgp_default_ipv4_unicast_cmd,
       "no bgp default ipv4-unicast",
       NO_STR
       BGP_STR
       "Default behavior\n"
       "IPv4 unicast\n")
{
  struct bgp *bgp;

  bgp = vty->index;
  SET_FLAG (bgp->config, BGP_CONFIG_NO_DEFAULT_IPV4);
  return CMD_SUCCESS;
}

DEFUN (bgp_default_ipv4_unicast,
       bgp_default_ipv4_unicast_cmd,
       "bgp default ipv4-unicast",
       BGP_STR
       "Default behavior\n"
       "IPv4 unicast\n")
{
  struct bgp *bgp;

  bgp = vty->index;
  UNSET_FLAG (bgp->config, BGP_CONFIG_NO_DEFAULT_IPV4);
  return CMD_SUCCESS;
}

/* allocate new peer object */
struct peer *
peer_new ()
{
  struct peer *peer;
  struct servent *sp;

  /* Allocate new peer. */
  peer = XMALLOC (MTYPE_BGP_PEER, sizeof (struct peer));
  bzero (peer, sizeof (struct peer));

  /* Set default value. */
  peer->fd = -1;
  peer->v_start = BGP_INIT_START_TIMER;
  peer->v_connect = BGP_DEFAULT_CONNECT_RETRY;
  peer->v_holdtime = BGP_DEFAULT_HOLDTIME;
  peer->v_keepalive = BGP_DEFAULT_KEEPALIVE;
  peer->status = Idle;
  peer->ostatus = Idle;
  peer->version = BGP_VERSION_4;
  peer->translate_update  = 0;
  SET_FLAG (peer->flags, PEER_FLAG_SEND_COMMUNITY);
  SET_FLAG (peer->flags, PEER_FLAG_SEND_EXT_COMMUNITY);
  SET_FLAG (peer->sflags, PEER_STATUS_CAPABILITY_OPEN);

  peer->ibuf = stream_new (BGP_MAX_PACKET_SIZE);
  peer->obuf = stream_fifo_new ();
  peer->conf = newlist_new ();

  peer->adj_in[AFI_IP][SAFI_UNICAST] = route_table_init ();
  peer->adj_in[AFI_IP][SAFI_MULTICAST] = route_table_init ();
  peer->adj_in[AFI_IP6][SAFI_UNICAST] = route_table_init ();
  peer->adj_in[AFI_IP6][SAFI_MULTICAST] = route_table_init ();

  peer->adj_out[AFI_IP][SAFI_UNICAST] = route_table_init ();
  peer->adj_out[AFI_IP][SAFI_MULTICAST] = route_table_init ();
  peer->adj_out[AFI_IP][SAFI_MPLS_VPN] = route_table_init ();
  peer->adj_out[AFI_IP6][SAFI_UNICAST] = route_table_init ();
  peer->adj_out[AFI_IP6][SAFI_MULTICAST] = route_table_init ();

  /* Get service port number. */
  sp = getservbyname ("bgp", "tcp");
  peer->port = (sp == NULL) ? BGP_PORT_DEFAULT : ntohs(sp->s_port);

  return peer;
}

/* Check peer's AS number and determin is this peer IBPG or EBGP */
int
peer_sort (struct peer *peer)
{
  /* Find the relevant BGP structure */
  struct bgp *bgp;
  struct peer_conf *conf;
  struct newnode *nn;

  /* This becomes slightly more complicated as we have to find the CONFEDERATION
     list, so we can see if this is a BGP_PEER_CONFED */
  bgp = NULL;
  NEWLIST_LOOP (peer->conf, conf, nn)
    {
      bgp = conf->bgp;
    }

  if(bgp && CHECK_FLAG(bgp->config, BGP_CONFIG_CONFEDERATION))
    {
      if(peer->local_as == 0)
	return BGP_PEER_INTERNAL;

      if(peer->local_as == peer->as)
	{
	  if(peer->local_as == bgp->confederation_id)
	    return BGP_PEER_EBGP;
	  else
	    return BGP_PEER_IBGP;
	}

      if(bgp_confederation_peers_check(bgp, peer->as))
	return BGP_PEER_CONFED;

      return BGP_PEER_EBGP;
    }
  else
    {
      return (peer->local_as == 0
	      ? BGP_PEER_INTERNAL : peer->local_as == peer->as
	      ? BGP_PEER_IBGP : BGP_PEER_EBGP);
    }
}

int
peer_list_cmp (struct peer *p1, struct peer *p2)
{
  return sockunion_cmp (&p1->su, &p2->su);
}

int
peer_conf_cmp (struct peer_conf *p1, struct peer_conf *p2)
{
  return sockunion_cmp (&p1->peer->su, &p2->peer->su);
}

struct peer_conf *
peer_conf_new()
{
  struct peer_conf *pconf;

  pconf = XMALLOC (MTYPE_PEER_CONF, sizeof (struct peer_conf));
  memset (pconf, 0, sizeof (struct peer_conf));
  return pconf;
}

void
peer_conf_free (struct peer_conf *pconf)
{
  XFREE (MTYPE_PEER_CONF, pconf);
}

void
peer_conf_delete (struct peer_conf *conf)
{
  int i;
  struct bgp_filter *filter;

  filter = &conf->filter;

  for (i = 0; i < BGP_FILTER_MAX; i++)
    {
      if (filter->dlist[i].name)
	free (filter->dlist[i].name);
      if (filter->plist[i].name)
	free (filter->plist[i].name);
      if (filter->aslist[i].name)
	free (filter->aslist[i].name);
      if (filter->map[i].name)
	free (filter->map[i].name);
    }
  peer_conf_free (conf);
}

/* BGP instance creation by `router bgp' commands. */
struct bgp *
bgp_create ()
{
  struct bgp *bgp;

  bgp = XMALLOC (MTYPE_BGP, sizeof (struct bgp));
  memset (bgp, 0, sizeof (struct bgp));

  bgp->peer_group = newlist_new ();
  bgp->peer_conf = newlist_new ();
  bgp->peer_conf->cmp = (int (*)(void *, void *)) peer_conf_cmp;

  bgp->route[AFI_IP] = route_table_init ();
  bgp->route[AFI_IP6] = route_table_init ();

  bgp->aggregate[AFI_IP] = route_table_init ();
  bgp->aggregate[AFI_IP6] = route_table_init ();

  bgp->rib[AFI_IP][SAFI_UNICAST] = route_table_init ();
  bgp->rib[AFI_IP][SAFI_MULTICAST] = route_table_init ();
  bgp->rib[AFI_IP][SAFI_MPLS_VPN] = route_table_init ();
  bgp->rib[AFI_IP6][SAFI_UNICAST] = route_table_init ();
  bgp->rib[AFI_IP6][SAFI_MULTICAST] = route_table_init ();

  return bgp;
}

/* Return first entry of BGP. */
struct bgp *
bgp_get_default ()
{
  return newlist_first (bgp_list);
}

/* Lookup BGP entry. */
struct bgp *
bgp_lookup (as_t as, char *name)
{
  struct bgp *bgp;
  struct newnode *nn;

  NEWLIST_LOOP (bgp_list, bgp, nn)
    if (bgp->as == as
	&& ((bgp->name == NULL && name == NULL) 
	    || (bgp->name && name && strcmp (bgp->name, name) == 0)))
      return bgp;
  return NULL;
}

/* Lookup BGP structure by view name. */
struct bgp *
bgp_lookup_by_name (char *name)
{
  struct bgp *bgp;
  struct newnode *nn;

  NEWLIST_LOOP (bgp_list, bgp, nn)
    if ((bgp->name == NULL && name == NULL)
	|| (bgp->name && name && strcmp (bgp->name, name) == 0))
      return bgp;
  return NULL;
}

/* Called from VTY commands. */
int
bgp_get (struct vty *vty, as_t as, char *name)
{
  struct bgp *bgp;

  /* Multiple instance check. */
  if (! bgp_multiple_instance)
    {
      if (name)
	{
	  vty_out (vty, "Please specify 'bgp multiple-instance' first%s",
		   VTY_NEWLINE);
	  return CMD_WARNING;
	}

      /* Get first BGP structure if exists. */
      bgp = bgp_get_default ();

      if (bgp)
	{
	  if (bgp->as != as)
	    {
	      vty_out (vty, "bgp is already running under AS %d%s", bgp->as,
		       VTY_NEWLINE);
	      return CMD_WARNING;
	    }
	  vty->node = BGP_NODE;
	  vty->index = bgp;
	  return CMD_SUCCESS;
	}

      bgp = bgp_create ();
      bgp->as = as;
      newnode_add (bgp_list, bgp);
      vty->node = BGP_NODE;
      vty->index = bgp;
      return CMD_SUCCESS;
    }
  else
    {
      bgp = bgp_lookup (as, name);

      if (bgp)
	{
	  vty->node = BGP_NODE;
	  vty->index = bgp;
	  return CMD_SUCCESS;
	}
      
      bgp = bgp_create ();
      bgp->as = as;
      if (name)
	bgp->name = strdup (name);
      newnode_add (bgp_list, bgp);
      vty->node = BGP_NODE;
      vty->index = bgp;

      return CMD_SUCCESS;
    }
  return CMD_SUCCESS;
}

int
bgp_get_by_str (struct vty *vty, char *as_str, char *name)
{
  char *endptr = NULL;
  as_t as;

  /* Convert string to number. */
  as = strtoul (as_str, &endptr, 10);
  if (as == ULONG_MAX || *endptr != '\0' || as < 1 || as > 65535)
    {
      vty_out (vty, "AS value error%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  return bgp_get (vty, as, name);
}

/* Delete BGP instance. */
void
bgp_delete (struct bgp *bgp)
{
  struct peer_conf *conf;
  struct newnode *nn;
  struct newnode *next;

  bgp->peer_group->del = (void (*)(void *)) peer_group_free;

  newlist_delete (bgp->peer_group);

  for (nn = bgp->peer_conf->head; nn; nn = next)
    {
      conf = nn->data;
      next = nn->next;
      peer_delete (conf->peer);
    }

  /* Clear peer_conf */
  newlist_delete (bgp->peer_conf);

  /* Delete static route. */
  bgp_static_delete (bgp);

  newnode_delete (bgp_list, bgp);

  if (bgp->name)
    free (bgp->name);

  XFREE (MTYPE_BGP, bgp);
}

/* This function is called from VTY command.  Act as a wrapper of
   bgp_delte (). */
int
bgp_destroy (struct vty *vty, char *as_str, char *name)
{
  struct bgp *bgp;
  char *endptr = NULL;
  as_t as;
  /* struct in_addr id; */

  /* Convert string to number. */
  as = strtoul (as_str, &endptr, 10);
  if (as == ULONG_MAX || *endptr != '\0' || as < 1 || as > 65535)
    {
      vty_out (vty, "AS value error%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

#if 0
  /* Convert string to id. */
  if (id_str)
    {
      if (inet_aton (id_str, &id) == 0)
	{
	  vty_out (vty, "router id string error: %s%s", id_str, VTY_NEWLINE);
	  return CMD_WARNING;
	}
    }
  else
    id.s_addr = 0;
#endif /* 0 */

  /* Lookup bgp structure. */
  bgp = bgp_lookup (as, name);

  if (!bgp)
    {
      vty_out (vty, "Can't find BGP instance%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  bgp_delete (bgp);

  return CMD_SUCCESS;
}

/* `router bgp' commands. */
DEFUN (router_bgp, 
       router_bgp_cmd, 
       "router bgp <1-65535>",
       ROUTER_STR
       BGP_STR
       AS_STR)
{
  return bgp_get_by_str (vty, argv[0], NULL);
}

DEFUN (router_bgp_view,
       router_bgp_view_cmd,
       "router bgp <1-65535> view WORD",
       ROUTER_STR
       BGP_STR
       AS_STR
       "BGP view\n"
       "view name\n")
{
  return bgp_get_by_str (vty, argv[0], argv[1]);
}

/* `no router bgp' commands. */
DEFUN (no_router_bgp,
       no_router_bgp_cmd,
       "no router bgp <1-65535>",
       NO_STR
       ROUTER_STR
       BGP_STR
       AS_STR)
{
  return bgp_destroy (vty, argv[0], NULL);
}

DEFUN (no_router_bgp_view,
       no_router_bgp_view_cmd,
       "no router bgp <1-65535> view WORD",
       NO_STR
       ROUTER_STR
       BGP_STR
       AS_STR
       "BGP view\n"
       "view name\n")
{
  return bgp_destroy (vty, argv[0], argv[1]);
}

/* Peer identification.

   Peer structure is identified by it's IP address, local AS number,
   remote AS number and local router-id.  Normally, local router-id
   identification is used only for Merit MRT like route server
   configuration.

   When user configure the peer under specific BGP instance node, only
   IP address and local AS number are used for looking up.  If the
   peer's remote AS number and user configuration AS number is
   different, the peer's AS number is changed. */

struct peer *
peer_lookup_with_local_as (union sockunion *su, as_t local_as)
{
  struct peer *peer;
  struct newnode *nn;

  NEWLIST_LOOP (peer_list, peer, nn)
    {
      if (sockunion_same (&peer->su, su) 
	  && peer->local_as == local_as)
	return peer;
    }
  return NULL;
}

/* Accepting remote BGP connection, at least remote connection's
   source IP address is configured as a peer.  This function check the
   existance of the IP address. */

struct peer *
peer_lookup_by_su (union sockunion *su)
{
  struct peer *peer;
  struct newnode *nn;

  NEWLIST_LOOP (peer_list, peer, nn)
    {
      if (sockunion_same (&peer->su, su))
	return peer;
    }
  return NULL;
}

/* BGP Open packet includes remote router's AS number and router-id.
   We lookup local peer with those information.  First loop check
   exact match peer including remote router-id.  Second loop check
   anonymous router-id peer.  */

struct peer *
peer_lookup_with_open (union sockunion *su, as_t remote_as,
		       struct in_addr *remote_id)
{
  struct peer *peer;
  struct newnode *nn;

  NEWLIST_LOOP (peer_list, peer, nn)
    {
      if (sockunion_same (&peer->su, su)
	  && (peer->as == remote_as) 
	  && (peer->remote_id.s_addr == remote_id->s_addr))
	return peer;
    }
  NEWLIST_LOOP (peer_list, peer, nn)
    {
      if (sockunion_same (&peer->su, su)
	  && (peer->as == remote_as) 
	  && (peer->remote_id.s_addr == 0))
	return peer;
    }
  return NULL;
}

struct peer_conf *
peer_conf_lookup (struct bgp *bgp, union sockunion *su, int afi)
{
  struct newnode *nn;
  struct peer_conf *conf;

  NEWLIST_LOOP (bgp->peer_conf, conf, nn)
    {
      if (sockunion_same (&conf->peer->su, su))
	{
	  if (afi == AFI_IP && (conf->afc[AFI_IP][SAFI_UNICAST]
				|| conf->afc[AFI_IP][SAFI_MULTICAST]))
	    return conf;
	  if (afi == AFI_IP6 && (conf->afc[AFI_IP6][SAFI_UNICAST] 
				 || conf->afc[AFI_IP6][SAFI_MULTICAST]))
	    return conf;
	  if (afi == AFI_IP && (! peer_active (conf->peer)))
	    return conf;
	}
    }
  return NULL;
}

/* Utility function for lookup peer from VTY commands. */
struct peer_conf *
peer_conf_lookup_vty (struct vty *vty, char *ip_str, int afi)
{
  int ret;
  struct bgp *bgp;
  union sockunion su;
  struct peer_conf *conf;

  bgp = vty->index;

  ret = str2sockunion (ip_str, &su);
  if (ret < 0)
    {
      vty_out (vty, "Malformed address: %s%s", ip_str, VTY_NEWLINE);
      return NULL;
    }

  conf = peer_conf_lookup (bgp, &su, afi);
  if (! conf)
    {
      vty_out (vty, "Can't find peer: %s%s", ip_str, VTY_NEWLINE);
      return NULL;
    }
  return conf;
}

struct peer_conf *
peer_conf_lookup_existing (struct bgp *bgp, union sockunion *su)
{
  struct newnode *nn;
  struct peer_conf *conf;

  NEWLIST_LOOP (bgp->peer_conf, conf, nn)
    {
      if (sockunion_same (&conf->peer->su, su))
	return conf;
    }
  return NULL;
}

#define BGP_UPTIME_LEN 25

/* Display peer uptime. */
char *
peer_uptime (struct peer *peer, char *buf, size_t len)
{
  time_t uptime;
  struct tm *tm;

  /* Check buffer length. */
  if (len < BGP_UPTIME_LEN)
    {
      zlog_warn ("peer_uptime (): buffer shortage %s", len);
      return "";
    }

  /* If there is no connection has been done before print `never'. */
  if (peer->uptime == 0)
    {
      snprintf (buf, len, "never   ");
      return buf;
    }

  /* Get current time. */
  uptime = time (NULL);
  uptime -= peer->uptime;
  tm = gmtime (&uptime);

  /* Making formatted timer strings. */
#define ONE_DAY_SECOND 60*60*24
#define ONE_WEEK_SECOND 60*60*24*7

  if (uptime < ONE_DAY_SECOND)
    snprintf (buf, len, "%02d:%02d:%02d", 
	      tm->tm_hour, tm->tm_min, tm->tm_sec);
  else if (uptime < ONE_WEEK_SECOND)
    snprintf (buf, len, "%dd%02dh%02dm", 
	      tm->tm_yday, tm->tm_hour, tm->tm_min);
  else
    snprintf (buf, len, "%02dw%dd%02dh", 
	      tm->tm_yday/7, tm->tm_yday - ((tm->tm_yday/7) * 7), tm->tm_hour);
  return buf;
}

/* If peer is configured at least one address family return 1. */
int
peer_active (struct peer *peer)
{
  if (peer->afc[AFI_IP][SAFI_UNICAST]
      || peer->afc[AFI_IP][SAFI_MULTICAST]
      || peer->afc[AFI_IP][SAFI_MPLS_VPN]
      || peer->afc[AFI_IP6][SAFI_UNICAST]
      || peer->afc[AFI_IP6][SAFI_MULTICAST])
    return 1;
  return 0;
}

struct peer *
peer_create (union sockunion *su, as_t local_as, struct in_addr id,
	     as_t remote_as)
{
  struct peer *peer;
  char buf[SU_ADDRSTRLEN];

  peer = peer_new ();
  peer->su = *su;
  peer->local_as = local_as;
  peer->as = remote_as;
  peer->local_id = id;
  newnode_add (peer_list, peer);

  /* Default TTL set. */
  peer->ttl = (peer_sort (peer) == BGP_PEER_IBGP ? 255 : 1);

  /* Make peer's address string. */
  sockunion2str (su, buf, SU_ADDRSTRLEN);
  peer->host = strdup (buf);

  /* Set up peer's events and timers. */
  bgp_timer_set (peer);

  return peer;
}

/* Make accept BGP peer.  Called from bgp_accept (). */
struct peer *
peer_create_accept ()
{
  struct peer *peer;

  peer = peer_new ();
  newnode_add (peer_list, peer);

  return peer;
}

/* Change peer's AS number */
int
peer_as_change (struct peer *peer, as_t as)
{
  /* Stop peer. */
  bgp_stop (peer);

  peer->as = as;

  /* ebgp-multihop reset. */

  return CMD_SUCCESS;
}

struct peer_conf *
peer_conf_create (int afi, int safi, struct peer *peer)
{
  struct peer_conf *conf;
  int active;

  /* Make new peer configuration then link it to the peer. */
  conf = peer_conf_new ();
  conf->peer = peer;
  newnode_add (peer->conf, conf);

  /* Store peer's active status. */
  active = peer_active (peer);

  if (safi & SAFI_UNICAST)
    {
      conf->afc[afi][SAFI_UNICAST] = 1;
      peer->afc[afi][SAFI_UNICAST]++;
    }
  if (safi & SAFI_MULTICAST)
    {
      conf->afc[afi][SAFI_MULTICAST] = 1;
      peer->afc[afi][SAFI_MULTICAST]++;
    }
  if (safi == SAFI_MPLS_VPN)
    {
      conf->afc[afi][safi] = 1;
      peer->afc[afi][safi]++;
    }

  /* If this configuration activate the peer, set start timer. */
  if (! active && peer_active (peer))
    bgp_timer_set (peer);

  return conf;
}

void
peer_conf_active (int afi, int safi, struct peer_conf *conf)
{
  int active;
  struct peer *peer;

  peer = conf->peer;
  active = peer_active (peer);

  conf->afc[afi][safi] = 1;
  conf->peer->afc[afi][safi]++;

  /* If this configuration activate the peer, set start timer. */
  if (! active && peer_active (peer))
    bgp_timer_set (peer);
}

void
peer_conf_deactive (int afi, int safi, struct peer_conf *conf)
{
  struct peer *peer;

  peer = conf->peer;

  /* Must be configured. */
  if (! conf->afc[afi][safi])
    return;

  conf->afc[afi][safi] = 0;
  peer->afc[afi][safi]--;

  if (! peer_active (peer))
    BGP_EVENT_ADD (peer, BGP_Stop);
}

/* Set peer to passive mode. */
int
peer_passive_set (struct peer *peer)
{
  /* Already passive mode. */
  if (CHECK_FLAG (peer->flags, PEER_FLAG_PASSIVE))
    return CMD_SUCCESS;

  SET_FLAG (peer->flags, PEER_FLAG_PASSIVE);

  /* Change status from Idle -> Active if status is Idle. */
  if (peer->status == Idle)
    {
      peer->status = Active;
      bgp_timer_set (peer);
    }

  return CMD_SUCCESS;
}

int
peer_passive_unset (struct peer *peer)
{
  UNSET_FLAG (peer->flags, PEER_FLAG_PASSIVE);
  return CMD_SUCCESS;
}

/* Make or change remote peer's AS number. */
int
peer_remote_as (struct vty *vty, char *ip_str, char *as_str, int afi, int safi,
		int passive)
{
  int ret;
  struct bgp *bgp;
  char *endptr = NULL;
  as_t as;
  union sockunion su;
  struct peer *peer;
  struct peer_conf *conf;

  ret = str2sockunion (ip_str, &su);
  if (ret < 0)
    {
      vty_out (vty, "Malformed address: %s%s", ip_str, VTY_NEWLINE);
      return CMD_WARNING;
    }

  as = strtoul (as_str, &endptr, 10);
  if (as == ULONG_MAX || *endptr != '\0' || as < 1 || as > 65535)
    {
      vty_out (vty, "AS value error: %s%s", as_str, VTY_NEWLINE);
      return CMD_WARNING;
    }

  bgp = vty->index;

  peer = peer_lookup_with_local_as (&su, bgp->as);
  if (CHECK_FLAG(bgp->config, BGP_CONFIG_CONFEDERATION) && ! peer)
    {
      peer = peer_lookup_with_local_as (&su, bgp->confederation_id);
    }

  if (peer)
    {
      /* Lookup peer_conf */
      conf = peer_conf_lookup (bgp, &su, afi);

      if (! conf)
	{
	  /* New peer configuration. */
	  conf = peer_conf_create (afi, safi, peer);
	  conf->bgp = bgp;
	  newnode_add (bgp->peer_conf, conf);
	}

      /* Existing peer's AS number change. */
      if (peer->as != as)
	peer_as_change (peer, as);

      /* Existing peer's SAFI change. */
      /* XXXX need code here. */;
    }
  else
    {
      /* Real peer creation. */

      /* If the peer is not part of our CONFED, and its not an iBGP peer then
	 spoof the source AS */
      if (CHECK_FLAG (bgp->config, BGP_CONFIG_CONFEDERATION) 
	  && ! bgp_confederation_peers_check(bgp, as) 
	  && bgp->as != as)
        {
          peer = peer_create (&su, bgp->confederation_id, bgp->id, as); 
        }
      else
	{
	  peer = peer_create (&su, bgp->as, bgp->id, as);
	}

      /* If this is IPv4 unicast configuration and "no bgp default
         ipv4-unicast" is specified. */
      if (CHECK_FLAG (bgp->config, BGP_CONFIG_NO_DEFAULT_IPV4)
	  && afi == AFI_IP && safi == SAFI_UNICAST)
	conf = peer_conf_create (0, 0, peer);
      else
	conf = peer_conf_create (afi, safi, peer);

      conf->bgp = bgp;
      newnode_add (bgp->peer_conf, conf);
    }

  /* Passive flag set. */
  if (passive)
    peer_passive_set (peer);

  return CMD_SUCCESS;
}

int
peer_activate (struct vty *vty, char *ip_str, int afi, int safi)
{
  int ret;
  union sockunion su;
  struct bgp *bgp;
  struct peer_conf *conf;

  bgp = vty->index;

  /* Lookup peer. */
  ret = str2sockunion (ip_str, &su);
  if (ret < 0)
    {
      vty_out (vty, "Malformed address: %s%s", ip_str, VTY_NEWLINE);
      return CMD_WARNING;
    }

  conf = peer_conf_lookup_existing (bgp, &su);
  if (! conf)
    {
      vty_out (vty, "Specify remote-as under \"router bgp ASN\" first%s",
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Activate the address family configuration. */
  if (! conf->afc[afi][safi])
    peer_conf_active (afi, safi, conf);

  return CMD_SUCCESS;
}

int
peer_deactivate (struct vty *vty, char *ip_str, int afi, int safi)
{
  int ret;
  union sockunion su;
  struct bgp *bgp;
  struct peer_conf *conf;

  bgp = vty->index;

  /* Lookup peer. */
  ret = str2sockunion (ip_str, &su);
  if (ret < 0)
    {
      vty_out (vty, "Malformed address: %s%s", ip_str, VTY_NEWLINE);
      return CMD_WARNING;
    }

  conf = peer_conf_lookup_existing (bgp, &su);
  if (! conf)
    {
      vty_out (vty, "Can't find the peer%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* De-activate the address family configuration. */
  if (conf->afc[afi][safi])
    peer_conf_deactive (afi, safi, conf);

  return CMD_SUCCESS;

}

/* Delete peer from confguration. */
void
peer_delete (struct peer *peer)
{
  struct peer_conf *conf;
  struct newnode *nn;

  /* Withdraw all information from routing table.  We can not use
     BGP_EVENT_ADD (peer, BGP_Stop) at here.  Because the event is
     executed after peer structure is deleted. */
  bgp_stop (peer);
  fsm_change_status (peer, Idle);

  /* Delete peer_conf link from BGP structure. */
  NEWLIST_LOOP (peer->conf, conf, nn)
    {
      newnode_delete (conf->bgp->peer_conf, conf);
    }

  /* Free peer_conf structure. */
  peer->conf->del = (void (*) (void *)) peer_conf_delete;
  newlist_delete (peer->conf);
  peer->conf = NULL;

  /* Stop all timers. */
  BGP_TIMER_OFF (peer->t_start);
  BGP_TIMER_OFF (peer->t_keepalive);
  BGP_TIMER_OFF (peer->t_holdtime);
  BGP_TIMER_OFF (peer->t_connect);
  BGP_TIMER_OFF (peer->t_asorig);
  BGP_TIMER_OFF (peer->t_routeadv);

  /* Delete from all peer list. */
  newnode_delete (peer_list, peer);

  if (peer->ibuf)
    stream_free (peer->ibuf);

  /* Free allocated host character. */
  if (peer->host)
    free (peer->host);

  /* Local and remote addresses. */
  if (peer->su_local)
    XFREE (MTYPE_TMP, peer->su_local);
  if (peer->su_remote)
    XFREE (MTYPE_TMP, peer->su_remote);

  /* Free peer structure. */
  XFREE (MTYPE_BGP_PEER, peer);
}

int
peer_destroy (struct vty *vty, char *ip_str, char *as_str, int afi, int safi,
	      int passive)
{
  int ret;
  struct bgp *bgp;
  char *endptr = NULL;
  as_t as = 0;
  union sockunion su;
  struct peer *peer;

  ret = str2sockunion (ip_str, &su);
  if (ret < 0)
    {
      vty_out (vty, "Malformed address: %s%s", ip_str, VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (as_str)
    {
      as = strtoul (as_str, &endptr, 10);
      if (as == ULONG_MAX || *endptr != '\0' || as < 1 || as > 65535)
	{
	  vty_out (vty, "AS value error: %s%s", as_str, VTY_NEWLINE);
	  return CMD_WARNING;
	}
    }

  bgp = vty->index;

  peer = peer_lookup_with_local_as (&su, bgp->as);
  if (CHECK_FLAG(bgp->config, BGP_CONFIG_CONFEDERATION) && !peer)
    {
      peer = peer_lookup_with_local_as (&su, bgp->confederation_id);
    }

  if (! peer)
    {
      vty_out (vty, "Can't find peer: %s%s", ip_str, VTY_NEWLINE);
      return CMD_WARNING;
    }
  if (as_str && peer->as != as)
    {
      vty_out (vty, "AS mismatch%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  peer_delete (peer);

  return CMD_SUCCESS;
}

/* Change specified peer flag. */
int
peer_change_flag (struct vty *vty, char *ip_str, int afi, u_int16_t flag,
		  int set)
{
  struct peer *peer;
  struct peer_conf *conf;

  conf = peer_conf_lookup_vty (vty, ip_str, afi);
  if (! conf)
    return CMD_WARNING;
  peer = conf->peer;
  
  if (set)
    SET_FLAG (peer->flags, flag);
  else
    UNSET_FLAG (peer->flags, flag);
  return CMD_SUCCESS;
}

/* Change specified peer flag with resetting the connection.  If the
   flag is not changed nothing occur. */
int
peer_change_flag_with_reset (struct vty *vty, char *ip_str, int afi,
			     u_int16_t flag, int set)
{
  struct peer *peer;
  struct peer_conf *conf;

  conf = peer_conf_lookup_vty (vty, ip_str, afi);
  if (! conf)
    return CMD_WARNING;
  peer = conf->peer;

  if (set)
    {
      if (! CHECK_FLAG (peer->flags, flag))
	{
	  SET_FLAG (peer->flags, flag);
	  BGP_EVENT_ADD (peer, BGP_Stop);
	}
    }
  else
    {
      if (CHECK_FLAG (peer->flags, flag))
	{
	  UNSET_FLAG (peer->flags, flag);
	  BGP_EVENT_ADD (peer, BGP_Stop);
	}
    }
  return CMD_SUCCESS;
}

DEFUN (neighbor_remote_as,
       neighbor_remote_as_cmd,
       NEIGHBOR_CMD "remote-as <1-65535>",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Specify a BGP neighbor\n"
       AS_STR)
{
  return peer_remote_as (vty, argv[0], argv[1], AFI_IP, SAFI_UNICAST, 0);
}

DEFUN (neighbor_remote_as_passive,
       neighbor_remote_as_passive_cmd,
       NEIGHBOR_CMD "remote-as <1-65535> passive",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Specify a BGP neighbor\n"
       AS_STR
       "Passive mode\n")
{
  return peer_remote_as (vty, argv[0], argv[1], AFI_IP, SAFI_UNICAST, 1);
}

DEFUN (neighbor_remote_as_unicast,
       neighbor_remote_as_unicast_cmd,
       NEIGHBOR_CMD "remote-as <1-65535> nlri unicast",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Specify a BGP neighbor\n"
       AS_STR
       "Network Layer Reachable Information\n"
       "Configure for unicast routes\n")
{
  return peer_remote_as (vty, argv[0], argv[1], AFI_IP, SAFI_UNICAST, 0);
}

DEFUN (neighbor_remote_as_multicast,
       neighbor_remote_as_multicast_cmd,
       NEIGHBOR_CMD "remote-as <1-65535> nlri multicast",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Specify a BGP neighbor\n"
       AS_STR
       "Network Layer Reachable Information\n"
       "Configure for multicast routes\n")
{
  return peer_remote_as (vty, argv[0], argv[1], AFI_IP, SAFI_MULTICAST, 0);
}

DEFUN (neighbor_remote_as_unicast_multicast,
       neighbor_remote_as_unicast_multicast_cmd,
       NEIGHBOR_CMD "remote-as <1-65535> nlri unicast multicast",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Specify a BGP neighbor\n"
       AS_STR
       "Network Layer Reachable Information\n"
       "Configure for unicast routes\n"
       "Configure for multicast routes\n")
{
  return peer_remote_as (vty, argv[0], argv[1], AFI_IP, SAFI_UNICAST_MULTICAST, 0);
}

DEFUN (neighbor_activate,
       neighbor_activate_cmd,
       NEIGHBOR_CMD "activate",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Enable the Address Family for this Neighbor\n")
{
  return peer_activate (vty, argv[0], AFI_IP, SAFI_UNICAST);
}

DEFUN (no_neighbor_activate,
       no_neighbor_activate_cmd,
       NO_NEIGHBOR_CMD "activate",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Enable the Address Family for this Neighbor\n")
{
  return peer_deactivate (vty, argv[0], AFI_IP, SAFI_UNICAST);
}

#ifdef HAVE_IPV6
DEFUN (ipv6_bgp_neighbor, 
       ipv6_bgp_neighbor_cmd, 
       "ipv6 bgp neighbor (A.B.C.D|X:X::X:X) remote-as <1-65535>",
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Specify a BGP neighbor\n"
       AS_STR)
{
  return peer_remote_as (vty, argv[0], argv[1], AFI_IP6, SAFI_UNICAST, 0);
}

DEFUN (ipv6_bgp_neighbor_passive, 
       ipv6_bgp_neighbor_passive_cmd, 
       "ipv6 bgp neighbor (A.B.C.D|X:X::X:X) remote-as <1-65535> passive",
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Specify a BGP neighbor\n"
       AS_STR
       "Passive mode\n")
{
  return peer_remote_as (vty, argv[0], argv[1], AFI_IP6, SAFI_UNICAST, 1);
}

DEFUN (ipv6_bgp_neighbor_unicast, 
       ipv6_bgp_neighbor_unicast_cmd, 
       "ipv6 bgp neighbor (A.B.C.D|X:X::X:X) remote-as <1-65535> nlri unicast",
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Specify a BGP neighbor\n"
       AS_STR
       "Network Layer Reachable Information\n"
       "Configure for unicast routes\n")
{
  return peer_remote_as (vty, argv[0], argv[1], AFI_IP6, SAFI_UNICAST, 0);
}

DEFUN (ipv6_bgp_neighbor_multicast, 
       ipv6_bgp_neighbor_multicast_cmd, 
       "ipv6 bgp neighbor (A.B.C.D|X:X::X:X) remote-as <1-65535> nlri multicast",
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Specify a BGP neighbor\n"
       AS_STR
       "Network Layer Reachable Information\n"
       "Configure for multicast routes\n")
{
  return peer_remote_as (vty, argv[0], argv[1], AFI_IP6, SAFI_MULTICAST, 0);
}

DEFUN (ipv6_bgp_neighbor_unicast_multicast, 
       ipv6_bgp_neighbor_unicast_multicast_cmd, 
       "ipv6 bgp neighbor (A.B.C.D|X:X::X:X) remote-as <1-65535> nlri unicast multicast",
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Specify a BGP neighbor\n"
       AS_STR
       "Network Layer Reachable Information\n"
       "Configure for unicast routes\n"
       "Configure for multicast routes\n")
{
  return peer_remote_as (vty, argv[0], argv[1], AFI_IP6, SAFI_UNICAST_MULTICAST, 0);
}

#endif /* HAVE_IPV6 */

DEFUN (no_neighbor,
       no_neighbor_cmd,
       NO_NEIGHBOR_CMD,
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR)
{
  return peer_destroy (vty, argv[0], NULL, AFI_IP, SAFI_UNICAST, 0);
}

DEFUN (no_neighbor_remote_as,
       no_neighbor_remote_as_cmd,
       NO_NEIGHBOR_CMD "remote-as <1-65535>",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Specify a BGP neighbor\n"
       AS_STR)
{
  return peer_destroy (vty, argv[0], argv[1], AFI_IP, SAFI_UNICAST, 0);
}

DEFUN (no_ipv6_bgp_neighbor,
       no_ipv6_bgp_neighbor_cmd,
       "no ipv6 bgp neighbor (A.B.C.D|X:X::X:X)",
       NO_STR
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP Address\n"
       "IPv6 Address\n")
{
  return peer_destroy (vty, argv[0], NULL, AFI_IP6, SAFI_UNICAST, 0);
}

DEFUN (no_ipv6_bgp_neighbor_remote_as,
       no_ipv6_bgp_neighbor_remote_as_cmd,
       "no ipv6 bgp neighbor (A.B.C.D|X:X::X:X) remote-as <1-65535>",
       NO_STR
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP Address\n"
       "IPv6 Address\n"
       "Specify a BGP neighbor\n"
       AS_STR)
{
  return peer_destroy (vty, argv[0], argv[1], AFI_IP6, SAFI_UNICAST, 0);
}

/* router-id set. */
int
peer_router_id (struct vty *vty, char *ip_str, int afi, char *id_str)
{
  struct peer *peer;
  struct peer_conf *conf;
  struct in_addr id;
  int ret;

  conf = peer_conf_lookup_vty (vty, ip_str, afi);
  if (! conf)
    return CMD_WARNING;

  peer = conf->peer;

  if (id_str)
    {
      ret = inet_aton (id_str, &id);
      if (! ret)
	{
	  vty_out (vty, "Malformed router identifier: %s%s", id_str,
		   VTY_NEWLINE);
	  return CMD_WARNING;
	}
      peer->remote_id = id;
    }
  else
    {
      peer->remote_id.s_addr = 0;
    }

  return CMD_SUCCESS;
}

DEFUN (neighbor_router_id,
       neighbor_router_id_cmd,
       NEIGHBOR_CMD "router-id A.B.C.D",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Set neighbor's special router-id value\n"
       "IP address\n")
{
  return peer_router_id (vty, argv[0], AFI_IP, argv[1]);
}

DEFUN (no_neighbor_router_id,
       no_neighbor_router_id_cmd,
       NO_NEIGHBOR_CMD "router-id A.B.C.D",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Set neighbor's special router-id value\n"
       "IP address\n")
{
  return peer_router_id (vty, argv[0], AFI_IP, NULL);
}

/* neighbor shutdown. */
DEFUN (neighbor_shutdown,
       neighbor_shutdown_cmd,
       NEIGHBOR_CMD "shutdown",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Administratively shut down this neighbor\n")
{
  return peer_change_flag_with_reset (vty, argv[0], AFI_IP,
				      PEER_FLAG_SHUTDOWN, 1);
}

DEFUN (no_neighbor_shutdown,
       no_neighbor_shutdown_cmd,
       NO_NEIGHBOR_CMD "shutdown",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Administratively shut down this neighbor\n")
{
  return peer_change_flag_with_reset (vty, argv[0], AFI_IP,
				      PEER_FLAG_SHUTDOWN, 0);
}

DEFUN (ipv6_bgp_neighbor_shutdown,
       ipv6_bgp_neighbor_shutdown_cmd,
       "ipv6 bgp neighbor (A.B.C.D|X:X::X:X) shutdown",
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Administratively shut down this neighbor\n")
{
  return peer_change_flag_with_reset (vty, argv[0], AFI_IP6,
				      PEER_FLAG_SHUTDOWN, 1);
}

DEFUN (no_ipv6_bgp_neighbor_shutdown,
       no_ipv6_bgp_neighbor_shutdown_cmd,
       "no ipv6 bgp neighbor (A.B.C.D|X:X::X:X) shutdown",
       NO_STR
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Administratively shut down this neighbor\n")
{
  return peer_change_flag_with_reset (vty, argv[0], AFI_IP6,
				      PEER_FLAG_SHUTDOWN, 0);
}

/* neighbor ebgp-multihop. */
int
peer_ebgp_multihop_set (struct vty *vty, char *ip_str, char *ttl_str, int afi)
{
  struct peer *peer;
  struct peer_conf *conf;
  int ttl = TTL_MAX;

  conf = peer_conf_lookup_vty (vty, ip_str, afi);
  if (! conf)
    return CMD_WARNING;

  if (ttl_str)
    ttl = atoi (ttl_str);

  if (ttl == 0)
    {
      vty_out (vty, "TTL value error: %s%s", ttl_str, VTY_NEWLINE);
      return CMD_WARNING;
    }

  peer = conf->peer;
  if (peer_sort (peer) == BGP_PEER_IBGP)
    {
      vty_out (vty, "peer is IBGP peer%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  peer->ttl = ttl;

  /* Set runnning connection's ttl. */
  if (peer->fd >= 0)
    sockopt_ttl (peer->su.sa.sa_family, peer->fd, peer->ttl);

  return CMD_SUCCESS;
}

int
peer_ebgp_multihop_unset (struct vty *vty, char *ip_str, char *ttl_str,
			  int afi)
{
  struct peer *peer;
  struct peer_conf *conf;
  int ttl = TTL_MAX;

  conf = peer_conf_lookup_vty (vty, ip_str, afi);
  if (! conf)
    return CMD_WARNING;

  if (ttl_str)
    ttl = atoi (ttl_str);

  if (ttl == 0)
    {
      vty_out (vty, "TTL value error: %s%s", ttl_str, VTY_NEWLINE);
      return CMD_WARNING;
    }

  peer = conf->peer;
  if (peer_sort (peer) == BGP_PEER_IBGP)
    {
      vty_out (vty, "peer is IBGP peer%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Set default EBGP TTL. */
  peer->ttl = 1;

  /* Set runnning connection's ttl. */
  if (peer->fd >= 0)
    sockopt_ttl (peer->su.sa.sa_family, peer->fd, peer->ttl);

  return CMD_SUCCESS;
}

/* neighbor ebgp-multihop. */
DEFUN (neighbor_ebgp_multihop,
       neighbor_ebgp_multihop_cmd,
       NEIGHBOR_CMD "ebgp-multihop",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Allow EBGP neighbors not on directly connected networks\n")
{
  return peer_ebgp_multihop_set (vty, argv[0], NULL, AFI_IP);
}

DEFUN (neighbor_ebgp_multihop_ttl,
       neighbor_ebgp_multihop_ttl_cmd,
       NEIGHBOR_CMD "ebgp-multihop <1-255>",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Allow EBGP neighbors not on directly connected networks\n"
       "maximum hop count\n")
{
  return peer_ebgp_multihop_set (vty, argv[0], argv[1], AFI_IP);
}

DEFUN (no_neighbor_ebgp_multihop,
       no_neighbor_ebgp_multihop_cmd,
       NO_NEIGHBOR_CMD "ebgp-multihop",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Allow EBGP neighbors not on directly connected networks\n")
{
  return peer_ebgp_multihop_unset (vty, argv[0], NULL, AFI_IP);
}

DEFUN (no_neighbor_ebgp_multihop_ttl,
       no_neighbor_ebgp_multihop_ttl_cmd,
       NO_NEIGHBOR_CMD "ebgp-multihop <1-255>",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Allow EBGP neighbors not on directly connected networks\n"
       "maximum hop count\n")
{
  return peer_ebgp_multihop_unset (vty, argv[0], argv[1], AFI_IP);
}

DEFUN (ipv6_bgp_neighbor_ebgp_multihop,
       ipv6_bgp_neighbor_ebgp_multihop_cmd,
       "ipv6 bgp neighbor (A.B.C.D|X:X::X:X) ebgp-multihop",
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Allow EBGP neighbors not on directly connected networks\n")
{
  return peer_ebgp_multihop_set (vty, argv[0], NULL, AFI_IP6);
}

DEFUN (ipv6_bgp_neighbor_ebgp_multihop_ttl,
       ipv6_bgp_neighbor_ebgp_multihop_ttl_cmd,
       "ipv6 bgp neighbor (A.B.C.D|X:X::X:X) ebgp-multihop <1-255>",
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Allow EBGP neighbors not on directly connected networks\n"
       "maximum hop count\n")
{
  return peer_ebgp_multihop_set (vty, argv[0], argv[1], AFI_IP6);
}

DEFUN (no_ipv6_bgp_neighbor_ebgp_multihop,
       no_ipv6_bgp_neighbor_ebgp_multihop_cmd,
       "no ipv6 bgp neighbor (A.B.C.D|X:X::X:X) ebgp-multihop",
       NO_STR
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Allow EBGP neighbors not on directly connected networks\n")
{
  return peer_ebgp_multihop_unset (vty, argv[0], NULL, AFI_IP6);
}

DEFUN (no_ipv6_bgp_neighbor_ebgp_multihop_ttl,
       no_ipv6_bgp_neighbor_ebgp_multihop_ttl_cmd,
       "no ipv6 bgp neighbor (A.B.C.D|X:X::X:X) ebgp-multihop <1-255>",
       NO_STR
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Allow EBGP neighbors not on directly connected networks\n"
       "maximum hop count\n")
{
  return peer_ebgp_multihop_unset (vty, argv[0], argv[1], AFI_IP6);
}

/* neighbor description. */
int
peer_description_set (struct vty *vty, char *ip_str, int afi, char *str)
{
  struct peer *peer;
  struct peer_conf *conf;

  conf = peer_conf_lookup_vty (vty, ip_str, afi);
  if (! conf)
    return CMD_WARNING;
  peer = conf->peer;

  if (peer->desc)
    XFREE (MTYPE_TMP, peer->desc);
  peer->desc = str;
  return CMD_SUCCESS;
}

int
peer_description_unset (struct vty *vty, char *ip_str, int afi)
{
  struct peer *peer;
  struct peer_conf *conf;

  conf = peer_conf_lookup_vty (vty, ip_str, afi);
  if (! conf)
    return CMD_WARNING;
  peer = conf->peer;

  if (peer->desc)
    XFREE (MTYPE_TMP, peer->desc);
  peer->desc = NULL;
  return CMD_SUCCESS;
}

DEFUN (neighbor_description,
       neighbor_description_cmd,
       NEIGHBOR_CMD "description .LINE",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Neighbor specific description\n"
       "Up to 80 characters describing this neighbor\n")
{
  int i;
  struct buffer *b;
  char *str;

  if (argc == 1)
    return CMD_SUCCESS;

  /* Make string from buffer.  This function should be provided by
     buffer.c. */
  b = buffer_new (BUFFER_STRING, 1024);
  for (i = 1; i < argc; i++)
    {
      buffer_putstr (b, (u_char *)argv[i]);
      buffer_putc (b, ' ');
    }
  buffer_putc (b, '\0');
  str = buffer_getstr (b);
  buffer_free (b);

  return peer_description_set (vty, argv[0], AFI_IP, str);
}

DEFUN (no_neighbor_description,
       no_neighbor_description_cmd,
       NO_NEIGHBOR_CMD "description .LINE",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Neighbor specific description\n"
       "Up to 80 characters describing this neighbor\n")
{
  return peer_description_unset (vty, argv[0], AFI_IP);
}

DEFUN (ipv6_bgp_neighbor_description,
       ipv6_bgp_neighbor_description_cmd,
       "ipv6 bgp neighbor (A.B.C.D|X:X::X:X) description .LINE",
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Neighbor specific description\n"
       "Up to 80 characters describing this neighbor\n")
{
  int i;
  struct buffer *b;
  char *str;

  if (argc == 1)
    return CMD_SUCCESS;

  b = buffer_new (BUFFER_STRING, 1024);
  for (i = 1; i < argc; i++)
    {
      buffer_putstr (b, (u_char *)argv[i]);
      buffer_putc (b, ' ');
    }
  buffer_putc (b, '\0');
  str = buffer_getstr (b);
  buffer_free (b);

  return peer_description_set (vty, argv[0], AFI_IP6, str);
}

DEFUN (no_ipv6_bgp_neighbor_description,
       no_ipv6_bgp_neighbor_description_cmd,
       "no ipv6 bgp neighbor (A.B.C.D|X:X::X:X) description .LINE",
       NO_STR
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Neighbor specific description\n"
       "Up to 80 characters describing this neighbor\n")
{
  return peer_description_unset (vty, argv[0], AFI_IP6);
}

/* neighbor next-hop-self. */
DEFUN (neighbor_nexthop_self,
       neighbor_nexthop_self_cmd,
       NEIGHBOR_CMD "next-hop-self",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Disable the next hop calculation for this neighbor\n")
{
  return peer_change_flag (vty, argv[0], AFI_IP, PEER_FLAG_NEXTHOP_SELF, 1);
}

DEFUN (no_neighbor_nexthop_self,
       no_neighbor_nexthop_self_cmd,
       NO_NEIGHBOR_CMD "next-hop-self",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Disable the next hop calculation for this neighbor\n")
{
  return peer_change_flag (vty, argv[0], AFI_IP, PEER_FLAG_NEXTHOP_SELF, 0);
}

DEFUN (ipv6_bgp_neighbor_nexthop_self,
       ipv6_bgp_neighbor_nexthop_self_cmd,
       "ipv6 bgp neighbor (A.B.C.D|X:X::X:X) next-hop-self",
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Disable the next hop calculation for this neighbor\n")
{
  return peer_change_flag (vty, argv[0], AFI_IP6, PEER_FLAG_NEXTHOP_SELF, 1);
}

DEFUN (no_ipv6_bgp_neighbor_nexthop_self,
       no_ipv6_bgp_neighbor_nexthop_self_cmd,
       "no ipv6 bgp neighbor (A.B.C.D|X:X::X:X) next-hop-self",
       NO_STR
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Disable the next hop calculation for this neighbor\n")
{
  return peer_change_flag (vty, argv[0], AFI_IP6, PEER_FLAG_NEXTHOP_SELF, 0);
}

/* neighbor update-source. */
int
peer_update_source_set (struct vty *vty, char *ip_str, int afi, 
			char *source_str)
{
  struct peer *peer;
  struct peer_conf *conf;

  conf = peer_conf_lookup_vty (vty, ip_str, afi);
  if (! conf)
    return CMD_WARNING;
  peer = conf->peer;

  peer->update_source = sockunion_str2su (source_str);

  if (peer->update_source == NULL)
    {
      peer->update_if = strdup (source_str);
      if (peer->update_source)
	{
	  free (peer->update_source);
	  peer->update_source = NULL;
	}
      return CMD_SUCCESS;
    }

  if (peer->update_if)
    {
      free (peer->update_if);
      peer->update_if = NULL;
    }

  return CMD_SUCCESS;
}

int
peer_update_source_unset (struct vty *vty, char *ip_str, int afi)
{
  struct peer *peer;
  struct peer_conf *conf;

  conf = peer_conf_lookup_vty (vty, ip_str, afi);
  if (! conf)
    return CMD_WARNING;
  peer = conf->peer;

  if (peer->update_source)
    {
      free (peer->update_source);
      peer->update_source = NULL;
    }
  if (peer->update_if)
    {
      free (peer->update_if);
      peer->update_if = NULL;
    }

  return CMD_SUCCESS;
}

DEFUN (neighbor_update_source,
       neighbor_update_source_cmd,
       NEIGHBOR_CMD "update-source WORD",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Source of routing updates\n"
       "Interface name\n")
{
  return peer_update_source_set (vty, argv[0], AFI_IP, argv[1]);
}

DEFUN (no_neighbor_update_source,
       no_neighbor_update_source_cmd,
       NO_NEIGHBOR_CMD "update-source",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Source of routing updates\n"
       "Interface name\n")
{
  return peer_update_source_unset (vty, argv[0], AFI_IP);
}

DEFUN (ipv6_bgp_neighbor_update_source,
       ipv6_bgp_neighbor_update_source_cmd,
       "ipv6 bgp neighbor (A.B.C.D|X:X::X:X) update-source WORD",
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Source of routing updates\n"
       "Interface name\n")
{
  return peer_update_source_set (vty, argv[0], AFI_IP6, argv[1]);
}

DEFUN (no_ipv6_bgp_neighbor_update_source,
       no_ipv6_bgp_neighbor_update_source_cmd,
       "no ipv6 bgp neighbor (A.B.C.D|X:X::X:X) update-source",
       NO_STR
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Source of routing updates\n"
       "Interface name\n")
{
  return peer_update_source_unset (vty, argv[0], AFI_IP6);
}

/* neighbor default-originate. */
DEFUN (neighbor_default_originate,
       neighbor_default_originate_cmd,
       NEIGHBOR_CMD "default-originate",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Originate default route to this neighbor\n")
{
  return peer_change_flag (vty, argv[0], AFI_IP, PEER_FLAG_DEFAULT_ORIGINATE, 1);
}

DEFUN (no_neighbor_default_originate,
       no_neighbor_default_originate_cmd,
       NO_NEIGHBOR_CMD "default-originate",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Originate default route to this neighbor\n")
{
  return peer_change_flag (vty, argv[0], AFI_IP, PEER_FLAG_DEFAULT_ORIGINATE, 0);
}

DEFUN (ipv6_bgp_neighbor_default_originate,
       ipv6_bgp_neighbor_default_originate_cmd,
       "ipv6 bgp neighbor (A.B.C.D|X:X::X:X) default-originate",
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Originate default route to this neighbor\n")
{
  return peer_change_flag (vty, argv[0], AFI_IP6, PEER_FLAG_DEFAULT_ORIGINATE, 1);
}

DEFUN (no_ipv6_bgp_neighbor_default_originate,
       no_ipv6_bgp_neighbor_default_originate_cmd,
       "no ipv6 bgp neighbor (A.B.C.D|X:X::X:X) default-originate",
       NO_STR
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Originate default route to this neighbor\n")
{
  return peer_change_flag (vty, argv[0], AFI_IP6, PEER_FLAG_DEFAULT_ORIGINATE, 0);
}

/* neighbor port. */
int
peer_port (struct vty *vty, char *ip_str, int afi, char *port_str)
{
  struct peer *peer;
  struct peer_conf *conf;
  unsigned long port = 0;
  char *endptr = NULL;
  struct servent *sp;

  conf = peer_conf_lookup_vty (vty, ip_str, afi);
  if (! conf)
    return CMD_WARNING;
  peer = conf->peer;

  if (port_str == NULL)
    { 
      sp = getservbyname ("bgp", "tcp");
      peer->port = (sp == NULL) ? BGP_PORT_DEFAULT : ntohs (sp->s_port);
    }
  else
    {
      port = strtoul (port_str, &endptr, 10);
      if (port == ULONG_MAX || *endptr != '\0')
	{
	  vty_out (vty, "port value error%s", VTY_NEWLINE);
	  return CMD_WARNING;
	}
      if (port > 65535)
	{
	  vty_out (vty, "port value error%s", VTY_NEWLINE);
	  return CMD_WARNING;
	}
    }
  /* Set peer port. */
  peer->port = port;

  return CMD_SUCCESS;
}

/* Set specified peer's BGP version.  */
DEFUN (neighbor_port,
       neighbor_port_cmd,
       NEIGHBOR_CMD "port <0-65535>",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Neighbor's BGP port\n")
{
  return peer_port (vty, argv[0], AFI_IP, argv[1]);
}

DEFUN (no_neighbor_port,
       no_neighbor_port_cmd,
       NO_NEIGHBOR_CMD "port <0-65535>",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Neighbor's BGP port\n")
{
  return peer_port (vty, argv[0], AFI_IP, NULL);
}

DEFUN (ipv6_bgp_neighbor_port,
       ipv6_bgp_neighbor_port_cmd,
       "ipv6 bgp neighbor (A.B.C.D|X:X::X:X) port <0-65535>",
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Neighbor's BGP port\n")
{
  return peer_port (vty, argv[0], AFI_IP6, argv[1]);
}

DEFUN (no_ipv6_bgp_neighbor_port,
       no_ipv6_bgp_neighbor_port_cmd,
       "no ipv6 bgp neighbor (A.B.C.D|X:X::X:X) port <0-65535>",
       NO_STR
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Neighbor's BGP port\n")
{
  return peer_port (vty, argv[0], AFI_IP6, NULL);
}

/* neighbor send-community. */
DEFUN (neighbor_send_community,
       neighbor_send_community_cmd,
       NEIGHBOR_CMD "send-community",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Send Community attribute to this neighbor (default enable)\n")
{
  return peer_change_flag (vty, argv[0], AFI_IP, PEER_FLAG_SEND_COMMUNITY, 1);
}

DEFUN (no_neighbor_send_community,
       no_neighbor_send_community_cmd,
       NO_NEIGHBOR_CMD "send-community",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Send Community attribute to this neighbor (default enable)\n")
{
  return peer_change_flag (vty, argv[0], AFI_IP, PEER_FLAG_SEND_COMMUNITY, 0);
}

DEFUN (ipv6_bgp_neighbor_send_community,
       ipv6_bgp_neighbor_send_community_cmd,
       "ipv6 bgp neighbor (A.B.C.D|X:X::X:X) send-community",
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Send Community attribute to this neighbor (default enable)\n")
{
  return peer_change_flag (vty, argv[0], AFI_IP6, PEER_FLAG_SEND_COMMUNITY, 1);
}

DEFUN (no_ipv6_bgp_neighbor_send_community,
       no_ipv6_bgp_neighbor_send_community_cmd,
       "no ipv6 bgp neighbor (A.B.C.D|X:X::X:X) send-community",
       NO_STR
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Send Community attribute to this neighbor (default enable)\n")
{
  return peer_change_flag (vty, argv[0], AFI_IP6, PEER_FLAG_SEND_COMMUNITY, 0);
}

/* neighbor send-community extended. */
DEFUN (neighbor_send_community_extended,
       neighbor_send_community_extended_cmd,
       NEIGHBOR_CMD "send-community extended",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Send Community attribute to this neighbor (default enable)\n"
       "Extended Community\n")
{
  return peer_change_flag (vty, argv[0], AFI_IP, PEER_FLAG_SEND_EXT_COMMUNITY, 1);
}

DEFUN (no_neighbor_send_community_extended,
       no_neighbor_send_community_extended_cmd,
       NO_NEIGHBOR_CMD "send-community extended",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Send Community attribute to this neighbor (default enable)\n"
       "Extended Community\n")
{
  return peer_change_flag (vty, argv[0], AFI_IP, PEER_FLAG_SEND_EXT_COMMUNITY, 0);
}

DEFUN (ipv6_bgp_neighbor_send_community_extended,
       ipv6_bgp_neighbor_send_community_extended_cmd,
       "ipv6 bgp neighbor (A.B.C.D|X:X::X:X) send-community extended",
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Send Community attribute to this neighbor (default enable)\n"
       "Extended Community\n")
{
  return peer_change_flag (vty, argv[0], AFI_IP6, PEER_FLAG_SEND_EXT_COMMUNITY, 1);
}

DEFUN (no_ipv6_bgp_neighbor_send_community_extended,
       no_ipv6_bgp_neighbor_send_community_extended_cmd,
       "no ipv6 bgp neighbor (A.B.C.D|X:X::X:X) send-community extended",
       NO_STR
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Send Community attribute to this neighbor (default enable)\n"
       "Extended Community\n")
{
  return peer_change_flag (vty, argv[0], AFI_IP6, PEER_FLAG_SEND_EXT_COMMUNITY, 0);
}

/* neighbor weight. */
int
peer_weight_set (struct vty *vty, char *ip_str, int afi, char *weight_str)
{
  struct peer *peer;
  struct peer_conf *conf;
  unsigned long weight;
  char *endptr = NULL;

  conf = peer_conf_lookup_vty (vty, ip_str, afi);
  if (! conf)
    return CMD_WARNING;
  peer = conf->peer;

  weight = strtoul (weight_str, &endptr, 10);
  if (weight == ULONG_MAX || *endptr != '\0')
    {
      vty_out (vty, "weight value error%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  if (weight > 65535)
    {
      vty_out (vty, "weight value error%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  
  /* Set weight flag to peer configure. */
  peer->config |= PEER_CONFIG_WEIGHT;
  peer->weight = weight;

  return CMD_SUCCESS;
}

int
peer_weight_unset (struct vty *vty, char *ip_str, int afi)
{
  struct peer *peer;
  struct peer_conf *conf;

  conf = peer_conf_lookup_vty (vty, ip_str, afi);
  if (! conf)
    return CMD_WARNING;
  peer = conf->peer;
  peer->config &= ~PEER_CONFIG_WEIGHT;

  return CMD_SUCCESS;
}

DEFUN (neighbor_weight,
       neighbor_weight_cmd,
       NEIGHBOR_CMD "weight <0-65535>",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Set default weight for routes from this neighbor\n"
       "default weight\n")
{
  return peer_weight_set (vty, argv[0], AFI_IP, argv[1]);
}

DEFUN (no_neighbor_weight,
       no_neighbor_weight_cmd,
       NO_NEIGHBOR_CMD "weight [<0-65535>]",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Set default weight for routes from this neighbor\n"
       "default weight\n")
{
  return peer_weight_unset (vty, argv[0], AFI_IP);
}

DEFUN (ipv6_bgp_neighbor_weight,
       ipv6_bgp_neighbor_weight_cmd,
       "ipv6 bgp neighbor (A.B.C.D|X:X::X:X) weight <0-65535>",
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Set default weight for routes from this neighbor\n"
       "default weight\n")
{
  return peer_weight_set (vty, argv[0], AFI_IP6, argv[1]);
}

DEFUN (no_ipv6_bgp_neighbor_weight,
       no_ipv6_bgp_neighbor_weight_cmd,
       "no ipv6 bgp neighbor (A.B.C.D|X:X::X:X) weight [<0-65535>]",
       NO_STR
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Set default weight for routes from this neighbor\n"
       "default weight\n")
{
  return peer_weight_unset (vty, argv[0], AFI_IP6);
}

/* neighbor soft-reconfig. */
DEFUN (neighbor_soft_reconfiguration,
       neighbor_soft_reconfiguration_cmd,
       NEIGHBOR_CMD "soft-reconfiguration inbound",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Per neighbor soft reconfiguration\n"
       "Allow inbound soft reconfiguration for this neighbor\n")
{
  return peer_change_flag_with_reset (vty, argv[0], AFI_IP,
				      PEER_FLAG_SOFT_RECONFIG, 1);
}

DEFUN (no_neighbor_soft_reconfiguration,
       no_neighbor_soft_reconfiguration_cmd,
       NO_NEIGHBOR_CMD "soft-reconfiguration inbound",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Per neighbor soft reconfiguration\n"
       "Allow inbound soft reconfiguration for this neighbor\n")
{
  return peer_change_flag_with_reset (vty, argv[0], AFI_IP,
				      PEER_FLAG_SOFT_RECONFIG, 0);
}

DEFUN (ipv6_bgp_neighbor_soft_reconfiguration,
       ipv6_bgp_neighbor_soft_reconfiguration_cmd,
       "ipv6 bgp neighbor (A.B.C.D|X:X::X:X) soft-reconfiguration inbound",
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Per neighbor soft reconfiguration\n"
       "Allow inbound soft reconfiguration for this neighbor\n")
{
  return peer_change_flag_with_reset (vty, argv[0], AFI_IP6,
				      PEER_FLAG_SOFT_RECONFIG, 1);
}

DEFUN (no_ipv6_bgp_neighbor_soft_reconfiguration,
       no_ipv6_bgp_neighbor_soft_reconfiguration_cmd,
       "no ipv6 bgp neighbor (A.B.C.D|X:X::X:X) soft-reconfiguration inbound",
       NO_STR
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Per neighbor soft reconfiguration\n"
       "Allow inbound soft reconfiguration for this neighbor\n")
{
  return peer_change_flag_with_reset (vty, argv[0], AFI_IP6,
				      PEER_FLAG_SOFT_RECONFIG, 0);
}

/* neighbor route-reflector. */
int
peer_route_reflector (struct vty *vty, char *ip_str, int afi, int set)
{
  struct bgp *bgp;
  struct peer *peer;
  struct peer_conf *conf;

  conf = peer_conf_lookup_vty (vty, ip_str, afi);
  if (! conf)
    return CMD_WARNING;

  bgp = vty->index;
  peer = conf->peer;

  if (set)
    {
      if (! CHECK_FLAG (peer->flags, PEER_FLAG_REFLECTOR_CLIENT))
	{
	  bgp->reflector_cnt++;
	  SET_FLAG (peer->flags, PEER_FLAG_REFLECTOR_CLIENT);
	  BGP_EVENT_ADD (peer, BGP_Stop);
	}
    }
  else
    {
      if (CHECK_FLAG (peer->flags, PEER_FLAG_REFLECTOR_CLIENT))
	{
	  bgp->reflector_cnt--;
	  UNSET_FLAG (peer->flags, PEER_FLAG_REFLECTOR_CLIENT);
	  BGP_EVENT_ADD (peer, BGP_Stop);
	}
    }
  return CMD_SUCCESS;
}

DEFUN (neighbor_route_reflector_client,
       neighbor_route_reflector_client_cmd,
       NEIGHBOR_CMD "route-reflector-client",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Configure a neighbor as Route Reflector client\n")
{
  return peer_route_reflector (vty, argv[0], AFI_IP, 1);
}

DEFUN (no_neighbor_route_reflector_client,
       no_neighbor_route_reflector_client_cmd,
       NO_NEIGHBOR_CMD "route-reflector-client",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Configure a neighbor as Route Reflector client\n")
{
  return peer_route_reflector (vty, argv[0], AFI_IP, 0);
}

DEFUN (ipv6_bgp_neighbor_route_reflector_client,
       ipv6_bgp_neighbor_route_reflector_client_cmd,
       "ipv6 bgp neighbor (A.B.C.D|X:X::X:X) route-reflector-client",
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Configure a neighbor as Route Reflector client\n")
{
  return peer_route_reflector (vty, argv[0], AFI_IP6, 1);
}

DEFUN (no_ipv6_bgp_neighbor_route_reflector_client,
       no_ipv6_bgp_neighbor_route_reflector_client_cmd,
       "no ipv6 bgp neighbor (A.B.C.D|X:X::X:X) route-reflector-client",
       NO_STR
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Configure a neighbor as Route Reflector client\n")
{
  return peer_route_reflector (vty, argv[0], AFI_IP6, 0);
}

/* neighbor route-server-client. */
DEFUN (neighbor_route_server_client,
       neighbor_route_server_client_cmd,
       NEIGHBOR_CMD "route-server-client",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Configure a neighbor as Route Server client\n")
{
  return peer_change_flag_with_reset (vty, argv[0], AFI_IP,
				      PEER_FLAG_RSERVER_CLIENT, 1);
}

DEFUN (no_neighbor_route_server_client,
       no_neighbor_route_server_client_cmd,
       NO_NEIGHBOR_CMD "route-server-client",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Configure a neighbor as Route Server client\n")
{
  return peer_change_flag_with_reset (vty, argv[0], AFI_IP,
				      PEER_FLAG_RSERVER_CLIENT, 0);
}

DEFUN (ipv6_bgp_neighbor_route_server_client,
       ipv6_bgp_neighbor_route_server_client_cmd,
       "ipv6 bgp neighbor (A.B.C.D|X:X::X:X) route-server-client",
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Configure a neighbor as Route Server client\n")
{
  return peer_change_flag_with_reset (vty, argv[0], AFI_IP6,
				      PEER_FLAG_RSERVER_CLIENT, 1);
}

DEFUN (no_ipv6_bgp_neighbor_route_server_client,
       no_ipv6_bgp_neighbor_route_server_client_cmd,
       "no ipv6 bgp neighbor (A.B.C.D|X:X::X:X) route-server-client",
       NO_STR
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Configure a neighbor as Route Server client\n")
{
  return peer_change_flag_with_reset (vty, argv[0], AFI_IP6,
				      PEER_FLAG_RSERVER_CLIENT, 0);
}

/* neighbor route-refresh. */
DEFUN (neighbor_route_refresh,
       neighbor_route_refresh_cmd,
       NEIGHBOR_CMD "route-refresh",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Configure a neighbor as Route Refresh enable\n")
{
  return peer_change_flag_with_reset (vty, argv[0], AFI_IP, 
				      PEER_FLAG_ROUTE_REFRESH, 1);
}

DEFUN (no_neighbor_route_refresh,
       no_neighbor_route_refresh_cmd,
       NO_NEIGHBOR_CMD "route-refresh",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Configure a neighbor as Route Refresh enable\n")
{
  return peer_change_flag_with_reset (vty, argv[0], AFI_IP,
				      PEER_FLAG_ROUTE_REFRESH, 0);
}

DEFUN (ipv6_bgp_neighbor_route_refresh,
       ipv6_bgp_neighbor_route_refresh_cmd,
       "ipv6 bgp neighbor (A.B.C.D|X:X::X:X) route-refresh",
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Configure a neighbor as Route Refresh enable\n")
{
  return peer_change_flag_with_reset (vty, argv[0], AFI_IP6,
				      PEER_FLAG_ROUTE_REFRESH, 1);
}

DEFUN (no_ipv6_bgp_neighbor_route_refresh,
       no_ipv6_bgp_neighbor_route_refresh_cmd,
       "no ipv6 bgp neighbor (A.B.C.D|X:X::X:X) route-refresh",
       NO_STR
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Configure a neighbor as Route Refresh enable\n")
{
  return peer_change_flag_with_reset (vty, argv[0], AFI_IP6,
				      PEER_FLAG_ROUTE_REFRESH, 0);
}

/* neighbor transparent-as */
DEFUN (neighbor_transparent_as,
       neighbor_transparent_as_cmd,
       NEIGHBOR_CMD "transparent-as",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Do not append my AS number even peer is EBGP peer\n")
{
  return peer_change_flag_with_reset (vty, argv[0], AFI_IP, 
				      PEER_FLAG_TRANSPARENT_AS, 1);
}

DEFUN (no_neighbor_transparent_as,
       no_neighbor_transparent_as_cmd,
       NO_NEIGHBOR_CMD "transparent-as",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Do not append my AS number even peer is EBGP peer\n")
{
  return peer_change_flag_with_reset (vty, argv[0], AFI_IP,
				      PEER_FLAG_TRANSPARENT_AS, 0);
}

DEFUN (ipv6_bgp_neighbor_transparent_as,
       ipv6_bgp_neighbor_transparent_as_cmd,
       "ipv6 bgp neighbor (A.B.C.D|X:X::X:X) transparent-as",
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Do not append my AS number even peer is EBGP peer\n")
{
  return peer_change_flag_with_reset (vty, argv[0], AFI_IP6,
				      PEER_FLAG_TRANSPARENT_AS, 1);
}

DEFUN (no_ipv6_bgp_neighbor_transparent_as,
       no_ipv6_bgp_neighbor_transparent_as_cmd,
       "no ipv6 bgp neighbor (A.B.C.D|X:X::X:X) transparent-as",
       NO_STR
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Do not append my AS number even peer is EBGP peer\n")
{
  return peer_change_flag_with_reset (vty, argv[0], AFI_IP6,
				      PEER_FLAG_TRANSPARENT_AS, 0);
}

/* neighbor transparent-nexthop */
DEFUN (neighbor_transparent_nexthop,
       neighbor_transparent_nexthop_cmd,
       NEIGHBOR_CMD "transparent-nexthop",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Do not change nexthop even peer is EBGP peer\n")
{
  return peer_change_flag_with_reset (vty, argv[0], AFI_IP, 
				      PEER_FLAG_TRANSPARENT_NEXTHOP, 1);
}

DEFUN (no_neighbor_transparent_nexthop,
       no_neighbor_transparent_nexthop_cmd,
       NO_NEIGHBOR_CMD "transparent-nexthop",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Do not change nexthop even peer is EBGP peer\n")
{
  return peer_change_flag_with_reset (vty, argv[0], AFI_IP,
				      PEER_FLAG_TRANSPARENT_NEXTHOP, 0);
}

DEFUN (ipv6_bgp_neighbor_transparent_nexthop,
       ipv6_bgp_neighbor_transparent_nexthop_cmd,
       "ipv6 bgp neighbor (A.B.C.D|X:X::X:X) transparent-nexthop",
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Do not change nexthop even peer is EBGP peer\n")
{
  return peer_change_flag_with_reset (vty, argv[0], AFI_IP6,
				      PEER_FLAG_TRANSPARENT_NEXTHOP, 1);
}

DEFUN (no_ipv6_bgp_neighbor_transparent_nexthop,
       no_ipv6_bgp_neighbor_transparent_nexthop_cmd,
       "no ipv6 bgp neighbor (A.B.C.D|X:X::X:X) transparent-nexthop",
       NO_STR
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Do not change nexthop even peer is EBGP peer\n")
{
  return peer_change_flag_with_reset (vty, argv[0], AFI_IP6,
				      PEER_FLAG_TRANSPARENT_NEXTHOP, 0);
}

/* neighbor translate-update. */
int
peer_translate_update (struct vty *vty, char *ip_str, int afi, int safi)
{
  struct peer *peer;
  struct peer_conf *conf;

  conf = peer_conf_lookup_vty (vty, ip_str, afi);
  if (! conf)
    return CMD_WARNING;

  peer = conf->peer;
  peer->translate_update = safi;
  return CMD_SUCCESS;
}

DEFUN (neighbor_translate_update_multicast,
       neighbor_translate_update_multicast_cmd,
       NEIGHBOR_CMD "translate-update nlri multicast",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Translate bgp updates\n"
       "Network Layer Reachable Information\n"
       "multicast information\n")
{
  return peer_translate_update (vty, argv[0], AFI_IP, SAFI_MULTICAST);
}

DEFUN (neighbor_translate_update_unimulti,
       neighbor_translate_update_unimulti_cmd,
       NEIGHBOR_CMD "translate-update nlri unicast multicast",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Translate bgp updates\n"
       "Network Layer Reachable Information\n"
       "unicast information\n"
       "multicast inforamtion\n")
{
  return peer_translate_update (vty, argv[0], AFI_IP, SAFI_UNICAST_MULTICAST);
}

DEFUN (no_neighbor_translate_update,
       no_neighbor_translate_update_cmd,
       NO_NEIGHBOR_CMD "translate-update",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Translate bgp updates\n")
{
  return peer_translate_update (vty, argv[0], AFI_IP, 0);
}

DEFUN (no_neighbor_translate_update_multicast,
       no_neighbor_translate_update_multicast_cmd,
       NO_NEIGHBOR_CMD "translate-update nlri multicast",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Translate bgp updates\n"
       "Network Layer Reachable Information\n"
       "multicast information\n")
{
  return peer_translate_update (vty, argv[0], AFI_IP, 0);
}

DEFUN (no_neighbor_translate_update_unimulti,
       no_neighbor_translate_update_unimulti_cmd,
       NO_NEIGHBOR_CMD "translate-update nlri unicast multicast",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Translate bgp updates\n"
       "Network Layer Reachable Information\n"
       "unicast information\n"
       "multicast inforamtion\n")
{
  return peer_translate_update (vty, argv[0], AFI_IP, 0);
}

/* neighbor dont-capability-negotiate */
DEFUN (neighbor_dont_capability_negotiate,
       neighbor_dont_capability_negotiate_cmd,
       NEIGHBOR_CMD "dont-capability-negotiate",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Do not perform capability negotiation\n")
{
  return peer_change_flag (vty, argv[0], AFI_IP,
			   PEER_FLAG_DONT_CAPABILITY, 1);
}

DEFUN (no_neighbor_dont_capability_negotiate,
       no_neighbor_dont_capability_negotiate_cmd,
       NO_NEIGHBOR_CMD "dont-capability-negotiate",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Do not perform capability negotiation\n")
{
  return peer_change_flag (vty, argv[0], AFI_IP,
			   PEER_FLAG_DONT_CAPABILITY, 0);
}

DEFUN (ipv6_neighbor_dont_capability_negotiate,
       ipv6_neighbor_dont_capability_negotiate_cmd,
       "ipv6 bgp neighbor (A.B.C.D|X:X::X:X) dont-capability-negotiate",
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Do not perform capability negotiation\n")
{
  return peer_change_flag (vty, argv[0], AFI_IP6,
			   PEER_FLAG_DONT_CAPABILITY, 1);
}

DEFUN (no_ipv6_neighbor_dont_capability_negotiate,
       no_ipv6_neighbor_dont_capability_negotiate_cmd,
       "no ipv6 bgp neighbor (A.B.C.D|X:X::X:X) dont-capability-negotiate",
       NO_STR
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Do not perform capability negotiation\n")
{
  return peer_change_flag (vty, argv[0], AFI_IP6,
			   PEER_FLAG_DONT_CAPABILITY, 0);
}

/* Override capability negotiation. */
int
peer_override_capability (struct vty *vty, char *ip_str, int afi, int set)
{
  struct peer *peer;
  struct peer_conf *conf;

  conf = peer_conf_lookup_vty (vty, ip_str, afi);
  if (! conf)
    return CMD_WARNING;
  peer = conf->peer;
  
  if (set)
    {
      if (CHECK_FLAG (peer->flags, PEER_FLAG_STRICT_CAP_MATCH))
	{
	  vty_out (vty, "Can't set override-capability and strict-capability-match at the same time%s", VTY_NEWLINE);
	  return CMD_WARNING;
	}
      SET_FLAG (peer->flags, PEER_FLAG_OVERRIDE_CAPABILITY);
    }
  else
    UNSET_FLAG (peer->flags, PEER_FLAG_OVERRIDE_CAPABILITY);
  return CMD_SUCCESS;
}

/* Override capability negotiation. */
DEFUN (neighbor_override_capability,
       neighbor_override_capability_cmd,
       NEIGHBOR_CMD "override-capability",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Override capability negotiation result\n")
{
  return peer_override_capability (vty, argv[0], AFI_IP, 1);
}

DEFUN (no_neighbor_override_capability,
       no_neighbor_override_capability_cmd,
       NO_NEIGHBOR_CMD "override-capability",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Override capability negotiation result\n")
{
  return peer_override_capability (vty, argv[0], AFI_IP, 0);
}

DEFUN (ipv6_neighbor_override_capability,
       ipv6_neighbor_override_capability_cmd,
       "ipv6 bgp neighbor (A.B.C.D|X:X::X:X) override-capability",
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Override capability negotiation result\n")
{
  return peer_override_capability (vty, argv[0], AFI_IP6, 1);
}

DEFUN (no_ipv6_neighbor_override_capability,
       no_ipv6_neighbor_override_capability_cmd,
       "no ipv6 bgp neighbor (A.B.C.D|X:X::X:X) override-capability",
       NO_STR
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Override capability negotiation result\n")
{
  return peer_override_capability (vty, argv[0], AFI_IP6, 0);
}

/* Strict capability match. */
int
peer_strict_capability (struct vty *vty, char *ip_str, int afi, int set)
{
  struct peer *peer;
  struct peer_conf *conf;

  conf = peer_conf_lookup_vty (vty, ip_str, afi);
  if (! conf)
    return CMD_WARNING;
  peer = conf->peer;
  
  if (set)
    {
      if (CHECK_FLAG (peer->flags, PEER_FLAG_OVERRIDE_CAPABILITY))
	{
	  vty_out (vty, "Can't set override-capability and strict-capability-match at the same time%s", VTY_NEWLINE);
	  return CMD_WARNING;
	}
      SET_FLAG (peer->flags, PEER_FLAG_STRICT_CAP_MATCH);
    }
  else
    UNSET_FLAG (peer->flags, PEER_FLAG_STRICT_CAP_MATCH);
  return CMD_SUCCESS;
}

DEFUN (neighbor_strict_capability,
       neighbor_strict_capability_cmd,
       NEIGHBOR_CMD "strict-capability-match",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Strict capability negotiation match\n")
{
  return peer_strict_capability (vty, argv[0], AFI_IP, 1);
}

DEFUN (no_neighbor_strict_capability,
       no_neighbor_strict_capability_cmd,
       NO_NEIGHBOR_CMD "strict-capability-match",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Strict capability negotiation match\n")
{
  return peer_strict_capability (vty, argv[0], AFI_IP, 0);
}

DEFUN (ipv6_neighbor_strict_capability,
       ipv6_neighbor_strict_capability_cmd,
       "ipv6 bgp neighbor (A.B.C.D|X:X::X:X) strict-capability-match",
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Strict capability negotiation match\n")
{
  return peer_strict_capability (vty, argv[0], AFI_IP6, 1);
}

DEFUN (no_ipv6_neighbor_strict_capability,
       no_ipv6_neighbor_strict_capability_cmd,
       "no ipv6 bgp neighbor (A.B.C.D|X:X::X:X) strict-capability-match",
       NO_STR
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Strict capability negotiation match\n")
{
  return peer_strict_capability (vty, argv[0], AFI_IP6, 0);
}

int
peer_timers_holdtime_set (struct vty *vty, char *ip_str, int afi,
			  char *time_str)
{
  struct peer *peer;
  struct peer_conf *conf;
  unsigned long holdtime;
  char *endptr = NULL;

  conf = peer_conf_lookup_vty (vty, ip_str, afi);
  if (! conf)
    return CMD_WARNING;

  peer = conf->peer;

  /* Hold time value check. */
  holdtime = strtoul (time_str, &endptr, 10);

  if (holdtime == ULONG_MAX || *endptr != '\0')
    {
      vty_out (vty, "hold time value must be positive integer%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  if (holdtime > 65535)
    {
      vty_out (vty, "hold time value must be <0,3-65535>%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  if (holdtime < 3 && holdtime != 0)
    {
      vty_out (vty, "hold time value must be either 0 or greater than 3%s",
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Set value to the configuration. */
  peer->config |= PEER_CONFIG_HOLDTIME;
  peer->holdtime = holdtime;

  /* Set value to timer setting. */
  peer->v_holdtime = holdtime;

  return CMD_SUCCESS;
}

int
peer_timers_holdtime_unset (struct vty *vty, char *ip_str, int afi)
{
  struct peer *peer;
  struct peer_conf *conf;

  conf = peer_conf_lookup_vty (vty, ip_str, afi);
  if (! conf)
    return CMD_WARNING;

  peer = conf->peer;

  /* Clear configuration. */
  peer->config &= ~PEER_CONFIG_HOLDTIME;
  peer->holdtime = 0;

  /* Set timer setting to default value. */
  peer->v_holdtime = BGP_DEFAULT_HOLDTIME;

  return CMD_SUCCESS;
}

DEFUN (neighbor_timers_holdtime,
       neighbor_timers_holdtime_cmd,
       NEIGHBOR_CMD "timers holdtime <0-65535>",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "BGP per neighbor timers\n"
       "BGP holdtimer\n"
       "holdtime\n")
{
  return peer_timers_holdtime_set (vty, argv[0], AFI_IP, argv[1]);
}

DEFUN (no_neighbor_timers_holdtime,
       no_neighbor_timers_holdtime_cmd,
       NO_NEIGHBOR_CMD "timers holdtime [TIME]",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "BGP per neighbor timers\n"
       "BGP holdtimer\n"
       "holdtime\n")
{
  return peer_timers_holdtime_unset (vty, argv[0], AFI_IP);
}

DEFUN (ipv6_bgp_neighbor_timers_holdtime,
       ipv6_bgp_neighbor_timers_holdtime_cmd,
       "ipv6 bgp neighbor (A.B.C.D|X:X::X:X) timers holdtime <0-65535>",
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "BGP per neighbor timers\n"
       "BGP holdtimer\n"
       "holdtime\n")
{
  return peer_timers_holdtime_set (vty, argv[0], AFI_IP6, argv[1]);
}

DEFUN (no_ipv6_bgp_neighbor_timers_holdtime,
       no_ipv6_bgp_neighbor_timers_holdtime_cmd,
       "no ipv6 bgp neighbor (A.B.C.D|X:X::X:X) timers holdtime [TIMER]",
       NO_STR
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "BGP per neighbor timers\n"
       "BGP holdtimer\n"
       "holdtime\n")
{
  return peer_timers_holdtime_unset (vty, argv[0], AFI_IP6);
}

int
peer_timers_keepalive_set (struct vty *vty, char *ip_str, int afi,
			   char *time_str)
{
  struct peer *peer;
  struct peer_conf *conf;
  unsigned long keepalive;
  char *endptr = NULL;

  conf = peer_conf_lookup_vty (vty, ip_str, afi);
  if (! conf)
    return CMD_WARNING;

  peer = conf->peer;

  /* Hold time value check. */
  keepalive = strtoul (time_str, &endptr, 10);

  if (keepalive == ULONG_MAX || *endptr != '\0')
    {
      vty_out (vty, "keepalive time value must be positive integer%s",
	       VTY_NEWLINE);
      return CMD_WARNING;
    }
  if (keepalive > 65535)
    {
      vty_out (vty, "keepalive time value must be <0-65535>%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Set value to the configuration. */
  peer->config |= PEER_CONFIG_KEEPALIVE;
  peer->keepalive = keepalive;

  /* Set value to timer setting. */
  peer->v_keepalive = keepalive;

  return CMD_SUCCESS;
}

int
peer_timers_keepalive_unset (struct vty *vty, char *ip_str, int afi)
{
  struct peer *peer;
  struct peer_conf *conf;

  conf = peer_conf_lookup_vty (vty, ip_str, afi);
  if (! conf)
    return CMD_WARNING;

  peer = conf->peer;

  /* Clear configuration. */
  peer->config &= ~PEER_CONFIG_KEEPALIVE;
  peer->keepalive = 0;

  /* Set timer setting to default value. */
  peer->v_keepalive = min (BGP_DEFAULT_KEEPALIVE, peer->v_holdtime / 3);

  return CMD_SUCCESS;
}

DEFUN (neighbor_timers_keepalive,
       neighbor_timers_keepalive_cmd,
       NEIGHBOR_CMD "timers keepalive <0-65535>",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "BGP per neighbor timers\n"
       "BGP keepalive interval\n"
       "Keepalive interval\n")
{
  return peer_timers_keepalive_set (vty, argv[0], AFI_IP, argv[1]);
}

DEFUN (no_neighbor_timers_keepalive,
       no_neighbor_timers_keepalive_cmd,
       NO_NEIGHBOR_CMD "timers keepalive [TIMER]",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "BGP per neighbor timers\n"
       "BGP keepalive interval\n"
       "Keepalive interval\n")
{
  return peer_timers_keepalive_unset (vty, argv[0], AFI_IP);
}

DEFUN (ipv6_bgp_neighbor_timers_keepalive,
       ipv6_bgp_neighbor_timers_keepalive_cmd,
       "ipv6 bgp neighbor (A.B.C.D|X:X::X:X) timers keepalive <0-65535>",
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "BGP per neighbor timers\n"
       "BGP keepalive interval\n"
       "Keepalive interval\n")
{
  return peer_timers_keepalive_set (vty, argv[0], AFI_IP6, argv[1]);
}

DEFUN (no_ipv6_bgp_neighbor_timers_keepalive,
       no_ipv6_bgp_neighbor_timers_keepalive_cmd,
       "no ipv6 bgp neighbor (A.B.C.D|X:X::X:X) timers keepalive [TIMER]",
       NO_STR
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "BGP per neighbor timers\n"
       "BGP keepalive interval\n"
       "Keepalive interval\n")
{
  return peer_timers_keepalive_unset (vty, argv[0], AFI_IP6);
}

int
peer_timers_connect_set (struct vty *vty, char *ip_str, int afi,
			 char *time_str)
{
  struct peer *peer;
  struct peer_conf *conf;
  unsigned long connect;
  char *endptr = NULL;

  conf = peer_conf_lookup_vty (vty, ip_str, afi);
  if (! conf)
    return CMD_WARNING;

  peer = conf->peer;

  /* Hold time value check. */
  connect = strtoul (time_str, &endptr, 10);

  if (connect == ULONG_MAX || *endptr != '\0')
    {
      vty_out (vty, "connect time value must be positive integer%s",
	       VTY_NEWLINE);
      return CMD_WARNING;
    }
  if (connect > 65535)
    {
      vty_out (vty, "connect time value must be <0-65535>%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Set value to the configuration. */
  peer->config |= PEER_CONFIG_CONNECT;
  peer->connect = connect;

  /* Set value to timer setting. */
  peer->v_connect = connect;

  return CMD_SUCCESS;
}

int
peer_timers_connect_unset (struct vty *vty, char *ip_str, int afi)
{
  struct peer *peer;
  struct peer_conf *conf;

  conf = peer_conf_lookup_vty (vty, ip_str, afi);
  if (! conf)
    return CMD_WARNING;
  peer = conf->peer;

  /* Clear configuration. */
  UNSET_FLAG (peer->config, PEER_CONFIG_CONNECT);
  peer->connect = 0;

  /* Set timer setting to default value. */
  peer->v_connect = BGP_DEFAULT_CONNECT_RETRY;

  return CMD_SUCCESS;
}

DEFUN (neighbor_timers_connect,
       neighbor_timers_connect_cmd,
       NEIGHBOR_CMD "timers connect <0-65535>",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "BGP per neighbor timers\n"
       "BGP connect timer\n"
       "Connect timer\n")
{
  return peer_timers_connect_set (vty, argv[0], AFI_IP, argv[1]);
}

DEFUN (no_neighbor_timers_connect,
       no_neighbor_timers_connect_cmd,
       NO_NEIGHBOR_CMD "timers connect [TIMER]",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "BGP per neighbor timers\n"
       "BGP connect timer\n"
       "Connect timer\n")
{
  return peer_timers_connect_unset (vty, argv[0], AFI_IP);
}

DEFUN (ipv6_bgp_neighbor_timers_connect,
       ipv6_bgp_neighbor_timers_connect_cmd,
       "ipv6 bgp neighbor (A.B.C.D|X:X::X:X) timers connect <0-65535>",
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "BGP per neighbor timers\n"
       "BGP connect timer\n"
       "Connect timer\n")
{
  return peer_timers_connect_set (vty, argv[0], AFI_IP6, argv[1]);
}

DEFUN (no_ipv6_bgp_neighbor_timers_connect,
       no_ipv6_bgp_neighbor_timers_connect_cmd,
       "no ipv6 bgp neighbor (A.B.C.D|X:X::X:X) timers connect [TIMER]",
       NO_STR
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "BGP per neighbor timers\n"
       "BGP connect timer\n"
       "Connect timer\n")
{
  return peer_timers_connect_unset (vty, argv[0], AFI_IP6);
}

int
peer_version (struct vty *vty, char *ip_str, int afi, char *str)
{
  struct peer *peer;
  struct peer_conf *conf;

  conf = peer_conf_lookup_vty (vty, ip_str, afi);
  if (! conf)
    return CMD_WARNING;
  peer = conf->peer;

  /* BGP version string check. */
  if (str)
    {
      if (strcmp (str, "4") == 0)
	peer->version = BGP_VERSION_4;
      else if (strcmp (str, "4+") == 0)
	peer->version = BGP_VERSION_MP_4;
      else if (strcmp (str, "4-") == 0)
	peer->version = BGP_VERSION_MP_4_DRAFT_00;
      else
	vty_out (vty, "BGP version malformed!%s", VTY_NEWLINE);
    }
  else
    peer->version = BGP_VERSION_4;

  return CMD_SUCCESS;
}

DEFUN (neighbor_version,
       neighbor_version_cmd,
       NEIGHBOR_CMD "version BGP_VERSION",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Set the BGP version to match a neighbor\n"
       "Neighbor's BGP version 4 or 4+ or 4-\n")
{
  return peer_version (vty, argv[0], AFI_IP, argv[1]);
}

DEFUN (no_neighbor_version,
       no_neighbor_version_cmd,
       NO_NEIGHBOR_CMD "version [BGP_VERSION]",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Set the BGP version to match a neighbor\n"
       "Neighbor's BGP version 4 or 4+ or 4-\n")
{
  return peer_version (vty, argv[0], AFI_IP, NULL);
}

DEFUN (ipv6_bgp_neighbor_version,
       ipv6_bgp_neighbor_version_cmd,
       "ipv6 bgp neighbor (A.B.C.D|X:X::X:X) version BGP_VERSION",
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Set the BGP version to match a neighbor\n"
       "Neighbor's BGP version 4 or 4+ or 4-\n")
{
  return peer_version (vty, argv[0], AFI_IP6, argv[1]);
}

DEFUN (no_ipv6_bgp_neighbor_version,
       no_ipv6_bgp_neighbor_version_cmd,
       "no ipv6 bgp neighbor (A.B.C.D|X:X::X:X) version [BGP_VERSION]",
       NO_STR
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Set the BGP version to match a neighbor\n"
       "Neighbor's BGP version 4 or 4+ or 4-\n")
{
  return peer_version (vty, argv[0], AFI_IP6, NULL);
}

/* neighbor interface */
int
peer_interface (struct vty *vty, char *ip_str, int afi, char *str)
{
  struct peer *peer;
  struct peer_conf *conf;

  conf = peer_conf_lookup_vty (vty, ip_str, afi);
  if (! conf)
    return CMD_WARNING;
  peer = conf->peer;

  if (str)
    {
      if (peer->ifname)
	free (peer->ifname);
      peer->ifname = strdup (str);
    }
  else
    {
      if (peer->ifname)
	free (peer->ifname);
      peer->ifname = NULL;
    }
  return CMD_SUCCESS;
}

DEFUN (neighbor_interface,
       neighbor_interface_cmd,
       NEIGHBOR_CMD "interface WORD",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Interface\n"
       "Interface name\n")
{
  return peer_interface (vty, argv[0], AFI_IP, argv[1]);
}

DEFUN (no_neighbor_interface,
       no_neighbor_interface_cmd,
       NO_NEIGHBOR_CMD "interface WORD",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Interface\n"
       "Interface name\n")
{
  return peer_interface (vty, argv[0], AFI_IP, NULL);
}

DEFUN (ipv6_bgp_neighbor_interface,
       ipv6_bgp_neighbor_interface_cmd,
       "ipv6 bgp neighbor (A.B.C.D|X:X::X:X) interface WORD",
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Interface\n"
       "Interface name\n")
{
  return peer_interface (vty, argv[0], AFI_IP6, argv[1]);
}

DEFUN (no_ipv6_bgp_neighbor_interface,
       no_ipv6_bgp_neighbor_interface_cmd,
       "no ipv6 bgp neighbor (A.B.C.D|X:X::X:X) interface WORD",
       NO_STR
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Interface\n"
       "Interface name\n")
{
  return peer_interface (vty, argv[0], AFI_IP6, NULL);
}

/* Set distribute list to the peer. */
int
bgp_distribute_set (struct vty *vty, char *ip_str, int afi, char *name_str,
		    char *direct_str)
{
  struct peer_conf *conf;
  struct bgp_filter *filter;
  int direct;

  conf = peer_conf_lookup_vty (vty, ip_str, afi);
  if (! conf)
    return CMD_WARNING;

  /* Check filter direction. */
  if (strncmp (direct_str, "in", 1) == 0)
    direct = BGP_FILTER_IN;
  else if (strncmp (direct_str, "out", 1) == 0)
    direct = BGP_FILTER_OUT;
  else
    {
      vty_out (vty, "filter direction must be [in|out]%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  filter = &conf->filter;

  if (filter->dlist[direct].name)
    free (filter->dlist[direct].name);
  filter->dlist[direct].name = strdup (name_str);
  filter->dlist[direct].v4 = access_list_lookup (AF_INET, name_str);
#ifdef HAVE_IPV6
  filter->dlist[direct].v6 = access_list_lookup (AF_INET6, name_str);
#endif /* HAVE_IPV6 */

  return CMD_SUCCESS;
}

int
bgp_distribute_unset (struct vty *vty, char *ip_str, int afi, char *name_str,
		      char *direct_str)
{
  struct peer_conf *conf;
  struct bgp_filter *filter;
  int direct;

  conf = peer_conf_lookup_vty (vty, ip_str, afi);
  if (! conf)
    return CMD_WARNING;
  
  /* Check filter direction. */
  if (strcmp (direct_str, "in") == 0)
    direct = BGP_FILTER_IN;
  else if (strcmp (direct_str, "out") == 0)
    direct = BGP_FILTER_OUT;
  else
    {
      vty_out (vty, "distribute direction must be [in|out]%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  filter = &conf->filter;

  if (! filter->dlist[direct].name)
    {
      vty_out (vty, "There is no such filter: %s%s", name_str, VTY_NEWLINE);
      return CMD_WARNING;
    }
  if (strcmp (filter->dlist[direct].name, name_str) != 0)
    {
      vty_out (vty, "There is no such filter: %s%s", name_str, VTY_NEWLINE);
      return CMD_WARNING;
    }
  free (filter->dlist[direct].name);
  filter->dlist[direct].name = NULL;
  filter->dlist[direct].v4 = NULL;
  filter->dlist[direct].v6 = NULL;

  return CMD_SUCCESS;
}

/* Update distribute list. */
void
bgp_distribute_update (struct access_list *access)
{
  struct newnode *nn, *nm;
  struct bgp *bgp;
  struct peer_conf *conf;
  struct bgp_filter *filter;

  NEWLIST_LOOP (bgp_list, bgp, nn)
    {
      NEWLIST_LOOP (bgp->peer_conf, conf, nm)
	{
	  filter = &conf->filter;

	  /* Input filter update. */
	  if (filter->dlist[BGP_FILTER_IN].name)
	    {
	      filter->dlist[BGP_FILTER_IN].v4 = 
		access_list_lookup (AF_INET, filter->dlist[BGP_FILTER_IN].name);
#ifdef HAVE_IPV6
	      filter->dlist[BGP_FILTER_IN].v6 = 
		access_list_lookup (AF_INET6, filter->dlist[BGP_FILTER_IN].name);
#endif /* HAVE_IPV6 */
	    }
	  else
	    {
	      filter->dlist[BGP_FILTER_IN].v4 = NULL;
#ifdef HAVE_IPV6
	      filter->dlist[BGP_FILTER_IN].v6 = NULL;
#endif /* HAVE_IPV6 */
	    }
	  /* Output filter update. */
	  if (filter->dlist[BGP_FILTER_OUT].name)
	    {
	      filter->dlist[BGP_FILTER_OUT].v4 = 
		access_list_lookup (AF_INET, filter->dlist[BGP_FILTER_OUT].name);
#ifdef HAVE_IPV6
	      filter->dlist[BGP_FILTER_OUT].v6 = 
		access_list_lookup (AF_INET6, filter->dlist[BGP_FILTER_OUT].name);
#endif /* HAVE_IPV6 */
	    }
	  else
	    {
	      filter->dlist[BGP_FILTER_OUT].v4 = NULL;
#ifdef HAVE_IPV6
	      filter->dlist[BGP_FILTER_OUT].v6 = NULL;
#endif /* HAVE_IPV6 */
	    }
	}
    }
}

DEFUN (neighbor_distribute_list,
       neighbor_distribute_list_cmd,
       NEIGHBOR_CMD "distribute-list WORD (in|out)",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Filter updates to/from this neighbor\n"
       "IP Access-list name\n"
       "Filter incoming updates\n"
       "Filter outgoing updates\n")
{
  return bgp_distribute_set (vty, argv[0], AFI_IP, argv[1], argv[2]);
}

DEFUN (no_neighbor_distribute_list,
       no_neighbor_distribute_list_cmd,
       NO_NEIGHBOR_CMD "distribute-list WORD (in|out)",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Filter updates to/from this neighbor\n"
       "IP Access-list name\n"
       "Filter incoming updates\n"
       "Filter outgoing updates\n")
{
  return bgp_distribute_unset (vty, argv[0], AFI_IP, argv[1], argv[2]);
}

DEFUN (ipv6_bgp_neighbor_distribute_list,
       ipv6_bgp_neighbor_distribute_list_cmd,
       "ipv6 bgp neighbor (A.B.C.D|X:X::X:X) distribute-list WORD (in|out)",
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Filter updates to/from this neighbor\n"
       "IPv6 Access-list name\n"
       "Filter incoming updates\n"
       "Filter outgoing updates\n")
{
  return bgp_distribute_set (vty, argv[0], AFI_IP6, argv[1], argv[2]);
}

DEFUN (no_ipv6_bgp_neighbor_distribute_list,
       no_ipv6_bgp_neighbor_distribute_list_cmd,
       "no ipv6 bgp neighbor (A.B.C.D|X:X::X:X) distribute-list WORD (in|out)",
       NO_STR
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Filter updates to/from this neighbor\n"
       "IPv6 Access-list name\n"
       "Filter incoming updates\n"
       "Filter outgoing updates\n")
{
  return bgp_distribute_unset (vty, argv[0], AFI_IP6, argv[1], argv[2]);
}

/* Set prefix list to the peer. */
int
bgp_prefix_list_set (struct vty *vty, char *ip_str, int afi, char *name_str,
		     char *direct_str)
{
  struct peer_conf *conf;
  int direct;
  struct bgp_filter *filter;

  conf = peer_conf_lookup_vty (vty, ip_str, afi);
  if (! conf)
    return CMD_WARNING;

  /* Check filter direction. */
  if (strncmp (direct_str, "in", 1) == 0)
    direct = BGP_FILTER_IN;
  else if (strncmp (direct_str, "out", 1) == 0)
    direct = BGP_FILTER_OUT;
  else
    {
      vty_out (vty, "vty, filter direction must be [in|out]%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  filter = &conf->filter;

  if (filter->plist[direct].name)
    free (filter->plist[direct].name);
  filter->plist[direct].name = strdup (name_str);
  filter->plist[direct].v4 = prefix_list_lookup (AF_INET, name_str);
#ifdef HAVE_IPV6
  filter->plist[direct].v6 = prefix_list_lookup (AF_INET6, name_str);
#endif /* HAVE_IPV6 */

  return CMD_SUCCESS;
}

int
bgp_prefix_list_unset (struct vty *vty, char *ip_str, int afi, char *name_str,
		       char *direct_str)
{
  struct peer_conf *conf;
  int direct;
  struct bgp_filter *filter;

  conf = peer_conf_lookup_vty (vty, ip_str, afi);
  if (! conf)
    return CMD_WARNING;
  
  /* Check filter direction. */
  if (strcmp (direct_str, "in") == 0)
    direct = BGP_FILTER_IN;
  else if (strcmp (direct_str, "out") == 0)
    direct = BGP_FILTER_OUT;
  else
    {
      vty_out (vty, "filter direction must be [in|out]%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  filter = &conf->filter;

  if (! filter->plist[direct].name)
    {
      vty_out (vty, "There is no such filter: %s%s", name_str, VTY_NEWLINE);
      return CMD_WARNING;
    }
  if (strcmp (filter->plist[direct].name, name_str) != 0)
    {
      vty_out (vty, "There is no such filter: %s%s", name_str, VTY_NEWLINE);
      return CMD_WARNING;
    }
  free (filter->plist[direct].name);
  filter->plist[direct].name = NULL;
  filter->plist[direct].v4 = NULL;
  filter->plist[direct].v6 = NULL;

  return CMD_SUCCESS;
}

/* Update prefix-list list. */
void
bgp_prefix_list_update ()
{
  struct newnode *nn, *nm;
  struct bgp *bgp;
  struct peer_conf *conf;
  struct bgp_filter *filter;

  NEWLIST_LOOP (bgp_list, bgp, nn)
    {
      NEWLIST_LOOP (bgp->peer_conf, conf, nm)
	{
	  filter = &conf->filter;

	  /* Input filter update. */
	  if (filter->plist[BGP_FILTER_IN].name)
	    {
	      filter->plist[BGP_FILTER_IN].v4 = 
		prefix_list_lookup (AF_INET, filter->plist[BGP_FILTER_IN].name);
#ifdef HAVE_IPV6
	      filter->plist[BGP_FILTER_IN].v6 = 
		prefix_list_lookup (AF_INET6, filter->plist[BGP_FILTER_IN].name);
#endif /* HAVE_IPV6 */
	    }
	  else
	    {
	      filter->plist[BGP_FILTER_IN].v4 = NULL;
#ifdef HAVE_IPV6
	      filter->plist[BGP_FILTER_IN].v6 = NULL;
#endif /* HAVE_IPV6 */
	    }
	  /* Output filter update. */
	  if (filter->plist[BGP_FILTER_OUT].name)
	    {
	      filter->plist[BGP_FILTER_OUT].v4 = 
		prefix_list_lookup (AF_INET, filter->plist[BGP_FILTER_OUT].name);
#ifdef HAVE_IPV6
	      filter->plist[BGP_FILTER_OUT].v6 = 
		prefix_list_lookup (AF_INET6, filter->plist[BGP_FILTER_OUT].name);
#endif /* HAVE_IPV6 */
	    }
	  else
	    {
	      filter->plist[BGP_FILTER_OUT].v4 = NULL;
#ifdef HAVE_IPV6
	      filter->plist[BGP_FILTER_OUT].v6 = NULL;
#endif /* HAVE_IPV6 */
	    }
	}
    }
}

DEFUN (neighbor_prefix_list,
       neighbor_prefix_list_cmd,
       NEIGHBOR_CMD "prefix-list WORD (in|out)",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Filter updates to/from this neighbor\n"
       "Name of a prefix list\n"
       "Filter incoming updates\n"
       "Filter outgoing updates\n")
{
  return bgp_prefix_list_set (vty, argv[0], AFI_IP, argv[1], argv[2]);
}

DEFUN (no_neighbor_prefix_list,
       no_neighbor_prefix_list_cmd,
       NO_NEIGHBOR_CMD "prefix-list WORD (in|out)",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Filter updates to/from this neighbor\n"
       "Name of a prefix list\n"
       "Filter incoming updates\n"
       "Filter outgoing updates\n")
{
  return bgp_prefix_list_unset (vty, argv[0], AFI_IP, argv[1], argv[2]);
}

DEFUN (ipv6_bgp_neighbor_prefix_list,
       ipv6_bgp_neighbor_prefix_list_cmd,
       "ipv6 bgp neighbor (A.B.C.D|X:X::X:X) prefix-list WORD (in|out)",
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Filter updates to/from this neighbor\n"
       "Name of a prefix list\n"
       "Filter incoming updates\n"
       "Filter outgoing updates\n")
{
  return bgp_prefix_list_set (vty, argv[0], AFI_IP6, argv[1], argv[2]);
}

DEFUN (no_ipv6_bgp_neighbor_prefix_list,
       no_ipv6_bgp_neighbor_prefix_list_cmd,
       "no ipv6 bgp neighbor (A.B.C.D|X:X::X:X) prefix-list WORD (in|out)",
       NO_STR
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Filter updates to/from this neighbor\n"
       "Name of a prefix list\n"
       "Filter incoming updates\n"
       "Filter outgoing updates\n")
{
  return bgp_prefix_list_unset (vty, argv[0], AFI_IP6, argv[1], argv[2]);
}

int
bgp_aslist_set (struct vty *vty, char *ip_str, int afi, char *name_str,
		char *direct_str)
{
  struct as_list *as_list_lookup (char *name);
  struct peer_conf *conf;
  int direct;
  struct bgp_filter *filter;

  conf = peer_conf_lookup_vty (vty, ip_str, afi);
  if (! conf)
    return CMD_WARNING;

  /* Check filter direction. */
  if (strcmp (direct_str, "in") == 0)
    direct = BGP_FILTER_IN;
  else if (strcmp (direct_str, "out") == 0)
    direct = BGP_FILTER_OUT;
  else
    {
      vty_out (vty, "filter direction must be [in|out]%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  filter = &conf->filter;

  if (filter->aslist[direct].name)
    free (filter->aslist[direct].name);

  filter->aslist[direct].name = strdup (name_str);
  filter->aslist[direct].aslist = as_list_lookup (name_str);

  return CMD_SUCCESS;
}

int
bgp_aslist_unset (struct vty *vty, char *ip_str, int afi, char *name_str,
		  char *direct_str)
{
  struct peer_conf *conf;
  int direct;
  struct bgp_filter *filter;

  conf = peer_conf_lookup_vty (vty, ip_str, afi);
  if (! conf)
    return CMD_WARNING;
  
  /* Check filter direction. */
  if (strcmp (direct_str, "in") == 0)
    direct = BGP_FILTER_IN;
  else if (strcmp (direct_str, "out") == 0)
    direct = BGP_FILTER_OUT;
  else
    {
      vty_out (vty, "filter direction must be [in|out]%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  filter = &conf->filter;
  
  if (! filter->aslist[direct].name)
    {
      vty_out (vty, "There is no such filter: %s%s", name_str, VTY_NEWLINE);
      return CMD_WARNING;
    }
  if (strcmp (filter->aslist[direct].name, name_str) != 0)
    {
      vty_out (vty, "There is no such filter: %s%s", name_str, VTY_NEWLINE);
      return CMD_WARNING;
    }
  free (filter->aslist[direct].name);
  filter->aslist[direct].name = NULL;
  filter->aslist[direct].aslist = NULL;

  return CMD_SUCCESS;
}

void
bgp_aslist_update ()
{
  struct newnode *nn, *nm;
  struct bgp *bgp;
  struct peer_conf *conf;
  struct bgp_filter *filter;
  struct as_list *as_list_lookup (char *name);

  NEWLIST_LOOP (bgp_list, bgp, nn)
    {
      NEWLIST_LOOP (bgp->peer_conf, conf, nm)
	{
	  filter = &conf->filter;

	  /* Input filter update. */
	  if (filter->aslist[BGP_FILTER_IN].name)
	    filter->aslist[BGP_FILTER_IN].aslist = 
	      as_list_lookup (filter->aslist[BGP_FILTER_IN].name);
	  else
	    filter->aslist[BGP_FILTER_IN].aslist = NULL;
	  /* Output filter update. */
	  if (filter->aslist[BGP_FILTER_OUT].name)
	    filter->aslist[BGP_FILTER_OUT].aslist = 
	      as_list_lookup (filter->aslist[BGP_FILTER_OUT].name);
	  else
	    filter->aslist[BGP_FILTER_OUT].aslist = NULL;
	}
    }
}

DEFUN (neighbor_filter_list,
       neighbor_filter_list_cmd,
       NEIGHBOR_CMD "filter-list WORD (in|out)",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Establish BGP filters\n"
       "AS path access-list name\n"
       "Filter incoming routes\n"
       "Filter outgoing routes\n")
{
  return bgp_aslist_set (vty, argv[0], AFI_IP, argv[1], argv[2]);
}

DEFUN (no_neighbor_filter_list,
       no_neighbor_filter_list_cmd,
       NO_NEIGHBOR_CMD "filter-list WORD (in|out)",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Establish BGP filters\n"
       "AS path access-list name\n"
       "Filter incoming routes\n"
       "Filter outgoing routes\n")
{
  return bgp_aslist_unset (vty, argv[0], AFI_IP, argv[1], argv[2]);
}

DEFUN (ipv6_bgp_neighbor_filter_list,
       ipv6_bgp_neighbor_filter_list_cmd,
       "ipv6 bgp neighbor (A.B.C.D|X:X::X:X) filter-list WORD (in|out)",
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Establish BGP filters\n"
       "AS path access-list name\n"
       "Filter incoming routes\n"
       "Filter outgoing routes\n")
{
  return bgp_aslist_set (vty, argv[0], AFI_IP6, argv[1], argv[2]);
}

DEFUN (no_ipv6_bgp_neighbor_filter_list,
       no_ipv6_bgp_neighbor_filter_list_cmd,
       "no ipv6 bgp neighbor (A.B.C.D|X:X::X:X) filter-list WORD (in|out)",
       NO_STR
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Establish BGP filters\n"
       "AS path access-list name\n"
       "Filter incoming routes\n"
       "Filter outgoing routes\n")
{
  return bgp_aslist_unset (vty, argv[0], AFI_IP6, argv[1], argv[2]);
}

/* Set route-map to the peer. */
int
bgp_route_map_set (struct vty *vty, char *ip_str, int afi, char *name_str,
		   char *direct_str)
{
  struct peer_conf *conf;
  int direct;
  struct bgp_filter *filter;

  conf = peer_conf_lookup_vty (vty, ip_str, afi);
  if (! conf)
    return CMD_WARNING;

  /* Check filter direction. */
  if (strcmp (direct_str, "in") == 0)
    direct = BGP_FILTER_IN;
  else if (strcmp (direct_str, "out") == 0)
    direct = BGP_FILTER_OUT;
  else
    {
      vty_out (vty, "filter direction must be [in|out]%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  filter = &conf->filter;

  if (filter->map[direct].name)
    free (filter->map[direct].name);
  
  filter->map[direct].name = strdup (name_str);
  filter->map[direct].map = route_map_lookup_by_name (name_str);

  return CMD_SUCCESS;
}

/* Unset route-map from the peer. */
int
bgp_route_map_unset (struct vty *vty, char *ip_str, int afi, char *name_str,
		     char *direct_str)
{
  struct peer_conf *conf;
  int direct;
  struct bgp_filter *filter;

  conf = peer_conf_lookup_vty (vty, ip_str, afi);
  if (! conf)
    return CMD_WARNING;
  
  /* Check filter direction. */
  if (strcmp (direct_str, "in") == 0)
    direct = BGP_FILTER_IN;
  else if (strcmp (direct_str, "out") == 0)
    direct = BGP_FILTER_OUT;
  else
    {
      vty_out (vty, "filter direction must be [in|out]%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  filter = &conf->filter;

  if (! filter->map[direct].name)
    {
      vty_out (vty, "There is no such filter: %s%s", name_str, VTY_NEWLINE);
      return CMD_WARNING;
    }
  if (strcmp (filter->map[direct].name, name_str) != 0)
    {
      vty_out (vty, "There is no such filter: %s%s", name_str, VTY_NEWLINE);
      return CMD_WARNING;
    }

  free (filter->map[direct].name);
  filter->map[direct].name = NULL;
  filter->map[direct].map = NULL;

  return CMD_SUCCESS;
}

DEFUN (neighbor_route_map,
       neighbor_route_map_cmd,
       NEIGHBOR_CMD "route-map WORD (in|out)",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Apply route map to neighbor\n"
       "Name of route map\n"
       "Apply map to incoming routes\n"
       "Apply map to outbound routes\n")
{
  return bgp_route_map_set (vty, argv[0], AFI_IP, argv[1], argv[2]);
}

DEFUN (no_neighbor_route_map,
       no_neighbor_route_map_cmd,
       NO_NEIGHBOR_CMD "route-map WORD (in|out)",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Apply route map to neighbor\n"
       "Name of route map\n"
       "Apply map to incoming routes\n"
       "Apply map to outbound routes\n")
{
  return bgp_route_map_unset (vty, argv[0], AFI_IP, argv[1], argv[2]);
}

DEFUN (ipv6_bgp_neighbor_route_map,
       ipv6_bgp_neighbor_route_map_cmd,
       "ipv6 bgp neighbor (A.B.C.D|X:X::X:X) route-map WORD (in|out)",
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Apply route map to neighbor\n"
       "Name of route map\n"
       "Apply map to incoming routes\n"
       "Apply map to outbound routes\n")
{
  return bgp_route_map_set (vty, argv[0], AFI_IP6, argv[1], argv[2]);
}

DEFUN (no_ipv6_bgp_neighbor_route_map,
       no_ipv6_bgp_neighbor_route_map_cmd,
       "no ipv6 bgp neighbor (A.B.C.D|X:X::X:X) route-map WORD (in|out)",
       NO_STR
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Apply route map to neighbor\n"
       "Name of route map\n"
       "Apply map to incoming routes\n"
       "Apply map to outbound routes\n")
{
  return bgp_route_map_unset (vty, argv[0], AFI_IP6, argv[1], argv[2]);
}

int
bgp_maximum_prefix_set (struct vty *vty, char *ip_str, u_int16_t afi,
			char *num_str)
{
  struct peer_conf *conf;
  unsigned long num;
  char *endptr = NULL;

  /* Lookup peer configuration. */
  conf = peer_conf_lookup_vty (vty, ip_str, afi);
  if (! conf)
    return CMD_WARNING;

  /* Convert string to unsigned long. */
  num = strtoul (num_str, &endptr, 10);
  if (num == ULONG_MAX || *endptr != '\0')
    {
      vty_out (vty, "maximum-prefix count must be positive integer%s",
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Set maximum prefix value. */
  conf->pmax[afi][SAFI_UNICAST] = num;

  return CMD_SUCCESS;
}

int
bgp_maximum_prefix_unset (struct vty *vty, char *ip_str, u_int16_t afi,
			  char *num_str)
{
  struct peer_conf *conf;
  unsigned long num;
  char *endptr = NULL;

  /* Lookup peer configuration. */
  conf = peer_conf_lookup_vty (vty, ip_str, afi);
  if (! conf)
    return CMD_WARNING;

  /* Convert string to unsigned long. */
  if (num_str)
    {
      num = strtoul (num_str, &endptr, 10);
      if (num == ULONG_MAX || *endptr != '\0')
	{
	  vty_out (vty, "maximum-prefix count must be positive integer%s",
		   VTY_NEWLINE);
	  return CMD_WARNING;
	}

      if (conf->pmax[afi][SAFI_UNICAST] != num)
	{
	  vty_out (vty, "maximum-prefix configuration mismatch%s",
		   VTY_NEWLINE);
	  return CMD_WARNING;
	}
    }

  conf->pmax[afi][SAFI_UNICAST] = 0;

  return CMD_SUCCESS;
}

/* Maximum number of prefix configuration.  prefix count is different
   for each peer configuration.  So this configuration can be set for
   each peer configuration. */
DEFUN (neighbor_maximum_prefix,
       neighbor_maximum_prefix_cmd,
       NEIGHBOR_CMD "maximum-prefix <1-4294967295>",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Maximum number of prefix accept from this peer\n"
       "maximum no. of prefix limit\n")
{
  return bgp_maximum_prefix_set (vty, argv[0], AFI_IP, argv[1]);
}

DEFUN (no_neighbor_maximum_prefix,
       no_neighbor_maximum_prefix_cmd,
       NO_NEIGHBOR_CMD "maximum-prefix [NUMBER]",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Maximum number of prefix accept from this peer\n"
       "maximum no. of prefix limit\n")
{
  return bgp_maximum_prefix_unset (vty, argv[0], AFI_IP, 
				   argc >= 2 ? argv[1] : NULL);
}

/* BGP clear types. */
enum clear_type
{
  clear_all,
  clear_peer,
  clear_peer_group,
  clear_as
};

int
peer_have_afi (struct peer *peer, int afi)
{
  return ((afi == AFI_IP && (peer->afc[AFI_IP][SAFI_UNICAST]
			     || peer->afc[AFI_IP][SAFI_MULTICAST])) 
	  || (afi == AFI_IP6 && (peer->afc[AFI_IP6][SAFI_UNICAST] 
				 || peer->afc[AFI_IP6][SAFI_MULTICAST])));
}

/* `clear ip bgp' functions. */
int
clear_bgp (struct vty *vty, int afi, enum clear_type type, char *arg)
{
  int cleared;
  struct peer *peer;
  struct newnode *nn;
  as_t as;
  unsigned long as_ul;
  char *endptr = NULL;
  union sockunion su;
  int ret;

  /* Clear all bgp neighbors. */
  if (type == clear_all)
    {
      NEWLIST_LOOP (peer_list, peer, nn)
	{
	  if (peer_have_afi (peer, afi))
	    {
	      if (! CHECK_FLAG (peer->flags, PEER_FLAG_SHUTDOWN))
		{
		  UNSET_FLAG (peer->sflags, PEER_STATUS_PREFIX_OVERFLOW);
		  peer->v_start = BGP_INIT_START_TIMER;
		  BGP_EVENT_ADD (peer, BGP_Stop);
		}
	    }
	}
      vty_out (vty, "All bgp neighbors cleared%s", VTY_NEWLINE);

      return CMD_SUCCESS;
    }
  /* Clear specified peer.  Arg is string of the peer. */
  else if (type == clear_peer)
    {
      cleared = 0;

      /* Make sockunion for lookup. */
      ret = str2sockunion (arg, &su);
      if (ret < 0)
	{
	  vty_out (vty, "Malformed address: %s%s", arg, VTY_NEWLINE);
	  return CMD_WARNING;
	}

      NEWLIST_LOOP (peer_list, peer, nn)
	{
	  if (peer_have_afi (peer, afi) && sockunion_same (&peer->su, &su))
	    {
	      if (! CHECK_FLAG (peer->flags, PEER_FLAG_SHUTDOWN))
		{
		  UNSET_FLAG (peer->sflags, PEER_STATUS_PREFIX_OVERFLOW);
		  peer->v_start = BGP_INIT_START_TIMER;
		  BGP_EVENT_ADD (peer, BGP_Stop);
		}
	      cleared = 1;
	    }
	}

      if (cleared)
	vty_out (vty, "Peer %s cleared%s", arg, VTY_NEWLINE);
      else
	vty_out (vty, "Can't find peer %s%s", arg, VTY_NEWLINE);

      return CMD_SUCCESS;
    }
  /* AS based clear. */
  else if (type == clear_as)
    {
      cleared = 0;

      as_ul = strtoul(arg, &endptr, 10);

      if ((as_ul == ULONG_MAX) || (*endptr != '\0') || (as_ul > USHRT_MAX))
	{
	  vty_out (vty, "Invalid neighbor specifier: %s%s", arg, 
		   VTY_NEWLINE);
	  return CMD_SUCCESS;
	}

      as = (as_t) as_ul;

      NEWLIST_LOOP (peer_list, peer, nn)
	{
	  if (peer_have_afi (peer, afi) && peer->as == as)
	    {
	      if (! CHECK_FLAG (peer->flags, PEER_FLAG_SHUTDOWN))
		{
		  UNSET_FLAG (peer->sflags, PEER_STATUS_PREFIX_OVERFLOW);
		  peer->v_start = BGP_INIT_START_TIMER;
		  BGP_EVENT_ADD (peer, BGP_Stop);
		}
	      cleared = 1;
	    }
	}
      if (cleared)
	vty_out (vty, "All neighbors which AS is %s cleared%s", arg, 
		 VTY_NEWLINE);
      else
	vty_out (vty, "No neighbor with AS %s cleared%s", arg, VTY_NEWLINE);
           
      return CMD_SUCCESS;
    }

  /* Not reached. */
  return CMD_SUCCESS;
}

DEFUN (clear_ip_bgp_all,
       clear_ip_bgp_all_cmd,
       "clear ip bgp *",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all connections\n")
{
  return clear_bgp (vty, AFI_IP, clear_all, NULL);
}

DEFUN (clear_ip_bgp_peer,
       clear_ip_bgp_peer_cmd, 
       "clear ip bgp (A.B.C.D|X:X::X:X)",
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP neighbor IP address to clear\n"
       "BGP neighbor IPv6 address to clear\n")
{
  return clear_bgp (vty, AFI_IP, clear_peer, argv[0]);
}

DEFUN (clear_ip_bgp_peer_group,
       clear_ip_bgp_peer_group_cmd, 
       "clear ip bgp peer-group WORD",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear BGP connections of peer-group\n"
       "BGP peer-group name to clear connection\n")
{
  return clear_bgp (vty, AFI_IP, clear_peer_group, argv[0]);
}

DEFUN (clear_ip_bgp_as,
       clear_ip_bgp_as_cmd,
       "clear ip bgp <1-65535>",
       CLEAR_STR
       IP_STR
       BGP_STR
       "AS number of the peers\n")
{
  return clear_bgp (vty, AFI_IP, clear_as, argv[0]);
}       

#ifdef HAVE_IPV6
DEFUN (clear_ipv6_bgp_all,
       clear_ipv6_bgp_all_cmd,
       "clear ipv6 bgp *",
       CLEAR_STR
       IPV6_STR
       BGP_STR
       "Clear all connections\n")
{
  return clear_bgp (vty, AFI_IP6, clear_all, NULL);
}

DEFUN (clear_ipv6_bgp_peer,
       clear_ipv6_bgp_peer_cmd, 
       "clear ipv6 bgp (A.B.C.D|X:X::X:X)",
       CLEAR_STR
       IPV6_STR
       BGP_STR
       "BGP neighbor IP address to clear\n"
       "BGP neighbor IPv6 address to clear\n")
{
  return clear_bgp (vty, AFI_IP6, clear_peer, argv[0]);
}

DEFUN (clear_ipv6_bgp_peer_group,
       clear_ipv6_bgp_peer_group_cmd, 
       "clear ipv6 bgp peer-group WORD",
       CLEAR_STR
       IPV6_STR
       BGP_STR
       "Clear BGP connections of peer-group\n"
       "BGP peer-group name to clear connection\n")
{
  return clear_bgp (vty, AFI_IP6, clear_peer_group, argv[0]);
}

DEFUN (clear_ipv6_bgp_as,
       clear_ipv6_bgp_as_cmd,
       "clear ipv6 bgp <1-65535>",
       CLEAR_STR
       IPV6_STR
       BGP_STR
       "AS number of the peers\n")
{
  return clear_bgp (vty, AFI_IP6, clear_as, argv[0]);
}       
#endif /* HAVE_IPV6 */

/* Clear ip bgp neighbor soft in. */
int
clear_bgp_soft_in (struct vty *vty, afi_t afi, char *ip_str)
{
  int ret;
  union sockunion su;
  struct peer *peer;
  struct newnode *nn;
  int cleared = 0;

  /* Looking up peer with IP address string. */
  ret = str2sockunion (ip_str, &su);
  if (ret < 0)
    {
      vty_out (vty, "Malformed address: %s%s", ip_str, VTY_NEWLINE);
      return CMD_WARNING;
    }

  NEWLIST_LOOP (peer_list, peer, nn)
    {
      if (peer_have_afi (peer, afi) && sockunion_same (&peer->su, &su))
	{
	  /* If neighbor has route refresh capability, send route refresh
	     message to the peer. */
	  if (peer->refresh && peer->status == Established)
	    {
	      bgp_route_refresh_send (peer, afi, SAFI_UNICAST);
	      bgp_route_refresh_send (peer, afi, SAFI_MULTICAST);
	      cleared = 1;
	    }
	  else
	    {
	      /* If neighbor has soft reconfiguration inbound flag.
                 Use Adj-RIB-In database. */
	      if (CHECK_FLAG (peer->flags, PEER_FLAG_SOFT_RECONFIG))
		{
		  bgp_soft_reconfig_in (peer);
		  cleared = 1;
		}
	    }
	}
    }

  if (cleared)
    vty_out (vty, "Peer %s is cleared%s", ip_str, VTY_NEWLINE);
  else
    vty_out (vty, "Can't soft clear peer %s%s", ip_str, VTY_NEWLINE);

  return CMD_SUCCESS;
}

DEFUN (clear_ip_bgp_peer_soft_in,
       clear_ip_bgp_peer_soft_in_cmd,
       "clear ip bgp A.B.C.D soft in",
       CLEAR_STR
       IP_STR
       BGP_STR
       "IP address\n"
       "Soft reconfiguration\n"
       "soft reconfigure inbound update\n")
{
  return clear_bgp_soft_in (vty, AFI_IP, argv[0]);
}

DEFUN (clear_ipv6_bgp_peer_soft_in,
       clear_ipv6_bgp_peer_soft_in_cmd,
       "clear ipv6 bgp (A.B.C.D|X:X::X:X) soft in",
       CLEAR_STR
       IPV6_STR
       BGP_STR
       "IP address\n"
       "IPv6 address\n"
       "Soft reconfiguration\n"
       "soft reconfigure inbound update\n")
{
  return clear_bgp_soft_in (vty, AFI_IP6, argv[0]);
}

/* Show BGP peer's summary information. */
int
bgp_show_summary (struct vty *vty, int afi, int safi, int all)
{
  struct bgp *bgp;
  struct peer *peer;
  struct peer_conf *conf;
  struct newnode *nn;
  struct newnode *nm;
  int write = 0;
  char timebuf[BGP_UPTIME_LEN];

  /* Header string for each address family. */
  static char header_v4[] = " Neighbor        V     AS MsgRcvd MsgSent   TblVer InQ OutQ Up/Down  State/Pref";
  static char header_v6[] = " Neighbor                          AS      MsgRcvd MsgSent  Up/Down  State/Pref";

  NEWLIST_LOOP (bgp_list, bgp, nn)
    {
      NEWLIST_LOOP (bgp->peer_conf, conf, nm)
	{
	  peer = conf->peer;

	  if (conf->afc[afi][safi] || all)
	    {
	      if (! write)
		{
		  vty_out (vty, "%s%s", afi == AFI_IP ? header_v4 : header_v6,
			   VTY_NEWLINE);
		  write++;
		}

	      if (afi == AFI_IP)
		vty_out (vty, "%-17s", peer->host);
	      else
		vty_out (vty, "%-31s", peer->host);

	      if (afi == AFI_IP)
		{
		  switch (peer->version) 
		    {
		    case BGP_VERSION_4:
		      vty_out (vty, "%d ", peer->version);
		      break;
		    case BGP_VERSION_MP_4:
		      vty_out (vty, "4+");
		      break;
		    case BGP_VERSION_MP_4_DRAFT_00:
		      vty_out (vty, "4-");
		      break;
		    }
		}

	      if (afi == AFI_IP)
		vty_out (vty, " %5d %7d %7d %7d %4d %4d ",
			 peer->as,
			 peer->open_in + peer->update_in +
			 peer->keepalive_in + peer->notify_in,
			 peer->open_out + peer->update_out +
			 peer->keepalive_out + peer->notify_out,
			 0, 0, peer->obuf->count);
	      else
		vty_out (vty, " %5d     %7d %7d   ",
			 peer->as,
			 peer->open_in + peer->update_in +
			 peer->keepalive_in + peer->notify_in,
			 peer->open_out + peer->update_out +
			 peer->keepalive_out + peer->notify_out);

	      vty_out (vty, "%8s", 
		       peer_uptime (peer, timebuf, BGP_UPTIME_LEN));

	      if (peer->status == Established)
		{
		  vty_out (vty, " %9d", conf->pcount[afi][safi]);
		}
	      else
		{
		  if (CHECK_FLAG (peer->flags, PEER_FLAG_SHUTDOWN))
		    vty_out (vty, " Shutdown");
		  else if (CHECK_FLAG (peer->sflags, PEER_STATUS_PREFIX_OVERFLOW))
		    vty_out (vty, " PrefixOvflw");
		  else
		    vty_out (vty, " %-11s", LOOKUP(bgp_status_msg, peer->status));
		}

	      vty_out (vty, "%s", VTY_NEWLINE);

	      if (afi == AFI_IP6 && peer->desc)
		vty_out (vty, "  Description: %s%s", peer->desc, VTY_NEWLINE);
	    }
	}
    }

  if (! write)
    vty_out (vty, "No %s neighbor is configured%s",
	     afi == AFI_IP ? "IPv4" : "IPv6", VTY_NEWLINE);
  return CMD_SUCCESS;
}

/* `show ip bgp summary' commands. */
DEFUN (show_ip_bgp_summary, 
       show_ip_bgp_summary_cmd,
       "show ip bgp summary",
       SHOW_STR
       IP_STR
       BGP_STR
       "Summary of BGP neighbor status\n")
{
  return bgp_show_summary (vty, AFI_IP, SAFI_UNICAST, 0);
}

/* `show ip bgp summary' commands. */
DEFUN (show_ip_bgp_summary_all, 
       show_ip_bgp_summary_all_cmd,
       "show ip bgp summary all",
       SHOW_STR
       IP_STR
       BGP_STR
       "Summary of BGP neighbor status\n"
       "Display all peers\n")
{
  return bgp_show_summary (vty, AFI_IP, SAFI_UNICAST, 1);
}

DEFUN (show_ip_mbgp_summary, 
       show_ip_mbgp_summary_cmd,
       "show ip mbgp summary",
       SHOW_STR
       IP_STR
       MBGP_STR
       "Summary of MBGP neighbor status\n")
{
  return bgp_show_summary (vty, AFI_IP, SAFI_MULTICAST, 0);
}

DEFUN (show_ip_bgp_vpnv4_all_summary,
       show_ip_bgp_vpnv4_all_summary_cmd,
       "show ip bgp vpnv4 all summary",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display VPNv4 NLRI specific information\n"
       "Display information about all VPNv4 NLRIs\n"
       "Summary of BGP neighbor status\n")
{
  return bgp_show_summary (vty, AFI_IP, SAFI_MPLS_VPN, 0);
}

#ifdef HAVE_IPV6
DEFUN (show_ipv6_bgp_summary, 
       show_ipv6_bgp_summary_cmd,
       "show ipv6 bgp summary",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Summary of BGP neighbor status\n")
{
  return bgp_show_summary (vty, AFI_IP6, SAFI_UNICAST, 0);
}

DEFUN (show_ipv6_mbgp_summary, 
       show_ipv6_mbgp_summary_cmd,
       "show ipv6 mbgp summary",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Summary of BGP neighbor status\n")
{
  return bgp_show_summary (vty, AFI_IP6, SAFI_MULTICAST, 0);
}
#endif /* HAVE_IPV6 */

/* Show BGP peer's information. */
enum show_type
{
  show_all,
  show_peer
};

/* Return next event time. */
int
bgp_next_timer (struct thread *thread)
{
  struct timeval timer_now;
  gettimeofday (&timer_now, NULL);
  return thread->u.sands.tv_sec - timer_now.tv_sec;
}

void
bgp_show_peer (struct vty *vty, struct peer_conf *conf, afi_t afi, safi_t safi)
{
  char buf1[BUFSIZ];
  char buf2[BUFSIZ];
  char timebuf[BGP_UPTIME_LEN];
  struct peer *p;
  struct bgp_filter *filter;

  p = conf->peer;
  filter = &conf->filter;

  /* Configured IP address. */
  vty_out (vty, "%s%s", p->host, VTY_NEWLINE);

  /* Description. */
  if (p->desc)
    vty_out (vty, "  Description: %s%s", p->desc, VTY_NEWLINE);

  /* BGP Version. */
  vty_out (vty, "  BGP version: 4");
  if (p->version == BGP_VERSION_MP_4_DRAFT_00)
    vty_out (vty, "(with draft-00 verion of multiporotocol extension)");
  vty_out (vty, "%s", VTY_NEWLINE);

  /* AS information. */
  vty_out (vty, "  Remote AS: %d, Local AS: %d, Link type: %s%s",
	   p->as, p->local_as, 
	   p->as == p->local_as ? "IBGP" :
	   (bgp_confederation_peers_check(conf->bgp, p->as) ? "CONFEDERATION" : "EBGP"),
	   VTY_NEWLINE);

  /* Router IDs. */
  vty_out (vty, "  Remote router ID: %s, Local router ID: %s%s", 
	   inet_ntop (AF_INET, &p->remote_id, buf1, BUFSIZ),
	   inet_ntop (AF_INET, &p->local_id, buf2, BUFSIZ), VTY_NEWLINE);

  /* Remote address. */
  if (p->su_remote)
    {
      vty_out (vty, "  Remote address: ");
      vty_out (vty, "%s%s", sockunion2str (p->su_remote, buf1, SU_ADDRSTRLEN),
	       VTY_NEWLINE);
    }

  /* Local address. */
  if (p->su_local)
    {
      vty_out (vty, "  Local address: ");
      vty_out (vty, "%s%s", sockunion2str (p->su_local, buf1, SU_ADDRSTRLEN),
	       VTY_NEWLINE);
    }

  /* Nexthop display. */
  if (p->su_local)
    {
      vty_out (vty, "  Nexthop: %s%s", 
	       inet_ntop (AF_INET, &p->nexthop.v4, buf1, BUFSIZ),
	       VTY_NEWLINE);
#ifdef HAVE_IPV6
      vty_out (vty, "  Nexthop global: %s", 
	       inet_ntop (AF_INET6, &p->nexthop.v6_global, buf1, BUFSIZ));
      vty_out (vty, "  Nexthop local: %s%s",
	       inet_ntop (AF_INET6, &p->nexthop.v6_local, buf1, BUFSIZ),
	       VTY_NEWLINE);
      vty_out (vty, "  BGP connection: %s%s",
	       p->shared_network ? "shared network" : "non shared network",
	       VTY_NEWLINE);
#endif /* HAVE_IPV6 */
    }

  /* Status. */
  vty_out (vty, "  BGP Status: %s, Old status: %s%s", 
	   CHECK_FLAG (p->flags, PEER_FLAG_SHUTDOWN) 
	   ? "Shutdown" : LOOKUP(bgp_status_msg, p->status),
	   LOOKUP(bgp_status_msg, p->ostatus),
	   VTY_NEWLINE);

  /* Packet counts. */
  vty_out(vty, "  Received packets: %d Send packets: %d%s",
	  p->open_in + p->update_in + p->keepalive_in + p->notify_in,
	  p->open_out + p->update_out + p->keepalive_out + p->notify_out,
	  VTY_NEWLINE);

  /* Configured timer values. */
  vty_out (vty,"  Keepalive: %d Holdtime: %d%s",
	   p->v_keepalive, p->v_holdtime, VTY_NEWLINE);

  /* Timer information. */
  if (p->t_start)
    vty_out (vty, "  Next start timer due in %d seconds%s",
	     bgp_next_timer (p->t_start), VTY_NEWLINE);
  if (p->t_connect)
    vty_out (vty, "  Next connect timer due in %d seconds%s",
	     bgp_next_timer (p->t_connect), VTY_NEWLINE);
  
  /* Elapsed time. */
  vty_out (vty, "  Elapsed time after last connection: %8s%s", 
	   peer_uptime (p, timebuf, BGP_UPTIME_LEN), VTY_NEWLINE);

  vty_out (vty, "  Read thread: %s  Write thread: %s%s", 
	   p->t_read ? "on" : "off",
	   p->t_write ? "on" : "off",
	   VTY_NEWLINE);

  /* Prefix count. */
  if (p->status == Established) 
    {
      vty_out (vty, "  IPv4 prefix count unicast/multicast: %d/%d%s", 
	       conf->pcount[AFI_IP][SAFI_UNICAST],
	       conf->pcount[AFI_IP][SAFI_MULTICAST], VTY_NEWLINE);
#ifdef HAVE_IPV6
      vty_out (vty, "  IPv6 prefix count unicast/multicast: %d/%d%s",
	       conf->pcount[AFI_IP6][SAFI_UNICAST],
	       conf->pcount[AFI_IP6][SAFI_MULTICAST], VTY_NEWLINE);
#endif /* HAVE_IPV6 */
    }

  /* distribute-list */
  if (afi == AFI_IP)
    {
      if (filter->dlist[BGP_FILTER_IN].name)
	vty_out (vty, "  distribute-list in: %s%s%s",
		 filter->dlist[BGP_FILTER_IN].v4 ? "*" : "",
		 filter->dlist[BGP_FILTER_IN].name,
		 VTY_NEWLINE);
      if (filter->dlist[BGP_FILTER_OUT].name)
	vty_out (vty, "  distribute-list out: %s%s%s",
		 filter->dlist[BGP_FILTER_OUT].v4 ? "*" : "",
		 filter->dlist[BGP_FILTER_OUT].name,
		 VTY_NEWLINE);

      /* prefix-list */
      if (filter->plist[BGP_FILTER_IN].name)
	vty_out (vty, "  prefix-list in: %s%s%s",
		 filter->plist[BGP_FILTER_IN].v4 ? "*" : "",
		 filter->plist[BGP_FILTER_IN].name,
		 VTY_NEWLINE);
      if (filter->plist[BGP_FILTER_OUT].name)
	vty_out (vty, "  prefix-list out: %s%s%s",
		 filter->plist[BGP_FILTER_OUT].v4 ? "*" : "",
		 filter->plist[BGP_FILTER_OUT].name,
		 VTY_NEWLINE);
    }
#ifdef HAVE_IPV6
  else if (afi == AFI_IP6)
    {
      if (filter->dlist[BGP_FILTER_IN].name)
	vty_out (vty, "  distribute-list in: %s%s%s",
		 filter->dlist[BGP_FILTER_IN].v6 ? "*" : "",
		 filter->dlist[BGP_FILTER_IN].name,
		 VTY_NEWLINE);
      if (filter->dlist[BGP_FILTER_OUT].name)
	vty_out (vty, "  distribute-list out: %s%s%s",
		 filter->dlist[BGP_FILTER_OUT].v6 ? "*" : "",
		 filter->dlist[BGP_FILTER_OUT].name,
		 VTY_NEWLINE);

      /* prefix-list */
      if (filter->plist[BGP_FILTER_IN].name)
	vty_out (vty, "  prefix-list in: %s%s%s",
		 filter->plist[BGP_FILTER_IN].v6 ? "*" : "",
		 filter->plist[BGP_FILTER_IN].name,
		 VTY_NEWLINE);
      if (filter->plist[BGP_FILTER_OUT].name)
	vty_out (vty, "  prefix-list out: %s%s%s",
		 filter->plist[BGP_FILTER_OUT].v6 ? "*" : "",
		 filter->plist[BGP_FILTER_OUT].name,
		 VTY_NEWLINE);
    }
#endif /* HAVE_IPV6 */

  /* filter-list. */
  if (filter->aslist[BGP_FILTER_IN].name)
    vty_out (vty, "  filter-list in: %s%s%s",
	     filter->aslist[BGP_FILTER_IN].aslist ? "*" : "",
	     filter->aslist[BGP_FILTER_IN].name,
	     VTY_NEWLINE);
  if (filter->aslist[BGP_FILTER_OUT].name)
    vty_out (vty, "  filter-list out: %s%s%s",
	     filter->aslist[BGP_FILTER_OUT].aslist ? "*" : "",
	     filter->aslist[BGP_FILTER_OUT].name,
	     VTY_NEWLINE);

  /* route-map. */
  if (filter->map[BGP_FILTER_IN].name)
    vty_out (vty, "  route-map in: %s%s%s",
	     filter->map[BGP_FILTER_IN].map ? "*" : "",
	     filter->map[BGP_FILTER_IN].name,
	     VTY_NEWLINE);
  if (filter->map[BGP_FILTER_OUT].name)
    vty_out (vty, "  route-map out: %s%s%s",
	     filter->map[BGP_FILTER_OUT].map ? "*" : "",
	     filter->map[BGP_FILTER_OUT].name,
	     VTY_NEWLINE);

  /* Address family configuration. */
  vty_out (vty, "  Neighbor NLRI negotiation:%s", VTY_NEWLINE);

  vty_out (vty, "   Configured for");

  /* IPv4 */
  if (p->afc[AFI_IP][SAFI_UNICAST]) 
    {
      vty_out (vty, " IPv4 unicast");

      if (p->afc[AFI_IP][SAFI_MULTICAST]) 
	vty_out (vty, " and multicast");
    }
  else
    {
      if (p->afc[AFI_IP][SAFI_MULTICAST]) 
	vty_out (vty, " IPv4 multicast");
    }
  if (p->afc[AFI_IP][SAFI_MPLS_VPN])
    vty_out (vty, " VPNv4 unicast");
  /* IPv6 */
#ifdef HAVE_IPV6
  if (p->afc[AFI_IP6][SAFI_UNICAST]) 
    {
      vty_out (vty, " IPv6 unicast");

      if (p->afc[AFI_IP6][SAFI_MULTICAST]) 
	vty_out (vty, " and multicast");
    }
  else
    {
      if (p->afc[AFI_IP6][SAFI_MULTICAST]) 
	vty_out (vty, " IPv6 multicast");
    }
#endif /* HAVE_IPV6 */
  vty_out(vty, "%s", VTY_NEWLINE);

  if (p->afc_nego[AFI_IP][SAFI_UNICAST] 
      || p->afc_nego[AFI_IP][SAFI_MULTICAST]
      || p->afc_nego[AFI_IP][SAFI_MPLS_VPN]
      || p->afc_nego[AFI_IP6][SAFI_UNICAST]
      || p->afc_nego[AFI_IP6][SAFI_MULTICAST])
    {
      vty_out (vty, "   Negotiated for");

      /* IPv4 */
      if (p->afc_nego[AFI_IP][SAFI_UNICAST])
	{
	  vty_out (vty, " IPv4 unicast");
	  if (p->afc_nego[AFI_IP][SAFI_MULTICAST]) 
	    vty_out (vty, "and multicast");
	}
      else
	{
	  if (p->afc_nego[AFI_IP][SAFI_MULTICAST]) 
	    vty_out (vty, " IPv4 multicast");
	}
      if (p->afc_nego[AFI_IP][SAFI_MPLS_VPN])
	vty_out (vty, " VPNv4 unicast");
#ifdef HAVE_IPV6
      if (p->afc_nego[AFI_IP6][SAFI_UNICAST])
	{
	  vty_out (vty, " IPv6 unicast");
	  if (p->afc_nego[AFI_IP6][SAFI_MULTICAST]) 
	    vty_out (vty, " and multicast");
	}
      else
	{
	  if (p->afc_nego[AFI_IP6][SAFI_MULTICAST]) 
	    vty_out (vty, " IPv6 multicast");
	}
#endif /* HAVE_IPV6 */
      vty_out (vty, "%s", VTY_NEWLINE);
    }
  else
    {
      if (p->status == Established)
	vty_out (vty, "   Negotiated for nothing.  Please check configuration.%s", VTY_NEWLINE);
    }

  if (p->notify.code == BGP_NOTIFY_OPEN_ERR
      && p->notify.subcode == BGP_NOTIFY_OPEN_UNSUP_CAPBL)
    bgp_capability_vty_out (vty, p);
}

int
bgp_show_neighbor (struct vty *vty, int afi, int safi, enum show_type type,
		   char *ip_str)
{
  struct newnode *nn, *nm;
  struct bgp *bgp;
  struct peer_conf *conf;
  union sockunion su;
  int ret;

  if (ip_str)
    {
      ret = str2sockunion (ip_str, &su);
      if (ret < 0)
	{
	  vty_out (vty, "Malformed address: %s", ip_str);
	  return CMD_WARNING;
	}
    }

  NEWLIST_LOOP (bgp_list, bgp, nn)
    {
      NEWLIST_LOOP (bgp->peer_conf, conf, nm)
	{
	  switch (type)
	    {
	    case show_all:
	      if (conf->afc[afi][safi])
		bgp_show_peer (vty, conf, afi, safi);
	      break;
	    case show_peer:
	      if (conf->afc[afi][safi] 
		  && sockunion_same (&conf->peer->su, &su))
		bgp_show_peer (vty, conf, afi, safi);
	      break;
	    }
	}
    }
  return CMD_SUCCESS;
}

DEFUN (show_ip_bgp_neighbors,
       show_ip_bgp_neighbors_cmd,
       "show ip bgp neighbors",
       SHOW_STR
       IP_STR
       BGP_STR
       "Detailed information on BGP neighbor\n")
{
  return bgp_show_neighbor (vty, AFI_IP, SAFI_UNICAST, show_all, NULL);
}

DEFUN (show_ip_bgp_neighbors_peer,
       show_ip_bgp_neighbors_peer_cmd,
       "show ip bgp neighbors (A.B.C.D|X:X::X:X)",
       SHOW_STR
       IP_STR
       BGP_STR
       "Detailed information on BGP neighbor\n"
       "IP address\n"
       "IPv6 address\n")
{
  return bgp_show_neighbor (vty, AFI_IP, SAFI_UNICAST, show_peer, argv[0]);
}

DEFUN (show_ip_mbgp_neighbors,
       show_ip_mbgp_neighbors_cmd,
       "show ip mbgp neighbors",
       SHOW_STR
       IP_STR
       MBGP_STR
       "Detailed information on MBGP neighbor\n")
{
  return bgp_show_neighbor (vty, AFI_IP, SAFI_MULTICAST, show_all, NULL);
}

DEFUN (show_ip_mbgp_neighbors_peer,
       show_ip_mbgp_neighbors_peer_cmd,
       "show ip mbgp neighbors (A.B.C.D|X:X::X:X)",
       SHOW_STR
       IP_STR
       MBGP_STR
       "Detailed information on MBGP neighbor\n"
       "IP address\n"
       "IPv6 address\n")
{
  return bgp_show_neighbor (vty, AFI_IP, SAFI_MULTICAST, show_peer, argv[0]);
}

DEFUN (show_ip_bgp_vpnv4_all_neighbors,
       show_ip_bgp_vpnv4_all_neighbors_cmd,
       "show ip bgp vpnv4 all neighbors",
       SHOW_STR
       IP_STR
       BGP_STR
       "VPNv4\n"
       "All\n"
       "Detailed information on BGP neighbor\n")
{
  return bgp_show_neighbor (vty, AFI_IP, SAFI_MPLS_VPN, show_all, NULL);
}

#ifdef HAVE_IPV6
DEFUN (show_ipv6_bgp_neighbors,
       show_ipv6_bgp_neighbors_cmd,
       "show ipv6 bgp neighbors [PEER]",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Detailed information on BGP neighbor\n")
{
  return bgp_show_neighbor (vty, AFI_IP6, SAFI_UNICAST, show_all, NULL);
}

DEFUN (show_ipv6_bgp_neighbors_peer,
       show_ipv6_bgp_neighbors_peer_cmd,
       "show ipv6 bgp neighbors (A.B.C.D|X:X::X:X)",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Detailed information on BGP neighbor\n"
       "IP address\n"
       "IPv6 address\n")
{
  return bgp_show_neighbor (vty, AFI_IP6, SAFI_UNICAST, show_peer, argv[0]);
}

DEFUN (show_ipv6_mbgp_neighbors,
       show_ipv6_mbgp_neighbors_cmd,
       "show ipv6 mbgp neighbors [PEER]",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Detailed information on MBGP neighbor\n")
{
  return bgp_show_neighbor (vty, AFI_IP6, SAFI_MULTICAST, show_all, NULL);
}

DEFUN (show_ipv6_mbgp_neighbors_peer,
       show_ipv6_mbgp_neighbors_peer_cmd,
       "show ipv6 mbgp neighbors (A.B.C.D|X:X::X:X)",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Detailed information on MBGP neighbor\n"
       "IP address\n"
       "IPv6 address\n")
{
  return bgp_show_neighbor (vty, AFI_IP6, SAFI_MULTICAST, show_peer, argv[0]);
}
#endif /* HAVE_IPV6 */

/* Show BGP's AS paths internal data.  There are both `show ip bgp
   paths' and `show ip mbgp paths'.  Those functions results are the
   same.*/
DEFUN (show_ip_bgp_paths, 
       show_ip_bgp_paths_cmd,
       "show ip bgp paths",
       SHOW_STR
       IP_STR
       BGP_STR
       "Path information\n")
{
  vty_out (vty, "Address Refcnt Path%s", VTY_NEWLINE);
  aspath_print_all_vty (vty);
  return CMD_SUCCESS;
}

DEFUN (show_ip_mbgp_paths, 
       show_ip_mbgp_paths_cmd,
       "show ip mbgp paths",
       SHOW_STR
       IP_STR
       MBGP_STR
       "Path information\n")
{
  vty_out (vty, "Address Refcnt Path\r\n");
  aspath_print_all_vty (vty);

  return CMD_SUCCESS;
}

/* Show BGP's community internal data. */
DEFUN (show_ip_bgp_community, 
       show_ip_bgp_community_cmd,
       "show ip bgp community",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the communities\n")
{
  vty_out (vty, "Address Refcnt Community%s", VTY_NEWLINE);
  community_print_all_vty (vty);
  return CMD_SUCCESS;
}

DEFUN (show_ip_mbgp_community, 
       show_ip_mbgp_community_cmd,
       "show ip mbgp community",
       SHOW_STR
       IP_STR
       MBGP_STR
       "Display routes matching the communities\n")
{
  vty_out (vty, "Address Refcnt Community\r\n");
  community_print_all_vty (vty);
  return CMD_SUCCESS;
}

/* BGP peer configuration display function. */
void
bgp_config_write_peer (struct vty *vty, struct bgp *bgp,
		       struct peer_conf *conf, afi_t afi, safi_t safi)
{
  struct peer *peer;
  char *v6str;
  char addr[SU_ADDRSTRLEN];
  char buf[SU_ADDRSTRLEN];
  struct bgp_filter *filter;

  peer = conf->peer;
  filter = &conf->filter;
  v6str = (afi == AFI_IP ? "" : " ipv6 bgp");
  if (afi == AFI_IP && safi == SAFI_MPLS_VPN)
    v6str = " ";
  sockunion2str (&peer->su, addr, SU_ADDRSTRLEN);

  /* remote-as. */
  if (safi == SAFI_MPLS_VPN)
    {
      vty_out (vty, "%s neighbor %s activate%s", v6str, addr, VTY_NEWLINE);
      return;
    }

  vty_out (vty, "%s neighbor %s remote-as %d",
	   v6str, addr, peer->as);
  if (conf->afc[afi][SAFI_UNICAST] && conf->afc[afi][SAFI_MULTICAST])
    vty_out (vty, " nlri unicast multicast");
  else if (conf->afc[afi][SAFI_MULTICAST])
    vty_out (vty, " nlri multicast");
  vty_out (vty, "%s", VTY_NEWLINE);

  /* activate. */
  if (afi == AFI_IP && safi == 0)
    {
      if (CHECK_FLAG (bgp->config, BGP_CONFIG_NO_DEFAULT_IPV4))
	{
	  if (conf->afc[AFI_IP][SAFI_UNICAST])
	    vty_out (vty, " neighbor %s activate%s", addr, VTY_NEWLINE);
	}
      else
	{
	  if (! conf->afc[AFI_IP][SAFI_UNICAST])
	    vty_out (vty, " no neighbor %s activate%s", addr, VTY_NEWLINE);
	}
    }

  /* passive. */
  if (CHECK_FLAG (peer->flags, PEER_FLAG_PASSIVE))
    vty_out (vty, "%s neighbor %s passive%s", v6str, addr, VTY_NEWLINE);

  /* BGP port. */
  if (peer->port != BGP_PORT_DEFAULT)
    vty_out (vty, "%s neighbor %s port %d%s", v6str, addr, peer->port, 
	     VTY_NEWLINE);

  /* Local interface name. */
  if (peer->ifname)
    vty_out (vty, "%s neighbor %s interface %s%s", v6str, addr, peer->ifname,
	     VTY_NEWLINE);
  
  /* Update-source. */
  if (peer->update_if)
    vty_out (vty, "%s neighbor %s update-source %s%s", v6str, addr, 
	     peer->update_if, VTY_NEWLINE);
  if (peer->update_source)
    vty_out (vty, "%s neighbor %s update-source %s%s", v6str, addr, 
	     sockunion2str (peer->update_source, buf, SU_ADDRSTRLEN),
	     VTY_NEWLINE);

  /* Shutdown. */
  if (CHECK_FLAG (peer->flags, PEER_FLAG_SHUTDOWN))
    vty_out (vty, "%s neighbor %s shutdown%s", v6str, addr, VTY_NEWLINE);

  /* Description. */
  if (peer->desc)
    vty_out (vty, "%s neighbor %s description %s%s", v6str, addr, peer->desc,
	     VTY_NEWLINE);

  /* BGP version print. */
  if (peer->version != BGP_VERSION_4)
    {
      vty_out (vty, "%s neighbor %s", v6str, addr);

      if (peer->version == BGP_VERSION_MP_4)
	vty_out (vty, " version %s%s", "4+", VTY_NEWLINE);
      else if (peer->version == BGP_VERSION_MP_4_DRAFT_00)
	vty_out (vty, " version %s%s", "4-", VTY_NEWLINE);
    }

  /* Default information */
  if (CHECK_FLAG (peer->flags, PEER_FLAG_DEFAULT_ORIGINATE))
    vty_out (vty, "%s neighbor %s default-originate%s", v6str, addr,
	     VTY_NEWLINE);

  /* Nexthop self. */
  if (CHECK_FLAG (peer->flags, PEER_FLAG_NEXTHOP_SELF))
    vty_out (vty, "%s neighbor %s next-hop-self%s", v6str, addr, VTY_NEWLINE);

  /* Soft reconfiguration inbound. */
  if (CHECK_FLAG (peer->flags, PEER_FLAG_SOFT_RECONFIG))
    vty_out (vty, "%s neighbor %s soft-reconfiguration inbound%s", v6str, addr,
	     VTY_NEWLINE);

  /* Route reflector client. */
  if (CHECK_FLAG (peer->flags, PEER_FLAG_REFLECTOR_CLIENT))
    vty_out (vty, "%s neighbor %s route-reflector-client%s", v6str, addr,
	     VTY_NEWLINE);

  /* Route server client. */
  if (CHECK_FLAG (peer->flags, PEER_FLAG_RSERVER_CLIENT))
    vty_out (vty, "%s neighbor %s route-server-client%s", v6str, addr,
	     VTY_NEWLINE);

  /* Route refresh. */
  if (CHECK_FLAG (peer->flags, PEER_FLAG_ROUTE_REFRESH))
    vty_out (vty, "%s neighbor %s route-refresh%s", v6str, addr,
	     VTY_NEWLINE);

  /* ebgp-multihop print. */
  if (peer_sort (peer) == BGP_PEER_EBGP && peer->ttl != 1)
    {
      vty_out (vty, "%s neighbor %s", v6str, addr);

      if (peer->ttl == TTL_MAX)
	vty_out (vty, " ebgp-multihop%s", VTY_NEWLINE);
      else
	vty_out (vty, " ebgp-multihop %d%s", peer->ttl, VTY_NEWLINE);
    }

  /* send-community print. */
  if (! (CHECK_FLAG (peer->flags, PEER_FLAG_SEND_COMMUNITY)))
    vty_out (vty, " no%s neighbor %s send-community%s", v6str, addr,
	     VTY_NEWLINE);

  /* send-community print. */
  if (! (CHECK_FLAG (peer->flags, PEER_FLAG_SEND_EXT_COMMUNITY)))
    vty_out (vty, " no%s neighbor %s send-community extended%s", v6str, addr,
	     VTY_NEWLINE);

  /* dont capability negotiation. */
  if (CHECK_FLAG (peer->flags, PEER_FLAG_DONT_CAPABILITY))
    vty_out (vty, "%s neighbor %s dont-capability-negotiate%s", v6str, addr,
	     VTY_NEWLINE);

  /* override capability negotiation. */
  if (CHECK_FLAG (peer->flags, PEER_FLAG_OVERRIDE_CAPABILITY))
    vty_out (vty, "%s neighbor %s override-capability%s", v6str, addr,
	     VTY_NEWLINE);

  /* strict capability negotiation. */
  if (CHECK_FLAG (peer->flags, PEER_FLAG_STRICT_CAP_MATCH))
    vty_out (vty, "%s neighbor %s strict-capability-match%s", v6str, addr,
	     VTY_NEWLINE);

  /* Default weight. */
  if (peer->config & PEER_CONFIG_WEIGHT)
    vty_out (vty, "%s neighbor %s weight %d%s", v6str, addr, peer->weight,
	     VTY_NEWLINE);

  /* translate-update. */
  if (peer->translate_update)
    {
      vty_out (vty, "%s neighbor %s", v6str, addr);

      if (peer->translate_update == SAFI_UNICAST_MULTICAST) 
	vty_out (vty, " translate-update nlri unicast multicast%s", 
		 VTY_NEWLINE);
      else if (peer->translate_update == SAFI_MULTICAST) 
	vty_out (vty, " translate-update nlri multicast%s", 
		 VTY_NEWLINE);
    }

  /* timers. */
  if (peer->config & PEER_CONFIG_HOLDTIME)
    vty_out (vty, "%s neighbor %s timers holdtime %ld%s", v6str, addr, 
	     peer->holdtime, VTY_NEWLINE);
  if (peer->config & PEER_CONFIG_KEEPALIVE)
    vty_out (vty, "%s neighbor %s timers keepalive %ld%s", v6str, addr, 
	     peer->keepalive, VTY_NEWLINE);
  if (peer->config & PEER_CONFIG_CONNECT)
    vty_out (vty, "%s neighbor %s timers connect %ld%s", v6str, addr, 
	     peer->connect, VTY_NEWLINE);

  /* distribute-list. */
  if (filter->dlist[BGP_FILTER_IN].name)
    vty_out (vty, "%s neighbor %s distribute-list %s in%s", v6str, addr, 
	     filter->dlist[BGP_FILTER_IN].name, VTY_NEWLINE);
  if (filter->dlist[BGP_FILTER_OUT].name)
    vty_out (vty, "%s neighbor %s distribute-list %s out%s", v6str, addr, 
	     filter->dlist[BGP_FILTER_OUT].name, VTY_NEWLINE);

  /* prefix-list. */
  if (filter->plist[BGP_FILTER_IN].name)
    vty_out (vty, "%s neighbor %s prefix-list %s in%s", v6str, addr, 
	     filter->plist[BGP_FILTER_IN].name, VTY_NEWLINE);
  if (filter->plist[BGP_FILTER_OUT].name)
    vty_out (vty, "%s neighbor %s prefix-list %s out%s", v6str, addr, 
	     filter->plist[BGP_FILTER_OUT].name, VTY_NEWLINE);

  /* filter-list. */
  if (filter->aslist[BGP_FILTER_IN].name)
    vty_out (vty, "%s neighbor %s filter-list %s in%s", v6str, addr, 
	     filter->aslist[BGP_FILTER_IN].name, VTY_NEWLINE);
  if (filter->aslist[BGP_FILTER_OUT].name)
    vty_out (vty, "%s neighbor %s filter-list %s out%s", v6str, addr, 
	     filter->aslist[BGP_FILTER_OUT].name, VTY_NEWLINE);

  /* route-map. */
  if (filter->map[BGP_FILTER_IN].name)
    vty_out (vty, "%s neighbor %s route-map %s in%s", v6str, addr, 
	     filter->map[BGP_FILTER_IN].name, VTY_NEWLINE);
  if (filter->map[BGP_FILTER_OUT].name)
    vty_out (vty, "%s neighbor %s route-map %s out%s", v6str, addr, 
	     filter->map[BGP_FILTER_OUT].name, VTY_NEWLINE);

  /* maximum-prefix. */
  if (conf->pmax[afi][SAFI_UNICAST])
    vty_out (vty, "%s neighbor %s maximum-prefix %d%s", v6str, addr,
	     conf->pmax[afi][SAFI_UNICAST], VTY_NEWLINE);

  /* transparent-as. */
  if (CHECK_FLAG (peer->flags, PEER_FLAG_TRANSPARENT_AS))
    vty_out (vty, "%s neighbor %s transparent-as%s", v6str, addr,
	     VTY_NEWLINE);

  /* transparent-nexthop. */
  if (CHECK_FLAG (peer->flags, PEER_FLAG_TRANSPARENT_NEXTHOP))
    vty_out (vty, "%s neighbor %s transparent-nexthop%s", v6str, addr,
	     VTY_NEWLINE);
}

int
conf_active (struct peer_conf *conf)
{
  if (conf->afc[AFI_IP][SAFI_UNICAST]
      || conf->afc[AFI_IP][SAFI_MULTICAST]
      || conf->afc[AFI_IP][SAFI_MPLS_VPN]
      || conf->afc[AFI_IP6][SAFI_UNICAST]
      || conf->afc[AFI_IP6][SAFI_MULTICAST])
    return 1;
  return 0;
}

int
bgp_config_write (struct vty *vty)
{
  int write = 0;
  struct bgp *bgp;
  struct peer_group *group;
  struct peer_conf *conf;
  struct newnode *nn, *nm, *no;

  /* BGP Multiple instance. */
  if (bgp_multiple_instance)
    {    
      vty_out (vty, "bgp multiple-instance%s", VTY_NEWLINE);
      vty_out (vty, "!%s", VTY_NEWLINE);
    }

  /* BGP configuration. */
  NEWLIST_LOOP (bgp_list, bgp, nn)
    {
      if (write)
	vty_out (vty, "!%s", VTY_NEWLINE);

      /* Router bgp ASN */
      vty_out (vty, "router bgp %d", bgp->as);

      if (bgp_multiple_instance)
	{
#if 0
	  if (bgp->afi == AFI_IP && bgp->safi == SAFI_MULTICAST)
	    vty_out (vty, " multicast");
	  else if (bgp->afi == AFI_IP6 && bgp->safi == SAFI_UNICAST)
	    vty_out (vty, " ipv6");
	  else if (bgp->afi == AFI_IP6 && bgp->safi == SAFI_MULTICAST)
	    vty_out (vty, " ipv6 multicast");
	  if (bgp->id.s_addr != 0)
	    vty_out (vty, " router-id %s", inet_ntoa (bgp->id));
#endif /* 0 */
	  if (bgp->name)
	    vty_out (vty, " view %s", bgp->name);
	}
      vty_out (vty, "%s", VTY_NEWLINE);

      /* BGP configuration. */
      if (CHECK_FLAG (bgp->config, BGP_CONFIG_ALWAYS_COMPARE_MED))
	vty_out (vty, " bgp always-compare-med%s", VTY_NEWLINE);

      /* BGP bestpath method. */
      if (CHECK_FLAG (bgp->config, BGP_CONFIG_MISSING_AS_WORST))
	vty_out (vty, " bgp bestpath missing-as-worst%s", VTY_NEWLINE);

      /* BGP default ipv4-unicast. */
      if (CHECK_FLAG (bgp->config, BGP_CONFIG_NO_DEFAULT_IPV4))
	vty_out (vty, " no bgp default ipv4-unicast%s", VTY_NEWLINE);

      /* BGP router ID and cluster ID. */
      if (CHECK_FLAG (bgp->config, BGP_CONFIG_ROUTER_ID))
	vty_out (vty, " bgp router-id %s%s", inet_ntoa (bgp->id), 
		 VTY_NEWLINE);
      if (CHECK_FLAG (bgp->config, BGP_CONFIG_CLUSTER_ID))
	vty_out (vty, " bgp cluster-id %s%s", inet_ntoa (bgp->cluster), 
		 VTY_NEWLINE);

      /* Confederation Information */
      if(CHECK_FLAG(bgp->config, BGP_CONFIG_CONFEDERATION))
	{
	  vty_out(vty, " bgp confederation identifier %i%s", 
		  bgp->confederation_id,
		  VTY_NEWLINE);
	  if(bgp->confederation_peers_cnt > 0)
	    {
	      vty_out(vty, " bgp confederation peers");
	      bgp_confederation_peers_print(vty, bgp);
	      vty_out(vty, "%s", VTY_NEWLINE);
	    }
	}

      /* BGP redistribute configuration. */
      bgp_config_write_redistribute (vty, bgp, AFI_IP);

      /* BGP static route configuration. */
      bgp_config_write_network (vty, bgp, AFI_IP);

      /* peer-group */
      NEWLIST_LOOP (bgp->peer_group, group, nm)
	{
	  vty_out (vty, " neighbor %s peer-group", group->name);
	  if (group->safi == SAFI_MULTICAST)
	    vty_out (vty, " nlri multicast");
	  else if (group->safi == SAFI_UNICAST_MULTICAST)
	    vty_out (vty, " nlri unicast multicast");
	  vty_out (vty, "%s", VTY_NEWLINE);

	  if (group->as)
	    vty_out (vty, " neighbor %s remote-as %d%s", group->as,
		     VTY_NEWLINE);
	}

      /* Normal neighbor configuration. */
      NEWLIST_LOOP (bgp->peer_conf, conf, no)
	{
	  if (conf->afc[AFI_IP][SAFI_UNICAST] 
	      || conf->afc[AFI_IP][SAFI_MULTICAST]
	      || conf->afc[AFI_IP][SAFI_MPLS_VPN]
	      || ! conf_active (conf))
	    bgp_config_write_peer (vty, bgp, conf, AFI_IP, 0);
	}

      /* IPv6 neighbor configuration. */
      /* vty_out (vty, "!%s", VTY_NEWLINE); */

      /* IPv6 BGP redistribute configuration. */
      bgp_config_write_redistribute (vty, bgp, AFI_IP6);

      /* IPv6 BGP static route configuration. */
      bgp_config_write_network (vty, bgp, AFI_IP6);

      NEWLIST_LOOP (bgp->peer_conf, conf, no)
	{
	  if (conf->afc[AFI_IP6][SAFI_UNICAST]
	      || conf->afc[AFI_IP6][SAFI_MULTICAST])
	    bgp_config_write_peer (vty, bgp, conf, AFI_IP6, 0);
	}

      {
	int first = 1;

	NEWLIST_LOOP (bgp->peer_conf, conf, no)
	  {
	    if (conf->afc[AFI_IP][SAFI_MPLS_VPN])
	      {
		if (first)
		  {
		    vty_out (vty, "!%s", VTY_NEWLINE);
		    vty_out (vty, " address-family vpnv4 unicast%s",
			     VTY_NEWLINE);
		    first = 0;
		  }

		bgp_config_write_peer (vty, bgp, conf, AFI_IP, SAFI_MPLS_VPN);
	      }
	  }
	if (! first)
	  vty_out (vty, " exit-address-family%s", VTY_NEWLINE);
      }

      write++;
    }
  return write;
}

/* BGP node structure. */
struct cmd_node bgp_node =
{
  BGP_NODE,
  "%s(config-router)# ",
};

/* Install bgp related commands. */
void
bgp_init ()
{
  /* Install bgp top node. */
  install_node (&bgp_node, bgp_config_write);
  install_default (BGP_NODE);

  /* "bgp multiple-instance" commands. */
  install_element (CONFIG_NODE, &bgp_multiple_instance_cmd);
  install_element (CONFIG_NODE, &no_bgp_multiple_instance_cmd);

  /* "bgp router-id" commands. */
  install_element (BGP_NODE, &bgp_router_id_cmd);
  install_element (BGP_NODE, &no_bgp_router_id_cmd);

  /* "bgp cluster-id" commands. */
  install_element (BGP_NODE, &bgp_cluster_id_cmd);
  install_element (BGP_NODE, &no_bgp_cluster_id_cmd);

  /* "bgp always-compare-med" commands */
  install_element (BGP_NODE, &bgp_always_compare_med_cmd);
  install_element (BGP_NODE, &no_bgp_always_compare_med_cmd);

  /* "bgp bestpath missing-as-worst" commands. */
  install_element (BGP_NODE, &bgp_bestpath_missing_as_worst_cmd);
  install_element (BGP_NODE, &no_bgp_bestpath_missing_as_worst_cmd);

  /* "no bgp default ipv4-unicast" commands. */
  install_element (BGP_NODE, &no_bgp_default_ipv4_unicast_cmd);
  install_element (BGP_NODE, &bgp_default_ipv4_unicast_cmd);

  /* "router bgp" commands. */
  install_element (CONFIG_NODE, &router_bgp_cmd);
  install_element (CONFIG_NODE, &router_bgp_view_cmd);

  /* "no router bgp" commands. */
  install_element (CONFIG_NODE, &no_router_bgp_cmd);
  install_element (CONFIG_NODE, &no_router_bgp_view_cmd);

  /* "neighbor remote-as" commands. */
  install_element (BGP_NODE, &neighbor_remote_as_cmd);
  install_element (BGP_NODE, &neighbor_remote_as_passive_cmd);
  install_element (BGP_NODE, &neighbor_remote_as_unicast_cmd);
  install_element (BGP_NODE, &neighbor_remote_as_multicast_cmd);
  install_element (BGP_NODE, &neighbor_remote_as_unicast_multicast_cmd);

  install_element (BGP_NODE, &neighbor_activate_cmd);
  install_element (BGP_NODE, &no_neighbor_activate_cmd);

  /* "no neighbor remote-as" commands. */
  install_element (BGP_NODE, &no_neighbor_cmd);
  install_element (BGP_NODE, &no_neighbor_remote_as_cmd);

  /* "neighbor shutdown" commands. */
  install_element (BGP_NODE, &neighbor_shutdown_cmd);
  install_element (BGP_NODE, &no_neighbor_shutdown_cmd);

  /* "neighbor ebgp-multihop" commands. */
  install_element (BGP_NODE, &neighbor_ebgp_multihop_cmd);
  install_element (BGP_NODE, &neighbor_ebgp_multihop_ttl_cmd);
  install_element (BGP_NODE, &no_neighbor_ebgp_multihop_cmd);
  install_element (BGP_NODE, &no_neighbor_ebgp_multihop_ttl_cmd);

  /* "neighbor description" commands. */
  install_element (BGP_NODE, &neighbor_description_cmd);
  install_element (BGP_NODE, &no_neighbor_description_cmd);

  /* "neighbor version" commands. */
  install_element (BGP_NODE, &neighbor_version_cmd);
  install_element (BGP_NODE, &no_neighbor_version_cmd);

  /* "neighbor interface" commands. */
  install_element (BGP_NODE, &neighbor_interface_cmd);
  install_element (BGP_NODE, &no_neighbor_interface_cmd);

  /* "neighbor next-hop-self" commands. */
  install_element (BGP_NODE, &neighbor_nexthop_self_cmd);
  install_element (BGP_NODE, &no_neighbor_nexthop_self_cmd);

  /* "neighbor update-source" commands. "*/
  install_element (BGP_NODE, &neighbor_update_source_cmd);
  install_element (BGP_NODE, &no_neighbor_update_source_cmd);

  /* "neighbor default-originate" commands. */
  install_element (BGP_NODE, &neighbor_default_originate_cmd);
  install_element (BGP_NODE, &no_neighbor_default_originate_cmd);

  /* "neighbor port" commands. */
  install_element (BGP_NODE, &neighbor_port_cmd);
  install_element (BGP_NODE, &no_neighbor_port_cmd);

  /* "neighbor send-community" commands.*/
  install_element (BGP_NODE, &neighbor_send_community_cmd);
  install_element (BGP_NODE, &no_neighbor_send_community_cmd);

  /* "neighbor send-community extended" commands.*/
  install_element (BGP_NODE, &neighbor_send_community_extended_cmd);
  install_element (BGP_NODE, &no_neighbor_send_community_extended_cmd);

  /* "neighbor weight" commands. */
  install_element (BGP_NODE, &neighbor_weight_cmd);
  install_element (BGP_NODE, &no_neighbor_weight_cmd);

  /* "neighbor softreconfiguration inbound" commands.*/
  install_element (BGP_NODE, &neighbor_soft_reconfiguration_cmd);
  install_element (BGP_NODE, &no_neighbor_soft_reconfiguration_cmd);

  /* "neighbor route-reflector" commands.*/
  install_element (BGP_NODE, &neighbor_route_reflector_client_cmd);
  install_element (BGP_NODE, &no_neighbor_route_reflector_client_cmd);

  /* "neighbor route-server" commands.*/
  install_element (BGP_NODE, &neighbor_route_server_client_cmd);
  install_element (BGP_NODE, &no_neighbor_route_server_client_cmd);

  /* "neighbor route-refresh" commands.*/
  install_element (BGP_NODE, &neighbor_route_refresh_cmd);
  install_element (BGP_NODE, &no_neighbor_route_refresh_cmd);

  /* "neighbor translate-update" commands. */
  install_element (BGP_NODE, &neighbor_translate_update_multicast_cmd);
  install_element (BGP_NODE, &neighbor_translate_update_unimulti_cmd);
  install_element (BGP_NODE, &no_neighbor_translate_update_cmd);
  install_element (BGP_NODE, &no_neighbor_translate_update_multicast_cmd);
  install_element (BGP_NODE, &no_neighbor_translate_update_unimulti_cmd);

  /* "neighbor dont-capability-negotiate" commands. */
  install_element (BGP_NODE, &neighbor_dont_capability_negotiate_cmd);
  install_element (BGP_NODE, &no_neighbor_dont_capability_negotiate_cmd);

  /* "neighbor override-capability" commands. */
  install_element (BGP_NODE, &neighbor_override_capability_cmd);
  install_element (BGP_NODE, &no_neighbor_override_capability_cmd);

  /* "neighbor strict-capability-match" commands. */
  install_element (BGP_NODE, &neighbor_strict_capability_cmd);
  install_element (BGP_NODE, &no_neighbor_strict_capability_cmd);

  /* "neighbor timers holdtime" commands. */
  install_element (BGP_NODE, &neighbor_timers_holdtime_cmd);
  install_element (BGP_NODE, &no_neighbor_timers_holdtime_cmd);

  /* "neighbor timers keepalive" commands. */
  install_element (BGP_NODE, &neighbor_timers_keepalive_cmd);
  install_element (BGP_NODE, &no_neighbor_timers_keepalive_cmd);

  /* "neighbor timers connect" commands. */
  install_element (BGP_NODE, &neighbor_timers_connect_cmd);
  install_element (BGP_NODE, &no_neighbor_timers_connect_cmd);

  /* Filters */
  install_element (BGP_NODE, &neighbor_distribute_list_cmd);
  install_element (BGP_NODE, &no_neighbor_distribute_list_cmd);
  install_element (BGP_NODE, &neighbor_prefix_list_cmd);
  install_element (BGP_NODE, &no_neighbor_prefix_list_cmd);
  install_element (BGP_NODE, &neighbor_filter_list_cmd);
  install_element (BGP_NODE, &no_neighbor_filter_list_cmd);
  install_element (BGP_NODE, &neighbor_route_map_cmd);
  install_element (BGP_NODE, &no_neighbor_route_map_cmd);
#if 0
  install_element (BGP_NODE, &neighbor_peer_group_cmd);
  install_element (BGP_NODE, &neighbor_peer_group_remote_as_cmd);
#endif /* 0 */

  /* "neighbor maximum-prefix" commands. */
  install_element (BGP_NODE, &neighbor_maximum_prefix_cmd);
  install_element (BGP_NODE, &no_neighbor_maximum_prefix_cmd);

  /* "bgp confederation" commands. */
  install_element (BGP_NODE, &bgp_confederation_identifier_cmd);
  install_element (BGP_NODE, &bgp_confederation_peers_cmd);
  install_element (BGP_NODE, &no_bgp_confederation_identifier_cmd);
  install_element (BGP_NODE, &no_bgp_confederation_peers_cmd);

  /* "transparent-as" commands. */
  install_element (BGP_NODE, &neighbor_transparent_as_cmd);
  install_element (BGP_NODE, &no_neighbor_transparent_as_cmd);

  /* "transparent-nexthop" commands. */
  install_element (BGP_NODE, &neighbor_transparent_nexthop_cmd);
  install_element (BGP_NODE, &no_neighbor_transparent_nexthop_cmd);

  /* "show ip bgp summary" commands. */
  install_element (VIEW_NODE, &show_ip_bgp_summary_cmd);
  install_element (VIEW_NODE, &show_ip_mbgp_summary_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_summary_all_cmd);

  install_element (ENABLE_NODE, &show_ip_bgp_summary_cmd);
  install_element (ENABLE_NODE, &show_ip_mbgp_summary_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_summary_all_cmd);

  /* "show ip bgp neighbors" commands. */
  install_element (VIEW_NODE, &show_ip_bgp_neighbors_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_neighbors_peer_cmd);
  install_element (VIEW_NODE, &show_ip_mbgp_neighbors_cmd);
  install_element (VIEW_NODE, &show_ip_mbgp_neighbors_peer_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_vpnv4_all_neighbors_cmd);

  install_element (ENABLE_NODE, &show_ip_bgp_neighbors_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_neighbors_peer_cmd);
  install_element (ENABLE_NODE, &show_ip_mbgp_neighbors_cmd);
  install_element (ENABLE_NODE, &show_ip_mbgp_neighbors_peer_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_vpnv4_all_neighbors_cmd);

  /* "show ip bgp paths" commands. */
  install_element (VIEW_NODE, &show_ip_bgp_paths_cmd);
  install_element (VIEW_NODE, &show_ip_mbgp_paths_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_paths_cmd);
  install_element (ENABLE_NODE, &show_ip_mbgp_paths_cmd);

  /* "show ip bgp community" commands. */
  install_element (VIEW_NODE, &show_ip_bgp_community_cmd);
  install_element (VIEW_NODE, &show_ip_mbgp_community_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_community_cmd);
  install_element (ENABLE_NODE, &show_ip_mbgp_community_cmd);

  /* "clear ip bgp commands" */
  install_element (ENABLE_NODE, &clear_ip_bgp_all_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_peer_cmd);
#if 0 
  install_element (ENABLE_NODE, &clear_ip_bgp_peer_group_cmd);
#endif /* 0 */
  install_element (ENABLE_NODE, &clear_ip_bgp_as_cmd);

  /* "clear ip bgp neighbor soft in "*/
  install_element (ENABLE_NODE, &clear_ip_bgp_peer_soft_in_cmd);

  install_element (VIEW_NODE, &show_ip_bgp_vpnv4_all_summary_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_vpnv4_all_summary_cmd);

#ifdef HAVE_IPV6
  install_element (BGP_NODE, &ipv6_bgp_neighbor_cmd);
  install_element (BGP_NODE, &ipv6_bgp_neighbor_passive_cmd);
  install_element (BGP_NODE, &ipv6_bgp_neighbor_unicast_cmd);
  install_element (BGP_NODE, &ipv6_bgp_neighbor_multicast_cmd);
  install_element (BGP_NODE, &ipv6_bgp_neighbor_unicast_multicast_cmd);

  install_element (BGP_NODE, &no_ipv6_bgp_neighbor_cmd);
  install_element (BGP_NODE, &no_ipv6_bgp_neighbor_remote_as_cmd);

  install_element (BGP_NODE, &ipv6_bgp_neighbor_shutdown_cmd);
  install_element (BGP_NODE, &no_ipv6_bgp_neighbor_shutdown_cmd);

  install_element (BGP_NODE, &ipv6_bgp_neighbor_ebgp_multihop_cmd);
  install_element (BGP_NODE, &ipv6_bgp_neighbor_ebgp_multihop_ttl_cmd);
  install_element (BGP_NODE, &no_ipv6_bgp_neighbor_ebgp_multihop_cmd);
  install_element (BGP_NODE, &no_ipv6_bgp_neighbor_ebgp_multihop_ttl_cmd);

  install_element (BGP_NODE, &ipv6_bgp_neighbor_description_cmd);
  install_element (BGP_NODE, &no_ipv6_bgp_neighbor_description_cmd);

  install_element (BGP_NODE, &ipv6_bgp_neighbor_version_cmd);
  install_element (BGP_NODE, &no_ipv6_bgp_neighbor_version_cmd);

  install_element (BGP_NODE, &ipv6_bgp_neighbor_interface_cmd);
  install_element (BGP_NODE, &no_ipv6_bgp_neighbor_interface_cmd);

  install_element (BGP_NODE, &ipv6_bgp_neighbor_nexthop_self_cmd);
  install_element (BGP_NODE, &no_ipv6_bgp_neighbor_nexthop_self_cmd);

  install_element (BGP_NODE, &ipv6_bgp_neighbor_update_source_cmd);
  install_element (BGP_NODE, &no_ipv6_bgp_neighbor_update_source_cmd);

  install_element (BGP_NODE, &ipv6_bgp_neighbor_default_originate_cmd);
  install_element (BGP_NODE, &no_ipv6_bgp_neighbor_default_originate_cmd);

  install_element (BGP_NODE, &ipv6_bgp_neighbor_port_cmd);
  install_element (BGP_NODE, &no_ipv6_bgp_neighbor_port_cmd);

  install_element (BGP_NODE, &ipv6_bgp_neighbor_send_community_cmd);
  install_element (BGP_NODE, &no_ipv6_bgp_neighbor_send_community_cmd);

  install_element (BGP_NODE, &ipv6_bgp_neighbor_send_community_extended_cmd);
  install_element (BGP_NODE, &no_ipv6_bgp_neighbor_send_community_extended_cmd);

  install_element (BGP_NODE, &ipv6_bgp_neighbor_weight_cmd);
  install_element (BGP_NODE, &no_ipv6_bgp_neighbor_weight_cmd);

  install_element (BGP_NODE, &ipv6_bgp_neighbor_soft_reconfiguration_cmd);
  install_element (BGP_NODE, &no_ipv6_bgp_neighbor_soft_reconfiguration_cmd);

  install_element (BGP_NODE, &ipv6_bgp_neighbor_route_reflector_client_cmd);
  install_element (BGP_NODE, &no_ipv6_bgp_neighbor_route_reflector_client_cmd);

  install_element (BGP_NODE, &ipv6_bgp_neighbor_route_server_client_cmd);
  install_element (BGP_NODE, &no_ipv6_bgp_neighbor_route_server_client_cmd);

  install_element (BGP_NODE, &ipv6_bgp_neighbor_route_refresh_cmd);
  install_element (BGP_NODE, &no_ipv6_bgp_neighbor_route_refresh_cmd);

  install_element (BGP_NODE, &ipv6_neighbor_dont_capability_negotiate_cmd);
  install_element (BGP_NODE, &no_ipv6_neighbor_dont_capability_negotiate_cmd);

  install_element (BGP_NODE, &ipv6_neighbor_override_capability_cmd);
  install_element (BGP_NODE, &no_ipv6_neighbor_override_capability_cmd);

  install_element (BGP_NODE, &ipv6_neighbor_strict_capability_cmd);
  install_element (BGP_NODE, &no_ipv6_neighbor_strict_capability_cmd);

  install_element (BGP_NODE, &ipv6_bgp_neighbor_timers_holdtime_cmd);
  install_element (BGP_NODE, &no_ipv6_bgp_neighbor_timers_holdtime_cmd);

  install_element (BGP_NODE, &ipv6_bgp_neighbor_timers_keepalive_cmd);
  install_element (BGP_NODE, &no_ipv6_bgp_neighbor_timers_keepalive_cmd);

  install_element (BGP_NODE, &ipv6_bgp_neighbor_timers_connect_cmd);
  install_element (BGP_NODE, &no_ipv6_bgp_neighbor_timers_connect_cmd);

  install_element (BGP_NODE, &ipv6_bgp_neighbor_distribute_list_cmd);
  install_element (BGP_NODE, &no_ipv6_bgp_neighbor_distribute_list_cmd);
  install_element (BGP_NODE, &ipv6_bgp_neighbor_prefix_list_cmd);
  install_element (BGP_NODE, &no_ipv6_bgp_neighbor_prefix_list_cmd);
  install_element (BGP_NODE, &ipv6_bgp_neighbor_filter_list_cmd);
  install_element (BGP_NODE, &no_ipv6_bgp_neighbor_filter_list_cmd);
  install_element (BGP_NODE, &ipv6_bgp_neighbor_route_map_cmd);
  install_element (BGP_NODE, &no_ipv6_bgp_neighbor_route_map_cmd);

  install_element (BGP_NODE, &ipv6_bgp_neighbor_transparent_as_cmd);
  install_element (BGP_NODE, &no_ipv6_bgp_neighbor_transparent_as_cmd);

  install_element (BGP_NODE, &ipv6_bgp_neighbor_transparent_nexthop_cmd);
  install_element (BGP_NODE, &no_ipv6_bgp_neighbor_transparent_nexthop_cmd);

  install_element (VIEW_NODE, &show_ipv6_bgp_summary_cmd);
  install_element (VIEW_NODE, &show_ipv6_mbgp_summary_cmd);

  install_element (ENABLE_NODE, &show_ipv6_bgp_summary_cmd);
  install_element (ENABLE_NODE, &show_ipv6_mbgp_summary_cmd);

  install_element (VIEW_NODE, &show_ipv6_bgp_neighbors_cmd);
  install_element (VIEW_NODE, &show_ipv6_bgp_neighbors_peer_cmd);
  install_element (VIEW_NODE, &show_ipv6_mbgp_neighbors_cmd);
  install_element (VIEW_NODE, &show_ipv6_mbgp_neighbors_peer_cmd);

  install_element (ENABLE_NODE, &show_ipv6_bgp_neighbors_cmd);
  install_element (ENABLE_NODE, &show_ipv6_bgp_neighbors_peer_cmd);
  install_element (ENABLE_NODE, &show_ipv6_mbgp_neighbors_cmd);
  install_element (ENABLE_NODE, &show_ipv6_mbgp_neighbors_peer_cmd);

  install_element (ENABLE_NODE, &clear_ipv6_bgp_all_cmd);
  install_element (ENABLE_NODE, &clear_ipv6_bgp_peer_cmd);
#if 0
  install_element (ENABLE_NODE, &clear_ipv6_bgp_peer_group_cmd);
#endif /* 0 */
  install_element (ENABLE_NODE, &clear_ipv6_bgp_as_cmd);

  install_element (ENABLE_NODE, &clear_ipv6_bgp_peer_soft_in_cmd);
#endif /* HAVE_IPV6 */

  /* Make global lists. */
  bgp_list = newlist_new ();
  peer_list = newlist_new ();
  peer_list->cmp = (int (*)(void *, void *)) peer_list_cmp;

  /* BGP multiple instance. */
  bgp_multiple_instance = 0;

  /* Init zebra. */
  zebra_init ();

  /* BGP inits. */
  bgp_attr_init ();
  bgp_debug_init ();
  bgp_dump_init ();
  bgp_route_init ();
  bgp_route_map_init ();

  /* Access list initialize. */
  access_list_init ();
  access_list_add_hook (bgp_distribute_update);
  access_list_delete_hook (bgp_distribute_update);

  /* Filter list initialize. */
  bgp_filter_init ();
  as_list_add_hook (bgp_aslist_update);
  as_list_delete_hook (bgp_aslist_update);

  /* Prefix list initialize.*/
  prefix_list_init ();
  prefix_list_add_hook (bgp_prefix_list_update);
  prefix_list_delete_hook (bgp_prefix_list_update);

  /* Community list initialize. */
  community_list_init ();

#ifdef HAVE_SNMP
  bgp_snmp_init ();
#endif /* HAVE_SNMP */
}
