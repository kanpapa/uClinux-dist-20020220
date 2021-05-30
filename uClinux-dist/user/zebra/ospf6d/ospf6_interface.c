/*
 * Copyright (C) 1999 Yasuhiro Ohara
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
 * along with GNU Zebra; see the file COPYING.  If not, write to the 
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330, 
 * Boston, MA 02111-1307, USA.  
 */

#include "ospf6d.h"

#include "if.h"
#include "log.h"
#include "command.h"

#include "ospf6_interface.h"
#include "ospf6_top.h"
#include "ospf6_lsdb.h"

/* Allocate new interface structure */
static struct ospf6_interface *
ospf6_interface_new ()
{
  struct ospf6_interface *new = (struct ospf6_interface *)
    XMALLOC (MTYPE_OSPF6_IF, sizeof (struct ospf6_interface));

  if (new)
    memset (new, 0, sizeof (struct ospf6_interface));
  else
    zlog_warn ("Can't malloc ospf6_interface");

  return new;
}

static void
ospf6_interface_free (struct ospf6_interface *o6i)
{
  XFREE (MTYPE_OSPF6_IF, o6i);
  return;
}

struct in6_addr *
ospf6_interface_linklocal_addr (struct interface *ifp)
{
  listnode n;
  struct connected *c;
  struct in6_addr *l = (struct in6_addr *) NULL;

  /* for each connected address */
  for (n = listhead (ifp->connected); n; nextnode (n))
    {
      c = (struct connected *) getdata (n);

      /* if family not AF_INET6, ignore */
      if (c->address->family != AF_INET6)
        continue;

      /* linklocal scope check */
      if (IN6_IS_ADDR_LINKLOCAL (&c->address->u.prefix6))
        l = &c->address->u.prefix6;
    }
  return l;
}

/* Create new ospf6 interface structure */
struct ospf6_interface *
ospf6_interface_create (struct interface *ifp, struct ospf6 *o6)
{
  struct ospf6_interface *o6i;

  o6i = ospf6_interface_new ();
  if (!o6i)
    {
      zlog_err ("Can't allocate ospf6_interface for ifindex %d", ifp->ifindex);
      return (struct ospf6_interface *) NULL;
    }

  o6i->instance_id = 0;
  o6i->if_id = ifp->ifindex;
  o6i->lladdr = (struct in6_addr *) NULL;
  o6i->area = (struct area *) NULL;
  o6i->state = IFS_DOWN;
  o6i->is_passive = 0;
  o6i->neighbor_list = list_init ();
  ospf6_lsdb_init_interface (o6i);
  o6i->transdelay = 1;
  o6i->priority = 1;
  o6i->hello_interval = 10;
  o6i->dead_interval = 40;
  o6i->rxmt_interval = 5;
  o6i->cost = 1;
  o6i->ifmtu = 1500;

  o6i->network_prefixes = list_init ();
  /*o6i->connected_prefixes = list_init ();*/

  o6i->lsa_seqnum_link = o6i->lsa_seqnum_network
                       = o6i->lsa_seqnum_intra_prefix
                       = INITIAL_SEQUENCE_NUMBER;

  /* register interface list */
  if (!o6)
    o6 = ospf6_start ();
  list_add_node (ospf6->ospf6_interface_list, o6i);

  /* link both */
  o6i->interface = ifp;
  ifp->info = o6i;

  return o6i;
}

void
ospf6_interface_if_add (struct interface *ifp, struct ospf6 *o6)
{
  struct ospf6_interface *o6i;

  o6i = (struct ospf6_interface *) ifp->info;
  if (!o6i)
    o6i = ospf6_interface_create (ifp, o6);
  if (!o6i)
    return;

  o6i->if_id = ifp->ifindex;

  ospf6_interface_address_update (ifp);

  /* interface start */
  if (o6i->area)
    thread_add_event (master, interface_up, o6i, 0);
}

void
ospf6_interface_if_del (struct interface *ifp, struct ospf6 *o6)
{
  struct ospf6_interface *o6i;

  o6i = ospf6_interface_lookup_by_index (ifp->ifindex, o6);
  if (!o6i)
    return;

  /* cut link */
  o6i->interface = NULL;
  ifp->info = NULL;

  /* interface stop */
  if (o6i->area)
    thread_add_event (master, interface_down, o6i, 0);
}

void
ospf6_interface_address_update (struct interface *ifp)
{
  struct ospf6_interface *o6i;

  if (!ifp->info)
    ospf6_interface_if_add (ifp, ospf6);

  o6i = (struct ospf6_interface *) ifp->info;

  /* reset linklocal pointer */
  o6i->lladdr = ospf6_interface_linklocal_addr (ifp);

  /* if area is null, can't make link-lsa */
  if (!o6i->area)
    return;

  /* create new Link-LSA */
#if 1
  ospf6_lsa_update_link (o6i);
#else
  {
    struct ospf6_lsa *lsa = NULL;
    lsa = ospf6_make_link_lsax (o6i);
    if (!lsa)
      return;

    ospf6_lsa_flood (lsa);
    ospf6_lsdb_install (lsa);
    ospf6_lsa_unlock (lsa);
  }
#endif
}

void
delete_ospf6_interface (struct ospf6_interface *o6if)
{
  listnode n;

  for (n = listhead (o6if->neighbor_list); n; nextnode (n))
    delete_ospf6_nbr (getdata (n));
  list_delete_all (o6if->neighbor_list);

  thread_cancel (o6if->thread_send_hello);
  thread_cancel (o6if->thread_send_lsack_delayed);

  ospf6_lsdb_finish_interface (o6if);

  list_delete_by_val (o6if->area->if_list, o6if);
  ospf6_interface_free (o6if);

  return;
}

struct ospf6_interface *
ospf6_interface_lookup_by_index (int ifindex, struct ospf6 *o6)
{
  listnode node;
  struct ospf6_interface *o6i;
  struct ospf6_interface *found = NULL;

  for (node = listhead (o6->ospf6_interface_list); node; nextnode (node))
    {
      o6i = (struct ospf6_interface *) getdata (node);
      if (o6i->if_id == ifindex)
        {
          found = o6i;
          break;
        }
    }

  if (!found)
    {
      if (IS_OSPF6_DUMP_INTERFACE)
        zlog_info ("interface lookup: cannot find ifindex %d", ifindex);
      return (struct ospf6_interface *) NULL;
    }

  /* check validity */
  if (found->interface && found->interface != if_lookup_by_index (ifindex))
    {
      zlog_warn ("interface lookup: attached interface seems invalid: %s",
                 found->interface->name);
    }

  if (found->interface && found != found->interface->info)
    {
      zlog_warn ("interface lookup: back pointer wrong: %s",
                 found->interface->name);
    }

  return found;
}

/* count number of full neighbor */
int
ospf6_interface_count_full_nbr (struct ospf6_interface *o6if)
{
  listnode n;
  struct neighbor *nbr;
  int count = 0;

  for (n = listhead (o6if->neighbor_list); n; nextnode (n))
    {
      nbr = (struct neighbor *) getdata (n);
      if (nbr->state == NBS_FULL)
        count++;
    }

  return count;
}

int
ospf6_interface_is_enabled (struct ospf6_interface *o6i)
{
  assert (o6i);
  if (o6i->state > IFS_DOWN)
    {
      assert (o6i->area);
      return 1;
    }

  return 0;
}

/* show specified interface structure */
int
show_if (struct vty *vty, struct interface *iface)
{
  struct ospf6_interface *ospf6_interface;
  struct connected *c;
  struct prefix *p;
  listnode i;
  char strbuf[64], dr[32], bdr[32];
  char *updown[3] = {"down", "up", NULL};
  char *type;

  /* check interface type */
  if (if_is_loopback (iface))
    type = "LOOPBACK";
  else if (if_is_broadcast (iface))
    type = "BROADCAST";
  else if (if_is_pointopoint (iface))
    type = "POINTOPOINT";
  else
    type = "UNKNOWN";

  vty_out (vty, "%s is %s, type %s%s",
           iface->name, updown[if_is_up (iface)], type,
	   VTY_NEWLINE);

  if (iface->info == NULL)
    {
      vty_out (vty, "   OSPF not enabled on this interface%s", VTY_NEWLINE);
      return 0;
    }
  else
    ospf6_interface = (struct ospf6_interface *)iface->info;

  vty_out (vty, "  Internet Address:%s", VTY_NEWLINE);
  for (i = listhead (iface->connected); i; nextnode (i))
    {
      c = (struct connected *)getdata (i);
      p = c->address;
      prefix2str (p, strbuf, sizeof (strbuf));
      switch (p->family)
        {
        case AF_INET:
          vty_out (vty, "   inet : %s%s", strbuf,
		   VTY_NEWLINE);
          break;
        case AF_INET6:
          vty_out (vty, "   inet6: %s%s", strbuf,
		   VTY_NEWLINE);
          break;
        default:
          vty_out (vty, "   ???  : %s%s", strbuf,
		   VTY_NEWLINE);
          break;
        }
    }

  if (ospf6_interface->area)
    {
      vty_out (vty, "  Instance ID %lu, Router ID %s%s",
	       ospf6_interface->instance_id,
	       inet4str (ospf6_interface->area->ospf6->router_id),
	       VTY_NEWLINE);
      vty_out (vty, "  Area ID %s, Cost %hu%s",
	       inet4str (ospf6_interface->area->area_id), 
	       ospf6_interface->cost, VTY_NEWLINE);
    }
  else
    vty_out (vty, "  Not Attached to Area%s", VTY_NEWLINE);

  vty_out (vty, "  State %s, Transmit Delay %lu sec, Priority %d%s",
           ifs_name[ospf6_interface->state],
           ospf6_interface->transdelay,
           ospf6_interface->priority,
	   VTY_NEWLINE);
  vty_out (vty, "  Timer intervals configured:%s", VTY_NEWLINE);
  vty_out (vty, "   Hello %lu, Dead %lu, Retransmit %lu%s",
           ospf6_interface->hello_interval,
           ospf6_interface->dead_interval,
           ospf6_interface->rxmt_interval,
	   VTY_NEWLINE);

  inet_ntop (AF_INET, &ospf6_interface->dr, dr, sizeof (dr));
  inet_ntop (AF_INET, &ospf6_interface->bdr, bdr, sizeof (bdr));
  vty_out (vty, "  DR:%s BDR:%s%s", dr, bdr, VTY_NEWLINE);

  vty_out (vty, "  Number of I/F scoped LSAs is %u%s",
           listcount (ospf6_interface->lsdb), VTY_NEWLINE);
  vty_out (vty, "  %-16s %5d times, %-16s %5d times%s",
                "DRElection", ospf6_interface->ospf6_stat_dr_election,
                "DelayedLSAck", ospf6_interface->ospf6_stat_delayed_lsack,
                VTY_NEWLINE);

  return 0;
}

DEFUN (no_interface,
       no_interface_cmd,
       "no interface IFNAME [area AREA_ID]",
       INTERFACE_STR
       "Delete Interface.")
{
  char *ifname;
  area_id_t area_id;
  struct area *area;
  struct ospf6_interface *o6i;
  struct interface *ifp;

  ifname = argv[0];
  inet_pton (AF_INET, argv[1], &area_id);

  if (area_id != 0)
    {
      vty_out (vty, "Area ID other than Backbone(0.0.0.0), "
               "not yet implimented%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  ifp = if_lookup_by_name (ifname);
  if (!ifp)
    {
      vty_out (vty, "No such interface: %s%s", ifname,
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  area = ospf6_area_lookup (area_id);
  if (!area)
    {
      vty_out (vty, "No such area: %s%s",
               inet4str (area_id),
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  o6i = ospf6_interface_lookup_by_index (ifp->ifindex, ospf6);
  if (!o6i)
    {
      vty_out (vty, "No such ospf6 interface: %s%s", ifname,
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* xxx ospf6_interface_delete (o6i, area); */
  return CMD_SUCCESS;
}

/* interface variable set command */
DEFUN (ipv6_ospf6_cost,
       ipv6_ospf6_cost_cmd,
       "ipv6 ospf6 cost COST",
       IP6_STR
       OSPF6_STR
       "Interface cost\n"
       "<1-65535> Cost\n"
       )
{
  struct ospf6_interface *o6i;
  struct interface *ifp;

  ifp = (struct interface *)vty->index;
  assert (ifp);

  o6i = (struct ospf6_interface *)ifp->info;
  if (!o6i)
    o6i = ospf6_interface_create (ifp, ospf6);
  assert (o6i);

  o6i->cost = strtol (argv[0], NULL, 10);
  return CMD_SUCCESS;
}

/* interface variable set command */
DEFUN (ipv6_ospf6_hellointerval,
       ipv6_ospf6_hellointerval_cmd,
       "ipv6 ospf6 hello-interval HELLO_INTERVAL",
       IP6_STR
       OSPF6_STR
       "Time between HELLO packets\n"
       SECONDS_STR
       )
{
  struct ospf6_interface *ospf6_interface;
  struct interface *ifp;

  ifp = (struct interface *) vty->index;
  assert (ifp);
  ospf6_interface = (struct ospf6_interface *) ifp->info;
  if (!ospf6_interface)
    ospf6_interface = ospf6_interface_create (ifp, ospf6);
  assert (ospf6_interface);

  ospf6_interface->hello_interval = strtol (argv[0], NULL, 10);
  return CMD_SUCCESS;
}

/* interface variable set command */
DEFUN (ipv6_ospf6_deadinterval,
       ipv6_ospf6_deadinterval_cmd,
       "ipv6 ospf6 dead-interval ROUTER_DEAD_INTERVAL",
       IP6_STR
       OSPF6_STR
       "Interval after which a neighbor is declared dead\n"
       SECONDS_STR
       )
{
  struct ospf6_interface *ospf6_interface;
  struct interface *ifp;

  ifp = (struct interface *) vty->index;
  assert (ifp);
  ospf6_interface = (struct ospf6_interface *) ifp->info;
  if (!ospf6_interface)
    ospf6_interface = ospf6_interface_create (ifp, ospf6);
  assert (ospf6_interface);

  ospf6_interface->dead_interval = strtol (argv[0], NULL, 10);
  return CMD_SUCCESS;
}

/* interface variable set command */
DEFUN (ipv6_ospf6_transmitdelay,
       ipv6_ospf6_transmitdelay_cmd,
       "ipv6 ospf6 transmit-delay TRANSMITDELAY",
       IP6_STR
       OSPF6_STR
       "Link state transmit delay\n"
       SECONDS_STR
       )
{
  struct ospf6_interface *ospf6_interface;
  struct interface *ifp;

  ifp = (struct interface *) vty->index;
  assert (ifp);
  ospf6_interface = (struct ospf6_interface *) ifp->info;
  if (!ospf6_interface)
    ospf6_interface = ospf6_interface_create (ifp, ospf6);
  assert (ospf6_interface);

  ospf6_interface->transdelay = strtol (argv[0], NULL, 10);
  return CMD_SUCCESS;
}

/* interface variable set command */
DEFUN (ipv6_ospf6_retransmitinterval,
       ipv6_ospf6_retransmitinterval_cmd,
       "ipv6 ospf6 retransmit-interval RXMTINTERVAL",
       IP6_STR
       OSPF6_STR
       "Time between retransmitting lost link state advertisements\n"
       SECONDS_STR
       )
{
  struct ospf6_interface *ospf6_interface;
  struct interface *ifp;

  ifp = (struct interface *) vty->index;
  assert (ifp);
  ospf6_interface = (struct ospf6_interface *) ifp->info;
  if (!ospf6_interface)
    ospf6_interface = ospf6_interface_create (ifp, ospf6);
  assert (ospf6_interface);

  ospf6_interface->rxmt_interval = strtol (argv[0], NULL, 10);
  return CMD_SUCCESS;
}

/* interface variable set command */
DEFUN (ipv6_ospf6_priority,
       ipv6_ospf6_priority_cmd,
       "ipv6 ospf6 priority PRIORITY",
       IP6_STR
       OSPF6_STR
       "Router priority\n"
       "<0-255> Priority\n"
       )
{
  struct ospf6_interface *ospf6_interface;
  struct interface *ifp;

  ifp = (struct interface *) vty->index;
  assert (ifp);
  ospf6_interface = (struct ospf6_interface *)ifp->info;
  if (!ospf6_interface)
    ospf6_interface = ospf6_interface_create (ifp, ospf6);
  assert (ospf6_interface);

  ospf6_interface->priority = strtol (argv[0], NULL, 10);
  return CMD_SUCCESS;
}

DEFUN (ipv6_ospf6_instance,
       ipv6_ospf6_instance_cmd,
       "ipv6 ospf6 instance-id INSTANCE",
       IP6_STR
       OSPF6_STR
       "Instance ID\n"
       "<0-255> Instance ID\n"
       )
{
  struct ospf6_interface *ospf6_interface;
  struct interface *ifp;

  ifp = (struct interface *)vty->index;
  assert (ifp);

  ospf6_interface = (struct ospf6_interface *)ifp->info;
  if (!ospf6_interface)
    ospf6_interface = ospf6_interface_create (ifp, ospf6);
  assert (ospf6_interface);

  ospf6_interface->instance_id = strtol (argv[0], NULL, 10);
  return CMD_SUCCESS;
}

int
ospf6_interface_config_write (struct vty *vty)
{
  listnode j,k;
  struct ospf6_interface *ospf6_interface;
  struct area *area;

  for (j = listhead (ospf6->area_list); j; nextnode (j))
    {
      area = (struct area *) getdata (j);
      for (k = listhead (area->if_list); k; nextnode (k))
        {
          ospf6_interface = (struct ospf6_interface *) getdata (k);
          vty_out (vty, "interface %s%s",
		   ospf6_interface->interface->name,
		   VTY_NEWLINE);
          vty_out (vty, " ipv6 ospf6 cost %d%s",
		   ospf6_interface->cost,
		   VTY_NEWLINE);
          vty_out (vty, " ipv6 ospf6 hello-interval %d%s",
		   ospf6_interface->hello_interval,
		   VTY_NEWLINE);
          vty_out (vty, " ipv6 ospf6 dead-interval %d%s",
                   ospf6_interface->dead_interval,
		   VTY_NEWLINE);
          vty_out (vty, " ipv6 ospf6 retransmit-interval %d%s",
                   ospf6_interface->rxmt_interval,
		   VTY_NEWLINE);
          vty_out (vty, " ipv6 ospf6 priority %d%s",
                   ospf6_interface->priority,
		   VTY_NEWLINE);
          vty_out (vty, " ipv6 ospf6 transmit-delay %d%s",
                   ospf6_interface->transdelay,
		   VTY_NEWLINE);
          vty_out (vty, " ipv6 ospf6 instance-id %d%s",
                   ospf6_interface->instance_id,
		   VTY_NEWLINE);
          vty_out (vty, "!%s", VTY_NEWLINE);
        }
    }

  return 0;
}

struct cmd_node interface_node =
{
  INTERFACE_NODE,
  "%s(config-if)# ",
};

void
ospf6_interface_init ()
{
  /* Install interface node. */
  install_node (&interface_node, ospf6_interface_config_write);

  install_default (INTERFACE_NODE);
  install_element (INTERFACE_NODE, &interface_desc_cmd);
  install_element (INTERFACE_NODE, &no_interface_desc_cmd);
  install_element (INTERFACE_NODE, &ipv6_ospf6_cost_cmd);
  install_element (INTERFACE_NODE, &ipv6_ospf6_deadinterval_cmd);
  install_element (INTERFACE_NODE, &ipv6_ospf6_hellointerval_cmd);
  install_element (INTERFACE_NODE, &ipv6_ospf6_priority_cmd);
  install_element (INTERFACE_NODE, &ipv6_ospf6_retransmitinterval_cmd);
  install_element (INTERFACE_NODE, &ipv6_ospf6_transmitdelay_cmd);
  install_element (INTERFACE_NODE, &ipv6_ospf6_instance_cmd);
}

