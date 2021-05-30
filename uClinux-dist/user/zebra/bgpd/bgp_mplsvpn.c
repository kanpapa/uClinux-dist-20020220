/* MPLS-VPN
 * Copyright (C) 2000 Kunihiro Ishiguro <kunihiro@zebra.org>
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

#include "command.h"
#include "prefix.h"
#include "newlist.h"
#include "table.h"
#include "log.h"
#include "memory.h"
#include "stream.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_mplsvpn.h"

int peer_activate (struct vty *, char *, int, int);
int peer_deactivate (struct vty *, char *, int, int);
int route_vty_out (struct vty *, struct prefix *, struct bgp_info *);
int route_vty_out_tag (struct vty *, struct prefix *, struct bgp_info *);

u_int16_t
decode_rd_type (u_char *pnt)
{
  u_int16_t v;
  
  v = ((u_int16_t) *pnt++ << 8);
  v |= (u_int16_t) *pnt;
  return v;
}

u_int32_t
decode_label (u_char *pnt)
{
  u_int32_t l;

  l = ((u_int32_t) *pnt++ << 12);
  l |= (u_int32_t) *pnt++ << 4;
  l |= (u_int32_t) ((*pnt & 0xf0) >> 4);
  return l;
}

void
decode_rd_as (u_char *pnt, struct rd_as *rd_as)
{
  rd_as->as = (u_int16_t) *pnt++ << 8;
  rd_as->as |= (u_int16_t) *pnt++;
  
  rd_as->val = ((u_int32_t) *pnt++ << 24);
  rd_as->val |= ((u_int32_t) *pnt++ << 16);
  rd_as->val |= ((u_int32_t) *pnt++ << 8);
  rd_as->val |= (u_int32_t) *pnt;
}

void
decode_rd_ip (u_char *pnt, struct rd_ip *rd_ip)
{
  memcpy (&rd_ip->ip, pnt, 4);
  pnt += 4;
  
  rd_ip->val = ((u_int16_t) *pnt++ << 8);
  rd_ip->val |= (u_int16_t) *pnt;
}

int bgp_update (struct peer *, struct prefix *, struct attr *, 
		afi_t, safi_t, int, int, struct prefix_rd *, u_char *);

int bgp_withdraw (struct peer *, struct prefix *, struct attr *, 
		  int, int, int, int, struct prefix_rd *, u_char *);
int
nlri_parse_vpnv4 (struct peer *peer, struct attr *attr, 
		  struct bgp_nlri *packet)
{
  u_char *pnt;
  u_char *lim;
  struct prefix p;
  int psize;
  int prefixlen;
  u_int32_t label;
  u_int16_t type;
  struct rd_as rd_as;
  struct rd_ip rd_ip;
  struct prefix_rd prd;
  u_char *tagpnt;

  /* Check peer status. */
  if (peer->status != Established)
    return 0;
  
  /* Make prefix_rd */
  prd.family = AF_UNSPEC;
  prd.safi = SAFI_MPLS_VPN;
  prd.prefixlen = 64;

  pnt = packet->nlri;
  lim = pnt + packet->length;

  for (; pnt < lim; pnt += psize)
    {
      /* Clear prefix structure. */
      memset (&p, 0, sizeof (struct prefix));

      /* Fetch prefix length. */
      prefixlen = *pnt++;
      p.family = AF_INET;
      p.safi = SAFI_MPLS_VPN;
      psize = PSIZE (prefixlen);

      if (prefixlen < 88)
	{
	  zlog_err ("prefix length is less than 88: %d", prefixlen);
	  return -1;
	}

      label = decode_label (pnt);

      /* Copyr label to prefix. */
      tagpnt = pnt;;

      /* Copy routing distinguisher to rd. */
      memcpy (&prd.val, pnt + 3, 8);

      /* Decode RD type. */
      type = decode_rd_type (pnt + 3);

      /* Decode RD value. */
      if (type == RD_TYPE_AS)
	decode_rd_as (pnt + 5, &rd_as);
      else if (type == RD_TYPE_IP)
	decode_rd_ip (pnt + 5, &rd_ip);
      else
	{
	  zlog_err ("Invalid RD type %d", type);
	  return -1;
	}

      p.prefixlen = prefixlen - 88;
      memcpy (&p.u.prefix, pnt + 11, psize - 11);
#if 0
      if (type == RD_TYPE_AS)
	zlog_info ("prefix %ld:%ld:%ld:%s/%d", label, rd_as.as, rd_as.val,
		   inet_ntoa (p.u.prefix4), p.prefixlen);
      else if (type == RD_TYPE_IP)
	zlog_info ("prefix %ld:%s:%ld:%s/%d", label, inet_ntoa (rd_ip.ip),
		   rd_ip.val, inet_ntoa (p.u.prefix4), p.prefixlen);
#endif /* 0 */

      if (pnt + psize > lim)
	return -1;

      if (attr)
	bgp_update (peer, &p, attr, AFI_IP, SAFI_MPLS_VPN,
		    ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL, &prd, tagpnt);
      else
	bgp_withdraw (peer, &p, attr, AFI_IP, SAFI_MPLS_VPN,
		      ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL, &prd, tagpnt);
    }

  /* Packet length consistency check. */
  if (pnt != lim)
    return -1;

  return 0;
}

DEFUN (address_family_vpnv4,
       address_family_vpnv4_cmd,
       "address-family vpnv4",
       "Address family configuration\n"
       "IPv4 MPLS-VPN\n")
{
  vty->node = BGP_VPNV4_NODE;
  return CMD_SUCCESS;
}

ALIAS (address_family_vpnv4,
       address_family_vpnv4_unicast_cmd,
       "address-family vpnv4 unicast",
       "Address family configuration\n"
       "IPv4 MPLS-VPN\n"
       "Unicast\n")

DEFUN (exit_address_family,
       exit_address_family_cmd,
       "exit-address-family",
       "Exit from address family configuration\n")
{
  if (vty->node == BGP_VPNV4_NODE)
    vty->node = BGP_NODE;
  return CMD_SUCCESS;
}

DEFUN (vpnv4_activate,
       vpnv4_activate_cmd,
       "neighbor A.B.C.D activate",
       NEIGHBOR_STR
       "Neighbor address\n"
       "Activate this peer\n")
{
  return peer_activate (vty, argv[0], AFI_IP, SAFI_MPLS_VPN);
}

DEFUN (no_vpnv4_activate,
       no_vpnv4_activate_cmd,
       "no neighbor A.B.C.D activate",
       NO_STR
       NEIGHBOR_STR
       "Neighbor address\n"
       "De-activate this peer\n")
{
  return peer_deactivate (vty, argv[0], AFI_IP, SAFI_MPLS_VPN);
}

extern struct peer *peer_self;

int
str2prefix_rd (u_char *str, struct prefix_rd *prd)
{
  int ret;
  u_char *p;
  u_char *p2;
  struct stream *s;
  u_char *half;
  struct in_addr addr;

  s = stream_new (8);

  prd->family = AF_UNSPEC;
  prd->safi = SAFI_MPLS_VPN;
  prd->prefixlen = 64;

  p = strchr (str, ':');
  if (! p)
    return 0;

  if (! all_digit (p + 1))
    return 0;

  half = XMALLOC (MTYPE_TMP, (p - str) + 1);
  memcpy (half, str, (p - str));
  half[p - str] = '\0';

  p2 = strchr (str, '.');

  if (! p2)
    {
      if (! all_digit (half))
	{
	  XFREE (MTYPE_TMP, half);
	  return 0;
	}
      stream_putw (s, RD_TYPE_AS);
      stream_putw (s, atoi (half));
      stream_putl (s, atol (p + 1));
    }
  else
    {
      ret = inet_aton (half, &addr);
      if (! ret)
	{
	  XFREE (MTYPE_TMP, half);
	  return 0;
	}
      stream_putw (s, RD_TYPE_IP);
      stream_put_in_addr (s, &addr);
      stream_putw (s, atol (p + 1));
    }
  memcpy (prd->val, s->data, 8);

  return 1;
}

int
str2tag (u_char *str, u_char *tag)
{
  u_int32_t l;

  l = atol (str);

  tag[0] = (u_char)(l >> 12);
  tag[1] = (u_char)(l >> 4);
  tag[2] = (u_char)(l << 4);

  return 1;
}

/* For testing purpose, static route of MPLS-VPN. */
DEFUN (vpnv4_network,
       vpnv4_network_cmd,
       "network A.B.C.D/M rd WORD tag WORD",
       "static route for VPNv4\n"
       "prefix\n"
       "rd\n"
       "rd value\n"
       "tag\n"
       "tag value\n")
{
  return bgp_static_set_vpnv4 (vty, argv[0], argv[1], argv[2]);
}

/* For testing purpose, static route of MPLS-VPN. */
DEFUN (no_vpnv4_network,
       no_vpnv4_network_cmd,
       "no network A.B.C.D/M rd WORD tag WORD",
       NO_STR
       "static route for VPNv4\n"
       "prefix\n"
       "rd\n"
       "rd value\n"
       "tag\n"
       "tag value\n")
{
  return bgp_static_unset_vpnv4 (vty, argv[0], argv[1], argv[2]);
}

int
bgp_show_mpls_vpn (struct vty *vty, int tags)
{
  struct bgp *bgp;
  struct route_table *table;
  struct route_node *rn;
  struct route_node *rm;
  struct bgp_info *ri;
  int rd_header;
  int header = 1;
  char v4_header[] = "   Network            Next Hop         Metric LocPrf Weight Path%s";
  char v4_header_tag[] = "   Network            Next Hop                Tag%s";

  bgp = bgp_get_default ();
  if (bgp == NULL)
    {
      vty_out (vty, "No BGP process is configured%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  
  for (rn = route_top (bgp->rib[AFI_IP][SAFI_MPLS_VPN]); rn; rn = route_next (rn))
    if ((table = rn->info) != NULL)
      {
	rd_header = 1;

	for (rm = route_top (table); rm; rm = route_next (rm))
	  for (ri = rm->info; ri; ri = ri->next)
	    {
	      if (header)
		{
		  if (tags)
		    vty_out (vty, v4_header_tag, VTY_NEWLINE);
		  else
		    vty_out (vty, v4_header, VTY_NEWLINE);
		  header = 0;
		}

	      if (rd_header)
		{
		  u_int16_t type;
		  struct rd_as rd_as;
		  struct rd_ip rd_ip;
		  u_char *pnt;

		  pnt = rn->p.u.val;

		  /* Decode RD type. */
		  type = decode_rd_type (pnt);
		  /* Decode RD value. */
		  if (type == RD_TYPE_AS)
		    decode_rd_as (pnt + 2, &rd_as);
		  else if (type == RD_TYPE_IP)
		    decode_rd_ip (pnt + 2, &rd_ip);

		  vty_out (vty, "Route Distinguisher: ");

		  if (type == RD_TYPE_AS)
		    vty_out (vty, "%ld:%ld", rd_as.as, rd_as.val);
		  else if (type == RD_TYPE_IP)
		    vty_out (vty, "%s:%ld", inet_ntoa (rd_ip.ip), rd_ip.val);
		  
		  vty_out (vty, "%s", VTY_NEWLINE);		  
		  rd_header = 0;
		}
	      if (tags)
		route_vty_out_tag (vty, &rm->p, ri);
	      else
		route_vty_out (vty, &rm->p, ri);
	    }
      }
  return CMD_SUCCESS;
}

int
bgp_show_mpls_vpn_route (struct vty *vty, char *ip_str)
{
  int ret;
  struct bgp *bgp;
  struct route_table *table;
  struct route_node *rn;
  struct route_node *rm;
  struct bgp_info *ri;
  int rd_header;
  struct prefix match;
  int display = 0;

  /* Check IP address argument. */
  ret = str2prefix (ip_str, &match);
  if (! ret)
    {
      vty_out (vty, "address is malformed%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  match.family = AF_INET;
  match.safi = SAFI_MPLS_VPN;
  match.prefixlen = IPV4_MAX_BITLEN;

  bgp = bgp_get_default ();
  if (bgp == NULL)
    {
      vty_out (vty, "No BGP process is configured%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  
  for (rn = route_top (bgp->rib[AFI_IP][SAFI_MPLS_VPN]); rn;
       rn = route_next (rn))
    if ((table = rn->info) != NULL)
      {
	rd_header = 1;

	if ((rm = route_node_match (table, &match)) != NULL)
	  {
	    for (ri = rm->info; ri; ri = ri->next)
	      {
		if (rd_header)
		  {
		    u_int16_t type;
		    struct rd_as rd_as;
		    struct rd_ip rd_ip;
		    u_char *pnt;

		    pnt = rn->p.u.val;

		    /* Decode RD type. */
		    type = decode_rd_type (pnt);
		    /* Decode RD value. */
		    if (type == RD_TYPE_AS)
		      decode_rd_as (pnt + 2, &rd_as);
		    else if (type == RD_TYPE_IP)
		      decode_rd_ip (pnt + 2, &rd_ip);
		
		    vty_out (vty, "Route Distinguisher: ");

		    if (type == RD_TYPE_AS)
		      vty_out (vty, "%ld:%ld", rd_as.as, rd_as.val);
		    else if (type == RD_TYPE_IP)
		      vty_out (vty, "%s:%ld", inet_ntoa (rd_ip.ip), rd_ip.val);
		  
		    vty_out (vty, "%s", VTY_NEWLINE);		  
		    rd_header = 0;
		  }
		display++;
		route_vty_out_detail (vty, &rm->p, ri);
	      }
	  }
      }
  if (! display)
    {
      vty_out (vty, "Can't find route%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return CMD_SUCCESS;
}

DEFUN (show_ip_bgp_vpnv4_all,
       show_ip_bgp_vpnv4_all_cmd,
       "show ip bgp vpnv4 all",
       SHOW_STR
       IP_STR
       BGP_STR
       "VPNv4\n"
       "All routes\n")
{
  return bgp_show_mpls_vpn (vty, 0);
}


DEFUN (show_ip_bgp_vpnv4_all_tags,
       show_ip_bgp_vpnv4_all_tags_cmd,
       "show ip bgp vpnv4 all tags",
       SHOW_STR
       IP_STR
       BGP_STR
       "VPNv4\n"
       "All\n"
       "Tags\n")
{
  return bgp_show_mpls_vpn (vty, 1);
}

DEFUN (show_ip_bgp_vpnv4_all_route,
       show_ip_bgp_vpnv4_all_route_cmd,
       "show ip bgp vpnv4 all A.B.C.D",
       SHOW_STR
       IP_STR
       BGP_STR
       "VPNv4\n"
       "All RD routes\n"
       "prefix to display\n")
{
  return bgp_show_mpls_vpn_route (vty, argv[0]);
}

/* BGP_VPNV4_NODE. */
struct cmd_node bgp_vpnv4_node =
{
  BGP_VPNV4_NODE,
  "%s(config-router-af)# ",
};

void
bgp_mplsvpn_init ()
{
  install_node (&bgp_vpnv4_node, NULL);
  install_default (BGP_VPNV4_NODE);

  install_element (BGP_NODE, &address_family_vpnv4_cmd);
  install_element (BGP_NODE, &address_family_vpnv4_unicast_cmd);
  install_element (BGP_VPNV4_NODE, &vpnv4_activate_cmd);
  install_element (BGP_VPNV4_NODE, &no_vpnv4_activate_cmd);
  install_element (BGP_VPNV4_NODE, &exit_address_family_cmd);

  install_element (BGP_VPNV4_NODE, &vpnv4_network_cmd);
  install_element (BGP_VPNV4_NODE, &no_vpnv4_network_cmd);

  install_element (VIEW_NODE, &show_ip_bgp_vpnv4_all_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_vpnv4_all_route_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_vpnv4_all_tags_cmd);

  install_element (ENABLE_NODE, &show_ip_bgp_vpnv4_all_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_vpnv4_all_route_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_vpnv4_all_tags_cmd);
}
