/* BGP packet management routine.
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

#include "thread.h"
#include "stream.h"
#include "network.h"
#include "prefix.h"
#include "command.h"
#include "log.h"
#include "memory.h"
#include "sockunion.h"		/* for inet_ntop () */
#include "newlist.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_dump.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_fsm.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_packet.h"
#include "bgpd/bgp_open.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_community.h"
#include "bgpd/bgp_network.h"
#include "bgpd/bgp_mplsvpn.h"

int stream_put_prefix (struct stream *, struct prefix *);

/* Set up BGP packet marker and packet type. */
static int
bgp_packet_set_marker (struct stream *s, u_char type)
{
  int i;

  /* Fill in marker. */
  for (i = 0; i < BGP_MARKER_SIZE; i++)
    stream_putc (s, 0xff);

  /* Dummy total length. This field is should be filled in later on. */
  stream_putw (s, 0);

  /* BGP packet type. */
  stream_putc (s, type);

  /* Return current stream size. */
  return stream_get_putp (s);
}

/* Set BGP packet header size entry.  If size is zero then use current
   stream size. */
static int
bgp_packet_set_size (struct stream *s, bgp_size_t size)
{
  int cp;

  /* Preserve current pointer. */
  cp = stream_get_putp (s);
  stream_set_putp (s, BGP_MARKER_SIZE);

  /* If size is specifed use it. */
  if (size)
    stream_putw (s, size);
  else
    stream_putw (s, cp);

  /* Write back current pointer. */
  stream_set_putp (s, cp);

  return cp;
}

/* Add new packet to the peer. */
void
bgp_packet_add (struct peer *peer, struct stream *s)
{
  /* Add packet to the end of list. */
  stream_fifo_push (peer->obuf, s);
}

/* Free first packet. */
void
bgp_packet_delete (struct peer *peer)
{
  stream_free (stream_fifo_pop (peer->obuf));
}

/* Duplicate packet. */
struct stream *
bgp_packet_dup (struct stream *s)
{
  struct stream *new;

  new = stream_new (stream_get_endp (s));

  new->endp = s->endp;
  new->putp = s->putp;
  new->getp = s->getp;

  memcpy (new->data, s->data, stream_get_endp (s));

  return new;
}

/* Check file descriptor whether connect is established. */
static void
bgp_connect_check (struct peer *peer)
{
  int status;
  int slen;
  int ret;

  /* Anyway I have to reset read and write thread. */
  BGP_READ_OFF (peer->t_read);
  BGP_WRITE_OFF (peer->t_write);

  /* Check file descriptor. */
  slen = sizeof (status);
  ret = getsockopt(peer->fd, SOL_SOCKET, SO_ERROR, (void *) &status, &slen);

  /* If getsockopt is fail, this is fatal error. */
  if (ret < 0)
    {
      zlog (peer->log, LOG_INFO, "can't get sockopt for nonblocking connect");
      BGP_EVENT_ADD (peer, TCP_fatal_error);
      return;
    }      

  /* When status is 0 then TCP connection is established. */
  if (status == 0)
    {
      BGP_EVENT_ADD (peer, TCP_connection_open);
    }
  else
    {
      if (BGP_DEBUG (events, EVENTS))
	  plog_info (peer->log, "%s [Event] Connect failed (%s)",
		     peer->host, strerror (errno));
      BGP_EVENT_ADD (peer, TCP_connection_open_failed);
    }
}

/* Write packet to the peer. */
int
bgp_write (struct thread *thread)
{
  struct peer *peer;
  u_char type;
  struct stream *s; 
  int ret;

  /* Yes first of all get peer pointer. */
  peer = THREAD_ARG (thread);
  peer->t_write = NULL;

  /* In case of sending notify we don't want proceed below routine. */

  /* For non-blocking IO check. */
  if (peer->status == Connect)
    {
      bgp_connect_check (peer);
      return 0;
    }

  /* There should be at least one packet. */
  s = stream_fifo_head (peer->obuf);
  if (!s)
    return 0;
  assert (stream_get_endp (s) >= BGP_HEADER_SIZE);

  /* peer->fd is writable. */
  ret = writen (peer->fd, STREAM_DATA (s), stream_get_endp (s));
  if (ret <= 0)
    {
      bgp_stop (peer);
      peer->status = Idle;
      bgp_timer_set (peer);
      return 0;
    }

  /* Retrieve BGP packet type. */
  stream_set_getp (s, BGP_MARKER_SIZE + 2);
  type = stream_getc (s);

  switch (type)
    {
    case BGP_MSG_OPEN:
      peer->open_out++;
      break;
    case BGP_MSG_UPDATE:
      peer->update_out++;
      break;
    case BGP_MSG_NOTIFY:
      peer->notify_out++;
      /* Double start timer. */
      peer->v_start *= 2;

      /* Overflow check. */
      if (peer->v_start >= (60 * 2))
	peer->v_start = (60 * 2);

      /* BGP_EVENT_ADD (peer, BGP_Stop); */
      bgp_stop (peer);
      peer->status = Idle;
      bgp_timer_set (peer);
      return 0;
      break;
    case BGP_MSG_KEEPALIVE:
      peer->keepalive_out++;
      break;
    }

  /* OK we send packet so delete it. */
  bgp_packet_delete (peer);
  
  /* If there is a packet still need bgp write thread. */
  if (stream_fifo_head (peer->obuf))
    BGP_WRITE_ON (peer->t_write, bgp_write, peer->fd);
  
  return 0;
}

/* This is only for sending NOTIFICATION message to neighbor. */
int
bgp_write_notify (struct peer *peer)
{
  int ret;
  u_char type;
  struct stream *s; 

  /* There should be at least one packet. */
  s = stream_fifo_head (peer->obuf);
  if (!s)
    return 0;
  assert (stream_get_endp (s) >= BGP_HEADER_SIZE);

  /* I'm not sure fd is writable. */
  ret = writen (peer->fd, STREAM_DATA (s), stream_get_endp (s));
  if (ret <= 0)
    {
      bgp_stop (peer);
      peer->status = Idle;
      bgp_timer_set (peer);
      return 0;
    }

  /* Retrieve BGP packet type. */
  stream_set_getp (s, BGP_MARKER_SIZE + 2);
  type = stream_getc (s);

  assert (type == BGP_MSG_NOTIFY);

  /* Type should be notify. */
  peer->notify_out++;

  /* Double start timer. */
  peer->v_start *= 2;

  /* Overflow check. */
  if (peer->v_start >= (60 * 2))
    peer->v_start = (60 * 2);

  /* We don't call event manager at here for avoiding other events. */
  bgp_stop (peer);
  peer->status = Idle;
  bgp_timer_set (peer);

  return 0;
}

/* Make keepalive packet and send it to the peer. */
void
bgp_keepalive_send (struct peer *peer)
{
  struct stream *s;

  s = stream_new (BGP_MAX_PACKET_SIZE);

  /* Make keepalive packet. */
  bgp_packet_set_marker (s, BGP_MSG_KEEPALIVE);
  bgp_packet_set_size (s, 0);

  /* Dump packet if debug option is set. */
  /* bgp_packet_dump (s); */

  /* Add packet to the peer. */
  bgp_packet_add (peer, s);

  BGP_WRITE_ON (peer->t_write, bgp_write, peer->fd);
}

/* Make open packet and send it to the peer. */
void
bgp_open_send (struct peer *peer)
{
  struct stream *s;

  s = stream_new (BGP_MAX_PACKET_SIZE);

  /* Make open packet. */
  bgp_packet_set_marker (s, BGP_MSG_OPEN);

  /* Set open packet values. */
  stream_putc (s, BGP_VERSION_4);        /* BGP version */
  stream_putw (s, peer->local_as);	 /* My Autonomous System*/
  stream_putw (s, peer->v_holdtime);	 /* Hold Time */
  stream_put_in_addr (s, &peer->local_id); /* BGP Identifier */

  /* Set capability code. */
  bgp_open_capability (s, peer);

  /* Set BGP packet length. */
  bgp_packet_set_size (s, 0);

  /* Dump packet if debug option is set. */
  /* bgp_packet_dump (s); */

  /* Add packet to the peer. */
  bgp_packet_add (peer, s);

  BGP_WRITE_ON (peer->t_write, bgp_write, peer->fd);
}

/* Send BGP notify packet with data potion. */
void
bgp_notify_send_with_data (struct peer *peer, u_char code, u_char sub_code,
			   u_char *data, size_t datalen)
{
  struct stream *s;

  /* Allocate new stream. */
  s = stream_new (BGP_MAX_PACKET_SIZE);

  /* Make nitify packet. */
  bgp_packet_set_marker (s, BGP_MSG_NOTIFY);

  /* Set notify packet values. */
  stream_putc (s, code);        /* BGP notify code */
  stream_putc (s, sub_code);	/* BGP notify sub_code */

  /* If notify data is present. */
  if (data)
    stream_write (s, data, datalen);
  
  /* Set BGP packet length. */
  bgp_packet_set_size (s, 0);

  /* Add packet to the peer. */
  stream_fifo_free (peer->obuf);
  bgp_packet_add (peer, s);

  /* For debug */
  {
    struct bgp_notify bgp_notify;

    bgp_notify.code = code;
    bgp_notify.subcode = sub_code;
    bgp_notify.data = NULL;
    bgp_notify_print (peer, &bgp_notify, "SEND");
  }

  /* Call imidiately. */
  BGP_WRITE_OFF (peer->t_write);

  bgp_write_notify (peer);
}

/* Send BGP notify packet. */
void
bgp_notify_send (struct peer *peer, u_char code, u_char sub_code)
{
  bgp_notify_send_with_data (peer, code, sub_code, NULL, 0);
}

/* Send BGP update packet. */
void
bgp_update_send (struct peer_conf *conf, struct peer *peer,
		 struct prefix *p, struct attr *attr, afi_t afi, safi_t safi,
		 struct peer *from, struct prefix_rd *prd, u_char *tag)
{
  struct stream *s;
  struct stream *packet;
  unsigned long pos;
  bgp_size_t total_attr_len;
  char attrstr[BUFSIZ];
  char buf[BUFSIZ];

#ifdef DISABLE_BGP_ANNOUNCE
  return;
#endif /* DISABLE_BGP_ANNOUNCE */

  /* Make attribute dump string. */
  bgp_dump_attr (peer, attr, attrstr, BUFSIZ);

  zlog (peer->log, LOG_INFO, "%s [Update:SEND] %s/%d %s",
	peer->host, inet_ntop(p->family, &(p->u.prefix), buf, BUFSIZ),
	p->prefixlen, attrstr);

  s = stream_new (BGP_MAX_PACKET_SIZE);

  /* Make BGP update packet. */
  bgp_packet_set_marker (s, BGP_MSG_UPDATE);

  /* Unfeasible Routes Length. */
  stream_putw (s, 0);		

  /* Make place for total attribute length.  */
  pos = stream_get_putp (s);
  stream_putw (s, 0);
  total_attr_len = bgp_packet_attribute (conf, peer, s, attr, p, afi, safi, from, prd, tag);

  /* Set Total Path Attribute Length. */
  stream_putw_at (s, pos, total_attr_len);

  /* NLRI set. */
  if (p->family == AF_INET && safi == SAFI_UNICAST)
    stream_put_prefix (s, p);

  /* Set size. */
  bgp_packet_set_size (s, 0);

  packet = bgp_packet_dup (s);
  stream_free (s);

  /* Dump packet if debug option is set. */
#ifdef DEBUG
  bgp_packet_dump (packet);
#endif /* DEBUG */

  /* Add packet to the peer. */
  bgp_packet_add (peer, packet);

  BGP_WRITE_ON (peer->t_write, bgp_write, peer->fd);
}

/* Send BGP update packet. */
void
bgp_withdraw_send (struct peer *peer, struct prefix *p, afi_t afi, safi_t safi,
		   struct prefix_rd *prd, u_char *tag)
{
  struct stream *s;
  struct stream *packet;
  unsigned long pos;
  unsigned long cp;
  bgp_size_t unfeasible_len;
  bgp_size_t total_attr_len;
  char buf[BUFSIZ];

#ifdef DISABLE_BGP_ANNOUNCE
  return;
#endif /* DISABLE_BGP_ANNOUNCE */

  total_attr_len = 0;
  pos = 0;

  zlog (peer->log, LOG_INFO, "%s [Withdraw:SEND] %s/%d",
	peer->host, inet_ntop(p->family, &(p->u.prefix), buf, BUFSIZ),
	p->prefixlen);

  s = stream_new (BGP_MAX_PACKET_SIZE);

  /* Make BGP update packet. */
  bgp_packet_set_marker (s, BGP_MSG_UPDATE);

  /* Unfeasible Routes Length. */;
  cp = stream_get_putp (s);
  stream_putw (s, 0);

  /* Withdrawn Routes. */
  if (p->family == AF_INET && safi == SAFI_UNICAST)
    {
      stream_put_prefix (s, p);

      unfeasible_len = stream_get_putp (s) - cp - 2;
      stream_putw_at (s, cp, unfeasible_len);
    }

  /* Make attribute. */
#ifdef HAVE_IPV6
  if((p->family == AF_INET6)
     || (p->family == AF_INET && safi == SAFI_MULTICAST)
     || (p->family == AF_INET && safi == SAFI_MPLS_VPN))
    {
      pos = stream_get_putp (s);
      stream_putw (s, 0);
      total_attr_len = bgp_packet_withdraw (peer, s, p, afi, safi, prd, tag);

      /* Set Total Path Attribute Length. */
      stream_putw_at (s, pos, total_attr_len);
    }
  else
    stream_putw (s, 0);
#else
  stream_putw (s, 0);
#endif /* HAVE_IPV6 */

  bgp_packet_set_size (s, 0);

  packet = bgp_packet_dup (s);
  stream_free (s);

  /* Add packet to the peer. */
  bgp_packet_add (peer, packet);

  BGP_WRITE_ON (peer->t_write, bgp_write, peer->fd);
}

char *
afi2str (afi_t afi)
{
  if (afi == AFI_IP)
    return "AFI_IP";
  else if (afi == AFI_IP6)
    return "AFI_IP6";
  else
    return "Unknown AFI";
}

char *
safi2str (safi_t safi)
{
  if (safi == SAFI_UNICAST)
    return "SAFI_UNICAST";
  else if (safi == SAFI_MULTICAST)
    return "SAFI_MULTICAST";
  else
    return "Unknown SAFI";
}

/* Send route refresh message to the peer. */
void
bgp_route_refresh_send (struct peer *peer, afi_t afi, safi_t safi)
{
  struct stream *s;
  struct stream *packet;

#ifdef DISABLE_BGP_ANNOUNCE
  return;
#endif /* DISABLE_BGP_ANNOUNCE */

  zlog (peer->log, LOG_INFO, "%s [Refresh:SEND] %s %s", 
	peer->host, afi2str (afi), safi2str (safi));

  s = stream_new (BGP_MAX_PACKET_SIZE);

  /* Make BGP update packet. */
  bgp_packet_set_marker (s, BGP_MSG_ROUTE_REFRESH);

  /* Encode Route Refresh message. */
  stream_putw (s, afi);
  stream_putc (s, 0);
  stream_putc (s, safi);
  
  /* Set packet size. */
  bgp_packet_set_size (s, 0);

  /* Make real packet. */
  packet = bgp_packet_dup (s);
  stream_free (s);

  /* Add packet to the peer. */
  bgp_packet_add (peer, packet);

  BGP_WRITE_ON (peer->t_write, bgp_write, peer->fd);
}

/* RFC1771 6.8 Connection collision detection. */
int
bgp_collision_detect (struct peer *new)
{
  struct peer *peer;
  struct newnode *nn;

  /* Upon receipt of an OPEN message, the local system must examine
     all of its connections that are in the OpenConfirm state.  A BGP
     speaker may also examine connections in an OpenSent state if it
     knows the BGP Identifier of the peer by means outside of the
     protocol.  If among these connections there is a connection to a
     remote BGP speaker whose BGP Identifier equals the one in the
     OPEN message, then the local system performs the following
     collision resolution procedure: */

  NEWLIST_LOOP (peer_list, peer, nn)
    {
      /* Under OpenConfirm status, local peer structure already hold
         remote router ID. */

      if (peer != new
	  && (peer->status == OpenConfirm)
	  && peer->remote_id.s_addr == new->remote_id.s_addr)
	{
	  /* 1. The BGP Identifier of the local system is compared to
	     the BGP Identifier of the remote system (as specified in
	     the OPEN message). */

	  if (ntohl (peer->local_id.s_addr < peer->remote_id.s_addr))
	    {
	      /* 2. If the value of the local BGP Identifier is less
		 than the remote one, the local system closes BGP
		 connection that already exists (the one that is
		 already in the OpenConfirm state), and accepts BGP
		 connection initiated by the remote system. */

	      bgp_notify_send (peer, BGP_NOTIFY_CEASE, 0);
	      return 0;
	    }
	  else
	    {
	      /* 3. Otherwise, the local system closes newly created
		 BGP connection (the one associated with the newly
		 received OPEN message), and continues to use the
		 existing one (the one that is already in the
		 OpenConfirm state). */

	      bgp_notify_send (new, BGP_NOTIFY_CEASE, 0);
	      return 1;
	    }
	}
    }
  return 0;
}

int
bgp_open_receive (struct peer *peer, bgp_size_t size)
{
  int ret;
  u_char version;
  u_char optlen;
  u_int16_t holdtime;
  as_t remote_as;
  struct peer *realpeer;
  struct in_addr remote_id;
  int capability;

  realpeer = NULL;
  
  /* Parse open packet. */
  version = stream_getc (peer->ibuf);
  remote_as  = stream_getw (peer->ibuf);
  holdtime = stream_getw (peer->ibuf);
  remote_id.s_addr = stream_get_ipv4 (peer->ibuf);

  /* Lookup peer from Open packet. */
  if (CHECK_FLAG (peer->sflags, PEER_STATUS_ACCEPT_PEER))
    {
      realpeer = peer_lookup_with_open (&peer->su, remote_as, &remote_id);

      /* Peer's source IP address is check in bgp_accept(), so this
	 must be AS number mismatch or remote-id configuration
	 mismatch. */
      if (! realpeer)
	return -1;
    }

  /* When collision is detected and this peer is closed.  Retrun
     immidiately. */
  if (bgp_collision_detect (peer))
    return -1;

  /* Hack part. */
  if (CHECK_FLAG (peer->sflags, PEER_STATUS_ACCEPT_PEER))
    {
      if (realpeer->status != Active)
	{
	  zlog_info ("%s [Event] peer's status is not Active", realpeer->host);
	  return -1;
	}

      zlog_info ("%s [Event] Transfer temporary BGP peer to existing one",
		 peer->host);

      bgp_stop (realpeer);
      
      /* Transfer file descriptor. */
      realpeer->fd = peer->fd;
      peer->fd = -1;

      /* Transfer input buffer. */
      stream_free (realpeer->ibuf);
      realpeer->ibuf = peer->ibuf;
      peer->ibuf = NULL;

      /* Transfer status. */
      realpeer->status = peer->status;
      bgp_stop (peer);

      /* peer pointer change. Open packet send to neighbor. */
      peer = realpeer;
      bgp_open_send (peer);
      BGP_READ_ON (peer->t_read, bgp_read, peer->fd);
    }

  /* Set remote router-id */
  peer->remote_id = remote_id;

  /* Peer BGP version check. */
  if (version != BGP_VERSION_4)
    {
      bgp_notify_send (peer, 
		       BGP_NOTIFY_OPEN_ERR, 
		       BGP_NOTIFY_OPEN_UNSUP_VERSION);
      return -1;
    }

  /* Check neighbor as number. */
  if (remote_as != peer->as)
    {
      bgp_notify_send (peer,
		       BGP_NOTIFY_OPEN_ERR, 
		       BGP_NOTIFY_OPEN_BAD_PEER_AS);
      return -1;
    }

  /* From the rfc: Upon receipt of an OPEN message, a BGP speaker MUST
     calculate the value of the Hold Timer by using the smaller of its
     configured Hold Time and the Hold Time received in the OPEN message.
     The Hold Time MUST be either zero or at least three seconds.  An
     implementation may reject connections on the basis of the Hold Time. */

  if (holdtime < 3 && holdtime != 0)
    {
      bgp_notify_send (peer,
		       BGP_NOTIFY_OPEN_ERR, 
		       BGP_NOTIFY_OPEN_UNACEP_HOLDTIME);
      return -1;
    }
    
  if (holdtime < peer->v_holdtime)
    peer->v_holdtime = holdtime;

  /* From the rfc: A reasonable maximum time between KEEPALIVE messages
     would be one third of the Hold Time interval.  KEEPALIVE messages
     MUST NOT be sent more frequently than one per second.  An
     implementation MAY adjust the rate at which it sends KEEPALIVE
     messages as a function of the Hold Time interval. */

  if (peer->config & PEER_CONFIG_KEEPALIVE)
    {
      if (peer->v_keepalive > (peer->v_holdtime / 3))
	{
	  zlog (peer->log, LOG_WARNING,
		"%s [Warning] Holdtime %d, but keepalive configured as %d not %d", peer->host, peer->v_holdtime, peer->v_keepalive, (peer->v_holdtime / 3));
	}
    }
  else
    {
      peer->v_keepalive = peer->v_holdtime / 3;
    }

  /* Open option part parse. */
  capability = 0;
  optlen = stream_getc (peer->ibuf);
  if (optlen != 0) 
    {
      ret = bgp_open_option_parse (peer, optlen, &capability);
      if (ret < 0)
	return ret;

      stream_forward (peer->ibuf, optlen);
    }

  /* Override capability. */
  if (! capability || CHECK_FLAG (peer->flags, PEER_FLAG_OVERRIDE_CAPABILITY))
    {
      peer->afc_nego[AFI_IP][SAFI_UNICAST] = peer->afc[AFI_IP][SAFI_UNICAST];
      peer->afc_nego[AFI_IP][SAFI_MULTICAST] = peer->afc[AFI_IP][SAFI_MULTICAST];
      peer->afc_nego[AFI_IP6][SAFI_UNICAST] = peer->afc[AFI_IP6][SAFI_UNICAST];
      peer->afc_nego[AFI_IP6][SAFI_MULTICAST] = peer->afc[AFI_IP6][SAFI_MULTICAST];
    }

  /* Get sockname. */
  bgp_getsockname (peer);

  /* Increment packet count. */
  peer->open_in++;

  BGP_EVENT_ADD (peer, Receive_OPEN_message);

  return 0;
}

/* Parse BGP Update packet and make attribute object. */
int
bgp_update_receive (struct peer *peer, bgp_size_t size)
{
  int ret;
  u_char *end;
  struct stream *s;
  struct attr attr;
  bgp_size_t attribute_len;
  bgp_size_t update_len;
  bgp_size_t withdraw_len;
  struct bgp_nlri update;
  struct bgp_nlri withdraw;
  struct bgp_nlri mp_update;
  struct bgp_nlri mp_withdraw;

  /* Status must be Established. */
  if (peer->status != Established) 
    {
      zlog_err ("%s [FSM] Update packet received under status %s",
		peer->host, LOOKUP (bgp_status_msg, peer->status));
      bgp_notify_send (peer, BGP_NOTIFY_FSM_ERR, 0);
      return -1;
    }

  /* Set initial values. */
  memset (&attr, 0, sizeof (struct attr));
  memset (&update, 0, sizeof (struct bgp_nlri));
  memset (&withdraw, 0, sizeof (struct bgp_nlri));
  memset (&mp_update, 0, sizeof (struct bgp_nlri));
  memset (&mp_withdraw, 0, sizeof (struct bgp_nlri));

  s = peer->ibuf;
  end = stream_pnt (s) + size;

  /* RFC1771 6.3 If the Unfeasible Routes Length or Total Attribute
     Length is too large (i.e., if Unfeasible Routes Length + Total
     Attribute Length + 23 exceeds the message Length), then the Error
     Subcode is set to Malformed Attribute List.  */
  if (stream_pnt (s) + 2 > end)
    {
      zlog_err ("%s [Error] Update packet error"
		" (packet length is short for unfeasible length)",
		peer->host);
      bgp_notify_send (peer, BGP_NOTIFY_UPDATE_ERR, 
		       BGP_NOTIFY_UPDATE_MAL_ATTR);
      return -1;
    }

  /* Unfeasible Route Length. */
  withdraw_len = stream_getw (s);

  /* Unfeasible Route Length check. */
  if (stream_pnt (s) + withdraw_len > end)
    {
      zlog_err ("%s [Error] Update packet error"
		" (packet unfeasible length overflow %d)",
		peer->host, withdraw_len);
      bgp_notify_send (peer, BGP_NOTIFY_UPDATE_ERR, 
		       BGP_NOTIFY_UPDATE_MAL_ATTR);
      return -1;
    }

  /* Unfeasible Route packet format check. */
  if (withdraw_len > 0)
    {
      ret = nlri_sanity_check (peer, AFI_IP, stream_pnt (s), withdraw_len);
      if (ret < 0)
	return -1;

      if (BGP_DEBUG (packet, PACKET_RECV))
	  zlog_info ("%s [Update:RECV] Unfeasible NLRI received", peer->host);

      withdraw.afi = AFI_IP;
      withdraw.safi = SAFI_UNICAST;
      withdraw.nlri = stream_pnt (s);
      withdraw.length = withdraw_len;
      stream_forward (s, withdraw_len);
    }
  
  /* Attribute total length check. */
  if (stream_pnt (s) + 2 > end)
    {
      zlog_warn ("%s [Error] Packet Error"
		 " (update packet is short for attribute length)",
		 peer->host);
      bgp_notify_send (peer, BGP_NOTIFY_UPDATE_ERR, 
		       BGP_NOTIFY_UPDATE_MAL_ATTR);
      return -1;
    }

  /* Fetch attribute total length. */
  attribute_len = stream_getw (s);

  /* Attribute length check. */
  if (stream_pnt (s) + attribute_len > end)
    {
      zlog_warn ("%s [Error] Packet Error"
		 " (update packet attribute length overflow %d)",
		 peer->host, attribute_len);
      bgp_notify_send (peer, BGP_NOTIFY_UPDATE_ERR, 
		       BGP_NOTIFY_UPDATE_MAL_ATTR);
      return -1;
    }

  /* Parse attribute when it exists. */
  if (attribute_len)
    {
      ret = bgp_attr_parse (peer, &attr, attribute_len, 
			    &mp_update, &mp_withdraw);
      if (ret < 0)
	return -1;
    }

  /* Network Layer Reachability Information. */
  update_len = end - stream_pnt (s);

  if (update_len)
    {
      /* Check NLRI packet format and prefix length. */
      ret = nlri_sanity_check (peer, AFI_IP, stream_pnt (s), update_len);
      if (ret < 0)
	return -1;

      /* Set NLRI portion to structure. */
      update.afi = AFI_IP;
      update.safi = SAFI_UNICAST;
      update.nlri = stream_pnt (s);
      update.length = update_len;
      stream_forward (s, update_len);
    }

  /* NLRI is processed only when the peer is configured specific
     Address Family and Subsequent Address Family. */
  if (peer->afc[AFI_IP][SAFI_UNICAST])
    {
      if (withdraw.length)
	nlri_parse (peer, NULL, &withdraw);
      if (update.length)
	nlri_parse (peer, &attr, &update);
    }
  if (peer->afc[AFI_IP][SAFI_MULTICAST])
    {
      if (mp_update.length
	  && mp_update.afi == AFI_IP 
	  && mp_update.safi == SAFI_MULTICAST)
	nlri_parse (peer, &attr, &mp_update);

      if (mp_withdraw.length
	  && mp_withdraw.afi == AFI_IP 
	  && mp_withdraw.safi == SAFI_MULTICAST)
	nlri_parse (peer, NULL, &mp_withdraw);
    }
  if (peer->afc[AFI_IP6][SAFI_UNICAST])
    {
      if (mp_update.length 
	  && mp_update.afi == AFI_IP6 
	  && mp_update.safi == SAFI_UNICAST)
	nlri_parse (peer, &attr, &mp_update);

      if (mp_withdraw.length 
	  && mp_withdraw.afi == AFI_IP6 
	  && mp_withdraw.safi == SAFI_UNICAST)
	nlri_parse (peer, NULL, &mp_withdraw);
    }
  if (peer->afc[AFI_IP6][SAFI_MULTICAST])
    {
      if (mp_update.length 
	  && mp_update.afi == AFI_IP6 
	  && mp_update.safi == SAFI_MULTICAST)
	nlri_parse (peer, &attr, &mp_update);

      if (mp_withdraw.length 
	  && mp_withdraw.afi == AFI_IP6 
	  && mp_withdraw.safi == SAFI_MULTICAST)
	nlri_parse (peer, NULL, &mp_withdraw);
    }
  if (peer->afc[AFI_IP][SAFI_MPLS_VPN])
    {
      if (mp_update.length 
	  && mp_update.afi == AFI_IP 
	  && mp_update.safi == BGP_SAFI_VPNV4)
	nlri_parse_vpnv4 (peer, &attr, &mp_update);

      if (mp_withdraw.length 
	  && mp_withdraw.afi == AFI_IP 
	  && mp_withdraw.safi == BGP_SAFI_VPNV4)
	nlri_parse_vpnv4 (peer, NULL, &mp_withdraw);
    }

  /* Everything is done.  We unintern temporary structures which
     interned in bgp_attr_parse(). */
  if (attr.aspath)
    aspath_unintern (attr.aspath);
  if (attr.community)
    community_unintern (attr.community);
  if (attr.cluster)
    cluster_unintern (attr.cluster);

  /* If peering is stopped due to some reason, do not generate BGP
     event.  */
  if (peer->status != Established)
    return 0;

  /* Increment packet counter. */
  peer->update_in++;

  /* Generate BGP event. */
  BGP_EVENT_ADD (peer, Receive_UPDATE_message);

  return 0;
}

/* Notify message treatment function. */
void
bgp_notify_receive (struct peer *peer, bgp_size_t size)
{
  struct bgp_notify bgp_notify;

  if (peer->notify.data)
    {
      XFREE (MTYPE_TMP, peer->notify.data);
      peer->notify.data = NULL;
      peer->notify.length = 0;
    }

  bgp_notify.code = stream_getc (peer->ibuf);
  bgp_notify.subcode = stream_getc (peer->ibuf);

  bgp_notify_print(peer, &bgp_notify, "RECV");

  /* We have to check for Notify with Unsupported Optional Parameter.
     in that case we fallback to open without the capability option.
     But this done in bgp_stop. We just mark it here to avoid changing
     the fsm tables.  */
  if (bgp_notify.code == BGP_NOTIFY_OPEN_ERR &&
      bgp_notify.subcode == BGP_NOTIFY_OPEN_UNSUP_PARAM )
    UNSET_FLAG (peer->sflags, PEER_STATUS_CAPABILITY_OPEN);

  /* Also apply to Unsupported Capability until remote router support
     capability. */
  if (bgp_notify.code == BGP_NOTIFY_OPEN_ERR &&
      bgp_notify.subcode == BGP_NOTIFY_OPEN_UNSUP_CAPBL)
    {
      UNSET_FLAG (peer->sflags, PEER_STATUS_CAPABILITY_OPEN);

      /* For further diagnostic record returned Data. */
      if (size > 2)
	{
	  peer->notify.code = bgp_notify.code;
	  peer->notify.subcode = bgp_notify.subcode;
	  peer->notify.length = size - 2;
	  peer->notify.data = XMALLOC (MTYPE_TMP, size - 2);
	  memcpy (peer->notify.data, stream_pnt (peer->ibuf), size - 2);
	}
    }

  BGP_EVENT_ADD (peer, Receive_NOTIFICATION_message);
}

/* Keepalive treatment function -- get keepalive send keepalive */
void
bgp_keepalive_receive (struct peer *peer, bgp_size_t size)
{
  BGP_EVENT_ADD (peer, Receive_KEEPALIVE_message);
}

/* Route refresh message is received. */
void
bgp_route_refresh_receive (struct peer *peer, bgp_size_t size)
{
  afi_t afi;
  safi_t safi;
  u_char reserved;

  /* If peer does not have the capability, send notification. */
  if (! peer->refresh)
    {
      plog_err (peer->log, "%s [Error] BGP route refresh is not enabled",
		peer->host);
      bgp_notify_send (peer,
		       BGP_NOTIFY_HEADER_ERR,
		       BGP_NOTIFY_HEADER_BAD_MESTYPE);
      return;
    }

  /* Status must be Established. */
  if (peer->status != Established) 
    {
      plog_err (peer->log,
		"%s [Error] Route refresh packet received under status %s",
		peer->host, LOOKUP (bgp_status_msg, peer->status));
      bgp_notify_send (peer, BGP_NOTIFY_FSM_ERR, 0);
      return;
    }

  /* Packet size of already check in bgp_read (). */
  
  /* Parse packet. */
  afi = stream_getw (peer->ibuf);
  reserved = stream_getc (peer->ibuf);
  safi = stream_getc (peer->ibuf);

  /* Check AFI and SAFI. */
  if (afi != AFI_IP && afi != AFI_IP6)
    {
      plog_err (peer->log,
		"%s [Error] Unknown AFI %d route refresh",
		peer->host, afi);
      bgp_notify_send (peer, BGP_NOTIFY_CEASE, 0);
      return;
    }
  if (safi != SAFI_UNICAST && safi != SAFI_MULTICAST)
    {
      plog_err (peer->log,
		"%s [Error] Unknown SAFI %d route refresh", safi);
      bgp_notify_send (peer, BGP_NOTIFY_CEASE, 0);
      return;
    }

  /* Perform route refreshment to the peer */
  bgp_announce_table (peer);
}

/* BGP read utility function. */
int
bgp_read_packet (struct peer *peer, bgp_size_t size)
{
  int nbytes;

  /* If size is zero then return. */
  if (! size)
    return 0;

  /* Read packet from fd. */
  nbytes = stream_read (peer->ibuf, peer->fd, size);

  /* If read byte is smaller than zero then error occured. */
  if (nbytes < 0) 
    {
      plog_err (peer->log, "%s [Error] bgp_read_packet error: %s",
		 peer->host, strerror (errno));
      BGP_EVENT_ADD (peer, TCP_fatal_error);
      return -1;
    }  

  /* When read byte is zero : clear bgp peer and return */
  if (nbytes == 0) 
    {
      plog_info (peer->log, "%s [Event] BGP connection closed fd %d",
		 peer->host, peer->fd);
      BGP_EVENT_ADD (peer, TCP_connection_closed);
      return -1;
    }

  /* If header size is defferent print warning and return */
  if (nbytes != size) 
    {
      plog_err (peer->log,
		"%s [Error] bgp_read can't read all of packet %d/%d : %s",
		peer->host, size, nbytes, strerror (errno));
      BGP_EVENT_ADD (peer, TCP_fatal_error);
      return -1;
    }
  return 0;
}

/* Starting point of packet process function. */
int
bgp_read (struct thread *thread)
{
  int ret;
  u_char type;
  struct peer *peer;
  bgp_size_t size;

  /* Yes first of all get peer pointer. */
  peer = THREAD_ARG (thread);
  peer->t_read = NULL;

  /* For non-blocking IO check. */
  if (peer->status == Connect)
    {
      bgp_connect_check (peer);
      goto done;
    }
  else
    BGP_READ_ON (peer->t_read, bgp_read, peer->fd);

  /* Clear input buffer. */
  stream_reset (peer->ibuf);

  /* Read packet header to determin type of the packet */
  ret = bgp_read_packet (peer, BGP_HEADER_SIZE);

  /* Header read error. */
  if (ret < 0) 
    goto done;

  /* Get size and type. */
  stream_forward (peer->ibuf, BGP_MARKER_SIZE);
  size = stream_getw (peer->ibuf);
  type = stream_getc (peer->ibuf);

  /* BGP type check. */
  if (type != BGP_MSG_OPEN && type != BGP_MSG_UPDATE 
      && type != BGP_MSG_NOTIFY && type != BGP_MSG_KEEPALIVE 
      && type != BGP_MSG_ROUTE_REFRESH)
    {
      plog_err (peer->log,
		"%s [Error] Unknown BGP packet type %d received",
		peer->host, type);
      bgp_notify_send (peer,
		       BGP_NOTIFY_HEADER_ERR,
		       BGP_NOTIFY_HEADER_BAD_MESTYPE);
      goto done;
    }
  /* Mimimum packet length check. */
  if ((size < BGP_HEADER_SIZE)
      || (size > BGP_MAX_PACKET_SIZE)
      || (type == BGP_MSG_OPEN && size < BGP_MSG_OPEN_MIN_SIZE)
      || (type == BGP_MSG_UPDATE && size < BGP_MSG_UPDATE_MIN_SIZE)
      || (type == BGP_MSG_NOTIFY && size < BGP_MSG_NOTIFY_MIN_SIZE)
      || (type == BGP_MSG_KEEPALIVE && size != BGP_MSG_KEEPALIVE_MIN_SIZE)
      || (type == BGP_MSG_ROUTE_REFRESH && size != BGP_MSG_ROUTE_REFRESH_MIN_SIZE))
    {
      plog_err (peer->log,
		"%s [Error] Bad BGP message length %d for BGP type %s",
		peer->host, size, bgp_type_str[type]);
      bgp_notify_send (peer,
		       BGP_NOTIFY_HEADER_ERR,
		       BGP_NOTIFY_HEADER_BAD_MESLEN);
      goto done;
    }

  /* Adjust size to message length. */
  size -= BGP_HEADER_SIZE;

  ret = bgp_read_packet (peer, size);
  if (ret < 0) 
    goto done;

  /* BGP packet dump function. */
  bgp_dump_packet (peer, type, peer->ibuf);
  
  /* Read rest of the packet and call each sort of packet routine */
  switch (type) 
    {
    case BGP_MSG_OPEN:
      bgp_open_receive (peer, size);
      break;
    case BGP_MSG_UPDATE:
      bgp_update_receive (peer, size);
      break;
    case BGP_MSG_NOTIFY:
      bgp_notify_receive (peer, size);
      break;
    case BGP_MSG_KEEPALIVE:
      bgp_keepalive_receive (peer, size);
      break;
    case BGP_MSG_ROUTE_REFRESH:
      bgp_route_refresh_receive (peer, size);
      break;
    }

 done:
  if (CHECK_FLAG (peer->sflags, PEER_STATUS_ACCEPT_PEER))
    {
      zlog_info ("%s [Event] Accepting BGP peer delete", peer->host);
      peer_delete (peer);
    }
  return 0;
}
