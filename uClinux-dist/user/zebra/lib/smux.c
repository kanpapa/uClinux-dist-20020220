/* SNMP support
 * Copyright (C) 1999 Kunihiro Ishiguro <kunihiro@zebra.org>
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

#ifdef HAVE_SNMP

#include <asn1.h>
#include <snmp.h>
#include <snmp_impl.h>

#include "smux.h"
#include "log.h"
#include "thread.h"
#include "vector.h"
#include "command.h"
#include "version.h"
#include "memory.h"
#include "sockunion.h"

#define min(A,B) ((A) < (B) ? (A) : (B))

enum smux_event {SMUX_SCHEDULE, SMUX_CONNECT, SMUX_READ};

void smux_event (enum smux_event, int);


/* SMUX socket. */
int sock = -1;

/* SMUX subtree vector. */
vector treevec;

/* SMUX oid. */
oid *smux_oid;
size_t smux_oid_len;

/* SMUX default oid. */
oid *smux_default_oid;
size_t smux_default_oid_len;

/* SMUX password. */
char *smux_passwd;
char *smux_default_passwd = "";

/* SMUX read threads. */
struct thread *smux_read_thread;

/* SMUX connect thrads. */
struct thread *smux_connect_thread;

/* SMUX debug flag. */
int debug_smux = 1;

/* SMUX failure count. */
int fail = 0;

void *
oid_copy (void *dest, void *src, size_t size)
{
  return memcpy (dest, src, size * sizeof (oid));
}

void
oid2in_addr (oid oid[], int len, struct in_addr *addr)
{
  int i;
  u_char *pnt;
  
  if (len == 0)
    return;

  pnt = (u_char *) addr;

  for (i = 0; i < len; i++)
    *pnt++ = oid[i];
}

void
oid_copy_addr (oid oid[], struct in_addr *addr, int len)
{
  int i;
  u_char *pnt;
  
  if (len == 0)
    return;

  pnt = (u_char *) addr;

  for (i = 0; i < len; i++)
    oid[i] = *pnt++;
}

int
oid_compare (oid *o1, int o1_len, oid *o2, int o2_len)
{
  int i;

  for (i = 0; i < min (o1_len, o2_len); i++)
    {
      if (o1[i] < o2[i])
	return -1;
      else if (o1[i] > o2[i])
	return 1;
    }
  if (o1_len < o2_len)
    return -1;
  if (o1_len > o2_len)
    return 1;

  return 0;
}

int
oid_compare_part (oid *o1, int o1_len, oid *o2, int o2_len)
{
  int i;

  for (i = 0; i < min (o1_len, o2_len); i++)
    {
      if (o1[i] < o2[i])
	return -1;
      else if (o1[i] > o2[i])
	return 1;
    }
  if (o1_len < o2_len)
    return -1;

  return 0;
}

void
smux_oid_dump (char *prefix, oid *oid, size_t oid_len)
{
  int i;
  int first = 1;
  char buf[MAX_OID_LEN * 3];

  buf[0] = '\0';

  for (i = 0; i < oid_len; i++)
    {
      sprintf (buf + strlen (buf), "%s%d", first ? "" : ".", (int) oid[i]);
      first = 0;
    }
  zlog_info ("%s: %s", prefix, buf);
}

int
smux_sock ()
{
  int ret;
  struct sockaddr_in serv;
  struct servent *sp;
  
  sock = socket (AF_INET, SOCK_STREAM, 0);
  if (sock < 0)
    {
      zlog_warn ("Can't make socket for SNMP");
      return -1;
    }

  memset (&serv, 0, sizeof (struct sockaddr_in));
  serv.sin_family = AF_INET;
#ifdef HAVE_SIN_LEN
  serv.sin_len = sizeof (struct sockaddr_in);
#endif /* HAVE_SIN_LEN */

  sp = getservbyname ("smux", "tcp");
  if (sp != NULL) 
    serv.sin_port = sp->s_port;
  else
    serv.sin_port = htons (SMUX_PORT_DEFAULT);

  serv.sin_addr.s_addr = htonl (INADDR_LOOPBACK);

  sockopt_reuseaddr (sock);
  sockopt_reuseport (sock);

  ret = connect (sock, (struct sockaddr *) &serv, sizeof (struct sockaddr_in));
  if (ret < 0)
    {
      close (sock);
      zlog_warn ("Can't connect to SNMP agent with SMUX");
      return -1;
    }
  return sock;
}

void
smux_getresp_send (oid objid[], size_t objid_len, long reqid, long errstat,
		   long errindex, u_char val_type, void *arg, size_t arg_len)
{
  int ret;
  u_char buf[BUFSIZ];
  u_char *ptr, *h1, *h1e, *h2, *h2e;
  int len, length;

  ptr = buf;
  len = BUFSIZ;
  length = len;

  if (debug_smux)
    {
      zlog_info ("SMUX GETRSP send");
      zlog_info ("SMUX GETRSP reqid: %d", reqid);
    }

  h1 = ptr;
  /* Place holder h1 for complete sequence */
  ptr = asn_build_sequence (ptr, &len, (u_char) SMUX_GETRSP, 0);
  h1e = ptr;
 
  ptr = asn_build_int (ptr, &len,
		       (u_char) (ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		       &reqid, sizeof (reqid));

  if (debug_smux)
    zlog_info ("SMUX GETRSP errstat: %d", errstat);

  ptr = asn_build_int (ptr, &len,
		       (u_char) (ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		       &errstat, sizeof (errstat));
  if (debug_smux)
    zlog_info ("SMUX GETRSP errindex: %d", errindex);

  ptr = asn_build_int (ptr, &len,
		       (u_char) (ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		       &errindex, sizeof (errindex));

  h2 = ptr;
  /* Place holder h2 for one variable */
  ptr = asn_build_sequence (ptr, &len, 
			   (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR),
			   0);
  h2e = ptr;

  ptr = snmp_build_var_op (ptr, objid, &objid_len, 
			   val_type, arg_len, arg, &len);

  /* Now variable size is known, fill in size */
  asn_build_sequence(h2,&length,(u_char)(ASN_SEQUENCE|ASN_CONSTRUCTOR),ptr-h2e);

  /* Fill in size of whole sequence */
  asn_build_sequence(h1,&length,(u_char)SMUX_GETRSP,ptr-h1e);

  if (debug_smux)
    zlog_info ("SMUX getresp send: %d", ptr - buf);
  
  ret = send (sock, buf, (ptr - buf), 0);
}

char *
smux_var (char *ptr, int len, oid objid[], size_t *objid_len)
{
  u_char type;
  u_char val_type;
  size_t val_len;
  u_char *val;

  if (debug_smux)
    zlog_info ("SMUX var parse: len %d", len);

  /* Parse header. */
  ptr = asn_parse_header (ptr, &len, &type);
  
  if (debug_smux)
    {
      zlog_info ("SMUX var parse: type %d len %d", type, len);
      zlog_info ("SMUX var parse: type must be %d", 
		 (ASN_SEQUENCE | ASN_CONSTRUCTOR));
    }

  /* Parse var option. */
  *objid_len = MAX_OID_LEN;
  ptr = snmp_parse_var_op(ptr, objid, objid_len, &val_type, 
			  &val_len, &val, &len);

  /* Requested object id length is objid_len. */
  if (debug_smux)
    smux_oid_dump ("Request OID", objid, *objid_len);

  if (debug_smux)
    zlog_info ("SMUX val_type: %d", val_type);

  /* Check request value type. */
  switch (val_type)
    {
    case ASN_NULL:
      /* In case of SMUX_GET or SMUX_GET_NEXT val_type is set to
         ASN_NULL. */
      zlog_info ("ASN_NULL");
      break;

    case ASN_INTEGER:
      zlog_info ("ASN_INTEGER");
      break;
    case ASN_COUNTER:
    case ASN_GAUGE:
    case ASN_TIMETICKS:
    case ASN_UINTEGER:
      zlog_info ("ASN_COUNTER");
      break;
    case ASN_COUNTER64:
      zlog_info ("ASN_COUNTER64");
      break;
    case ASN_IPADDRESS:
      zlog_info ("ASN_IPADDRESS");
      break;
    case ASN_OCTET_STR:
      zlog_info ("ASN_OCTET_STR");
      break;
    case ASN_OPAQUE:
    case ASN_NSAP:
    case ASN_OBJECT_ID:
      zlog_info ("ASN_OPAQUE");
      break;
    case SNMP_NOSUCHOBJECT:
      zlog_info ("SNMP_NOSUCHOBJECT");
      break;
    case SNMP_NOSUCHINSTANCE:
      zlog_info ("SNMP_NOSUCHINSTANCE");
      break;
    case SNMP_ENDOFMIBVIEW:
      zlog_info ("SNMP_ENDOFMIBVIEW");
      break;
    case ASN_BIT_STR:
      zlog_info ("ASN_BIT_STR");
      break;
    default:
      zlog_info ("Unknown type");
      break;
    }
  return ptr;
}

/* exact version. */
int
smux_get (oid *reqid, size_t *reqid_len, int exact, 
	  u_char *val_type,void **val, size_t *val_len)
{
  int i, j;
  struct subtree *subtree;
  struct variable *v;
  int subresult;
  oid *suffix;
  int suffix_len;
  int result;
  WriteMethod *write_method=NULL;

  /* Check */
  for (i = 0; i < vector_max (treevec); i++)
    {
      subtree = vector_slot (treevec, i);
      subresult = oid_compare_part (reqid, *reqid_len, 
				    subtree->name, subtree->name_len);

      /* Subtree matched. */
      if (subresult == 0)
	{
	  /* Prepare suffix. */
	  suffix = reqid + subtree->name_len;
	  suffix_len = *reqid_len - subtree->name_len;
	  result = subresult;

	  /* Check variables. */
	  for (j = 0; j < subtree->variables_num; j++)
	    {
	      v = &subtree->variables[j];

	      /* Always check suffix */
	      result = oid_compare_part (suffix, suffix_len,
					 v->name, v->namelen);

	      /* This is exact match so result must be zero. */
	      if (result == 0)
		{
		  if (debug_smux)
		    zlog_info ("SMUX function call index is %d", v->magic);

		  *val = (*v->findVar) (v, suffix, &suffix_len, exact,
		    val_len, &write_method);

		  /* There is no instance. */
		  if (*val == NULL)
		    return SNMP_NOSUCHINSTANCE;

		  /* Call is suceed. */
		  *val_type = v->type;

		  return 0;
		}

	      /* If above execution is failed or oid is small (so
                 there is no further match). */
	      if (result < 0)
		return SNMP_NOSUCHOBJECT;
	    }
	}
    }
  return SNMP_NOSUCHOBJECT;
}

int
smux_getnext (oid *reqid, size_t *reqid_len, int exact, 
		 u_char *val_type,void **val, size_t *val_len)
{
  int i, j;
  oid save[MAX_OID_LEN];
  int savelen = 0;
  struct subtree *subtree;
  struct variable *v;
  int subresult;
  oid *suffix;
  int suffix_len;
  int result;
  WriteMethod *write_method=NULL;

  /* Save incoming request. */
  oid_copy (save, reqid, *reqid_len);
  savelen = *reqid_len;

  /* Check */
  for (i = 0; i < vector_max (treevec); i++)
    {
      subtree = vector_slot (treevec, i);

      subresult = oid_compare_part (reqid, *reqid_len, 
				    subtree->name, subtree->name_len);

      /* If request is in the tree. The agent has to make sure we
         only receive requests we have registered for. */
      if (subresult == 0)
	{

	  /* Prepare suffix. */
	  suffix = reqid + subtree->name_len;
	  suffix_len = *reqid_len - subtree->name_len;
	  result = subresult;

	  for (j = 0; j < subtree->variables_num; j++)
	    {
	      v = &subtree->variables[j];

	      /* Next then check result >= 0. */
	      if (result >= 0)
		result = oid_compare_part (suffix, suffix_len,
					   v->name, v->namelen);

	      if (result <= 0)
		{
		  if (debug_smux)
		    zlog_info ("SMUX function call index is %d", v->magic);
		  if(result<0)
		    {
		      oid_copy(suffix, v->name, v->namelen);
		      suffix_len = v->namelen;
		    }
		  *val = (*v->findVar) (v, suffix, &suffix_len, exact,
		    val_len, &write_method);
		  *reqid_len = suffix_len + subtree->name_len;
		  if (*val)
		    {
		      *val_type = v->type;
		      return 0;
		    }
		}
	    }
	}
    }
  memcpy (reqid, save, savelen * sizeof(oid));
  *reqid_len = savelen;

  return SNMP_NOSUCHOBJECT;
}

/* GET message header. */
char *
smux_parse_get_header (char *ptr, size_t *len, long *reqid)
{
  u_char type;
  long errstat;
  long errindex;

  /* Request ID. */
  ptr = asn_parse_int (ptr, len, &type, reqid, sizeof (*reqid));

  if (debug_smux)
    zlog_info ("SMUX GET reqid: %d len: %d", reqid, *len);

  /* Error status. */
  ptr = asn_parse_int (ptr, len, &type, &errstat, sizeof (errstat));

  if (debug_smux)
    zlog_info ("SMUX GET errstat %d len: %d", errstat, *len);

  /* Error index. */
  ptr = asn_parse_int (ptr, len, &type, &errindex, sizeof (errindex));

  if (debug_smux)
    zlog_info ("SMUX GET errindex %d len: %d", errindex, *len);

  return ptr;
}

void
smux_parse_get (char *ptr, size_t len, int exact)
{
  long reqid;
  oid oid[MAX_OID_LEN];
  size_t oid_len;
  u_char val_type;
  void *val;
  size_t val_len;
  int ret;

  if (debug_smux)
    zlog_info ("SMUX GET message parse: len %d", len);
  
  /* Parse GET message header. */
  ptr = smux_parse_get_header (ptr, &len, &reqid);
  
  /* Parse GET message object ID. */
  ptr = smux_var (ptr, len, oid, &oid_len);

  /* Traditional getstatptr. */
  if (exact)
    ret = smux_get (oid, &oid_len, exact, &val_type, &val, &val_len);
  else
    ret = smux_getnext (oid, &oid_len, exact, &val_type, &val, &val_len);

  /* Return result. */
  if (ret == 0)
    smux_getresp_send (oid, oid_len, reqid, 0, 0, val_type, val, val_len);
  else
    smux_getresp_send (oid, oid_len, reqid, ret, 3, ASN_NULL, NULL, 0);
}

/* Parse SMUX_CLOSE message. */
void
smux_parse_close (char *ptr, int len)
{
  long reason = 0;

  while (len--)
    {
      reason = (reason << 8) | (long) *ptr;
      ptr++;
    }
  zlog_info ("SMUX_CLOSE with reason: %d", reason);
}

/* SMUX_RRSP message. */
void
smux_parse_rrsp (char *ptr, int len)
{
  char val;
  long errstat;
  
  ptr = asn_parse_int (ptr, &len, &val, &errstat, sizeof (errstat));

  if (debug_smux)
    zlog_info ("SMUX_RRSP value: %d errstat: %d", val, errstat);
}

/* Parse SMUX message. */
int
smux_parse (char *ptr, int len)
{
  u_char type;

  /* Parse SMUX message type and subsequent length. */
  ptr = asn_parse_header (ptr, &len, &type);

  if (debug_smux)
    zlog_info ("SMUX message received type: %d rest len: %d", type, len);

  switch (type)
    {
    case SMUX_OPEN:
      /* Open must be not send from SNMP agent. */
      zlog_warn ("SMUX_OPEN received: resetting connection.");
      return -1;
      break;
    case SMUX_RREQ:
      /* SMUX_RREQ message is invalied for us. */
      zlog_warn ("SMUX_RREQ received: resetting connection.");
      return -1;
      break;
    case SMUX_SOUT:
      /* SMUX_SOOUT message is invalied for us. */
      zlog_warn ("SMUX_SOUT received: resetting connection.");
      return -1;
      break;
    case SMUX_GETRSP:
      /* SMUX_GETRSP message is invalied for us. */
      zlog_warn ("SMUX_GETRSP received: resetting connection.");
      return -1;
      break;
    case SMUX_CLOSE:
      /* Close SMUX connection. */
      if (debug_smux)
	zlog_info ("SMUX_CLOSE");
      smux_parse_close (ptr, len);
      return -1;
      break;
    case SMUX_RRSP:
      /* This is responce for register message. */
      if (debug_smux)
	zlog_info ("SMUX_RRSP");
      smux_parse_rrsp (ptr, len);
      break;
    case SMUX_GET:
      /* Exaxt request for object id. */
      if (debug_smux)
	zlog_info ("SMUX_GET");
      smux_parse_get (ptr, len, 1);
      break;
    case SMUX_GETNEXT:
      /* NExt request for object id. */
      if (debug_smux)
	zlog_info ("SMUX_GETNEXT");
      smux_parse_get (ptr, len, 0);
      break;
    case SMUX_SET:
      /* SMUX_SET is not yet supported. */
      if (debug_smux)
	zlog_info ("SMUX_SET is not yet supported sorry.");
      break;
    default:
      zlog_info ("Unknown type: %d", type);
      break;
    }
  return 0;
}

/* SMUX message read function. */
int
smux_read (struct thread *t)
{
  int sock;
  int len;
  u_char buf[SMUXMAXPKTSIZE];
  int ret;

  /* Clear thread. */
  sock = THREAD_FD (t);
  smux_read_thread = NULL;

  if (debug_smux)
    zlog_info ("SMUX read start");

  /* Read message from SMUX socket. */
  len = recv (sock, buf, SMUXMAXPKTSIZE, 0);

  if (len < 0)
    {
      zlog_warn ("Can't read all SMUX packet: %s", strerror (errno));
      close (sock);
      smux_event (SMUX_CONNECT, 0);
      return -1;
    }

  if (len == 0)
    {
      zlog_warn ("SMUX connection closed: %d", sock);
      close (sock);
      smux_event (SMUX_CONNECT, 0);
      return -1;
    }

  if (debug_smux)
    zlog_info ("SMUX read len: %d", len);

  /* Parse the message. */
  ret = smux_parse (buf, len);

  if (ret < 0)
    {
      close (sock);
      smux_event (SMUX_CONNECT, 0);
      return -1;
    }

  /* Regiser read thread. */
  smux_event (SMUX_READ, sock);

  return 0;
}

int
smux_open (int sock)
{
  u_char buf[BUFSIZ];
  u_char *ptr;
  int len;
  u_long version;
  u_char progname[] = "zebra-" ZEBRA_VERSION;

  if (debug_smux)
    {
      smux_oid_dump ("SMUX open oid", smux_oid, smux_oid_len);
      zlog_info ("SMUX open progname: %s", progname);
      zlog_info ("SMUX open password: %s", smux_passwd);
    }

  ptr = buf;
  len = BUFSIZ;

  /* SMUX Header.  As placeholder. */
  ptr = asn_build_header (ptr, &len, (u_char) SMUX_OPEN, 0);

  /* SMUX Open. */
  version = 0;
  ptr = asn_build_int (ptr, &len, 
		       (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		       &version, sizeof (u_long));

  /* SMUX connection oid. */
  ptr = asn_build_objid (ptr, &len,
			 (u_char) 
			 (ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OBJECT_ID),
			 smux_oid, smux_oid_len);

  /* SMUX connection description. */
  ptr = asn_build_string (ptr, &len, 
			  (u_char)
			  (ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OCTET_STR),
			  progname, strlen (progname));

  /* SMUX connection password. */
  ptr = asn_build_string (ptr, &len, 
			  (u_char)
			  (ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OCTET_STR),
			  smux_passwd, strlen (smux_passwd));

  /* Fill in real SMUX header.  We exclude ASN header size (2). */
  len = BUFSIZ;
  asn_build_header (buf, &len, (u_char) SMUX_OPEN, (ptr - buf) - 2);

  return send (sock, buf, (ptr - buf), 0);
}

int
smux_register (int sock)
{
  u_char buf[BUFSIZ];
  u_char *ptr;
  int len, i, ret;
  long priority;
  long operation;
  struct subtree *subtree;

  ptr = buf;
  len = BUFSIZ;
  ret = 0;

  for (i = 0; i < vector_max (treevec); i++)
    {
      subtree = vector_slot (treevec, i);

      /* SMUX RReq Header. */
      ptr = asn_build_header (ptr, &len, (u_char) SMUX_RREQ, 0);

      /* Register MIB tree. */
      ptr = asn_build_objid (ptr, &len,
			    (u_char)
			    (ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OBJECT_ID),
			    subtree->name, subtree->name_len);

      /* Priority. */
      priority = -1;
      ptr = asn_build_int (ptr, &len, 
		          (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		          &priority, sizeof (u_long));

      /* Operation. */
      operation = 1;
      ptr = asn_build_int (ptr, &len, 
		          (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		          &operation, sizeof (u_long));

      if (debug_smux)
        {
          smux_oid_dump ("SMUX register oid", subtree->name, subtree->name_len);
          zlog_info ("SMUX register priority: %d", priority);
          zlog_info ("SMUX register operation: %d", operation);
        }

      len = BUFSIZ;
      asn_build_header (buf, &len, (u_char) SMUX_RREQ, (ptr - buf) - 2);
      ret = send (sock, buf, (ptr - buf), 0);
      if (ret < 0)
        return ret;
    }
  return ret;
}

/* Try to connect to SNMP agent. */
int
smux_connect (struct thread *t)
{
  int ret;
  int sock;

  if (debug_smux)
    zlog_info ("SMUX connect try %d", fail + 1);

  /* Clear thread poner of myself. */
  smux_connect_thread = NULL;

  /* Make socket.  Try to connect. */
  sock = smux_sock ();
  if (sock < 0)
    {
      if (++fail < SMUX_MAX_FAILURE)
	smux_event (SMUX_CONNECT, 0);
      return 0;
    }

  /* Send OPEN PDU. */
  ret = smux_open (sock);
  if (ret < 0)
    {
      zlog_warn ("SMUX open message send failed: %s", strerror (errno));
      close (sock);
      smux_event (SMUX_CONNECT, 0);
      return -1;
    }

  /* Send any outstanding register PDUs. */
  ret = smux_register (sock);
  if (ret < 0)
    {
      zlog_warn ("SMUX register message send failed: %s", strerror (errno));
      close (sock);
      smux_event (SMUX_CONNECT, 0);
      return -1;
    }

  /* Everything goes fine. */
  smux_event (SMUX_READ, sock);

  return 0;
}

/* Clear all SMUX related resources. */
void
smux_stop ()
{
  if (smux_read_thread)
    thread_cancel (smux_read_thread);
  if (smux_connect_thread)
    thread_cancel (smux_connect_thread);

  if (sock >= 0)
    close (sock);
}

extern struct thread_master *master;

void
smux_event (enum smux_event event, int sock)
{
  switch (event)
    {
    case SMUX_SCHEDULE:
      smux_connect_thread = thread_add_event (master, smux_connect, NULL, 0);
      break;
    case SMUX_CONNECT:
      smux_connect_thread = thread_add_timer (master, smux_connect, NULL, 10);
      break;
    case SMUX_READ:
      smux_read_thread = thread_add_read (master, smux_read, NULL, sock);
      break;
    default:
      break;
    }
}

int
smux_str2oid (char *str, oid *oid, size_t *oid_len)
{
  int len;
  int val;

  len = 0;
  val = 0;
  *oid_len = 0;

  if (*str == '.')
    str++;
  if (*str == '\0')
    return 0;

  while (1)
    {
      if (! isdigit (*str))
	return -1;

      while (isdigit (*str))
	{
	  val *= 10;
	  val += (*str - '0');
	  str++;
	}

      if (*str == '\0')
	break;
      if (*str != '.')
	return -1;

      oid[len++] = val;
      val = 0;
      str++;
    }

  oid[len++] = val;
  *oid_len = len;

  return 0;
}

oid *
smux_oid_dup (oid *objid, size_t objid_len)
{
  oid *new;

  new = XMALLOC (MTYPE_TMP, sizeof (oid) * objid_len);
  oid_copy (new, objid, objid_len);

  return new;
}

int
smux_peer_oid (struct vty *vty, char *oid_str, char *passwd_str)
{
  int ret;
  oid oid[MAX_OID_LEN];
  size_t oid_len;

  ret = smux_str2oid (oid_str, oid, &oid_len);
  if (ret != 0)
    {
      vty_out (vty, "object ID malformed%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (smux_oid && smux_oid != smux_default_oid)
    free (smux_oid);

  if (smux_passwd && smux_passwd != smux_default_passwd)
    {
      free (smux_passwd);
      smux_passwd = NULL;
    }

  smux_oid = smux_oid_dup (oid, oid_len);
  smux_oid_len = oid_len;

  if (passwd_str)
    smux_passwd = strdup (passwd_str);

  return CMD_SUCCESS;
}

int
smux_header_generic (struct variable *v, oid *name, size_t *length, int exact,
		 size_t *var_len, WriteMethod **write_method)
{
  oid fulloid[MAX_OID_LEN];
  int ret;

  oid_copy (fulloid, v->name, v->namelen);
  fulloid[v->namelen] = 0;
  /* Check against full instance. */
  ret = oid_compare (name, *length, fulloid, v->namelen + 1);

  /* Check single instance. */
  if ((exact && (ret != 0)) || (!exact && (ret >= 0)))
	return MATCH_FAILED;

  /* In case of getnext, fill in full instance. */
  memcpy (name, fulloid, (v->namelen + 1) * sizeof (oid));
  *length = v->namelen + 1;

  *write_method = 0;
  *var_len = sizeof(long);    /* default to 'long' results */

  return MATCH_SUCCEEDED;
}

int
smux_peer_default ()
{
  if (smux_oid != smux_default_oid)
    {
      free (smux_oid);
      smux_oid = smux_default_oid;
      smux_oid_len = smux_default_oid_len;
    }
  if (smux_passwd != smux_default_passwd)
    {
      free (smux_passwd);
      smux_passwd = smux_default_passwd;
    }
  return CMD_SUCCESS;
}

DEFUN (smux_peer,
       smux_peer_cmd,
       "smux peer OID",
       "SNMP MUX protocol settings\n"
       "SNMP MUX peer settings\n"
       "Object ID used in SMUX peering\n")
{
  return smux_peer_oid (vty, argv[0], NULL);
}

DEFUN (smux_peer_password,
       smux_peer_password_cmd,
       "smux peer OID PASSWORD",
       "SNMP MUX protocol settings\n"
       "SNMP MUX peer settings\n"
       "SMUX peering object ID\n"
       "SMUX peering password\n")
{
  return smux_peer_oid (vty, argv[0], argv[1]);
}

DEFUN (no_smux_peer,
       no_smux_peer_cmd,
       "no smux peer OID",
       NO_STR
       "SNMP MUX protocol settings\n"
       "SNMP MUX peer settings\n"
       "Object ID used in SMUX peering\n")
{
  return smux_peer_default ();
}

DEFUN (no_smux_peer_password,
       no_smux_peer_password_cmd,
       "no smux peer OID PASSWORD",
       NO_STR
       "SNMP MUX protocol settings\n"
       "SNMP MUX peer settings\n"
       "SMUX peering object ID\n"
       "SMUX peering password\n")
{
  return smux_peer_default ();
}

int
config_write_smux (struct vty *vty)
{
  if (smux_oid != smux_default_oid || smux_passwd != smux_default_passwd)
    {
      vty_out (vty, "smux peer %s %s%s", smux_oid, smux_passwd, VTY_NEWLINE);
      return 1;
    }
  return 0;
}

/* Register subtree to smux master tree. */
void
smux_register_mib(char *descr, struct variable *var, size_t width, int num, 
		  oid name[], size_t namelen)
{
  struct subtree *tree;

  tree = (struct subtree *)malloc(sizeof(struct subtree));
  oid_copy (tree->name, name, namelen);
  tree->name_len = namelen;
  tree->variables = var;
  tree->variables_num = num;
  tree->variables_width = width;
  tree->registered = 0;
  vector_set (treevec, tree);
}

void
smux_reset ()
{
  /* Setting configuration to default. */
  smux_peer_default ();
}

/* Initialize some values then schedule first SMUX connection. */
void
smux_init (oid defoid[], size_t defoid_len)
{
  /* Set default SMUX oid. */
  smux_default_oid = defoid;
  smux_default_oid_len = defoid_len;

  smux_oid = smux_default_oid;
  smux_oid_len = smux_default_oid_len;
  smux_passwd = smux_default_passwd;
  
  /* Make MIB tree. */
  treevec = vector_init (VECTOR_MIN_SIZE);

  /* Install commands. */
  install_element (CONFIG_NODE, &smux_peer_cmd);
  install_element (CONFIG_NODE, &smux_peer_password_cmd);
  install_element (CONFIG_NODE, &no_smux_peer_cmd);
  install_element (CONFIG_NODE, &no_smux_peer_password_cmd);
}

void
smux_start(void)
{
  /* Schedule first connection. */
  smux_event (SMUX_SCHEDULE, 0);
}
#endif /* HAVE_SNMP */
