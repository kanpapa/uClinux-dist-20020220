/*
 * snmptrap.c - send snmp traps to a network entity.
 *
 */
/******************************************************************
	Copyright 1989, 1991, 1992 by Carnegie Mellon University

                      All Rights Reserved

Permission to use, copy, modify, and distribute this software and its
documentation for any purpose and without fee is hereby granted,
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in
supporting documentation, and that the name of CMU not be
used in advertising or publicity pertaining to distribution of the
software without specific, written prior permission.

CMU DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
CMU BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
SOFTWARE.
******************************************************************/
#include <config.h>

#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif
#include <sys/types.h>
#if HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif
#if TIME_WITH_SYS_TIME
# ifdef WIN32
#  include <sys/timeb.h>
# else
#  include <sys/time.h>
# endif
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif
#if HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#include <stdio.h>
#if HAVE_WINSOCK_H
#include <winsock.h>
#endif
#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#if HAVE_NETDB_H
#include <netdb.h>
#endif
#if HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#include "asn1.h"
#include "snmp_api.h"
#include "snmp_client.h"
#include "mib.h"
#include "snmp.h"
#include "snmp_impl.h"
#include "system.h"
#include "snmp_parse_args.h"
#include "snmpv3.h"

oid objid_enterprise[] = {1, 3, 6, 1, 4, 1, 3, 1, 1};
oid objid_sysdescr[]   = {1, 3, 6, 1, 2, 1, 1, 1, 0};
oid objid_sysuptime[]  = {1, 3, 6, 1, 2, 1, 1, 3, 0};
oid objid_snmptrap[]   = {1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0};
int inform = 0;

void usage(void)
{
    fprintf(stderr,"Usage: %s ", inform ? "snmpinform" : "snmptrap");
    snmp_parse_args_usage(stderr);
    fprintf(stderr," [<trap parameters> ...]\n\n");
    snmp_parse_args_descriptions(stderr);
    fprintf(stderr, "  -v 1 trap parameters:\n\t enterprise-oid agent trap-type specific-type uptime [ var ]...\n");
    fprintf(stderr, "  or\n");
    fprintf(stderr, "  -v 2 trap parameters:\n\t uptime trapoid [ var ] ...\n");
}

int snmp_input(int operation,
	       struct snmp_session *session,
	       int reqid,
	       struct snmp_pdu *pdu,
	       void *magic)
{
  return 1;
}

in_addr_t parse_address(char *address)
{
    in_addr_t addr;
    struct sockaddr_in saddr;
    struct hostent *hp;

    if ((addr = inet_addr(address)) != -1)
	return addr;
    hp = gethostbyname(address);
    if (hp == NULL){
	fprintf(stderr, "unknown host: %s\n", address);
	exit(1);
    } else {
	memcpy(&saddr.sin_addr, hp->h_addr, hp->h_length);
	return saddr.sin_addr.s_addr;
    }

}

int main(int argc, char *argv[])
{
    struct snmp_session session, *ss;
    struct snmp_pdu *pdu, *response;
    struct sockaddr_in *pduIp;
    oid name[MAX_OID_LEN];
    size_t name_length;
    int	arg;
    int status;
    char *trap = NULL, *specific = NULL, *description = NULL, *agent = NULL;
    char *prognam;

    prognam = strrchr(argv[0], '/');
    if (prognam) prognam++;
    else prognam = argv[0];

    if (strcmp(prognam, "snmpinform") == 0) inform = 1;
    arg = snmp_parse_args(argc, argv, &session, NULL, NULL);

    SOCK_STARTUP;

    session.callback = snmp_input;
    session.callback_magic = NULL;
    if (session.remote_port == SNMP_DEFAULT_REMPORT)
	session.remote_port = SNMP_TRAP_PORT;

    if (session.version == SNMP_VERSION_3 && !inform) {
        /* for traps, we use ourselves as the authoritative engine
           which is really stupid since command line apps don't have a
           notion of a persistent engine.  Hence, our boots and time
           values are probably always really wacked with respect to what
           a manager would like to see.

           The following should be enough to:

           1) prevent the library from doing discovery for engineid & time.
           2) use our engineid instead of the remote engineid for
              authoritative & privacy related operations.
           3) The remote engine must be configured with users for our engineID.

           -- Wes */

        /* setup the engineID based on IP addr.  Need a different
           algorthim here.  This will cause problems with agents on the
           same machine sending traps. */
        setup_engineID(NULL, NULL);

        /* pick our own engineID */
        if (session.securityEngineIDLen == 0 ||
            session.securityEngineID == NULL) {
            session.securityEngineID =
                snmpv3_generate_engineID(&session.securityEngineIDLen);
        }
        if (session.contextEngineIDLen == 0 ||
            session.contextEngineID == NULL) {
            session.contextEngineID =
                snmpv3_generate_engineID(&session.contextEngineIDLen);
        }

        /* set boots and time, which will cause problems if this
           machine ever reboots and a remote trap receiver has cached our
           boots and time...  I'll cause a not-in-time-window report to
           be sent back to this machine. */
        if (session.engineBoots == 0)
            session.engineBoots = 1;
        if (session.engineTime == 0)             /* not really correct, */
            session.engineTime = get_uptime();   /* but it'll work. Sort of. */
    }

    ss = snmp_open(&session);
    if (ss == NULL){
      /* diagnose snmp_open errors with the input struct snmp_session pointer */
        snmp_sess_perror("snmptrap", &session);
        SOCK_CLEANUP;
        exit(1);
    }

    if (session.version == SNMP_VERSION_1) {
	if (inform) {
	    fprintf(stderr, "Cannot send INFORM as SNMPv1 PDU\n");
	    exit(1);
	}
	pdu = snmp_pdu_create(SNMP_MSG_TRAP);
	pduIp = (struct sockaddr_in *)&pdu->agent_addr;
	if (arg == argc) {
	    fprintf(stderr, "No enterprise oid\n");
	    usage();
            SOCK_CLEANUP;
	    exit(1);
	}
	if (argv[arg][0] == 0) {
	    pdu->enterprise = (oid *)malloc(sizeof (objid_enterprise));
	    memcpy(pdu->enterprise, objid_enterprise, sizeof(objid_enterprise));
	    pdu->enterprise_length = sizeof(objid_enterprise)/sizeof (oid);
	}
	else {
	    name_length = MAX_OID_LEN;
	    if (!snmp_parse_oid(argv[arg], name, &name_length)) {
		snmp_perror(argv[arg]);
		usage ();
                SOCK_CLEANUP;
		exit (1);
	    }
	    pdu->enterprise = (oid *)malloc(name_length * sizeof(oid));
	    memcpy(pdu->enterprise, name, name_length * sizeof(oid));
	    pdu->enterprise_length = name_length;
	}
	if (++arg >= argc) {
	    fprintf (stderr, "Missing agent parameter\n");
	    usage ();
            SOCK_CLEANUP;
	    exit (1);
	}
	agent = argv [arg];
	pduIp->sin_family = AF_INET;
	if (agent != NULL && strlen (agent) != 0)
	    pduIp->sin_addr.s_addr = parse_address(agent);
	else
	    pduIp->sin_addr.s_addr = get_myaddr();
	if (++arg == argc) {
	    fprintf (stderr, "Missing generic-trap parameter\n");
	    usage ();
            SOCK_CLEANUP;
	    exit (1);
	}
	trap = argv [arg];
	pdu->trap_type = atoi(trap);
	if (++arg == argc) {
	    fprintf (stderr, "Missing specific-trap parameter\n");
	    usage ();
            SOCK_CLEANUP;
	    exit (1);
	}
	specific = argv [arg];
	pdu->specific_type = atoi(specific);
	if (++arg == argc) {
	    fprintf (stderr, "Missing uptime parameter\n");
	    usage ();
            SOCK_CLEANUP;
	    exit (1);
	}
	description = argv [arg];
	if (description == NULL || *description == 0)
	    pdu->time = get_uptime();
	else
	    pdu->time = atol (description);
    }
    else {
	long sysuptime;
	char csysuptime [20];

	pdu = snmp_pdu_create(inform ? SNMP_MSG_INFORM : SNMP_MSG_TRAP2);
	if (arg == argc) {
	    fprintf(stderr, "Missing up-time parameter\n");
	    usage();
            SOCK_CLEANUP;
	    exit(1);
	}
	trap = argv[arg];
	if (*trap == 0) {
	    sysuptime = get_uptime ();
	    sprintf (csysuptime, "%ld", sysuptime);
	    trap = csysuptime;
	}
	snmp_add_var (pdu, objid_sysuptime, sizeof (objid_sysuptime)/sizeof(oid),
		      't', trap);
	if (++arg == argc) {
	    fprintf (stderr, "Missing trap-oid parameter\n");
	    usage ();
            SOCK_CLEANUP;
	    exit (1);
	}
	if (snmp_add_var (pdu, objid_snmptrap, sizeof (objid_snmptrap)/sizeof(oid),
		      'o', argv [arg]) != 0) {
	    snmp_perror(argv[arg]);
	    SOCK_CLEANUP;
	    exit(1);
	}
    }
    arg++;

    while (arg < argc) {
	arg += 3;
	if (arg > argc) {
	    fprintf(stderr, "%s: Missing type/value for variable\n", argv[arg-3]);
	    SOCK_CLEANUP;
	    exit(1);
	}
	name_length = MAX_OID_LEN;
	if (!snmp_parse_oid(argv [arg-3], name, &name_length)) {
	    snmp_perror(argv [arg-3]);
            SOCK_CLEANUP;
	    exit(1);
	}
	if (snmp_add_var (pdu, name, name_length, argv [arg-2][0], argv [arg-1]) != 0) {
	    snmp_perror(argv[arg-3]);
	    SOCK_CLEANUP;
	    exit(1);
	}
    }

    if (inform) status = snmp_synch_response(ss, pdu, &response);
    else status = snmp_send(ss, pdu) == 0;
    if (status) {
        snmp_sess_perror(inform ? "snmpinform" : "snmptrap", ss);
	snmp_free_pdu(pdu);
    }
    else if (inform) snmp_free_pdu(response);

    snmp_close(ss);
    SOCK_CLEANUP;
    return (0);
}
