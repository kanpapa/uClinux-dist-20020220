/*
 * snmpwalk.c - send snmp GETNEXT requests to a network entity, walking a
 * subtree.
 *
 */
/**********************************************************************
	Copyright 1988, 1989, 1991, 1992 by Carnegie Mellon University

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
#include "default_store.h"
#include "snmp_parse_args.h"
#include "getopt.h"

#define DS_WALK_INCLUDE_REQUESTED 1
#define DS_WALK_PRINT_STATISTICS  2

oid objid_mib[] = {1, 3, 6, 1, 2, 1};
int numprinted = 0;

void usage(void)
{
  fprintf(stderr,"Usage: snmpwalk ");
  snmp_parse_args_usage(stderr);
  fprintf(stderr," [<objectID>]\n\n");
  snmp_parse_args_descriptions(stderr);
  fprintf(stderr, "  -C <APPOPTS>  Toggle various application specific behaviour:\n");
  fprintf(stderr, "\t\t  APPOPTS values:\n");
  fprintf(stderr,"\t\t      p: Print the number of variables found.\n");
  fprintf(stderr,"\t\t      i: Include the requested OID in the search range.\n");
}

void
snmp_get_and_print(struct snmp_session *ss, oid *theoid, size_t theoid_len) {
    struct snmp_pdu *pdu, *response;
    struct variable_list *vars;
    int status;
    
    pdu = snmp_pdu_create(SNMP_MSG_GET);
    snmp_add_null_var(pdu, theoid, theoid_len);

    status = snmp_synch_response(ss, pdu, &response);
    if (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR) {
        for(vars = response->variables; vars; vars = vars->next_variable) {
            numprinted++;
            print_variable(vars->name, vars->name_length, vars);
        }
    }
    if (response)
        snmp_free_pdu(response);
}

static void optProc(int argc, char *const *argv, int opt)
{
    switch (opt) {
        case 'C':
            while (*optarg) {
                switch (*optarg++) {
                    case 'i':
                        ds_toggle_boolean(DS_APPLICATION_ID,
                                          DS_WALK_INCLUDE_REQUESTED);
                        break;

                    case 'p':
                        ds_toggle_boolean(DS_APPLICATION_ID,
                                          DS_WALK_PRINT_STATISTICS);
                        break;

                    default:
                        fprintf(stderr,
                                "Unknown flag passed to -C: %c\n", *optarg);
                        usage();
                        exit(1);
                }
            }
            break;
    }
}

int main(int argc, char *argv[])
{
    struct snmp_session  session, *ss;
    struct snmp_pdu *pdu, *response;
    struct variable_list *vars;
    int    arg;
    oid    name[MAX_OID_LEN];
    size_t name_length;
    oid    root[MAX_OID_LEN];
    size_t rootlen;
    int    count;
    int    running;
    int    status;

    ds_register_config(ASN_BOOLEAN, "snmpwalk", "includeRequested",
                       DS_APPLICATION_ID, DS_WALK_INCLUDE_REQUESTED);
    ds_register_config(ASN_BOOLEAN, "snmpwalk", "printStatistics",
                       DS_APPLICATION_ID, DS_WALK_PRINT_STATISTICS);

    /* get the common command line arguments */
    arg = snmp_parse_args(argc, argv, &session, "C:", optProc);

    /* get the initial object and subtree */
    if (arg < argc) {
      /* specified on the command line */
      rootlen = MAX_OID_LEN;
      if (snmp_parse_oid(argv[arg], root, &rootlen) == NULL) {
        snmp_perror(argv[arg]);
        exit(1);
      }
    } else {
      /* use default value */
      memmove(root, objid_mib, sizeof(objid_mib));
      rootlen = sizeof(objid_mib) / sizeof(oid);
    }

    SOCK_STARTUP;

    /* open an SNMP session */
    ss = snmp_open(&session);
    if (ss == NULL){
      /* diagnose snmp_open errors with the input struct snmp_session pointer */
      snmp_sess_perror("snmpwalk", &session);
      SOCK_CLEANUP;
      exit(1);
    }

    /* get first object to start walk */
    memmove(name, root, rootlen * sizeof(oid));
    name_length = rootlen;

    running = -1;

    if (ds_get_boolean(DS_APPLICATION_ID, DS_WALK_INCLUDE_REQUESTED)) {
        snmp_get_and_print(ss, root, rootlen);
    }
    
    while(running){
      /* create PDU for GETNEXT request and add object name to request */
      pdu = snmp_pdu_create(SNMP_MSG_GETNEXT);
      snmp_add_null_var(pdu, name, name_length);

      /* do the request */
      status = snmp_synch_response(ss, pdu, &response);
      if (status == STAT_SUCCESS){
        if (response->errstat == SNMP_ERR_NOERROR){
          /* check resulting variables */
          for(vars = response->variables; vars; vars = vars->next_variable){
            if ((vars->name_length < rootlen) ||
                (memcmp(root, vars->name, rootlen * sizeof(oid))!=0)) {
              /* not part of this subtree */
              running = 0;
              continue;
            }
            numprinted++;
            print_variable(vars->name, vars->name_length, vars);
            if ((vars->type != SNMP_ENDOFMIBVIEW) &&
                (vars->type != SNMP_NOSUCHOBJECT) &&
                (vars->type != SNMP_NOSUCHINSTANCE)){
              /* not an exception value */
              memmove((char *)name, (char *)vars->name,
              vars->name_length * sizeof(oid));
              name_length = vars->name_length;
            } else
              /* an exception value, so stop */
              running = 0;
          }
        } else {
          /* error in response, print it */
          running = 0;
          if (response->errstat == SNMP_ERR_NOSUCHNAME){
            printf("End of MIB\n");
          } else {
            fprintf(stderr, "Error in packet.\nReason: %s\n",
		    snmp_errstring(response->errstat));
            if (response->errstat == SNMP_ERR_NOSUCHNAME){
              fprintf(stderr, "The request for this object identifier failed: ");
              for(count = 1, vars = response->variables;
                    vars && count != response->errindex;
                    vars = vars->next_variable, count++)
                /*EMPTY*/;
              if (vars)
                fprint_objid(stderr, vars->name, vars->name_length);
              fprintf(stderr, "\n");
            }
          }
        }
      } else if (status == STAT_TIMEOUT){
        fprintf(stderr, "Timeout: No Response from %s\n", session.peername);
        running = 0;
      } else {    /* status == STAT_ERROR */
        snmp_sess_perror("snmpwalk", ss);
        running = 0;
      }
      if (response)
        snmp_free_pdu(response);
    }

    if (numprinted == 0 && status == STAT_SUCCESS) {
        /* no printed successful results, which may mean we were
           pointed at an only existing instance.  Attempt a GET, just
           for get measure. */
        snmp_get_and_print(ss, root, rootlen);
    }
    snmp_close(ss);

    if (ds_get_boolean(DS_APPLICATION_ID, DS_WALK_PRINT_STATISTICS)) {
        printf("Variables found: %d\n", numprinted);
    }

    SOCK_CLEANUP;
    return 0;
}
