/*
 * snmp_agent.h
 *
 * External definitions for functions in snmp_agent.c.
 */

#ifndef SNMP_AGENT_H
#define SNMP_AGENT_H

#define SNMP_MAX_PDU_SIZE 64000 /* local constraint on PDU size sent by agent
                                  (see also SNMP_MAX_MSG_SIZE in snmp_api.h) */

struct agent_snmp_session {
    int		mode;
    struct variable_list *start, *end;
    struct snmp_session  *session;
    struct snmp_pdu      *pdu;
    int		rw;
    int		exact;
    int		status;
    
    struct request_list *outstanding_requests;
    struct agent_snmp_session *next;
};

/* config file parsing routines */
int handle_snmp_packet(int, struct snmp_session *, int, struct snmp_pdu *, void *);
int handle_next_pass( struct agent_snmp_session *);
int  handle_var_list( struct agent_snmp_session *);
void snmp_agent_parse_config (char *, char *);
struct agent_snmp_session  *init_agent_snmp_session( struct snmp_session *, struct snmp_pdu *);
int getNextSessID(void);
int init_master_agent(int dest_port,
                       int (*pre_parse) (struct snmp_session *, snmp_ipaddr),
                       int (*post_parse) (struct snmp_session *, struct snmp_pdu *,int));
int agent_check_and_process(int block);

#endif
