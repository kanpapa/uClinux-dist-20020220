/* callback.c: A generic callback mechanism */

#ifndef CALLBACK_H
#define CALLBACK_H

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_CALLBACK_IDS    2
#define MAX_CALLBACK_SUBIDS 8

/* Callback Major Types */
#define SNMP_CALLBACK_LIBRARY     0
#define SNMP_CALLBACK_APPLICATION 1

/* SNMP_CALLBACK_LIBRARY minor types */
#define SNMP_CALLBACK_POST_READ_CONFIG	        0
#define SNMP_CALLBACK_STORE_DATA	        1
#define SNMP_CALLBACK_SHUTDOWN		        2
#define SNMP_CALLBACK_POST_PREMIB_READ_CONFIG	3
#define SNMP_CALLBACK_LOGGING			4

typedef int (SNMPCallback)(int majorID, int minorID, void *serverarg,
                           void *clientarg);

struct snmp_gen_callback {
   SNMPCallback         *sc_callback;
   void                 *sc_client_arg;
   struct snmp_gen_callback *next;
};

/* function prototypes */
void init_callbacks(void);
int snmp_register_callback(int major, int minor, SNMPCallback *new_callback,
                           void *arg);
int snmp_call_callbacks(int major, int minor, void *caller_arg);

#ifdef __cplusplus
}
#endif

#endif /* CALLBACK_H */
