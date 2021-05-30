/* ucdDemoPublic.c */

#include <config.h>

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

#if HAVE_WINSOCK_H
#include <winsock.h>
#endif

#include "mibincl.h"
#include "snmpv3.h"
#include "snmpusm.h"
#include "agent_read_config.h"
#include "util_funcs.h"
#include "ucdDemoPublic.h"

#define MYMAX 1024
#define MAXUSERS 10

int num=0;
static char demoUsers[MAXUSERS][MYMAX+1];
static char demopass[MYMAX+1];

void ucdDemo_parse_user(const char *word, char *line) {
  if (num == MAXUSERS)
    return;

  if (strlen(line) > MYMAX)
    return;
  
  strcpy(demoUsers[num++], line);
}


void ucdDemo_parse_userpass(const char *word, char *line) {
  if (strlen(line) > MYMAX)
    return;
  
  strcpy(demopass, line);
}

/* this variable defines function callbacks and type return information 
   for the ucdDemoPublic mib */

struct variable2 ucdDemoPublic_variables[] = {
  { UCDDEMORESETKEYS    , ASN_INTEGER   , RWRITE, var_ucdDemoPublic, 1, { 1 } },
  { UCDDEMOPUBLICSTRING , ASN_OCTET_STR , RWRITE, var_ucdDemoPublic, 1, { 2 } },
  { UCDDEMOUSERLIST     , ASN_OCTET_STR , RWRITE, var_ucdDemoPublic, 1, { 3 } },
  { UCDDEMOPASSPHRASE   , ASN_OCTET_STR , RWRITE, var_ucdDemoPublic, 1, { 4 } },

};

/* Define the OID pointer to the top of the mib tree that we're
   registering underneath */
oid ucdDemoPublic_variables_oid[] = { 1,3,6,1,4,1,2021,14,1,1 };

void init_ucdDemoPublic(void) {
  REGISTER_MIB( "examples/ucdDemoPublic", ucdDemoPublic_variables,
		variable2, ucdDemoPublic_variables_oid);
  snmpd_register_config_handler("demoUser",
                                ucdDemo_parse_user, NULL, "USER");
  snmpd_register_config_handler("demoPass",
                                ucdDemo_parse_userpass, NULL, "PASSPHASE");
}

unsigned char publicString[MYMAX+1];

unsigned char *
var_ucdDemoPublic(
    struct variable *vp,
    oid     *name,
    size_t  *length,
    int     exact,
    size_t  *var_len,
    WriteMethod **write_method)
{
  static long long_ret;
  static char string[MYMAX+1], *cp;
  int i;
  
  *write_method = 0;           /* assume it isnt writable for the time being */
  *var_len = sizeof(long_ret); /* assume an integer and change later if not */

  if (header_generic(vp,name,length,exact,var_len,write_method))
      return 0;

  /* this is where we do the value assignments for the mib results. */
  switch(vp->magic) {

    case UCDDEMORESETKEYS:
      *write_method = write_ucdDemoResetKeys;
      long_ret = 0;
      return (unsigned char *) &long_ret;

    case UCDDEMOPUBLICSTRING:
      *write_method = write_ucdDemoPublicString;
      *var_len = strlen(publicString);
      return (unsigned char *) publicString;

    case UCDDEMOUSERLIST:
      cp = string;
      for(i=0; i < num; i++) {
        sprintf(cp, " %s", demoUsers[i]);
        cp = cp + strlen(cp);
      }
      *var_len = strlen(string);
      return (unsigned char *) string;
      
    case UCDDEMOPASSPHRASE:
      *var_len = strlen(demopass);
      return (unsigned char *) demopass;
      
    default:
      DEBUGMSGTL(("snmpd", "unknown sub-id %d in var_ucdDemoPublic\n", vp->magic));
  }
  return 0;
}

int
write_ucdDemoResetKeys(
   int      action,
   u_char   *var_val,
   u_char   var_val_type,
   size_t   var_val_len,
   u_char   *statP,
   oid      *name,
   size_t   name_len)
{
  /* variables we may use later */
  static long long_ret;
  static unsigned char string[1500];
  static oid objid[MAX_OID_LEN];
  static struct counter64 c64;
  int bigsize=1000;
  unsigned char *engineID;
  int engineIDLen;
  int i;
  struct usmUser *user;

  if (var_val_type != ASN_INTEGER) {
      DEBUGMSGTL(("ucdDemoPublic","write to ucdDemoResetKeys not ASN_INTEGER\n"));
      return SNMP_ERR_WRONGTYPE;
  }
  if (var_val_len > sizeof(long_ret)) {
      DEBUGMSGTL(("ucdDemoPublic","write to ucdDemoResetKeys: bad length\n"));
      return SNMP_ERR_WRONGLENGTH;
  }
  if (action == COMMIT) {
      long_ret = *((long *) var_val);
      if (long_ret == 1) {
        engineID = snmpv3_generate_engineID(&engineIDLen);
        for(i=0; i < num; i++) {
          user = usm_get_user(engineID, engineIDLen, demoUsers[i]);
          if (user) {
            usm_set_user_password(user, "userSetAuthPass", demopass);
            usm_set_user_password(user, "userSetPrivPass", demopass);
          }
        }
        /* reset the keys */
      }
  }
  return SNMP_ERR_NOERROR;
}

int
write_ucdDemoPublicString(
   int      action,
   u_char   *var_val,
   u_char   var_val_type,
   size_t   var_val_len,
   u_char   *statP,
   oid      *name,
   size_t   name_len)
{
  if (var_val_type != ASN_OCTET_STR) {
      DEBUGMSGTL(("ucdDemoPublic","write to ucdDemoPublicString not ASN_OCTET_STR\n"));
      return SNMP_ERR_WRONGTYPE;
  }
  if (var_val_len > MYMAX) {
      DEBUGMSGTL(("ucdDemoPublic","write to ucdDemoPublicString: bad length\n"));
      return SNMP_ERR_WRONGLENGTH;
  }
  if (action == COMMIT) {
      strcpy(publicString, var_val);
  }
  return SNMP_ERR_NOERROR;
}

