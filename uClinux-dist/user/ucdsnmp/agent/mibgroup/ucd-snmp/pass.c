#include <config.h>

#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <stdio.h>
#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <ctype.h>
#include <sys/types.h>
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_SYS_WAIT_H
# include <sys/wait.h>
#endif
#if HAVE_WINSOCK_H
#include <winsock.h>
#endif

#if HAVE_DMALLOC_H
#include <dmalloc.h>
#endif

#include "mibincl.h"
#include "struct.h"
#include "pass.h"
#include "extensible.h"
#include "util_funcs.h"
#include "read_config.h"
#include "agent_read_config.h"
#include "system.h"

struct extensible *passthrus=NULL;
int numpassthrus=0;

/* the relocatable extensible commands variables */
struct variable2 extensible_passthru_variables[] = {
  /* bogus entry.  Only some of it is actually used. */
  {MIBINDEX, ASN_INTEGER, RWRITE, var_extensible_pass, 0, {MIBINDEX}},
};

/*  This is also called from pass_persist.c */
int asc2bin(char *p)
{
    char *r, *q = p;
    char c;
    int n = 0;

    for (;;) {
        c = (char) strtol(q, &r, 16);
        if (r == q) break;
        *p++ = c;
        q = r;
        n++;
    }
    return n;
}

/*  This is also called from pass_persist.c */
int bin2asc(char *p, size_t n)
{
    int i, flag = 0;
    char buffer[SNMP_MAXBUF];

    for (i = 0; i < (int)n; i++) {
        buffer[i] = p[i];
        if (!isprint(p[i])) flag = 1;
    }
    if (flag == 0) {
	p[n] = 0;
	return n;
    }
    for (i = 0; i < (int)n; i++) {
        sprintf(p, "%02x ", (unsigned char)(buffer[i] & 0xff));
        p += 3;
    }
    *--p = 0;
    return 3 * n - 1;
}


void init_pass(void) 
{
  snmpd_register_config_handler("pass", pass_parse_config,
                                pass_free_config,"miboid command");
}


void pass_parse_config(const char *token, char* cptr)
{
  struct extensible **ppass = &passthrus, **etmp, *ptmp;
  char *tcptr;
  int i;
  
  if (*cptr == '.') cptr++;
  if (!isdigit(*cptr)) {
    config_perror("second token is not a OID");
    return;
  }
  numpassthrus++;
  
  while(*ppass != NULL)
    ppass = &((*ppass)->next);
  (*ppass) = (struct extensible *) malloc(sizeof(struct extensible));
  if (*ppass == NULL)
    return;
  (*ppass)->type = PASSTHRU;

  (*ppass)->miblen = parse_miboid(cptr,(*ppass)->miboid);
  while (isdigit(*cptr) || *cptr == '.') cptr++;
  /* name */
  cptr = skip_white(cptr);
  if (cptr == NULL) {
    config_perror("No command specified on pass line");
    (*ppass)->command[0] = 0;
  } else {
    for(tcptr=cptr; *tcptr != 0 && *tcptr != '#' && *tcptr != ';';
        tcptr++);
    strncpy((*ppass)->command,cptr,tcptr-cptr);
    (*ppass)->command[tcptr-cptr] = 0;
  }
  strcpy((*ppass)->name, (*ppass)->command);
  (*ppass)->next = NULL;

  register_mib("pass", (struct variable *) extensible_passthru_variables,
               sizeof(struct variable2),
               1, (*ppass)->miboid, (*ppass)->miblen);

  /* argggg -- pasthrus must be sorted */
  if (numpassthrus > 0) {
    etmp = (struct extensible **)
      malloc(((sizeof(struct extensible *)) * numpassthrus));
    if (etmp == NULL)
      return;

    for(i=0,ptmp = (struct extensible *) passthrus;
        i < numpassthrus && ptmp != 0;
        i++, ptmp = ptmp->next)
      etmp[i] = ptmp;
    qsort((void *)etmp, numpassthrus, sizeof(struct extensible *),
	  pass_compare);
    passthrus = (struct extensible *) etmp[0];
    ptmp = (struct extensible *) etmp[0];
    
    for(i=0; i < numpassthrus-1; i++) {
      ptmp->next = etmp[i+1];
      ptmp = ptmp->next;
    }
    ptmp->next = NULL;
    free(etmp);
  }
}

void pass_free_config (void) 
{
  struct extensible *etmp, *etmp2;
  
  for (etmp = passthrus; etmp != NULL;) {
    etmp2 = etmp;
    etmp = etmp->next;
    unregister_mib(etmp2->miboid, etmp2->miblen);
    free(etmp2);
  }
  passthrus = NULL;
  numpassthrus = 0;
}

u_char *var_extensible_pass(struct variable *vp,
				   oid *name,
				   size_t *length,
				   int exact,
				   size_t *var_len,
				   WriteMethod **write_method)
{

  oid newname[MAX_OID_LEN];
  int i, j, rtest=0, fd, newlen, last;
  static long long_ret;
  static char buf[SNMP_MAXBUF], buf2[SNMP_MAXBUF];
  static oid  objid[MAX_OID_LEN];
  struct extensible *passthru;
  FILE *file;

  long_ret = *length;
  for(i=1; i<= numpassthrus; i++) {
    passthru = get_exten_instance(passthrus,i);
    last = passthru->miblen;
    if (passthru->miblen > *length)
      last = *length;
    for(j=0,rtest=0; j < last && !rtest; j++) {
      if (name[j] != passthru->miboid[j]) {
        if (name[j] < passthru->miboid[j])
          rtest = -1;
        else
          rtest = 1;
      }
    }
    if ((exact && rtest == 0) || (!exact && rtest <= 0)) {
      /* setup args */
      if (passthru->miblen >= *length || rtest < 0)
        sprint_mib_oid(buf, passthru->miboid, passthru->miblen);
      else 
        sprint_mib_oid(buf, name, *length);
      if (exact)
        sprintf(passthru->command,"%s -g %s",passthru->name,buf);
      else
        sprintf(passthru->command,"%s -n %s",passthru->name,buf);
      DEBUGMSGTL(("ucd-snmp/pass", "pass-running:  %s\n",passthru->command));
      /* valid call.  Exec and get output */
      if ((fd = get_exec_output(passthru))) {
        file = fdopen(fd,"r");
        if (fgets(buf,sizeof(buf),file) == NULL) {
          *var_len = 0;
          fclose(file);
          wait_on_exec(passthru);
          return(NULL);
        }
        newlen = parse_miboid(buf,newname);

        /* its good, so copy onto name/length */
        memcpy( (char *)name,(char *) newname, (int)newlen * sizeof (oid));
        *length = newlen;

        /* set up return pointer for setable stuff */
        *write_method = setPass;

        if (newlen == 0 || fgets(buf,sizeof(buf),file) == NULL
            || fgets(buf2,sizeof(buf2),file) == NULL) {
          *var_len = 0;
          fclose(file);
          wait_on_exec(passthru);
          return(NULL);
        }
        fclose(file);
        wait_on_exec(passthru);

        /* buf contains the return type, and buf2 contains the data */
        if (!strncasecmp(buf,"string",6)) {
          buf2[strlen(buf2)-1] = 0;  /* zap the linefeed */
          *var_len = strlen(buf2);
          vp->type = ASN_OCTET_STR;
          return((unsigned char *) buf2);
        } else if (!strncasecmp(buf,"integer",7)) {
          *var_len = sizeof(long_ret);
          long_ret = strtol(buf2, NULL, 10);
          vp->type = ASN_INTEGER;
          return((unsigned char *) &long_ret);
        } else if (!strncasecmp(buf,"unsigned",7)) {
          *var_len = sizeof(long_ret);
          long_ret = strtoul(buf2, NULL, 10);
          vp->type = ASN_UNSIGNED;
          return((unsigned char *) &long_ret);
        } else if (!strncasecmp(buf,"counter",7)) {
          *var_len = sizeof(long_ret);
          long_ret = strtoul(buf2, NULL, 10);
          vp->type = ASN_COUNTER;
          return((unsigned char *) &long_ret);
        } else if (!strncasecmp(buf,"octet",5)) {
          *var_len = asc2bin(buf2);
          vp->type = ASN_OCTET_STR;
          return((unsigned char *) buf2);
        } else if (!strncasecmp(buf,"gauge",5)) {
          *var_len = sizeof(long_ret);
          long_ret = strtoul(buf2, NULL, 10);
          vp->type = ASN_GAUGE;
          return((unsigned char *) &long_ret);
        } else if (!strncasecmp(buf,"objectid",8)) {
          newlen = parse_miboid(buf2,objid);
          *var_len = newlen*sizeof(oid);
          vp->type = ASN_OBJECT_ID;
          return((unsigned char *) objid);
        } else if (!strncasecmp(buf,"timetick",8)) {
          *var_len = sizeof(long_ret);
          long_ret = strtoul(buf2, NULL, 10);
          vp->type = ASN_TIMETICKS;
          return((unsigned char *) &long_ret);
        } else if (!strncasecmp(buf,"ipaddress",9)) {
          newlen = parse_miboid(buf2,objid);
          if (newlen != 4) {
            snmp_log(LOG_ERR,"invalid ipaddress returned:  %s\n",buf2);
            *var_len = 0;
            return(NULL);
          }
          long_ret = (objid[0] << (8*3)) + (objid[1] << (8*2)) +
            (objid[2] << 8) + objid[3];
	  long_ret = htonl(long_ret);
          *var_len = sizeof(long_ret);
          vp->type = ASN_IPADDRESS;
          return((unsigned char *) &long_ret);
        }
      }
      *var_len = 0;
      return(NULL);
    }
  }
  if (var_len)
    *var_len = 0;
  *write_method = NULL;
  return(NULL);
}

int
setPass(int action,
	u_char *var_val,
	u_char var_val_type,
	size_t var_val_len,
	u_char *statP,
	oid *name,
	size_t name_len)
{
  int i, j, rtest, last;
  struct extensible *passthru;

  static char buf[SNMP_MAXBUF], buf2[SNMP_MAXBUF];
  static long tmp;
  static unsigned long utmp;
  size_t itmp;
  static oid objid[MAX_OID_LEN];
  
  for(i=1; i<= numpassthrus; i++) {
    passthru = get_exten_instance(passthrus,i);
    last = passthru->miblen;
    if (passthru->miblen > name_len)
      last = name_len;
    for(j=0,rtest=0; j < last && !rtest; j++) {
      if (name[j] != passthru->miboid[j]) {
        if (name[j] < passthru->miboid[j])
          rtest = -1;
        else
          rtest = 1;
      }
    }
    if (rtest <= 0) {
      if (action != COMMIT)
        return SNMP_ERR_NOERROR;
      /* setup args */
      if (passthru->miblen >= name_len || rtest < 0)
        sprint_mib_oid(buf, passthru->miboid, passthru->miblen);
      else 
        sprint_mib_oid(buf, name, name_len);
      sprintf(passthru->command,"%s -s %s ",passthru->name,buf);
      switch(var_val_type) {
        case ASN_INTEGER:
        case ASN_COUNTER:
        case ASN_GAUGE:
        case ASN_TIMETICKS:
          tmp = *((long *) var_val);
          switch (var_val_type) {
            case ASN_INTEGER:
              sprintf(buf,"integer %d",(int) tmp);
              break;
            case ASN_COUNTER:
              sprintf(buf,"counter %d",(int) tmp);
              break;
            case ASN_GAUGE:
              sprintf(buf,"gauge %d",(int) tmp);
              break;
            case ASN_TIMETICKS:
              sprintf(buf,"timeticks %d",(int) tmp);
              break;
          }
          break;
        case ASN_IPADDRESS:
          utmp = *((u_long *) var_val);
	  utmp = ntohl(utmp);
          sprintf(buf,"ipaddress %d.%d.%d.%d",
                  (int) ((utmp & 0xff000000) >> (8*3)),
                  (int) ((utmp & 0xff0000) >> (8*2)),
                  (int) ((utmp & 0xff00) >> (8)),
                  (int) ((utmp & 0xff)));
          break;
        case ASN_OCTET_STR:
          itmp = sizeof(buf2);
          memcpy(buf2, var_val, var_val_len);
          if (bin2asc(buf2, var_val_len) == (int)itmp)
              sprintf(buf,"string %s",buf2);
          else
              sprintf(buf,"octet %s",buf2);
          break;
        case ASN_OBJECT_ID:
          itmp = var_val_len/sizeof(oid);
          memcpy(objid, var_val, var_val_len);
          sprint_mib_oid(buf2, objid, itmp);
          sprintf(buf,"objectid \"%s\"",buf2);
          break;
      }
      strcat(passthru->command,buf);
      DEBUGMSGTL(("ucd-snmp/pass", "pass-running:  %s\n",passthru->command));
      exec_command(passthru);
      if (!strncasecmp(passthru->output,"not-writable",11)) {
        return SNMP_ERR_NOTWRITABLE;
      } else if (!strncasecmp(passthru->output,"wrong-type",9)) {
        return SNMP_ERR_WRONGTYPE;
      } 
      return SNMP_ERR_NOERROR;
    }
  }
  if (snmp_get_do_debugging()) {
    sprint_mib_oid(buf2,name,name_len);
    DEBUGMSGTL(("ucd-snmp/pass", "pass-notfound:  %s\n",buf2));
  }
  return SNMP_ERR_NOSUCHNAME;
}

int pass_compare(const void *a, const void *b)
{
  const struct extensible * const *ap, * const *bp;
  ap = (const struct extensible * const *) a;
  bp = (const struct extensible * const *) b;
  return snmp_oid_compare((*ap)->miboid,(*ap)->miblen,(*bp)->miboid,(*bp)->miblen);
}
