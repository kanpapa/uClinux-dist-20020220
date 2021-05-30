/*
 * vmstat_netbsd1.c
 */

#include <config.h>

/* Ripped from /usr/scr/usr.bin/vmstat/vmstat.c (covering all bases) */
#include <sys/param.h>
#include <sys/time.h>
#include <sys/proc.h>
#include <sys/dkstat.h>
#include <sys/buf.h>
#include <sys/uio.h>
#include <sys/namei.h>
#include <sys/malloc.h>
#include <sys/signal.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <sys/sysctl.h>
#include <sys/vmmeter.h>

#include <vm/vm_param.h>
#include <uvm/uvm_extern.h>

#include <time.h>
#include <nlist.h>
#include <kvm.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <paths.h>
#include <limits.h>


#include "mibincl.h"
#include "util_funcs.h"

#include "vmstat.h"
#include "auto_nlist.h"

/* CPU percentage */
#define CPU_PRC         100
#define CPTIME_SYMBOL	"cp_time"
#define BOOTTIME_SYMBOL	"boottime"

void init_vmstat_netbsd1(void) 
{

  struct variable2 extensible_vmstat_variables[] = {
    {MIBINDEX, ASN_INTEGER, RONLY, var_extensible_vmstat,1,{MIBINDEX}},
    {ERRORNAME, ASN_OCTET_STR, RONLY, var_extensible_vmstat, 1, {ERRORNAME }},
    {SWAPIN, ASN_INTEGER, RONLY, var_extensible_vmstat, 1, {SWAPIN}},
    {SWAPOUT, ASN_INTEGER, RONLY, var_extensible_vmstat, 1, {SWAPOUT}},
    {IOSENT, ASN_INTEGER, RONLY, var_extensible_vmstat, 1, {IOSENT}},
    {IORECEIVE, ASN_INTEGER, RONLY, var_extensible_vmstat, 1, {IORECEIVE}},
    {SYSINTERRUPTS, ASN_INTEGER, RONLY, var_extensible_vmstat, 1, {SYSINTERRUPTS}},
    {SYSCONTEXT, ASN_INTEGER, RONLY, var_extensible_vmstat, 1, {SYSCONTEXT}},
    {CPUUSER, ASN_INTEGER, RONLY, var_extensible_vmstat, 1, {CPUUSER}},
    {CPUSYSTEM, ASN_INTEGER, RONLY, var_extensible_vmstat, 1, {CPUSYSTEM}},
    {CPUIDLE, ASN_INTEGER, RONLY, var_extensible_vmstat, 1, {CPUIDLE}},
/* Future use: */
/*
  {ERRORFLAG, ASN_INTEGER, RONLY, var_extensible_vmstat, 1, {ERRORFLAG }},
  {ERRORMSG, ASN_OCTET_STR, RONLY, var_extensible_vmstat, 1, {ERRORMSG }}
*/
  };

  /* Define the OID pointer to the top of the mib tree that we're
   registering underneath */
  oid vmstat_variables_oid[] = { EXTENSIBLEMIB,11 };

  /* register ourselves with the agent to handle our mib tree */
  REGISTER_MIB("ucd-snmp/vmstat", extensible_vmstat_variables, variable2, \
               vmstat_variables_oid);
  
}


long
getuptime(void )
{
	static time_t now, boottime;
	time_t uptime;

	if (boottime == 0)
		auto_nlist(BOOTTIME_SYMBOL, (char *)&boottime, sizeof (boottime));

	time(&now);
	uptime = now - boottime;

	return(uptime);
}

unsigned char *var_extensible_vmstat(struct variable *vp,
				     oid *name,
				     size_t *length,
				     int exact,
				     size_t *var_len,
				     WriteMethod **write_method)
{

    int loop;

    time_t time_new = getuptime();
    static time_t time_old;
    static time_t time_diff;

    static long cpu_old[CPUSTATES];
    static long cpu_new[CPUSTATES];
    static long cpu_diff[CPUSTATES];
    static long cpu_total;
    long cpu_sum;
    double cpu_prc;

    static struct uvmexp mem_old, mem_new;
    int mem_mib[] = {CTL_VM, VM_UVMEXP};
    int mem_size = sizeof(struct uvmexp);

    static long long_ret;
    static char errmsg[300];

    long_ret = 0;  /* set to 0 as default */

    if (header_generic(vp,name,length,exact,var_len,write_method))
	return(NULL);

    /* Update structures (only if time has passed) */
    if (time_new != time_old)
    {
	time_diff = time_new - time_old;
	time_old = time_new;

	/* CPU usage */
	auto_nlist(CPTIME_SYMBOL, (char *)cpu_new, sizeof (cpu_new));
	
	cpu_total = 0;
	
	for (loop = 0; loop < CPUSTATES; loop++)
	{
	    cpu_diff[loop] = cpu_new[loop] - cpu_old[loop];
	    cpu_old[loop] = cpu_new[loop];
	    cpu_total += cpu_diff[loop];
	}
	
	if (cpu_total == 0) cpu_total = 1;

	/* Memory info */
	mem_old = mem_new;
	sysctl(mem_mib, 2, &mem_new, &mem_size, NULL, 0);
    }

/* Rate macro */
#define rate(x) (((x)+ time_diff/2) / time_diff)

/* Page-to-kb macro */
#define ptok(p) ((p) * (mem_new.pagesize >> 10))

    switch (vp->magic) {
    case MIBINDEX:
	long_ret = 1;
	return((u_char *) (&long_ret));
    case ERRORNAME:    /* dummy name */
	sprintf(errmsg,"systemStats");
	*var_len = strlen(errmsg);
	return((u_char *) (errmsg));
    case SWAPIN:
	long_ret = ptok(mem_new.swapins - mem_old.swapins);
	long_ret = rate(long_ret);
	return((u_char *) (&long_ret));
    case SWAPOUT:
	long_ret = ptok(mem_new.swapouts - mem_old.swapouts);
	long_ret = rate(long_ret);
	return((u_char *) (&long_ret));
    case IOSENT:
#if NO_DUMMY_VALUES
	return NULL;
#endif
	long_ret = -1;
	return((u_char *) (&long_ret));
    case IORECEIVE:
#if NO_DUMMY_VALUES
	return NULL;
#endif
	long_ret = -1;
	return((u_char *) (&long_ret));
    case SYSINTERRUPTS:
	long_ret = rate(mem_new.intrs - mem_old.intrs);
	return((u_char *) (&long_ret));
    case SYSCONTEXT:
	long_ret = rate(mem_new.swtch - mem_old.swtch);
	return((u_char *) (&long_ret));
    case CPUUSER:
	cpu_sum = cpu_diff[CP_USER] + cpu_diff[CP_NICE];
	cpu_prc = (float)cpu_sum / (float)cpu_total;
	long_ret = cpu_prc * CPU_PRC;
	return((u_char *) (&long_ret));
    case CPUSYSTEM:
	cpu_sum = cpu_diff[CP_SYS] + cpu_diff[CP_INTR];
	cpu_prc = (float)cpu_sum / (float)cpu_total;
	long_ret = cpu_prc * CPU_PRC;
	return((u_char *) (&long_ret));
    case CPUIDLE:
	cpu_sum = cpu_diff[CP_IDLE];
	cpu_prc = (float)cpu_sum / (float)cpu_total;
	long_ret = cpu_prc * CPU_PRC;
	return((u_char *) (&long_ret));
/* reserved for future use */
/*
  case ERRORFLAG:
  return((u_char *) (&long_ret));
  case ERRORMSG:
  return((u_char *) (&long_ret));
  */
    }
    return NULL;
}

