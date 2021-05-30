
/*
 *  13 Jun 91  wsak (wk0x@andrew) added mips support
 */

#include <config.h>

#ifdef CAN_USE_NLIST

#include <sys/types.h>
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdio.h>
#include <errno.h>
#if HAVE_STRING_H
#include <string.h>
#endif
#if HAVE_FCNTL_H
#include <fcntl.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_KVM_H
#include <kvm.h>
#endif

#include "asn1.h"
#include "snmp_api.h"
#include "snmp_impl.h"
#include "snmp_logging.h"
#include "default_store.h"

#include "kernel.h"
#include "ds_agent.h"

#ifndef NULL
#define NULL 0
#endif


#if HAVE_KVM_H
kvm_t *kd;

void
init_kmem(const char *file)
{
#if HAVE_KVM_OPENFILES
    char err[4096];
    kd = kvm_openfiles(NULL, NULL, NULL, O_RDONLY, err);
    if (kd == NULL && !ds_get_boolean(DS_APPLICATION_ID, DS_AGENT_NO_ROOT_ACCESS)) {
	snmp_log(LOG_CRIT, "init_kmem: kvm_openfiles failed: %s\n", err);
	exit(1);
    }
#else
    kd = kvm_open(NULL, NULL, NULL, O_RDONLY, NULL);
    if (!kd && !ds_get_boolean(DS_APPLICATION_ID, DS_AGENT_NO_ROOT_ACCESS)) {
	snmp_log(LOG_CRIT, "init_kmem: kvm_open failed: %s\n", strerror(errno));
	exit(1);
    }
#endif	/* HAVE_KVM_OPENFILES */
}


/*
 *  klookup:
 *
 *  It seeks to the location  off  in kmem
 *  It does a read into  target  of  siz  bytes.
 *
 *  Return 0 on failure and 1 on sucess.
 *
 */


int
klookup(unsigned long off,
	char   *target,
	int     siz)
{
    int result;
    if (kd == NULL) return 0;
    result = kvm_read(kd, off, target, siz);
    if (result != siz) {
#if HAVE_KVM_OPENFILES
 snmp_log(LOG_ERR,"kvm_read(*, %lx, %p, %d) = %d: %s\n", off, target, siz,
		result, kvm_geterr(kd));
#else
 snmp_log(LOG_ERR,"kvm_read(*, %lx, %p, %d) = %d: ", off, target, siz,
		result);
	snmp_log_perror("klookup");
#endif
	return 0;
    }
    return 1;
}

#else /* HAVE_KVM_H */

static off_t klseek (off_t);
static int klread (char *, int);
int swap, mem, kmem;

void
init_kmem(const char *file)
{
  kmem = open(file, O_RDONLY);
  if (kmem < 0 && !ds_get_boolean(DS_APPLICATION_ID, DS_AGENT_NO_ROOT_ACCESS)){
    snmp_log_perror(file);
    exit(1);
  }
  fcntl(kmem,F_SETFD,1);
  mem = open("/dev/mem",O_RDONLY);    
  if (mem < 0 && !ds_get_boolean(DS_APPLICATION_ID, DS_AGENT_NO_ROOT_ACCESS)){
    snmp_log_perror("/dev/mem");
    exit(1);
  }
  fcntl(mem,F_SETFD,1);
#ifdef DMEM_LOC
  swap = open(DMEM_LOC,O_RDONLY);
  if (swap < 0 && !ds_get_boolean(DS_APPLICATION_ID, DS_AGENT_NO_ROOT_ACCESS)){
    snmp_log_perror(DMEM_LOC);
    exit(1);
  }
  fcntl(swap,F_SETFD,1);
#endif
}


/*
 *  Seek into the kernel for a value.
 */
static off_t
klseek(off_t base)
{
  return (lseek(kmem, (off_t)base, SEEK_SET));
}


/*
 *  Read from the kernel 
 */
static int
klread(char *buf,
       int buflen)
{
  return (read(kmem, buf, buflen));
}


/*
 *  klookup:
 *
 *  It seeks to the location  off  in kmem
 *  It does a read into  target  of  siz  bytes.
 *
 *  Return 0 on failure and 1 on sucess.
 *
 */


int
klookup(unsigned long off,
	char   *target,
	int     siz)
{
  long retsiz;

  if (kmem < 0) return 0;

  if ((retsiz = klseek((off_t) off)) != off) {
    snmp_log(LOG_ERR, "klookup(%lx, %p, %d): ", off, target, siz);
    snmp_log_perror("klseek");
#ifdef EXIT_ON_BAD_KLREAD
    exit(1);
#endif
    return (0);
  }
  if ((retsiz = klread(target, siz)) != siz ) {
    if (snmp_get_do_debugging()) {
    /* these happen too often on too many architectures to print them
       unless we're in debugging mode. People get very full log files. */
      snmp_log(LOG_ERR, "klookup(%lx, %p, %d): ", off, target, siz);
      snmp_log_perror("klread");
    }
#ifdef EXIT_ON_BAD_KLREAD
    exit(1);
#endif
    return(0);
  }
  return (1);
}

#endif /* HAVE_KVM_H */

#endif /* CAN_USE_NLIST */
