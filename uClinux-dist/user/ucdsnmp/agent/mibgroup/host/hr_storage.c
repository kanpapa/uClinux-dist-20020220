/*
 *  Host Resources MIB - storage group implementation - hr_storage.c
 *
 */

#include <config.h>
#include <sys/types.h>
#include <sys/param.h>
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
#if HAVE_SYS_VM_H
#include <sys/vm.h>
#else
#if HAVE_VM_VM_H
#include <vm/vm.h>
#if HAVE_MACHINE_TYPES_H
#include <machine/types.h>
#endif
#if HAVE_SYS_VMMETER_H
#include <sys/vmmeter.h>
#endif
#if HAVE_VM_VM_PARAM_H
#include <vm/vm_param.h>
#endif
#else
#if HAVE_SYS_VMPARAM_H
#include <sys/vmparam.h>
#endif
#if HAVE_SYS_VMMAC_H
#include <sys/vmmac.h>
#endif
#if HAVE_SYS_VMMETER_H
#include <sys/vmmeter.h>
#endif
#if HAVE_SYS_VMSYSTM_H
#include <sys/vmsystm.h>
#endif
#endif /* vm/vm.h */
#endif /* sys/vm.h */
#if HAVE_SYS_POOL_H
#define __POOL_EXPOSE
#include <sys/pool.h>
#endif
#if HAVE_SYS_MBUF_H
#include <sys/mbuf.h>
#endif
#if HAVE_SYS_SYSCTL_H
#include <sys/sysctl.h>
#if defined(CTL_HW) && defined(HW_PAGESIZE)
#define USE_SYSCTL
#endif
#if defined(CTL_VM) && defined(VM_METER)
#define USE_SYSCTL_VM
#endif
#endif

#include "host_res.h"
#include "hr_storage.h"
#include "hr_filesys.h"
#include "auto_nlist.h"

#if HAVE_MNTENT_H
#include <mntent.h>
#endif
#if HAVE_SYS_MNTTAB_H
#include <sys/mnttab.h>
#endif
#if HAVE_SYS_STATVFS_H
#include <sys/statvfs.h>
#endif
#if HAVE_SYS_VFS_H
#include <sys/vfs.h>
#endif
#if HAVE_SYS_MOUNT_H
#include <sys/mount.h>
#endif
#ifdef HAVE_MACHINE_PARAM_H
#include <machine/param.h>
#endif
#include <sys/stat.h>

#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif

#include "../../../snmplib/system.h"

#define HRSTORE_MONOTONICALLY_INCREASING

	/*********************
	 *
	 *  Kernel & interface information,
	 *   and internal forward declarations
	 *
	 *********************/


#ifdef solaris2

extern struct mnttab *HRFS_entry;
#define HRFS_mount	mnt_mountp
#define HRFS_statfs	statvfs

#elif defined(HAVE_GETFSSTAT)

extern struct statfs *HRFS_entry;
extern int fscount;
#define HRFS_statfs	statfs
#define HRFS_mount	f_mntonname

#else

extern struct mntent *HRFS_entry;
#define HRFS_mount	mnt_dir
#define HRFS_statfs	statfs

#endif

#ifndef linux
static int physmem, pagesize;
#endif

	/*********************
	 *
	 *  Initialisation & common implementation functions
	 *
	 *********************/
int Get_Next_HR_Store (void);
void  Init_HR_Store (void);
int header_hrstore (struct variable *,oid *, size_t *, int, size_t *, WriteMethod **);
int header_hrstoreEntry (struct variable *,oid *, size_t *, int, size_t *, WriteMethod **);

int linux_mem (int, int);

#define	HRSTORE_MEMSIZE		1
#define	HRSTORE_INDEX		2
#define	HRSTORE_TYPE		3
#define	HRSTORE_DESCR		4
#define	HRSTORE_UNITS		5
#define	HRSTORE_SIZE		6
#define	HRSTORE_USED		7
#define	HRSTORE_FAILS		8

struct variable4 hrstore_variables[] = {
    { HRSTORE_MEMSIZE,   ASN_INTEGER, RONLY, var_hrstore, 1, {2}},
    { HRSTORE_INDEX,     ASN_INTEGER, RONLY, var_hrstore, 3, {3,1,1}},
    { HRSTORE_TYPE,    ASN_OBJECT_ID, RONLY, var_hrstore, 3, {3,1,2}},
    { HRSTORE_DESCR,   ASN_OCTET_STR, RONLY, var_hrstore, 3, {3,1,3}},
    { HRSTORE_UNITS,     ASN_INTEGER, RONLY, var_hrstore, 3, {3,1,4}},
    { HRSTORE_SIZE,      ASN_INTEGER, RONLY, var_hrstore, 3, {3,1,5}},
    { HRSTORE_USED,      ASN_INTEGER, RONLY, var_hrstore, 3, {3,1,6}},
    { HRSTORE_FAILS,     ASN_COUNTER, RONLY, var_hrstore, 3, {3,1,7}}
};
oid hrstore_variables_oid[] = { 1,3,6,1,2,1,25,2 };


void init_hr_storage (void)
{
#ifdef USE_SYSCTL
    int mib [2];
    size_t len;
#endif

#ifdef USE_SYSCTL
    mib[0] = CTL_HW;
    mib[1] = HW_PHYSMEM;
    len = sizeof(physmem);
    if (sysctl(mib, 2, &physmem, &len, NULL, 0) == -1) perror("sysctl: physmem");
    mib[1] = HW_PAGESIZE;
    len = sizeof(pagesize);
    if (sysctl(mib, 2, &pagesize, &len, NULL, 0) == -1) perror("sysctl: pagesize");
    physmem /= pagesize;
#else	/* USE_SYSCTL */
    auto_nlist(PHYSMEM_SYMBOL, (char *)&physmem, sizeof (physmem));
#ifdef PGSHIFT
    pagesize = 1 << PGSHIFT;
#elif defined(PAGE_SHIFT)
    pagesize = 1 << PAGE_SHIFT;
#elif defined(PAGE_SIZE)
    pagesize = PAGE_SIZE;
#else
#  ifndef linux
    pagesize = PAGESIZE;
#  endif
#endif
#endif	/* USE_SYSCTL */
#ifdef TOTAL_MEMORY_SYMBOL
    auto_nlist(TOTAL_MEMORY_SYMBOL,0,0);
#endif
#ifdef MBSTAT_SYMBOL
    auto_nlist(MBSTAT_SYMBOL,0,0);
#endif

    REGISTER_MIB("host/hr_storage", hrstore_variables, variable4, hrstore_variables_oid);
}

/*
  header_hrstore(...
  Arguments:
  vp	  IN      - pointer to variable entry that points here
  name    IN/OUT  - IN/name requested, OUT/name found
  length  IN/OUT  - length of IN/OUT oid's 
  exact   IN      - TRUE if an exact match was requested
  var_len OUT     - length of variable or 0 if function returned
  write_method
  
*/

int
header_hrstore(struct variable *vp,
	       oid *name,
	       size_t *length,
	       int exact,
	       size_t *var_len,
	       WriteMethod **write_method)
{
#define HRSTORE_NAME_LENGTH	9
    oid newname[MAX_OID_LEN];
    int result;

    DEBUGMSGTL(("host/hr_storage", "var_hrstore: "));
    DEBUGMSGOID(("host/hr_storage", name, *length));
    DEBUGMSG(("host/hr_storage"," %d\n", exact));

    memcpy( (char *)newname,(char *)vp->name, vp->namelen * sizeof(oid));
    newname[HRSTORE_NAME_LENGTH] = 0;
    result = snmp_oid_compare(name, *length, newname, vp->namelen + 1);
    if ((exact && (result != 0)) || (!exact && (result >= 0)))
        return(MATCH_FAILED);
    memcpy( (char *)name,(char *)newname, (vp->namelen + 1) * sizeof(oid));
    *length = vp->namelen + 1;

    *write_method = 0;
    *var_len = sizeof(long);	/* default to 'long' results */
    return(MATCH_SUCCEEDED);
}

int
header_hrstoreEntry(struct variable *vp,
		    oid *name,
		    size_t *length,
		    int exact,
		    size_t *var_len,
		    WriteMethod **write_method)
{
#define HRSTORE_ENTRY_NAME_LENGTH	11
    oid newname[MAX_OID_LEN];
    int storage_idx, LowIndex = -1;
    int result;

    DEBUGMSGTL(("host/hr_storage", "var_hrstoreEntry: "));
    DEBUGMSGOID(("host/hr_storage", name, *length));
    DEBUGMSG(("host/hr_storage"," %d\n", exact));

    memcpy( (char *)newname,(char *)vp->name, (int)vp->namelen * sizeof(oid));
	/* Find "next" storage entry */

    Init_HR_Store();
    for ( ;; ) {
        storage_idx = Get_Next_HR_Store();
        DEBUGMSG(("host/hr_storage", "(index %d ....", storage_idx));
        if ( storage_idx == -1 )
	    break;
	newname[HRSTORE_ENTRY_NAME_LENGTH] = storage_idx;
    DEBUGMSGOID(("host/hr_storage", newname, *length));
    DEBUGMSG(("host/hr_storage","\n"));
        result = snmp_oid_compare(name, *length, newname, vp->namelen + 1);
        if (exact && (result == 0)) {
	    LowIndex = storage_idx;
	    /* Save storage status information */
            break;
	}
	if ((!exact && (result < 0)) &&
		( LowIndex == -1 || storage_idx < LowIndex )) {
	    LowIndex = storage_idx;
	    /* Save storage status information */
#ifdef HRSTORE_MONOTONICALLY_INCREASING
            break;
#endif
	}
    }

    if ( LowIndex == -1 ) {
        DEBUGMSGTL(("host/hr_storage", "... index out of range\n"));
        return(MATCH_FAILED);
    }

    memcpy( (char *)name,(char *)newname, ((int)vp->namelen + 1) * sizeof(oid));
    *length = vp->namelen + 1;
    *write_method = 0;
    *var_len = sizeof(long);	/* default to 'long' results */

    DEBUGMSGTL(("host/hr_storage", "... get storage stats "));
    DEBUGMSGOID(("host/hr_storage", name, *length));
    DEBUGMSG(("host/hr_storage","\n"));
    return LowIndex;
}

oid storage_type_id[] = { 1,3,6,1,2,1, 25, 2, 1, 1 };		/* hrStorageOther */
int storage_type_len = sizeof(storage_type_id)/sizeof(storage_type_id[0]);

	/*********************
	 *
	 *  System specific implementation functions
	 *
	 *********************/

static const char *hrs_descr[] = {
	NULL,
	"Real Memory",		/* HRS_TYPE_MEM */
	"Swap Space",		/* HRS_TYPE_SWAP */
	"Memory Buffers"	/* HRS_TYPE_MBUF */
};



u_char *
var_hrstore(struct variable *vp,
	    oid *name,
	    size_t *length,
	    int exact,
	    size_t *var_len,
	    WriteMethod **write_method)
{
    int store_idx=0;
#ifndef linux
#ifndef solaris2
#if defined(TOTAL_MEMORY_SYMBOL) || defined(USE_SYSCTL_VM)
    struct vmtotal memory_totals;
#endif
#if HAVE_SYS_POOL_H
    struct pool mbpool, mclpool;
    int i;
#endif
    struct mbstat  mbstat;
#endif	/* solaris2 */
#else	/* linux */
    struct stat  kc_buf;
#endif	/* linux */
    static char string[100];
    struct HRFS_statfs stat_buf;

    if ( vp->magic == HRSTORE_MEMSIZE ) {
        if (header_hrstore(vp, name, length, exact, var_len, write_method) == MATCH_FAILED )
	    return NULL;
    }
    else {
        
        store_idx = header_hrstoreEntry(vp, name, length, exact, var_len, write_method);
        if ( store_idx == MATCH_FAILED )
	    return NULL;

	if ( store_idx < HRS_TYPE_FS_MAX ) {
	    if ( HRFS_statfs( HRFS_entry->HRFS_mount, &stat_buf) < 0 )
		return NULL;
	}
#if !defined(linux) && !defined(solaris2)
	else switch ( store_idx ) {
		case HRS_TYPE_MEM:
		case HRS_TYPE_SWAP:
#ifdef USE_SYSCTL_VM
			{   int mib[2];
			    size_t len = sizeof(memory_totals);
			    mib[0] = CTL_VM;
			    mib[1] = VM_METER;
			    sysctl(mib, 2, &memory_totals, &len, NULL, 0);
			}
#elif defined(TOTAL_MEMORY_SYMBOL)
			auto_nlist(TOTAL_MEMORY_SYMBOL, (char *)&memory_totals, sizeof (struct vmtotal));
#endif
			break;
		case HRS_TYPE_MBUF:
#if HAVE_SYS_POOL_H
			auto_nlist(MBPOOL_SYMBOL, (char *)&mbpool, sizeof(mbpool));
			auto_nlist(MCLPOOL_SYMBOL, (char *)&mclpool, sizeof(mclpool));
#endif
			auto_nlist(MBSTAT_SYMBOL, (char *)&mbstat, sizeof (mbstat));
			break;
		default:
			break;
	}
#endif
    }
        


    switch (vp->magic){
	case HRSTORE_MEMSIZE:
#ifndef linux
	    long_return = physmem * (pagesize / 1024);
#else
	    stat("/proc/kcore", &kc_buf);
	    long_return = kc_buf.st_size/1024;	/* 4K too large ? */
#endif
	    return (u_char *)&long_return;

	case HRSTORE_INDEX:
	    long_return = store_idx;
	    return (u_char *)&long_return;
	case HRSTORE_TYPE:
	    if ( store_idx < HRS_TYPE_FS_MAX )
		storage_type_id[storage_type_len-1] = 4;	/* Assume fixed */
	    else switch ( store_idx ) {
		case HRS_TYPE_MEM:
			storage_type_id[storage_type_len-1] = 2;	/* RAM */
			break;
		case HRS_TYPE_SWAP:
			storage_type_id[storage_type_len-1] = 3;	/* Virtual Mem */
			break;
		case HRS_TYPE_MBUF:
			storage_type_id[storage_type_len-1] = 1;	/* Other */
			break;
		default:
			storage_type_id[storage_type_len-1] = 1;	/* Other */
			break;
	    }
            *var_len = sizeof(storage_type_id);
	    return (u_char *)storage_type_id;
	case HRSTORE_DESCR:
	    if (store_idx<HRS_TYPE_FS_MAX) {
	        strcpy(string, HRFS_entry->HRFS_mount);
	        *var_len = strlen(string);
	        return (u_char *) string;
	    }
	    else {
	        store_idx = store_idx-HRS_TYPE_FS_MAX;
	        *var_len = strlen( hrs_descr[store_idx] );
	        return (u_char *)hrs_descr[store_idx];
	    }
	case HRSTORE_UNITS:
	    if ( store_idx < HRS_TYPE_FS_MAX )
		long_return = stat_buf.f_bsize;
	    else switch ( store_idx ) {
		case HRS_TYPE_MEM:
		case HRS_TYPE_SWAP:
#ifdef USE_SYSCTL
			long_return = pagesize;
#elif defined(NBPG)
			long_return = NBPG;
#else
			long_return = 1024;	/* Report in Kb */
#endif
			break;
		case HRS_TYPE_MBUF:
#ifdef MSIZE
			long_return = MSIZE;
#else
			long_return = 256;
#endif
			break;
		default:
#if NO_DUMMY_VALUES
			return NULL;
#endif
			long_return = 1024;	/* As likely as any! */
			break;
	    }
	    return (u_char *)&long_return;
	case HRSTORE_SIZE:
	    if ( store_idx < HRS_TYPE_FS_MAX )
		long_return = stat_buf.f_blocks;
	    else switch ( store_idx ) {
#if !defined(linux) && !defined(solaris2)
#if defined(TOTAL_MEMORY_SYMBOL) || defined(USE_SYSCTL_VM)
		case HRS_TYPE_MEM:
			long_return = memory_totals.t_rm;
			break;
		case HRS_TYPE_SWAP:
			long_return = memory_totals.t_vm;
			break;
#else
		case HRS_TYPE_MEM:
			long_return = physmem;
			break;
		case HRS_TYPE_SWAP:
#if NO_DUMMY_VALUES
			return NULL;
#endif
			break;
#endif
		case HRS_TYPE_MBUF:
#if HAVE_SYS_POOL_H
			long_return = 0;
			for (i = 0; i < sizeof(mbstat.m_mtypes)/sizeof(mbstat.m_mtypes[0]); i++)
			    long_return += mbstat.m_mtypes[i];
#else
			long_return = mbstat.m_mbufs;
#endif
			break;
#else	/* linux */
#ifdef linux
		case HRS_TYPE_MEM:
		case HRS_TYPE_SWAP:
			long_return = linux_mem( store_idx, HRSTORE_SIZE);
			break;
#endif
#endif
		default:
#if NO_DUMMY_VALUES
			return NULL;
#endif
			long_return = 1024;
			break;
	    }
	    return (u_char *)&long_return;
	case HRSTORE_USED:
	    if ( store_idx < HRS_TYPE_FS_MAX )
		long_return = (stat_buf.f_blocks - stat_buf.f_bfree);
	    else switch ( store_idx ) {
#if !defined(linux) && !defined(solaris2)
#if defined(TOTAL_MEMORY_SYMBOL) || defined(USE_SYSCTL_VM)
		case HRS_TYPE_MEM:
			long_return = memory_totals.t_arm;
			break;
		case HRS_TYPE_SWAP:
			long_return = memory_totals.t_avm;
			break;
#endif
		case HRS_TYPE_MBUF:
#if HAVE_SYS_POOL_H
			long_return = (mbpool.pr_nget - mbpool.pr_nput)*mbpool.pr_size
				+ (mclpool.pr_nget - mclpool.pr_nput)*mclpool.pr_size;
#else
			long_return = mbstat.m_clusters - mbstat.m_clfree;	/* unlikely, but... */
#endif
			break;
#else	/* linux */
#ifdef linux
		case HRS_TYPE_MEM:
		case HRS_TYPE_SWAP:
			long_return = linux_mem( store_idx, HRSTORE_USED);
			break;
#endif
#endif
		default:
#if NO_DUMMY_VALUES
			return NULL;
#endif
			long_return = 1024;
			break;
	    }
	    return (u_char *)&long_return;
	case HRSTORE_FAILS:
	    if ( store_idx < HRS_TYPE_FS_MAX )
		long_return = 0;
	    else switch ( store_idx ) {
		case HRS_TYPE_MEM:
		case HRS_TYPE_SWAP:
#if NO_DUMMY_VALUES
			return NULL;
#endif
			long_return = 0;
			break;
#if !defined(linux) && !defined(solaris2)
		case HRS_TYPE_MBUF:
			long_return = mbstat.m_drops;
			break;
#endif
		default:
#if NO_DUMMY_VALUES
			return NULL;
#endif
			long_return = 0;
			break;
	    }
	    return (u_char *)&long_return;
	default:
	    DEBUGMSGTL(("snmpd", "unknown sub-id %d in var_hrstore\n", vp->magic));
    }
    return NULL;
}


	/*********************
	 *
	 *  Internal implementation functions
	 *
	 *********************/

static int FS_storage;
static int HRS_index;

void
Init_HR_Store (void)
{
   HRS_index = -1;
   Init_HR_FileSys();
   FS_storage = 1;	/* Start with file-based storage */
}

int
Get_Next_HR_Store(void)
{
		/* File-based storage */
    long_return = -1;
    if ( FS_storage == 1 ) {
	HRS_index = Get_Next_HR_FileSys();

        if ( HRS_index >= 0 ) 
            return HRS_index;
	FS_storage = 0;		/* End of filesystems */
	HRS_index = HRS_TYPE_FS_MAX;
    }

		/* 'Other' storage types */
    ++HRS_index;
#ifndef solaris2
    if ( HRS_index < HRS_TYPE_MAX )
	return HRS_index;
    else
#endif
	return -1;
}

#ifdef linux
int
linux_mem(int mem_type, 
	  int size_or_used)
{
    FILE *fp;
    char buf[100];
    int size = -1, used = -1;

    if ((fp = fopen( "/proc/meminfo", "r")) == NULL )
	return -1;

    while ( fgets( buf, sizeof(buf), fp ) != NULL ) {
	if (( !strncmp( buf, "Mem:", 4 ) && mem_type == HRS_TYPE_MEM ) ||
	    ( !strncmp( buf, "Swap:", 5 ) && mem_type == HRS_TYPE_SWAP )) {
		sscanf( buf, "%*s %d %d", &size, &used );
		break;
	}
    }

    fclose(fp);
    return ( size_or_used == HRSTORE_SIZE ? size : used )/1024;

}
#endif
