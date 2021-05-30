#ifndef	__SHADOW_H
#define	__SHADOW_H

#include <sys/types.h>
#include <features.h>
#include <stdio.h>
#include <paths.h>

__BEGIN_DECLS

/* The spwd structure. */
struct spwd
{
	char *sp_namp;      /* Username. */
	char *sp_pwdp;      /* Password. */
	long int sp_lstchg; /* Date of last change. */
	long int sp_min;    /* Minimum number of days between changes. */
	long int sp_max;    /* Maximum number of days between changes. */
	long int sp_warn;   /* Number of days to warn user to change password. */
	long int sp_inact;  /* Number of days password may be expired before
	                     * becoming inactive. */
	long int sp_expire; /* Number of days since 1970-01-01 until account
	                     * expires. */
	long int sp_flag;   /* Reserved. */
};


extern int lckpwdf __P ((void));
extern int ulckpwdf __P ((void));

extern void setspent __P ((void));
extern void endspent __P ((void));
extern struct spwd * getspent __P ((void));

extern int putspent __P ((const struct spwd * __p, FILE * __f));

extern struct spwd * sgetspent __P ((const char*));
extern struct spwd * fgetspent __P ((FILE * file));

extern struct spwd * getspuid __P ((const uid_t));
extern struct spwd * getspnam __P ((const char *));


extern int getspent_r __P ((struct spwd *__restrict __resultbuf,
			    char *__restrict __buffer, size_t __buflen,
			    struct spwd **__restrict __result));
extern int getspuid_r __P ((uid_t __uid,
			    struct spwd *__restrict __resultbuf,
			    char *__restrict __buffer, size_t __buflen,
			    struct spwd **__restrict __result));
extern int getspnam_r __P ((const char *__restrict __name,
			    struct spwd *__restrict __resultbuf,
			    char *__restrict __buffer, size_t __buflen,
			    struct spwd **__restrict __result));
extern int sgetspent_r __P ((const char *__restrict __string,
			     struct spwd *__restrict __resultbuf,
			     char *__restrict __buffer, size_t __buflen,
			     struct spwd **__restrict __result));
extern int fgetspent_r __P ((FILE *__restrict __stream,
			     struct spwd *__restrict __resultbuf,
			     char *__restrict __buffer, size_t __buflen,
			     struct spwd **__restrict __result));

#ifdef _LIBC
/* These are used internally to uClibc */
extern int __sgetspent_r __P ((const char * string, struct spwd * spwd,
	char * line_buff, size_t buflen));
extern int __getspent_r __P ((struct spwd * spwd, char * line_buff, 
	size_t buflen, int spwd_fd));
#endif

__END_DECLS

#endif /* pwd.h  */



