/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 * Based in part on code from sash, Copyright (c) 1999 by David I. Bell 
 * Permission has been granted to redistribute this code under the GPL.
 *
 */
#ifndef	_INTERNAL_H_
#define	_INTERNAL_H_

#include "Config.h"
#include <stdlib.h>
#include <utmp.h>
#include "pwd_grp/pwd.h"
#include "pwd_grp/grp.h"
#include "shadow_.h"
#ifdef TLG_FEATURE_MD5_PASSWORDS
# include "md5.h"
#endif
#ifdef TLG_FEATURE_SHA1_PASSWORDS
# include "sha1.h"
#endif
#include "shadow_.h"

#include <config/autoconf.h>

/* Some useful definitions */
#define FALSE   ((int) 1)
#define TRUE    ((int) 0)
#define FAIL_DELAY 3
#define TIMEOUT 60
#define NOLOGIN_FILE	    "/etc/nologin"
#ifndef CONFIG_USER_FLATFSD_FLATFSD
#define PASSWD_FILE	    "/etc/passwd"
#define GROUP_FILE	    "/etc/group"
#else
#define PASSWD_FILE	    "/etc/config/passwd"
#define GROUP_FILE	    "/etc/config/group"
#endif
#define _PATH_LOGIN	    "/bin/login"
#define CRYPT_EP_SIZE 13		/* Maximum encrypted password size */


enum Location {
	_TLG_DIR_ROOT = 0,
	_TLG_DIR_BIN,
	_TLG_DIR_SBIN,
	_TLG_DIR_USR_BIN,
	_TLG_DIR_USR_SBIN
};

struct Applet {
	const char *name;
	int (*main) (int argc, char **argv);
	enum Location location;
	int need_suid;
	const char *usage;
};

/* From busybox.c */
extern const struct Applet applets[];

/* Automagically pull in all the applet function prototypes and
 * applet usage strings.  These are all of the form:
 *	extern int foo_main(int argc, char **argv);
 *	extern const char foo_usage[];
 * These are all autogenerated from the set of currently defined applets. 
 */
#define PROTOTYPES
#include "applets.h"
#undef PROTOTYPES

extern const char *applet_name;


/* Utility routines */
extern const char *applet_name;
extern void usage(const char *usage) __attribute__ ((noreturn));
extern void error_msg(const char *s,

					  ...) __attribute__ ((format(printf, 1, 2)));
extern void error_msg_and_die(const char *s,
							  ...) __attribute__ ((noreturn,
												   format(printf, 1, 2)));
extern void perror_msg(const char *s,
					   ...) __attribute__ ((format(printf, 1, 2)));
extern void perror_msg_and_die(const char *s,
							   ...) __attribute__ ((noreturn,
													format(printf, 1, 2)));

extern char *pw_encrypt(const char *clear, const char *salt);
extern void addenv(const char *string, const char *value);
extern void *xmalloc(size_t size);
extern char *xstrdup(const char *s);
extern void initenv();
extern void checkutmp(int picky);
extern void updwtmp(const char *filename, const struct utmp *ut);
extern void set_env(int argc, char *const *argv);
extern void setutmp(const char *name, const char *line);
extern void setup_env(struct passwd *info);
extern void shell(char *file, char *arg);
extern struct spwd *pwd_to_spwd(const struct passwd *pw);
extern int update_passwd(const struct passwd *pw, char *crypt_pw);
extern int obscure(const char *old, const char *new,

				   const struct passwd *pwdp);


extern struct utmp utent;


#define STRFCPY(A,B) \
        (strncpy((A), (B), sizeof(A) - 1), (A)[sizeof(A) - 1] = '\0')

#include <strings.h>


#endif							/* _INTERNAL_H_ */
