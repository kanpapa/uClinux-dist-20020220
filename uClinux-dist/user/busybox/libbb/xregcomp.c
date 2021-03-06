/* vi: set sw=4 ts=4: */
/*
 * Utility routines.
 *
 * Copyright (C) tons of folks.  Tracking down who wrote what
 * isn't something I'm going to worry about...  If you wrote something
 * here, please feel free to acknowledge your work.
 *
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

#include <stdio.h>
#include "libbb.h"
#include <ctype.h>
#include <stdlib.h>

#if !defined(__UC_LIBC__)
#include <regex.h>
void xregcomp(regex_t *preg, const char *regex, int cflags)
{
	int ret;
	if ((ret = regcomp(preg, regex, cflags)) != 0) {
		int errmsgsz = regerror(ret, preg, NULL, 0);
		char *errmsg = xmalloc(errmsgsz);
		regerror(ret, preg, errmsg, errmsgsz);
		error_msg_and_die("xregcomp: %s", errmsg);
	}
}
#else
#include <regexp.h>
void xregcomp(regexp **preg, const char *reg, int cflags)
{
	regexp *ret;
	const char *r;
	r = reg;
	if (cflags)
		error_msg_and_die("xregcomp: no support for -i");
	ret = regcomp(r);
	if (ret == NULL) {
		regerror("cannot compile expression");
		exit(1);
	}
	*preg = ret;
}
#endif

/* END CODE */
/*
Local Variables:
c-file-style: "linux"
c-basic-offset: 4
tab-width: 4
End:
*/
