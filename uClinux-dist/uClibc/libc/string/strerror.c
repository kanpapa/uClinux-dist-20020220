/* Copyright (C) 1991, 1993, 1994 Free Software Foundation, Inc.
This file is part of the GNU C Library.

The GNU C Library is free software; you can redistribute it and/or
modify it under the terms of the GNU Library General Public License as
published by the Free Software Foundation; either version 2 of the
License, or (at your option) any later version.

The GNU C Library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Library General Public License for more details.

You should have received a copy of the GNU Library General Public
License along with the GNU C Library; see the file COPYING.LIB.  If
not, write to the Free Software Foundation, Inc., 675 Mass Ave,
Cambridge, MA 02139, USA.  */

/*
 * Manuel Novoa III       Dec 2000
 *
 * Converted to use my new (un)signed long (long) to string routines, which
 * are smaller than the previous functions and don't require static buffers.
 * Removed dependence on strcat in the process.
 *
 * Also appended a test routine ( -DCHECK_BUF ) to allow a quick check
 * on the buffer length when the sys_errorlist is modified.
 *
 * Added the option WANT_ERRORLIST for low-memory applications to omit the
 * error message strings and only output the error number.
 */

#define WANT_ERRORLIST     1

#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <limits.h>

#if (INT_MAX >> 31)
/* We're set up for 32 bit ints */
#error need to check size allocation for static buffer 'retbuf'
#endif

extern char *__ltostr(char *buf, long uval, int base, int uppercase);

#if WANT_ERRORLIST
static char retbuf[48];
#else
static char retbuf[33];			/* 33 is sufficient for 32 bit ints */
#endif
static const char unknown_error[] = "Unknown Error: errno"; /* = */

/* Return a string descibing the errno code in ERRNUM.
   The storage is good only until the next call to strerror.
   Writing to the storage causes undefined behavior.  */
char *strerror(int err)
{
	char *pos;

#if WANT_ERRORLIST
	if ((err >= 0) && (err < sys_nerr)) {
		strcpy(retbuf, sys_errlist[err]);
		return retbuf;
	}
#endif

	/* unknown error */
	pos = __ltostr(retbuf + sizeof(retbuf) + 1, err, 10, 0)
		- sizeof(unknown_error); /* leave space for the '=' */
	strcpy(pos, unknown_error);
	*(pos + sizeof(unknown_error) - 1) = '=';
	return pos;
}

#ifdef CHECK_BUF
/* quick way to check buffer length */
#include <stdio.h>
#include <stdlib.h>
int main(void)
{
	int max = 0;
	int j, retcode;
	char *p;
#if WANT_ERRORLIST
	int i;
#endif

	retcode = EXIT_SUCCESS;

#if WANT_ERRORLIST
	for ( i=0 ; i < sys_nerr ; i++ ) {
		j = strlen(sys_errlist[i])+1;
		if (j > max) max = j;
	}
#endif

	p = strerror(INT_MIN);
	j = strlen(p)+1;
	if (j > max) {
	    max = j;
	    printf("strerror.c - Test of INT_MIN: <%s>  %d\n", p, j);
	}

	if (sizeof(retbuf) != max) {
		printf("Error: strerror.c - dimension of retbuf should be = %d\n", max);
		retcode = EXIT_FAILURE;
	}
	printf("Passed.\n");

	return retcode;
}
#endif
