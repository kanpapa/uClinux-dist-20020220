/* Copyright (C) 1991, 1994, 1996, 1997 Free Software Foundation, Inc.
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
   License along with the GNU C Library; see the file COPYING.LIB.  If not,
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.  */

#include <string.h>

/* Return the length of the maximum initial segment of S
   which contains no characters from REJECT.  */
size_t strcspn( const char *s, const char *reject)
{
    register const char *scan1;
    register const char *scan2;
    size_t count;

    count = 0;
    for (scan1 = s; *scan1 != '\0'; scan1++) {
	for (scan2 = reject; *scan2 != '\0';)       /* ++ moved down. */
	    if (*scan1 == *scan2++)
		return(count);
	count++;
    }
    return(count);
}

