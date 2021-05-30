/*
 * fgetpwent.c - This file is part of the libc-8086/pwd package for ELKS,
 * Copyright (C) 1995, 1996 Nat Friedman <ndf@linux.mit.edu>.
 * 
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Library General Public
 *  License as published by the Free Software Foundation; either
 *  version 2 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Library General Public License for more details.
 *
 *  You should have received a copy of the GNU Library General Public
 *  License along with this library; if not, write to the Free
 *  Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#include <errno.h>
#include <stdio.h>
#include <pwd.h>
#include "config.h"

#define PWD_BUFFER_SIZE 256

/* file descriptor for the password file currently open */
static char line_buff[PWD_BUFFER_SIZE];
static struct passwd pwd;

int fgetpwent_r (FILE *file, struct passwd *password,
	char *buff, size_t buflen, struct passwd **crap)
{
	if (file == NULL) {
		__set_errno(EINTR);
		return -1;
	}
	return(__getpwent_r(password, buff, buflen, fileno(file)));
}

struct passwd *fgetpwent(FILE * file)
{
    if (fgetpwent_r(file, &pwd, line_buff, PWD_BUFFER_SIZE, NULL) != -1) {
	return &pwd;
    }
    return NULL;
}
