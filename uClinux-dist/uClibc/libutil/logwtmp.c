/* Copyright (C) 1996, 1997 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Ulrich Drepper <drepper@cygnus.com>, 1996.

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
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <utmp.h>


void logwtmp (const char *line, const char *name, const char *host)
{
  struct utmp ut;
  struct flock lock;
  int ut_fd;


  /* Set information in new entry.  */
  memset (&ut, 0, sizeof (ut));
#if _HAVE_UT_PID - 0
  ut.ut_pid = getpid ();
#endif
#if _HAVE_UT_TYPE - 0
  ut.ut_type = name[0] ? USER_PROCESS : DEAD_PROCESS;
#endif
  strncpy (ut.ut_line, line, sizeof ut.ut_line);
  strncpy (ut.ut_name, name, sizeof ut.ut_name);
#if _HAVE_UT_HOST - 0
  strncpy (ut.ut_host, host, sizeof ut.ut_host);
#endif

#if _HAVE_UT_TV - 0
  gettimeofday (&ut.ut_tv, NULL);
#else
  time (&ut.ut_time);
#endif

/*  updwtmp (_PATH_WTMP, &ut); */
/* from tinylogin */

	if ((ut_fd = open(_PATH_WTMP, O_APPEND | O_WRONLY)) >= 0) {
		/* Lock the utmp file before updating */
		lock.l_type = F_WRLCK;
		lock.l_whence = SEEK_SET;
		lock.l_start = 0;
		lock.l_len = 0;
		if (fcntl(ut_fd, F_SETLK, &lock) >= 0) {
			write(ut_fd, (void *) &ut, sizeof(ut));
			/* Now unlock the utmp file */
			lock.l_type = F_UNLCK;
		}
		close(ut_fd);
	}


}
