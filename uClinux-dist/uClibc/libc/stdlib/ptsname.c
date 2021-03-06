/* Copyright (C) 1998 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Zack Weinberg <zack@rabi.phys.columbia.edu>, 1998.

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

#include <errno.h>
#include <paths.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <termios.h>
#include <unistd.h>

#if !defined UNIX98PTY_ONLY

/* Check if DEV corresponds to a master pseudo terminal device.  */
#define MASTER_P(Dev)                                                         \
  (major ((Dev)) == 2                                                         \
   || (major ((Dev)) == 4 && minor ((Dev)) >= 128 && minor ((Dev)) < 192)     \
   || (major ((Dev)) >= 128 && major ((Dev)) < 136))

/* Check if DEV corresponds to a master pseudo terminal device.  */
#define SLAVE_P(Dev)                                                          \
  (major ((Dev)) == 3                                                         \
   || (major ((Dev)) == 4 && minor ((Dev)) >= 192 && minor ((Dev)) < 256)     \
   || (major ((Dev)) >= 136 && major ((Dev)) < 144))

/* Note that major number 4 corresponds to the old BSD style pseudo
   terminal devices.  As of Linux 2.1.115 these are no longer
   supported.  They have been replaced by major numbers 2 (masters)
   and 3 (slaves).  */
     
/* The are declared in getpt.c.  */
extern const char _ptyname1[];
extern const char _ptyname2[];

#endif

/* Directory where we can find the slave pty nodes.  */
#define _PATH_DEVPTS "/dev/pts/"

extern char *__ultostr(char *buf, unsigned long uval, int base, int uppercase);

/* Store at most BUFLEN characters of the pathname of the slave pseudo
   terminal associated with the master FD is open on in BUF.
   Return 0 on success, otherwise an error number.  */
int ptsname_r (int fd, char *buf, size_t buflen)
{
  int save_errno = errno;
#if !defined UNIX98PTY_ONLY
  struct stat st;
#endif
  int ptyno;

  if (buf == NULL)
    {
      errno = EINVAL;
      return EINVAL;
    }

#if !defined UNIX98PTY_ONLY
  if (!isatty (fd))
    {
      errno = ENOTTY;
      return ENOTTY;
    }
#elif !defined TIOCGPTN
# error "UNIX98PTY_ONLY enabled but TIOCGPTN ioctl not supported by your kernel."
#endif
#ifdef TIOCGPTN
  if (ioctl (fd, TIOCGPTN, &ptyno) == 0)
    {
      /* Buffer we use to print the number in.  For a maximum size for
         `int' of 8 bytes we never need more than 20 digits.  */
      char numbuf[21];
      static const char devpts[] = _PATH_DEVPTS;
      char *p;

      numbuf[20] = '\0';
      p = __ultostr (&numbuf[sizeof numbuf - 1], ptyno, 10, 0);

      if (buflen < sizeof devpts + &numbuf[sizeof numbuf - 1] - p)
	{
	  errno = ERANGE;
	  return ERANGE;
	}

      strcpy (buf, devpts);
      strcat (buf, p);
    }
#endif
#if defined UNIX98PTY_ONLY
  else
    {
      /* If the ioctl fails it wasn't a Unix 98 master PTY */
      errno = ENOTTY;
      return ENOTTY;
    }
  /* Note: Don't bother with stat on the slave name and checking the
           driver's major device number - the ioctl above succeeded so
           we know the fd was a Unix'98 master and the /dev/pts/ prefix
           is set by definition.  If the name isn't really a slave PTY,
           the system is misconfigured anyway - something else will fail
           later.
   */
#else
# if !defined TIOCGPTN
  else if (errno == EINVAL)
# endif
    {
      char *p;

      if (buflen < strlen (_PATH_TTY) + 3)
	{
	  errno = ERANGE;
	  return ERANGE;
	}

      if (fstat (fd, &st) < 0)
	return errno;

      /* Check if FD really is a master pseudo terminal.  */
      if (! MASTER_P (st.st_rdev))
	{
	  errno = ENOTTY;
	  return ENOTTY;
	}

      ptyno = minor (st.st_rdev);
      /* This is for the old BSD pseudo terminals.  As of Linux
         2.1.115 these are no longer supported.  */
      if (major (st.st_rdev) == 4)
	ptyno -= 128;

      if (ptyno / 16 >= strlen (_ptyname1))
	{
	  errno = ENOTTY;
	  return ENOTTY;
	}

      strcpy (buf, _PATH_TTY);
      p = buf + strlen (buf);
      p[0] = _ptyname1[ptyno / 16];
      p[1] = _ptyname2[ptyno % 16];
      p[2] = '\0';
    }

  if (__xstat (_STAT_VER, buf, &st) < 0)
    return errno;

  /* Check if the name we're about to return really corresponds to a
     slave pseudo terminal.  */
  if (! S_ISCHR (st.st_mode) || ! SLAVE_P (st.st_rdev))
    {
      /* This really is a configuration problem.  */
      errno = ENOTTY;
      return ENOTTY;
    }
#endif

  errno = save_errno;
  return 0;
}

/* Return the pathname of the pseudo terminal slave assoicated with
   the master FD is open on, or NULL on errors.
   The returned storage is good until the next call to this function.  */
char *
ptsname (int fd)
{
  static char buffer[sizeof (_PATH_DEVPTS) + 20];

  return ptsname_r (fd, buffer, sizeof (buffer)) != 0 ? NULL : buffer;
}
