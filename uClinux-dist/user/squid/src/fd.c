
/*
 * $Id: fd.c,v 1.37.2.1 2000/02/09 23:29:55 wessels Exp $
 *
 * DEBUG: section 51    Filedescriptor Functions
 * AUTHOR: Duane Wessels
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by the
 *  National Science Foundation.  Squid is Copyrighted (C) 1998 by
 *  the Regents of the University of California.  Please see the
 *  COPYRIGHT file for full details.  Squid incorporates software
 *  developed and/or copyrighted by other sources.  Please see the
 *  CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */

#include "squid.h"

const char *fdTypeStr[] =
{
    "None",
    "Log",
    "File",
    "Socket",
    "Pipe",
    "Unknown"
};

static void fdUpdateBiggest(int fd, int);

static void
fdUpdateBiggest(int fd, int opening)
{
    if (fd < Biggest_FD)
	return;
    assert(fd < Squid_MaxFD);
    if (fd > Biggest_FD) {
	/*
	 * assert that we are not closing a FD bigger than
	 * our known biggest FD
	 */
	assert(opening);
	Biggest_FD = fd;
	return;
    }
    /* if we are here, then fd == Biggest_FD */
    /*
     * assert that we are closing the biggest FD; we can't be
     * re-opening it
     */
    assert(!opening);
    while (!fd_table[Biggest_FD].flags.open)
	Biggest_FD--;
}

void
fd_close(int fd)
{
    fde *F = &fd_table[fd];
    if (F->type == FD_FILE) {
	assert(F->read_handler == NULL);
	assert(F->write_handler == NULL);
    }
    debug(51, 3) ("fd_close FD %d %s\n", fd, F->desc);
    F->flags.open = 0;
    fdUpdateBiggest(fd, 0);
    Number_FD--;
    commUpdateReadBits(fd, NULL);
    commUpdateWriteBits(fd, NULL);
    memset(F, '\0', sizeof(fde));
    F->timeout = 0;
}

void
fd_open(int fd, unsigned int type, const char *desc)
{
    fde *F = &fd_table[fd];
    assert(fd >= 0);
#if USE_ASYNC_IO
    if (F->flags.closing) {
	/* Reuse of a closed FD before we have noticed it is closed */
	fd_close(fd);
    }
#endif
    if (F->flags.open) {
	debug(51, 1) ("WARNING: Closing open FD %4d\n", fd);
	fd_close(fd);
    }
    assert(!F->flags.open);
    debug(51, 3) ("fd_open FD %d %s\n", fd, desc);
    F->type = type;
    F->flags.open = 1;
    fdUpdateBiggest(fd, 1);
    if (desc)
	xstrncpy(F->desc, desc, FD_DESC_SZ);
    Number_FD++;
}

void
fd_note(int fd, const char *s)
{
    fde *F = &fd_table[fd];
    xstrncpy(F->desc, s, FD_DESC_SZ);
}

void
fd_bytes(int fd, int len, unsigned int type)
{
    fde *F = &fd_table[fd];
    if (len < 0)
	return;
    assert(type == FD_READ || type == FD_WRITE);
    if (type == FD_READ)
	F->bytes_read += len;
    else
	F->bytes_written += len;
}

void
fdFreeMemory(void)
{
    safe_free(fd_table);
}

void
fdDumpOpen(void)
{
    int i;
    fde *F;
    for (i = 0; i < Squid_MaxFD; i++) {
	F = &fd_table[i];
	if (!F->flags.open)
	    continue;
	if (i == fileno(debug_log))
	    continue;
	debug(51, 1) ("Open FD %-10s %4d %s\n",
	    F->bytes_read && F->bytes_written ? "READ/WRITE" :
	    F->bytes_read ? "READING" :
	    F->bytes_written ? "WRITING" : null_string,
	    i, F->desc);
    }
}

int
fdNFree(void)
{
    return Squid_MaxFD - Number_FD - Opening_FD;
}

/* Called when we runs out of file descriptors */
void
fdAdjustReserved(void)
{
    int new;
    int x;
    static time_t last = 0;
    /*
     * don't update too frequently
     */
    if (last + 5 > squid_curtime)
	return;
    /*
     * Calculate a new reserve, based on current usage and a small extra
     */
    new = Squid_MaxFD - Number_FD + XMIN(25, Squid_MaxFD / 16);
    if (new <= RESERVED_FD)
	return;
    x = Squid_MaxFD - 20 - XMIN(25, Squid_MaxFD / 16);
    if (new > x) {
	/* perhaps this should be fatal()? -DW */
	debug(51, 0) ("WARNING: This machine has a serious shortage of filedescriptors.\n");
	new = x;
    }
    debug(51, 0) ("Reserved FD adjusted from %d to %d due to failures\n",
	RESERVED_FD, new);
    RESERVED_FD = new;
}
