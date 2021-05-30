

/*
 * $Id: recv-announce.c,v 1.20.8.1 2000/02/09 23:30:00 wessels Exp $
 *
 * DEBUG: section 0     Announcement Server
 * AUTHOR: Harvest Derived
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

#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <signal.h>

#define RECV_BUF_SIZE 8192

extern void xmemcpy(void *from, void *to, int len);

/*
 * This program must be run from inetd.  First add something like this
 * to /etc/services:
 * 
 * cached_announce 3131/udp             # cache announcements
 * 
 * And then add something like this to /etc/inetd/conf:
 * 
 * cached_announce dgram udp       wait cached /tmp/recv-announce recv-announce /tmp/recv-announce.log
 * 
 * 
 * A single instance of this process will continue to handle incoming
 * requests.  If it dies, or is killed, inetd should restart it when the
 * next message arrives.
 * 
 */

/* 
 * usage: recv-announce logfile
 */

static void
sig_handle(void)
{
    fflush(stdout);
    close(2);
    close(1);
    close(0);
    exit(0);
}


int
main(int argc, char *argv[])
{
    char buf[RECV_BUF_SIZE];
    struct sockaddr_in R;
    int len;
    struct hostent *hp = NULL;
    char logfile[BUFSIZ];
    char ip[4];

    for (len = 0; len < 32; len++) {
	signal(len, sig_handle);
    }


    if (argc > 1)
	strcpy(logfile, argv[1]);
    else
	strcpy(logfile, "/tmp/recv-announce.log");

    close(1);
    if (open(logfile, O_WRONLY | O_CREAT | O_APPEND, 0660) < 0) {
	perror(logfile);
	exit(1);
    }
    close(2);
    dup(1);


    for (;;) {
	memset(buf, '\0', RECV_BUF_SIZE);
	memset(&R, '\0', len = sizeof(R));

	if (recvfrom(0, buf, RECV_BUF_SIZE, 0, &R, &len) < 0) {
	    perror("recv");
	    exit(2);
	}
	xmemcpy(ip, &R.sin_addr.s_addr, 4);
	hp = gethostbyaddr(ip, 4, AF_INET);
	printf("==============================================================================\n");
	printf("Received from %s [%s]\n",
	    inet_ntoa(R.sin_addr),
	    (hp && hp->h_name) ? hp->h_name : "Unknown");
	fputs(buf, stdout);
	fflush(stdout);
    }
    return 0;
}
