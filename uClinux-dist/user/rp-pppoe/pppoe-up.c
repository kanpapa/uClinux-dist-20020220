/*
 *	This little program just needs to prod diald with a message
 *	so that it nows what PPP interface came up, since it is run from
 *	pppd,  the FIFO env. var. is not set, so we pass in the fifo using
 *	ipparam.  The PPP setup you need is:
 *
 *		ip-up /bin/pppoe-up
 *		ipparam <fifo-filename>
 *
 *	arg0 - progname
 *	arg1 - ifname
 *	arg2 - devname
 *	arg3 - speed
 *	arg4 - local ip
 *	arg5 - remote ip
 *	arg6 - fifo
 *
 *  This program also execs /etc/config/firewall so that
 *  it can use the new IP address.
 *
 *	Copyright (C) 2000, Lineo (http://www.lineo.com)
 */

#include <stdio.h>
#include <fcntl.h>

#undef DEBUG
#ifdef DEBUG
#include <errno.h>
#include <syslog.h>
#endif

main(argc, argv)
	int		argc;
	char	*argv[];
{
	int		fd, n;
	char	cmd[80], *fifo;
	char	*execargv[3];

	if (argc < 7) {
#ifdef DEBUG
		syslog(LOG_INFO, "%s: need 7 args\n", argv[0]);
#endif
		exit(1);
	}

	fifo = argv[6];

	fd = open(fifo, O_WRONLY|O_NONBLOCK);
	if (fd == -1) {
#ifdef DEBUG
		syslog(LOG_INFO, "%s: open %d\n", argv[0], errno);
#endif
//		exit(2);
	}else{ /*assume we aren't running in always up mode*/
		fcntl(fd, F_SETFL, 0);
		strcpy(cmd, "interface ");
		strcat(cmd, argv[1]);
		strcat(cmd, "\n");
		n = write(fd, cmd, strlen(cmd));
#ifdef DEBUG
	if (n != strlen(cmd))
		syslog(LOG_INFO, "%s: write %d of %d (%d)\n", argv[0], n,
				strlen(cmd), errno);
#endif
	
		close(fd);
	}

	execargv[0] = "/bin/firewall";
	execargv[1] = NULL;
	execv("/bin/firewall", execargv);
#ifdef DEBUG
	syslog(LOG_INFO, "%s: exec /bin/firewall : %d", argv[0], errno);
#endif

	exit(0);
}

