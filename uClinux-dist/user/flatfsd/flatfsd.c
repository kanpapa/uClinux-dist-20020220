/*****************************************************************************/

/*
 *	flatfsd.c -- Flat file-system daemon.
 *
 *	(C) Copyright 1999-2001, Greg Ungerer (gerg@lineo.com).
 *	(C) Copyright 2000-2001, Lineo Inc. (www.lineo.com)
 */

/*****************************************************************************/

#include <stdio.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include <linux/config.h>
#include <linux/ledman.h>

#ifdef CONFIG_MTD
#include <linux/mtd/mtd.h>
#else
#include <linux/blkmem.h>
#endif

/*****************************************************************************/

#define	FILEFS	"/dev/flash/config"

extern int	numfiles;
extern int	numbytes;

/*****************************************************************************/

static int run_usr1 = 0;
static int run_usr2 = 0;

/*****************************************************************************/

void block_sig(int blp) {
sigset_t sigs;
	sigemptyset(&sigs);
	sigaddset(&sigs, SIGUSR1);
	sigaddset(&sigs, SIGUSR2);
	sigprocmask(blp?SIG_BLOCK:SIG_UNBLOCK, &sigs, NULL);
}


void sigusr1(int signr)
{
	run_usr1 = 1;
}

void do_usr1(void)
{
#if !defined(CONFIG_JFFS_FS) && !defined(CONFIG_JFFS2_FS)
	int	rc;
#endif
	block_sig(1);
	run_usr1 = 0;

#if !defined(CONFIG_JFFS_FS) && !defined(CONFIG_JFFS2_FS)
	if ((rc = flatwrite(FILEFS)) < 0) {
		printf("FLATFSD: failed to write flatfs, err=%d errno=%d\n",
			rc, errno);
	}
#endif
	block_sig(0);
}

/*****************************************************************************/

/*
 *	Clear config filesystem and reboot.
 */

void sigusr2(int signr)
{
	run_usr2 = 1;
}

void do_usr2(void)
{
	int localargc = 0;
	char *localargv[2];

#if defined(CONFIG_JFFS_FS) || defined(CONFIG_JFFS2_FS)
	run_usr2 = 0;
	flatclean();
	sleep(1);
#else
	int		fdflat;
	char		 c;
 #if defined(CONFIG_MTD)
	mtd_info_t	mtd_info;
	erase_info_t	erase_info;
 #endif

	block_sig(1);
	run_usr2 = 0;

	if ((fdflat = open(FILEFS, O_RDWR)) >= 0) {
 #if defined(CONFIG_MTD)
		if (ioctl(fdflat, MEMGETINFO, &mtd_info) == 0) {
			erase_info.start = 0;
			erase_info.length = mtd_info.size;
			ioctl(fdflat, MEMERASE, &erase_info);
		}
 #else
		/* cheat and erase only the first sector */
		ioctl(fdflat, BMSERASE, 0);
 #endif

		/* Put flash back in read mode because some old boot loaders don't */
		read(fdflat, &c, 1);
	}
#endif

	/* Try to do a nice reboot */
	localargv[localargc++] = "reboot";
	localargv[localargc] = NULL;
	execvp("reboot", localargv);

	/* That failed, force reboot now */
#if __GNU_LIBRARY__ > 5
	reboot(0x01234567);
#else
	reboot(0xfee1dead, 672274793, 0x01234567);
#endif
	block_sig(0);
}

/*****************************************************************************/

int creatpidfile()
{
	FILE	*f;
	pid_t	pid;
	char	*pidfile = "/var/run/flatfsd.pid";

	pid = getpid();
	if ((f = fopen(pidfile, "w")) == NULL) {
		printf("FLATFSD: failed to open(%s), errno=%d\n",
			pidfile, errno);
		return(-1);
	}
	fprintf(f, "%d\n", pid);
	fclose(f);
	return(0);
}

/*****************************************************************************/

/*
 *	Lodge ourselves with the kernel LED manager. If it gets an
 *	interrupt from the reset switch it will send us a SIGUSR2.
 */
int register_resetpid(void)
{
#if defined(CONFIG_LEDMAN) && defined(LEDMAN_CMD_SIGNAL)
	int	fd;

	if ((fd = open("/dev/ledman", O_RDONLY)) < 0) {
		printf("FLATFSD: failed to open(/dev/ledman), errno=%d\n",
			errno);
		return(-1);
	}
	if (ioctl(fd, LEDMAN_CMD_SIGNAL, 0) < 0) {
		printf("FLATFSD: failed to register pid, errno=%d\n", errno);
		return(-2);
	}
	close(fd);
#endif
	return(0);
}

/*****************************************************************************/

void usage(int rc)
{
	printf("usage: flatfsd [-rh?]\n");
	exit(rc);
}

/*****************************************************************************/

int main(int argc, char *argv[])
{
	struct sigaction	act;
	int			rc, readonly;

	readonly = 0;

	if ((rc = getopt(argc, argv, "rh?")) != EOF) {
		switch(rc) {
		case 'r':
			readonly++;
			break;
		case 'h':
		case '?':
			usage(0);
			break;
		default:
			usage(1);
			break;
		}
	}

	if (readonly) {
#if defined(CONFIG_JFFS_FS) || defined(CONFIG_JFFS2_FS)
		if ((rc = flatfilecount()) < 0) {
			printf("FLATFSD: failed to count files?  "
				"err=%d errno=%d\n", rc, errno);
			exit(1);
		}
		printf("FLATFSD: %d files in flatfs\n", rc);
		if (rc == 0) {
			printf("FLATFSD: non-existent or bad flatfs, "
				"creating new one...\n");
			flatclean();
			if ((rc = flatnew()) < 0) {
				printf("FLATFSD: failed to create new flatfs, "
					"err=%d errno=%d\n", rc, errno);
				fflush(stdout);
				exit(1);
			}
		}
#else
		if ((rc = flatread(FILEFS)) < 0) {
			if (rc == -5) {
				printf("FLATFSD: non-existent or bad flatfs, "
					"creating new one...\n");
				flatclean();
				if ((rc = flatnew()) < 0) {
					printf("FLATFSD: failed to create new "
						"flatfs, err=%d errno=%d\n",
						rc, errno);
					fflush(stdout);
					exit(1);
				}
				do_usr1();
			} else {
				printf("FLATFSD: failed to read flatfs, err=%d "
					"errno=%d\n", rc, errno);
				fflush(stdout);
				exit(1);
			}
		}
		printf("FLATFSD: created %d configuration files (%d bytes)\n",
			numfiles, numbytes);
#endif /* CONFIG_JFFS_FS || CONFIG_JFFS2_FS */
		fflush(stdout);
		exit(0);
	}

	/*
	 *	Spin forever, waiting for a signal to write...
	 */
	creatpidfile();

	act.sa_handler = sigusr1;
	memset(&act.sa_mask, 0, sizeof(act.sa_mask));
	act.sa_flags = SA_RESTART;
	act.sa_restorer = 0;
	sigaction(SIGUSR1, &act, NULL);

	act.sa_handler = sigusr2;
	memset(&act.sa_mask, 0, sizeof(act.sa_mask));
	act.sa_flags = SA_RESTART;
	act.sa_restorer = 0;
	sigaction(SIGUSR2, &act, NULL);

	register_resetpid();

	for (;;) {
		if (run_usr1)
			do_usr1();
		else if (run_usr2)
			do_usr2();
		else
			pause();
	}
	exit(0);
}

/*****************************************************************************/
