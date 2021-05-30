/*****************************************************************************/

/*
 *	setkey.c -- manual set crypto key program
 *
 *	(C) Copyright 2002, Greg Ungerer (gerg@snapgear.com).
 */

/*****************************************************************************/

#include <stdio.h>
#include <fcntl.h>
#include <getopt.h>
#include <errno.h>
#include <ctype.h>
#include <linux/key.h>

/*****************************************************************************/

void usage(int rc)
{
	printf("usage: setkey [-fh?] [-s <key>]\n\n"
		"\t-h?\t\tthis help\n"
		"\t-f\t\tfreshen the crypto key\n"
		"\t-s <key>\tset the crypto key\n");
	exit(rc);
}

/*****************************************************************************/

void printkey(unsigned char *kp, int size)
{
	printf("KEY: ");
	if (size <= 0) {
		printf("<EMPTY>\n");
	} else {
		printf("%02x", *kp++);
		for (size--; (size); size--)
			printf(":%02x", *kp++);
		printf("\n");
	}
}

/*****************************************************************************/

int main(int argc, char *argv[])
{
	unsigned char	rc4key[32];
	char		*kstr, *ep;
	int		get, set, freshen;
	int		c, i, nr;

	freshen = 0;
	get = 1;
	set = 0;
	kstr = NULL;

	while ((c = getopt(argc, argv, "?hfs:")) > 0) {
		switch (c) {
		case 's':
			set++;
			kstr = optarg;
			get = 0;
			break;
		case 'f':
			freshen++;
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

	if (set) {
		for (nr = 0; (nr < sizeof(rc4key)); ) {
			rc4key[nr] = strtol(kstr, &ep, 0);
			if (kstr == ep) {
				fprintf(stderr, "setkey: bad key string\n");
				exit(1);
			}
			nr++;
			if (*ep == '\0')
				break;
			kstr = ep + 1;
		}
		printkey(&rc4key, nr);
		if (setdriverkey(&rc4key, nr) < 0) {
			fprintf(stderr, "setkey: setdriverkey() failed, "
				"errno=%d\n", errno);
			exit(1);
		}
	}

	if (freshen) {
		if (freshendriverkey() < 0) {
			fprintf(stderr, "setkey: freshendriverkey() failed, "
				"errno=%d\n", errno);
			exit(1);
		}
	}

	if (get) {
		if ((nr = getdriverkey(rc4key, sizeof(rc4key))) < 0) {
			fprintf(stderr, "setkey: getdriverkey() failed, "
				"errno=%d\n", errno);
			exit(1);
		}
		printkey(&rc4key, nr);
	}

	return(0);
}

/*****************************************************************************/
