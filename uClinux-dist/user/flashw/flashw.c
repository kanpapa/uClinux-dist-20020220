/*****************************************************************************/

/*
 *	flashw.c -- FLASH device writter.
 *
 *	(C) Copyright 1999-2001, Greg Ungerer (gerg@snapgear.com).
 *	(C) Copyright 2000-2001, Lineo Inc. (www.lineo.com)
 */

/*****************************************************************************/

#include <stdio.h>
#include <fcntl.h>
#include <getopt.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <linux/config.h>
#ifdef CONFIG_MTD
#include <linux/mtd/mtd.h>
#else
#include <linux/blkmem.h>
#endif

/*****************************************************************************/

char *version = "1.3.2";

/*****************************************************************************/

void usage(int rc)
{
	printf("usage: flashw [-h?vbpeul] [-o <offset>] (-f <file> | values) "
		"<rom-device>\n\n"
		"\t-h\t\tthis help\n"
		"\t-v\t\tprint version info\n"
		"\t-b\t\targs to written in binary\n"
		"\t-p\t\tpreserve existing FLASH contents\n"
		"\t-e\t\tdo not erase first\n"
		"\t-u\t\tunlock FLASH segments before programming\n"
		"\t-l\t\tlock FLASH segments when done\n"
		"\t-o <offset>\twrite into FLASH at offset\n"
		"\t-f <file>\tprogram contents of file\n\n");
	exit(rc);
}

/*****************************************************************************/

int mkbinbuf(char *str, char *buf, int len)
{
	int	pos;
	char	*ep, *sbuf;

	for (sbuf = buf, pos = 0; (pos < len); ) {
		*buf++ = strtol(str, &ep, 0);
		pos += (ep - str) + 1;
		str = ep + 1;
	}

	return(buf - sbuf);
}

/*****************************************************************************/

int main(int argc, char *argv[])
{
	int	fd, fdcp, binary, erase, preserve, dolock, dounlock;
	int	len, size, pos, end, i;
	long	offset;
	char	*file, *flashdev, *sp, *pbuf;
	char	buf[1024];
#ifdef CONFIG_MTD
	mtd_info_t	mtd_info;
	erase_info_t	erase_info;
#endif

	file = NULL;
	binary = 0;
	erase = 1;
	preserve = 0;
	offset = 0;
	dolock = 0;
	dounlock = 0;

	while ((pos = getopt(argc, argv, "h?bepulo:f:")) != EOF) {
		switch (pos) {
		case 'b':
			binary++;
			break;
		case 'f':
			file = optarg;
			break;
		case 'e':
			erase = 0;
			break;
		case 'p':
			preserve++;
			break;
		case 'u':
			dounlock++;
			break;
		case 'l':
			dolock++;
			break;
		case 'o':
			offset = strtol(optarg, NULL, 0);
			break;
		case 'v':
			printf("%s: version %s\n", argv[0], version);
			exit(0);
		case 'h':
		case '?':
			usage(0);
			break;
		default:
			usage(1);
			break;
		}
	}

	if (optind >= argc)
		usage(1);

	flashdev = argv[argc - 1];

	/* Open and size the FLASH device. */
	if ((fd = open(flashdev, O_RDWR)) < 0) {
		printf("ERROR: failed to open(%s), errno=%d\n",
			flashdev, errno);
		exit(1);
	}

#ifdef CONFIG_MTD
	if (ioctl(fd, MEMGETINFO, &mtd_info) < 0) {
		printf("ERROR: ioctl(MEMGETINFO) failed, errno=%d\n",
			errno);
		exit(1);
	}
	len = mtd_info.size;
	size = mtd_info.erasesize;
#else
	if (ioctl(fd, BMGETSIZEB, &len) < 0) {
		printf("ERROR: ioctl(BMGETSIZEB) failed, errno=%d\n",
			errno);
		exit(1);
	}
	if (ioctl(fd, BMSGSIZE, &size) < 0) {
		printf("ERROR: ioctl(BMSGSIZE) failed, errno=%d\n",
			errno);
		exit(1);
	}
#endif

	if (offset >= len) {
		printf("ERROR: offset=%d larger then FLASH size=%d\n",
			offset, len);
		exit(1);
	}

	/* Preserve FLASH contents if possible */
	pbuf = (char *) malloc(len);
	if (pbuf == (char *) NULL) {
		printf("ERROR: could not allocate %d bytes for "
			"preserve buffer, errno=\n", len, errno);
		exit(1);
	}
	if ((i = read(fd, pbuf, len)) != len) {
		printf("ERROR: could not read(%d bytes)=%d for "
			"preserve buffer, errno=%d\n", len, i, errno);
		exit(1);
	}

	/* Unlock and Erase each segment of FLASH in this device */
	if (erase) {
#ifdef CONFIG_MTD
		erase_info.start = 0;
		erase_info.length = size;
		/* Don't bother checking for failure here */
		if (dounlock)
			ioctl(fd, MEMUNLOCK, &erase_info);

		erase_info.start = 0;
		erase_info.length = size;
		if (ioctl(fd, MEMERASE, &erase_info) < 0) {
			printf("ERROR: ioctl(MEMERASE) failed, errno=%d\n",
				errno);
		}
#else
 		for (pos = len - size; (pos >= 0); pos -= size) {
 			if (ioctl(fd, BMSERASE, pos) < 0) {
 				printf("ERROR: ioctl(BMERASE) failed, pos=%x, "
					"errno=%d\n", pos, errno);
 			}
		}
#endif
	}

	/* Start reprogram from begining of FLASH */
	if (lseek(fd, 0, SEEK_SET) < 0) {
		printf("ERROR: lseek(offset=0) failed, errno=%d\n", errno);
		exit(1);
	}

	/* Write preserve buffer upto offset, or seek to offset */
	if (preserve) {
		if (write(fd, pbuf, offset) < offset) {
			printf("ERROR: preserve write(size=%d) failed, "
				"errno=%d\n", offset, errno);
		}
	} else {
		if (lseek(fd, offset, SEEK_SET) < 0) {
			printf("ERROR: lseek(offset=%d) failed, errno=%d\n",
				offset, errno);
			exit(1);
		}
	}

	/* All ready, now write out new contents */
	if (file != NULL) {
		if ((fdcp = open(file, O_RDONLY)) < 0) {
			printf("ERROR: failed to open(%s), errno=%d\n",
				file, errno);
			exit(1);
		}

		end = offset;
		while ((size = read(fdcp, buf, sizeof(buf))) > 0) {
			if (write(fd, buf, size) != size) {
				printf("ERROR: write(size=%d) failed, "
					"errno=%d\n", size, errno);
			}
			end += size;
		}

		close(fdcp);
	} else {
		end = offset;
		for (pos = optind; (pos < (argc - 1)); pos++) {
			sp = argv[pos];
			size = strlen(sp);
			if (binary) {
				size = mkbinbuf(sp, buf, size);
				sp = &buf[0];
			} else {
				sp[size++] = ' ';
			}
			if (write(fd, sp, size) != size) {
				printf("ERROR: write(size=%d) failed, "
					"errno=%d\n", size, errno);
			}
			end += size;
		}

		/* Put string terminator if not in binary mode */
		if (!binary) {
			sp = NULL;
			if (write(fd, &sp, 1) != 1) {
				printf("ERROR: write(size=1) of TERMINATOR "
					"failed, errno=%d\n",errno);
			}
			end++;
		}
	}

	/* Write remaining contents of preserve buffer */
	if (preserve) {
		if (write(fd, (pbuf + end), (len - end)) < (len - end)) {
			printf("ERROR: preserve write(size=%d) failed, "
				"errno=%d\n", (len - end), errno);
		}
	}

#ifdef CONFIG_MTD
	if (dolock) {
		erase_info.start = 0;
		erase_info.length = mtd_info.erasesize;
		if (ioctl(fd, MEMLOCK, &erase_info) < 0) {
			printf("ERROR: ioctl(MEMLOCK) failed, errno=%d\n",
				errno);
		}
  	}
#endif /* CONFIG_MTD */

	close(fd);
	exit(0);
}

/*****************************************************************************/
