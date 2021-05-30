/*****************************************************************************/

/*
 *	flatfs.c -- flat FLASH file-system.
 *
 *	(C) Copyright 1999, Greg Ungerer (gerg@lineo.com).

/*****************************************************************************/

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <dirent.h>
#include <unistd.h>
#include <errno.h>
#include <malloc.h>
#include <string.h>
#include <stdlib.h>

#include <sys/mount.h>

#include <linux/config.h>
#ifdef CONFIG_MTD
#include <linux/mtd/mtd.h>
#else
#include <linux/blkmem.h>
#endif

#include "flatfs.h"

/*****************************************************************************/

/*
 *	Globals for file and byte count.
 */
int	numfiles;
int	numbytes;
int	numdropped;

/*****************************************************************************/

/*
 *	Chechksum the contents of FLASH file.
 *	Pretty bogus check-sum really, but better than nothing :-)
 */

unsigned int chksum(unsigned char *sp, unsigned int len)
{
	unsigned int	chksum;
	unsigned char	*ep;

	for (chksum = 0, ep = sp + len; (sp < ep);)
		chksum += *sp++;
	return(chksum);
}

/*****************************************************************************/

/*
 *	Read the contents of a flat file-system and dump them out as
 *	regular files. Mmap would be nice, but alas...
 */

int flatread(char *flatfs)
{
	struct flathdr	hdr;
	int		version;
	struct flatent	ent;
	unsigned int	len, n, size, sum;
	int		fdflat, fdfile;
	char		filename[128];
	unsigned char	buf[1024];
	mode_t		mode;
#ifdef CONFIG_MTD
	mtd_info_t	mtd_info;
#endif
	char *confbuf, *confline, *confdata;
	time_t t;

	if (chdir(DSTDIR) < 0)
		return(-1);

	if ((fdflat = open(flatfs, O_RDONLY)) < 0)
		return(-1);
#ifdef CONFIG_MTD
	if (ioctl(fdflat, MEMGETINFO, &mtd_info) < 0)
		return(-2);
	len = mtd_info.size;
#else
	if (ioctl(fdflat, BMGETSIZEB, &len) < 0)
		return(-2);
#endif

	/* Check that header is valid */
	if (read(fdflat, (void *) &hdr, sizeof(hdr)) != sizeof(hdr))
		return(-3);

	if (hdr.magic == FLATFS_MAGIC) {
		version = 1;
	} else if (hdr.magic == FLATFS_MAGIC_V2) {
		version = 2;
	} else {
		fprintf(stderr, "flatfsd: invalid header magic\n");
		return(-5);
	}

	/* Check contents are valid */
	for (sum = 0, size = sizeof(hdr); (size < len); size += sizeof(buf)) {
		n = (size > sizeof(buf)) ? sizeof(buf) : size;
		if (read(fdflat, (void *) &buf[0], n) != n)
			return(-4);
		sum += chksum(&buf[0], n);
	}

	if (sum != hdr.chksum) {
		fprintf(stderr, "flatfsd: bad header checksum\n");
		return(-5);
	}

	if (lseek(fdflat, sizeof(hdr), SEEK_SET) < sizeof(hdr))
		return(-6);

	for (numfiles = 0, numbytes = 0; ; numfiles++) {
		/* Get the name of next file. */
		if (read(fdflat, (void *) &ent, sizeof(ent)) != sizeof(ent))
			return(-7);

		if (ent.filelen == FLATFS_EOF)
			break;

		n = ((ent.namelen + 3) & ~0x3);
		if (n > sizeof(filename))
			return(-8);

		if (read(fdflat, (void *) &filename[0], n) != n)
			return(-9);

		if (version >= 2) {
			if (read(fdflat, (void *) &mode, sizeof(mode)) != sizeof(mode))
				return(-7);
		} else {
			mode = 0644;
		}

		if (strcmp(filename, FLATFSD_CONFIG) == 0) {
			/* Read our special flatfsd config file into memory */
			confbuf = malloc(ent.filelen);
			if (!confbuf)
				return(-14);

			if (read(fdflat, confbuf, ent.filelen) != ent.filelen)
				return(-15);

			confline = strtok(confbuf, "\n");
			while (confline) {
				confdata = strchr(confline, ' ');
				if (confdata) {
					*confdata = '\0';
					confdata++;
					if (!strcmp(confline, "time")) {
						t = atol(confdata);
						if (t > time(NULL))
							stime(&t);
					}
				}
				confline = strtok(NULL, "\n");
			}
		}
		else {
			/* Write contents of file out for real. */
			fdfile = open(filename, (O_WRONLY | O_TRUNC | O_CREAT), mode);
			if (fdfile < 0)
				return(-10);
			
			for (size = ent.filelen; (size > 0); size -= n) {
				n = (size > sizeof(buf)) ? sizeof(buf) : size;
				if (read(fdflat, &buf[0], n) != n)
					return(-11);
				if (write(fdfile, (void *) &buf[0], n) != n)
					return(-12);
			}

			close(fdfile);
		}

		/* Read alignment padding */
		n = ((ent.filelen + 3) & ~0x3) - ent.filelen;
		if (read(fdflat, &buf[0], n) != n)
			return(-13);

		numbytes += ent.filelen;
	}

	close(fdflat);
	return(0);
}

/*****************************************************************************/

int writefile(char *name, char *buf, int len,
		unsigned int *psum, unsigned int *ptotal)
{
	struct stat	st;
	unsigned int size;
	int fdfile;
	struct flatent	*ent;

	/*
	 *	Write file entry into flat fs. Names and file
	 *	contents are aligned on long word boundaries.
	 *	They are padded to that length with zeros.
	 */
	if (stat(name, &st) < 0)
		return(-20);

	size = strlen(name) + 1;
	if (size > 128) {
		numdropped++;
		return(-21);
	}
	if ((st.st_size + size + sizeof(*ent) + 8) > (len - *ptotal)) {
		numdropped++;
		return(-22);
	}

	ent = (struct flatent *)(buf + *ptotal);
	ent->namelen = size;
	ent->filelen = st.st_size;
	*psum += chksum((char *)ent, sizeof(*ent));
	*ptotal += sizeof(*ent);

	/* Write file name out, with padding to align */
	memcpy(buf + *ptotal, name, size);
	*ptotal += size;
	*psum += chksum(name, size);
	size = ((size + 3) & ~0x3) - size;
	*ptotal += size;

	/* Write out the permissions */
	size = sizeof(st.st_mode);
	memcpy(buf + *ptotal, &st.st_mode, size);
	*ptotal += size;
	*psum += chksum((unsigned char *) &st.st_mode, size);

	/* Write the contents of the file. */
	size = st.st_size;
	if ((fdfile = open(name, O_RDONLY)) < 0)
		return(-23);
	if (read(fdfile, buf + *ptotal, size) != size) {
		close(fdfile);
		return(-24);
	}
	*psum += chksum(buf + *ptotal, size);
	*ptotal += size;
	close(fdfile);

	/* Pad to align */
	size = ((st.st_size + 3) & ~0x3)- st.st_size;
	*ptotal += size;

	numfiles++;
	numbytes += ent->filelen;

	return 0;
}

/*
 *	Write out the contents of the local directory to flat file-system.
 *	The writing process is not quite as easy as read. Use the usual
 *	write system call so that FLASH programming is done properly.
 */

int flatwrite(char *flatfs)
{
	FILE		*hfile;
	DIR		*dirp;
	struct dirent	*dp;
	struct flathdr	*hdr;
	unsigned int	sum, size, len, total, n;
	int		fdflat, pos, rc;
	unsigned char	*buf;
	struct flatent	*ent;
#ifdef CONFIG_MTD
	mtd_info_t	mtd_info;
	erase_info_t	erase_info;
#endif

	sum = 0;

	if (chdir(SRCDIR) < 0)
		return(-1);

	/* Open and get the size of the FLASH file-system. */
	if ((fdflat = open(flatfs, O_RDWR)) < 0)
		return(-2);

#ifdef CONFIG_MTD
	if (ioctl(fdflat, MEMGETINFO, &mtd_info) < 0) {
		close(fdflat);
		return(-3);
	}
	len = mtd_info.size;
#else
	if (ioctl(fdflat, BMGETSIZEB, &len) < 0) {
		close(fdflat);
		return(-3);
	}
	if (ioctl(fdflat, BMSGSIZE, &size) < 0) {
		close(fdflat);
		return(-4);
	}
#endif

	buf = malloc(len);
	if (!buf) {
		close(fdflat);
		return(-6);
	}
	memset(buf, 0, len);

	/* Write out contents of all files, skip over header */
	numfiles = 0;
	numbytes = 0;
	numdropped = 0;
	total = sizeof(*hdr);

	/* Create a special config file */
	hfile = fopen(FLATFSD_CONFIG, "w");
	if (!hfile) {
		rc = -7;
		goto cleanup;
	}
	fprintf(hfile, "time %ld\n", time(NULL));
	fclose(hfile);
	rc = writefile(FLATFSD_CONFIG, buf, len, &sum, &total);
	unlink(FLATFSD_CONFIG);
	if (rc < 0)
		goto cleanup;

	/* Scan directory */
	if ((dirp = opendir(".")) == NULL) {
		rc = -8;
		goto cleanup;
	}

	while ((dp = readdir(dirp)) != NULL) {

		if ((strcmp(dp->d_name, ".") == 0) ||
		    (strcmp(dp->d_name, "..") == 0))
			continue;

		rc = writefile(dp->d_name, buf, len, &sum, &total);
		if (rc < 0) {
			closedir(dirp);
			goto cleanup;
		}
	}

	closedir(dirp);

	/* Write the terminating entry */
	if (len - total < sizeof(*ent)) {
		rc = -9;
		goto cleanup;
	}
	ent = (struct flatent *)(buf + total);
	ent->namelen = FLATFS_EOF;
	ent->filelen = FLATFS_EOF;
	sum += chksum((char *)ent, sizeof(*ent));

	/* Construct header */
	hdr = (struct flathdr *)buf;
	hdr->magic = FLATFS_MAGIC_V2;
	hdr->chksum = sum;

	/* Erase the FLASH file-system. */
#ifdef CONFIG_MTD
	erase_info.start = 0;
	erase_info.length = len;
	if (ioctl(fdflat, MEMERASE, &erase_info) < 0) {
		rc = -10;
		goto cleanup;
	}
#else
	for (pos = len - size; (pos >= 0); pos -= size) {
		if (ioctl(fdflat, BMSERASE, pos) < 0) {
			rc = -10;
			goto cleanup;
		}
	}
#endif

	/* Write everything out */
	if (write(fdflat, buf, len) != len) {
		rc = -11;
		goto cleanup;
	}

	rc = 0;

 cleanup:
	free(buf);
	close(fdflat);
	return(rc);
}

/*****************************************************************************/
