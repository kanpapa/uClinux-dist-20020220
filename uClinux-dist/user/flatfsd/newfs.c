/*****************************************************************************/

/*
 *	newfs.c -- create new flat FLASH file-system.
 *
 *	(C) Copyright 1999, Greg Ungerer (gerg@lineo.com).
 *	(C) Copyright 2000, Lineo Inc. (www.lineo.com)
 */

/*****************************************************************************/

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <dirent.h>
#include <unistd.h>
#include <errno.h>

#include "flatfs.h"

/*****************************************************************************/

/*
 *	Count the number of files in the config area.
 */

int flatfilecount(void)
{
	DIR		*dirp;
	struct dirent	*dp;
	int		numfiles = 0;

	if (chdir(SRCDIR) < 0)
		return(-1);

	/* Scan directory */
	if ((dirp = opendir(".")) == NULL)
		return(-2);

	while ((dp = readdir(dirp)) != NULL) {
		if ((strcmp(dp->d_name, ".") == 0) ||
		    (strcmp(dp->d_name, "..") == 0))
			continue;
		numfiles++;
	}

	closedir(dirp);
	return(numfiles);
}

/*****************************************************************************/

/*
 *	Remove all files from the config file-system.
 */

int flatclean(void)
{
	DIR		*dirp;
	struct dirent	*dp;

	if (chdir(SRCDIR) < 0)
		return(-1);

	/* Scan directory */
	if ((dirp = opendir(".")) == NULL)
		return(-2);

	while ((dp = readdir(dirp)) != NULL) {
		if ((strcmp(dp->d_name, ".") == 0) ||
		    (strcmp(dp->d_name, "..") == 0))
			continue;
		unlink(dp->d_name);
	}

	closedir(dirp);
	return(0);
}

/*****************************************************************************/

/*
 *	This is basically just a directory copy. Copy all files from the
 *	default directory to the config directory.
 */

int flatnew(void)
{
	DIR		*dirp;
	struct stat	st;
	struct dirent	*dp;
	unsigned int	size, n;
	int		fddefault, fdconfig;
	char		filename[512];
	unsigned char	buf[1024];

	if (chdir(DEFAULTDIR) < 0)
		return(-1);

	/* Scan directory */
	if ((dirp = opendir(".")) == NULL)
		return(-2);

	numfiles = 0;
	numbytes = 0;
	numdropped = 0;

	while ((dp = readdir(dirp)) != NULL) {

		if ((strcmp(dp->d_name, ".") == 0) ||
		    (strcmp(dp->d_name, "..") == 0))
			continue;

		if (stat(dp->d_name, &st) < 0)
			return(-3);

		strcpy(filename, SRCDIR);
		strcat(filename, "/");
		strcat(filename, dp->d_name);

		/* Write the contents of the file. */
		if ((fddefault = open(dp->d_name, O_RDONLY)) < 0)
			return(-4);
		fdconfig = open(filename, O_WRONLY | O_TRUNC | O_CREAT, st.st_mode);
		if (fdconfig < 0)
			return(-5);

		for (size = st.st_size; (size > 0); size -= n) {
			n = (size > sizeof(buf)) ? sizeof(buf) : size;
			if (read(fddefault, &buf[0], n) != n)
				break;
			if (write(fdconfig, (void *) &buf[0], n) != n)
				break;
		}
		close(fdconfig);
		close(fddefault);

		if (size > 0) {
			numdropped++;
		} else {
			numfiles++;
			numbytes += st.st_size;
		}
	}

	closedir(dirp);
	return(0);
}

/*****************************************************************************/
