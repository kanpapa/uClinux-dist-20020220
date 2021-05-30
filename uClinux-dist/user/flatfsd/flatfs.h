/*****************************************************************************/

/*
 *	flatfs.h -- support for flat FLASH file systems.
 *
 *	(C) Copyright 1999, Greg Ungerer (gerg@lineo.com).
 *	(C) Copyright 2000, Lineo Inc. (www.lineo.com)
 */

/*****************************************************************************/
#ifndef flatfs_h
#define flatfs_h
/*****************************************************************************/

/*
 *	Magic numbers used in flat file-system.
 */
#define	FLATFS_MAGIC	0xcafe1234
#define	FLATFS_MAGIC_V2	0xcafe2345
#define	FLATFS_EOF	0xffffffff

#define FLATFSD_CONFIG ".flatfsd"

/*
 *	Flat file-system header structure.
 */
struct flathdr {
	unsigned int	magic;
	unsigned int	chksum;
};

struct flatent {
	unsigned int	namelen;
	unsigned int	filelen;
};


/*
 *	Hardwire the source and destination directories :-(
 */
#define	DEFAULTDIR	"/etc/default"
#define	SRCDIR		"/etc/config"
#define	DSTDIR		SRCDIR

/*
 *	Globals for file and byte count.
 */
extern int	numfiles;
extern int	numbytes;
extern int	numdropped;

/*****************************************************************************/
#endif
