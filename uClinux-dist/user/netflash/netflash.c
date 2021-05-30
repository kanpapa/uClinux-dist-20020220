/****************************************************************************/

/*
 * netflash.c:  network FLASH loader.
 *
 * Copyright (C) 1999-2001,  Greg Ungerer (gerg@snapgear.com)
 * Copyright (C) 2000-2001,  Lineo (www.lineo.com)
 *
 * Copied and hacked from rootloader.c which was:
 *
 * Copyright (C) 1998  Kenneth Albanowski <kjahds@kjahds.com>,
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <unistd.h>
#include <dirent.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/termios.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <linux/config.h>
#include <config/autoconf.h>
#ifdef CONFIG_MTD
#include <linux/mtd/mtd.h>
#else
#include <linux/blkmem.h>
#endif
#ifdef CONFIG_LEDMAN
#include <linux/ledman.h>
#endif
#ifdef CONFIG_USER_NETFLASH_DECOMPRESS
#include <zlib.h>
#endif
#ifdef CONFIG_MTD
#include <linux/jffs2.h>
#endif

#include "netflash.h"
#include "exit_codes.h"
#include "versioning.h"

/****************************************************************************/

#ifdef CONFIG_USER_NETFLASH_HMACMD5
#include "hmacmd5.h"
#define HMACMD5_OPTIONS "m:"
#else
#define HMACMD5_OPTIONS
#endif

#ifdef CONFIG_USER_NETFLASH_DECOMPRESS
#define DECOMPRESS_OPTIONS "z"
#else
#define DECOMPRESS_OPTIONS
#endif /*CONFIG_USER_NETFLASH_VERSION*/

#define CMD_LINE_OPTIONS "bc:Cd:fFhijklnr:tuv?" DECOMPRESS_OPTIONS HMACMD5_OPTIONS

#define DHCPCD_PID_FILE "/var/run/dhcpcd-eth0.pid"

#define CHECKSUM_LENGTH	4

/****************************************************************************/

char *version = "2.1.1";

struct fileblock_t *fileblocks = NULL;
int fileblocks_num = 0;

unsigned long file_offset = 0;
unsigned long file_length = 0;
unsigned long image_length = 0;
unsigned int calc_checksum = 0;

#define	BLOCK_OVERHEAD	16
#define	block_len	(_block_len - BLOCK_OVERHEAD)
int _block_len = 8192;

/*
 *	Indicate we want to throw away the image,
 *	use this to merely check version information. 
 */
int dothrow = 0;

extern int tftpverbose;
extern int ftpverbose;

FILE	*nfd;

#ifdef CONFIG_USER_NETFLASH_DECOMPRESS
z_stream z;
struct fileblock_t *zfb;
static int gz_magic[2] = {0x1f, 0x8b}; /* gzip magic header */
#endif

/****************************************************************************/

void restartinit(void)
{
	printf("netflash: restarting init process...\n");
	kill(1, SIGCONT);
}


void memcpy_withsum(void *dst, void *src, int len, unsigned int *sum)
{
	unsigned char *dp = (unsigned char *)dst;
	unsigned char *sp = (unsigned char *)src;

	while(len > 0){
		*dp = *sp;
		*sum += *dp++;
		sp++;
		len--;
	}
}


/*
 *	Note: This routine is more general than it currently needs to
 *	be since it handles out of order writes.
 */
void add_data(unsigned long address, unsigned char * data, unsigned long len)
{
	int l;
	struct fileblock_t *fb;
	struct fileblock_t *fbprev = NULL;
	struct fileblock_t *fbnew;

	/*printf("add_data(%lx:%lx)\n", address, len);*/

	/* The fileblocks list is ordered, so initialise this outside
	 * the while loop to save some search time. */
	fb=fileblocks;
	do {
		/* Search for any blocks that overlap with the range we are adding */
		for (; fb!=NULL; fbprev=fb, fb=fb->next) {
			if (address < fb->pos)
				break;
			
			if (address < (fb->pos + fb->maxlength)) {
				l = fb->maxlength - (address - fb->pos);
				if (l > len)
					l = len;
				memcpy_withsum(fb->data + (address - fb->pos),
					data, l, &calc_checksum);
				fb->length = l + (address - fb->pos);
				
				address += l;
				data += l;
				len -= l;
				if (len == 0)
					return;
			}
		}
	
		printf("."); fflush(stdout);

		/* At this point:
		 * fb = block following the range we are adding,
		 *      or NULL if at end
		 * fbprev = block preceding the range, or NULL if at start
		 */
#ifdef CONFIG_USER_NETFLASH_VERSION
		if (dothrow && fileblocks_num > 2) {
			/* Steal the first block from the list. */
			fbnew = fileblocks;
			fileblocks = fbnew->next;
			if (fbprev == fbnew)
				fbprev = NULL;

			fbnew->pos = address;

			if (fb && ((fb->pos - address) < fbnew->maxlength))
				fbnew->maxlength = fb->pos - address;

		} else {
#endif /*CONFIG_USER_NETFLASH_VERSION*/

			fbnew = malloc(sizeof(*fbnew));
			if (!fbnew) {
				printf("netflash: Insufficient memory for image!\n");
				exit(1);
			}
			
			fbnew->pos = address;

			for (;;) {
				if (fb && ((fb->pos - address) < block_len))
					fbnew->maxlength = fb->pos - address;
				else
					fbnew->maxlength = block_len;
			
				fbnew->data = malloc(fbnew->maxlength);
				if (fbnew->data)
					break;

				/* Halve the block size and try again, down to 1 page */
				if (_block_len < 4096) {
					printf("netflash: Insufficient memory for image!\n");
					exit(1);
				}
				_block_len /= 2;
			}

			fileblocks_num++;

#ifdef CONFIG_USER_NETFLASH_VERSION
		}
#endif

		l = fbnew->maxlength;
		if (l > len)
			l = len;
		memcpy_withsum(fbnew->data, data, l, &calc_checksum);
		fbnew->length = l;
		address += l;
		data += l;
		len -= l;
		
		fbnew->next = fb;
		if (fbprev)
			fbprev->next = fbnew;
		else
			fileblocks = fbnew;

		/* Next search starts after the block we just added */
		fbprev = fbnew;
	} while (len > 0);
}


/*
 *	Remove bytes from the end of the data. This is used to remove
 *	checksum/versioning data before writing or decompressing.
 */
void remove_data(int length)
{
	struct fileblock_t *fb;
	struct fileblock_t *fbnext;

	if (fileblocks != NULL && file_length >= length) {
		file_length -= length;
		for (fb = fileblocks; fb != NULL; fb = fb->next) {
			if ((fb->pos + fb->length) >= file_length)
				break;
		}
		fb->length = file_length - fb->pos;
		
		while (fb->next != NULL) {
			fbnext = fb->next;
			fb->next = fbnext->next;
			free(fbnext->data);
			free(fbnext);
		}
	}
}


/*
 *	Generate a checksum over the data.
 */
void chksum()
{
	unsigned char *sp, *ep;
	unsigned int l;
	unsigned int file_checksum;
	int i;
	struct fileblock_t *fb;

	file_checksum = 0;

	if (fileblocks != NULL && file_length >= CHECKSUM_LENGTH) {
		for (fb = fileblocks; fb != NULL; fb = fb->next) {
			if ((fb->pos + fb->length) >= (file_length - CHECKSUM_LENGTH)) {
				sp = fb->data + (file_length - CHECKSUM_LENGTH - fb->pos);
				break;
			}
		}
		
		ep = fb->data + fb->length;
		for (i = 0; i < CHECKSUM_LENGTH; i++) {
			if (sp >= ep) {
				fb = fb->next;
				sp = fb->data;
				ep = sp + fb->length;
			}
			file_checksum = (file_checksum << 8) | *sp;
			calc_checksum -= *sp;
			sp++;
		}

		remove_data(CHECKSUM_LENGTH);

		calc_checksum = (calc_checksum & 0xffff) + (calc_checksum >> 16);
		calc_checksum = (calc_checksum & 0xffff) + (calc_checksum >> 16);

		if (calc_checksum != file_checksum) {
			printf("netflash: bad image checksum=0x%04x, expected checksum=0x%04x\n",
					calc_checksum, file_checksum);
			exit(1);
		}
	}
	else {
		printf("netflash: image is too short to contain a checksum\n");
		exit(1);
	}
}


#ifdef CONFIG_USER_NETFLASH_HMACMD5
int check_hmac_md5(char *key)
{
	HMACMD5_CTX ctx;
	int length, total;
	unsigned char hash[16];
	int i;
	struct fileblock_t *fb;

	if (fileblocks != NULL && file_length >= 16) {
		HMACMD5Init(&ctx, key, strlen(key));

		total = 0;
		length = 0;
		for (fb = fileblocks; fb != NULL; fb = fb->next) {
			if (fb->length > (file_length - total - 16))
				length = file_length - total - 16;
			else
				length = fb->length;

			HMACMD5Update(&ctx, fb->data, length);

			total += length;
			if (length != fb->length)
				break;
		}

		HMACMD5Final(hash, &ctx);
		for (i=0; i<16; i++, length++) {
			if (length>=fb->length) {
				length = 0;
				fb = fb->next;
			}
			if (hash[i] != fb->data[length]) {
				printf("netflash: bad HMAC MD5 signature\n");
				exit(1);
			}
		}
		printf("netflash: HMAC MD5 signature okay\n");

		remove_data(16);
    }
}
#endif


#ifdef CONFIG_USER_NETFLASH_DECOMPRESS
/* Read the decompressed size from the gzip format */
int decompress_size()
{
    unsigned char *sp, *ep;
    int	i, total, size;
    struct fileblock_t *fb;

    /* Get a pointer to the start of the inflated size */
    total = 0;
    size = 0;
    if (fileblocks != NULL && file_length >= 4) {
		for (fb = fileblocks; fb != NULL; fb = fb->next) {
			if ((total + fb->length) >= (file_length - 4)) {
				sp = fb->data + (file_length - total - 4);
				break;
			}
			total += fb->length;
		}
		
		ep = fb->data + fb->length;
		for (i = 0; i < 4; i++) {
			if (sp >= ep) {
				fb = fb->next;
				sp = fb->data;
				ep = sp + fb->length;
			}
			size |= (*sp++) << (8*i);
		}
    }

    return size;
}


/*
 *	Skip bytes, ensuring at least 1 byte remains to be read.
 *	Don't use this to skip past the last byte in the file.
 */
int decompress_skip_bytes(int pos, int num)
{
    while (zfb) {
		if (pos + num < zfb->length)
			return pos + num;
		
		num -= zfb->length - pos;
		pos = 0;
		zfb = zfb->next;
    }
    printf("netflash: compressed image is too short\n");
    exit(1);
}


int decompress_init()
{
    int pos, flg, xlen, size;

    zfb = fileblocks;
    pos = 0;
	
    /* Skip over gzip header */
    pos = decompress_skip_bytes(pos, 2);
	
    if (zfb->data[pos] != 8) {
		printf("netflash: image is compressed, unknown compression method\n");
		exit(1);
    }
    pos = decompress_skip_bytes(pos, 1);
	
    flg = zfb->data[pos];
    pos = decompress_skip_bytes(pos, 1);
	
    /* Skip mod time, extended flag, and os */
    pos = decompress_skip_bytes(pos, 6);
	
    /* Skip extra field */
    if (flg & 0x04) {
		xlen = zfb->data[pos];
		pos = decompress_skip_bytes(pos, 1);
		xlen += zfb->data[pos]<<8;
		pos = decompress_skip_bytes(pos, 1+xlen);
    }
	
    /* Skip file name */
    if (flg & 0x08) {
		while (zfb->data[pos])
			pos = decompress_skip_bytes(pos, 1);
		pos = decompress_skip_bytes(pos, 1);
    }
	
    /* Skip comment */
    if (flg & 0x10) {
		while (zfb->data[pos])
			pos = decompress_skip_bytes(pos, 1);
		pos = decompress_skip_bytes(pos, 1);
    }
	
    /* Skip CRC */
    if (flg & 0x02) {
		pos = decompress_skip_bytes(pos, 2);
    }
	
    z.next_in = zfb->data + pos;
    z.avail_in = zfb->length - pos;
    z.zalloc = Z_NULL;
    z.zfree = Z_NULL;
    z.opaque = Z_NULL;
    if (inflateInit2(&z, -MAX_WBITS) != Z_OK) {
		printf("netflash: image is compressed, decompression failed\n");
		exit(1);
    }
    
    size = decompress_size();
    if (size <= 0) {
		printf("netflash: image is compressed, decompressed length is invalid\n");
		exit(1);
    }

    return size;
}


int decompress(char* data, int length)
{
    int rc;

    z.next_out = data;
    z.avail_out = length;

    for (;;) {
		rc = inflate(&z, Z_SYNC_FLUSH);
		
		if (rc == Z_OK) {
			if (z.avail_out == 0)
				return length;
			
			if (z.avail_in != 0) {
				/* Note: This shouldn't happen, but if it does then
				 * need to add code to add another level of buffering
				 * that we append file blocks to...
				 */
				printf("netflash: decompression deadlock\n");
				exit(1);
			}
			
			zfb = zfb->next;
			if (!zfb) {
				printf("netflash: unexpected end of file for decompression\n");
				exit(1);
			}
			z.next_in = zfb->data;
			z.avail_in = zfb->length;
		}
		else if (rc == Z_STREAM_END) {
			return length - z.avail_out;
		}
		else {
			printf("netflash: error during decompression: %x\n", rc);
			exit(1);
		}
    }
}

int check_decompression(int doinflate)
{
	if (doinflate) {
		if (fileblocks->length >= 2
				&& fileblocks->data[0] == gz_magic[0]
				&& fileblocks->data[1] == gz_magic[1]) {
			image_length = decompress_init();
			printf("netflash: image is compressed, decompressed length=%d\n",
					image_length);
		} else {
			printf("netflash: image is not compressed\n");
			exit(1);
		}
	}
#ifdef CONFIG_USER_NETFLASH_AUTODECOMPRESS
	else if (fileblocks->length >= 2
			&& fileblocks->data[0] == gz_magic[0]
			&& fileblocks->data[1] == gz_magic[1]) {
		doinflate = 1;
		image_length = decompress_init();
		printf("netflash: image is compressed, decompressed length=%d\n",
				image_length);
	}
#endif
	else {
		image_length = file_length;
	}

	return doinflate;
}
#endif

/****************************************************************************/

/*
 *	Local copies of the open/close/write used by tftp loader.
 *	The idea is that we get tftp to do all the work of getting
 *	the file over the network. The following code back ends
 *	that process, preparing the read data for FLASH programming.
 */
int local_creat(char *name, int flags)
{
	return(fileno(nfd));
}

FILE *local_fdopen(int fd, char *flags)
{
	return(nfd);
}

FILE *local_fopen(const char *name, const char *flags)
{
	return(nfd);
}

int local_fclose(FILE *fp)
{
	printf("\n");
	fflush(stdout);
	sleep(1);
	return(0);
}

int local_fseek(FILE *fp, int offset, int whence)
{
	/* Shouldn't happen... */
	return(0);
}

int local_putc(int ch, FILE *fp)
{
	/* Shouldn't happen... */
	return(0);
}

int local_write(int fd, char *buf, int count)
{
  add_data(file_offset, buf, count);
  file_offset += count;
  if (file_offset > file_length)
	  file_length = file_offset;
  return(count);
}

/****************************************************************************/
 
/*
 * Call to tftp. This will initialize tftp and do a get operation.
 * This will call the local_write() routine with the data that is
 * fetched, and it will create the ioctl structure.
 */
int tftpfetch(char *srvname, char *filename)
{
  char	*tftpargv[8];

  tftpverbose = 0;	/* Set to 1 for tftp trace info */

  tftpargv[0] = "tftp";
  tftpargv[1] = srvname;
  tftpmain(2, tftpargv);
  tftpsetbinary();
  
  printf("netflash: fetching file \"%s\" from %s\n", filename, srvname);
  tftpargv[0] = "get";
  tftpargv[1] = filename;
  tftpget(2, tftpargv);
  return(0);
}

/****************************************************************************/
 
/*
 * Call to ftp. This will initialize ftp and do a get operation.
 * This will call the local_write() routine with the data that is
 * fetched, and it will create the ioctl structure.
 */
int ftpconnect(char *srvname)
{
  char	*ftpargv[4];

#ifdef FTP
  ftpverbose = 0;	/* Set to 1 for ftp trace info */
  printf("netflash: login to remote host %s\n", srvname);

  ftpargv[0] = "ftp";
  ftpargv[1] = srvname;
  ftpmain(2, ftpargv);
  return(0);

#else
  printf("netflash: no ftp support builtin\n");
  return(-1);
#endif /* FTP */
}

int ftpfetch(char *srvname, char *filename)
{
  char	*ftpargv[4];

#ifdef FTP
  ftpverbose = 0;	/* Set to 1 for ftp trace info */
  printf("\nnetflash: ftping file \"%s\" from %s\n", filename, srvname);
  setbinary(); /* make sure we are in binary mode */

  ftpargv[0] = "get";
  ftpargv[1] = filename;
  get(2, ftpargv);

  quit();
  return(0);

#else
  printf("NETFLASH: no ftp support builtin\n");
  return(-1);
#endif /* FTP */
}

/****************************************************************************/

/*
 *	When fetching file we need to even number of bytes in write
 *	buffers. Otherwise FLASH programming will fail. This is mostly
 *	only a problem with http for some reason.
 */

int filefetch(char *filename)
{
  int fd, i, j;
  unsigned char buf[1024];

  if (strncmp(filename, "http://", 7) == 0)
    fd = openhttp(filename);
  else
    fd = open(filename, O_RDONLY);

  if (fd < 0)
    return(-1);

  for (;;) {
    printf(".");
    if ((i = read(fd, buf, sizeof(buf))) <= 0)
      break;
    if (i & 0x1) {
	/* Read more to make even sized buffer */
	if ((j = read(fd, &buf[i], 1)) > 0)
		i += j;
    }
    add_data(file_offset, buf, i);
	file_offset += i;
	file_length = file_offset;
  }

  close(fd);
  printf("\n");
  return(0);
}

/****************************************************************************/

/*
 *	Search for a process and send a signal to it.
 */
#if defined(CONFIG_JFFS_FS) || defined(CONFIG_JFFS2_FS)
void killprocname(char *name, int signo)
{
	DIR *dir;
	struct dirent *entry;
	FILE *f;
	char path[32];
	char line[64];

	dir = opendir("/proc");
	if (!dir)
		return;

	while ((entry = readdir(dir)) != NULL) {
		if (!isdigit(*entry->d_name))
			continue;

		sprintf(path, "/proc/%s/status", entry->d_name);
		if ((f = fopen(path, "r")) == NULL)
			continue;

		while (fgets(line, sizeof(line), f) != NULL) {
			if (line[strlen(line)-1] == '\n') {
				line[strlen(line)-1] = '\0';
				if (strncmp(line, "Name:\t", 6) == 0
						&& strcmp(line+6, name) == 0) {
					kill(atoi(entry->d_name), signo);
					fclose(f);
					closedir(dir);
					return;
				}
			}
		}

		fclose(f);
	}
	closedir(dir);
}
#endif

/****************************************************************************/

/*
 *  Read a process pid file and send a signal to it.
 */
void killprocpid(char *file, int signo)
{
    FILE* f;
    pid_t pid;
	char value[16];

    f = fopen(file, "r");
    if (f == NULL)
        return;

    if (fread(value, 1, sizeof(value), f) > 0) {
		pid = atoi(value);
		if (pid)
			kill(pid, signo);
        unlink(file);
    }
    fclose(f);
}

/****************************************************************************/

/*
 *	Find the current console device. We output trace to this device
 *	if it is the controlling tty at process start.
 */
char	*consolelist[] = {
	"/dev/console",
	"/dev/ttyS0",
	"/dev/cua0",
	"/dev/ttyS1",
	"/dev/cua1"
};

#define	clistsize	(sizeof(consolelist) / sizeof(char *))
 
char *getconsole(void)
{
	struct stat	myst, st;
	int		i;

	if (fstat(0, &myst) < 0)
		return((char *) NULL);

	for (i = 0; (i < clistsize); i++) {
		if (!stat(consolelist[i], &st) && 
				(myst.st_rdev == st.st_rdev))
			return(consolelist[i]);
	}
	return "/dev/null";
}

/****************************************************************************/

/*
 * Kill of processes now to reclaim some memory. Need this now so
 * we can buffer an entire firmware image...
 */
void kill_processes(char *console)
{
	int ttyfd;
	struct termios tio;

	if (console == NULL)
		console = getconsole();

	ttyfd = open(console, O_RDWR|O_NDELAY|O_NOCTTY);
	if (ttyfd >= 0) {
		if (tcgetattr(ttyfd, &tio) >= 0) {
			tio.c_cflag |= CLOCAL;
			tcsetattr(ttyfd, TCSAFLUSH, &tio);
		}
		close(ttyfd);
	}
	freopen(console, "w", stdout);
	freopen(console, "w", stderr);
	
	printf("netflash: killing tasks...\n");
	fflush(stdout);
	sleep(1);
	
	kill(1, SIGTSTP);		/* Stop init from reforking tasks */
	atexit(restartinit);		/* If exit prematurely, restart init */
	sync();

	signal(SIGTERM,SIG_IGN);	/* Don't kill ourselves... */
	setpgrp(); 			/* Don't let our parent kill us */
	sleep(1);
	signal(SIGHUP, SIG_IGN);	/* Don't die if our parent dies due to
					 * a closed controlling terminal */
	
	/*Don't take down network interfaces that use dhcpcd*/
	killprocpid(DHCPCD_PID_FILE, SIGKILL);

	kill(-1, SIGTERM);		/* Kill everything that'll die */
	sleep(1);			/* give em a moment... */

	if (console)
		freopen(console, "w", stdout);
}

/****************************************************************************/

#if defined(CONFIG_USER_MOUNT_UMOUNT) || defined(CONFIG_USER_BUSYBOX_UMOUNT)
void umount_all(void)
{
	char *localargv[4];
	int localargc;
	pid_t pid;
	int status;

	localargc = 0;
	localargv[localargc++] = "umount";
	localargv[localargc++] = "-a";
	localargv[localargc++] = "-r";
	localargv[localargc++] = NULL;
	pid = vfork();
	if (pid < 0) {
		printf("netflash: vfork() failed\n");
		exit(1);
	}
	else if (pid == 0) {
		execvp("/bin/umount", localargv);
		_exit(1);
	}
	waitpid(pid, &status, 0);
}
#endif

/****************************************************************************/

int usage(int rc)
{
  printf("usage: netflash [-bCfFhijklntuv"
#ifdef CONFIG_USER_NETFLASH_DECOMPRESS
	"z"
#endif
	"?] [-d <delay>] [-c <console-device>] [-r <flash-device>] "
#ifdef CONFIG_USER_NETFLASH_HMACMD5
	"[-m <hmac-md5-key>] "
#endif
	"[<net-server>] <file-name>\n\n"
	"\t-b\tdon't reboot hardware when done\n"
	"\t-C\tcheck that image was written correctly\n"
	"\t-f\tuse FTP as load protocol\n"
	"\t-F\tforce overwrite (do not preserve special regions)\n"
  	"\t-h\tprint help\n"
	"\t-i\tignore any version information\n"
	"\t-j\timage is a JFFS2 filesystem\n"
  	"\t-k\tdon't kill other processes\n"
  	"\t\t(ignored when root filesystem is inside flash)\n"
	"\t-l\tlock flash segments when done\n"
  	"\t-n\tfile with no checksum at end\n"
	"\t-t\tcheck the image and then throw it away \n"
	"\t-u\tunlock flash segments before programming\n"
  	"\t-v\tdisplay version number\n"
#ifdef CONFIG_USER_NETFLASH_DECOMPRESS
	"\t-z\tdecompress image before writing\n"
#endif
  );

  exit(rc);
}

/****************************************************************************/

int netflashmain(int argc, char *argv[])
{
	char *srvname, *filename;
	char *rdev, *console;
	char *sgdata, *check_buf;
	int rd, rc, tmpfd;
	int checkimage, preserveconfig, delay;
	int dochecksum, dokill, doreboot, doftp;
	int dopreserve, doversion, dolock, dounlock, dojffs2;
	int devsize, sgsize, sgpos, sglength;
	struct fileblock_t *fb, *fbprev;

#ifdef CONFIG_USER_NETFLASH_DECOMPRESS
	int doinflate;
#endif
#ifdef CONFIG_MTD
	mtd_info_t mtd_info, rootfs_info;
	erase_info_t erase_info;
#else
	struct blkmem_program_t *prog;
#endif
#ifdef CONFIG_LEDMAN
	int ledmancount = 0;
#endif
#ifdef CONFIG_USER_NETFLASH_HMACMD5
	char *hmacmd5key = NULL;
#endif

	rdev = "/dev/flash/image";
	srvname = NULL;
	filename = NULL;
	console = NULL;
	dochecksum = 1;
	dokill = 1;
	doreboot = 1;
	dolock = 0;
	dounlock = 0;
	delay = 0;
	doftp = 0;
	dothrow = 0;
	dopreserve = 1;
	preserveconfig = 0;
	checkimage = 0;
	dojffs2 = 0;

#ifdef CONFIG_USER_NETFLASH_VERSION
	doversion = 1;
#endif /*CONFIG_USER_NETFLASH_VERSION*/
#ifdef CONFIG_USER_NETFLASH_DECOMPRESS
	doinflate = 0;
#endif

	while ((rc = getopt(argc, argv, CMD_LINE_OPTIONS)) > 0) {
		switch (rc) {
		case 'b':
			doreboot = 0;
			break;
		case 'c':
			console = optarg;
			break;
		case 'C':
			checkimage = 1;
			break;
		case 'd':
			delay = (atoi(optarg));
			break;
		case 'f':
			doftp = 1;
			break;
		case 'F':
			dopreserve = 0;
			break;
		case 'i': 
			doversion = 0; 
			break;
		case 'j':
			dojffs2 = 1;
			break;
		case 'k':
			dokill = 0;
			break;
		case 'l':
			dolock++;
			break;
#ifdef CONFIG_USER_NETFLASH_HMACMD5
		case 'm':
			hmacmd5key = optarg;
			break;
#endif
		case 'n':
			dochecksum = 0;
			break;
		case 'r':
			rdev = optarg;
			break;
		case 't':
			dothrow = 1;
			break;
		case 'u':
			dounlock++;
			break;
		case 'v':
			printf("netflash: version %s\n", version);
			exit(0);
#ifdef CONFIG_USER_NETFLASH_DECOMPRESS
		case 'z':
			doinflate = 1;
			break;
#endif
		case 'h':
		case '?':
			usage(0);
			break;
		}
	}
  
#ifdef CONFIG_ROMFS_FROM_ROM
	if (!checkimage && !dothrow &&
	    (!strcmp(rdev, "/dev/flash/all") ||
	    !strcmp(rdev, "/dev/flash/image"))) {
		/*
		 *	We don't want to be writing over processes
		 *	executing in place
		 */
		dokill = 1;
	}
#endif /* CONFIG_ROMFS_FROM_ROM */
  
	if ((nfd = fopen("/dev/null", "rw")) == NULL) {
		fprintf(stderr, "netflash: failed to open(/dev/null)\n");
		exit(1);
	}

	if (optind == (argc - 1)) {
		srvname = NULL;
		filename = argv[optind];
	} else if (optind == (argc - 2)) {
		srvname = argv[optind++];
		filename = argv[optind];
	} else {
		usage(1);
	}

	if (delay > 0) {
		/* sleep the required time */
		printf("netflash: waiting %d seconds before updating "
			"flash...\n",delay);
		sleep(delay);
	}

	/*
	 *	Need to do any real FTP setup early, before killing processes
	 *	(and this losing association with the controlling tty).
	 */
	if (doftp) {
		if (ftpconnect(srvname))
			exit(1);
	}

	if (dokill)
		kill_processes(console);

	/*
	 * Open the flash device and allocate a segment sized block.
	 * This is the largest block we need to allocate, so we do
	 * it first to try to avoid fragmentation effects.
	 */
	if (dopreserve && (strcmp(rdev, "/dev/flash/image") == 0))
		preserveconfig = 1;

	rd = open(rdev, O_RDWR);
	if (rd < 0) {
		printf("netflash: open(%s)=%d failed (errno=%d)\n",
			rdev, rd, errno);
		exit(1);
	}
  
	devsize = 0;

#ifdef CONFIG_MTD
	if (ioctl(rd, MEMGETINFO, &mtd_info) < 0) {
		printf("netflash: ioctl(MEMGETINFO) failed, errno=%d\n", errno);
		exit(1);
	}
	devsize = mtd_info.size;
	sgsize = mtd_info.erasesize;

	/*
	 * NETtel/x86 boards that boot direct from INTEL FLASH also have a
	 * boot sector at the top of the FLASH. When programming complete
	 * images we need to not overwrite this.
	 */
	if (preserveconfig) {
		if ((tmpfd = open("/dev/flash/rootfs", O_RDONLY)) > 0) {
			if (ioctl(tmpfd, MEMGETINFO, &rootfs_info) >= 0) {
				if (rootfs_info.size & 0x000fffff)
					devsize = (devsize & 0xfff00000) |
						(rootfs_info.size & 0x000fffff);
			}
			close(tmpfd);
		}
	}
	/*
	 *	Unlock the segments to be reprogrammed...
	 */
	erase_info.start = 0;
	erase_info.length = mtd_info.size;
	/* Don't bother checking for failure */
	if (dounlock)
		ioctl(rd, MEMUNLOCK, &erase_info);
#else
	if (ioctl(rd, BMGETSIZEB, &devsize) != 0) {
		printf("netflash: ioctl(BMGETSIZEB) failed, errno=%d\n", errno);
		exit(1);
	}
	if (ioctl(rd, BMSGSIZE, &sgsize) != 0) {
		printf("netflash: ioctl(BMSGSIZE) failed, errno=%d\n", errno);
		exit(1);
	}
#endif

	sgdata = malloc(sgsize);
	if (!sgdata) {
		printf("netflash: Insufficient memory for image!\n");
		exit(1);
	}

	if (checkimage) {
		check_buf = malloc(sgsize);
		if (!check_buf) {
			printf("netflash: Insufficient memory for image!\n");
			exit(1);
		}
	}

	/*
	 * Initialize memory structure for FLASH image data.
	 */
#ifndef CONFIG_MTD
	prog = malloc(128);
	if (!prog) {
		printf("netflash: Unable to allocate memory\n");
		exit(1);
	}

	prog->magic1 = 0;
	prog->magic2 = 0;
	prog->blocks = 0;
	prog->reset = 0;
#endif

	fileblocks = NULL;
	file_offset = 0;
	file_length = 0;

	/*
	 * Fetch file into memory buffers. Exactly how depends on the exact
	 * load method. Support for tftp, http and local file currently.
	 */
	if (srvname) {
		if (doftp)
			ftpfetch(srvname, filename);
		else
			tftpfetch(srvname, filename);
	} else {
		if (filefetch(filename) < 0) {
			printf("netflash: failed to find %s\n", filename);
			exit(1);
		}
	}

	/*
	 * Do some checks on the data received
	 *    - starts at offset 0
	 *    - length > 0
	 *    - no holes
	 *    - checksum
	 */
	if (fileblocks == NULL) {
		printf("netflash: failed to load new image\n");
		exit(1);
	}

	if (!dothrow) {
		if (fileblocks->pos != 0) {
			printf("netflash: failed to load new image\n");
			exit(1);
		}
	}

	if (file_length == 0) {
		printf("netflash: failed to load new image\n");
		exit(1);
	}

	for (fb = fileblocks; fb->next != NULL; fb = fb->next) {
		if (fb->pos + fb->length != fb->next->pos) {
			printf("netflash: failed to load new image\n");
			exit(1);
		}
	}

	printf("netflash: got \"%s\", length=%d\n", filename, file_length);

#ifdef CONFIG_USER_NETFLASH_HMACMD5
	if (hmacmd5key)
		check_hmac_md5(hmacmd5key);
	else
#endif
	if (dochecksum)
		chksum();

	/*
	 * Check the version information.
	 * Side effect: this also checks whether version information is present,
	 * and if so, removes it, since it doesn't need to get written to flash.
	 */
	rc = check_vendor(vendor_name, product_name, image_version);

#ifdef CONFIG_USER_NETFLASH_VERSION
	if (doversion){
		switch (rc){
		case 1:
			printf("netflash: VERSION - product name incorrect.\n");
			exit(WRONG_PRODUCT);
		case 2:
			printf("netflash: VERSION - vendor name incorrect.\n");
			exit(WRONG_VENDOR);
#ifndef CONFIG_USER_NETFLASH_VERSION_ALLOW_CURRENT
		case 3:
			printf("netflash: VERSION - you are trying to upgrade "
				"with the same firmware\n"
				"         version that you already have.\n");
			exit(ALREADY_CURRENT);
#endif /* !CONFIG_USER_NETFLASH_VERSION_ALLOW_CURRENT */
#ifndef CONFIG_USER_NETFLASH_VERSION_ALLOW_OLDER
		case 4:
			printf("netflash: VERSION - you are trying to upgrade "
				"with an older version of\n"
				"         the firmware.\n");
			exit(VERSION_OLDER);
#endif /* !CONFIG_USER_NETFLASH_VERSION_ALLOW_OLDER */
		case 5:
			printf("netflash: VERSION - you are trying to load an "
				"image that does not\n         "
				"contain valid version information.\n");
			exit(NO_VERSION);
		case 0:
			default:
			break;
		}
	}
#endif /*CONFIG_USER_NETFLASH_VERSION*/

#ifdef CONFIG_USER_NETFLASH_DECOMPRESS
	doinflate = check_decompression(doinflate);
#else
	image_length = file_length;
#endif

	/* Check image that we fetched will actually fit in the FLASH device. */
	if (image_length > devsize) {
		printf("netflash: image too large for FLASH device (size=%d)\n",
			devsize);
		exit(1);
	}

	if(dothrow){
		printf("netflash: the image is good.\n");
		exit(0);
	}

#if defined(CONFIG_USER_MOUNT_UMOUNT) || defined(CONFIG_USER_BUSYBOX_UMOUNT)
	if (doreboot)
		umount_all();
#endif

#ifdef CONFIG_JFFS_FS
	/* Stop the JFFS garbage collector */
	killprocname("jffs_gcd", SIGSTOP);
#endif
#ifdef CONFIG_JFFS2_FS
	/* Stop the JFFS2 garbage collector */
	killprocname("jffs2_gcd_mtd1", SIGSTOP);
#endif

#if 0
{
	/* Check how much free memory we have */
	FILE* memfile;
	char buf[128];

	memfile = fopen("/proc/meminfo", "r");
	if (memfile) {
		while (fgets(buf, sizeof(buf), memfile))
			fputs(buf, stdout);
		fclose(memfile);
	}
}
#endif

	/*
	 * Program the FLASH device.
	 */
	fflush(stdout);
	sleep(1);

#ifdef CONFIG_LEDMAN
	ledman_cmd(LEDMAN_CMD_ALT_ON, LEDMAN_NVRAM_1);
	ledman_cmd(LEDMAN_CMD_ALT_ON, LEDMAN_NVRAM_2);
#endif

	/* Write the data one segment at a time */
	printf("netflash: programming FLASH device %s\n", rdev);
	fflush(stdout);
	fb = fileblocks;
	for (sgpos = 0; sgpos < devsize; sgpos += sgsize) {
		sglength = 0;

#ifdef CONFIG_USER_NETFLASH_DECOMPRESS
		if (doinflate) {
			sglength = decompress(sgdata, sgsize);
		} else {
#endif
		/* Copy the file blocks into the segment buffer */
		while (fb && (fb->pos < sgpos + sgsize)) {
			if (fb->pos + fb->length > sgpos + sgsize)
				sglength = sgsize;
			else
				sglength = fb->pos + fb->length - sgpos;
			  
			if (fb->pos < sgpos) {
				memcpy(sgdata, fb->data + (sgpos - fb->pos),
					sglength);
			} else {
				memcpy(sgdata + (fb->pos - sgpos), fb->data,
					sglength - (fb->pos - sgpos));
			}

			if (fb->pos + fb->length > sgpos + sgsize) {
				/*
				 * Need to keep fb pointing to this block
				 * for the start of the next segment.
				 */
				break;
			}
			fb = fb->next;
		}
#ifdef CONFIG_USER_NETFLASH_DECOMPRESS
		}
#endif

	if (checkimage) {
		if (lseek(rd, sgpos, SEEK_SET) != sgpos)
		  	printf("netflash: lseek(%x) failed\n", sgpos);
		if (read(rd, check_buf, sglength) < 0) {
			printf("netflash: read failed, pos=%x, errno=%d\n",
				sgpos, errno);
		} else if (memcmp(sgdata, check_buf, sglength) != 0) {
			int i;
			printf("netflash: check failed, pos=%x\n", sgpos);
			for (i = 0; i < sglength; i++) {
				if (sgdata[i] != check_buf[i])
					printf("%x(%x,%x) ", sgpos + i,
						sgdata[i] & 0xff,
						check_buf[i] & 0xff);
			}
			printf("\n");
		}
		continue;
	}

#if defined(CONFIG_NETtel) && defined(CONFIG_X86)
	if (!preserveconfig || sgpos < 0xe0000 || sgpos >= 0x100000) {
#endif

#ifdef CONFIG_MTD
		erase_info.start = sgpos;
		erase_info.length = sgsize;
		if (ioctl(rd, MEMERASE, &erase_info) < 0) {
			printf("netflash: ioctl(MEMERASE) failed, errno=%d\n",
				errno);
		} else if (sglength > 0) {
			if (lseek(rd, sgpos, SEEK_SET) != sgpos) {
				printf("netflash: lseek(%x) failed\n", sgpos);
			} else if (write(rd, sgdata, sglength) < 0) {
				printf("netflash: write() failed, pos=%x, "
					"errno=%d\n", sgpos, errno);
			}
		} else if (dojffs2) {
			static struct jffs2_unknown_node marker = {
					JFFS2_MAGIC_BITMASK,
					JFFS2_NODETYPE_CLEANMARKER,
					sizeof(struct jffs2_unknown_node),
					0xe41eb0b1
				};

			if (lseek(rd, sgpos, SEEK_SET) != sgpos) {
				printf("netflash: lseek(%x) failed\n", sgpos);
			} else if (write(rd, &marker, sizeof(marker)) < 0) {
				printf("netflash: write() failed, pos=%x, "
					"errno=%d\n", sgpos, errno);
			}
		}
#else
		prog->magic1 = BMPROGRAM_MAGIC_1;
		prog->magic2 = BMPROGRAM_MAGIC_2;
		prog->blocks = 1;
		prog->block[0].data = sgdata;
		prog->block[0].pos = sgpos;
		prog->block[0].length = sglength;
		prog->block[0].magic3 = BMPROGRAM_MAGIC_3;
		if (ioctl(rd, BMPROGRAM, prog) != 0) {
			printf("netflash: ioctl(BMPROGRAM) failed, "
				"errno=%d\n", errno);
		}
#endif

		printf("."); fflush(stdout);
#ifdef CONFIG_LEDMAN
		ledman_cmd(LEDMAN_CMD_OFF | LEDMAN_CMD_ALTBIT,
			ledmancount ? LEDMAN_NVRAM_1 : LEDMAN_NVRAM_2);
		ledman_cmd(LEDMAN_CMD_ON | LEDMAN_CMD_ALTBIT,
	 		ledmancount ? LEDMAN_NVRAM_2 : LEDMAN_NVRAM_1);
		ledmancount = (ledmancount + 1) & 1;
#endif

#if defined(CONFIG_NETtel) && defined(CONFIG_X86)
		} /* if (!preserveconfig || ...) */
#endif
	}

#ifdef CONFIG_LEDMAN
	printf("\n"); fflush(stdout);
	ledman_cmd(LEDMAN_CMD_ALT_OFF, LEDMAN_NVRAM_1);
	ledman_cmd(LEDMAN_CMD_ALT_OFF, LEDMAN_NVRAM_2);
#endif

	/* Put the flash back in read mode, some old boot loaders don't */
	lseek(rd, 0, SEEK_SET);
	read(rd, sgdata, 1);

#ifdef CONFIG_MTD
	if (dolock) {
		printf("netflash: locking flash segments...\n");
		erase_info.start = 0;
		erase_info.length = mtd_info.size;
		if (ioctl(rd, MEMLOCK, &erase_info) < 0)
			printf("netflash: ioctl(MEMLOCK) failed, errno=%d\n",
				errno);
	}
#endif /* CONFIG_MTD */

	if (doreboot) {
#if __GNU_LIBRARY__ > 5
		reboot(0x01234567);
#else
		reboot(0xfee1dead, 672274793, 0x01234567);
#endif
	}

	return 0;
}

/****************************************************************************/
