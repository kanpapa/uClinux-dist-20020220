#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/mount.h>

/* $Id: doc_loadbios.c,v 1.5 2000/11/12 22:51:07 lethal Exp $ */
#include <linux/mtd/mtd.h>

unsigned char databuf[512];

int main(int argc,char **argv)
{
   mtd_info_t meminfo;
   int ifd,ofd;
   struct stat statbuf;
   erase_info_t erase;
   unsigned long retlen, ofs;

   if (argc < 3) {
	   fprintf(stderr,"You must specify a device and the source firmware file\n");
	   return 1;
   }
   
   // Open and size the device
   if ((ofd = open(argv[1],O_RDWR)) < 0) {
	   perror("Open flash device");
	   return 1;
   }
   
   if ((ifd = open(argv[2], O_RDONLY)) < 0) {
	   perror("Open firmware file\n");
	   close(ofd);
	   return 1;
   }
   
   if (fstat(ifd, &statbuf) != 0) {
	   perror("Stat firmware file");
	   close(ofd);
	   close(ifd);
	   return 1;
   }
   
#if 0
   if (statbuf.st_size > 65536) {
	   printf("Firmware too large (%ld bytes)\n",statbuf.st_size);
	   close(ifd);
	   close(ofd);
	   return 1;
   }
#endif   
     
   if (ioctl(ofd,MEMGETINFO,&meminfo) != 0) {
	   perror("ioctl(MEMGETINFO)");
	   close(ifd);
	   close(ofd);
	   return 1;
   }

   erase.length = meminfo.erasesize;

   for (ofs = 0 ; ofs < statbuf.st_size ; ofs += meminfo.erasesize) {
	   erase.start = ofs;
	   printf("Performing Flash Erase of length %lu at offset %lu\n",
		  erase.length, erase.start);
	   
	   if (ioctl(ofd,MEMERASE,&erase) != 0) {      
		   perror("ioctl(MEMERASE)");
		   close(ofd);
		   close(ifd);
		   return 1;
	   }
   }


   do {
	   retlen = read(ifd, databuf, 512);
	   if (retlen < 512)
	     memset(databuf+retlen, 0xff, 512-retlen);
	   write(ofd, databuf, 512);
   } while (retlen == 512);

   return 0;
}
