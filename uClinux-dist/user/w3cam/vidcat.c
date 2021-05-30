/*
 * vidcat.c
 *
 * Copyright (C) 1998 - 2000 Rasca, Berlin
 * EMail: thron@gmx.de
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/types.h>
#include <linux/videodev.h>
#ifdef HAVE_LIBZ
#include <zlib.h>
#endif
#ifdef HAVE_LIBPNG
#include <png.h>
#endif
#ifdef HAVE_LIBJPEG
#include <jpeglib.h>
#endif

#define DEF_WIDTH	320
#define DEF_HEIGHT	240

#define FMT_UNKNOWN	0
#define FMT_PPM		1
#define FMT_PNG		2
#define FMT_JPEG	3

#define IN_TV			0
#define IN_COMPOSITE	1
#define IN_COMPOSITE2	2
#define IN_SVIDEO		3
#define IN_DEFAULT		8

#define NORM_PAL		0
#define NORM_NTSC		1
#define NORM_SECAM		2
#define NORM_DEFAULT	0

#define QUAL_DEFAULT	80

char *basename (const char *s);

/* globals
 */
static int verbose = 0;

/*
 */
void
usage (char *pname)
{
	fprintf (stderr,
	"VidCat, Version %s\n"
	"Usage: %s <options>\n"
	" -s NxN                      define size of the output image (default:"
		" %dx%d)\n"
	" -f {ppm|jpeg|png}           output format of the image\n"
	" -i {tv|comp1|comp2|s-video} which input channel to use\n"
	" -q <quality>                only for jpeg: quality setting (1-100,"
		" default: %d)\n"
	" -d <device>                 video device (default: "VIDEO_DEV")\n"
	" -l                          loop on, doesn't make sense in most cases\n"
	" -b                          make a raw PPM instead of an ASCII one\n"
	"Example: vidcat | xsetbg stdin\n",
		VERSION, (char*)basename(pname), DEF_WIDTH, DEF_HEIGHT, QUAL_DEFAULT);
	exit (1);
}

/*
 * read rgb image from v4l device
 * return: mmap'ed buffer and size
 */
char *
get_image (int dev, int width, int height, int input,int norm,int fmt,int *size)
{
	struct video_capability vid_caps;
	struct video_mbuf vid_buf;
	struct video_mmap vid_mmap;
	struct video_channel vid_chnl;
	char *map;
	int len;

	if (ioctl (dev, VIDIOCGCAP, &vid_caps) == -1) {
		perror ("ioctl (VIDIOCGCAP)");
		return (NULL);
	}
	if (input != IN_DEFAULT) {
		vid_chnl.channel = -1;
		if (ioctl (dev, VIDIOCGCHAN, &vid_chnl) == -1) {
			perror ("ioctl (VIDIOCGCHAN)");
		} else {
			vid_chnl.channel = input;
			vid_chnl.norm    = norm;
			if (ioctl (dev, VIDIOCSCHAN, &vid_chnl) == -1) {
				perror ("ioctl (VIDIOCSCHAN)");
				return (NULL);
			}
		}
	}
	if (ioctl (dev, VIDIOCGMBUF, &vid_buf) == -1) {
		/* to do a normal read()
		 */
		struct video_window vid_win;
		if (verbose) {
			fprintf (stderr, "using read()\n");
		}

		if (ioctl (dev, VIDIOCGWIN, &vid_win) != -1) {
			vid_win.width  = width;
			vid_win.height = height;
			if (ioctl (dev, VIDIOCSWIN, &vid_win) == -1)
				return (NULL);
		}

		map = malloc (width * height * 3);
		len = read (dev, map, width * height * 3);
		if (len <=  0) {
			free (map);
			return (NULL);
		}
		*size = 0;
		return (map);
	}

	map = mmap (0, vid_buf.size, PROT_READ|PROT_WRITE,MAP_SHARED,dev,0);
	if ((unsigned char *)-1 == (unsigned char *)map) {
		perror ("mmap()");
		return (NULL);
	}

	vid_mmap.format = fmt;
	vid_mmap.frame = 0;
	vid_mmap.width = width;
	vid_mmap.height =height;
	if (ioctl (dev, VIDIOCMCAPTURE, &vid_mmap) == -1) {
		perror ("VIDIOCMCAPTURE");
		munmap (map, vid_buf.size);
		return (NULL);
	}
	if (ioctl (dev, VIDIOCSYNC, &vid_mmap) == -1) {
		perror ("VIDIOCSYNC");
		munmap (map, vid_buf.size);
		return (NULL);
	}
	*size = vid_buf.size;
	return (map);
}

/*
 */
void
put_image_jpeg (char *image, int width, int height, int quality)
{
#ifdef HAVE_LIBJPEG
	int y, x, line_width;
	JSAMPROW row_ptr[1];
	struct jpeg_compress_struct cjpeg;
	struct jpeg_error_mgr jerr;
	char *line;

	line = malloc (width * 3);
	if (!line)
		return;
	cjpeg.err = jpeg_std_error(&jerr);
	jpeg_create_compress (&cjpeg);
	cjpeg.image_width = width;
	cjpeg.image_height= height;
	cjpeg.input_components = 3;
	cjpeg.in_color_space = JCS_RGB;
	jpeg_set_defaults (&cjpeg);

	jpeg_set_quality (&cjpeg, quality, TRUE);
	cjpeg.dct_method = JDCT_FASTEST;
	jpeg_stdio_dest (&cjpeg, stdout);

	jpeg_start_compress (&cjpeg, TRUE);

	row_ptr[0] = line;
	line_width = width * 3;
	for ( y = 0; y < height; y++) {
	for (x = 0; x < line_width; x+=3) {
			line[x]   = image[x+2];
			line[x+1] = image[x+1];
			line[x+2] = image[x];
		}
		jpeg_write_scanlines (&cjpeg, row_ptr, 1);
		image += line_width;
	}
	jpeg_finish_compress (&cjpeg);
	jpeg_destroy_compress (&cjpeg);
	free (line);
#endif
}

/*
 * write png image to stdout
 */
void
put_image_png (char *image, int width, int height)
{
#ifdef HAVE_LIBPNG
	int y;
	char *p;
	png_infop info_ptr;
	png_structp png_ptr = png_create_write_struct (PNG_LIBPNG_VER_STRING,
						NULL, NULL, NULL);
	if (!png_ptr)
		return;
	info_ptr = png_create_info_struct (png_ptr);
	if (!info_ptr)
		return;

	png_init_io (png_ptr, stdout);
	png_set_IHDR (png_ptr, info_ptr, width, height,
					8, PNG_COLOR_TYPE_RGB, PNG_INTERLACE_NONE,
					PNG_COMPRESSION_TYPE_DEFAULT, PNG_FILTER_TYPE_DEFAULT);
	png_set_bgr (png_ptr);
	png_write_info (png_ptr, info_ptr);
	p = image;
	for (y = 0; y < height; y++) {
		png_write_row (png_ptr, p);
		p+=width*3;
	}
	png_write_end (png_ptr, info_ptr);
#endif
}

/*
 * write ppm image to stdout
 */
void
put_image_ppm (char *image, int width, int height, int binary)
{
	int x, y, ls=0;
	unsigned char *p = (unsigned char *)image;
	if (!binary) {
	printf ("P3\n%d %d\n%d\n", width, height, 255);
	for (x = 0; x < width; x++) {
		for (y = 0; y < height; y++) {
			printf ("%03d %03d %03d  ", p[2], p[1], p[0]);
			p += 3;
			if (ls++ > 4) {
				printf ("\n");
				ls = 0;
			}
		}
	}
	printf ("\n");
	} else {
		unsigned char buff[3];
		printf ("P6\n%d %d\n%d\n", width, height, 255);
		for (x = 0; x < width * height; x++) {
			buff[0] = p[2];
			buff[1] = p[1];
			buff[2] = p[0];
			fwrite (buff, 1, 3, stdout);
			p += 3;
		}
	}
	fflush (stdout);
}

/*
 * main()
 */
int
main (int argc, char *argv[])
{
	int width = DEF_WIDTH, height = DEF_HEIGHT, size, dev = -1, c;
	char *image, *device = VIDEO_DEV;
	int max_try = 5;	/* we try 5 seconds/times to open the device */
	int quality = QUAL_DEFAULT;	/* default jpeg quality setting */
	int input = IN_DEFAULT;
	int norm  = NORM_DEFAULT;
	int palette = VIDEO_PALETTE_RGB24;
	int loop =0 ;
	int binary = 0;
#ifdef HAVE_LIBJPEG
	int format = FMT_JPEG;
#else
#ifdef HAVE_LIBPNG
	int format = FMT_PNG;
#else
	int format = FMT_PPM;
#endif
#endif

	while ((c = getopt (argc, argv, "bs:f:q:i:d:lv")) != EOF) {
		switch (c) {
			case 'b':
				binary = 1;
				break;
			case 'd':
				device = optarg;
				break;
			case 's':
				sscanf (optarg, "%dx%d", &width, &height);
				break;
			case 'f':
				if (strcasecmp ("ppm", optarg) == 0)
					format = FMT_PPM;
				else if (strcasecmp ("png", optarg) == 0)
					format = FMT_PNG;
				else if (strcasecmp ("jpeg", optarg) == 0)
					format = FMT_JPEG;
				else
					format = FMT_UNKNOWN;
				break;
			case 'q':
				sscanf (optarg, "%d", &quality);
				break;
			case 'i':
				if (strcasecmp ("tv", optarg) == 0) {
					input = IN_TV;
				} else if (strcasecmp ("comp1", optarg) == 0) {
					input = IN_COMPOSITE;
				} else if (strcasecmp ("comp2", optarg) ==0) {
					input = IN_COMPOSITE2;
				} else if (strcasecmp ("s-video", optarg) == 0) {
					input = IN_SVIDEO;
				}
				break;
			case 'l':
				loop = 1;
				break;
			case 'v':
				verbose++;
				break;
			default:
				usage (argv[0]);
				break;
		}
	}
again:
	/* open the video4linux device */
	while (max_try) {
		dev = open (device, O_RDWR);
		if (dev == -1) {
			if (!--max_try) {
				fprintf (stderr, "Can't open device %s\n", VIDEO_DEV);
				exit (0);
			}
			sleep (1);
		} else {
			break;
		}
	}
	image = get_image (dev, width, height, input, norm, palette, &size);
	if (!size)
		close (dev);
	if (image) {
		switch (format) {
			case FMT_PPM:
				put_image_ppm (image, width, height, binary);
				break;
			case FMT_PNG:
				put_image_png (image, width, height);
				break;
			case FMT_JPEG:
				put_image_jpeg (image, width, height, quality);
				break;
			default:
				fprintf (stderr, "Unknown format (%d)\n", format);
				break;
		}
		if (size) {
			munmap (image, size);
			close (dev);
		} else if (image) {
			free (image);
		}
		if (loop)
			goto again;
	} else {
		fprintf (stderr, "Error: Can't get image\n");
	}
	return (0);
}

