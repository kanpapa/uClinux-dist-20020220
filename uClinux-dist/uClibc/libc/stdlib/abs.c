/* Copyright (C) 1995,1996 Robert de Bath <rdebath@cix.compulink.co.uk>
 * This file is part of the Linux-8086 C library and is distributed
 * under the GNU Library General Public License.
 */
#include <unistd.h>
#include <string.h>
#include <sys/types.h>

int abs(int arg1)
{
	return arg1 > 0 ? arg1 : -arg1;
}

