/*
 * arch/v850/lib/bcopy.c -- Memory copying
 *
 *  Copyright (C) 2001  NEC Corporation
 *  Copyright (C) 2001  Miles Bader <miles@gnu.org>
 *
 * This file is subject to the terms and conditions of the GNU General
 * Public License.  See the file COPYING in the main directory of this
 * archive for more details.
 *
 * Written by Miles Bader <miles@gnu.org>
 */

#include <linux/types.h>
#include <asm/string.h>

#define CHUNK_SIZE	32 /* bytes */
#define CHUNK_MASK	(CHUNK_SIZE - 1)

#define CHUNK_ALIGNED(addr)	(((unsigned long)addr & 0x3) == 0)

static inline void copy_chunks (const void *src, void *dst, unsigned num_chunks)
{
	for (; num_chunks; num_chunks--) {
		asm ("mov %0, ep;"
		     "sld.w 0[ep], r12; sld.w 4[ep], r13;"
		     "sld.w 8[ep], r14; sld.w 12[ep], r15;"
		     "sld.w 16[ep], r20; sld.w 20[ep], r17;"
		     "sld.w 24[ep], r18; sld.w 28[ep], r19;"
		     "mov %1, ep;"
		     "sst.w r12, 0[ep]; sst.w r13, 4[ep];"
		     "sst.w r14, 8[ep]; sst.w r15, 12[ep];"
		     "sst.w r20, 16[ep]; sst.w r17, 20[ep];"
		     "sst.w r18, 24[ep]; sst.w r19, 28[ep]"
		     :: "r" (src), "r" (dst)
		     : "r12", "r13", "r14", "r15", "r20", "r17", "r18", "r19",
		     "ep", "memory");
		src += CHUNK_SIZE;
		dst += CHUNK_SIZE;
	}
}

inline void *memcpy (void *dst, const void *src, __kernel_size_t count)
{
	if (count % CHUNK_SIZE ==0 && CHUNK_ALIGNED(src) && CHUNK_ALIGNED(dst))
		/* Copy large blocks efficiently.  */
		copy_chunks (src, dst, count / CHUNK_SIZE);
	else {
		char *_dst = dst;
		const char *_src = src;
		while (count--)
			*_dst++ = *_src++;
	}

	return dst;
}

char *bcopy (const char *src, char *dst, int count)
{
	return memcpy (dst, src, count);
}
