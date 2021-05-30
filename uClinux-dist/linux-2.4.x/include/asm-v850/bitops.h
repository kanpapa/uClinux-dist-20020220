/*
 * include/asm-v850/bitops.h -- Bit operations
 *
 *  Copyright (C) 2001  NEC Corporation
 *  Copyright (C) 2001  Miles Bader <miles@gnu.org>
 *  Copyright (C) 1992  Linus Torvalds.
 *
 * This file is subject to the terms and conditions of the GNU General
 * Public License.  See the file COPYING in the main directory of this
 * archive for more details.
 */

#ifndef __V850_BITOPS_H__
#define __V850_BITOPS_H__


#include <linux/config.h>
#include <asm/byteorder.h>	/* swab32 */
#include <asm/system.h>		/* save_flags */

#ifdef __KERNEL__

/*
 * The __ functions are not atomic
 */

extern void set_bit (int nr, volatile void *addr);
extern void __set_bit (int nr, volatile void *addr);
extern void clear_bit (int nr, volatile void *addr);
extern void change_bit (int nr, volatile void *addr);
extern void __change_bit (int nr, volatile void *addr);
extern int test_and_set_bit (int nr, volatile void *addr);
extern int __test_and_set_bit (int nr, volatile void *addr);
extern int test_and_clear_bit (int nr, volatile void *addr);
extern int __test_and_clear_bit (int nr, volatile void *addr);
extern int test_and_change_bit (int nr, volatile void *addr);
extern int __test_and_change_bit (int nr, volatile void *addr);
extern int __constant_test_bit (int nr, const volatile void *addr);
extern int __test_bit (int nr, volatile void *addr);
extern int find_first_zero_bit (void *addr, unsigned size);
extern int find_next_zero_bit (void *addr, int size, int offset);

/*
 * ffz = Find First Zero in word. Undefined if no zero exists,
 * so code should check against ~0UL first..
 */
extern __inline__ unsigned long ffz (unsigned long word)
{
	unsigned long result = 0;

	while (word & 1) {
		result++;
		word >>= 1;
	}
	return result;
}


/*
 * Note -- the following definitions generate warnings of the following
 * form:  `asm operand 0 probably doesn't match constraints', which are
 * certainly bogus, because they are all register constrainst, so any
 * operand should just be forced into a register.  However I don't know
 * how to disable the warning.
 */

extern __inline__ void set_bit (int nr, volatile void *addr)
{
	__asm__ __volatile__ ("set1 %0, [%1]"
			      : : "r" (nr & 0x7), "r" (addr + (nr >> 3)));
}

extern __inline__ void __set_bit (int nr, volatile void *addr)
{
	__asm__ __volatile__ ("set1 %0, [%1]"
			      : : "r" (nr & 0x7), "r" (addr + (nr >> 3)));
}

/*
 * clear_bit () doesn't provide any barrier for the compiler.
 */
#define smp_mb__before_clear_bit()	barrier ()
#define smp_mb__after_clear_bit()	barrier ()

extern __inline__ void clear_bit (int nr, volatile void *addr)
{
	__asm__ __volatile__ ("clr1 %0, [%1]"
			      : : "r" (nr & 0x7), "r" (addr + (nr >> 3)));
}

extern __inline__ void change_bit (int nr, volatile void *addr)
{
	__asm__ __volatile__ ("not1 %0, [%1]"
			      : : "r" (nr & 0x7), "r" (addr + (nr >> 3)));
}

extern __inline__ void __change_bit (int nr, volatile void *addr)
{
	__asm__ __volatile__ ("not1 %0, [%1]"
			      : : "r" (nr & 0x7), "r" (addr + (nr >> 3)));
}

extern __inline__ int test_and_set_bit (int nr, volatile void *addr)
{
	int res, flags;
	save_flags_cli (flags);
	__asm__ __volatile__ ("tst1 %1, [%2]; setf nz, %0; set1 %1, [%2]"
			      : "=&r" (res)
			      : "r" (nr & 0x7), "r" (addr + (nr >> 3)));
	restore_flags (flags);
	return res;
}

extern __inline__ int __test_and_set_bit (int nr, volatile void *addr)
{
	int res;
	__asm__ __volatile__ ("tst1 %1, [%2]; setf nz, %0; set1 %1, [%2]"
			      : "=&r" (res)
			      : "r" (nr & 0x7), "r" (addr + (nr >> 3)));
	return res;
}

extern __inline__ int test_and_clear_bit (int nr, volatile void *addr)
{
	int res, flags;
	save_flags_cli (flags);
	__asm__ __volatile__ ("tst1 %1, [%2]; setf nz, %0; clr1 %1, [%2]"
			      : "=&r" (res)
			      : "r" (nr & 0x7), "r" (addr + (nr >> 3)));
	restore_flags (flags);
	return res;
}

extern __inline__ int __test_and_clear_bit (int nr, volatile void *addr)
{
	int res;
	__asm__ __volatile__ ("tst1 %1, [%2]; setf nz, %0; clr1 %1, [%2]"
			      : "=&r" (res)
			      : "r" (nr & 0x7), "r" (addr + (nr >> 3)));
	return res;
}

extern __inline__ int test_and_change_bit (int nr, volatile void *addr)
{
	int res, flags;
	save_flags_cli (flags);
	__asm__ __volatile__ ("tst1 %1, [%2]; setf nz, %0; not1 %1, [%2]"
			      : "=&r" (res)
			      : "r" (nr & 0x7), "r" (addr + (nr >> 3)));
	restore_flags (flags);
	return res;
}

extern __inline__ int __test_and_change_bit (int nr, volatile void *addr)
{
	int res;
	__asm__ __volatile__ ("tst1 %1, [%2]; setf nz, %0; not1 %1, [%2]"
			      : "=&r" (res)
			      : "r" (nr & 0x7), "r" (addr + (nr >> 3)));
	return res;
}

/*
 * This routine doesn't need to be atomic.
 */
#define __constant_test_bit(nr, addr)					      \
  ({									      \
    int res;								      \
    __asm__ __volatile__ ("tst1 %1, %2[%3]; setf nz, %0"		      \
			  : "=r" (res)					      \
			  : "i" (nr & 0x7), "i" (nr >> 3), "r" (addr));	      \
    res;								      \
  })

extern __inline__ int __test_bit (int nr, volatile void *addr)
{
	int res;
	__asm__ __volatile__ ("tst1 %1, [%2]; setf nz, %0"
			      : "=r" (res)
			      : "r" (nr & 0x7), "r" (addr + (nr >> 3)));
	return res;
}

#define test_bit(nr,addr)						      \
  (__builtin_constant_p (nr)						      \
   ? __constant_test_bit ((nr), (addr))					      \
   : __test_bit ((nr), (addr)))

#define find_first_zero_bit(addr, size) \
  find_next_zero_bit ((addr), (size), 0)

extern __inline__ int find_next_zero_bit (void *addr, int size, int offset)
{
	unsigned long *p = ((unsigned long *) addr) + (offset >> 5);
	unsigned long result = offset & ~31UL;
	unsigned long tmp;

	if (offset >= size)
		return size;
	size -= result;
	offset &= 31UL;
	if (offset) {
		tmp = * (p++);
		tmp |= ~0UL >> (32-offset);
		if (size < 32)
			goto found_first;
		if (~tmp)
			goto found_middle;
		size -= 32;
		result += 32;
	}
	while (size & ~31UL) {
		if (~ (tmp = * (p++)))
			goto found_middle;
		result += 32;
		size -= 32;
	}
	if (!size)
		return result;
	tmp = *p;

 found_first:
	tmp |= ~0UL >> size;
 found_middle:
	return result + ffz (tmp);
}

#define ffs(x) generic_ffs (x)

/*
 * hweightN: returns the hamming weight (i.e. the number
 * of bits set) of a N-bit word
 */
#define hweight32(x) generic_hweight32 (x)
#define hweight16(x) generic_hweight16 (x)
#define hweight8(x) generic_hweight8 (x)

#define ext2_set_bit			test_and_set_bit
#define ext2_clear_bit			test_and_clear_bit
#define ext2_test_bit			test_bit
#define ext2_find_first_zero_bit	find_first_zero_bit
#define ext2_find_next_zero_bit		find_next_zero_bit

/* Bitmap functions for the minix filesystem.  */
#define minix_test_and_set_bit(nr,addr) test_and_set_bit (nr,addr)
#define minix_set_bit(nr,addr) set_bit (nr,addr)
#define minix_test_and_clear_bit(nr,addr) test_and_clear_bit (nr,addr)
#define minix_test_bit(nr,addr) test_bit (nr,addr)
#define minix_find_first_zero_bit(addr,size) find_first_zero_bit (addr,size)

#endif /* __KERNEL__ */

#endif /* __V850_BITOPS_H__ */
