/*
 * include/asm-v850/posix_types.h -- Kernel versions of standard types
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

#ifndef __V850_POSIX_TYPES_H__
#define __V850_POSIX_TYPES_H__

typedef unsigned int	__kernel_dev_t;
typedef unsigned long	__kernel_ino_t;
typedef unsigned int	__kernel_mode_t;
typedef unsigned int	__kernel_nlink_t;
typedef long		__kernel_off_t;
typedef int		__kernel_pid_t;
typedef unsigned short	__kernel_ipc_pid_t;
typedef unsigned int	__kernel_uid_t;
typedef unsigned int	__kernel_gid_t;
typedef unsigned int	__kernel_size_t;
typedef int		__kernel_ssize_t;
typedef int		__kernel_ptrdiff_t;
typedef long		__kernel_time_t;
typedef long		__kernel_suseconds_t;
typedef long		__kernel_clock_t;
typedef int		__kernel_daddr_t;
typedef char *		__kernel_caddr_t;
typedef unsigned short	__kernel_uid16_t;
typedef unsigned short	__kernel_gid16_t;
typedef unsigned int	__kernel_uid32_t;
typedef unsigned int	__kernel_gid32_t;

typedef unsigned short	__kernel_old_uid_t;
typedef unsigned short	__kernel_old_gid_t;

#ifdef __GNUC__
typedef long long	__kernel_loff_t;
#endif

typedef struct {
#if defined(__KERNEL__) || defined(__USE_ALL)
	int	val[2];
#else /* !defined(__KERNEL__) && !defined(__USE_ALL) */
	int	__val[2];
#endif /* !defined(__KERNEL__) && !defined(__USE_ALL) */
} __kernel_fsid_t;

#if defined(__KERNEL__) || !defined(__GLIBC__) || (__GLIBC__ < 2)

#undef	__FD_SET
#define __FD_SET(fd,fdsetp)						      \
  do {									      \
	int __fd = (fd);						      \
	void *__addr = (void *)&((__kernel_fd_set *)fdsetp)->fds_bits;	      \
	__asm__ __volatile__ ("set1 %0, [%1]"				      \
			      : /*nothing*/				      \
			      : "r" (__fd & 0x7), "r" (__addr + (__fd >> 3)));\
  } while (0)

#undef	__FD_CLR
#define __FD_CLR(fd,fdsetp)						      \
  do {									      \
	int __fd = (fd);						      \
	void *__addr = (void *)&((__kernel_fd_set *)fdsetp)->fds_bits;	      \
	__asm__ __volatile__ ("clr1 %0, [%1]"				      \
			      : /*nothing*/				      \
			      : "r" (__fd & 0x7), "r" (__addr + (__fd >> 3)));\
  } while (0)

#undef	__FD_ISSET
#define __FD_ISSET(fd,fdsetp)						      \
  ({									      \
	int __fd = (fd);						      \
	void *__addr = (void *)&((__kernel_fd_set *)fdsetp)->fds_bits;	      \
	int res;							      \
	__asm__ ("tst1 %1, [%2]; setf nz, %0"				      \
	         : "=r" (res)						      \
		 : "r" (__fd & 0x7), "r" (__addr + (__fd >> 3)));	      \
	res;								      \
  })

#undef	__FD_ZERO
#define __FD_ZERO(fdsetp) (memset (fdsetp, 0, sizeof(*(fd_set *)fdsetp)))

#endif /* defined(__KERNEL__) || !defined(__GLIBC__) || (__GLIBC__ < 2) */

#endif /* __V850_POSIX_TYPES_H__ */
