#ifndef _LINUX_STRING_H_
#define _LINUX_STRING_H_

#include <linux/config.h>
#include <linux/autoconf.h>	/* for CONFIG_COLDFIRE */
#include <linux/types.h>	/* for size_t */

#ifndef NULL
#define NULL ((void *) 0)
#endif

#ifdef __cplusplus
extern "C" {
#endif

extern char * ___strtok;
extern char * strcpy(char *,const char *);
extern char * strncpy(char *,const char *, __kernel_size_t);
extern char * strcat(char *, const char *);
extern char * strncat(char *, const char *, __kernel_size_t);
extern char * strchr(const char *,int);
extern char * strrchr(const char *,int);
extern char * strpbrk(const char *,const char *);
extern char * strtok(char *,const char *);
extern char * strstr(const char *,const char *);
extern __kernel_size_t strlen(const char *);
extern __kernel_size_t strnlen(const char *,__kernel_size_t);
extern __kernel_size_t strspn(const char *,const char *);
extern int strcmp(const char *,const char *);
extern int strncmp(const char *,const char *,__kernel_size_t);

#if !defined( CONFIG_ARCH_ATMEL )
extern void * memset(void *,int,__kernel_size_t);
extern void * memcpy(void *,const void *,__kernel_size_t);
extern int memcmp(const void *,const void *,__kernel_size_t);
#endif
extern void * memscan(void *,int,__kernel_size_t);
extern void * memmove(void *,const void *,__kernel_size_t);

/*
 * Include machine specific inline routines
 */
#include <asm/string.h>

#ifdef __cplusplus
}
#endif

#endif /* _LINUX_STRING_H_ */
