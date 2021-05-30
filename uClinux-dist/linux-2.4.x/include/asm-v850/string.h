#ifndef __V850_STRING_H__
#define __V850_STRING_H__

#define __HAVE_ARCH_BCOPY
#define __HAVE_ARCH_MEMCPY

extern void *memcpy (void *, const void *, __kernel_size_t);
extern char *bcopy (const char *, char *, int);

#endif /* __V850_STRING_H__ */
