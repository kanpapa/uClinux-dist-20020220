#ifndef __V850_MODULE_H__
#define __V850_MODULE_H__

#define module_map(x)		vmalloc(x)
#define module_unmap(x)		vfree(x)
#define module_arch_init(x)	((void)0)

#endif /* __V850_MODULE_H__ */
