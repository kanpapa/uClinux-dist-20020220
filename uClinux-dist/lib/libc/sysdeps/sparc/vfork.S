
#include <asm/unistd.h>

#ifndef __NR_vfork
#define __NR_vfork __NR_fork /* uClinux-2.0 only has fork which is vfork */
#endif

#define IMM #

.text
.align 4
.globl errno

.globl vfork
.type	 vfork,@function
vfork:
	ld	[%sp], %g0		/* save the return address for later */
	mov	__NR_vfork, %g1
	ta	0x10
	mov	%o0, %i0
	mov	-4097, %g2
	cmp 	%i0, %g2
	bcs	1f
	 nop
	jmpl	%g0, %o7		/* don't return,  just jmp directly */
	 nop
1:
	neg	%i0, %i0
	sethi	%hi(errno), %g3
	st	%i0, [%g3+%lo(errno)]
	mov	-1, %i0
	jmpl	%g0, %o7		/* don't return,  just jmp directly */
	 nop

