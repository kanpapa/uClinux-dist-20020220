/*
 * This function is _not_ called directly.  It is jumped to (so no return
 * address is on the stack) when attempting to use a symbol that has not yet
 * been resolved.  The first time a jump symbol (such as a function call inside
 * a shared library) is used (before it gets resolved) it will jump here to
 * _dl_linux_resolve.  When we get called the stack looks like this:
 *	reloc_entry
 *	tpnt
 *
 * This function saves all the registers, puts a copy of reloc_entry and tpnt
 * on the stack (as function arguments) then make the function call
 * _dl_linux_resolver(tpnt, reloc_entry).  _dl_linux_resolver() figures out
 * where the jump symbol is _really_ supposed to have jumped to and returns
 * that to us.  Once we have that, we overwrite tpnt with this fixed up
 * address. We then clean up after ourselves, put all the registers back how we
 * found them, then we jump to where the fixed up address, which is where the
 * jump symbol that got us here really wanted to jump to in the first place.
 * found them, then we jump to the fixed up address, which is where the jump
 * symbol that got us here really wanted to jump to in the first place.  
 *  -Erik Andersen
 */
.text
.globl _dl_linux_resolve
.type _dl_linux_resolve,#function
.align 2
_dl_linux_resolve:
	stmdb sp!,{r0-r3,sl,fp}
	sub r1, ip, lr
	sub r1, r1, #4
	add r1, r1, r1
	ldr r0, [lr, #-4]
	mov r3,r0

	bl _dl_linux_resolver

//	str r0, [lr, #-4]
	mov ip, r0
	ldmia sp!,{r0-r3,sl,fp,lr}
	mov pc,ip
.size _dl_linux_resolve, .-_dl_linux_resolve

