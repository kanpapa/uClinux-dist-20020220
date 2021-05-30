/* Note, all symbols are prefixed with an extra `_' for compatibility with
   the existing linux sources.  */
MEMORY {
       /* 1MB of SRAM; we can't use the last 32KB, because it's used by
          the monitor scratch-RAM.  This memory is mirrored 4 times.  */
       SRAM  : ORIGIN = 0x00400000, LENGTH = 0x000F8000
       /* Monitor scratch RAM; only the interrupt vectors should go here.  */
       MRAM  : ORIGIN = 0x004F8000, LENGTH = 0x00008000
       /* 32MB of SDRAM */
       SDRAM : ORIGIN = 0x00800000, LENGTH = 0x02000000
}

SECTIONS {
	 /* . = 0x00400000 ; */
	 . =  0x00800000 ; 
        __start = . ;

	.text : {
		__stext = . ;
        	*(.text)
			*(.text.exit)
			*(.text.lock)
			*(.exitcall.exit)
		__real_etext = .;	/* There may be data after here.  */
			*(.rodata)

		. = ALIGN (0x4) ;
			*(.kstrtab)

		. = ALIGN (4) ;
		*(.call_table_data)
		*(.call_table_text)

		. = ALIGN (16);          /* Exception table              */
		___start___ex_table = .;
			*(__ex_table)
		___stop___ex_table = .;

		___start___ksymtab = .;  /* Kernel symbol table          */
			*(__ksymtab)
		___stop___ksymtab = .;
		. = ALIGN (4) ;
		__etext = . ;
	} > SDRAM

	.data ALIGN (0x4) : {
		__sdata = . ;
		___data_start = . ;
        	*(.data)
			*(.data.exit)
		. = ALIGN (16);
		*(.data.cacheline_aligned)
		. = ALIGN (0x2000) ;
        	*(.data.init_task)
		. = ALIGN (0x2000) ;
		__edata = . ;
	} > SDRAM

	.bss ALIGN (0x4) : {
		__sbss = . ;
			*(.bss)
			*(COMMON)
		. = ALIGN (4) ;
		__ebss = . ;
	} > SDRAM

	.init ALIGN (4096) : {
		___init_begin = .;
			*(.text.init)
			*(.data.init)
		. = ALIGN (16);
		___setup_start = .;
			*(.setup.init)
		___setup_end = .;
		___initcall_start = .;
			*(.initcall.init)
		. = ALIGN (4) ;
		___initcall_end = .;
	} > SDRAM

	/* This provides address at which the interrupt vectors are
	   initially loaded by the loader.  */
	__intv_load_start = ALIGN (0x10) ;

	/* Interrupt vector space.  Because we're using the monitor
	   ROM, Instead of the native interrupt vector, we must use the
	   `alternate interrupt vector' area.  Note that this is in
	   `SRAM' space, which is not currently used by the kernel (the
	   kernel uses `SDRAM' space).  */

	/* We can't load the interrupt vectors directly into their
	   target location, because the monitor ROM for the GHS Multi
	   debugger barfs if we try.  Unfortunately, Multi also doesn't
	   deal correctly with ELF sections where the LMA and VMA differ
	   (it just ignores the LMA), so we can't use that feature to
	   work around the problem!  What we do instead is just put the
	   interrupt vectors into a normal section, and have the
	   `mach_early_init' function for Midas boards do the necessary
	   copying and relocation at runtime (this section basically
	   only contains `jr' instructions, so it's not that hard).

	   This the section structure I initially tried to use (which more
	   accurately expresses the intent):

		.intv 0x007F8000 : AT (ADDR (.init) + SIZEOF (.init)) {
		    ...
		} > MRAM
	*/

	.intv ALIGN (0x10) : {
		__intv_start = . ;
		*(.intv)		/* Interrupt vectors.  */
			*(.intv.common) /* Vectors common to all v850e proc. */
			. = 0x80 ;
			*(.intv.mach)   /* Machine-specific int. vectors.  */
		__intv_end = . ;
	} > SDRAM

	/* This is here so that when we free init memory, the initial
	   load-area of the interrupt vectors is freed too.  */
	___init_end = __intv_end;

	/* `blkmem' device contents for the root filesystem.  */
	.blkmem ALIGN (4096) : {
		__blkmem_0_start = . ;
		*(.blkmem0)
		*(=.blkmem0) /* bug in objcopy results in mis-named sections.*/
		__blkmem_0_end = . ;
	} > SDRAM

	__end = . ;
}
