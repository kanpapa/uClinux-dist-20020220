/* Note, all symbols are prefixed with an extra `_' for compatibility with
   the existing linux sources.  */

SECTIONS {
	. = 0;
        __start = . ;

	.intv : {
		__intv_start = . ;
		*(.intv)		/* Interrupt vectors.  */
			*(.intv.common) /* Vectors common to all v850e proc. */
			. = 0x80 ;
			*(.intv.mach)   /* Machine-specific int. vectors.  */
		__intv_end = . ;
	}

	.text : {
		__stext = . ;
        	*(.text)
			*(.text.exit)
			*(.text.lock)
			*(.exitcall.exit)
		__real_etext = .;	/* There may be data after here.  */
			*(.rodata)
		. = ALIGN(0x4) ;
			*(.kstrtab)
		. = ALIGN(16);          /* Exception table              */
		___start___ex_table = .;
			*(__ex_table)
		___stop___ex_table = .;

		___start___ksymtab = .;  /* Kernel symbol table          */
			*(__ksymtab)
		___stop___ksymtab = .;
		. = ALIGN(4) ;
		__etext = . ;
	}

	.data BLOCK(0x4) : {
		__sdata = . ;
		___data_start = . ;
        	*(.data)
			*(.data.exit)
		. = ALIGN(16);
		*(.data.cacheline_aligned)
		. = ALIGN(0x2000) ;
        	*(.data.init_task)
		. = ALIGN(0x2000) ;
		__edata = . ;
	}

	.bss BLOCK(0x4) : {
		__sbss = . ;
			*(.bss)
			*(COMMON)
		. = ALIGN(4) ;
		__ebss = . ;
	}

	.init BLOCK(4096) : {
		___init_begin = .;
			*(.text.init)
			*(.data.init)
		. = ALIGN(16);
		___setup_start = .;
			*(.setup.init)
		___setup_end = .;
		___initcall_start = .;
			*(.initcall.init)
		. = ALIGN(4) ;
		___initcall_end = .;
		___init_end = .;
	}

	__end = . ;
}
