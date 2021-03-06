/*
 * linux/include/asm-arm/arch-atmel/hardware.h
 * for Atmel AT91 series
 * 2001 Erwin Authried
 */

#ifndef __ASM_ARCH_HARDWARE_H
#define __ASM_ARCH_HARDWARE_H

/* 0=TC0, 1=TC1, 2=TC2 */
#define KERNEL_TIMER 1	

#ifdef CONFIG_CPU_AT91X40
/*
 ******************* AT91x40xxx ********************
 */

#define ARM_CLK		(32768000)

#define AT91_USART_CNT 2
#define AT91_USART0_BASE	(0xfffd0000)
#define AT91_USART1_BASE	(0xfffcc000)
#define AT91_TC_BASE		(0xfffe0000)
#define AIC_BASE		(0xfffff000)	
#define AT91_PIOA_BASE		(0xffff0000)
#define AT91_SF_CIDR		(0xfff00000)

#define HARD_RESET_NOW()

#define HW_AT91_TIMER_INIT(timer)	/* no PMC */

/* enable US0,US1 */
#define HW_AT91_USART_INIT ((volatile struct pio_regs *)AT91_PIOA_BASE)->pdr = \
				PIOA_RXD0|PIOA_TXD0|PIOA_RXD1|PIOA_TXD1; 
/* PIOA bit allocation */
#define PIOA_TCLK0	(1<<0)					
#define PIOA_TI0A0	(1<<1)					
#define PIOA_TI0B0	(1<<2)					
#define PIOA_TCLK1	(1<<3)					
#define PIOA_TIOA1	(1<<4)				
#define PIOA_TIOB1	(1<<5)				
#define PIOA_TCLK2	(1<<6)					
#define PIOA_TIOA2	(1<<7)				
#define PIOA_TIOB2	(1<<8)				
#define PIOA_IRQ0	(1<<9)				
#define PIOA_IRQ1	(1<<10)				
#define PIOA_IRQ2	(1<<11)				
#define PIOA_FIQ	(1<<12)					
#define PIOA_SCK0	(1<<13)					
#define PIOA_TXD0	(1<<14)					
#define PIOA_RXD0	(1<<15)

#define PIOA_SCK1	(1<<20)					
#define PIOA_TXD1	(1<<21)					
#define PIOA_RXD1	(1<<22)

#define PIOA_MCK0	(1<<25)	
#define PIOA_NCS2	(1<<26)
#define PIOA_NCS3	(1<<27)	

#define PIOA_A20_CS7	(1<<28)
#define PIOA_A21_CS6	(1<<29)	
#define PIOA_A22_CS5	(1<<30)
#define PIOA_A23_CS4	(1<<31)

#elif CONFIG_CPU_AT91X63
/*
 ******************* AT91x63xxx ********************
 */

#define ARM_CLK		(25000000)

#define AT91_USART_CNT 2
#define AT91_USART0_BASE	(0xfffc0000)
#define AT91_USART1_BASE	(0xfffc4000)
#define AT91_TC_BASE		(0xfffd0000)
#define AIC_BASE		(0xfffff000)
#define AT91_PIOA_BASE 		(0xfffec000)
#define AT91_PIOB_BASE 		(0xffff0000)
#define AT91_PMC_BASE		(0xffff4000)

#define HARD_RESET_NOW()

/* enable US0,US1 */
#define HW_AT91_USART_INIT ((volatile struct pmc_regs *)AT91_PMC_BASE)->pcer = \
				(1<<2) | (1<<3) | (1<<13); \
			   ((volatile struct pio_regs *)AT91_PIOA_BASE)->pdr = \
				PIOA_RXD0|PIOA_TXD0|PIOA_RXD1|PIOA_TXD1; 

#define HW_AT91_TIMER_INIT(timer) ((volatile struct pmc_regs *)AT91_PMC_BASE)->pcer = \
				1<<(timer+6);

/* PIOA bit allocation */
#define PIOA_TCLK3	(1<<0)					
#define PIOA_TI0A3	(1<<1)					
#define PIOA_TI0B3	(1<<2)					
#define PIOA_TCLK4	(1<<3)					
#define PIOA_TI0A4	(1<<4)					
#define PIOA_TI0B4	(1<<5)					
#define PIOA_TCLK5	(1<<6)					
#define PIOA_TI0A5	(1<<7)					
#define PIOA_TI0B5	(1<<8)					
#define PIOA_IRQ0	(1<<9)
#define PIOA_IRQ1	(1<<10)
#define PIOA_IRQ2	(1<<11)
#define PIOA_IRQ3	(1<<12)
#define PIOA_FIQ	(1<<13)
#define PIOA_SCK0	(1<<14)	
#define PIOA_TXD0	(1<<15)
#define PIOA_RXD0	(1<<16)
#define PIOA_SCK1	(1<<17)	
#define PIOA_TXD1	(1<<18)
#define PIOA_RXD1	(1<<19)
#define PIOA_SCK2	(1<<20)	
#define PIOA_TXD2	(1<<21)
#define PIOA_RXD2	(1<<22)
#define PIOA_SPCK	(1<<23)					
#define PIOA_MISO	(1<<24)					
#define PIOA_MOSI	(1<<25)					
#define PIOA_NPCS0	(1<<26)					
#define PIOA_NPCS1	(1<<27)					
#define PIOA_NPCS2	(1<<28)					
#define PIOA_NPCS3	(1<<29)					

/* PIOB bit allocation */
#define PIOB_MPI_NOE	(1<<0)					
#define PIOB_MPI_NLB	(1<<1)				
#define PIOB_MPI_NUB	(1<<2)				

#define PIOB_MCK0	(1<<17)				
#define PIOB_BMS	(1<<18)				
#define PIOB_TCLK0	(1<<19)				
#define PIOB_TIOA0	(1<<20)				
#define PIOB_TIOB0	(1<<21)				
#define PIOB_TCLK1	(1<<22)				
#define PIOB_TIOA1	(1<<23)				
#define PIOB_TIOB1	(1<<24)				
#define PIOB_TCLK2	(1<<25)				
#define PIOB_TIOA2	(1<<26)				
#define PIOB_TIOB2	(1<<27)		
#else 
  #error "Configuration error: No CPU defined"
#endif

/*
 ******************* COMMON PART ********************
 */
#define AIC_SMR(i)  (AIC_BASE+i*4)
#define AIC_IVR	    (AIC_BASE+0x100)
#define AIC_FVR	    (AIC_BASE+0x104)
#define AIC_ISR	    (AIC_BASE+0x108)
#define AIC_IPR	    (AIC_BASE+0x10C)
#define AIC_IMR	    (AIC_BASE+0x110)
#define AIC_CISR	(AIC_BASE+0x114)
#define AIC_IECR	(AIC_BASE+0x120)
#define AIC_IDCR	(AIC_BASE+0x124)
#define AIC_ICCR	(AIC_BASE+0x128)
#define AIC_ISCR	(AIC_BASE+0x12C)
#define AIC_EOICR   (AIC_BASE+0x130)


#ifndef __ASSEMBLER__
struct at91_timer_channel
{
	unsigned long ccr;				// channel control register		(WO)
	unsigned long cmr;				// channel mode register		(RW)
	unsigned long reserved[2];		
	unsigned long cv;				// counter value				(RW)
	unsigned long ra;				// register A					(RW)
	unsigned long rb;				// register B					(RW)
	unsigned long rc;				// register C					(RW)
	unsigned long sr;				// status register				(RO)
	unsigned long ier;				// interrupt enable register	(WO)
	unsigned long idr;				// interrupt disable register	(WO)
	unsigned long imr;				// interrupt mask register		(RO)
};

struct at91_timers
{
	struct {
		struct at91_timer_channel ch;
		unsigned char padding[0x40-sizeof(struct at91_timer_channel)];
	} chans[3];
	unsigned  long bcr;				// block control register		(WO)
	unsigned  long bmr;				// block mode	 register		(RW)
};
#endif

/*  TC control register */
#define TC_SYNC	(1)

/*  TC mode register */
#define TC2XC2S(x)	(x & 0x3)
#define TC1XC1S(x)	(x<<2 & 0xc)
#define TC0XC0S(x)	(x<<4 & 0x30)
#define TCNXCNS(timer,v) ((v) << (timer<<1))

/* TC channel control */
#define TC_CLKEN	(1)			
#define TC_CLKDIS	(1<<1)			
#define TC_SWTRG	(1<<2)			

/* TC interrupts enable/disable/mask and status registers */
#define TC_MTIOB	(1<<18)
#define TC_MTIOA	(1<<17)
#define TC_CLKSTA	(1<<16)

#define TC_ETRGS	(1<<7)
#define TC_LDRBS	(1<<6)
#define TC_LDRAS	(1<<5)
#define TC_CPCS		(1<<4)
#define TC_CPBS		(1<<3)
#define TC_CPAS		(1<<2)
#define TC_LOVRS	(1<<1)
#define TC_COVFS	(1)

/*
 *	USART registers
 */

#ifndef __ASSEMBLER__
struct atmel_usart_regs{
	unsigned long cr;		// control 
	unsigned long mr;		// mode
	unsigned long ier;		// interrupt enable
	unsigned long idr;		// interrupt disable
	unsigned long imr;		// interrupt mask
	unsigned long csr;		// channel status
	unsigned long rhr;		// receive holding 
	unsigned long thr;		// tramsmit holding		
	unsigned long brgr;		// baud rate generator		
	unsigned long rtor;		// rx time-out
	unsigned long ttgr;		// tx time-guard
	unsigned long res1;
	unsigned long rpr;		// rx pointer
	unsigned long rcr;		// rx counter
	unsigned long tpr;		// tx pointer
	unsigned long tcr;		// tx counter
};
#endif

/*  US control register */
#define US_SENDA	(1<<12)
#define US_STTO		(1<<11)
#define US_STPBRK	(1<<10)
#define US_STTBRK	(1<<9)
#define US_RSTSTA	(1<<8)
#define US_TXDIS	(1<<7)
#define US_TXEN		(1<<6)
#define US_RXDIS	(1<<5)
#define US_RXEN		(1<<4)
#define US_RSTTX	(1<<3)
#define US_RSTRX	(1<<2)

/* US mode register */
#define US_CLK0		(1<<18)
#define US_MODE9	(1<<17)
#define US_CHMODE(x)(x<<14 & 0xc000)
#define US_NBSTOP(x)(x<<12 & 0x3000)
#define US_PAR(x)	(x<<9 & 0xe00)
#define US_SYNC		(1<<8)
#define US_CHRL(x)	(x<<6 & 0xc0)
#define US_USCLKS(x)(x<<4 & 0x30)

/* US interrupts enable/disable/mask and status register */
#define US_DMSI		(1<<10)
#define US_TXEMPTY	(1<<9)
#define US_TIMEOUT	(1<<8)
#define US_PARE		(1<<7)
#define US_FRAME	(1<<6)
#define US_OVRE		(1<<5)
#define US_ENDTX	(1<<4)
#define US_ENDRX	(1<<3)
#define US_RXBRK	(1<<2)
#define US_TXRDY	(1<<1)
#define US_RXRDY	(1)

#define US_ALL_INTS (US_DMSI|US_TXEMPTY|US_TIMEOUT|US_PARE|US_FRAME|US_OVRE|US_ENDTX|US_ENDRX|US_RXBRK|US_TXRDY|US_RXRDY)
		
#define PIO(i)		(1<<i)

#ifndef __ASSEMBLER__
struct pio_regs{
	unsigned long per;
	unsigned long pdr;
	unsigned long psr;
	unsigned long res1;
	unsigned long oer;
	unsigned long odr;
	unsigned long osr;
	unsigned long res2;
	unsigned long ifer;
	unsigned long ifdr;
	unsigned long ifsr;
	unsigned long res3;
	unsigned long sodr;
	unsigned long codr;
	unsigned long odsr;
	unsigned long pdsr;
	unsigned long ier;
	unsigned long idr;
	unsigned long imr;
	unsigned long isr;
};
#endif

#ifndef __ASSEMBLER__
struct pmc_regs{
	unsigned long scer;
	unsigned long scdr;
	unsigned long scsr;
	unsigned long reserved;
	unsigned long pcer;
	unsigned long pcdr;
	unsigned long pcsr;
};
#endif

#endif  /* _ASM_ARCH_HARDWARE_H */


