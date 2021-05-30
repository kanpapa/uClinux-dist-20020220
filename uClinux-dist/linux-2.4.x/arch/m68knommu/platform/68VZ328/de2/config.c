/*
 *  linux/arch/m68knommu/platform/MC68VZ328/de2/config.c
 *
 *  Copyright (C) 1993 Hamish Macdonald
 *  Copyright (C) 1999 D. Jeff Dionne
 *  Copyright (C) 2001 Georges Menie, Ken Desmet
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file COPYING in the main directory of this archive
 * for more details.
 */

#include <stdarg.h>
#include <linux/config.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/tty.h>
#include <linux/console.h>
#include <linux/kd.h>

#include <asm/setup.h>
#include <asm/system.h>
#include <asm/pgtable.h>
#include <asm/irq.h>
#include <asm/machdep.h>
#include <asm/MC68VZ328.h>

/*
 * Port K - FIXME : should be declared in MC68VZ328.h
 */
#define PKDIR_ADDR      0xfffff440              /* Port K direction reg */
#define PKDATA_ADDR     0xfffff441              /* Port K data register */
#define PKPUEN_ADDR     0xfffff442              /* Port K Pull-Up enable reg */
#define PKSEL_ADDR      0xfffff443              /* Port K Select Register */

#define PKDIR           BYTE_REF(PKDIR_ADDR)
#define PKDATA          BYTE_REF(PKDATA_ADDR)
#define PKPUEN          BYTE_REF(PKPUEN_ADDR)
#define PKSEL           BYTE_REF(PKSEL_ADDR)

#define RTCTIME_ADDR	0xfffffb00
#define RTCTIME		LONG_REF(RTCTIME_ADDR)

#define BIT0  0x01
#define BIT1  0x02
#define BIT2  0x04
#define BIT3  0x08
#define BIT4  0x10
#define BIT5  0x20
#define BIT6  0x40
#define BIT7  0x80
#define BIT8  0x0100
#define BIT9  0x0200
#define BIT10 0x0400
#define BIT11 0x0800
#define BIT12 0x1000
#define BIT13 0x2000  
#define BIT14 0x4000  
#define BIT15 0x8000  

/* SPI 2 Control/Status register */
#define SPIDATA2	WORD_REF(0xfffff800)
/* SPI 2 Data register */
#define SPICONT2	WORD_REF(0xfffff802)

unsigned char dragen2_cs8900_hwaddr[6];

#if defined(CONFIG_HWADDR_FROMEEPROM)

/* EEPROM commands */
#define EE_WREN 0x0006
#define EE_WRDI 0x0004
#define EE_RDSR 0x0500
#define EE_WRSR 0x0100
#define EE_READ 0x0003
#define EE_WRIT 0x0002

#define eepromEnable	PDDATA &= ~BIT6
#define eepromDisable	PDDATA |= BIT6

unsigned short spi2Exchange(unsigned short data, int bitcount)  
{  
        unsigned short ret;  

	SPICONT2 = BIT9;
	SPICONT2 = BIT14|BIT9|((bitcount-1)&15);
	SPIDATA2 = data;
	SPICONT2 |= BIT8;
	while ((SPICONT2&BIT7) == 0);
        ret = SPIDATA2;  
	SPICONT2 = 0;

        return ret;  
}  

unsigned char eepromReadStatus(void)
{
	register unsigned char sts;

	eepromEnable;
	sts = spi2Exchange(EE_RDSR,16);
	eepromDisable;

	return sts;
}

int eepromWaitReady(void)
{
	int timeout = 1000;
	while (timeout && (eepromReadStatus() & 1)) --timeout;
	return timeout == 0;
}

int eepromRead(void *buf, int len, unsigned short addr)
{
	register unsigned short data;
	register int i;

	if (eepromWaitReady()) return -1;

	eepromEnable;
	(void)spi2Exchange(EE_READ,8);
	(void)spi2Exchange(addr,16);
	for (i = 0; i < (len>>1); ++i) {
		data = spi2Exchange(0,16);
		*(char *)buf++ = data>>8;
		*(char *)buf++ = data;
	}
	if (len&1) {
		*(char *)buf = spi2Exchange(0,8);
	}
	eepromDisable;

	return 0;
}

#endif /* CONFIG_HWADDR_FROMEEPROM */

static void dragen2_sched_init(void (*timer_routine)(int, void *, struct pt_regs *))
{
	/* disable timer 1 */
	TCTL = 0;

	/* set ISR */
	request_irq(TMR_IRQ_NUM, timer_routine, IRQ_FLG_LOCK, "timer", NULL);

	/* Restart mode, Enable int, 32KHz */
	TCTL = TCTL_OM | TCTL_IRQEN | TCTL_CLKSOURCE_32KHZ;
	/* Set prescaler (Divide 32KHz by 32)*/
	TPRER = 31;
	/* Set compare register  32Khz / 32 / 10 = 100 */
	TCMP = 10;                                                              

	/* Enable timer 1 */
	TCTL |= TCTL_TEN;
}

static void dragen2_tick(void)
{
  	/* Reset Timer1 */
	TSTAT &= 0;
}

static int dragen2_hwclk(int op, struct hwclk_time *t)
{
	if (!op) {
		/* read */
		long now = RTCTIME;
		t->hour = (now>>24)&0x1f;
		t->min = (now>>16)&0x3f;
		t->sec = now&0x3f;
	} else {
		/* write */
		RTCTIME = (t->hour<<24)+(t->min<<16)+(t->sec);
	}
	return 0;
}

static void dragen2_reset(void)
{
	cli();
	asm volatile ("
		moveal #0x04000000, %a0;
		moveb #0, 0xFFFFF300;
		moveal 0(%a0), %sp;
		moveal 4(%a0), %a0;
		jmp (%a0);
	");
}

void config_BSP(char *command, int len)
{
	extern void config_dragen2_irq(void);

	printk("68VZ328 DragonBallVZ support (c) 2001 Lineo, Inc.\n");
	command[0] = '\0'; /* no specific boot option */

	/* CSGB Init */
	CSGBB = 0x4000;
	CSB = 0x1a1;

	/* SPI 2 init */
        SPICONT2 = 0;  
        PESEL &= ~(BIT2|BIT1|BIT0);  

	/* TouchScreen init */
	PESEL |= BIT3;	/* select PE3 as I/O */
	PEDIR |= BIT3;	/* select Port E bit 3 as output */
	PEDATA |= BIT3;	/* set touchScr CS high */

	/* EEPROM init */
	PDSEL |= BIT6;	/* select PD6 as I/O */
	PDDIR |= BIT6;	/* select Port D bit 6 as output */
	PDDATA |= BIT6;	/* set eeprom CS high */

	/* CS8900 init */
	/* PK3: hardware sleep function pin, active low */
	PKSEL |= BIT3;	/* select pin as I/O */
	PKDIR |= BIT3;	/* select pin as output */
	PKDATA |= BIT3;	/* set pin high */

	/* PF5: hardware reset function pin, active high */
	PFSEL |= BIT5;	/* select pin as I/O */
	PFDIR |= BIT5;	/* select pin as output */
	PFDATA &= ~BIT5;	/* set pin low */

	/* cs8900 hardware reset */
	PFDATA |= BIT5;
	{ volatile int i; for (i = 0; i < 32000; ++i); }
	PFDATA &= ~BIT5;

	/* INT1 enable (cs8900 IRQ) */
	PDPOL &= ~BIT1;	/* active high signal */
	PDIQEG &= ~BIT1;
	PDIRQEN |= BIT1;	/* IRQ enabled */

#if defined(CONFIG_HWADDR_FROMEEPROM)
	/* read ETH address from EEPROM */
	eepromRead(dragen2_cs8900_hwaddr, sizeof dragen2_cs8900_hwaddr, CONFIG_HWADDR_OFFSET);
#else
	/* Set the ETH hardware address from the flash monitor location 0x400FFA */
	memcpy(dragen2_cs8900_hwaddr, (void *)0x400fffa, sizeof dragen2_cs8900_hwaddr);
#endif

	mach_sched_init      = dragen2_sched_init;
	mach_tick            = dragen2_tick;
	mach_reset           = dragen2_reset;
	mach_hwclk           = dragen2_hwclk;

	config_dragen2_irq();
}

