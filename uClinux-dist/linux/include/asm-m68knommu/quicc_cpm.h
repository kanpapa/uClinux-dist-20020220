/*
 *  External Interfaces for the management of the 68360
 *  Communication Processor Module (CPM).
 *
 *  Copyright (c) 2002 SED Systems, a Division of Calian Ltd.
 *          <hamilton@sedsystems.ca>
 */

#ifndef __QUICC_CPM_H__
#define __QUICC_CPM_H__

#include <linux/config.h>
#ifdef __KERNEL__
#if defined(CONFIG_M68360)
#include <linux/tty.h>
#include <asm/m68360.h>
extern QUICC *pquicc;

#if defined(CONFIG_SED_SIOS)
#define OSCILLATOR  ((unsigned long int)33000000)
#endif

extern unsigned long int system_clock;   /* Computed in quicc_cpm_init() */

/* Console print function pointer. */
typedef void (*console_print_function_t)(const char *);

int     quicc_cpm_init(void);     /*Initialize the communication processor.*/
QUICC   *m68360_get_pquicc(void); /* Get a pointer to the 68360 registers */
int     rs_quicc_init(void);          /* Resiter the serial devices. */
int     cpm_interrupt_init(void);
int     rs_quicc_console_setup(const char *arg);
console_print_function_t rs_quicc_console_init(void);

/* kick the watchdog timer. */
void quicc_kick_wdt(void);

/* Speed conversion functions. */
int cfsetospeed(struct termios *termios_p, long rate);
speed_t long_to_speed_t(long rate);
unsigned long cfgetospeed(const struct termios *termios_p);
#endif
#endif
#endif
