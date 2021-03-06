/****************************************************************************/
/*	vi:set tabstop=4 cindent shiftwidth=4:
 *
 *	ledman.c -- An LED manager,  primarily,  but not limited to Lineo devices
 *              manages up to 32 seperate LED at once.
 *	            Copyright (C) Lineo, 2000-2001.
 *	            Copyright (C) SnapGear, 2001-2002.
 *
 *	This driver currently supports 4 types of LED modes:
 *
 *	SET      - transient LED's that show activity,  cleared at next poll
 *	ON       - always ON
 *	OFF      - always OFF
 *  FLASHING - a blinking LED with the frequency determinbe by the poll func
 *
 *	We have two sets of LED's to support non-standard LED usage without
 *	losing previously/during use set of std values.
 *
 *	Hopefully for most cases, adding new HW with new LED patterns will be
 *	as simple as adding two tables, a small function and an entry in
 *	led_modes.  The tables being the map and the defaults while the
 *	function is the XXX_set function.
 *
 *	You can, however, add your own functions for XXX_bits, XXX_tick and
 *	take full control over all aspects of the LED's.
 */
/****************************************************************************/

#include <linux/config.h>
#include <linux/utsname.h>
#include <linux/kernel.h>
#include <linux/major.h>
#include <linux/string.h>
#include <linux/fcntl.h>
#include <linux/timer.h>
#include <linux/ledman.h>
#include <linux/module.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE < 0x020300
#include <linux/malloc.h>
#else
#include <linux/slab.h>
#endif

#if LINUX_VERSION_CODE < 0x020300
#define INIT_RET_TYPE	int
#define Module_init(a)
#else
#include <linux/init.h>
#define INIT_RET_TYPE	static int __init
#define Module_init(a)	module_init(a)
#endif

#if LINUX_VERSION_CODE < 0x020100
#define Get_user(a,b)	a = get_user(b)
#else
#include <asm/uaccess.h>
#define Get_user(a,b)	get_user(a,b)
#endif

#if LINUX_VERSION_CODE < 0x020100
static struct symbol_table ledman_syms = {
#include <linux/symtab_begin.h>
	X(ledman_cmd),
#include <linux/symtab_end.h>
};
#else
EXPORT_SYMBOL(ledman_cmd);
#endif

/****************************************************************************/

static void ledman_poll(unsigned long arg);
static int  ledman_ioctl(struct inode * inode, struct file * file,
								unsigned int cmd, unsigned long arg);
#if !defined(CONFIG_SH_KEYWEST)
static int	ledman_bits(unsigned long cmd, unsigned long bits);
static void	ledman_tick(void);
#endif

/****************************************************************************/

static struct timer_list	ledman_timerlist;

/****************************************************************************/

struct file_operations ledman_fops = {
	ioctl: ledman_ioctl,	/* ledman_ioctl */
};

/****************************************************************************/
/*
 *	some types to make adding new LED modes easier
 *
 *	First the elements for def array specifying default LED behaviour
 */

#define LEDS_SET	0
#define LEDS_ON		1
#define LEDS_OFF	2
#define LEDS_FLASH	3
#define LEDS_MAX	4

typedef unsigned int leddef_t[LEDS_MAX];

/*
 *	A LED map is a mapping from numbers in ledman.h to one or more
 *	physical LED bits.  Currently the typing limits us to 32 LED's
 *	though this would not be hard to change.
 */

typedef unsigned int ledmap_t[LEDMAN_MAX];

/*
 *	A LED mode is a definition of how a set of LED's should behave.
 *
 *	name    - a symbolic name for the LED mode,  used for changing modes
 *	map     - points to a ledmap array,  maps ledman.h defines to real LED bits
 *	def     - default behaviour for the LED bits (ie, on, flashing ...)
 *	bits    - perform command on physical bits,  you may use the default or
 *	          supply your own for more control.
 *	tick    - time based update of LED status,  used to clear SET LED's and
 *	          also for flashing LED's
 *	set     - set the real LED's to match the physical bits
 *	jiffies - how many clock ticks between runs of the tick routine.
 */


typedef struct {
	char	name[LEDMAN_MAX_NAME];
	u_int	*map;
	u_int	*def;
	int		(*bits)(unsigned long cmd, unsigned long led);
	void	(*tick)(void);
	void	(*set)(unsigned long led);
	int		jiffies;
} ledmode_t;

/****************************************************************************/

static int current_mode = 0;				/* the default LED mode */
static int initted = 0;

/*
 * We have two sets of LED's for transient operations like DHCP and so on
 * index 0 is the standard LED's and index 1 is the ALTBIT LED's
 */

static unsigned long leds_alt, leds_alt_cnt[32];
#if !defined(CONFIG_SH_KEYWEST)
static unsigned long leds_set[2];
#endif
static unsigned long leds_on[2], leds_off[2], leds_flash[2];

static pid_t ledman_resetpid;

/****************************************************************************/

/*
 *	Let the system specific defining begin
 */

#if defined(CONFIG_MTD_NETtel) && defined(CONFIG_X86)
/* This is the best method I could think of to distinguish the boards... */
#if defined(CONFIG_USB_MODULE) && !defined(CONFIG_PCMCIA)
#define CONFIG_SITECTRLER
#else
#define CONFIG_NETtelx86
#endif
extern ledmap_t	nettel_std;
extern leddef_t	nettel_def;
static void nettel_set(unsigned long bits);
static void ledman_initx86(void);
#endif /* CONFIG_MTD_NETtel && CONFIG_X86 */

#if defined(CONFIG_NETtel) && defined(CONFIG_M5307)
#ifdef ENTERASYS
extern ledmap_t enterasys_std;
extern leddef_t enterasys_def;
#endif
extern ledmap_t	nettel_std;
extern ledmap_t	nettel_alt;
extern leddef_t	nettel_def;
static void nettel_set(unsigned long bits);
#endif

#if defined(CONFIG_NETtel) && defined(CONFIG_M5272)
extern ledmap_t	nt5272_std;
extern leddef_t	nt5272_def;
static void nt5272_set(unsigned long bits);
#endif

#if defined(CONFIG_MARCONINAP) && defined(CONFIG_M5272)
extern ledmap_t	nap5272_std;
extern leddef_t	nap5272_def;
static void nap5272_set(unsigned long bits);
#endif

#if defined(CONFIG_NETtel) && defined(CONFIG_M5206e)
extern ledmap_t	nt1500_std;
extern leddef_t	nt1500_def;
static void nt1500_set(unsigned long bits);
#endif

#ifdef CONFIG_eLIA
extern ledmap_t	elia_std;
extern leddef_t	elia_def;
static void elia_set(unsigned long bits);
#endif

#ifdef CONFIG_SH_KEYWEST
extern ledmap_t	keywest_std;
extern leddef_t	keywest_def;
static void keywest_set(unsigned long bits);
static void ledman_initkeywest(void);
static int	keywest_bits(unsigned long cmd, unsigned long bits);
static void	keywest_tick(void);
#endif

/****************************************************************************/

ledmode_t led_mode[] = {

#ifdef ENTERASYS /* first in the list is the default */
	{ "enterasys", enterasys_std, enterasys_def, ledman_bits, ledman_tick, nettel_set, 1 },
#endif

#ifdef CONFIG_SNAPGEAR
	{ "snapgear", nettel_alt, nettel_def, ledman_bits, ledman_tick, nettel_set, 1 },
#endif

#if defined(CONFIG_X86)
	{ "std", nettel_std, nettel_def, ledman_bits, ledman_tick, nettel_set, 1 },
#endif

#if defined(CONFIG_NETtel) && defined(CONFIG_M5307)
	{ "std", nettel_std, nettel_def, ledman_bits, ledman_tick, nettel_set, 1 },
	{ "alt", nettel_alt, nettel_def, ledman_bits, ledman_tick, nettel_set, 1 },
#endif

#if defined(CONFIG_NETtel) && defined(CONFIG_M5272)
	{ "std", nt5272_std, nt5272_def, ledman_bits, ledman_tick, nt5272_set, 1 },
#endif

#if defined(CONFIG_NETtel) && defined(CONFIG_M5206e)
	{ "std", nt1500_std, nt1500_def, ledman_bits, ledman_tick, nt1500_set, 1 },
#endif

#if defined(CONFIG_MARCONINAP) && defined(CONFIG_M5272)
	{ "std", nap5272_std, nap5272_def, ledman_bits, ledman_tick, nap5272_set, 1 },
#endif

#ifdef CONFIG_eLIA
	{ "std", elia_std, elia_def, ledman_bits, ledman_tick, elia_set, 1 },
#endif

#ifdef CONFIG_SH_KEYWEST
	{ "std",keywest_std,keywest_def,keywest_bits,keywest_tick,keywest_set,HZ/10},
#endif

	{ "",  NULL, NULL, 0 }
};

/****************************************************************************/
/*
 *	boot arg processing ledman=mode
 */

void
ledman_setup(char *arg, int *ints)
{
	ledman_cmd(LEDMAN_CMD_MODE, (unsigned long) arg);
}

/****************************************************************************/

/****************************************************************************/

INIT_RET_TYPE ledman_init(void)
{
	printk(KERN_INFO "ledman: Copyright (C) SnapGear, 2000-2002.\n");

	if (register_chrdev(LEDMAN_MAJOR, "nled",  &ledman_fops) < 0) {
		printk("%s(%d): ledman_init() can't get Major %d\n",
				__FILE__, __LINE__, LEDMAN_MAJOR);
		return(-EBUSY);
	} 

#if defined(CONFIG_SH_KEYWEST)
	ledman_initkeywest();
#endif

#if defined(CONFIG_X86)
	ledman_initx86();
#endif

/*
 *	set the LEDs up correctly at boot
 */
	ledman_cmd(LEDMAN_CMD_RESET, LEDMAN_ALL);
/*
 *	start the timer
 */
	if (led_mode[current_mode].tick)
		ledman_timerlist.expires = jiffies + led_mode[current_mode].jiffies;
	else
		ledman_timerlist.expires = jiffies + HZ;
	ledman_timerlist.function = ledman_poll;
	ledman_timerlist.data = 0;
	add_timer(&ledman_timerlist);

#if LINUX_VERSION_CODE < 0x020100
	register_symtab(&ledman_syms);
#endif

	initted = 1;
	return(0);
}

Module_init(ledman_init);

/****************************************************************************/

void
ledman_killtimer(void)
{
/*
 *	stop the timer
 */
	del_timer(&ledman_timerlist);

/*
 *	set the LEDs up correctly at boot
 */
	ledman_cmd(LEDMAN_CMD_RESET, LEDMAN_ALL);
}
/****************************************************************************/

void
ledman_starttimer(void)
{
/*
 *	stop the timer
 */
	add_timer(&ledman_timerlist);

/*
 *	set the LEDs up correctly at boot
 */
	ledman_cmd(LEDMAN_CMD_RESET, LEDMAN_ALL);
}
/****************************************************************************/

static void
ledman_poll(unsigned long arg)
{
	if (led_mode[current_mode].tick) {
		(*led_mode[current_mode].tick)();
		ledman_timerlist.expires = jiffies + led_mode[current_mode].jiffies;
	} else
		ledman_timerlist.expires = jiffies + HZ;
	add_timer(&ledman_timerlist);
}

/****************************************************************************/

static int
ledman_ioctl(
	struct inode * inode,
	struct file * file,
	unsigned int cmd,
	unsigned long arg)
{
	char	mode[LEDMAN_MAX_NAME];
	int		i;

	if (cmd == LEDMAN_CMD_SIGNAL) {
		ledman_resetpid = current->pid;
		return(0);
	}

	if (cmd == LEDMAN_CMD_MODE) {
		for (i = 0; i < sizeof(mode) - 1; i++) {
			Get_user(mode[i], (char *) (arg + i));
			if (!mode[i])
				break;
		}
		mode[i] = '\0';
		arg = (unsigned long) &mode[0];
	}
	return(ledman_cmd(cmd, arg));
}

/****************************************************************************/
/*
 *	cmd - from ledman.h
 *	led - led code from ledman.h
 *
 *	check parameters and then call
 */

int
ledman_cmd(int cmd, unsigned long led)
{
	ledmode_t	*lmp;
	int			i;

	switch (cmd & ~LEDMAN_CMD_ALTBIT) {
	case LEDMAN_CMD_SET:
	case LEDMAN_CMD_ON:
	case LEDMAN_CMD_OFF:
	case LEDMAN_CMD_FLASH:
	case LEDMAN_CMD_RESET:
	case LEDMAN_CMD_ALT_ON:
	case LEDMAN_CMD_ALT_OFF:
		break;
	case LEDMAN_CMD_STARTTIMER:
		ledman_starttimer();
		return(0);
	case LEDMAN_CMD_KILLTIMER:
		ledman_killtimer();
		return(0);
	case LEDMAN_CMD_MODE:
		for (i = 0; led_mode[i].name[0]; i++)
			if (strcmp((char *) led, led_mode[i].name) == 0) {
				current_mode = i;
				if (initted)
					ledman_cmd(LEDMAN_CMD_RESET, LEDMAN_ALL);
				return(0);
			}
		return(-EINVAL);
	default:
		return(-EINVAL);
	}

	if (led < 0 || led >= LEDMAN_MAX)
		return(-EINVAL);

	lmp = &led_mode[current_mode];
	(*lmp->bits)(cmd, lmp->map[led]);
	return(0);
}

/****************************************************************************/
#if !defined(CONFIG_SH_KEYWEST)
/****************************************************************************/

static int
ledman_bits(unsigned long cmd, unsigned long bits)
{
	ledmode_t		*lmp = &led_mode[current_mode];
	int				 alt, i;
	unsigned long	 new_alt;

	alt = (cmd & LEDMAN_CMD_ALTBIT) ? 1 : 0;

	switch (cmd & ~LEDMAN_CMD_ALTBIT) {
	case LEDMAN_CMD_SET:
		leds_set[alt]   |= bits;
		break;
	case LEDMAN_CMD_ON:
		leds_on[alt]    |= bits;
		leds_off[alt]   &= ~bits;
		leds_flash[alt] &= ~bits;
		(*lmp->tick)();
		break;
	case LEDMAN_CMD_OFF:
		leds_on[alt]    &= ~bits;
		leds_off[alt]   |= bits;
		leds_flash[alt] &= ~bits;
		(*lmp->tick)();
		break;
	case LEDMAN_CMD_FLASH:
		leds_on[alt]    &= ~bits;
		leds_off[alt]   &= ~bits;
		leds_flash[alt] |= bits;
		break;
	case LEDMAN_CMD_RESET:
		leds_set[alt]   = (leds_set[alt]  &~bits) | (bits&lmp->def[LEDS_SET]);
		leds_on[alt]    = (leds_on[alt]   &~bits) | (bits&lmp->def[LEDS_ON]);
		leds_off[alt]   = (leds_off[alt]  &~bits) | (bits&lmp->def[LEDS_OFF]);
		leds_flash[alt] = (leds_flash[alt]&~bits) | (bits&lmp->def[LEDS_FLASH]);
		break;
	case LEDMAN_CMD_ALT_ON:
		new_alt = (bits & ~leds_alt);
		leds_alt |= bits;
		/*
		 * put any newly alt'd bits into a default state
		 */
		(*lmp->bits)(LEDMAN_CMD_RESET | LEDMAN_CMD_ALTBIT, new_alt);
		for (i = 0; i < 32; i++)
			if (bits & (1 << i))
				leds_alt_cnt[i]++;
		break;
	case LEDMAN_CMD_ALT_OFF:
		for (i = 0; i < 32; i++)
			if ((bits & (1 << i)) && leds_alt_cnt[i]) {
				leds_alt_cnt[i]--;
				if (leds_alt_cnt[i] == 0)
					leds_alt &= ~(1 << i);
			}
		break;
	default:
		return(-EINVAL);
	}
	return(0);
}

/****************************************************************************/

static void
ledman_tick(void)
{
	ledmode_t	*lmp = &led_mode[current_mode];
	int			new_value;
	static int	flash_on = 0;
/*
 *	work out which LED's should be on
 */
	new_value = 0;
	new_value |= (((leds_set[0] | leds_on[0]) & ~leds_off[0]) & ~leds_alt);
	new_value |= (((leds_set[1] | leds_on[1]) & ~leds_off[1]) & leds_alt);
/*
 *	flashing LED's run on their own devices,  ie,  according to the
 *	value fo flash_on
 */
	if ((flash_on++ % 60) >= 30)
		new_value |= ((leds_flash[0]&~leds_alt) | (leds_flash[1]&leds_alt));
	else
		new_value &= ~((leds_flash[0]&~leds_alt) | (leds_flash[1]&leds_alt));
/*
 *	set the HW
 */
 	(*lmp->set)(new_value);
	leds_set[0] = leds_set[1] = 0;
}

/****************************************************************************/
#endif /* !defined(CONFIG_SH_KEYWEST) */
/****************************************************************************/
#if defined(CONFIG_NETtel) && defined(CONFIG_M5307)
/****************************************************************************/
/*
 *	Here it the definition of the LED's on the NETtel circuit board
 *	as per the labels next to them.  The two parallel port LED's steal
 *	some high bits so we can map it more easily onto the HW
 *
 *	LED - D1   D2   D3   D4   D5   D6   D7   D8   D11  D12  
 *	HEX - 100  200  004  008  010  020  040  080  002  001
 *
 */

#include <asm/coldfire.h>
#include <asm/mcfsim.h>
#include <asm/nettel.h>

static ledmap_t	nettel_std = {
	0x3ff, 0x200, 0x100, 0x008, 0x004, 0x020, 0x010, 0x080, 0x080, 0x080,
	0x080, 0x040, 0x040, 0x002, 0x002, 0x024, 0x018, 0x001, 0x0ff, 0x0ff,
	0x000, 0x000, 0x000, 0x000, 0x000
};

#if defined(CONFIG_SNAPGEAR)

/*
 * all snapgear 5307 based boards have a SW link status on the front
 */

static ledmap_t nettel_alt = {
	0x3ff, 0x200, 0x100, 0x040, 0x040, 0x002, 0x002, 0x008, 0x008, 0x020,
	0x020, 0x000, 0x000, 0x000, 0x000, 0x024, 0x018, 0x001, 0x0ff, 0x080,
	0x000, 0x000, 0x080, 0x004, 0x010
};

#else

static ledmap_t nettel_alt = {
	0x3ff, 0x200, 0x100, 0x040, 0x040, 0x002, 0x002, 0x008, 0x004, 0x020,
	0x010, 0x000, 0x000, 0x000, 0x000, 0x024, 0x018, 0x001, 0x0ff, 0x080,
	0x000, 0x000, 0x080, 0x000, 0x000
};

#endif

static leddef_t	nettel_def = {
	0x000, 0x200, 0x000, 0x100,
};

#ifdef ENTERASYS
static ledmap_t enterasys_std = {
	0x3ff, 0x200, 0x100, 0x040, 0x040, 0x002, 0x002, 0x008, 0x004, 0x020,
	0x010, 0x000, 0x000, 0x000, 0x000, 0x024, 0x018, 0x001, 0x00c, 0x030,
	0x000, 0x000, 0x080, 0x000, 0x000
};
  
static leddef_t enterasys_def = {
	0x000, 0x200, 0x000, 0x100,
};
#endif

static void
nettel_set(unsigned long bits)
{
	int			pp;

	* (volatile char *) NETtel_LEDADDR = (~bits & 0xff);
	pp = ~(bits >> 3) & 0x60;
	ppdata = (ppdata & ~0x60) | pp;
	* ((volatile unsigned short *) (MCF_MBAR + MCFSIM_PADAT)) = ppdata;
}

/****************************************************************************/
#endif /* defined(CONFIG_NETtel) && defined(CONFIG_M5307) */
/****************************************************************************/
#if defined(CONFIG_NETtel) && defined(CONFIG_M5272)
/****************************************************************************/

/*
 *	For the SecureEdge Firewall (5272), 5 operational LED's.
 *
 *	LED -   POWER HEARTBEAT PA2    PA3    PA4
 * 	HEX -    001     002    004    008    010
 */

#include <asm/coldfire.h>
#include <asm/mcfsim.h>
#include <asm/nettel.h>

static ledmap_t nt5272_std = {
	0x01f, 0x001, 0x002, 0x008, 0x004, 0x008, 0x004, 0x000, 0x000, 0x000,
	0x000, 0x000, 0x000, 0x000, 0x000, 0x014, 0x008, 0x010, 0x01c, 0x010,
	0x000, 0x000, 0x000, 0x000, 0x000
};

static leddef_t	nt5272_def = {
	0x000, 0x001, 0x000, 0x002,
};

static void nt5272_set(unsigned long bits)
{
	*((volatile unsigned short *) (MCF_MBAR + MCFSIM_PADAT)) = (~bits & 0x1f);
}

/****************************************************************************/
#endif /* defined(CONFIG_NETtel) && defined(CONFIG_M5272) */
/****************************************************************************/
#if defined(CONFIG_MARCONINAP) && defined(CONFIG_M5272)
/****************************************************************************/

/*
 *	For the Marconi/NAP (5272), 2 operational LED's.
 *
 *	LED -   RUNNING DIAG
 * 	HEX -     001    002
 */

#include <asm/coldfire.h>
#include <asm/mcfsim.h>
#include <asm/nap.h>

static ledmap_t nap5272_std = {
	0x003, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000,
	0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000,
	0x000, 0x000, 0x000, 0x000, 0x000
};

static leddef_t	nap5272_def = {
	0x000, 0x001, 0x000, 0x002,
};

static void nap5272_set(unsigned long bits)
{
	volatile unsigned short	*pp;
	pp = (volatile unsigned short *) (MCF_MBAR + MCFSIM_PADAT);
	*pp = (*pp & 0xfffc) | (~bits & 0x3);
}

/****************************************************************************/
#endif /* defined(CONFIG_MARCONINAP) && defined(CONFIG_M5272) */
/****************************************************************************/
#if defined(CONFIG_NETtel) && defined(CONFIG_M5206e)
/****************************************************************************/
/*
 *	For the WebWhale/NETtel1500,  3 LED's (was 2)
 *
 *	LED - HEARTBEAT  DCD    DATA
 * 	HEX -    001     002    004
 */

#include <asm/coldfire.h>
#include <asm/mcfsim.h>
#include <asm/nettel.h>

static ledmap_t nt1500_std = {
	0x007, 0x000, 0x001, 0x004, 0x004, 0x004, 0x004, 0x000, 0x000, 0x000,
	0x000, 0x000, 0x000, 0x000, 0x000, 0x004, 0x002, 0x000, 0x007, 0x000,
	0x002, 0x002, 0x000, 0x000, 0x000
};

static leddef_t	nt1500_def = {
	0x000, 0x000, 0x000, 0x001,
};

static void
nt1500_set(unsigned long bits)
{
	* (volatile char *) NETtel_LEDADDR = (~bits & 0x7);
}

/****************************************************************************/
#endif /* defined(CONFIG_NETtel) && defined(CONFIG_M5206e) */
/****************************************************************************/
#ifdef CONFIG_eLIA
/****************************************************************************/
/*
 *	For the WebWhale,  only 2 LED's
 *
 *	LED - HEARTBEAT  USER
 *	HEX -    2        1
 */

#ifdef CONFIG_COLDFIRE
#include <asm/coldfire.h>
#include <asm/mcfsim.h>
#endif
#include <asm/elia.h>

static ledmap_t elia_std = {
	0x003, 0x000, 0x002, 0x001, 0x001, 0x001, 0x001, 0x000, 0x000, 0x000,
	0x000, 0x000, 0x000, 0x000, 0x000, 0x002, 0x001, 0x000, 0x000, 0x000,
	0x000, 0x000, 0x000, 0x000, 0x000
};

static leddef_t	elia_def = {
	0x000, 0x000, 0x000, 0x002,
};

static void
elia_set(unsigned long bits)
{
	int			pp;

	pp = ~(bits << 12) & 0x3000;
	ppdata = (ppdata & ~0x3000) | pp;
	* ((volatile unsigned short *) (MCF_MBAR + MCFSIM_PADAT)) = ppdata;
}

/****************************************************************************/
#endif /* CONFIG_eLIA */
/****************************************************************************/
/****************************************************************************/
#if defined(CONFIG_X86)
/****************************************************************************/

#include <linux/smp_lock.h>
#include <linux/sched.h>
#include <linux/reboot.h>
#include <linux/delay.h>
#include <asm/io.h>

#if defined(CONFIG_NETtelx86)
/*
 *	Here it the definition of the LED's on the x86 NETtel circuit board
 *	as per the labels next to them.
 *
 *	LED - D1   D2   D3   D4   D5   D6   D7   D8   D9   D10
 *	HEX - 001  002  004  008  010  020  040  080  100  200
 */
static ledmap_t	nettel_std = {
	0x03ff, 0x0002, 0x0001, 0x0100, 0x0100, 0x0080, 0x0080, 0x0010,
	0x0008, 0x0040, 0x0020, 0x0000, 0x0000, 0x0000, 0x0000, 0x0048,
	0x0030, 0x0200, 0x03fc, 0x0004, 0x0000, 0x0000,
};

static leddef_t	nettel_def = {
	0x0000, 0x0002, 0x0000, 0x0001,
};

#elif defined(CONFIG_SITECTRLER)
/*
 *	Here it the definition of the LED's on the SiteController circuit board
 *	as per the labels next to them. (D9 and D10 are not software controlled)
 *
 *	LED -  D1   D2   D3   D4   D5   D6   D7   D8 
 *	HEX - 0001 0002 0004 0008 0010 0020 0040 0080 
 */
static ledmap_t	nettel_std = {
	0x10fd, 0x0001, 0x1000, 0x0004, 0x0004, 0x0008, 0x0008, 0x0040,
	0x0040, 0x0080, 0x0080, 0x0000, 0x0000, 0x0000, 0x0000, 0x00cc,
	0x0030, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
};

static leddef_t	nettel_def = {
	0x0000, 0x0001, 0x0000, 0x1000,
};

#endif

static volatile unsigned short	*ledman_ledp;

static void nettel_set(unsigned long bits)
{
	*ledman_ledp = (~bits & 0xffff);
}

#if defined(CONFIG_JFFS_FS) || defined(CONFIG_JFFS2_FS)

static void ledman_interrupt(int irq, void *dev_id, struct pt_regs *regs)
{
	static unsigned long firstjiffies = 0;
	if (jiffies > (firstjiffies + (2 * HZ))) {
		firstjiffies = jiffies;
		printk("LED: reset switch interrupt! (sending signal to pid=%d)\n",
					ledman_resetpid);
	}
	kill_proc(ledman_resetpid, SIGUSR2, 1);
}

#elif defined(CONFIG_BLK_DEV_BLKMEM)

static void ledman_interrupt(int irq, void *dev_id, struct pt_regs *regs)
{
	extern int flash_eraseconfig(void);

	printk("LED: reset switch interrupt!\n");
	mdelay(1000);
	flash_eraseconfig();
	machine_restart(NULL);
}

#else

static void ledman_eraseconfig_handler(void *v)
{
	extern void nettel_eraseconfig(void);
	nettel_eraseconfig();
	printk(KERN_EMERG "Restarting system.\n");
	machine_restart(NULL);
}

struct tq_struct ledman_eraseconfig_tq = {
	routine: ledman_eraseconfig_handler
};

static void ledman_interrupt(int irq, void *dev_id, struct pt_regs *regs)
{
	printk("LED: reset switch interrupt!\n");
	mdelay(1000);

#if LINUX_VERSION_CODE < 0x020300
	queue_task(&ledman_eraseconfig_tq, &tq_scheduler);
#else
	schedule_task(&ledman_eraseconfig_tq);
#endif
}

#endif

static void ledman_initx86(void)
{
	volatile unsigned char	*mmcrp;

	/* Map the CPU MMCR register for access */
	mmcrp = (volatile unsigned char *) ioremap(0xfffef000, 4096);

	ledman_ledp = (volatile unsigned short *) (mmcrp + 0xc30);

	/* Setup extern "factory default" switch on IRQ12 */
	if (request_irq(12, ledman_interrupt, SA_INTERRUPT, "Reset", NULL))
		printk("LED: failed to register IRQ12 for Reset witch\n");
	else
		printk("LED: registered RESET switch on IRQ12\n");
}

/****************************************************************************/
#endif /* CONFIG_X86 */
/****************************************************************************/
/****************************************************************************/
#if defined(CONFIG_SH_KEYWEST)
/****************************************************************************/
/*
 *	Here it the definition of the how we use the 8 segment LED display on
 *	the Hitachi Keywest
 *
 *	LED - LD0  LD1  LD2  LD3  LD4  LD5  LD6  LD7
 *	HEX - 001  002  004  008  010  020  040  080
 *        HB   CNT  L1R  L1T  L2R  L2T  COM  VPN
 *
 */

#include <linux/kernel_stat.h>

#define KEYWEST_NUM_LEDS 8
#define	KEYWEST_LED_ADDR	0xb1ffe000

static ledmap_t	keywest_std = {
	0x0ff, 0x000, 0x001, 0x040, 0x040, 0x040, 0x040, 0x004, 0x008, 0x010,
	0x020, 0x000, 0x000, 0x000, 0x000, 0x054, 0x02a, 0x080, 0x07e, 0x000,
	0x000, 0x000,
};

static leddef_t	keywest_def = {
	0x000, 0x000, 0x000, 0x001,
};

static struct keywest_led_value {
	int				count;
	int				max;
	int				prev;
	unsigned char	disp;
} keywest_led_values[KEYWEST_NUM_LEDS][2];


struct keywest_font_s {
	unsigned char row[7];
} keywest_font[] = {
	{{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }}, /* bar 0 */
	{{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1f }}, /* bar 1 */
	{{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x1f, 0x1f }}, /* bar 2 */
	{{ 0x00, 0x00, 0x00, 0x00, 0x1f, 0x1f, 0x1f }}, /* bar 3 */
	{{ 0x00, 0x00, 0x00, 0x1f, 0x1f, 0x1f, 0x1f }}, /* bar 4 */
	{{ 0x00, 0x00, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f }}, /* bar 5 */
	{{ 0x00, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f }}, /* bar 6 */
	{{ 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f }}, /* bar 7 */
	{{ 0x00, 0x0a, 0x1f, 0x1f, 0x0e, 0x04, 0x00 }}, /* heart */
	{{ 0x08, 0x14, 0x14, 0x1c, 0x1c, 0x1c, 0x1c }}, /* vpn locked */
	{{ 0x02, 0x05, 0x05, 0x1c, 0x1c, 0x1c, 0x1c }}, /* vpn unlocked */
};

static unsigned int keywest_old_cntx = 0;

/*
 * program up some display bars
 */

static void ledman_initkeywest()
{
	int i, j;

	for (i = 0; i < sizeof(keywest_font) / sizeof(struct keywest_font_s); i++) {
		* (unsigned char *)(KEYWEST_LED_ADDR+0x20) = i;
		for (j = 0; j < 7; j++)
			* (unsigned char *)(KEYWEST_LED_ADDR+0x28+j) =
					keywest_font[i].row[j];
	}
	keywest_old_cntx = kstat.context_swtch;
}

/*
 *	We just rip through and write all LED 'disp' chars each tick.
 */

static void keywest_set(unsigned long bits)
{
	int i, alt;
	for (i = 0; i < KEYWEST_NUM_LEDS; i++) {
		alt = (leds_alt & (1 << i)) ? 1 : 0;
		* (unsigned char *)(KEYWEST_LED_ADDR+0x38+i) =
				keywest_led_values[i][alt].disp;
	}
}

static int
keywest_bits(unsigned long cmd, unsigned long bits)
{
	ledmode_t		*lmp = &led_mode[current_mode];
	int				 alt, i;
	unsigned long	 new_alt;

	alt = (cmd & LEDMAN_CMD_ALTBIT) ? 1 : 0;

	switch (cmd & ~LEDMAN_CMD_ALTBIT) {
	case LEDMAN_CMD_SET:
		bits   &= ~(leds_flash[alt]|leds_on[alt]|leds_off[alt]);
		for (i = 0; i < KEYWEST_NUM_LEDS; i++)
			if (bits & (1 << i))
				keywest_led_values[i][alt].count++;
		break;
	case LEDMAN_CMD_ON:
		leds_on[alt]    |= bits;
		leds_off[alt]   &= ~bits;
		leds_flash[alt] &= ~bits;
		(*lmp->tick)();
		break;
	case LEDMAN_CMD_OFF:
		leds_on[alt]    &= ~bits;
		leds_off[alt]   |= bits;
		leds_flash[alt] &= ~bits;
		(*lmp->tick)();
		break;
	case LEDMAN_CMD_FLASH:
		leds_on[alt]    &= ~bits;
		leds_off[alt]   &= ~bits;
		leds_flash[alt] |= bits;
		break;
	case LEDMAN_CMD_RESET:
		leds_on[alt]    = (leds_on[alt]   &~bits) | (bits&lmp->def[LEDS_ON]);
		leds_off[alt]   = (leds_off[alt]  &~bits) | (bits&lmp->def[LEDS_OFF]);
		leds_flash[alt] = (leds_flash[alt]&~bits) | (bits&lmp->def[LEDS_FLASH]);
		memset(keywest_led_values, 0, sizeof(keywest_led_values));
		break;
	case LEDMAN_CMD_ALT_ON:
		new_alt = (bits & ~leds_alt);
		leds_alt |= bits;
		/*
		 * put any newly alt'd bits into a default state
		 */
		(*lmp->bits)(LEDMAN_CMD_RESET | LEDMAN_CMD_ALTBIT, new_alt);
		for (i = 0; i < 32; i++)
			if (bits & (1 << i))
				leds_alt_cnt[i]++;
		break;
	case LEDMAN_CMD_ALT_OFF:
		for (i = 0; i < 32; i++)
			if ((bits & (1 << i)) && leds_alt_cnt[i]) {
				leds_alt_cnt[i]--;
				if (leds_alt_cnt[i] == 0)
					leds_alt &= ~(1 << i);
			}
		break;
	default:
		return(-EINVAL);
	}
	return(0);
}

static void
keywest_tick(void)
{
	ledmode_t	*lmp = &led_mode[current_mode];
	int			alt, i;
	static int	flash_on = 0;
	struct keywest_led_value *led_value;

	/*
	 * we take over the second LED as a context switch indicator
	 */
	keywest_led_values[1][0].count = kstat.context_swtch - keywest_old_cntx;
	keywest_old_cntx = kstat.context_swtch;

	for (i = 0; i < KEYWEST_NUM_LEDS; i++) {
		alt = (leds_alt >> i) & 1;
		led_value = &keywest_led_values[i][alt];
		if (leds_off[alt] & (1 << i)) {
			if ((1 << i) == 0x080) /* VPN unlock */
				led_value->disp = 0x8a;
			else
				led_value->disp = 0x20;
		} else if (leds_on[alt] & (1 << i)) {
			if ((1 << i) == 0x080) /* VPN lock */
				led_value->disp = 0x89;
			else
				led_value->disp = 0x87;
		} else if (leds_flash[alt] & (1 << i)) {
			if ((flash_on % 6) >= 3) {
				if ((1 << i) == 0x001) /* heart beat */
					led_value->disp = 0x88;
				else
					led_value->disp = 0x87;
			} else
				led_value->disp = 0x20;
		} else {
			int val;

			if (led_value->count > led_value->max)
				led_value->max = led_value->count;
			
			val = (led_value->prev + led_value->count) / 2;
			led_value->prev = val;

			val = (val * 7) / led_value->max;
			if (val == 0 && led_value->count)
				val = 1;
			led_value->disp = 0x80 + (val & 0x7);
			led_value->count = 0;
			/* degrade the maximum over time (except load) */
			if (i != 1)
				led_value->max = (led_value->max * 9)/10;
		}
	}
	flash_on++;
 	(*lmp->set)(0);
}

/****************************************************************************/
#endif /* CONFIG_SH_KEYWEST */
/****************************************************************************/
