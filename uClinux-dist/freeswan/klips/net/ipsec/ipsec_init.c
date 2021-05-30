/*
 * Initialization code, and /proc file system interface code.
 * Copyright (C) 1996, 1997  John Ioannidis.
 * Copyright (C) 1998, 1999, 2000, 2001  Richard Guy Briggs.
 * 
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 * 
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

char ipsec_init_c_version[] = "RCSID $Id: ipsec_init.c,v 1.69 2001/06/14 19:33:26 rgb Exp $";

#include <linux/config.h>
#include <linux/version.h>

#include <linux/module.h>
#include <linux/kernel.h> /* printk() */
#include <linux/malloc.h> /* kmalloc() */
#include <linux/errno.h>  /* error codes */
#include <linux/types.h>  /* size_t */
#include <linux/interrupt.h> /* mark_bh */

#include <linux/netdevice.h>   /* struct device, and other headers */
#include <linux/etherdevice.h> /* eth_type_trans */
#include <linux/ip.h>          /* struct iphdr */
#include <linux/in.h>          /* struct sockaddr_in */
#include <linux/skbuff.h>
#include <freeswan.h>
#ifdef SPINLOCK
#ifdef SPINLOCK_23
#include <linux/spinlock.h> /* *lock* */
#else /* SPINLOCK_23 */
#include <asm/spinlock.h> /* *lock* */
#endif /* SPINLOCK_23 */
#endif /* SPINLOCK */
#ifdef NET_21
#include <asm/uaccess.h>
#include <linux/in6.h>
#endif /* NET_21 */
#include <asm/checksum.h>
#include <net/ip.h>
#ifdef CONFIG_PROC_FS
#include <linux/proc_fs.h>
#endif /* CONFIG_PROC_FS */
#ifdef NETLINK_SOCK
#include <linux/netlink.h>
#else
#include <net/netlink.h>
#endif

#include "radij.h"
#include "ipsec_encap.h"
#include "ipsec_radij.h"
#include "ipsec_netlink.h"
#include "ipsec_xform.h"
#include "ipsec_tunnel.h"

#include "version.c"

#include "ipsec_rcv.h"
#include "ipsec_ah.h"
#include "ipsec_esp.h"

#ifdef CONFIG_IPSEC_IPCOMP
#include "ipcomp.h"
#endif /* CONFIG_IPSEC_IPCOMP */

#include <pfkeyv2.h>
#include <pfkey.h>

extern char *radij_c_version;

#ifdef CONFIG_IPSEC_DEBUG
int debug_eroute = 0;
int debug_spi = 0;
#endif /* CONFIG_IPSEC_DEBUG */

#ifdef CONFIG_PROC_FS
#ifndef PROC_FS_2325
DEBUG_NO_STATIC
#endif /* PROC_FS_2325 */
int
ipsec_eroute_get_info(char *buffer, char **start, off_t offset, int length
#ifndef PROC_NO_DUMMY
, int dummy
#endif /* !PROC_NO_DUMMY */
)
{
	struct wsbuf w = {buffer, length, offset, 0, 0, 0, 0};

#ifdef CONFIG_IPSEC_DEBUG
	if (debug_radij & DB_RJ_DUMPTREES)
	  rj_dumptrees();			/* XXXXXXXXX */
#endif /* CONFIG_IPSEC_DEBUG */

	KLIPS_PRINT(debug_tunnel & DB_TN_PROCFS,
		    "klips_debug:ipsec_eroute_get_info: "
		    "buffer=0x%p, *start=0x%x, offset=%d, length=%d\n",
		    buffer,
		    (u_int)*start,
		    (int)offset,
		    length);

	spin_lock_bh(&eroute_lock);

	rj_walktree(rnh, ipsec_rj_walker_procprint, &w);
/*	rj_walktree(mask_rjhead, ipsec_rj_walker_procprint, &w); */

	spin_unlock_bh(&eroute_lock);

	*start = buffer + (offset - w.begin);	/* Start of wanted data */
	w.len -= (offset - w.begin);			/* Start slop */
	if (w.len > length)
		w.len = length;
	return w.len;
}

#ifndef PROC_FS_2325
DEBUG_NO_STATIC
#endif /* PROC_FS_2325 */
int
ipsec_spi_get_info(char *buffer, char **start, off_t offset, int length
#ifndef  PROC_NO_DUMMY
, int dummy
#endif /* !PROC_NO_DUMMY */
)
{
	int len = 0;
	off_t pos = 0, begin = 0;
	int i;
	struct tdb *tdbp;
	char sa[SATOA_BUF];
	char buf_s[ADDRTOA_BUF];
#if 0
	char buf_d[ADDRTOA_BUF];
#endif
	size_t sa_len;

	KLIPS_PRINT(debug_tunnel & DB_TN_PROCFS,
		    "klips_debug:ipsec_spi_get_info: "
		    "buffer=0x%p, *start=0x%x, offset=%d, length=%d\n",
		    buffer,
		    (u_int)*start,
		    (int)offset,
		    length);
	
	spin_lock_bh(&tdb_lock);
	
	for (i = 0; i < TDB_HASHMOD; i++) {
		for (tdbp = tdbh[i]; tdbp; tdbp = tdbp->tdb_hnext) {
			sa_len = satoa(tdbp->tdb_said, 0, sa, SATOA_BUF);
			len += sprintf(buffer + len, "%s ", sa_len ? sa : " (error)");
			len += sprintf(buffer + len, "%s%s%s", TDB_XFORM_NAME(tdbp));
			len += sprintf(buffer + len, ": dir=%s",
				       (tdbp->tdb_flags & EMT_INBOUND) ?
				       "in " : "out");
#if 0
			if((tdbp->tdb_said.proto == IPPROTO_IPIP) && tdbp->tdb_addr_s && tdbp->tdb_addr_d) {
				addrtoa(((struct sockaddr_in*)(tdbp->tdb_addr_s))->sin_addr,
					0, buf_s, sizeof(buf_s));
				addrtoa(((struct sockaddr_in*)(tdbp->tdb_addr_d))->sin_addr,
					0, buf_d, sizeof(buf_d));
				len += sprintf(buffer + len, " %s -> %s",
					       buf_s, buf_d);
			}
#else
			if(tdbp->tdb_addr_s) {
				addrtoa(((struct sockaddr_in*)(tdbp->tdb_addr_s))->sin_addr,
					0, buf_s, sizeof(buf_s));
				len += sprintf(buffer + len, " src=%s",
					       buf_s);
			}
#endif

			if(tdbp->tdb_iv_bits) {
				int j;
				len += sprintf(buffer + len, " iv_bits=%dbits iv=0x",
					       tdbp->tdb_iv_bits);
				for(j = 0; j < tdbp->tdb_iv_bits / 8; j++) {
					len += sprintf(buffer + len, "%02x",
						       (__u32)((__u8*)(tdbp->tdb_iv))[j]);
				}
			}
			if(tdbp->tdb_encalg || tdbp->tdb_authalg) {
				if(tdbp->tdb_replaywin) {
					len += sprintf(buffer + len, " ooowin=%d",
						       tdbp->tdb_replaywin);
				}
				if(tdbp->tdb_replaywin_errs) {
					len += sprintf(buffer + len, " ooo_errs=%d",
						       tdbp->tdb_replaywin_errs);
				}
				if(tdbp->tdb_replaywin_lastseq) {
                                       len += sprintf(buffer + len, " seq=%d",
						      tdbp->tdb_replaywin_lastseq);
				}
				if(tdbp->tdb_replaywin_bitmap) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,3,0)
					len += sprintf(buffer + len, " bit=0x%Lx",
						       tdbp->tdb_replaywin_bitmap);
#else
					len += sprintf(buffer + len, " bit=0x%x%08x",
						       (__u32)(tdbp->tdb_replaywin_bitmap >> 32),
						       (__u32)tdbp->tdb_replaywin_bitmap);
#endif
				}
				if(tdbp->tdb_replaywin_maxdiff) {
					len += sprintf(buffer + len, " max_seq_diff=%d",
						       tdbp->tdb_replaywin_maxdiff);
				}
			}
			if(tdbp->tdb_flags & ~EMT_INBOUND) {
				len += sprintf(buffer + len, " flags=0x%x",
					       tdbp->tdb_flags & ~EMT_INBOUND);
				len += sprintf(buffer + len, "<");
				/* flag printing goes here */
				len += sprintf(buffer + len, ">");
			}
			if(tdbp->tdb_auth_bits) {
				len += sprintf(buffer + len, " alen=%d",
					       tdbp->tdb_auth_bits);
			}
			if(tdbp->tdb_key_bits_a) {
				len += sprintf(buffer + len, " aklen=%d",
					       tdbp->tdb_key_bits_a);
			}
			if(tdbp->tdb_auth_errs) {
				len += sprintf(buffer + len, " auth_errs=%d",
					       tdbp->tdb_auth_errs);
			}
			if(tdbp->tdb_key_bits_e) {
				len += sprintf(buffer + len, " eklen=%d",
					       tdbp->tdb_key_bits_e);
			}
			if(tdbp->tdb_encsize_errs) {
				len += sprintf(buffer + len, " encr_size_errs=%d",
					       tdbp->tdb_encsize_errs);
			}
			if(tdbp->tdb_encpad_errs) {
				len += sprintf(buffer + len, " encr_pad_errs=%d",
					       tdbp->tdb_encpad_errs);
			}
			
			len += sprintf(buffer + len, " life(c,s,h)=");
			if(tdbp->tdb_lifetime_allocations_c > 1 || 
			   tdbp->tdb_lifetime_allocations_s ||
			   tdbp->tdb_lifetime_allocations_h) {
				len += sprintf(buffer + len, "alloc(%d,%d,%d)",
					       (int)(jiffies - tdbp->tdb_lifetime_allocations_c),
					       tdbp->tdb_lifetime_allocations_s,
					       (int)tdbp->tdb_lifetime_allocations_h);
			}
			if(tdbp->tdb_lifetime_bytes_c ||
			   tdbp->tdb_lifetime_bytes_s ||
			   tdbp->tdb_lifetime_bytes_h) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,3,0)
				len += sprintf(buffer + len, "bytes(%Ld,%Ld,%Ld)",
					       tdbp->tdb_lifetime_bytes_c,
					       tdbp->tdb_lifetime_bytes_s,
					       tdbp->tdb_lifetime_bytes_h);
#else /* XXX high 32 bits are not displayed */
				len += sprintf(buffer + len, "bytes(%lu,%lu,%lu)",
					       (unsigned long)tdbp->tdb_lifetime_bytes_c,
					       (unsigned long)tdbp->tdb_lifetime_bytes_s,
					       (unsigned long)tdbp->tdb_lifetime_bytes_h);
#endif

			}
			if(tdbp->tdb_lifetime_addtime_c ||
			   tdbp->tdb_lifetime_addtime_s ||
			   tdbp->tdb_lifetime_addtime_h) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,3,0)
				len += sprintf(buffer + len, "add(%Ld,%Ld,%Ld)",
					       jiffies / HZ - tdbp->tdb_lifetime_addtime_c,
					       tdbp->tdb_lifetime_addtime_s,
					       tdbp->tdb_lifetime_addtime_h);
#else
				len += sprintf(buffer + len, "add(%lu,%lu,%lu)",
					       jiffies / HZ - (unsigned long)tdbp->tdb_lifetime_addtime_c,
					       (unsigned long)tdbp->tdb_lifetime_addtime_s,
					       (unsigned long)tdbp->tdb_lifetime_addtime_h);
#endif
			}
			if(tdbp->tdb_lifetime_usetime_c ||
			   tdbp->tdb_lifetime_usetime_s ||
			   tdbp->tdb_lifetime_usetime_h) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,3,0)
				len += sprintf(buffer + len, "use(%Ld,%Ld,%Ld)",
					       tdbp->tdb_lifetime_usetime_c ?
						jiffies / HZ - tdbp->tdb_lifetime_usetime_c : 0,
					       tdbp->tdb_lifetime_usetime_s,
					       tdbp->tdb_lifetime_usetime_h);
#else
				len += sprintf(buffer + len, "use(%lu,%lu,%lu)",
					       tdbp->tdb_lifetime_usetime_c ?
						jiffies / HZ - (unsigned long)tdbp->tdb_lifetime_usetime_c : 0,
					       (unsigned long)tdbp->tdb_lifetime_usetime_s,
					       (unsigned long)tdbp->tdb_lifetime_usetime_h);
#endif
			}
			if(tdbp->tdb_lifetime_packets_c ||
			   tdbp->tdb_lifetime_packets_s ||
			   tdbp->tdb_lifetime_packets_h) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,3,0)
				len += sprintf(buffer + len, "packets(%Ld,%Ld,%Ld)",
					       tdbp->tdb_lifetime_packets_c,
					       tdbp->tdb_lifetime_packets_s,
					       tdbp->tdb_lifetime_packets_h);
#else
				len += sprintf(buffer + len, "packets(%lu,%lu,%lu)",
					       (unsigned long)tdbp->tdb_lifetime_packets_c,
					       (unsigned long)tdbp->tdb_lifetime_packets_s,
					       (unsigned long)tdbp->tdb_lifetime_packets_h);
#endif
			}

			if(tdbp->tdb_lifetime_usetime_c) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,3,0)
				len += sprintf(buffer + len, " idle=%Ld",
					       jiffies / HZ - tdbp->tdb_lifetime_usetime_l);
#else
				len += sprintf(buffer + len, " idle=%lu",
					       jiffies / HZ - (unsigned long)tdbp->tdb_lifetime_usetime_l);
#endif
			}

#ifdef CONFIG_IPSEC_IPCOMP
			if(tdbp->tdb_said.proto == IPPROTO_COMP &&
			   (tdbp->tdb_comp_ratio_dbytes ||
			    tdbp->tdb_comp_ratio_cbytes)) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,3,0)
				len += sprintf(buffer + len, " ratio=%Ld:%Ld",
					       tdbp->tdb_comp_ratio_dbytes,
					       tdbp->tdb_comp_ratio_cbytes);
#else
				len += sprintf(buffer + len, " ratio=%lu:%lu",
					       (unsigned long)tdbp->tdb_comp_ratio_dbytes,
					       (unsigned long)tdbp->tdb_comp_ratio_cbytes);
#endif
			}
#endif /* CONFIG_IPSEC_IPCOMP */

			len += sprintf(buffer + len, "\n");

			pos = begin + len;
			if(pos < offset) {
				len = 0;
				begin = pos;
			}
			if (pos > offset + length) {
				goto done_spi_i;
			}
		}
	}

 done_spi_i:	
	spin_unlock_bh(&tdb_lock);

	*start = buffer + (offset - begin);	/* Start of wanted data */
	len -= (offset - begin);			/* Start slop */
	if (len > length)
		len = length;
	return len;
}

#ifndef PROC_FS_2325
DEBUG_NO_STATIC
#endif /* PROC_FS_2325 */
int
ipsec_spigrp_get_info(char *buffer, char **start, off_t offset, int length
#ifndef PROC_NO_DUMMY
, int dummy
#endif /* !PROC_NO_DUMMY */
)
{
	int len = 0;
	off_t pos = 0, begin = 0;
	int i;
	struct tdb *tdbp, *tdbp2;
	char sa[SATOA_BUF];
	size_t sa_len;

	KLIPS_PRINT(debug_tunnel & DB_TN_PROCFS,
		    "klips_debug:ipsec_spigrp_get_info: "
		    "buffer=0x%p, *start=0x%x, offset=%d, length=%d\n",
		    buffer,
		    (u_int)*start,
		    (int)offset,
		    length);

	spin_lock_bh(&tdb_lock);
	
	for (i = 0; i < TDB_HASHMOD; i++) {
		for (tdbp = tdbh[i]; tdbp; tdbp = tdbp->tdb_hnext)
		{
			if(!tdbp->tdb_inext)
			{
				tdbp2 = tdbp;
				while(tdbp2) {
					sa_len = satoa(tdbp2->tdb_said, 0, sa, SATOA_BUF);
					len += sprintf(buffer + len, "%s ",
						       sa_len ? sa : " (error)");
					tdbp2 = tdbp2->tdb_onext;
				}
				len += sprintf(buffer + len, "\n");
				pos = begin + len;
				if(pos < offset) {
					len = 0;
					begin = pos;
				}
				if (pos > offset + length) {
					goto done_spigrp_i;
				}
			}
		}
	}

 done_spigrp_i:	
	spin_unlock_bh(&tdb_lock);

	*start = buffer + (offset - begin);	/* Start of wanted data */
	len -= (offset - begin);			/* Start slop */
	if (len > length)
		len = length;
	return len;
}

#ifndef PROC_FS_2325
DEBUG_NO_STATIC
#endif /* PROC_FS_2325 */
int
ipsec_tncfg_get_info(char *buffer, char **start, off_t offset, int length
#ifndef PROC_NO_DUMMY
, int dummy
#endif /* !PROC_NO_DUMMY */
)
{
	int len = 0;
	off_t pos = 0, begin = 0;
	int i;
	char name[9];
	struct device *dev, *privdev;
	struct ipsecpriv *priv;

	KLIPS_PRINT(debug_tunnel & DB_TN_PROCFS,
		    "klips_debug:ipsec_tncfg_get_info: "
		    "buffer=0x%p, *start=0x%x, offset=%d, length=%d\n",
		    buffer,
		    (u_int)*start,
		    (int)offset,
		    length);

	for(i = 0; i < IPSEC_NUM_IF; i++) {
		sprintf(name, "ipsec%d", i);
		dev = ipsec_dev_get(name);
		if(dev) {
			priv = (struct ipsecpriv *)(dev->priv);
			len += sprintf(buffer + len, "%s",
				       dev->name);
			if(priv) {
				privdev = (struct device *)(priv->dev);
				len += sprintf(buffer + len, " -> %s",
					       privdev ? privdev->name : "NULL");
				len += sprintf(buffer + len, " mtu=%d(%d) -> %d",
					       dev->mtu,
					       priv->mtu,
					       privdev ? privdev->mtu : 0);
			} else {
				KLIPS_PRINT(debug_tunnel & DB_TN_PROCFS,
					    "klips_debug:ipsec_tncfg_get_info: device '%s' has no private data space!\n",
					    dev->name);
			}
			len += sprintf(buffer + len, "\n");

			pos = begin + len;
			if(pos < offset) {
				len = 0;
				begin = pos;
			}
			else if (pos > offset + length)	{
				break;
			}
		}
	}
	*start = buffer + (offset - begin);	/* Start of wanted data */
	len -= (offset - begin);			/* Start slop */
	if (len > length)
		len = length;
	return len;
}

#ifndef PROC_FS_2325
DEBUG_NO_STATIC
#endif /* PROC_FS_2325 */
int
ipsec_version_get_info(char *buffer, char **start, off_t offset, int length
#ifndef PROC_NO_DUMMY
, int dummy
#endif /* !PROC_NO_DUMMY */
)
{
	int len = 0;
	off_t begin = 0;

	KLIPS_PRINT(debug_tunnel & DB_TN_PROCFS,
		    "klips_debug:ipsec_version_get_info: "
		    "buffer=0x%p, *start=0x%x, offset=%d, length=%d\n",
		    buffer,
		    (u_int)*start,
		    (int)offset,
		    length);

	len += sprintf(buffer + len, "FreeS/WAN version: %s\n", freeswan_version);
#if 0
	KLIPS_PRINT(debug_tunnel & DB_TN_PROCFS,
		    "klips_debug:ipsec_version_get_info: "
		    "ipsec_init version: %s\n",
		    ipsec_init_c_version);
	KLIPS_PRINT(debug_tunnel & DB_TN_PROCFS,
		    "klips_debug:ipsec_version_get_info: "
		    "ipsec_tunnel version: %s\n",
		    ipsec_tunnel_c_version);
	KLIPS_PRINT(debug_tunnel & DB_TN_PROCFS,
		    "klips_debug:ipsec_version_get_info: "
		    "ipsec_netlink version: %s\n",
		    ipsec_netlink_c_version);
	KLIPS_PRINT(debug_tunnel & DB_TN_PROCFS,
		    "klips_debug:ipsec_version_get_info: "
		    "radij_c_version: %s\n",
		    radij_c_version);
#endif

	*start = buffer + (offset - begin);	/* Start of wanted data */
	len -= (offset - begin);			/* Start slop */
	if (len > length)
		len = length;
	return len;
}

#ifdef CONFIG_IPSEC_DEBUG
#ifndef PROC_FS_2325
DEBUG_NO_STATIC
#endif /* PROC_FS_2325 */
int
ipsec_klipsdebug_get_info(char *buffer, char **start, off_t offset, int length
#ifndef PROC_NO_DUMMY
, int dummy
#endif /* !PROC_NO_DUMMY */
)
{
	int len = 0;
	off_t begin = 0;

	KLIPS_PRINT(debug_tunnel & DB_TN_PROCFS,
		    "klips_debug:ipsec_klipsdebug_get_info: "
		    "buffer=0x%p, *start=0x%x, offset=%d, length=%d\n",
		    buffer,
		    (u_int)*start,
		    (int)offset,
		    length);

	len += sprintf(buffer + len, "debug_tunnel=%08x.\n", debug_tunnel);
	len += sprintf(buffer + len, "debug_netlink=%08x.\n", debug_netlink);
	len += sprintf(buffer + len, "debug_xform=%08x.\n", debug_xform);
	len += sprintf(buffer + len, "debug_eroute=%08x.\n", debug_eroute);
	len += sprintf(buffer + len, "debug_spi=%08x.\n", debug_spi);
	len += sprintf(buffer + len, "debug_radij=%08x.\n", debug_radij);
	len += sprintf(buffer + len, "debug_esp=%08x.\n", debug_esp);
	len += sprintf(buffer + len, "debug_ah=%08x.\n", debug_ah);
	len += sprintf(buffer + len, "debug_rcv=%08x.\n", debug_rcv);
	len += sprintf(buffer + len, "debug_pfkey=%08x.\n", debug_pfkey);

	*start = buffer + (offset - begin);	/* Start of wanted data */
	len -= (offset - begin);			/* Start slop */
	if (len > length)
		len = length;
	return len;
}
#endif /* CONFIG_IPSEC_DEBUG */

#ifndef PROC_FS_2325
struct proc_dir_entry ipsec_eroute =
{
	0,
	12, "ipsec_eroute",
	S_IFREG | S_IRUGO, 1, 0, 0, 0,
	&proc_net_inode_operations,
	ipsec_eroute_get_info,
	NULL, NULL, NULL, NULL, NULL
};

struct proc_dir_entry ipsec_spi =
{
	0,
	9, "ipsec_spi",
	S_IFREG | S_IRUGO, 1, 0, 0, 0,
	&proc_net_inode_operations,
	ipsec_spi_get_info,
	NULL, NULL, NULL, NULL, NULL
};

struct proc_dir_entry ipsec_spigrp =
{
	0,
	12, "ipsec_spigrp",
	S_IFREG | S_IRUGO, 1, 0, 0, 0,
	&proc_net_inode_operations,
	ipsec_spigrp_get_info,
	NULL, NULL, NULL, NULL, NULL
};

struct proc_dir_entry ipsec_tncfg =
{
	0,
	11, "ipsec_tncfg",
	S_IFREG | S_IRUGO, 1, 0, 0, 0,
	&proc_net_inode_operations,
	ipsec_tncfg_get_info,
	NULL, NULL, NULL, NULL, NULL
};

struct proc_dir_entry ipsec_version =
{
	0,
	13, "ipsec_version",
	S_IFREG | S_IRUGO, 1, 0, 0, 0,
	&proc_net_inode_operations,
	ipsec_version_get_info,
	NULL, NULL, NULL, NULL, NULL
};

#ifdef CONFIG_IPSEC_DEBUG
struct proc_dir_entry ipsec_klipsdebug =
{
	0,
	16, "ipsec_klipsdebug",
	S_IFREG | S_IRUGO, 1, 0, 0, 0,
	&proc_net_inode_operations,
	ipsec_klipsdebug_get_info,
	NULL, NULL, NULL, NULL, NULL
};
#endif /* CONFIG_IPSEC_DEBUG */
#endif /* !PROC_FS_2325 */
#endif /* CONFIG_PROC_FS */

int ipsec_device_event(struct notifier_block *dnot, unsigned long event, void *ptr);
/*
 * the following structure is required so that we receive
 * event notifications when network devices are enabled and
 * disabled (ifconfig up and down).
 */
static struct notifier_block ipsec_dev_notifier={
	ipsec_device_event,
	NULL,
	0
};

#ifdef CONFIG_SYSCTL
extern int ipsec_sysctl_register(void);
extern void ipsec_sysctl_unregister(void);
#endif

/* void */
int
ipsec_init(void)
{
	int error = 0;

#ifdef CONFIG_PROC_FS
#  ifndef PROC_FS_2325
#    ifdef PROC_FS_21
	error |= proc_register(proc_net, &ipsec_eroute);
	error |= proc_register(proc_net, &ipsec_spi);
	error |= proc_register(proc_net, &ipsec_spigrp);
	error |= proc_register(proc_net, &ipsec_tncfg);
	error |= proc_register(proc_net, &ipsec_version);
#      ifdef CONFIG_IPSEC_DEBUG
	error |= proc_register(proc_net, &ipsec_klipsdebug);
#      endif /* CONFIG_IPSEC_DEBUG */
#    else /* PROC_FS_21 */
	error |= proc_register_dynamic(&proc_net, &ipsec_eroute);
	error |= proc_register_dynamic(&proc_net, &ipsec_spi);
	error |= proc_register_dynamic(&proc_net, &ipsec_spigrp);
	error |= proc_register_dynamic(&proc_net, &ipsec_tncfg);
	error |= proc_register_dynamic(&proc_net, &ipsec_version);
#      ifdef CONFIG_IPSEC_DEBUG
	error |= proc_register_dynamic(&proc_net, &ipsec_klipsdebug);
#      endif /* CONFIG_IPSEC_DEBUG */
#    endif /* PROC_FS_21 */
#  else /* !PROC_FS_2325 */
	proc_net_create ("ipsec_eroute", 0, ipsec_eroute_get_info);
	proc_net_create ("ipsec_spi", 0, ipsec_spi_get_info);
	proc_net_create ("ipsec_spigrp", 0, ipsec_spigrp_get_info);
	proc_net_create ("ipsec_tncfg", 0, ipsec_tncfg_get_info);
	proc_net_create ("ipsec_version", 0, ipsec_version_get_info);
#    ifdef CONFIG_IPSEC_DEBUG
	proc_net_create ("ipsec_klipsdebug", 0, ipsec_klipsdebug_get_info);
#    endif /* CONFIG_IPSEC_DEBUG */
#  endif /* !PROC_FS_2325 */
#endif          /* CONFIG_PROC_FS */

	KLIPS_PRINT(1, "klips_info:ipsec_init: "
		    "KLIPS startup, FreeS/WAN IPSec version: %s\n",
		    freeswan_version);

#ifndef SPINLOCK
	tdb_lock.lock = 0;
	eroute_lock.lock = 0;
#endif /* !SPINLOCK */

	error |= ipsec_tdbinit();
	error |= ipsec_radijinit();

	error |= pfkey_init();

	error |= register_netdevice_notifier(&ipsec_dev_notifier);

#ifdef CONFIG_IPSEC_ESP
	inet_add_protocol(&esp_protocol);
#endif /* CONFIG_IPSEC_ESP */

#ifdef CONFIG_IPSEC_AH
	inet_add_protocol(&ah_protocol);
#endif /* CONFIG_IPSEC_AH */

#if 0
#ifdef CONFIG_IPSEC_IPCOMP
	inet_add_protocol(&comp_protocol);
#endif /* CONFIG_IPSEC_IPCOMP */
#endif

	error |= ipsec_tunnel_init_devices();

#ifdef CONFIG_SYSCTL
        error |= ipsec_sysctl_register();
#endif                                                                          

#if LINUX_VERSION_CODE < 0x020100
	libdes_init();
#endif
	return error;
}	


/* void */
int
ipsec_cleanup(void)
{
	int error = 0;

#ifdef CONFIG_SYSCTL
        ipsec_sysctl_unregister();
#endif                                                                          
	KLIPS_PRINT(debug_netlink, /* debug_tunnel & DB_TN_INIT, */
		    "klips_debug:ipsec_cleanup: "
		    "calling ipsec_tunnel_cleanup_devices.\n");
	error |= ipsec_tunnel_cleanup_devices();

#if 0
#ifdef CONFIG_IPSEC_IPCOMP
	if (inet_del_protocol(&comp_protocol) < 0)
		printk(KERN_INFO "klips_debug:ipsec_cleanup: "
		       "comp close: can't remove protocol\n");
#endif
#endif
#ifdef CONFIG_IPSEC_AH
	if (inet_del_protocol(&ah_protocol) < 0)
		printk(KERN_INFO "klips_debug:ipsec_cleanup: "
		       "ah close: can't remove protocol\n");
#endif /* CONFIG_IPSEC_AH */
#ifdef CONFIG_IPSEC_ESP
	if (inet_del_protocol(&esp_protocol) < 0)
		printk(KERN_INFO "klips_debug:ipsec_cleanup: "
		       "esp close: can't remove protocol\n");
#endif /* CONFIG_IPSEC_ESP */

	error |= unregister_netdevice_notifier(&ipsec_dev_notifier);

	KLIPS_PRINT(debug_netlink, /* debug_tunnel & DB_TN_INIT, */
		    "klips_debug:ipsec_cleanup: "
		    "calling ipsec_tdbcleanup.\n");
	error |= ipsec_tdbcleanup(0);
	KLIPS_PRINT(debug_netlink, /* debug_tunnel & DB_TN_INIT, */
		    "klips_debug:ipsec_cleanup: "
		    "calling ipsec_radijcleanup.\n");
	error |= ipsec_radijcleanup();
	
	KLIPS_PRINT(debug_pfkey, /* debug_tunnel & DB_TN_INIT, */
		    "klips_debug:ipsec_cleanup: "
		    "calling pfkey_cleanup.\n");
	error |= pfkey_cleanup();

#ifdef CONFIG_PROC_FS
#  ifndef PROC_FS_2325
#    ifdef CONFIG_IPSEC_DEBUG
	if (proc_net_unregister(ipsec_klipsdebug.low_ino) != 0)
		printk("klips_debug:ipsec_cleanup: "
		       "cannot unregister /proc/net/ipsec_klipsdebug\n");
#    endif /* CONFIG_IPSEC_DEBUG */
	if (proc_net_unregister(ipsec_version.low_ino) != 0)
		printk("klips_debug:ipsec_cleanup: "
		       "cannot unregister /proc/net/ipsec_version\n");
	if (proc_net_unregister(ipsec_eroute.low_ino) != 0)
		printk("klips_debug:ipsec_cleanup: "
		       "cannot unregister /proc/net/ipsec_eroute\n");
	if (proc_net_unregister(ipsec_spi.low_ino) != 0)
		printk("klips_debug:ipsec_cleanup: "
		       "cannot unregister /proc/net/ipsec_spi\n");
	if (proc_net_unregister(ipsec_spigrp.low_ino) != 0)
		printk("klips_debug:ipsec_cleanup: "
		       "cannot unregister /proc/net/ipsec_spigrp\n");
	if (proc_net_unregister(ipsec_tncfg.low_ino) != 0)
		printk("klips_debug:ipsec_cleanup: "
		       "cannot unregister /proc/net/ipsec_tncfg\n");
#  else /* !PROC_FS_2325 */
#    ifdef CONFIG_IPSEC_DEBUG
	proc_net_remove ("ipsec_klipsdebug");
#    endif /* CONFIG_IPSEC_DEBUG */
	proc_net_remove ("ipsec_eroute");
	proc_net_remove ("ipsec_spi");
	proc_net_remove ("ipsec_spigrp");
	proc_net_remove ("ipsec_tncfg");
	proc_net_remove ("ipsec_version");
#  endif /* !PROC_FS_2325 */
#endif          /* CONFIG_PROC_FS */

#if LINUX_VERSION_CODE < 0x020100
	libdes_cleanup();
#endif
	return error;
}

#ifdef MODULE
int
init_module(void)
{
	int error = 0;

	error |= ipsec_init();

	return error;
}

int
cleanup_module(void)
{
	int error = 0;

	KLIPS_PRINT(debug_netlink, /* debug_tunnel & DB_TN_INIT, */
		    "klips_debug:cleanup_module: "
		    "calling ipsec_cleanup.\n");

	error |= ipsec_cleanup();

	KLIPS_PRINT(1, "klips_info:cleanup_module: "
		    "ipsec module unloaded.\n");

	return error;
}
#endif /* MODULE */

/*
 * $Log: ipsec_init.c,v $
 * Revision 1.69  2001/06/14 19:33:26  rgb
 * Silence startup message for console, but allow it to be logged.
 * Update copyright date.
 *
 * Revision 1.68  2001/05/29 05:14:36  rgb
 * Added PMTU to /proc/net/ipsec_tncfg output.  See 'man 5 ipsec_tncfg'.
 *
 * Revision 1.67  2001/05/04 16:34:52  rgb
 * Rremove erroneous checking of return codes for proc_net_* in 2.4.
 *
 * Revision 1.66  2001/05/03 19:40:34  rgb
 * Check error return codes in startup and shutdown.
 *
 * Revision 1.65  2001/02/28 05:03:27  rgb
 * Clean up and rationalise startup messages.
 *
 * Revision 1.64  2001/02/27 22:24:53  rgb
 * Re-formatting debug output (line-splitting, joining, 1arg/line).
 * Check for satoa() return codes.
 *
 * Revision 1.63  2000/11/29 20:14:06  rgb
 * Add src= to the output of /proc/net/ipsec_spi and delete dst from IPIP.
 *
 * Revision 1.62  2000/11/06 04:31:24  rgb
 * Ditched spin_lock_irqsave in favour of spin_lock_bh.
 * Fixed longlong for pre-2.4 kernels (Svenning).
 * Add Svenning's adaptive content compression.
 * Disabled registration of ipcomp handler.
 *
 * Revision 1.61  2000/10/11 13:37:54  rgb
 * #ifdef out debug print that causes proc/net/ipsec_version to oops.
 *
 * Revision 1.60  2000/09/20 03:59:01  rgb
 * Change static info functions to DEBUG_NO_STATIC to reveal function names
 * in oopsen.
 *
 * Revision 1.59  2000/09/16 01:06:26  rgb
 * Added cast of var to silence compiler warning about long fed to int
 * format.
 *
 * Revision 1.58  2000/09/15 11:37:01  rgb
 * Merge in heavily modified Svenning Soerensen's <svenning@post5.tele.dk>
 * IPCOMP zlib deflate code.
 *
 * Revision 1.57  2000/09/12 03:21:50  rgb
 * Moved radij_c_version printing to ipsec_version_get_info().
 * Reformatted ipsec_version_get_info().
 * Added sysctl_{,un}register() calls.
 *
 * Revision 1.56  2000/09/08 19:16:50  rgb
 * Change references from DEBUG_IPSEC to CONFIG_IPSEC_DEBUG.
 * Removed all references to CONFIG_IPSEC_PFKEYv2.
 *
 * Revision 1.55  2000/08/30 05:19:03  rgb
 * Cleaned up no longer used spi_next, netlink register/unregister, other
 * minor cleanup.
 * Removed cruft replaced by TDB_XFORM_NAME.
 * Removed all the rest of the references to tdb_spi, tdb_proto, tdb_dst.
 * Moved debug version strings to printk when /proc/net/ipsec_version is
 * called.
 *
 * Revision 1.54  2000/08/20 18:31:05  rgb
 * Changed cosmetic alignment in spi_info.
 * Changed addtime and usetime to use actual value which is relative
 * anyways, as intended. (Momchil)
 *
 * Revision 1.53  2000/08/18 17:37:03  rgb
 * Added an (int) cast to shut up the compiler...
 *
 * Revision 1.52  2000/08/01 14:51:50  rgb
 * Removed _all_ remaining traces of DES.
 *
 * Revision 1.51  2000/07/25 20:41:22  rgb
 * Removed duplicate parameter in spi_getinfo.
 *
 * Revision 1.50  2000/07/17 03:21:45  rgb
 * Removed /proc/net/ipsec_spinew.
 *
 * Revision 1.49  2000/06/28 05:46:51  rgb
 * Renamed ivlen to iv_bits for consistency.
 * Changed output of add and use times to be relative to now.
 *
 * Revision 1.48  2000/05/11 18:26:10  rgb
 * Commented out calls to netlink_attach/detach to avoid activating netlink
 * in the kenrel config.
 *
 * Revision 1.47  2000/05/10 22:35:26  rgb
 * Comment out most of the startup version information.
 *
 * Revision 1.46  2000/03/22 16:15:36  rgb
 * Fixed renaming of dev_get (MB).
 *
 * Revision 1.45  2000/03/16 06:40:48  rgb
 * Hardcode PF_KEYv2 support.
 *
 * Revision 1.44  2000/01/22 23:19:20  rgb
 * Simplified code to use existing macro TDB_XFORM_NAME().
 *
 * Revision 1.43  2000/01/21 06:14:04  rgb
 * Print individual stats only if non-zero.
 * Removed 'bits' from each keylength for brevity.
 * Shortened lifetimes legend for brevity.
 * Changed wording from 'last_used' to the clearer 'idle'.
 *
 * Revision 1.42  1999/12/31 14:57:19  rgb
 * MB fix for new dummy-less proc_get_info in 2.3.35.
 *
 * Revision 1.41  1999/11/23 23:04:03  rgb
 * Use provided macro ADDRTOA_BUF instead of hardcoded value.
 * Sort out pfkey and freeswan headers, putting them in a library path.
 *
 * Revision 1.40  1999/11/18 18:47:01  rgb
 * Added dynamic proc registration for 2.3.25+.
 * Changed all device registrations for static linking to
 * dynamic to reduce the number and size of patches.
 * Changed all protocol registrations for static linking to
 * dynamic to reduce the number and size of patches.
 *
 * Revision 1.39  1999/11/18 04:12:07  rgb
 * Replaced all kernel version macros to shorter, readable form.
 * Added Marc Boucher's 2.3.25 proc patches.
 * Converted all PROC_FS entries to dynamic to reduce kernel patching.
 * Added CONFIG_PROC_FS compiler directives in case it is shut off.
 *
 * Revision 1.38  1999/11/17 15:53:38  rgb
 * Changed all occurrences of #include "../../../lib/freeswan.h"
 * to #include <freeswan.h> which works due to -Ilibfreeswan in the
 * klips/net/ipsec/Makefile.
 *
 * Revision 1.37  1999/10/16 04:23:06  rgb
 * Add stats for replaywin_errs, replaywin_max_sequence_difference,
 * authentication errors, encryption size errors, encryption padding
 * errors, and time since last packet.
 *
 * Revision 1.36  1999/10/16 00:30:47  rgb
 * Added SA lifetime counting.
 *
 * Revision 1.35  1999/10/15 22:14:00  rgb
 * Clean out cruft.
 *
 * Revision 1.34  1999/10/03 18:46:28  rgb
 * Spinlock fixes for 2.0.xx and 2.3.xx.
 *
 * Revision 1.33  1999/10/01 17:08:10  rgb
 * Disable spinlock init.
 *
 * Revision 1.32  1999/10/01 16:22:24  rgb
 * Switch from assignment init. to functional init. of spinlocks.
 *
 * Revision 1.31  1999/10/01 15:44:52  rgb
 * Move spinlock header include to 2.1> scope.
 *
 * Revision 1.30  1999/10/01 00:00:16  rgb
 * Added eroute structure locking.
 * Added tdb structure locking.
 * Minor formatting changes.
 * Add call to initialize tdb hash table.
 *
 * Revision 1.29  1999/09/23 20:22:40  rgb
 * Enable, tidy and fix network notifier code.
 *
 * Revision 1.28  1999/09/18 11:39:56  rgb
 * Start to add (disabled) netdevice notifier code.
 *
 * Revision 1.27  1999/08/28 08:24:47  rgb
 * Add compiler directives to compile cleanly without debugging.
 *
 * Revision 1.26  1999/08/06 16:03:22  rgb
 * Correct error messages on failure to unload /proc entries.
 *
 * Revision 1.25  1999/08/03 17:07:25  rgb
 * Report device MTU, not private MTU.
 *
 * Revision 1.24  1999/05/25 22:24:37  rgb
 * /PROC/NET/ipsec* init problem fix.
 *
 * Revision 1.23  1999/05/25 02:16:38  rgb
 * Make modular proc_fs entries dynamic and fix for 2.2.x.
 *
 * Revision 1.22  1999/05/09 03:25:35  rgb
 * Fix bug introduced by 2.2 quick-and-dirty patch.
 *
 * Revision 1.21  1999/05/05 22:02:30  rgb
 * Add a quick and dirty port to 2.2 kernels by Marc Boucher <marc@mbsi.ca>.
 *
 * Revision 1.20  1999/04/29 15:15:50  rgb
 * Fix undetected iv_len reporting bug.
 * Add sanity checking for null pointer to private data space.
 * Add return values to init and cleanup functions.
 *
 * Revision 1.19  1999/04/27 19:24:44  rgb
 * Added /proc/net/ipsec_klipsdebug support for reading the current debug
 * settings.
 * Instrument module load/init/unload.
 *
 * Revision 1.18  1999/04/15 15:37:24  rgb
 * Forward check changes from POST1_00 branch.
 *
 * Revision 1.15.2.3  1999/04/13 20:29:19  rgb
 * /proc/net/ipsec_* cleanup.
 *
 * Revision 1.15.2.2  1999/04/02 04:28:23  rgb
 * /proc/net/ipsec_* formatting enhancements.
 *
 * Revision 1.15.2.1  1999/03/30 17:08:33  rgb
 * Add pfkey initialisation.
 *
 * Revision 1.17  1999/04/11 00:28:57  henry
 * GPL boilerplate
 *
 * Revision 1.16  1999/04/06 04:54:25  rgb
 * Fix/Add RCSID Id: and Log: bits to make PHMDs happy.  This includes
 * patch shell fixes.
 *
 * Revision 1.15  1999/02/24 20:15:07  rgb
 * Update output format.
 *
 * Revision 1.14  1999/02/17 16:49:39  rgb
 * Convert DEBUG_IPSEC to KLIPS_PRINT
 * Ditch NET_IPIP dependancy.
 *
 * Revision 1.13  1999/01/26 02:06:37  rgb
 * Remove ah/esp switching on include files.
 * Removed CONFIG_IPSEC_ALGO_SWITCH macro.
 * Removed dead code.
 * Remove references to INET_GET_PROTOCOL.
 *
 * Revision 1.12  1999/01/22 06:19:18  rgb
 * Cruft clean-out.
 * 64-bit clean-up.
 * Added algorithm switch code.
 *
 * Revision 1.11  1998/12/01 05:54:53  rgb
 * Cleanup and order debug version output.
 *
 * Revision 1.10  1998/11/30 13:22:54  rgb
 * Rationalised all the klips kernel file headers.  They are much shorter
 * now and won't conflict under RH5.2.
 *
 * Revision 1.9  1998/11/10 05:35:13  rgb
 * Print direction in/out flag from /proc/net/ipsec_spi.
 *
 * Revision 1.8  1998/10/27 13:48:10  rgb
 * Cleaned up /proc/net/ipsec_* filesystem for easy parsing by scripts.
 * Fixed less(1) truncated output bug.
 * Code clean-up.
 *
 * Revision 1.7  1998/10/22 06:43:16  rgb
 * Convert to use satoa for printk.
 *
 * Revision 1.6  1998/10/19 14:24:35  rgb
 * Added inclusion of freeswan.h.
 *
 * Revision 1.5  1998/10/09 04:43:35  rgb
 * Added 'klips_debug' prefix to all klips printk debug statements.
 *
 * Revision 1.4  1998/07/27 21:50:22  rgb
 * Not necessary to traverse mask tree for /proc/net/ipsec_eroute.
 *
 * Revision 1.3  1998/06/25 19:51:20  rgb
 * Clean up #endif comments.
 * Shift debugging comment control for procfs to debug_tunnel.
 * Make proc_dir_entries visible to rest of kernel for static link.
 * Replace hardwired fileperms with macros.
 * Use macros for procfs inode numbers.
 * Rearrange initialisations between ipsec_init and module_init as appropriate
 * for static loading.
 *
 * Revision 1.2  1998/06/23 02:55:43  rgb
 * Slightly quieted init-time messages.
 * Re-introduced inet_add_protocol after it mysteriously disappeared...
 * Check for and warn of absence of IPIP protocol on install of module.
 * Move tdbcleanup to ipsec_xform.c.
 *
 * Revision 1.10  1998/06/18 21:29:04  henry
 * move sources from klips/src to klips/net/ipsec, to keep stupid kernel
 * build scripts happier in presence of symbolic links
 *
 * Revision 1.9  1998/06/14 23:49:40  rgb
 * Clarify version reporting on module loading.
 *
 * Revision 1.8  1998/06/11 05:54:23  rgb
 * Added /proc/net/ipsec_version to report freeswan and transform versions.
 * Added /proc/net/ipsec_spinew to generate new and unique spi's..
 * Fixed /proc/net/ipsec_tncfg bug.
 *
 * Revision 1.7  1998/05/25 20:23:13  rgb
 * proc_register changed to dynamic registration to avoid arbitrary inode
 * numbers.
 *
 * Implement memory recovery from tdb and eroute tables.
 *
 * Revision 1.6  1998/05/21 13:08:58  rgb
 * Rewrote procinfo subroutines to avoid *bad things* when more that 3k of
 * information is available for printout.
 *
 * Revision 1.5  1998/05/18 21:29:48  rgb
 * Cleaned up /proc/net/ipsec_* output, including a title line, algorithm
 * names instead of numbers, standard format for numerical output base,
 * whitespace for legibility, and the names themselves for consistency.
 *
 * Added /proc/net/ipsec_spigrp and /proc/net/ipsec_tncfg.
 *
 * Revision 1.4  1998/04/30 15:42:24  rgb
 * Silencing attach for normal operations with #ifdef IPSEC_DEBUG.
 *
 * Revision 1.3  1998/04/21 21:28:58  rgb
 * Rearrange debug switches to change on the fly debug output from user
 * space.  Only kernel changes checked in at this time.  radij.c was also
 * changed to temporarily remove buggy debugging code in rj_delete causing
 * an OOPS and hence, netlink device open errors.
 *
 * Revision 1.2  1998/04/12 22:03:22  rgb
 * Updated ESP-3DES-HMAC-MD5-96,
 * 	ESP-DES-HMAC-MD5-96,
 * 	AH-HMAC-MD5-96,
 * 	AH-HMAC-SHA1-96 since Henry started freeswan cvs repository
 * from old standards (RFC182[5-9] to new (as of March 1998) drafts.
 *
 * Fixed eroute references in /proc/net/ipsec*.
 *
 * Started to patch module unloading memory leaks in ipsec_netlink and
 * radij tree unloading.
 *
 * Revision 1.1  1998/04/09 03:06:05  henry
 * sources moved up from linux/net/ipsec
 *
 * Revision 1.1.1.1  1998/04/08 05:35:02  henry
 * RGB's ipsec-0.8pre2.tar.gz ipsec-0.8
 *
 * Revision 0.4  1997/01/15 01:28:15  ji
 * No changes.
 *
 * Revision 0.3  1996/11/20 14:39:04  ji
 * Fixed problem with node names of /proc/net entries.
 * Other minor cleanups.
 * Rationalized debugging code.
 *
 * Revision 0.2  1996/11/02 00:18:33  ji
 * First limited release.
 *
 *
 */
