/*
 * JFFS2 -- Journalling Flash File System, Version 2.
 *
 * Copyright (C) 2001, 2002 Red Hat, Inc.
 *
 * Created by David Woodhouse <dwmw2@cambridge.redhat.com>
 *
 * The original JFFS, from which the design for JFFS2 was derived,
 * was designed and implemented by Axis Communications AB.
 *
 * The contents of this file are subject to the Red Hat eCos Public
 * License Version 1.1 (the "Licence"); you may not use this file
 * except in compliance with the Licence.  You may obtain a copy of
 * the Licence at http://www.redhat.com/
 *
 * Software distributed under the Licence is distributed on an "AS IS"
 * basis, WITHOUT WARRANTY OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing rights and
 * limitations under the Licence.
 *
 * The Original Code is JFFS2 - Journalling Flash File System, version 2
 *
 * Alternatively, the contents of this file may be used under the
 * terms of the GNU General Public License version 2 (the "GPL"), in
 * which case the provisions of the GPL are applicable instead of the
 * above.  If you wish to allow the use of your version of this file
 * only under the terms of the GPL and not to allow others to use your
 * version of this file under the RHEPL, indicate your decision by
 * deleting the provisions above and replace them with the notice and
 * other provisions required by the GPL.  If you do not delete the
 * provisions above, a recipient may use your version of this file
 * under either the RHEPL or the GPL.
 *
 * $Id: write.c,v 1.41 2002/01/31 10:00:50 gleixner Exp $
 *
 *  01-30-2002  Thomas Gleixner (gleixner@autronix.de)
 *		set correct number of vecs entries in jffs2_write_dnode
 *		if just a empty node is created vecs[1] contains
 *		no data. So the number of vecs has to be 1 when 
 *		jffs2_flash_writev is called.
 */

#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/mtd/mtd.h>
#include "nodelist.h"
#include "crc32.h"


int jffs2_do_new_inode(struct jffs2_sb_info *c, struct jffs2_inode_info *f, uint32_t mode, struct jffs2_raw_inode *ri)
{
	struct jffs2_inode_cache *ic;

	ic = jffs2_alloc_inode_cache();
	if (!ic) {
		return -ENOMEM;
	}
	memset(ic, 0, sizeof(*ic));

	init_MUTEX_LOCKED(&f->sem);
	f->inocache = ic;
	f->inocache->nlink = 1;
	f->inocache->nodes = (struct jffs2_raw_node_ref *)f->inocache;
	f->inocache->ino = ri->ino =  ++c->highest_ino;
	D1(printk(KERN_DEBUG "jffs2_do_new_inode(): Assigned ino# %d\n", ri->ino));
	jffs2_add_ino_cache(c, f->inocache);

	ri->magic = JFFS2_MAGIC_BITMASK;
	ri->nodetype = JFFS2_NODETYPE_INODE;
	ri->totlen = PAD(sizeof(*ri));
	ri->hdr_crc = crc32(0, ri, sizeof(struct jffs2_unknown_node)-4);
	ri->mode = mode;
	f->highest_version = ri->version = 1;

	return 0;
}

/* jffs2_new_inode: allocate a new inode and inocache, add it to the hash,
   fill in the raw_inode while you're at it. */
struct inode *jffs2_new_inode (struct inode *dir_i, int mode, struct jffs2_raw_inode *ri)
{
	struct inode *inode;
	struct super_block *sb = dir_i->i_sb;
	struct jffs2_sb_info *c;
	struct jffs2_inode_info *f;
	int ret;

	D1(printk(KERN_DEBUG "jffs2_new_inode(): dir_i %ld, mode 0x%x\n", dir_i->i_ino, mode));

	c = JFFS2_SB_INFO(sb);
	
	inode = new_inode(sb);
	
	if (!inode)
		return ERR_PTR(-ENOMEM);

	/* Alloc jffs2_inode_info when that's split in 2.5 */

	f = JFFS2_INODE_INFO(inode);
	memset(f, 0, sizeof(*f));

	memset(ri, 0, sizeof(*ri));
	/* Set OS-specific defaults for new inodes */
	ri->uid = current->fsuid;

	if (dir_i->i_mode & S_ISGID) {
		ri->gid = dir_i->i_gid;
		if (S_ISDIR(mode))
			ri->mode |= S_ISGID;
	} else {
		ri->gid = current->fsgid;
	}
	ri->mode = mode;
	ret = jffs2_do_new_inode (c, f, mode, ri);
	if (ret) {
		make_bad_inode(inode);
		iput(inode);
		return ERR_PTR(ret);
	}
	inode->i_nlink = 1;
	inode->i_ino = ri->ino;
	inode->i_mode = ri->mode;
	inode->i_gid = ri->gid;
	inode->i_uid = ri->uid;
	inode->i_atime = inode->i_ctime = inode->i_mtime = 
		ri->atime = ri->mtime = ri->ctime = CURRENT_TIME;
	inode->i_blksize = PAGE_SIZE;
	inode->i_blocks = 0;
	inode->i_size = 0;

	insert_inode_hash(inode);

	return inode;
}

/* This ought to be in core MTD code. All registered MTD devices without writev should have
   this put in place. Bug the MTD maintainer */
static int mtd_fake_writev(struct mtd_info *mtd, const struct iovec *vecs, unsigned long count, loff_t to, size_t *retlen)
{
	unsigned long i;
	size_t totlen = 0, thislen;
	int ret = 0;

	for (i=0; i<count; i++) {
		mtd->write(mtd, to, vecs[i].iov_len, &thislen, vecs[i].iov_base);
		totlen += thislen;
		if (ret || thislen != vecs[i].iov_len)
			break;
		to += vecs[i].iov_len;
	}
	if (retlen)
		*retlen = totlen;
	return ret;
}


static inline int jffs2_flash_writev(struct jffs2_sb_info *c, const struct iovec *vecs, unsigned long count, loff_t to, size_t *retlen)
{
	if (c->mtd->writev)
		return c->mtd->writev(c->mtd, vecs, count, to, retlen);
	else
		return mtd_fake_writev(c->mtd, vecs, count, to, retlen);
}

static void writecheck(struct jffs2_sb_info *c, uint32_t ofs)
{
	unsigned char buf[16];
	size_t retlen;
	int ret, i;

	ret = jffs2_flash_read(c, ofs, 16, &retlen, buf);
	if (ret && retlen != 16) {
		D1(printk(KERN_DEBUG "read failed or short in writecheck(). ret %d, retlen %d\n", ret, retlen));
		return;
	}
	ret = 0;
	for (i=0; i<16; i++) {
		if (buf[i] != 0xff)
			ret = 1;
	}
	if (ret) {
		printk(KERN_WARNING "ARGH. About to write node to 0x%08x on flash, but there's data already there:\n", ofs);
		printk(KERN_WARNING "0x%08x: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", 
		       ofs,
		       buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
		       buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15]);
	}
}

	
	

/* jffs2_write_dnode - given a raw_inode, allocate a full_dnode for it, 
   write it to the flash, link it into the existing inode/fragment list */

struct jffs2_full_dnode *jffs2_write_dnode(struct jffs2_sb_info *c, struct jffs2_inode_info *f, struct jffs2_raw_inode *ri, const unsigned char *data, uint32_t datalen, uint32_t flash_ofs,  uint32_t *writelen)

{
	struct jffs2_raw_node_ref *raw;
	struct jffs2_full_dnode *fn;
	size_t retlen;
	struct iovec vecs[2];
	int ret;
	unsigned long cnt = 2;

	D1(if(ri->hdr_crc != crc32(0, ri, sizeof(struct jffs2_unknown_node)-4)) {
		printk(KERN_CRIT "Eep. CRC not correct in jffs2_write_dnode()\n");
		BUG();
	}
	   );
	vecs[0].iov_base = ri;
	vecs[0].iov_len = sizeof(*ri);
	vecs[1].iov_base = (unsigned char *)data;
	vecs[1].iov_len = datalen;

	writecheck(c, flash_ofs);

	if (ri->totlen != sizeof(*ri) + datalen) {
		printk(KERN_WARNING "jffs2_write_dnode: ri->totlen (0x%08x) != sizeof(*ri) (0x%08x) + datalen (0x%08x)\n", ri->totlen, sizeof(*ri), datalen);
	}
	raw = jffs2_alloc_raw_node_ref();
	if (!raw)
		return ERR_PTR(-ENOMEM);
	
	fn = jffs2_alloc_full_dnode();
	if (!fn) {
		jffs2_free_raw_node_ref(raw);
		return ERR_PTR(-ENOMEM);
	}
	raw->flash_offset = flash_ofs;
	raw->totlen = PAD(ri->totlen);
	raw->next_phys = NULL;

	fn->ofs = ri->offset;
	fn->size = ri->dsize;
	fn->frags = 0;
	fn->raw = raw;

	/* check number of valid vecs */
	if (!datalen || !data)
		cnt = 1;

	ret = jffs2_flash_writev(c, vecs, cnt, flash_ofs, &retlen);
		
	if (ret || (retlen != sizeof(*ri) + datalen)) {
		printk(KERN_NOTICE "Write of %d bytes at 0x%08x failed. returned %d, retlen %d\n", 
		       sizeof(*ri)+datalen, flash_ofs, ret, retlen);
		/* Mark the space as dirtied */
		if (retlen) {
			/* Doesn't belong to any inode */
			raw->next_in_ino = NULL;

			/* Don't change raw->size to match retlen. We may have 
			   written the node header already, and only the data will
			   seem corrupted, in which case the scan would skip over
			   any node we write before the original intended end of 
			   this node */
			jffs2_add_physical_node_ref(c, raw, sizeof(*ri)+datalen, 1);
			jffs2_mark_node_obsolete(c, raw);
		} else {
			printk(KERN_NOTICE "Not marking the space at 0x%08x as dirty because the flash driver returned retlen zero\n", raw->flash_offset);
			jffs2_free_raw_node_ref(raw);
		}

		/* Release the full_dnode which is now useless, and return */
		jffs2_free_full_dnode(fn);
		if (writelen)
			*writelen = retlen;
		return ERR_PTR(ret?ret:-EIO);
	}
	/* Mark the space used */
	jffs2_add_physical_node_ref(c, raw, retlen, 0);

	/* Link into per-inode list */
	raw->next_in_ino = f->inocache->nodes;
	f->inocache->nodes = raw;

	D1(printk(KERN_DEBUG "jffs2_write_dnode wrote node at 0x%08x with dsize 0x%x, csize 0x%x, node_crc 0x%08x, data_crc 0x%08x, totlen 0x%08x\n", flash_ofs, ri->dsize, ri->csize, ri->node_crc, ri->data_crc, ri->totlen));
	if (writelen)
		*writelen = retlen;

	f->inocache->nodes = raw;
	return fn;
}

struct jffs2_full_dirent *jffs2_write_dirent(struct jffs2_sb_info *c, struct jffs2_inode_info *f, struct jffs2_raw_dirent *rd, const unsigned char *name, uint32_t namelen, uint32_t flash_ofs,  uint32_t *writelen)
{
	struct jffs2_raw_node_ref *raw;
	struct jffs2_full_dirent *fd;
	size_t retlen;
	struct iovec vecs[2];
	int ret;

	D1(printk(KERN_DEBUG "jffs2_write_dirent(ino #%u, name at *0x%p \"%s\"->ino #%u, name_crc 0x%08x)\n", rd->pino, name, name, rd->ino, rd->name_crc));
	writecheck(c, flash_ofs);

	D1(if(rd->hdr_crc != crc32(0, rd, sizeof(struct jffs2_unknown_node)-4)) {
		printk(KERN_CRIT "Eep. CRC not correct in jffs2_write_dirent()\n");
		BUG();
	}
	   );

	vecs[0].iov_base = rd;
	vecs[0].iov_len = sizeof(*rd);
	vecs[1].iov_base = (unsigned char *)name;
	vecs[1].iov_len = namelen;
	
	raw = jffs2_alloc_raw_node_ref();

	if (!raw)
		return ERR_PTR(-ENOMEM);

	fd = jffs2_alloc_full_dirent(namelen+1);
	if (!fd) {
		jffs2_free_raw_node_ref(raw);
		return ERR_PTR(-ENOMEM);
	}
	raw->flash_offset = flash_ofs;
	raw->totlen = PAD(rd->totlen);
	raw->next_in_ino = f->inocache->nodes;
	f->inocache->nodes = raw;
	raw->next_phys = NULL;

	fd->version = rd->version;
	fd->ino = rd->ino;
	fd->nhash = full_name_hash(name, strlen(name));
	fd->type = rd->type;
	memcpy(fd->name, name, namelen);
	fd->name[namelen]=0;
	fd->raw = raw;

	ret = jffs2_flash_writev(c, vecs, 2, flash_ofs, &retlen);
		if (ret || (retlen != sizeof(*rd) + namelen)) {
			printk(KERN_NOTICE "Write of %d bytes at 0x%08x failed. returned %d, retlen %d\n", 
			       sizeof(*rd)+namelen, flash_ofs, ret, retlen);
		/* Mark the space as dirtied */
			if (retlen) {
				jffs2_add_physical_node_ref(c, raw, sizeof(*rd)+namelen, 1);
				jffs2_mark_node_obsolete(c, raw);
			} else {
				printk(KERN_NOTICE "Not marking the space at 0x%08x as dirty because the flash driver returned retlen zero\n", raw->flash_offset);
				jffs2_free_raw_node_ref(raw);
			}

		/* Release the full_dnode which is now useless, and return */
		jffs2_free_full_dirent(fd);
		if (writelen)
			*writelen = retlen;
		return ERR_PTR(ret?ret:-EIO);
	}
	/* Mark the space used */
	jffs2_add_physical_node_ref(c, raw, retlen, 0);
	if (writelen)
		*writelen = retlen;

	f->inocache->nodes = raw;
	return fd;
}

/* The OS-specific code fills in the metadata in the jffs2_raw_inode for us, so that
   we don't have to go digging in struct inode or its equivalent. It should set:
   mode, uid, gid, (starting)isize, atime, ctime, mtime */
int jffs2_write_inode_range(struct jffs2_sb_info *c, struct jffs2_inode_info *f,
			    struct jffs2_raw_inode *ri, unsigned char *buf, 
			    uint32_t offset, uint32_t writelen, uint32_t *retlen)
{
	int ret = 0;
	uint32_t writtenlen = 0;

       	D1(printk(KERN_DEBUG "jffs2_write_inode_range(): Ino #%u, ofs 0x%x, len 0x%x\n",
		  f->inocache->ino, offset, writelen));
		
	while(writelen) {
		struct jffs2_full_dnode *fn;
		unsigned char *comprbuf = NULL;
		unsigned char comprtype = JFFS2_COMPR_NONE;
		uint32_t phys_ofs, alloclen;
		uint32_t datalen, cdatalen;

		D2(printk(KERN_DEBUG "jffs2_commit_write() loop: 0x%x to write to 0x%x\n", writelen, offset));

		ret = jffs2_reserve_space(c, sizeof(*ri) + JFFS2_MIN_DATA_LEN, &phys_ofs, &alloclen, ALLOC_NORMAL);
		if (ret) {
			D1(printk(KERN_DEBUG "jffs2_reserve_space returned %d\n", ret));
			break;
		}
		down(&f->sem);
		datalen = writelen;
		cdatalen = min(alloclen - sizeof(*ri), writelen);

		comprbuf = kmalloc(cdatalen, GFP_KERNEL);
		if (comprbuf) {
			comprtype = jffs2_compress(buf, comprbuf, &datalen, &cdatalen);
		}
		if (comprtype == JFFS2_COMPR_NONE) {
			/* Either compression failed, or the allocation of comprbuf failed */
			if (comprbuf)
				kfree(comprbuf);
			comprbuf = buf;
			datalen = cdatalen;
		}
		/* Now comprbuf points to the data to be written, be it compressed or not.
		   comprtype holds the compression type, and comprtype == JFFS2_COMPR_NONE means
		   that the comprbuf doesn't need to be kfree()d. 
		*/

		ri->magic = JFFS2_MAGIC_BITMASK;
		ri->nodetype = JFFS2_NODETYPE_INODE;
		ri->totlen = sizeof(*ri) + cdatalen;
		ri->hdr_crc = crc32(0, ri, sizeof(struct jffs2_unknown_node)-4);

		ri->ino = f->inocache->ino;
		ri->version = ++f->highest_version;
		ri->isize = max(ri->isize, offset + datalen);
		ri->offset = offset;
		ri->csize = cdatalen;
		ri->dsize = datalen;
		ri->compr = comprtype;
		ri->node_crc = crc32(0, ri, sizeof(*ri)-8);
		ri->data_crc = crc32(0, comprbuf, cdatalen);

		fn = jffs2_write_dnode(c, f, ri, comprbuf, cdatalen, phys_ofs, NULL);

		jffs2_complete_reservation(c);

		if (comprtype != JFFS2_COMPR_NONE)
			kfree(comprbuf);

		if (IS_ERR(fn)) {
			ret = PTR_ERR(fn);
			up(&f->sem);
			break;
		}
		ret = jffs2_add_full_dnode_to_inode(c, f, fn);
		if (f->metadata) {
			jffs2_mark_node_obsolete(c, f->metadata->raw);
			jffs2_free_full_dnode(f->metadata);
			f->metadata = NULL;
		}
		up(&f->sem);
		if (ret) {
			/* Eep */
			D1(printk(KERN_DEBUG "Eep. add_full_dnode_to_inode() failed in commit_write, returned %d\n", ret));
			jffs2_mark_node_obsolete(c, fn->raw);
			jffs2_free_full_dnode(fn);
			break;
		}
		if (!datalen) {
			printk(KERN_WARNING "Eep. We didn't actually write any data in jffs2_write_inode_range()\n");
			ret = -EIO;
			break;
		}
		D1(printk(KERN_DEBUG "increasing writtenlen by %d\n", datalen));
		writtenlen += datalen;
		offset += datalen;
		writelen -= datalen;
		buf += datalen;
	}
	*retlen = writtenlen;
	return ret;
}

int jffs2_do_create(struct jffs2_sb_info *c, struct jffs2_inode_info *dir_f, struct jffs2_inode_info *f, struct jffs2_raw_inode *ri, const char *name, int namelen)
{
	struct jffs2_raw_dirent *rd;
	struct jffs2_full_dnode *fn;
	struct jffs2_full_dirent *fd;
	uint32_t alloclen, phys_ofs;
	uint32_t writtenlen;
	int ret;

	/* Try to reserve enough space for both node and dirent. 
	 * Just the node will do for now, though 
	 */
	ret = jffs2_reserve_space(c, sizeof(*ri), &phys_ofs, &alloclen, ALLOC_NORMAL);
	D1(printk(KERN_DEBUG "jffs2_do_create(): reserved 0x%x bytes\n", alloclen));
	if (ret)
		return ret;

	ri->data_crc = 0;
	ri->node_crc = crc32(0, ri, sizeof(*ri)-8);

	fn = jffs2_write_dnode(c, f, ri, NULL, 0, phys_ofs, &writtenlen);

	D1(printk(KERN_DEBUG "jffs2_do_create created file with mode 0x%x\n", ri->mode));

	if (IS_ERR(fn)) {
		D1(printk(KERN_DEBUG "jffs2_write_dnode() failed\n"));
		/* Eeek. Wave bye bye */
		up(&f->sem);
		jffs2_complete_reservation(c);
		return PTR_ERR(fn);
	}
	/* No data here. Only a metadata node, which will be 
	   obsoleted by the first data write
	*/
	f->metadata = fn;

	/* Work out where to put the dirent node now. */
	writtenlen = PAD(writtenlen);
	phys_ofs += writtenlen;
	alloclen -= writtenlen;
	up(&f->sem);

	if (alloclen < sizeof(*rd)+namelen) {
		/* Not enough space left in this chunk. Get some more */
		jffs2_complete_reservation(c);
		ret = jffs2_reserve_space(c, sizeof(*rd)+namelen, &phys_ofs, &alloclen, ALLOC_NORMAL);
		
		if (ret) {
			/* Eep. */
			D1(printk(KERN_DEBUG "jffs2_reserve_space() for dirent failed\n"));
			return ret;
		}
	}

	rd = jffs2_alloc_raw_dirent();
	if (!rd) {
		/* Argh. Now we treat it like a normal delete */
		jffs2_complete_reservation(c);
		return -ENOMEM;
	}

	down(&dir_f->sem);

	rd->magic = JFFS2_MAGIC_BITMASK;
	rd->nodetype = JFFS2_NODETYPE_DIRENT;
	rd->totlen = sizeof(*rd) + namelen;
	rd->hdr_crc = crc32(0, rd, sizeof(struct jffs2_unknown_node)-4);

	rd->pino = dir_f->inocache->ino;
	rd->version = ++dir_f->highest_version;
	rd->ino = ri->ino;
	rd->mctime = CURRENT_TIME;
	rd->nsize = namelen;
	rd->type = DT_REG;
	rd->node_crc = crc32(0, rd, sizeof(*rd)-8);
	rd->name_crc = crc32(0, name, namelen);

	fd = jffs2_write_dirent(c, dir_f, rd, name, namelen, phys_ofs, &writtenlen);

	jffs2_complete_reservation(c);
	jffs2_free_raw_dirent(rd);
	
	if (IS_ERR(fd)) {
		/* dirent failed to write. Delete the inode normally 
		   as if it were the final unlink() */
		up(&dir_f->sem);
		return PTR_ERR(fd);
	}

	/* Link the fd into the inode's list, obsoleting an old
	   one if necessary. */
	jffs2_add_fd_to_list(c, fd, &dir_f->dents);
	up(&dir_f->sem);

	return 0;
}


int jffs2_do_unlink(struct jffs2_sb_info *c, struct jffs2_inode_info *dir_f, const char *name, int namelen, struct jffs2_inode_info *dead_f)
{
	struct jffs2_raw_dirent *rd;
	struct jffs2_full_dirent *fd;
	uint32_t alloclen, phys_ofs;
	int ret;

	rd = jffs2_alloc_raw_dirent();
	if (!rd)
		return -ENOMEM;

	ret = jffs2_reserve_space(c, sizeof(*rd)+namelen, &phys_ofs, &alloclen, ALLOC_DELETION);
	if (ret) {
		jffs2_free_raw_dirent(rd);
		return ret;
	}

	down(&dir_f->sem);

	/* Build a deletion node */
	rd->magic = JFFS2_MAGIC_BITMASK;
	rd->nodetype = JFFS2_NODETYPE_DIRENT;
	rd->totlen = sizeof(*rd) + namelen;
	rd->hdr_crc = crc32(0, rd, sizeof(struct jffs2_unknown_node)-4);

	rd->pino = dir_f->inocache->ino;
	rd->version = ++dir_f->highest_version;
	rd->ino = 0;
	rd->mctime = CURRENT_TIME;
	rd->nsize = namelen;
	rd->type = DT_UNKNOWN;
	rd->node_crc = crc32(0, rd, sizeof(*rd)-8);
	rd->name_crc = crc32(0, name, namelen);

	fd = jffs2_write_dirent(c, dir_f, rd, name, namelen, phys_ofs, NULL);
	
	jffs2_complete_reservation(c);
	jffs2_free_raw_dirent(rd);

	if (IS_ERR(fd)) {
		up(&dir_f->sem);
		return PTR_ERR(fd);
	}

	/* File it. This will mark the old one obsolete. */
	jffs2_add_fd_to_list(c, fd, &dir_f->dents);
	up(&dir_f->sem);
	
	if (dead_f) { /* Null if this was a rename not a real unlink */

		down(&dead_f->sem);

		while (dead_f->dents) {
			/* There can be only deleted ones */
			fd = dead_f->dents;
			
			dead_f->dents = fd->next;
			
			if (fd->ino) {
				printk(KERN_WARNING "Deleting inode #%u with active dentry \"%s\"->ino #%u\n",
				       dead_f->inocache->ino, fd->name, fd->ino);
			} else {
				D1(printk(KERN_DEBUG "Removing deletion dirent for \"%s\" from dir ino #%u\n", fd->name, dead_f->inocache->ino));
			}
			jffs2_mark_node_obsolete(c, fd->raw);
			jffs2_free_full_dirent(fd);
		}

		dead_f->inocache->nlink--;
		/* NB: Caller must set inode nlink if appropriate */
		up(&dead_f->sem);
	}

	return 0;
}


int jffs2_do_link (struct jffs2_sb_info *c, struct jffs2_inode_info *dir_f, uint32_t ino, uint8_t type, const char *name, int namelen)
{
	struct jffs2_raw_dirent *rd;
	struct jffs2_full_dirent *fd;
	uint32_t alloclen, phys_ofs;
	int ret;

	rd = jffs2_alloc_raw_dirent();
	if (!rd)
		return -ENOMEM;

	ret = jffs2_reserve_space(c, sizeof(*rd)+namelen, &phys_ofs, &alloclen, ALLOC_NORMAL);
	if (ret) {
		jffs2_free_raw_dirent(rd);
		return ret;
	}
	
	down(&dir_f->sem);

	/* Build a deletion node */
	rd->magic = JFFS2_MAGIC_BITMASK;
	rd->nodetype = JFFS2_NODETYPE_DIRENT;
	rd->totlen = sizeof(*rd) + namelen;
	rd->hdr_crc = crc32(0, rd, sizeof(struct jffs2_unknown_node)-4);

	rd->pino = dir_f->inocache->ino;
	rd->version = ++dir_f->highest_version;
	rd->ino = ino;
	rd->mctime = CURRENT_TIME;
	rd->nsize = namelen;

	rd->type = type;

	rd->node_crc = crc32(0, rd, sizeof(*rd)-8);
	rd->name_crc = crc32(0, name, namelen);

	fd = jffs2_write_dirent(c, dir_f, rd, name, namelen, phys_ofs, NULL);
	
	jffs2_complete_reservation(c);
	jffs2_free_raw_dirent(rd);

	if (IS_ERR(fd)) {
		up(&dir_f->sem);
		return PTR_ERR(fd);
	}

	/* File it. This will mark the old one obsolete. */
	jffs2_add_fd_to_list(c, fd, &dir_f->dents);
	up(&dir_f->sem);

	return 0;
}
