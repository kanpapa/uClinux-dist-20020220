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
 * $Id: dir.c,v 1.58 2002/02/09 06:05:16 dwmw2 Exp $
 *
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/mtd/compatmac.h> /* For completion */
#include <linux/jffs2.h>
#include <linux/jffs2_fs_i.h>
#include <linux/jffs2_fs_sb.h>
#include "nodelist.h"
#include "crc32.h"

static int jffs2_readdir (struct file *, void *, filldir_t);

static int jffs2_create (struct inode *,struct dentry *,int);
static struct dentry *jffs2_lookup (struct inode *,struct dentry *);
static int jffs2_link (struct dentry *,struct inode *,struct dentry *);
static int jffs2_unlink (struct inode *,struct dentry *);
static int jffs2_symlink (struct inode *,struct dentry *,const char *);
static int jffs2_mkdir (struct inode *,struct dentry *,int);
static int jffs2_rmdir (struct inode *,struct dentry *);
static int jffs2_mknod (struct inode *,struct dentry *,int,int);
static int jffs2_rename (struct inode *, struct dentry *,
                        struct inode *, struct dentry *);

struct file_operations jffs2_dir_operations =
{
	read:		generic_read_dir,
	readdir:	jffs2_readdir,
	ioctl:		jffs2_ioctl,
	fsync:		jffs2_null_fsync
};


struct inode_operations jffs2_dir_inode_operations =
{
	create:		jffs2_create,
	lookup:		jffs2_lookup,
	link:		jffs2_link,
	unlink:		jffs2_unlink,
	symlink:	jffs2_symlink,
	mkdir:		jffs2_mkdir,
	rmdir:		jffs2_rmdir,
	mknod:		jffs2_mknod,
	rename:		jffs2_rename,
	setattr:	jffs2_setattr,
};

/***********************************************************************/


/* We keep the dirent list sorted in increasing order of name hash,
   and we use the same hash function as the dentries. Makes this 
   nice and simple
*/
static struct dentry *jffs2_lookup(struct inode *dir_i, struct dentry *target)
{
	struct jffs2_inode_info *dir_f;
	struct jffs2_sb_info *c;
	struct jffs2_full_dirent *fd = NULL, *fd_list;
	uint32_t ino = 0;
	struct inode *inode = NULL;

	D1(printk(KERN_DEBUG "jffs2_lookup()\n"));

	dir_f = JFFS2_INODE_INFO(dir_i);
	c = JFFS2_SB_INFO(dir_i->i_sb);

	down(&dir_f->sem);

	/* NB: The 2.2 backport will need to explicitly check for '.' and '..' here */
	for (fd_list = dir_f->dents; fd_list && fd_list->nhash <= target->d_name.hash; fd_list = fd_list->next) {
		if (fd_list->nhash == target->d_name.hash && 
		    (!fd || fd_list->version > fd->version) &&
		    strlen(fd_list->name) == target->d_name.len &&
		    !strncmp(fd_list->name, target->d_name.name, target->d_name.len)) {
			fd = fd_list;
		}
	}
	if (fd)
		ino = fd->ino;
	up(&dir_f->sem);
	if (ino) {
		inode = iget(dir_i->i_sb, ino);
		if (!inode) {
			printk(KERN_WARNING "iget() failed for ino #%u\n", ino);
			return (ERR_PTR(-EIO));
		}
	}

	d_add(target, inode);

	return NULL;
}

/***********************************************************************/


static int jffs2_readdir(struct file *filp, void *dirent, filldir_t filldir)
{
	struct jffs2_inode_info *f;
	struct jffs2_sb_info *c;
	struct inode *inode = filp->f_dentry->d_inode;
	struct jffs2_full_dirent *fd;
	unsigned long offset, curofs;

	D1(printk(KERN_DEBUG "jffs2_readdir() for dir_i #%lu\n", filp->f_dentry->d_inode->i_ino));

	f = JFFS2_INODE_INFO(inode);
	c = JFFS2_SB_INFO(inode->i_sb);

	offset = filp->f_pos;

	if (offset == 0) {
		D1(printk(KERN_DEBUG "Dirent 0: \".\", ino #%lu\n", inode->i_ino));
		if (filldir(dirent, ".", 1, 0, inode->i_ino, DT_DIR) < 0)
			goto out;
		offset++;
	}
	if (offset == 1) {
		D1(printk(KERN_DEBUG "Dirent 1: \"..\", ino #%lu\n", filp->f_dentry->d_parent->d_inode->i_ino));
		if (filldir(dirent, "..", 2, 1, filp->f_dentry->d_parent->d_inode->i_ino, DT_DIR) < 0)
			goto out;
		offset++;
	}

	curofs=1;
	down(&f->sem);
	for (fd = f->dents; fd; fd = fd->next) {

		curofs++;
		/* First loop: curofs = 2; offset = 2 */
		if (curofs < offset) {
			D2(printk(KERN_DEBUG "Skipping dirent: \"%s\", ino #%u, type %d, because curofs %ld < offset %ld\n", 
				  fd->name, fd->ino, fd->type, curofs, offset));
			continue;
		}
		if (!fd->ino) {
			D2(printk(KERN_DEBUG "Skipping deletion dirent \"%s\"\n", fd->name));
			offset++;
			continue;
		}
		D2(printk(KERN_DEBUG "Dirent %ld: \"%s\", ino #%u, type %d\n", offset, fd->name, fd->ino, fd->type));
		if (filldir(dirent, fd->name, strlen(fd->name), offset, fd->ino, fd->type) < 0)
			break;
		offset++;
	}
	up(&f->sem);
 out:
	filp->f_pos = offset;
	return 0;
}

/***********************************************************************/


static int jffs2_create(struct inode *dir_i, struct dentry *dentry, int mode)
{
	struct jffs2_raw_inode *ri;
	struct jffs2_inode_info *f, *dir_f;
	struct jffs2_sb_info *c;
	struct inode *inode;
	int ret;

	ri = jffs2_alloc_raw_inode();
	if (!ri)
		return -ENOMEM;
	
	c = JFFS2_SB_INFO(dir_i->i_sb);

	D1(printk(KERN_DEBUG "jffs2_create()\n"));

	inode = jffs2_new_inode(dir_i, mode, ri);

	if (IS_ERR(inode)) {
		D1(printk(KERN_DEBUG "jffs2_new_inode() failed\n"));
		jffs2_free_raw_inode(ri);
		return PTR_ERR(inode);
	}

	inode->i_op = &jffs2_file_inode_operations;
	inode->i_fop = &jffs2_file_operations;
	inode->i_mapping->a_ops = &jffs2_file_address_operations;
	inode->i_mapping->nrpages = 0;

	f = JFFS2_INODE_INFO(inode);
	dir_f = JFFS2_INODE_INFO(dir_i);

	ret = jffs2_do_create(c, dir_f, f, ri, 
			      dentry->d_name.name, dentry->d_name.len);

	if (ret) {
		jffs2_clear_inode(inode);
		make_bad_inode(inode);
		iput(inode);
		jffs2_free_raw_inode(ri);
		return ret;
	}

	jffs2_free_raw_inode(ri);
	d_instantiate(dentry, inode);

	D1(printk(KERN_DEBUG "jffs2_create: Created ino #%lu with mode %o, nlink %d(%d). nrpages %ld\n",
		  inode->i_ino, inode->i_mode, inode->i_nlink, f->inocache->nlink, inode->i_mapping->nrpages));
	return 0;
}

/***********************************************************************/


static int jffs2_unlink(struct inode *dir_i, struct dentry *dentry)
{
	struct jffs2_sb_info *c = JFFS2_SB_INFO(dir_i->i_sb);
	struct jffs2_inode_info *dir_f = JFFS2_INODE_INFO(dir_i);
	struct jffs2_inode_info *dead_f = JFFS2_INODE_INFO(dentry->d_inode);
	int ret;

	ret = jffs2_do_unlink(c, dir_f, dentry->d_name.name, 
			       dentry->d_name.len, dead_f);
	dentry->d_inode->i_nlink = dead_f->inocache->nlink;
	return ret;
}
/***********************************************************************/


static int jffs2_link (struct dentry *old_dentry, struct inode *dir_i, struct dentry *dentry)
{
	struct jffs2_sb_info *c = JFFS2_SB_INFO(old_dentry->d_inode->i_sb);
	struct jffs2_inode_info *f = JFFS2_INODE_INFO(old_dentry->d_inode);
	struct jffs2_inode_info *dir_f = JFFS2_INODE_INFO(dir_i);
	int ret;

	/* XXX: This is ugly */
	uint8_t type = (old_dentry->d_inode->i_mode & S_IFMT) >> 12;
	if (!type) type = DT_REG;

	ret = jffs2_do_link(c, dir_f, f->inocache->ino, type, dentry->d_name.name, dentry->d_name.len);

	if (!ret) {
		down(&f->sem);
		old_dentry->d_inode->i_nlink = ++f->inocache->nlink;
		up(&f->sem);
		d_instantiate(dentry, old_dentry->d_inode);
		atomic_inc(&old_dentry->d_inode->i_count);
	}
	return ret;
}

/***********************************************************************/

static int jffs2_symlink (struct inode *dir_i, struct dentry *dentry, const char *target)
{
	struct jffs2_inode_info *f, *dir_f;
	struct jffs2_sb_info *c;
	struct inode *inode;
	struct jffs2_raw_inode *ri;
	struct jffs2_raw_dirent *rd;
	struct jffs2_full_dnode *fn;
	struct jffs2_full_dirent *fd;
	int namelen;
	uint32_t alloclen, phys_ofs;
	uint32_t writtenlen;
	int ret;

	/* FIXME: If you care. We'd need to use frags for the target
	   if it grows much more than this */
	if (strlen(target) > 254)
		return -EINVAL;

	ri = jffs2_alloc_raw_inode();

	if (!ri)
		return -ENOMEM;
	
	c = JFFS2_SB_INFO(dir_i->i_sb);
	
	/* Try to reserve enough space for both node and dirent. 
	 * Just the node will do for now, though 
	 */
	namelen = dentry->d_name.len;
	ret = jffs2_reserve_space(c, sizeof(*ri) + strlen(target), &phys_ofs, &alloclen, ALLOC_NORMAL);

	if (ret) {
		jffs2_free_raw_inode(ri);
		return ret;
	}

	inode = jffs2_new_inode(dir_i, S_IFLNK | S_IRWXUGO, ri);

	if (IS_ERR(inode)) {
		jffs2_free_raw_inode(ri);
		jffs2_complete_reservation(c);
		return PTR_ERR(inode);
	}

	inode->i_op = &jffs2_symlink_inode_operations;

	f = JFFS2_INODE_INFO(inode);

	inode->i_size = ri->isize = ri->dsize = ri->csize = strlen(target);
	ri->totlen = sizeof(*ri) + ri->dsize;
	ri->hdr_crc = crc32(0, ri, sizeof(struct jffs2_unknown_node)-4);

	ri->compr = JFFS2_COMPR_NONE;
	ri->data_crc = crc32(0, target, strlen(target));
	ri->node_crc = crc32(0, ri, sizeof(*ri)-8);
	
	fn = jffs2_write_dnode(c, f, ri, target, strlen(target), phys_ofs, &writtenlen);

	jffs2_free_raw_inode(ri);

	if (IS_ERR(fn)) {
		/* Eeek. Wave bye bye */
		up(&f->sem);
		jffs2_complete_reservation(c);
		jffs2_clear_inode(inode);
		return PTR_ERR(fn);
	}
	/* No data here. Only a metadata node, which will be 
	   obsoleted by the first data write
	*/
	f->metadata = fn;
	up(&f->sem);

	/* Work out where to put the dirent node now. */
	writtenlen = (writtenlen+3)&~3;
	phys_ofs += writtenlen;
	alloclen -= writtenlen;

	if (alloclen < sizeof(*rd)+namelen) {
		/* Not enough space left in this chunk. Get some more */
		jffs2_complete_reservation(c);
		ret = jffs2_reserve_space(c, sizeof(*rd)+namelen, &phys_ofs, &alloclen, ALLOC_NORMAL);
		if (ret) {
			/* Eep. */
			jffs2_clear_inode(inode);
			return ret;
		}
	}

	rd = jffs2_alloc_raw_dirent();
	if (!rd) {
		/* Argh. Now we treat it like a normal delete */
		jffs2_complete_reservation(c);
		jffs2_clear_inode(inode);
		return -ENOMEM;
	}

	dir_f = JFFS2_INODE_INFO(dir_i);
	down(&dir_f->sem);

	rd->magic = JFFS2_MAGIC_BITMASK;
	rd->nodetype = JFFS2_NODETYPE_DIRENT;
	rd->totlen = sizeof(*rd) + namelen;
	rd->hdr_crc = crc32(0, rd, sizeof(struct jffs2_unknown_node)-4);

	rd->pino = dir_i->i_ino;
	rd->version = ++dir_f->highest_version;
	rd->ino = inode->i_ino;
	rd->mctime = CURRENT_TIME;
	rd->nsize = namelen;
	rd->type = DT_LNK;
	rd->node_crc = crc32(0, rd, sizeof(*rd)-8);
	rd->name_crc = crc32(0, dentry->d_name.name, namelen);

	fd = jffs2_write_dirent(c, dir_f, rd, dentry->d_name.name, namelen, phys_ofs, &writtenlen);
	
	jffs2_complete_reservation(c);
	
	if (IS_ERR(fd)) {
		/* dirent failed to write. Delete the inode normally 
		   as if it were the final unlink() */
		jffs2_free_raw_dirent(rd);
		up(&dir_f->sem);
		jffs2_clear_inode(inode);
		return PTR_ERR(fd);
	}

	dir_i->i_mtime = dir_i->i_ctime = rd->mctime;

	jffs2_free_raw_dirent(rd);

	/* Link the fd into the inode's list, obsoleting an old
	   one if necessary. */
	jffs2_add_fd_to_list(c, fd, &dir_f->dents);
	up(&dir_f->sem);

	d_instantiate(dentry, inode);
	return 0;
}


static int jffs2_mkdir (struct inode *dir_i, struct dentry *dentry, int mode)
{
	struct jffs2_inode_info *f, *dir_f;
	struct jffs2_sb_info *c;
	struct inode *inode;
	struct jffs2_raw_inode *ri;
	struct jffs2_raw_dirent *rd;
	struct jffs2_full_dnode *fn;
	struct jffs2_full_dirent *fd;
	int namelen;
	uint32_t alloclen, phys_ofs;
	uint32_t writtenlen;
	int ret;

	mode |= S_IFDIR;

	ri = jffs2_alloc_raw_inode();
	if (!ri)
		return -ENOMEM;
	
	c = JFFS2_SB_INFO(dir_i->i_sb);

	/* Try to reserve enough space for both node and dirent. 
	 * Just the node will do for now, though 
	 */
	namelen = dentry->d_name.len;
	ret = jffs2_reserve_space(c, sizeof(*ri), &phys_ofs, &alloclen, ALLOC_NORMAL);

	if (ret) {
		jffs2_free_raw_inode(ri);
		return ret;
	}

	inode = jffs2_new_inode(dir_i, mode, ri);

	if (IS_ERR(inode)) {
		jffs2_free_raw_inode(ri);
		jffs2_complete_reservation(c);
		return PTR_ERR(inode);
	}

	inode->i_op = &jffs2_dir_inode_operations;
	inode->i_fop = &jffs2_dir_operations;

	f = JFFS2_INODE_INFO(inode);

	ri->data_crc = 0;
	ri->node_crc = crc32(0, ri, sizeof(*ri)-8);
	
	fn = jffs2_write_dnode(c, f, ri, NULL, 0, phys_ofs, &writtenlen);

	jffs2_free_raw_inode(ri);

	if (IS_ERR(fn)) {
		/* Eeek. Wave bye bye */
		up(&f->sem);
		jffs2_complete_reservation(c);
		jffs2_clear_inode(inode);
		return PTR_ERR(fn);
	}
	/* No data here. Only a metadata node, which will be 
	   obsoleted by the first data write
	*/
	f->metadata = fn;
	up(&f->sem);

	/* Work out where to put the dirent node now. */
	writtenlen = PAD(writtenlen);
	phys_ofs += writtenlen;
	alloclen -= writtenlen;

	if (alloclen < sizeof(*rd)+namelen) {
		/* Not enough space left in this chunk. Get some more */
		jffs2_complete_reservation(c);
		ret = jffs2_reserve_space(c, sizeof(*rd)+namelen, &phys_ofs, &alloclen, ALLOC_NORMAL);
		if (ret) {
			/* Eep. */
			jffs2_clear_inode(inode);
			return ret;
		}
	}
	
	rd = jffs2_alloc_raw_dirent();
	if (!rd) {
		/* Argh. Now we treat it like a normal delete */
		jffs2_complete_reservation(c);
		jffs2_clear_inode(inode);
		return -ENOMEM;
	}

	dir_f = JFFS2_INODE_INFO(dir_i);
	down(&dir_f->sem);

	rd->magic = JFFS2_MAGIC_BITMASK;
	rd->nodetype = JFFS2_NODETYPE_DIRENT;
	rd->totlen = sizeof(*rd) + namelen;
	rd->hdr_crc = crc32(0, rd, sizeof(struct jffs2_unknown_node)-4);

	rd->pino = dir_i->i_ino;
	rd->version = ++dir_f->highest_version;
	rd->ino = inode->i_ino;
	rd->mctime = CURRENT_TIME;
	rd->nsize = namelen;
	rd->type = DT_DIR;
	rd->node_crc = crc32(0, rd, sizeof(*rd)-8);
	rd->name_crc = crc32(0, dentry->d_name.name, namelen);

	fd = jffs2_write_dirent(c, dir_f, rd, dentry->d_name.name, namelen, phys_ofs, &writtenlen);
	
	jffs2_complete_reservation(c);
	
	if (IS_ERR(fd)) {
		/* dirent failed to write. Delete the inode normally 
		   as if it were the final unlink() */
		jffs2_free_raw_dirent(rd);
		up(&dir_f->sem);
		jffs2_clear_inode(inode);
		return PTR_ERR(fd);
	}

	dir_i->i_mtime = dir_i->i_ctime = rd->mctime;

	jffs2_free_raw_dirent(rd);

	/* Link the fd into the inode's list, obsoleting an old
	   one if necessary. */
	jffs2_add_fd_to_list(c, fd, &dir_f->dents);
	up(&dir_f->sem);

	d_instantiate(dentry, inode);
	return 0;
}

static int jffs2_rmdir (struct inode *dir_i, struct dentry *dentry)
{
	struct jffs2_inode_info *f = JFFS2_INODE_INFO(dentry->d_inode);
	struct jffs2_full_dirent *fd;

	for (fd = f->dents ; fd; fd = fd->next) {
		if (fd->ino)
			return -ENOTEMPTY;
	}
	return jffs2_unlink(dir_i, dentry);
}

static int jffs2_mknod (struct inode *dir_i, struct dentry *dentry, int mode, int rdev)
{
	struct jffs2_inode_info *f, *dir_f;
	struct jffs2_sb_info *c;
	struct inode *inode;
	struct jffs2_raw_inode *ri;
	struct jffs2_raw_dirent *rd;
	struct jffs2_full_dnode *fn;
	struct jffs2_full_dirent *fd;
	int namelen;
	unsigned short dev;
	int devlen = 0;
	uint32_t alloclen, phys_ofs;
	uint32_t writtenlen;
	int ret;

	ri = jffs2_alloc_raw_inode();
	if (!ri)
		return -ENOMEM;
	
	c = JFFS2_SB_INFO(dir_i->i_sb);
	
	if ((mode & S_IFMT) == S_IFBLK ||
	    (mode & S_IFMT) == S_IFCHR) {
		dev = (MAJOR(to_kdev_t(rdev)) << 8) | MINOR(to_kdev_t(rdev));
		devlen = sizeof(dev);
	}
	
	/* Try to reserve enough space for both node and dirent. 
	 * Just the node will do for now, though 
	 */
	namelen = dentry->d_name.len;
	ret = jffs2_reserve_space(c, sizeof(*ri) + devlen, &phys_ofs, &alloclen, ALLOC_NORMAL);

	if (ret) {
		jffs2_free_raw_inode(ri);
		return ret;
	}

	inode = jffs2_new_inode(dir_i, mode, ri);

	if (IS_ERR(inode)) {
		jffs2_free_raw_inode(ri);
		jffs2_complete_reservation(c);
		return PTR_ERR(inode);
	}
	inode->i_op = &jffs2_file_inode_operations;
	init_special_inode(inode, inode->i_mode, rdev);

	f = JFFS2_INODE_INFO(inode);

	ri->dsize = ri->csize = devlen;
	ri->totlen = sizeof(*ri) + ri->csize;
	ri->hdr_crc = crc32(0, ri, sizeof(struct jffs2_unknown_node)-4);

	ri->compr = JFFS2_COMPR_NONE;
	ri->data_crc = crc32(0, &dev, devlen);
	ri->node_crc = crc32(0, ri, sizeof(*ri)-8);
	
	fn = jffs2_write_dnode(c, f, ri, (char *)&dev, devlen, phys_ofs, &writtenlen);

	jffs2_free_raw_inode(ri);

	if (IS_ERR(fn)) {
		/* Eeek. Wave bye bye */
		up(&f->sem);
		jffs2_complete_reservation(c);
		jffs2_clear_inode(inode);
		return PTR_ERR(fn);
	}
	/* No data here. Only a metadata node, which will be 
	   obsoleted by the first data write
	*/
	f->metadata = fn;
	up(&f->sem);

	/* Work out where to put the dirent node now. */
	writtenlen = (writtenlen+3)&~3;
	phys_ofs += writtenlen;
	alloclen -= writtenlen;

	if (alloclen < sizeof(*rd)+namelen) {
		/* Not enough space left in this chunk. Get some more */
		jffs2_complete_reservation(c);
		ret = jffs2_reserve_space(c, sizeof(*rd)+namelen, &phys_ofs, &alloclen, ALLOC_NORMAL);
		if (ret) {
			/* Eep. */
			jffs2_clear_inode(inode);
			return ret;
		}
	}

	rd = jffs2_alloc_raw_dirent();
	if (!rd) {
		/* Argh. Now we treat it like a normal delete */
		jffs2_complete_reservation(c);
		jffs2_clear_inode(inode);
		return -ENOMEM;
	}

	dir_f = JFFS2_INODE_INFO(dir_i);
	down(&dir_f->sem);

	rd->magic = JFFS2_MAGIC_BITMASK;
	rd->nodetype = JFFS2_NODETYPE_DIRENT;
	rd->totlen = sizeof(*rd) + namelen;
	rd->hdr_crc = crc32(0, rd, sizeof(struct jffs2_unknown_node)-4);

	rd->pino = dir_i->i_ino;
	rd->version = ++dir_f->highest_version;
	rd->ino = inode->i_ino;
	rd->mctime = CURRENT_TIME;
	rd->nsize = namelen;

	/* XXX: This is ugly. */
	rd->type = (mode & S_IFMT) >> 12;

	rd->node_crc = crc32(0, rd, sizeof(*rd)-8);
	rd->name_crc = crc32(0, dentry->d_name.name, namelen);

	fd = jffs2_write_dirent(c, dir_f, rd, dentry->d_name.name, namelen, phys_ofs, &writtenlen);
	
	jffs2_complete_reservation(c);
	
	if (IS_ERR(fd)) {
		/* dirent failed to write. Delete the inode normally 
		   as if it were the final unlink() */
		jffs2_free_raw_dirent(rd);
		up(&dir_f->sem);
		jffs2_clear_inode(inode);
		return PTR_ERR(fd);
	}

	dir_i->i_mtime = dir_i->i_ctime = rd->mctime;

	jffs2_free_raw_dirent(rd);

	/* Link the fd into the inode's list, obsoleting an old
	   one if necessary. */
	jffs2_add_fd_to_list(c, fd, &dir_f->dents);
	up(&dir_f->sem);

	d_instantiate(dentry, inode);

	return 0;
}

static int jffs2_rename (struct inode *old_dir_i, struct dentry *old_dentry,
                        struct inode *new_dir_i, struct dentry *new_dentry)
{
	int ret;
	struct jffs2_sb_info *c = JFFS2_SB_INFO(old_dir_i->i_sb);
	uint8_t type;

	/* XXX: We probably ought to alloc enough space for
	   both nodes at the same time. Writing the new link, 
	   then getting -ENOSPC, is quite bad :)
	*/

	/* Make a hard link */
	
	/* XXX: This is ugly */
	type = (old_dentry->d_inode->i_mode & S_IFMT) >> 12;
	if (!type) type = DT_REG;

	ret = jffs2_do_link(c, JFFS2_INODE_INFO(new_dir_i), 
			    old_dentry->d_inode->i_ino, type,
			    new_dentry->d_name.name, new_dentry->d_name.len);

	if (ret)
		return ret;

	/* Unlink the original */
	ret = jffs2_do_unlink(c, JFFS2_INODE_INFO(old_dir_i), 
		      old_dentry->d_name.name, old_dentry->d_name.len, NULL);

	/* We don't touch inode->i_nlink */

	if (ret) {
		/* Oh shit. We really ought to make a single node which can do both atomically */
		struct jffs2_inode_info *f = JFFS2_INODE_INFO(old_dentry->d_inode);
		down(&f->sem);
		old_dentry->d_inode->i_nlink = f->inocache->nlink++;
		up(&f->sem);

		printk(KERN_NOTICE "jffs2_rename(): Link succeeded, unlink failed (err %d). You now have a hard link\n", ret);
		/* Might as well let the VFS know */
		d_instantiate(new_dentry, old_dentry->d_inode);
		atomic_inc(&old_dentry->d_inode->i_count);
	}
	return ret;
}

