/*
 * JFFS2 -- Journalling Flash File System, Version 2.
 *
 * Copyright (C) 2002 Red Hat, Inc.
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
 * $Id: os-linux.h,v 1.1 2002/02/15 00:23:42 gerg Exp $
 *
 */

#ifndef __JFFS2_OS_LINUX_H__
#define __JFFS2_OS_LINUX_H__

#ifdef JFFS2_OUT_OF_KERNEL
#define JFFS2_INODE_INFO(i) ((struct jffs2_inode_info *) &(i)->u)
#define JFFS2_SB_INFO(sb) ((struct jffs2_sb_info *) &(sb)->u)
#else
#define JFFS2_INODE_INFO(i) (&i->u.jffs2_i)
#define JFFS2_SB_INFO(sb) (&sb->u.jffs2_sb)
#endif

#define OFNI_BS_2SFFJ(c)  ((struct super_block *) ( ((char *)c) - ((char *)(&((struct super_block *)NULL)->u)) ) )
#define OFNI_EDONI_2SFFJ(f)  ((struct inode *) ( ((char *)f) - ((char *)(&((struct inode *)NULL)->u)) ) )

#define JFFS2_F_I_SIZE(f) (OFNI_EDONI_2SFFJ(f)->i_size)
#define JFFS2_F_I_MODE(f) (OFNI_EDONI_2SFFJ(f)->i_mode)
#define JFFS2_F_I_UID(f) (OFNI_EDONI_2SFFJ(f)->i_uid)
#define JFFS2_F_I_GID(f) (OFNI_EDONI_2SFFJ(f)->i_gid)
#define JFFS2_F_I_CTIME(f) (OFNI_EDONI_2SFFJ(f)->i_ctime)
#define JFFS2_F_I_MTIME(f) (OFNI_EDONI_2SFFJ(f)->i_mtime)
#define JFFS2_F_I_ATIME(f) (OFNI_EDONI_2SFFJ(f)->i_atime)

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,5,1)
#define JFFS2_F_I_RDEV_MIN(f) (minor(OFNI_EDONI_2SFFJ(f)->i_rdev))
#define JFFS2_F_I_RDEV_MAJ(f) (major(OFNI_EDONI_2SFFJ(f)->i_rdev))
#else
#define JFFS2_F_I_RDEV_MIN(f) (MINOR(to_kdev_t(OFNI_EDONI_2SFFJ(f)->i_rdev)))
#define JFFS2_F_I_RDEV_MAJ(f) (MAJOR(to_kdev_t(OFNI_EDONI_2SFFJ(f)->i_rdev)))
#endif

#define jffs2_is_readonly(c) (OFNI_BS_2SFFJ(c)->s_flags & MS_RDONLY)
#define jffs2_can_mark_obsolete(c) (c->mtd->type == MTD_NORFLASH || c->mtd->type == MTD_RAM)

#define jffs2_flash_write(c, ofs, len, retlen, buf) ((c)->mtd->write((c)->mtd, ofs, len, retlen, buf))
#define jffs2_flash_read(c, ofs, len, retlen, buf) ((c)->mtd->read((c)->mtd, ofs, len, retlen, buf))

/* background.c */
int jffs2_start_garbage_collect_thread(struct jffs2_sb_info *c);
void jffs2_stop_garbage_collect_thread(struct jffs2_sb_info *c);
void jffs2_garbage_collect_trigger(struct jffs2_sb_info *c);

/* dir.c */
extern struct file_operations jffs2_dir_operations;
extern struct inode_operations jffs2_dir_inode_operations;

/* file.c */
extern struct file_operations jffs2_file_operations;
extern struct inode_operations jffs2_file_inode_operations;
extern struct address_space_operations jffs2_file_address_operations;
int jffs2_null_fsync(struct file *, struct dentry *, int);
int jffs2_setattr (struct dentry *dentry, struct iattr *iattr);
int jffs2_do_readpage_nolock (struct inode *inode, struct page *pg);
int jffs2_do_readpage_unlock (struct inode *inode, struct page *pg);
int jffs2_readpage (struct file *, struct page *);
int jffs2_prepare_write (struct file *, struct page *, unsigned, unsigned);
int jffs2_commit_write (struct file *, struct page *, unsigned, unsigned);

/* ioctl.c */
int jffs2_ioctl(struct inode *, struct file *, unsigned int, unsigned long);

/* symlink.c */
extern struct inode_operations jffs2_symlink_inode_operations;

/* super.c */


#endif /* __JFFS2_OS_LINUX_H__ */
