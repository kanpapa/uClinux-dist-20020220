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
 * $Id: nodelist.h,v 1.61 2002/02/09 06:05:16 dwmw2 Exp $
 *
 */

#ifndef __JFFS2_NODELIST_H__
#define __JFFS2_NODELIST_H__

#include <linux/config.h>
#include <linux/fs.h>

#include <linux/mtd/compatmac.h> /* For min/max in older kernels */
#include <linux/jffs2.h>
#include <linux/jffs2_fs_sb.h>
#include <linux/jffs2_fs_i.h>
#include "os-linux.h"

#ifndef CONFIG_JFFS2_FS_DEBUG
#define CONFIG_JFFS2_FS_DEBUG 2
#endif

#if CONFIG_JFFS2_FS_DEBUG > 0
#define D1(x) x
#else
#define D1(x)
#endif

#if CONFIG_JFFS2_FS_DEBUG > 1
#define D2(x) x
#else
#define D2(x)
#endif

/*
  This is all we need to keep in-core for each raw node during normal
  operation. As and when we do read_inode on a particular inode, we can
  scan the nodes which are listed for it and build up a proper map of 
  which nodes are currently valid. JFFSv1 always used to keep that whole
  map in core for each inode.
*/
struct jffs2_raw_node_ref
{
	struct jffs2_raw_node_ref *next_in_ino; /* Points to the next raw_node_ref
		for this inode. If this is the last, it points to the inode_cache
		for this inode instead. The inode_cache will have NULL in the first
		word so you know when you've got there :) */
	struct jffs2_raw_node_ref *next_phys;
	//	uint32_t ino;
	uint32_t flash_offset;
	uint32_t totlen;
//	uint16_t nodetype;
	
        /* flash_offset & 3 always has to be zero, because nodes are
	   always aligned at 4 bytes. So we have a couple of extra bits
	   to play with. So we set the least significant bit to 1 to
	   signify that the node is obsoleted by later nodes.
	*/
};

/* 
   Used for keeping track of deletion nodes &c, which can only be marked
   as obsolete when the node which they mark as deleted has actually been 
   removed from the flash.
*/
struct jffs2_raw_node_ref_list {
	struct jffs2_raw_node_ref *rew;
	struct jffs2_raw_node_ref_list *next;
};

/* For each inode in the filesystem, we need to keep a record of
   nlink, because it would be a PITA to scan the whole directory tree
   at read_inode() time to calculate it, and to keep sufficient information
   in the raw_node_ref (basically both parent and child inode number for 
   dirent nodes) would take more space than this does. We also keep
   a pointer to the first physical node which is part of this inode, too.
*/
struct jffs2_inode_cache {
	struct jffs2_scan_info *scan; /* Used during scan to hold
		temporary lists of nodes, and later must be set to
		NULL to mark the end of the raw_node_ref->next_in_ino
		chain. */
	struct jffs2_inode_cache *next;
	struct jffs2_raw_node_ref *nodes;
	uint32_t ino;
	int nlink;
};

struct jffs2_scan_info {
	struct jffs2_full_dirent *dents;
	struct jffs2_tmp_dnode_info *tmpnodes;
};
/*
  Larger representation of a raw node, kept in-core only when the 
  struct inode for this particular ino is instantiated.
*/

struct jffs2_full_dnode
{
	struct jffs2_raw_node_ref *raw;
	uint32_t ofs; /* Don't really need this, but optimisation */
	uint32_t size;
	uint32_t frags; /* Number of fragments which currently refer
			to this node. When this reaches zero, 
			the node is obsolete.
		     */
};

/* 
   Even larger representation of a raw node, kept in-core only while
   we're actually building up the original map of which nodes go where,
   in read_inode()
*/
struct jffs2_tmp_dnode_info
{
	struct jffs2_tmp_dnode_info *next;
	struct jffs2_full_dnode *fn;
	uint32_t version;
};       

struct jffs2_full_dirent
{
	struct jffs2_raw_node_ref *raw;
	struct jffs2_full_dirent *next;
	uint32_t version;
	uint32_t ino; /* == zero for unlink */
	unsigned int nhash;
	unsigned char type;
	unsigned char name[0];
};
/*
  Fragments - used to build a map of which raw node to obtain 
  data from for each part of the ino
*/
struct jffs2_node_frag
{
	struct jffs2_node_frag *next;
	struct jffs2_full_dnode *node; /* NULL for holes */
	uint32_t size;
	uint32_t ofs; /* Don't really need this, but optimisation */
	uint32_t node_ofs; /* offset within the physical node */
};

struct jffs2_eraseblock
{
	struct list_head list;
	int bad_count;
	uint32_t offset;		/* of this block in the MTD */

	uint32_t used_size;
	uint32_t dirty_size;
	uint32_t free_size;	/* Note that sector_size - free_size
				   is the address of the first free space */
	struct jffs2_raw_node_ref *first_node;
	struct jffs2_raw_node_ref *last_node;

	struct jffs2_raw_node_ref *gc_node;	/* Next node to be garbage collected */

	/* For deletia. When a dirent node in this eraseblock is
	   deleted by a node elsewhere, that other node can only 
	   be marked as obsolete when this block is actually erased.
	   So we keep a list of the nodes to mark as obsolete when
	   the erase is completed.
	*/
	// MAYBE	struct jffs2_raw_node_ref_list *deletia;
};

#define ACCT_SANITY_CHECK(c, jeb) do { \
	if (jeb->used_size + jeb->dirty_size + jeb->free_size != c->sector_size) { \
		printk(KERN_NOTICE "Eeep. Space accounting for block at 0x%08x is screwed\n", jeb->offset); \
		printk(KERN_NOTICE "free 0x%08x + dirty 0x%08x + used %08x != total %08x\n", \
		jeb->free_size, jeb->dirty_size, jeb->used_size, c->sector_size); \
		BUG(); \
	} \
	if (c->used_size + c->dirty_size + c->free_size + c->erasing_size + c->bad_size != c->flash_size) { \
		printk(KERN_NOTICE "Eeep. Space accounting superblock info is screwed\n"); \
		printk(KERN_NOTICE "free 0x%08x + dirty 0x%08x + used %08x + erasing %08x + bad %08x != total %08x\n", \
		c->free_size, c->dirty_size, c->used_size, c->erasing_size, c->bad_size, c->flash_size); \
		BUG(); \
	} \
} while(0)

#define ACCT_PARANOIA_CHECK(jeb) do { \
		uint32_t my_used_size = 0; \
		struct jffs2_raw_node_ref *ref2 = jeb->first_node; \
		while (ref2) { \
			if (!(ref2->flash_offset & 1)) \
				my_used_size += ref2->totlen; \
			ref2 = ref2->next_phys; \
		} \
		if (my_used_size != jeb->used_size) { \
			printk(KERN_NOTICE "Calculated used size %08x != stored used size %08x\n", my_used_size, jeb->used_size); \
			BUG(); \
		} \
	} while(0)

#define ALLOC_NORMAL	0	/* Normal allocation */
#define ALLOC_DELETION	1	/* Deletion node. Best to allow it */
#define ALLOC_GC	2	/* Space requested for GC. Give it or die */

#define JFFS2_RESERVED_BLOCKS_BASE 3						/* Number of free blocks there must be before we... */
#define JFFS2_RESERVED_BLOCKS_WRITE (JFFS2_RESERVED_BLOCKS_BASE + 2)		/* ... allow a normal filesystem write */
#define JFFS2_RESERVED_BLOCKS_DELETION (JFFS2_RESERVED_BLOCKS_BASE + 1)		/* ... allow a normal filesystem deletion */
#define JFFS2_RESERVED_BLOCKS_GCTRIGGER (JFFS2_RESERVED_BLOCKS_BASE + 3)	/* ... wake up the GC thread */
#define JFFS2_RESERVED_BLOCKS_GCBAD (JFFS2_RESERVED_BLOCKS_BASE + 1)		/* ... pick a block from the bad_list to GC */
#define JFFS2_RESERVED_BLOCKS_GCMERGE (JFFS2_RESERVED_BLOCKS_BASE)		/* ... merge pages when garbage collecting */


#define PAD(x) (((x)+3)&~3)

static inline int jffs2_raw_ref_to_inum(struct jffs2_raw_node_ref *raw)
{
	while(raw->next_in_ino) {
		raw = raw->next_in_ino;
	}

	return ((struct jffs2_inode_cache *)raw)->ino;
}

/* nodelist.c */
D1(void jffs2_print_frag_list(struct jffs2_inode_info *f));
void jffs2_add_fd_to_list(struct jffs2_sb_info *c, struct jffs2_full_dirent *new, struct jffs2_full_dirent **list);
void jffs2_add_tn_to_list(struct jffs2_tmp_dnode_info *tn, struct jffs2_tmp_dnode_info **list);
int jffs2_get_inode_nodes(struct jffs2_sb_info *c, ino_t ino, struct jffs2_inode_info *f,
			  struct jffs2_tmp_dnode_info **tnp, struct jffs2_full_dirent **fdp,
			  uint32_t *highest_version, uint32_t *latest_mctime,
			  uint32_t *mctime_ver);
struct jffs2_inode_cache *jffs2_get_ino_cache(struct jffs2_sb_info *c, int ino);
void jffs2_add_ino_cache (struct jffs2_sb_info *c, struct jffs2_inode_cache *new);
void jffs2_del_ino_cache(struct jffs2_sb_info *c, struct jffs2_inode_cache *old);
void jffs2_free_ino_caches(struct jffs2_sb_info *c);
void jffs2_free_raw_node_refs(struct jffs2_sb_info *c);

/* nodemgmt.c */
int jffs2_reserve_space(struct jffs2_sb_info *c, uint32_t minsize, uint32_t *ofs, uint32_t *len, int prio);
int jffs2_reserve_space_gc(struct jffs2_sb_info *c, uint32_t minsize, uint32_t *ofs, uint32_t *len);
int jffs2_add_physical_node_ref(struct jffs2_sb_info *c, struct jffs2_raw_node_ref *new, uint32_t len, int dirty);
void jffs2_complete_reservation(struct jffs2_sb_info *c);
void jffs2_mark_node_obsolete(struct jffs2_sb_info *c, struct jffs2_raw_node_ref *raw);

/* write.c */
struct inode *jffs2_new_inode (struct inode *dir_i, int mode, struct jffs2_raw_inode *ri);
struct jffs2_full_dnode *jffs2_write_dnode(struct jffs2_sb_info *c, struct jffs2_inode_info *f, struct jffs2_raw_inode *ri, const unsigned char *data, uint32_t datalen, uint32_t flash_ofs,  uint32_t *writelen);
struct jffs2_full_dirent *jffs2_write_dirent(struct jffs2_sb_info *c, struct jffs2_inode_info *f, struct jffs2_raw_dirent *rd, const unsigned char *name, uint32_t namelen, uint32_t flash_ofs,  uint32_t *writelen);
int jffs2_write_inode_range(struct jffs2_sb_info *c, struct jffs2_inode_info *f,
			    struct jffs2_raw_inode *ri, unsigned char *buf, 
			    uint32_t offset, uint32_t writelen, uint32_t *retlen);
int jffs2_do_create(struct jffs2_sb_info *c, struct jffs2_inode_info *dir_f, struct jffs2_inode_info *f, struct jffs2_raw_inode *ri, const char *name, int namelen);
int jffs2_do_unlink(struct jffs2_sb_info *c, struct jffs2_inode_info *dir_f, const char *name, int namelen, struct jffs2_inode_info *dead_f);
int jffs2_do_link (struct jffs2_sb_info *c, struct jffs2_inode_info *dir_f, uint32_t ino, uint8_t type, const char *name, int namelen);


/* readinode.c */
void jffs2_truncate_fraglist (struct jffs2_sb_info *c, struct jffs2_node_frag **list, uint32_t size);
int jffs2_add_full_dnode_to_fraglist(struct jffs2_sb_info *c, struct jffs2_node_frag **list, struct jffs2_full_dnode *fn);
int jffs2_add_full_dnode_to_inode(struct jffs2_sb_info *c, struct jffs2_inode_info *f, struct jffs2_full_dnode *fn);
void jffs2_read_inode (struct inode *);
int jffs2_do_read_inode(struct jffs2_sb_info *c, struct jffs2_inode_info *f, 
			uint32_t ino, struct jffs2_raw_inode *latest_node);
void jffs2_clear_inode (struct inode *);
void jffs2_do_clear_inode(struct jffs2_sb_info *c, struct jffs2_inode_info *f);

/* malloc.c */
int jffs2_create_slab_caches(void);
void jffs2_destroy_slab_caches(void);

struct jffs2_full_dirent *jffs2_alloc_full_dirent(int namesize);
void jffs2_free_full_dirent(struct jffs2_full_dirent *);
struct jffs2_full_dnode *jffs2_alloc_full_dnode(void);
void jffs2_free_full_dnode(struct jffs2_full_dnode *);
struct jffs2_raw_dirent *jffs2_alloc_raw_dirent(void);
void jffs2_free_raw_dirent(struct jffs2_raw_dirent *);
struct jffs2_raw_inode *jffs2_alloc_raw_inode(void);
void jffs2_free_raw_inode(struct jffs2_raw_inode *);
struct jffs2_tmp_dnode_info *jffs2_alloc_tmp_dnode_info(void);
void jffs2_free_tmp_dnode_info(struct jffs2_tmp_dnode_info *);
struct jffs2_raw_node_ref *jffs2_alloc_raw_node_ref(void);
void jffs2_free_raw_node_ref(struct jffs2_raw_node_ref *);
struct jffs2_node_frag *jffs2_alloc_node_frag(void);
void jffs2_free_node_frag(struct jffs2_node_frag *);
struct jffs2_inode_cache *jffs2_alloc_inode_cache(void);
void jffs2_free_inode_cache(struct jffs2_inode_cache *);

/* gc.c */
int jffs2_garbage_collect_pass(struct jffs2_sb_info *c);

/* read.c */
int jffs2_read_dnode(struct jffs2_sb_info *c, struct jffs2_full_dnode *fd, unsigned char *buf, int ofs, int len);
int jffs2_read_inode_range(struct jffs2_sb_info *c, struct jffs2_inode_info *f,
			   unsigned char *buf, uint32_t offset, uint32_t len);
char *jffs2_getlink(struct jffs2_sb_info *c, struct jffs2_inode_info *f);


/* compr.c */
unsigned char jffs2_compress(unsigned char *data_in, unsigned char *cpage_out, 
			     uint32_t *datalen, uint32_t *cdatalen);
int jffs2_decompress(unsigned char comprtype, unsigned char *cdata_in, 
		     unsigned char *data_out, uint32_t cdatalen, uint32_t datalen);

/* scan.c */
int jffs2_scan_medium(struct jffs2_sb_info *c);

/* build.c */
int jffs2_do_mount_fs(struct jffs2_sb_info *c);

/* erase.c */
void jffs2_erase_block(struct jffs2_sb_info *c, struct jffs2_eraseblock *jeb);
void jffs2_erase_pending_blocks(struct jffs2_sb_info *c);
void jffs2_mark_erased_blocks(struct jffs2_sb_info *c);
void jffs2_erase_pending_trigger(struct jffs2_sb_info *c);

#endif /* __JFFS2_NODELIST_H__ */
