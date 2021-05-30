/*
 * Memory management routine
 * Copyright (C) 1998 Kunihiro Ishiguro
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.  
 */

#ifndef _ZEBRA_MEMORY_H
#define _ZEBRA_MEMORY_H

/* #define MEMORY_LOG */

/* For tagging memory, below is the type of the memory. */
enum
{
  MTYPE_TMP = 1,
  MTYPE_COMMAND,
  MTYPE_COMMAND_CONST,
  MTYPE_STRVEC,
  MTYPE_VECTOR,
  MTYPE_VECTOR_INDEX,
  MTYPE_LINK_LIST,
  MTYPE_LINK_NODE,
  MTYPE_THREAD,
  MTYPE_THREAD_MASTER,
  MTYPE_VTY,
  MTYPE_VTY_HIST,
  MTYPE_IF,
  MTYPE_CONNECTED,
  MTYPE_AS_SEG,
  MTYPE_AS_STR,
  MTYPE_AS_PATH,
  MTYPE_COMMUNITY,
  MTYPE_COMMUNITY_VAL,
  MTYPE_ECOMMUNITY,
  MTYPE_ECOMMUNITY_VAL,
  MTYPE_CLUSTER,
  MTYPE_CLUSTER_VAL,
  MTYPE_BGP_ROUTE,
  MTYPE_ATTR,
  MTYPE_BUFFER,
  MTYPE_BUFFER_DATA,
  MTYPE_STREAM,
  MTYPE_STREAM_DATA,
  MTYPE_STREAM_FIFO,
  MTYPE_BGP_PEER,
  MTYPE_RADIX_NODE,
  MTYPE_RADIX_MASK,
  MTYPE_PREFIX,
  MTYPE_PREFIX_IPV4,
  MTYPE_PREFIX_IPV6,
  MTYPE_HASH,
  MTYPE_HASH_BACKET,
  MTYPE_RIPNG_ROUTE,
  MTYPE_RIPNG_AGGREGATE,
  MTYPE_ROUTE_TABLE,
  MTYPE_ROUTE_NODE,
  MTYPE_RIPNG_SLOT,
  MTYPE_ACCESS_LIST,
  MTYPE_ACCESS_FILTER,
  MTYPE_PREFIX_LIST,
  MTYPE_PREFIX_LIST_ENTRY,
  MTYPE_ROUTE_MAP,
  MTYPE_ROUTE_MAP_NAME,
  MTYPE_ROUTE_MAP_INDEX,
  MTYPE_ROUTE_MAP_RULE,
  MTYPE_ROUTE_MAP_RULE_STR,
  MTYPE_ROUTE_MAP_COMPILED,
  MTYPE_RIP_INFO,
  MTYPE_RIP_PEER,
  MTYPE_RIB,
  MTYPE_DESC,
  MTYPE_OSPF_TOP,
  MTYPE_OSPF_AREA,
  MTYPE_OSPF_AREA_RANGE,
  MTYPE_OSPF_NETWORK,
  MTYPE_OSPF_IF,
  MTYPE_OSPF_NEIGHBOR,
  MTYPE_OSPF_ROUTE,
  MTYPE_OSPF_ADDR,
  MTYPE_OSPF_MESSAGE,
  MTYPE_OSPF_TMP,
  MTYPE_OSPF_LSA,
  MTYPE_OSPF_LSA_DATA,
  MTYPE_OSPF_LSDB,
  MTYPE_OSPF_PACKET,
  MTYPE_OSPF_FIFO,
  MTYPE_OSPF_VERTEX,
  MTYPE_OSPF_NEXTHOP,
  MTYPE_OSPF_PATH,
  MTYPE_OSPF_VL_DATA,
  MTYPE_OSPF_CRYPT_KEY,
  MTYPE_OSPF_EXTERNAL_INFO,
  MTYPE_OSPF6_TOP,
  MTYPE_OSPF6_AREA,
  MTYPE_OSPF6_IF,
  MTYPE_OSPF6_NEIGHBOR,
  MTYPE_OSPF6_ROUTE,
  MTYPE_OSPF6_PREFIX,
  MTYPE_OSPF6_MESSAGE,
  MTYPE_OSPF6_LSA,
  MTYPE_OSPF6_VERTEX,
  MTYPE_OSPF6_OTHER,
  MTYPE_DISTRIBUTE,
  MTYPE_ZLOG,
  MTYPE_AS_FILTER,
  MTYPE_AS_LIST,
  MTYPE_COMMUNITY_ENTRY,
  MTYPE_COMMUNITY_LIST,
  MTYPE_ZEBRA,
  MTYPE_NEXTHOP,
  MTYPE_RTADV_PREFIX,
  MTYPE_IF_RMAP,
  MTYPE_NEWLIST,
  MTYPE_NEWNODE,
  MTYPE_BGP,
  MTYPE_PEER,
  MTYPE_PEER_CONF,
  MTYPE_PEER_GROUP,
  MTYPE_BGP_STATIC,
  MTYPE_BGP_AGGREGATE,
  MTYPE_BGP_CONFED_LIST,
  MTYPE_MAX
};

#ifdef MEMORY_LOG
#define XMALLOC(mtype, size) \
  mtype_zmalloc (__FILE__, __LINE__, (mtype), (size))
#define XCALLOC(mtype, num, size) \
  mtype_zcalloc (__FILE__, __LINE__, (mtype), (num), (size))
#define XREALLOC(mtype, ptr, size)  \
  mtype_zrealloc (__FILE__, __LINE__, (mtype), (ptr), (size))
#define XFREE(mtype, ptr) \
  mtype_zfree (__FILE__, __LINE__, (mtype), (ptr))
#define XSTRDUP(mtype, str) \
  mtype_zstrdup (__FILE__, __LINE__, (mtype), (str))
#else
#define XMALLOC(mtype, size)       zmalloc ((mtype), (size))
#define XCALLOC(mtype, num, size)  zcalloc ((mtype), (num), (size))
#define XREALLOC(mtype, ptr, size) zrealloc ((mtype), (ptr), (size))
#define XFREE(mtype, ptr)          zfree ((mtype), (ptr))
#define XSTRDUP(mtype, str)        zstrdup ((mtype), (str))
#endif /* MEMORY_LOG */

/* Prototypes of memory function. */
void *zmalloc (int type, size_t size);
void *zcalloc (int type, size_t num, size_t size);
void *zrealloc (int type, void *ptr, size_t size);
void  zfree (int type, void *ptr);
char *zstrdup (int type, char *str);

void *mtype_zmalloc (const char *file,
		     int line,
		     int type,
		     size_t size);

void *mtype_zcalloc (const char *file,
		     int line,
		     int type,
		     size_t num,
		     size_t size);

void *mtype_zrealloc (const char *file,
		     int line,
		     int type, 
		     void *ptr,
		     size_t size);

void mtype_zfree (const char *file,
		  int line,
		  int type,
		  void *ptr);

char *mtype_zstrdup (const char *file,
		     int line,
		     int type,
		     char *str);
void memory_init ();

#endif /* _ZEBRA_MEMORY_H */
