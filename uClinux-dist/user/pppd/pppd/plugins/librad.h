/*
 * librad.h
 *
 * (C) Copyright 2001, Lineo Inc. (www.lineo.com)
 */

#ifndef _LIBRAD_H
#define _LIBRAD_H

struct radius_attrib {
	u_char type;
	u_char length;
	union {
		u_long value;
		struct in_addr addr;
		char string[AUTH_STRING_LEN];
	} u;
	struct radius_attrib* next;
} __attribute__ ((__packed__));

u_int radius_sessionid(void);

int radius_add_attrib(
		struct radius_attrib **list, u_char type,
		u_int value, char *string, u_int length);

void radius_free_attrib(struct radius_attrib *list);

int radius_send_access_request(
		u_long host, int port, char *secret,
		struct radius_attrib *attriblist,
		struct radius_attrib **recvattriblist);

int radius_send_account_request(
		u_long host, int port, char *secret,
		struct radius_attrib *attriblist,
		struct radius_attrib **recvattriblist);

#endif
