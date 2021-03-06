/* vi: set sw=4 ts=4: */
/*
 * The one and only crypt(3) function.
 *
 * This source code is derived from Minix's pwdauth.c, which was based
 * on Andy Tanenbaum's book "Computer Networks", and then rewritten in
 * C by Kees J. Bot, 7 Feb 1994.  This code was ported from Minix to
 * uClibc on June 28, 2001 by Manuel Novoa III, and then reshuffled to
 * be reentrant by Erik Andersen <andersen@uclibc.org> on June 28, 2001. 
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Library General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Library General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Library General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 * Original copyright notice is retained at the end of this file.
 *
 */



/* This program gets as input the key and salt arguments of the crypt(3)
 * function as two null terminated strings.  The crypt result is output as
 * one null terminated string.  Input and output must be <= 1024 characters.
 * The exit code will be 1 on any error.
 *
 * If the key has the form '##name' then the key will be encrypted and the
 * result checked to be equal to the encrypted password in the shadow password
 * file.  If equal than '##name' will be returned, otherwise exit code 2.
 *
 * Otherwise the key will be encrypted normally and the result returned.
 *
 * As a special case, anything matches a null encrypted password to allow
 * a no-password login.
 */

#include <string.h>
#include <crypt.h>

extern char * md5_crypt_r( const char *pw, const char *salt, struct crypt_data * data);

static const struct ordering InitialTr = { {
	58,50,42,34,26,18,10, 2,60,52,44,36,28,20,12, 4,
	62,54,46,38,30,22,14, 6,64,56,48,40,32,24,16, 8,
	57,49,41,33,25,17, 9, 1,59,51,43,35,27,19,11, 3,
	61,53,45,37,29,21,13, 5,63,55,47,39,31,23,15, 7,
} };

static const struct ordering FinalTr = { {
	40, 8,48,16,56,24,64,32,39, 7,47,15,55,23,63,31,
	38, 6,46,14,54,22,62,30,37, 5,45,13,53,21,61,29,
	36, 4,44,12,52,20,60,28,35, 3,43,11,51,19,59,27,
	34, 2,42,10,50,18,58,26,33, 1,41, 9,49,17,57,25,
} };

static const struct ordering swap = { {
	33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,
	49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,
	 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15,16,
	17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,
} };

static const struct ordering KeyTr1 = { {
	57,49,41,33,25,17, 9, 1,58,50,42,34,26,18,
	10, 2,59,51,43,35,27,19,11, 3,60,52,44,36,
	63,55,47,39,31,23,15, 7,62,54,46,38,30,22,
	14, 6,61,53,45,37,29,21,13, 5,28,20,12, 4,
} };

static const struct ordering KeyTr2 = { {
	14,17,11,24, 1, 5, 3,28,15, 6,21,10,
	23,19,12, 4,26, 8,16, 7,27,20,13, 2,
	41,52,31,37,47,55,30,40,51,45,33,48,
	44,49,39,56,34,53,46,42,50,36,29,32,
} };

static const struct ordering etr = { {
	32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9,
	 8, 9,10,11,12,13,12,13,14,15,16,17,
	16,17,18,19,20,21,20,21,22,23,24,25,
	24,25,26,27,28,29,28,29,30,31,32, 1,
} };

static const struct ordering ptr = { {
	16, 7,20,21,29,12,28,17, 1,15,23,26, 5,18,31,10,
	 2, 8,24,14,32,27, 3, 9,19,13,30, 6,22,11, 4,25,
} };

static const unsigned char s_boxes[8][64] = {
{	14, 4,13, 1, 2,15,11, 8, 3,10, 6,12, 5, 9, 0, 7,
	 0,15, 7, 4,14, 2,13, 1,10, 6,12,11, 9, 5, 3, 8,
	 4, 1,14, 8,13, 6, 2,11,15,12, 9, 7, 3,10, 5, 0,
	15,12, 8, 2, 4, 9, 1, 7, 5,11, 3,14,10, 0, 6,13,
},

{	15, 1, 8,14, 6,11, 3, 4, 9, 7, 2,13,12, 0, 5,10,
	 3,13, 4, 7,15, 2, 8,14,12, 0, 1,10, 6, 9,11, 5,
	 0,14, 7,11,10, 4,13, 1, 5, 8,12, 6, 9, 3, 2,15,
	13, 8,10, 1, 3,15, 4, 2,11, 6, 7,12, 0, 5,14, 9,
},

{	10, 0, 9,14, 6, 3,15, 5, 1,13,12, 7,11, 4, 2, 8,
	13, 7, 0, 9, 3, 4, 6,10, 2, 8, 5,14,12,11,15, 1,
	13, 6, 4, 9, 8,15, 3, 0,11, 1, 2,12, 5,10,14, 7,
	 1,10,13, 0, 6, 9, 8, 7, 4,15,14, 3,11, 5, 2,12,
},

{	 7,13,14, 3, 0, 6, 9,10, 1, 2, 8, 5,11,12, 4,15,
	13, 8,11, 5, 6,15, 0, 3, 4, 7, 2,12, 1,10,14, 9,
	10, 6, 9, 0,12,11, 7,13,15, 1, 3,14, 5, 2, 8, 4,
	 3,15, 0, 6,10, 1,13, 8, 9, 4, 5,11,12, 7, 2,14,
},

{	 2,12, 4, 1, 7,10,11, 6, 8, 5, 3,15,13, 0,14, 9,
	14,11, 2,12, 4, 7,13, 1, 5, 0,15,10, 3, 9, 8, 6,
	 4, 2, 1,11,10,13, 7, 8,15, 9,12, 5, 6, 3, 0,14,
	11, 8,12, 7, 1,14, 2,13, 6,15, 0, 9,10, 4, 5, 3,
},

{	12, 1,10,15, 9, 2, 6, 8, 0,13, 3, 4,14, 7, 5,11,
	10,15, 4, 2, 7,12, 9, 5, 6, 1,13,14, 0,11, 3, 8,
	 9,14,15, 5, 2, 8,12, 3, 7, 0, 4,10, 1,13,11, 6,
	 4, 3, 2,12, 9, 5,15,10,11,14, 1, 7, 6, 0, 8,13,
},

{	 4,11, 2,14,15, 0, 8,13, 3,12, 9, 7, 5,10, 6, 1,
	13, 0,11, 7, 4, 9, 1,10,14, 3, 5,12, 2,15, 8, 6,
	 1, 4,11,13,12, 3, 7,14,10,15, 6, 8, 0, 5, 9, 2,
	 6,11,13, 8, 1, 4,10, 7, 9, 5, 0,15,14, 2, 3,12,
},

{	13, 2, 8, 4, 6,15,11, 1,10, 9, 3,14, 5, 0,12, 7,
	 1,15,13, 8,10, 3, 7, 4,12, 5, 6,11, 0,14, 9, 2,
	 7,11, 4, 1, 9,12,14, 2, 0, 6,10,13,15, 3, 5, 8,
	 2, 1,14, 7, 4,10, 8,13,15,12, 9, 0, 3, 5, 6,11,
},
};

static const int rots[] = {
	1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1,
};

static void transpose(struct block *data, const struct ordering *t, int n)
{
	struct block x;

	x = *data;

	while (n-- > 0) {
		data->b_data[n] = x.b_data[t->o_data[n] - 1];
	}
}

static void rotate(struct block *key)
{
	unsigned char *p = key->b_data;
	unsigned char *ep = &(key->b_data[55]);
	int data0 = key->b_data[0], data28 = key->b_data[28];

	while (p++ < ep) *(p-1) = *p;
	key->b_data[27] = data0;
	key->b_data[55] = data28;
}

static void f(int i, struct block *key, struct block *a, struct block *x, struct crypt_data *data)
{
	struct block e, ikey, y;
	int k;
	unsigned char *p, *q, *r;

	e = *a;
	transpose(&e, data->EP, 48);
	for (k = rots[i]; k; k--) rotate(key);
	ikey = *key;
	transpose(&ikey, &KeyTr2, 48);
	p = &(y.b_data[48]);
	q = &(e.b_data[48]);
	r = &(ikey.b_data[48]);
	while (p > y.b_data) {
		*--p = *--q ^ *--r;
	}
	q = x->b_data;
	for (k = 0; k < 8; k++) {
		int xb, r;

		r = *p++ << 5;
		r += *p++ << 3;
		r += *p++ << 2;
		r += *p++ << 1;
		r += *p++;
		r += *p++ << 4;

		xb = s_boxes[k][r];

		*q++ = (xb >> 3) & 1;
		*q++ = (xb>>2) & 1;
		*q++ = (xb>>1) & 1;
		*q++ = (xb & 1);
	}
	transpose(x, &ptr, 32);
}

void setkey_r(const char *k, struct crypt_data *data)
{
	struct block *key = &(data->key);
	memcpy(key, k, (sizeof(struct block)));
	transpose(key, &KeyTr1, 56);
}

extern void encrypt_r(char *blck, int edflag, struct crypt_data *data)
{
	struct block *key = &(data->key);
	struct block *p = (struct block *) blck;
	int i;

	transpose(p, &InitialTr, 64);
	for (i = 15; i>= 0; i--) {
		int j = edflag ? i : 15 - i;
		int k;
		struct block b, x;

		b = *p;
		for (k = 31; k >= 0; k--) {
			p->b_data[k] = b.b_data[k + 32];
		}
		f(j, key, p, &x, data);
		for (k = 31; k >= 0; k--) {
			p->b_data[k+32] = b.b_data[k] ^ x.b_data[k];
		}
	}
	transpose(p, &swap, 64);
	transpose(p, &FinalTr, 64);
}

extern char *crypt_r(const char *pw, const char *salt, struct crypt_data *data)
{
	char pwb[66];
	char *cp;
	static char result[16];
	char *p = pwb;
	struct ordering new_etr;
	int i;

	/* First, check if we are supposed to be using the MD5 replacement
	 * instead of DES...  */
	if (salt[0]=='$' && salt[1]=='1' && salt[2]=='$')
		return md5_crypt_r(pw, salt, data);

	data->EP = &etr;
	while (*pw && p < &pwb[64]) {
		int j = 7;

		while (j--) {
			*p++ = (*pw >> j) & 01;
		}
		pw++;
		*p++ = 0;
	}
	while (p < &pwb[64]) *p++ = 0;

	setkey_r(p = pwb, data);

	while (p < &pwb[66]) *p++ = 0;

	new_etr = etr;
	data->EP = &new_etr;
	if (salt[0] == 0 || salt[1] == 0) salt = "**";
	for (i = 0; i < 2; i++) {
		char c = *salt++;
		int j;

		result[i] = c;
		if ( c > 'Z') c -= 6 + 7 + '.';	/* c was a lower case letter */
		else if ( c > '9') c -= 7 + '.';/* c was upper case letter */
		else c -= '.';			/* c was digit, '.' or '/'. */
						/* now, 0 <= c <= 63 */
		for (j = 0; j < 6; j++) {
			if ((c >> j) & 01) {
				int t = 6*i + j;
				int temp = new_etr.o_data[t];
				new_etr.o_data[t] = new_etr.o_data[t+24];
				new_etr.o_data[t+24] = temp;
			}
		}
	}

	if (result[1] == 0) result[1] = result[0];

	for (i = 0; i < 25; i++) encrypt_r(pwb,0, data);
	data->EP = &etr;

	p = pwb;
	cp = result+2;
	while (p < &pwb[66]) {
		int c = 0;
		int j = 6;

		while (j--) {
			c <<= 1;
			c |= *p++;
		}
		c += '.';		/* becomes >= '.' */
		if (c > '9') c += 7;	/* not in [./0-9], becomes upper */
		if (c > 'Z') c += 6;	/* not in [A-Z], becomes lower */
		*cp++ = c;
	}
	*cp = 0;
	return result;
}


/*
 * Copyright (c) 1987,1997, Prentice Hall
 * All rights reserved.
 * 
 * Redistribution and use of the MINIX operating system in source and
 * binary forms, with or without modification, are permitted provided
 * that the following conditions are met:
 * 
 * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 
 * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following
 * disclaimer in the documentation and/or other materials provided
 * with the distribution.
 * 
 * Neither the name of Prentice Hall nor the names of the software
 * authors or contributors may be used to endorse or promote
 * products derived from this software without specific prior
 * written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS, AUTHORS, AND
 * CONTRIBUTORS ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL PRENTICE HALL OR ANY AUTHORS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


