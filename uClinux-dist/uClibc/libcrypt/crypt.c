/* vi: set sw=4 ts=4: */
/*
 * crypt() for uClibc
 *
 * Copyright (C) 2000 by Lineo, inc. and Erik Andersen
 * Copyright (C) 2000,2001 by Erik Andersen <andersen@uclibc.org>
 * Written by Erik Andersen <andersen@uclibc.org>
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
 */

#include <crypt.h>
#include <unistd.h>

/* For use by the old, non-reentrant routines (crypt/encrypt/setkey)  */
static struct crypt_data __crypt_data;

char * crypt(const char *key, const char *salt)
{
    return crypt_r (key, salt, &__crypt_data);
}

void setkey(const char *key)
{
    return setkey_r(key, &__crypt_data);
}

void encrypt(char *block, int edflag)
{
    return encrypt_r(block, edflag, &__crypt_data);
}

