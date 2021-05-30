/*
 * Redistribution Handler
 * Copyright (C) 1999 Kunihiro Ishiguro
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

#ifndef _ZEBRA_REDISTRIBUTE_H
#define _ZEBRA_REDISTRIBUTE_H

#include "table.h"

void zebra_redistribute_add (int, struct zebra_client *, int);
void zebra_redistribute_delete (int, struct zebra_client *, int);

void redistribute_add (struct route_node *np, struct rib *rib);
void redistribute_delete (struct route_node *np, struct rib *rib);

void zebra_interface_add_update (struct interface *ifp);
void zebra_interface_delete_update (struct interface *ifp);
void zebra_interface_address_add_update (struct interface *ifp, 
					 struct connected *c);

#endif /* _ZEBRA_REDISTRIBUTE_H */
