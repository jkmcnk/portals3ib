/*
 * This Cplant(TM) source code is part of the Portals3 Reference
 * Implementation.
 *
 * This Cplant(TM) source code is the property of Sandia National
 * Laboratories.
 *
 * This Cplant(TM) source code is copyrighted by Sandia National
 * Laboratories.
 *
 * The redistribution of this Cplant(TM) source code is subject to the
 * terms of version 2 of the GNU General Public License.
 * (See COPYING, or http://www.gnu.org/licenses/lgpl.html.)
 *
 * Cplant(TM) Copyright 1998-2006 Sandia Corporation. 
 *
 * Under the terms of Contract DE-AC04-94AL85000, there is a non-exclusive
 * license for use of this work by or on behalf of the US Government.
 * Export of this program may require a license from the United States
 * Government.
 */
/* Portals3 is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License,
 * as published by the Free Software Foundation.
 *
 * Portals3 is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Portals3; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
/* Copyright 2008-2011 NEC Deutschland GmbH, NEC HPC Europe */

#ifndef _PTL3_P3LIB_P3VALIDATE_H_
#define _PTL3_P3LIB_P3VALIDATE_H_

struct p3_ubuf_map {
	int pad;
};
struct p3_addrmap {
	int pad;
};

#define DECLARE_P3_ADDRMAP_HOOK 
#define init_p3_addrmap_hook(container) do {} while (0)
#define P3_ADDRMAP_ADDRKEY(container) (NULL)
#define msg_containing_hook(msg_type,hook) ((msg_type *)NULL)
#define p3_addrmap_hook_add_ref(container, addrkey) do {} while (0)
#define p3_addrmap_hook_release(container) do {} while (0)
#define p3_addrmap_hook_drop(container) do {} while (0)

#endif /* _PTL3_P3LIB_P3VALIDATE_H_ */
