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

#ifndef _PTL3_P3_HANDLE_H_
#define _PTL3_P3_HANDLE_H_

/* Portals uses opaque handles as a means of identifying objects.  An
 * implementation is free to construct handles in whatever fashion is
 * convenient.  It turns out that in this implementation, the API uses
 * network interface handles to look up NALs, but all the other handle 
 * types are used in the library to look up other Portals objects.
 *
 * We want O(1) lookup of Portals objects, so arrays are nice, but we
 * don't want a statically dimensioned array of them, for various reasons.
 * Instead, we'll have a 2D array, where the number of columns is statically
 * dimensioned, but we add rows on demand.  If the length of a row (number 
 * of columns) is a power of two, we can decompose an object index into
 * row and column indices with mask/shift operations.
 *
 * However, that means we can't easily compute the object's index from its
 * address, so we'll need to store the index in the object.  But, we won't
 * need 2^32 objects, and we will need a few flags per object, so we'll
 * pack the index and the flags together and call it an object id.
 *
 * It also turns out that occasionally the library needs to construct a
 * handle that can be used from API space, e.g. in building events to 
 * deliver.
 *
 * So, to simplify things we'll use the same format to build an object id
 * as we use for a descriptor handle:
 *
 *    bits       handle              id
 *   ------     ----------------    -----------------------------------
 *    0-15       object index        object index, bits 0-4  -> column
 *                                                      5-15 -> row
 *    16-18      interface index     interface index
 *
 *    19         unused              unused
 *
 *    20-23      unused              common API/lib object flags
 *    23-31      unused              object flags specific to either api or lib
 *
 * Note that an id flag bit set in the bits common to the API or library
 * have the same meaning to both the API and library, while a bit set in
 * those specific to either the API or library has a different meaning,
 * depending on context.  This should never be a problem, since we should
 * never pass indices between the API and the library, only handles.
 *
 * The macros that follow make it all happen.
 */
#define PTL_HNDL_BITS       32
#define PTL_HNDL_ID_BITS    16
#define PTL_HNDL_IF_BITS     3
#define PTL_INDX_FL_BITS    12

#define PTL_INDX_COL_BITS    5
#define PTL_INDX_ROW_BITS   11

#if PTL_HNDL_ID_BITS + PTL_HNDL_IF_BITS + PTL_INDX_FL_BITS > PTL_HNDL_BITS
#error Portal object index id, interface id, flag bits set incorrectly.
#endif
#if PTL_INDX_COL_BITS + PTL_INDX_ROW_BITS != PTL_HNDL_ID_BITS
#error Portal object row, column index bits set incorrectly!
#endif

#define PTL_INDX_MAX_COL     (1U<<PTL_INDX_COL_BITS)
#define PTL_INDX_MAX_ROW     (1U<<PTL_INDX_ROW_BITS)
#define PTL_MAX_OBJECTS      (1U<<PTL_HNDL_ID_BITS)
#define PTL_MAX_INTERFACES   (1U<<PTL_HNDL_IF_BITS)

#define PTL_HNDL_ID_MASK     (PTL_MAX_OBJECTS-1)
#define PTL_HNDL_IF_MASK     (PTL_MAX_INTERFACES-1 << PTL_HNDL_ID_BITS)
#define PTL_HNDL_MASK        (PTL_HNDL_ID_MASK | PTL_HNDL_IF_MASK)
#define PTL_INDX_FL_MASK \
	((1U<<PTL_INDX_FL_BITS)-1 << PTL_HNDL_BITS-PTL_INDX_FL_BITS)

#define PTL_OBJ_INDX(obj)    ((obj)->id & PTL_HNDL_ID_MASK)
#define PTL_OBJ_HNDL(obj)    ((obj)->id & PTL_HNDL_MASK)

#define PTL_INDX(hndl)       ((hndl) & PTL_HNDL_ID_MASK)
#define PTL_COL_INDX(hndl)   ((hndl) & PTL_INDX_MAX_COL-1)
#define PTL_ROW_INDX(hndl)   ((hndl) >> PTL_INDX_COL_BITS & PTL_INDX_MAX_ROW-1)

#define PTL_NI_HNDL(hndl)    ((hndl) & PTL_HNDL_IF_MASK)
#define PTL_NI_INDEX(hndl)   (PTL_NI_HNDL(hndl) >> PTL_HNDL_ID_BITS)
#define PTL_MAKE_NI_HNDL(cntr) (PTL_NI_HNDL((cntr) << PTL_HNDL_ID_BITS))

#define VALID_PTL_OBJ(tbl_obj,hndl) \
	(PTL_INDX(hndl) < (tbl_obj)->next_row * PTL_INDX_MAX_COL)

#define GET_PTL_OBJ(tbl_obj,hndl) \
	(&(tbl_obj)->tbl[PTL_ROW_INDX(hndl)][PTL_COL_INDX(hndl)])

/*
 * Use this to easily set object flag bits
 */
#define PTL_OBJ_FLAG(f)  ((f) << PTL_HNDL_BITS - PTL_INDX_FL_BITS)

/*
 * Common object flag bits
 */
#define OBJ_INUSE        PTL_OBJ_FLAG(0x001)	/* object is not free */

#define TST_OBJ(ptl_obj,flag) ((ptl_obj)->id & (flag) & PTL_INDX_FL_MASK)
#define SET_OBJ(ptl_obj,flag) ((ptl_obj)->id |= (flag) & PTL_INDX_FL_MASK)
#define CLR_OBJ(ptl_obj,flag) ((ptl_obj)->id &= ~((flag) & PTL_INDX_FL_MASK))



#endif /* _PTL3_P3_HANDLE_H_ */
