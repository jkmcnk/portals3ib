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

#ifndef _PTL3_API_ERRNO_H_
#define _PTL3_API_ERRNO_H_

extern const char *ptl_err_str[];

#define PTL_ERRORS			\
	ptlerr(PTL_OK),			\
	ptlerr(PTL_AC_INDEX_INVALID),	\
	ptlerr(PTL_EQ_DROPPED),		\
	ptlerr(PTL_EQ_EMPTY),		\
	ptlerr(PTL_EQ_INVALID),		\
	ptlerr(PTL_FAIL),		\
	ptlerr(PTL_HANDLE_INVALID),	\
	ptlerr(PTL_IFACE_INVALID),	\
	ptlerr(PTL_MD_ILLEGAL),		\
	ptlerr(PTL_MD_INVALID),		\
	ptlerr(PTL_MD_IN_USE),		\
	ptlerr(PTL_MD_NO_UPDATE),	\
	ptlerr(PTL_ME_INVALID),		\
	ptlerr(PTL_ME_IN_USE),		\
	ptlerr(PTL_ME_LIST_TOO_LONG),	\
	ptlerr(PTL_NI_INVALID),		\
	ptlerr(PTL_NO_INIT),		\
	ptlerr(PTL_NO_SPACE),		\
	ptlerr(PTL_PID_INVALID),	\
	ptlerr(PTL_PROCESS_INVALID),	\
	ptlerr(PTL_PT_FULL),		\
	ptlerr(PTL_PT_INDEX_INVALID),	\
	ptlerr(PTL_SEGV),		\
	ptlerr(PTL_SR_INDEX_INVALID),	\
	ptlerr(PTL_UNKNOWN_ERROR)

#define ptlerr(value) value

typedef enum {
	PTL_ERRORS,
	PTL_MAX_ERRNO
} ptl_err_t;

#undef ptlerr

#endif /* _PTL3_API_ERRNO_H_ */
