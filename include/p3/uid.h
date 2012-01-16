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

#ifndef _PTL3_P3_UID_H_
#define _PTL3_P3_UID_H_

/* P3.3 API spec, section 3.6.1 specifically allows a user to have different
 * ptl_uid_t values depending on which network interface is used.
 *
 * This is so brilliantly useless as to defy description.  Why, you ask?
 *
 * Hint: Consider a machine with an interface in each of multiple
 * administrative domains.  Consider messages forwarded from one domain
 * to another. Consider how the recipient of such a message could make
 * sense of the ptl_uid_t contained therein.  Good luck.
 *
 * In an attempt to highlight the difficulties of this madness, this 
 * implementation will explicitly use ptl_uid_t values that are different
 * based on the interface, regardless of whether the underlying system
 * user id values would be different in different administrative domains.
 */
typedef uid_t sys_uid_t;

static inline
ptl_uid_t sysuid_2_ptluid(sys_uid_t sid, ptl_handle_ni_t ni)
{
	/* FIXME: On Linux, the upper limit on the value of a uid_t seems
	 * to be determined by sizeof(__kernel_uid_t).  Configure.ac
	 * should be fixed up to make sure the following mangling doesn't
	 * result in duplicate uids.
	 */
	ptl_uid_t uid = sid;
	uid |= PTL_NI_INDEX(ni) << sizeof(uid)*CHAR_BIT - PTL_HNDL_IF_BITS;
	return uid;
}

#endif /* _PTL3_P3_UID_H_ */
