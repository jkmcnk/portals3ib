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

#include <p3-config.h>

#include <sys/types.h>
#include <limits.h>

/* If compiling for user-space (and maybe NIC-space), these need to be
 * the Portals3 versions of the Linux kernel include files, which
 * have been suitably modified for use in user-space code.
 */
#include <linux/list.h>

/* These are all Portals3 include files.
 */
#include <p3api/types.h>

#include <p3/lock.h>
#include <p3/handle.h>
#include <p3/process.h>
#include <p3/errno.h>

#include <p3lib/types.h>
#include <p3lib/p3lib.h>
#include <p3lib/nal.h>

int lib_PtlACEntry(lib_ni_t *ni,  
		ptl_ac_index_t ac_index, 
		ptl_pt_index_t pt_index, 
		ptl_process_id_t match_id, 
		ptl_uid_t user_id,
		ptl_jid_t job_id)
{
	lib_ace_t *ace;

	if (ac_index >= ni->actab.size) {
		return PTL_AC_INDEX_INVALID;
	}
	if (pt_index >= ni->ptltab.size &&
	    pt_index != PTL_PT_INDEX_ANY) {
		return PTL_PT_INDEX_INVALID;
	}
	ace = ni->actab.ace + ac_index;

	p3_lock(&ni->obj_update);
	ace->id = match_id;
	ace->uid = user_id;
	ace->jid = job_id;
	ace->ptl = pt_index;
	p3_unlock(&ni->obj_update);

	return PTL_OK;
}
