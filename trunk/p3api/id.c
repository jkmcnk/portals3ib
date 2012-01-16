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

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

/* If compiling for user-space (and maybe NIC-space), these need to be
 * the Portals3 versions of the Linux kernel include files, which
 * have been suitably modified for use in user-space code.
 */
#include <linux/list.h>

/* These are all Portals3 include files.
 */
#include <p3-config.h>

#include <p3/lock.h>

#include <p3api/types.h>
#include <p3api/nal.h>
#include <p3api/api.h>
#include <p3api/debug.h>

#include <p3/handle.h>
#include <p3/process.h>
#include <p3/errno.h>
#include <p3/debug.h>

#include <p3lib/id.h>
#include <p3lib/p3lib_support.h>

#include "init.h"
#include "request_lock.h"

int PtlGetJid(ptl_handle_ni_t ni_handle, ptl_jid_t *jid)
{
	int status;
	lib_ni_t *ni;
	
	if (!jid)
		return PTL_SEGV;

	if (p3_api_process.init < 0)
		return PTL_NO_INIT;

	if (!(PTL_NI_INDEX(ni_handle) < PTL_MAX_INTERFACES &&
	      p3_api_process.ni[PTL_NI_INDEX(ni_handle)]))
		return PTL_NI_INVALID;

	request_lock_lock();
	status = p3_has_process_and_ni(ni_handle, &ni);
	if (status != PTL_OK) {
		request_lock_unlock();
		return status;
	}
	
	status = lib_PtlGetJid(ni, jid);
	request_lock_unlock();

	return status;
}

int PtlGetId(ptl_handle_ni_t ni_handle, ptl_process_id_t *id)
{
	int status;
	lib_ni_t *ni;

	if (!id)
		return PTL_SEGV;

	if (p3_api_process.init < 0)
		return PTL_NO_INIT;

	if (!(PTL_NI_INDEX(ni_handle) < PTL_MAX_INTERFACES &&
	      p3_api_process.ni[PTL_NI_INDEX(ni_handle)]))
		return PTL_NI_INVALID;

	request_lock_lock();
	status = p3_has_process_and_ni(ni_handle, &ni);
	if (status != PTL_OK) {
		request_lock_unlock();
		return status;
	}
	
	status = lib_PtlGetId(ni, id);
	request_lock_unlock();

	return status;
}

int PtlGetUid(ptl_handle_ni_t ni_handle, ptl_uid_t *uid)
{
	int status;
	lib_ni_t *ni;

	if (!uid)
		return PTL_SEGV;

	if (p3_api_process.init < 0)
		return PTL_NO_INIT;

	if (!(PTL_NI_INDEX(ni_handle) < PTL_MAX_INTERFACES &&
	      p3_api_process.ni[PTL_NI_INDEX(ni_handle)]))
		return PTL_NI_INVALID;

	request_lock_lock();
	status = p3_has_process_and_ni(ni_handle, &ni);
	if (status != PTL_OK) {
		request_lock_unlock();
		return status;
	}
	
	status = lib_PtlGetUid(ni, uid);
	request_lock_unlock();
	
	return status;
}
