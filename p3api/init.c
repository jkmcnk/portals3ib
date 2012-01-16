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

#include <sys/types.h>

/* If compiling for user-space (and maybe NIC-space), these need to be
 * the Portals3 versions of the Linux kernel include files, which
 * have been suitably modified for use in user-space code.
 */
#include <linux/list.h>

/* These are all Portals3 include files.
 */
#include <p3-config.h>
#include <p3utils.h>

#include <p3/lock.h>

#include <p3api/types.h>
#include <p3api/api.h>
#include <p3api/nal.h>

#include <p3/handle.h>
#include <p3/process.h>
#include <p3/errno.h>

#include <p3lib/p3lib_support.h>
#include <p3lib/init.h>

#include "init.h"
#include "request_lock.h"


p3_process_t p3_api_process = {-1, PTL_JID_ANY, };

static int fini_is_ni_valid()
{
	p3_process_t *pp;
	
	pp = p3lib_cur_process();
	
	if (pp == NULL) {
		return PTL_NO_INIT;
	}
		
	return PTL_OK;
}

int PtlInit(int *max_interfaces)
{
	int status;
	
	if (p3_api_process.init >= 0)
		return PTL_OK;

	if (!max_interfaces)
		return PTL_SEGV;

	p3utils_init();

	request_lock_lock();
	status = lib_PtlInit();
	request_lock_unlock();	

	if (status == PTL_OK) {
		p3_api_process.init = 0;
		*max_interfaces = PTL_MAX_INTERFACES;
	}

	return status;
}

void PtlFini(void)
{
	int status;

	unsigned i;

	if (p3_api_process.init < 0)
		return;

	for (i=0; i<PTL_MAX_INTERFACES; i++) {
		if (p3_api_process.ni[i]) {
			api_ni_t *ni = p3_api_process.ni[i];
			ptl_handle_ni_t handle = PTL_OBJ_HNDL(ni);
			PtlNIFini(handle);
		}
	}
	
	request_lock_lock();
	status = fini_is_ni_valid();
	if (status != PTL_OK) {
		request_lock_unlock();
		return;
	}
	
	status = lib_PtlFini();
	request_lock_unlock();

	p3_api_process.init = -1;
	p3_api_process.jid = PTL_JID_ANY;
}
