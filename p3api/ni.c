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

#include <unistd.h>
#include <stdio.h>
#include <limits.h>

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
#include <p3api/nal.h>
#include <p3api/api.h>
#include <p3api/misc.h>

#include <p3/handle.h>
#include <p3/process.h>
#include <p3/obj_alloc.h>
#include <p3/errno.h>

#include <p3lib/ni.h>
#include <p3lib/me.h>
#include <p3lib/p3lib_support.h>

#include "init.h"
#include "request_lock.h"

static int niinit_debug_is_ni_valid(ptl_handle_any_t req_handle, lib_ni_t **ni_out)
{
	p3_process_t *pp;
	lib_ni_t *ni = NULL;
	unsigned int i;
	
	pp = p3lib_cur_process();
	
	if (pp == NULL) {
		return PTL_NO_INIT;
	}
	
	i = PTL_NI_INDEX(req_handle);
	
	if (i < 0 && i >= PTL_MAX_INTERFACES)
		return PTL_HANDLE_INVALID;
		
	ni = pp->ni[i];
	
	if (ni == NULL) {
		*ni_out = NULL;
		return PTL_OK;
	}

	p3_lock(&ni->obj_alloc);
	if (!TST_OBJ(ni, OBJ_INUSE)) {
		p3_unlock(&ni->obj_alloc);
		return PTL_HANDLE_INVALID;
	}
	
	p3_unlock(&ni->obj_alloc);
	
	*ni_out = ni;
	
	return PTL_OK;
}

int PtlNIInit(ptl_interface_t iface, ptl_pid_t pid,
	      ptl_ni_limits_t *desired, ptl_ni_limits_t *actual,
	      ptl_handle_ni_t *ni_handle)
{
	ptl_ni_limits_t limits_desired;
	ptl_ni_limits_t limits_actual;
	
	api_ni_t *ni;
	lib_ni_t *lib_ni;
	unsigned i, rc = PTL_OK;

	if (!ni_handle) {
		rc = PTL_SEGV;
		goto out;
	}
	if (p3_api_process.init < 0) {
		rc = PTL_NO_INIT;
		goto out;
	}
	/* Look for a duplicate init request.
	 */
	for (i=0; i<PTL_MAX_INTERFACES; i++) {
		ni = p3_api_process.ni[i];
		if (ni && ni->nal.type == iface) {
			*ni_handle = PTL_OBJ_HNDL(ni);
			goto success;
		}
	}
	if (!(ni = p3_malloc(sizeof(*ni)))) {
		rc = PTL_NO_SPACE;
		goto out;
	}
	p3lock_init(&ni->obj_alloc);

	if (desired) 
		limits_desired = *desired;
	else {
		/* We'll put infinite values here to make sure the NAL
		 * implementation does its job correctly on the library side.
		 */
		limits_desired.max_mes = INT_MAX;
		limits_desired.max_mds = INT_MAX;
		limits_desired.max_eqs = INT_MAX;
		limits_desired.max_ac_index = INT_MAX;
		limits_desired.max_pt_index = INT_MAX;
		limits_desired.max_md_iovecs = INT_MAX;
		limits_desired.max_me_list = INT_MAX;
		limits_desired.max_getput_md = INT_MAX;
	}
	
	request_lock_lock();
	
	rc = niinit_debug_is_ni_valid(0, &lib_ni);
	if (rc != PTL_OK) {
		p3_free(ni);
		request_lock_unlock();
		goto out;		
	}

	/* FIXME: we could add a call here to a NAL API-side function to
	 * put something NAL-specific in req.t.niinit.data.
	 */
	rc = lib_PtlNIInit(lib_ni, iface, pid, &limits_desired, 0, NULL,  
		&limits_actual, ni_handle);
	request_lock_unlock();

	if (rc != PTL_OK) {
		p3_free(ni);
		goto out;
	}
	p3_api_process.ni[PTL_NI_INDEX(*ni_handle)] = ni;

	ni->id = *ni_handle;
	ni->limits = limits_actual;

	INIT_LIST_HEAD(&ni->free_eq);
	PTL_ALLOC_INIT_TBL(&ni->eq);

	ni->nal.type = iface;
	ni->nal.private = NULL;		/* FIXME */
	ni->nal.errstr = NULL;		/* FIXME */
success:
	p3_api_process.init++;
	if (actual)
		*actual = ni->limits;

	/* FIXME:  Hmmmmm, does the API really need locking?
	 */
	p3_lock(&ni->obj_alloc);
	SET_OBJ(ni, OBJ_INUSE);
	p3_unlock(&ni->obj_alloc);
out:
	return rc;
}

int PtlNIEqDump(ptl_handle_ni_t ni_handle)
{
	api_ni_t *ni;
	unsigned if_idx = PTL_NI_INDEX(ni_handle);
	unsigned i;

	if (p3_api_process.init < 0)
		return PTL_NO_INIT;

	if (!(if_idx < PTL_MAX_INTERFACES && (ni = p3_api_process.ni[if_idx])))
		return PTL_NI_INVALID;

	printf("%d: ni eq tbl %p rows %d/%d\n",
	       getpid(), ni->eq.tbl, ni->eq.next_row, ni->eq.num_rows);

	if (!ni->eq.tbl)
		return PTL_OK;

	for (i=0; i<ni->eq.num_rows; i++)
		printf("%d: ni eq tbl row %p\n", getpid(), ni->eq.tbl[i]);

	return PTL_OK;
}

void __free_all_eq(api_ni_t *ni)
{
	unsigned i, j;

	/* Look for any event queues that are in use, and free them.
	 * FIXME: obj_alloc.h needs to have an iterator method for
	 * this type of thing.
	 */
	for (i=0; i<ni->eq.next_row; i++)
		for (j=0; j<PTL_INDX_MAX_COL; j++) {
			api_eq_t *eq = ni->eq.tbl[i] + j;
			if (TST_OBJ(eq, OBJ_INUSE)) {
				p3_free(eq->base);
				ptl_obj_free(eq, ni);
			}
		}
}

int PtlNIFini(ptl_handle_ni_t ni_handle)
{
	api_ni_t *ni;
	lib_ni_t *lib_ni;
	unsigned if_idx = PTL_NI_INDEX(ni_handle);
	int status;

	if (p3_api_process.init < 0)
		return PTL_NO_INIT;

	if (!(if_idx < PTL_MAX_INTERFACES && (ni = p3_api_process.ni[if_idx])))
		return PTL_NI_INVALID;

	p3_api_process.ni[if_idx] = NULL;
	p3_api_process.init--;

	request_lock_lock();
	
	status = p3_has_process_and_ni(ni_handle, &lib_ni);
	if (status != PTL_OK) {
		request_lock_unlock();
		return status;
	}

	lib_PtlNIFini(lib_ni);
	
	request_lock_unlock();

	__free_all_eq(ni);
	PTL_ALLOC_FREE_TBL(eq, ni);
	p3_free(ni);

	return PTL_OK;
}

int PtlNIStatus(ptl_handle_ni_t ni_handle,
		ptl_sr_index_t register_index,
		ptl_sr_value_t *status)
{
	int rt;
	lib_ni_t *ni;
	
	if (!status)
		return PTL_SEGV;

	if (p3_api_process.init < 0)
		return PTL_NO_INIT;

	if (!(PTL_NI_INDEX(ni_handle) < PTL_MAX_INTERFACES &&
	      p3_api_process.ni[PTL_NI_INDEX(ni_handle)]))
		return PTL_NI_INVALID;

	request_lock_lock();
	rt = p3_has_process_and_ni(ni_handle, &ni);
	if (rt != PTL_OK) {
		request_lock_unlock();
		return rt;
	}
	
	rt = lib_PtlNIStatus(ni, register_index, status);
	request_lock_unlock();
	
	return rt;
}

int PtlNIDist(ptl_handle_ni_t ni_handle,
	      ptl_process_id_t process,
	      unsigned long *distance)
{
	int status;
	lib_ni_t *ni;
	
	if (!distance)
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
	
	status = lib_PtlNIDist(ni, process.nid, distance);
	request_lock_unlock();

	return status;
}

int PtlNIHandle(ptl_handle_any_t handle, ptl_handle_ni_t *ni)
{
	if (!ni)
		return PTL_SEGV;

	if (p3_api_process.init < 0)
		return PTL_NO_INIT;

	if (!(PTL_NI_INDEX(handle) < PTL_MAX_INTERFACES &&
	      p3_api_process.ni[PTL_NI_INDEX(handle)]))
		return PTL_HANDLE_INVALID;

	*ni = PTL_NI_HNDL(handle);
	return PTL_OK;
}

/*
 * This function isn't part of the spec.  See p3api/debug.h for an explanation.
 */
int PtlTblDump(ptl_handle_ni_t ni_handle, int pt_index) 
{
	int status;
	lib_ni_t *ni;
	
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
	
	status = lib_PtlTblDump(ni, pt_index);
	request_lock_unlock();

	return status;
}

/*
 * This function isn't part of the spec either.  See p3api/debug.h for an
 * explanation.
 */ 
unsigned int PtlNIDebug(ptl_handle_ni_t ni_handle, unsigned int mask)
{
	int status;
	lib_ni_t *ni;
	unsigned int old_mask;
	
	if (p3_api_process.init < 0)
		return 0;

	if (!(ni_handle == PTL_INVALID_HANDLE) &&
	    !(PTL_NI_INDEX(ni_handle) < PTL_MAX_INTERFACES &&
	      p3_api_process.ni[PTL_NI_INDEX(ni_handle)]))
		return 0;

	request_lock_lock();
	status = niinit_debug_is_ni_valid(ni_handle, &ni);
	if (status != PTL_OK) {
		request_lock_unlock();
		return 0;
	}
	
	status = lib_PtlNIDebug(ni, mask, &old_mask);
	request_lock_unlock();

	return old_mask;
}
