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
#include <p3api/nal.h>
#include <p3api/api.h>
#include <p3api/debug.h>

#include <p3/handle.h>
#include <p3/process.h>
#include <p3/errno.h>
#include <p3/debug.h>

#include <p3lib/md.h>
#include <p3lib/p3lib_support.h>

#include "init.h"
#include "request_lock.h"


int PtlMDAttach(ptl_handle_me_t me_handle,
		ptl_md_t md,
		ptl_unlink_t unlink_op,
		ptl_handle_md_t *md_handle)
{
	int status;
	lib_ni_t *ni;
	ptl_md_iovec_t *iov;

	unsigned if_idx = PTL_NI_INDEX(me_handle);
	int iov_len = sizeof(ptl_md_iovec_t);

	if (!md_handle)
		return PTL_SEGV;

	if (p3_api_process.init < 0)
		return PTL_NO_INIT;

	if (PTL_NI_INDEX(md.eq_handle) != if_idx)
		return PTL_MD_ILLEGAL;

	if (!(if_idx < PTL_MAX_INTERFACES && p3_api_process.ni[if_idx]))
		return PTL_ME_INVALID;

	if (md.options & PTL_MD_IOVEC) {
		iov_len = md.length * sizeof(ptl_md_iovec_t);
	}
	if (!(iov = p3_malloc(iov_len)))
		return PTL_NO_SPACE;

	if (md.options & PTL_MD_IOVEC) {
		ptl_size_t i;
		ptl_md_iovec_t *tmp_iov = md.start;
		for (i=0; i<md.length; i++) {
			iov[i].iov_base = tmp_iov[i].iov_base;
			iov[i].iov_len  = tmp_iov[i].iov_len;
		}
	}
	else {
		iov[0].iov_base = md.start;
		iov[0].iov_len = md.length;
	}

	request_lock_lock();
	status = p3_has_process_and_ni(me_handle, &ni);
	if (status != PTL_OK) {
		request_lock_unlock();
		return status;
	}
	
	status = lib_PtlMDAttach(ni, me_handle, md, iov, unlink_op, md_handle);
	request_lock_unlock();

	p3_free(iov);
	return status;
}

int PtlMDBind(ptl_handle_ni_t ni_handle,
	      ptl_md_t md,
	      ptl_unlink_t unlink_op,
	      ptl_handle_md_t *md_handle)
{
	int status;
	lib_ni_t *ni;
	ptl_md_iovec_t *iov;

	unsigned if_idx = PTL_NI_INDEX(ni_handle);
	int iov_len = sizeof(ptl_md_iovec_t);

	if (!md_handle)
		return PTL_SEGV;

	if (p3_api_process.init < 0)
		return PTL_NO_INIT;

	if (PTL_NI_INDEX(md.eq_handle) != if_idx)
		return PTL_MD_ILLEGAL;

	if (!(if_idx < PTL_MAX_INTERFACES && p3_api_process.ni[if_idx]))
		return PTL_NI_INVALID;

	if (md.options & PTL_MD_IOVEC) {
		iov_len = md.length * sizeof(ptl_md_iovec_t);
	}
	if (!(iov = p3_malloc(iov_len)))
		return PTL_NO_SPACE;

	if (md.options & PTL_MD_IOVEC) {
		ptl_size_t i;
		ptl_md_iovec_t *tmp_iov = md.start;
		for (i=0; i<md.length; i++) {
			iov[i].iov_base = tmp_iov[i].iov_base;
			iov[i].iov_len  = tmp_iov[i].iov_len;
		}
	}
	else {
		iov[0].iov_base = md.start;
		iov[0].iov_len = md.length;
	}

	request_lock_lock();
	status = p3_has_process_and_ni(ni_handle, &ni);
	if (status != PTL_OK) {
		request_lock_unlock();
		return status;
	}
	
	status = lib_PtlMDBind(ni, md, iov, unlink_op, md_handle);
	request_lock_unlock();
	
	p3_free(iov);
	return status;
}

int PtlMDUnlink(ptl_handle_md_t md_handle)
{
	int status;
	lib_ni_t *ni;

	if (p3_api_process.init < 0)
		return PTL_NO_INIT;

	if (!(PTL_NI_INDEX(md_handle) < PTL_MAX_INTERFACES &&
	      p3_api_process.ni[PTL_NI_INDEX(md_handle)]))
		return PTL_MD_INVALID;

	request_lock_lock();
	status = p3_has_process_and_ni(md_handle, &ni);
	if (status != PTL_OK) {
		request_lock_unlock();
		return status;
	}
	
	status = lib_PtlMDUnlink(ni, md_handle);
	request_lock_unlock();

	return status;
}

/* Note: if the user expects that the MD to be copied into *old_md will
 * contain an iovec, then old_md->start needs to point to enough memory
 * to hold the largest expected iovec, and old_md->length needs to be
 * how long the largest expected iovec can be, and old_md->options must
 * have PTL_MD_IOVEC set.
 */
int PtlMDUpdate(ptl_handle_md_t md_handle,
		ptl_md_t *old_md,
		ptl_md_t *new_md,
		ptl_handle_eq_t eq_handle)
{
	api_ni_t *ni;
	lib_ni_t *lib_ni;
	api_eq_t *eq;
	ptl_seq_t sequence = -1;
	int req_iov_len = sizeof(ptl_md_iovec_t);
	int res_iov_len = sizeof(ptl_md_iovec_t);
	int rc;
	int old_md_valid;
	int new_md_valid;
	ptl_md_iovec_t *req_iov;
	ptl_md_iovec_t *res_iov;
	ptl_md_t req_new_md;
	ptl_md_t res_old_md;

	if (p3_api_process.init < 0)
		return PTL_NO_INIT;

	if (!(PTL_NI_INDEX(md_handle) < PTL_MAX_INTERFACES &&
	      (ni = p3_api_process.ni[PTL_NI_INDEX(md_handle)])))
		return PTL_MD_INVALID;

	if (eq_handle != PTL_EQ_NONE) {
		if (!(VALID_PTL_OBJ(&ni->eq, eq_handle) &&
		      TST_OBJ(eq = GET_PTL_OBJ(&ni->eq,eq_handle),OBJ_INUSE)))
			return PTL_EQ_INVALID;
		sequence = eq->sequence;
	}
	if (new_md && new_md->options & PTL_MD_IOVEC)
		req_iov_len = new_md->length * sizeof(ptl_md_iovec_t);

	if (!(req_iov = p3_malloc(req_iov_len)))
		return PTL_NO_SPACE;


	if (old_md && old_md->options & PTL_MD_IOVEC)
		res_iov_len = old_md->length * sizeof(ptl_md_iovec_t);

	if (!(res_iov = p3_malloc(res_iov_len))) {
		p3_free(req_iov);
		return PTL_NO_SPACE;
	}

	if (old_md) {
		old_md_valid = 1;

		res_old_md = *old_md;
		if (old_md->options & PTL_MD_IOVEC) {
			res_old_md.options |= PTL_MD_IOVEC;
			res_old_md.length = old_md->length;
		}
	}
	else {
		old_md_valid = 0;
	}

	if (new_md) {
		new_md_valid = 1;
		req_new_md = *new_md;

		if (new_md->options & PTL_MD_IOVEC) {
			ptl_size_t i;
			ptl_md_iovec_t *iov = new_md->start;
			for (i=0; i<new_md->length; i++) {

				req_iov[i].iov_base = iov[i].iov_base;
				req_iov[i].iov_len = iov[i].iov_len;
			}
		}
		else {
			req_iov[0].iov_base = new_md->start;
			req_iov[0].iov_len = new_md->length;
		}
	}
	else {
		new_md_valid = 0;
	}
	
	request_lock_lock();
	rc = p3_has_process_and_ni(md_handle, &lib_ni);
	if (rc != PTL_OK) {
		request_lock_unlock();
		goto out;
	}
	
	rc = lib_PtlMDUpdate(lib_ni, md_handle, &res_old_md, &req_new_md, 
			eq_handle, old_md_valid, new_md_valid, sequence, req_iov, res_iov);
	request_lock_unlock();
	
	if (rc != PTL_OK) {
		goto out;
	}

	if (old_md) {
		ptl_md_iovec_t *old_iov = old_md->start;

		*old_md = res_old_md;

		if (res_old_md.options & PTL_MD_IOVEC) {
			int i = res_old_md.length;

			while (i--) {
				old_iov[i].iov_base = res_iov[i].iov_base;
				old_iov[i].iov_len  = res_iov[i].iov_len;
			}
		}
	}
out:
	p3_free(req_iov);
	p3_free(res_iov);
	return rc;
}
