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

#include <p3lib/move.h>
#include <p3lib/ni.h>
#include <p3lib/p3lib_support.h>

#include "init.h"
#include "request_lock.h"

int PtlPut(ptl_handle_md_t md_handle,
	   ptl_ack_req_t ack_req,
	   ptl_process_id_t target_id,
	   ptl_pt_index_t pt_index,
	   ptl_ac_index_t ac_index,
	   ptl_match_bits_t match_bits,
	   ptl_size_t remote_offset,
	   ptl_hdr_data_t hdr_data)
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
	
	status = lib_PtlPut(ni, md_handle, ack_req, target_id, pt_index, ac_index,
		match_bits, remote_offset, hdr_data, 0, (ptl_size_t)-1, 0);
	request_lock_unlock();

	return status;
}

int PtlPutRegion(ptl_handle_md_t md_handle,
		 ptl_size_t local_offset,
		 ptl_size_t length,
		 ptl_ack_req_t ack_req,
		 ptl_process_id_t target_id,
		 ptl_pt_index_t pt_index,
		 ptl_ac_index_t ac_index,
		 ptl_match_bits_t match_bits,
		 ptl_size_t remote_offset,
		 ptl_hdr_data_t hdr_data)
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
	
	status = lib_PtlPut(ni, md_handle, ack_req, target_id, pt_index, ac_index,
		match_bits, remote_offset, hdr_data, local_offset, length, 1);
	request_lock_unlock();

	return status;
}

int PtlGet(ptl_handle_md_t md_handle,
	   ptl_process_id_t target_id,
	   ptl_pt_index_t pt_index,
	   ptl_ac_index_t ac_index,
	   ptl_match_bits_t match_bits,
	   ptl_size_t remote_offset)
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
	
	status = lib_PtlGet(ni, md_handle, target_id, pt_index, ac_index,
		match_bits, remote_offset, 0, (ptl_size_t)-1, 0);
	request_lock_unlock();
	
	return status;
}

int PtlGetRegion(ptl_handle_md_t md_handle,
		 ptl_size_t local_offset,
		 ptl_size_t length,
		 ptl_process_id_t target_id,
		 ptl_pt_index_t pt_index,
		 ptl_ac_index_t ac_index,
		 ptl_match_bits_t match_bits,
		 ptl_size_t remote_offset)
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

	status = lib_PtlGet(ni, md_handle, target_id, pt_index, ac_index,
		match_bits, remote_offset, local_offset, length, 1);
	request_lock_unlock();
	
	return status;
}

int PtlGetPut(ptl_handle_md_t get_md_handle, 
	      ptl_handle_md_t put_md_handle,
	      ptl_process_id_t target_id, 
	      ptl_pt_index_t pt_index,
	      ptl_ac_index_t ac_index, 
	      ptl_match_bits_t match_bits,
	      ptl_size_t remote_offset, 
	      ptl_hdr_data_t hdr_data)
{
	int status;
	lib_ni_t *ni;

	if (p3_api_process.init < 0)
		return PTL_NO_INIT;

	if (!(PTL_NI_INDEX(get_md_handle) < PTL_MAX_INTERFACES &&
	      p3_api_process.ni[PTL_NI_INDEX(get_md_handle)]))
		return PTL_MD_INVALID;

	if (PTL_NI_INDEX(put_md_handle) != PTL_NI_INDEX(get_md_handle))
		return PTL_MD_ILLEGAL;

	request_lock_lock();
	status = p3_has_process_and_ni(get_md_handle, &ni);
	if (status != PTL_OK) {
		request_lock_unlock();
		return status;
	}
	
	status = lib_PtlGetPut(ni, get_md_handle, put_md_handle, target_id, 
		pt_index, ac_index, match_bits, remote_offset, hdr_data);
	request_lock_unlock();
	
	return status;
}

/*
 * This function isn't part of the spec, but it should be.  An implementation
 * that has no progress thread anywhere (i.e. there is no NIC, kernel, or
 * user-space thread that can independently make progress) needs this
 * function to force progress to be made on outstanding messages.
 *
 * Anyway, we use it internally, but a library user needs to know it is
 * here to access it.  Also, a library user would only need it if not
 * using events at all.
 */
int PtlProgress(ptl_handle_any_t handle, ptl_time_t timeout)
{
	int status;
	lib_ni_t *ni;
	
	if (p3_api_process.init < 0)
		return PTL_NO_INIT;

	if (!(PTL_NI_INDEX(handle) < PTL_MAX_INTERFACES &&
	      p3_api_process.ni[PTL_NI_INDEX(handle)]))
		return PTL_NI_INVALID;	
	
	request_lock_lock();
	status = p3_has_process_and_ni(handle, &ni);
	if (status != PTL_OK) {
		request_lock_unlock();
		return status;
	}
	
	status = lib_PtlProgress(ni, timeout);
	request_lock_unlock();
	
	return status;
}
