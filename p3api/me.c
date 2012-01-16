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

#include <p3lib/me.h>
#include <p3lib/p3lib_support.h>

#include "init.h"
#include "request_lock.h"


int PtlMEAttach(ptl_handle_ni_t ni_handle,
		ptl_pt_index_t pt_index,
		ptl_process_id_t match_id,
		ptl_match_bits_t match_bits,
		ptl_match_bits_t ignore_bits,
		ptl_unlink_t unlink,
		ptl_ins_pos_t position,
		ptl_handle_me_t *me_handle)
{
	int status;
	lib_ni_t *ni;
	
	if (!me_handle)
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
	
	status = lib_PtlMEAttach(ni, pt_index, match_id, match_bits, ignore_bits,
			unlink, position, me_handle);
	request_lock_unlock();

	return status;
}

int PtlMEAttachAny(ptl_handle_ni_t ni_handle,
		   ptl_pt_index_t *pt_index,
		   ptl_process_id_t match_id,
		   ptl_match_bits_t match_bits,
		   ptl_match_bits_t ignore_bits,
		   ptl_unlink_t unlink,
		   ptl_handle_me_t *me_handle)
{
	int status;
	lib_ni_t *ni;

	if (!(me_handle && pt_index))
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
	
	status = lib_PtlMEAttachAny(ni, pt_index, match_id, match_bits, 
			ignore_bits, unlink, me_handle);
	request_lock_unlock();

	return status;
}

int PtlMEInsert(ptl_handle_me_t base,
		ptl_process_id_t match_id,
		ptl_match_bits_t match_bits,
		ptl_match_bits_t ignore_bits,
		ptl_unlink_t unlink,
		ptl_ins_pos_t position,
		ptl_handle_me_t *me_handle)
{
	int status;
	lib_ni_t *ni;

	if (!me_handle)
		return PTL_SEGV;

	if (p3_api_process.init < 0)
		return PTL_NO_INIT;

	if (!(PTL_NI_INDEX(base) < PTL_MAX_INTERFACES &&
	      p3_api_process.ni[PTL_NI_INDEX(base)]))
		return PTL_ME_INVALID;	
	
	request_lock_lock();
	status = p3_has_process_and_ni(base, &ni);
	if (status != PTL_OK) {
		request_lock_unlock();
		return status;
	}
	
	status = lib_PtlMEInsert(ni, base, match_id, match_bits, ignore_bits,
		unlink, position, me_handle);
	request_lock_unlock();

	return status;
}

int PtlMEUnlink(ptl_handle_me_t me_handle)
{
	int status;
	lib_ni_t *ni;
	
	if (p3_api_process.init < 0)
		return PTL_NO_INIT;

	if (!(PTL_NI_INDEX(me_handle) < PTL_MAX_INTERFACES &&
	      p3_api_process.ni[PTL_NI_INDEX(me_handle)]))
		return PTL_ME_INVALID;	
	
	request_lock_lock();
	status = p3_has_process_and_ni(me_handle, &ni);
	if (status != PTL_OK) {
		request_lock_unlock();
		return status;
	}
	
	status = lib_PtlMEUnlink(ni, me_handle);
	request_lock_unlock();

	return status;
}

/* This function isn't part of the spec. See p3api/debug.h for an explanation.
 */
int PtlMEDump(ptl_handle_me_t me_handle)
{
	int status;
	lib_ni_t *ni;

	if (p3_api_process.init < 0)
		return PTL_NO_INIT;

	if (!(PTL_NI_INDEX(me_handle) < PTL_MAX_INTERFACES &&
	      p3_api_process.ni[PTL_NI_INDEX(me_handle)]))
		return PTL_ME_INVALID;

	request_lock_lock();
	status = p3_has_process_and_ni(me_handle, &ni);
	if (status != PTL_OK) {
		request_lock_unlock();
		return status;
	}
	
	status = lib_PtlMEDump(ni, me_handle);
	request_lock_unlock();

	return status;
}

/*
 * [http://www.nccs.gov/wp-content/uploads/2007/08/pagel_paper.pdf]
 * Portals API extensions
 *
 * This change extended the Portals API by three new entry
 * points. These new functions are called PtlMEMDPost, PtlMEMDInsert,
 * and PtlMEMDAttach.  All three of these functions are essentially
 * amalgams of already existing Portals functions. The first of these
 * (PtlMEMDPost) essentially combines the actions of PtlMEInsert,
 * PtlMDAttach, and PtlMDUpdate. This particular sequence is used for
 * posting an MPI receive.  The combination replaces three distinct
 * system calls with one, thereby reducing the overall cost. This
 * change was added in the 1.4.28 and 1.5.07 XT releases.
 */
int PtlMEMDPost(ptl_handle_ni_t ni_handle,	/* ?unused? MEAttach ?*/
		ptl_handle_me_t base,		/* input MEInsert */
		ptl_process_id_t match_id,	/* input MEInsert */
		ptl_match_bits_t match_bits,	/* input MEInsert */
		ptl_match_bits_t ignore_bits,	/* input MEInsert */
		ptl_unlink_t unlink,		/* input MEInsert */
		ptl_ins_pos_t position,		/* input MEInsert */
		ptl_md_t md,			/* input MDAttach,
						   input MDUpdate? */
		ptl_unlink_t unlink_op, 	/* input MDAttach */
		ptl_handle_me_t *me_handle,	/* output MEInsert,
						   input MDAttach */
		ptl_handle_md_t *md_handle,	/* output MDAttach */
		ptl_handle_eq_t eq_handle	/* input MDUpdate */ )
{
	int ret;

	ret = PtlMEInsert(base, match_id, match_bits, ignore_bits,
			  unlink, position, me_handle);

	if (ret != PTL_OK)
		return ret;

	ret = PtlMDAttach(*me_handle, md, unlink_op, md_handle);
	if (ret == PTL_ME_IN_USE)
		ret = PtlMDUpdate(*md_handle, NULL, &md, eq_handle);

	return ret;
}

