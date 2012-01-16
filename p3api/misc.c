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

#include <p3/lock.h>

#include <p3api/types.h>
#include <p3api/nal.h>
#include <p3api/misc.h>
#include <p3api/debug.h>

#include <p3/handle.h>
#include <p3/process.h>
#include <p3/obj_alloc.h>
#include <p3/errno.h>

#include "init.h"

/* This function to return an error string for a Portals error number
 * isn't part of the spec, but it should be.
 */
const char *PtlErrorStr(unsigned ptl_errno)
{
	if (ptl_errno >= PTL_OK &&
	    ptl_errno <= PTL_UNKNOWN_ERROR)
		return ptl_err_str[ptl_errno];
	else
		return ptl_err_str[PTL_UNKNOWN_ERROR];
}

/* This function to return an error string for a network interface
 * error number isn't part of the spec, but it should be.
 */
const char *PtlNIFailStr(ptl_handle_ni_t ni_handle, ptl_ni_fail_t nal_errno)
{
	const char *err = "PTL_NI_UNKNOWN_ERROR";

	api_ni_t *ni;
	unsigned if_idx = PTL_NI_INDEX(ni_handle);

	if (!(p3_api_process.init >= 0 &&
	      if_idx < PTL_MAX_INTERFACES && (ni = p3_api_process.ni[if_idx])))
		goto out;

	if (nal_errno == PTL_NI_OK)
		err = "PTL_NI_OK";
	else if (nal_errno == PTL_NI_FAIL)
		err = "PTL_NI_FAIL";
	else if (ni->nal.errstr)
		err = ni->nal.errstr(&ni->nal, nal_errno);

out:
	return err;
}

/* This function to return an event type string for a Portals event
 * type isn't part of the spec, but it should be.
 */
const char *PtlEventKindStr(ptl_event_kind_t ev_kind)
{
	static const char *eks[] = {
		"PTL_EVENT_GET_START",
		"PTL_EVENT_GET_END",
		"PTL_EVENT_PUT_START",
		"PTL_EVENT_PUT_END",
		"PTL_EVENT_GETPUT_START",
		"PTL_EVENT_GETPUT_END",
		"PTL_EVENT_REPLY_START",
		"PTL_EVENT_REPLY_END",
		"PTL_EVENT_SEND_START",
		"PTL_EVENT_SEND_END",
		"PTL_EVENT_ACK",
		"PTL_EVENT_UNLINK"
	};
	if (ev_kind >= PTL_EVENT_GET_START && ev_kind <= PTL_EVENT_UNLINK)
		return eks[ev_kind];
	else
		return "PTL_UNKNOWN_EVENT_KIND";
}
