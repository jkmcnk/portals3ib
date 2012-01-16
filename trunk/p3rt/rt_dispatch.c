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

#include <unistd.h>
#include <limits.h>

/* If compiling for user-space (and maybe NIC-space), these need to be
 * the Portals3 versions of the Linux kernel include files, which
 * have been suitably modified for use in user-space code.
 */
#include <linux/list.h>

/* These are all Portals3 include files.
 */
#include <p3utils.h>

#include <p3api/types.h>
#include <p3api/debug.h>

#include <p3/lock.h>
#include <p3/handle.h>
#include <p3/process.h>
#include <p3/errno.h>
#include <p3/debug.h>

#include <p3lib/types.h>
#include <p3lib/p3lib.h>
#include <p3lib/nal.h>
#include <p3lib/p3lib_support.h>

#include <p3rt/forward.h>
#include <p3rt/dispatch.h>

#define P3RT_DISPATCH_ENTRY(fcn_id,fcn) {p3rt_##fcn, #fcn}

p3rt_dispatch_table_t p3rt_dispatch_table[] =
{
	P3RT_LIB_DISPATCH,
	{NULL, ""}
};

#undef P3RT_DISPATCH_ENTRY

void
p3rt_dispatch(p3rt_req_t *req, p3rt_res_t *res)
{
	lib_ni_t *ni = NULL;
	unsigned cid = req->call_index;
	unsigned i = PTL_NI_INDEX(req->handle);
	p3_process_t *pp = p3lib_cur_process();

	if (!pp || pp->init < 0) {
		res->status = PTL_NO_INIT;
		return;
	}
	if (cid > P3RT_MAX_DISPATCH || !p3rt_dispatch_table[cid].fun) {
		res->status = PTL_FAIL;
		return;
	}
	/* We are specifically allowed to call the set functions before
	 * PtlNIInit.
	 */
	if (!(((req->handle == PTL_INVALID_HANDLE) &&
	       (cid == P3RT_SET_JID || cid == P3RT_SET_RANK ||
		cid == P3RT_SET_NIDMAP || cid == P3RT_SET_PIDMAP)) ||
	      (i < PTL_MAX_INTERFACES && (ni = pp->ni[i])))) {
		res->status = PTL_HANDLE_INVALID;
		return;
	}
	if (ni) {
		p3_lock(&ni->obj_alloc);
		if (!TST_OBJ(ni, OBJ_INUSE))
			res->status = PTL_HANDLE_INVALID;
		p3_unlock(&ni->obj_alloc);

		if (DEBUG_P3(ni->debug, PTL_DBG_API))
			p3_print("p3rt_dispatch:"FMT_NIDPID
				 ": RT call %s (index %d)\n", ni->nid, ni->pid,
				 p3rt_dispatch_name(cid), cid);
	}
	if (res->status != PTL_HANDLE_INVALID)
		p3rt_dispatch_table[cid].fun(ni, req, res);
}

char *p3rt_dispatch_name(int cid)
{
	return p3rt_dispatch_table[cid].name;
}
