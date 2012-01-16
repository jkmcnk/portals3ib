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

#include <p3/obj_alloc.h>	/* MUST come after p3lib/p3lib.h */

#include <p3rt/types.h>
#include <p3rt/forward.h>

void p3rt_PtlSetJID(lib_ni_t *ni, p3rt_req_t *req, p3rt_res_t *res)
{
	p3_process_t *pp;

	p3_lock(&lib_update);

	pp = __p3lib_cur_process();	/* ni is allowed to be NULL */
	pp->jid = req->t.group.jid;

	p3_unlock(&lib_update);

	res->status = PTL_OK;
}

/* Call with lib_update lock held.
 */
static
rt_group_data_t *__rt_group_struct(lib_ni_t *ni, 
				   p3rt_req_t *req, p3rt_res_t *res)
{
	rt_group_data_t **grp;

	grp = ni ? 
		&ni->group :
		&(__p3lib_cur_process())->next_group;

	if (!*grp) {
		unsigned sz =
			sizeof(rt_group_data_t)
			+ req->t.group.map_sz * sizeof(ptl_process_id_t);

		if ((*grp = p3_malloc(sz))) {
			memset(*grp, 0, sz);
			(*grp)->rd_size = req->t.group.map_sz;
			(*grp)->rd_rid = (ptl_rid_t)-1;
		}
	}
	return *grp;
}

void p3rt_PtlSetRank(lib_ni_t *ni, p3rt_req_t *req, p3rt_res_t *res)
{
	rt_group_data_t *grp;

	p3_lock(&lib_update);

	grp = __rt_group_struct(ni, req, res);
	if (grp == NULL) {
		res->status = PTL_NO_SPACE;
		goto out_unlock;
	}
	if (req->t.group.map_sz) {
		unsigned i;
		if (grp->nmap_init ||
		    grp->rd_size != req->t.group.map_sz ||
		    req->t.group.size != req->t.group.map_sz) {
			res->status = PTL_FAIL;
			goto out_unlock;
		}
		if (grp->pmap_init) {
			res->status = PTL_PID_INVALID;
			goto out_unlock;
		}
		for (i=0; i<req->t.group.map_sz; i++)
			grp->rd_map[i] = req->t.group.map[i];

		grp->nmap_init = grp->pmap_init = 1;
	}
	grp->rd_rid = req->t.group.rank;
	grp->rd_size = req->t.group.size;
	res->status = PTL_OK;
out_unlock:
	p3_unlock(&lib_update);
}


void p3rt_PtlSetNIDMap(lib_ni_t *ni, p3rt_req_t *req, p3rt_res_t *res)
{
	rt_group_data_t *grp;

	p3_lock(&lib_update);

	grp = __rt_group_struct(ni, req, res);
	if (!grp) {
		res->status = PTL_NO_SPACE;
		goto out_unlock;
	}
	if (req->t.nidmap.size) {
		unsigned i;
		if (grp->nmap_init ||
		    grp->rd_size != req->t.nidmap.size) {
			res->status = PTL_FAIL;
			goto out_unlock;
		}
		for (i=0; i<req->t.nidmap.size; i++)
			grp->rd_map[i].nid = req->t.nidmap.map[i];

		grp->nmap_init = 1;
	}
	res->status = PTL_OK;
out_unlock:
	p3_unlock(&lib_update);
}

void p3rt_PtlSetPIDMap(lib_ni_t *ni, p3rt_req_t *req, p3rt_res_t *res)
{
	rt_group_data_t *grp;

	p3_lock(&lib_update);

	grp = __rt_group_struct(ni, req, res);
	if (!grp) {
		res->status = PTL_NO_SPACE;
		goto out_unlock;
	}
	if (req->t.pidmap.size) {
		unsigned i;
		if (grp->pmap_init ||
		    grp->rd_size != req->t.pidmap.size) {
			res->status = PTL_PID_INVALID;
			goto out_unlock;
		}
		for (i=0; i<req->t.pidmap.size; i++)
			grp->rd_map[i].pid = req->t.pidmap.map[i];

		grp->pmap_init = 1;
	}
	res->status = PTL_OK;
out_unlock:
	p3_unlock(&lib_update);
}

void p3rt_PtlGetRank(lib_ni_t *ni, p3rt_req_t *req, p3rt_res_t *res)
{
	if (ni->group) {
		res->t.group.rank = ni->group->rd_rid;
		res->t.group.size = ni->group->rd_size;
		res->status = PTL_OK;
	}
	else
		res->status = PTL_NO_INIT;
}

void p3rt_PtlGetNIDMap(lib_ni_t *ni, p3rt_req_t *req, p3rt_res_t *res)
{
	rt_group_data_t *grp = ni->group;
	ptl_nid_t *map = res->t.nidmap.map;
	unsigned i;

	if (!(grp && grp->pmap_init)) {
		res->status = PTL_NO_INIT;
		goto out;
	}
	if (grp->rd_size != req->t.nidmap.size) {
		res->status = PTL_FAIL;
		goto out;
	}
	for (i=0; i<grp->rd_size; i++) 
		map[i] = grp->rd_map[i].nid;

	res->status = PTL_OK;
out:
	return;
}

void p3rt_PtlGetPIDMap(lib_ni_t *ni, p3rt_req_t *req, p3rt_res_t *res)
{
	rt_group_data_t *grp = ni->group;
	ptl_pid_t *map = res->t.pidmap.map;
	unsigned i;

	if (!(grp && grp->pmap_init)) {
		res->status = PTL_NO_INIT;
		goto out;
	}
	if (grp->rd_size != req->t.pidmap.size) {
		res->status = PTL_FAIL;
		goto out;
	}
	for (i=0; i<grp->rd_size; i++) 
		map[i] = grp->rd_map[i].pid;

	res->status = PTL_OK;
out:
	return;
}

void p3rt_PtlGetRankId(lib_ni_t *ni, p3rt_req_t *req, p3rt_res_t *res)
{
	if (ni->group &&
	    req->t.group.rank < ni->group->rd_size) {

       		res->t.id.id = ni->group->rd_map[req->t.group.rank];
		res->status = PTL_OK;
	}
	else
		res->status = PTL_NO_INIT;
}

/* Call with lib_update lock held.
 */
ptl_pid_t p3rt_runtime_pid()
{
	rt_group_data_t *grp;
	p3_process_t *pp = __p3lib_cur_process();

	if (!(pp && (grp = pp->next_group)) ||
	    grp->rd_rid == (ptl_rid_t)-1)
		return PTL_PID_ANY;

	return grp->rd_map[grp->rd_rid].pid;
}
