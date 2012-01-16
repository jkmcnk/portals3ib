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

#include <p3api/types.h>
#include <p3api/debug.h>

#include <p3/errno.h>

#include <p3rt/p3rt.h>
#include <p3rt/forward.h>

#include <p3utils.h>

int PtlSetJID(ptl_jid_t jid)
{
	p3rt_req_t req = {P3RT_SET_JID, PTL_INVALID_HANDLE, };
	p3rt_res_t res = P3RT_RES_INIT;

	req.t.group.jid = jid;
	p3rt_forward(&req, sizeof(req), &res, sizeof(res));
	return res.status;
}

/* Parses a string of colon separated numbers and initializes either an 
 * array of nids or an array of pids; use to initialize nid, pid vs. rid maps.
 *
 * nmap != NULL && pmap == NULL => initialize nid map
 * nmap == NULL && pmap != NULL => initialize pid map
 *
 * returns PTL_OK on success.
 */
static 
int usrid_id_map(const char *mapname, const char *mapstr, 
		 ptl_nid_t **nmap, ptl_pid_t **pmap, unsigned *nnodes)
{
	int rtn = 0;
	unsigned i = 1;
	const char *ptr = mapstr;

	*nnodes = 0;
	if (nmap && *nmap || pmap && *pmap) {
		p3_print("usrid_id_map: map already allocated\n");
		rtn = PTL_FAIL;
		goto out;
	}
	while (*ptr) {
		if (i && *ptr == ':') ;
		else if (i) {
			i = 0;
			(*nnodes)++;
		}
		else if (*ptr == ':')
			i = 1;
		ptr++;
	}
	if (*nnodes <= 0) {
		rtn = PTL_FAIL;
		goto out;
	}
	i = 0;
	ptr = mapstr;

	if(nmap && !pmap) {
		*nmap = p3_malloc(*nnodes * sizeof(**nmap));
		if (!*nmap) {
			rtn = PTL_NO_SPACE;
			goto out;
		}
	}
	else if (pmap && !nmap) {
		*pmap = p3_malloc(*nnodes * sizeof(**pmap));
		if (!*pmap) {
			rtn = PTL_NO_SPACE;
			goto out;
		}
	}
	else {
		p3_print("init_id_map: invalid map type\n");
		rtn = PTL_FAIL;
		goto out;
	}
	while (*ptr) {
		char *c;
		while (*ptr == ':')
			ptr++;

		if(nmap && !pmap)
			(*nmap)[i] = strtoul(ptr, &c, 0);
		else if (pmap && !nmap)
			(*pmap)[i] = strtoul(ptr, &c, 0);

		if (++i == *nnodes) break;
		ptr = c;
	}
	if (i != *nnodes) {
		p3_print("Error reading %s map\n", mapname);
		rtn = PTL_FAIL;
	}
out:
	return rtn;
}

int PtlSetRank(ptl_handle_ni_t ni_handle,
	       unsigned rank, unsigned group_size)
{
	int err = PTL_OK;
	ptl_jid_t jid = PTL_JID_ANY;

	p3rt_req_t *req = NULL;
	p3rt_res_t res = P3RT_RES_INIT;
	unsigned reqlen = sizeof(*req);

	ptl_nid_t *nidmap = NULL;
	ptl_pid_t *pidmap = NULL;
	unsigned map_sz;

	if (rank == (unsigned)-1 && group_size == (unsigned)-1) {
		char *ev;

		if ((ev = getenv("PTL_MY_JID")))
			jid = strtoul(ev, NULL, 0);

		if (!(ev = getenv("PTL_MY_RID"))) {
			p3_print("Set PTL_MY_RID to specify rank.\n");
			err = PTL_NO_INIT;
			goto out;
		}
		rank = strtoul(ev, NULL, 0);

		if (!(ev = getenv("PTL_NIDMAP"))) {
			p3_print("Set PTL_NIDMAP to specify NID map.\n");
			err = PTL_NO_INIT;
			goto out;
		}
		err = usrid_id_map("PTL_NIDMAP", ev, &nidmap, NULL, &map_sz);
		if (err != PTL_OK)
			goto out;
		
		group_size = map_sz;

		if (!(ev = getenv("PTL_PIDMAP"))) {
			p3_print("Set PTL_PIDMAP to specify NID map.\n");
			err = PTL_NO_INIT;
			goto out;
		}
		err = usrid_id_map("PTL_PIDMAP", ev, NULL, &pidmap, &map_sz);
		if (err != PTL_OK)
			goto out;
		if (map_sz != group_size) {
			p3_print("Error: NID/PID map lengths differ.\n");
			err = PTL_FAIL;
			goto out;
		}
		if (!(rank < group_size)) {
			p3_print("Error: need rank < group_size.\n");
			err = PTL_FAIL;
			goto out;
		}
		reqlen += group_size * sizeof(ptl_process_id_t);
		req = p3_malloc(reqlen);
		if (!req) {
			err = PTL_NO_SPACE;
			goto out;
		}
		req->t.group.map_sz = group_size;
		for (map_sz = 0; map_sz < group_size; map_sz++) {
			req->t.group.map[map_sz].nid = nidmap[map_sz];
			req->t.group.map[map_sz].pid = pidmap[map_sz];
		}
	}
	else {
		req = p3_malloc(reqlen);
		if (!req)
			return PTL_NO_SPACE;
		req->t.group.map_sz = 0;
	}

	req->call_index = P3RT_SET_RANK;
	req->handle = ni_handle;
	req->t.group.jid = jid;
	req->t.group.rank = rank;
	req->t.group.size = group_size;

	p3rt_forward(req, reqlen, &res, sizeof(res));

	err = res.status;
out:
	if (nidmap)
		p3_free(nidmap);
	if (pidmap)
		p3_free(pidmap);
	if (req)
		p3_free(req);

	return err;
}

int PtlSetNIDMap(ptl_handle_ni_t ni_handle,
		 ptl_nid_t *map, unsigned group_size)
{
	unsigned i;
	int err = PTL_OK;

	p3rt_req_t *req = NULL;
	p3rt_res_t res = P3RT_RES_INIT;
	unsigned reqlen = sizeof(*req) + group_size * sizeof(ptl_nid_t);

	req = p3_malloc(reqlen);
	if (!req) {
		err = PTL_NO_SPACE;
		goto out;
	}
	for (i=0; i<group_size; i++)
		req->t.nidmap.map[i] = map[i];

	req->call_index = P3RT_SET_NIDMAP;
	req->handle = ni_handle;
	req->t.nidmap.size = group_size;

	p3rt_forward(req, reqlen, &res, sizeof(res));

	err = res.status;
	if (req)
		p3_free(req);
out:
	return err;
}

int PtlSetPIDMap(ptl_handle_ni_t ni_handle,
		 ptl_pid_t *map, unsigned group_size)
{
	unsigned i;
	int err = PTL_OK;

	p3rt_req_t *req = NULL;
	p3rt_res_t res = P3RT_RES_INIT;
	unsigned reqlen = sizeof(*req) + group_size * sizeof(ptl_pid_t);

	req = p3_malloc(reqlen);
	if (!req) {
		err = PTL_NO_SPACE;
		goto out;
	}
	for (i=0; i<group_size; i++)
		req->t.pidmap.map[i] = map[i];

	req->call_index = P3RT_SET_PIDMAP;
	req->handle = ni_handle;
	req->t.pidmap.size = group_size;

	p3rt_forward(req, reqlen, &res, sizeof(res));

	err = res.status;
	if (req)
		p3_free(req);
out:
	return err;
}

int PtlGetRank(ptl_handle_ni_t ni_handle,
	       unsigned *rank, unsigned *size)
{
	p3rt_req_t req = {P3RT_GET_RANK, ni_handle, };
	p3rt_res_t res = P3RT_RES_INIT;

	if (!(rank && size))
		return PTL_SEGV;

	p3rt_forward(&req, sizeof(req), &res, sizeof(res));

	if (res.status == PTL_OK) {
		*rank = res.t.group.rank;
		*size = res.t.group.size;
	}
	return res.status;
}

int PtlGetRankId(ptl_handle_ni_t ni_handle,
		 unsigned rank, ptl_process_id_t *id)
{
	p3rt_req_t req = {P3RT_GET_PPID, ni_handle, };
	p3rt_res_t res = P3RT_RES_INIT;

	if (!id)
		return PTL_SEGV;

	req.t.group.rank = rank;
	p3rt_forward(&req, sizeof(req), &res, sizeof(res));

	if (res.status == PTL_OK)
		*id = res.t.id.id;
	return res.status;
}

int PtlGetNIDMap(ptl_handle_ni_t ni_handle,
		 ptl_nid_t *map, unsigned group_size)
{
	p3rt_req_t req = {P3RT_GET_NIDMAP, ni_handle, };
	p3rt_res_t *res;
	int res_len = sizeof(*res);
	int rc;

	if (!map)
		return PTL_SEGV;

	req.t.nidmap.size = group_size;

	res_len += group_size * sizeof(ptl_nid_t);
	if (!(res = p3_malloc(res_len)))
		return PTL_NO_SPACE;

	p3rt_init_res(res);
		
	p3rt_forward(&req, sizeof(req), res, res_len);
	rc = res->status;

	if (rc == PTL_OK) {
		unsigned i;
		for (i=0; i<group_size; i++)
			map[i] = res->t.nidmap.map[i];
	}
	p3_free(res);
	return rc;
}

int PtlGetPIDMap(ptl_handle_ni_t ni_handle,
		 ptl_pid_t *map, unsigned group_size)
{
	p3rt_req_t req = {P3RT_GET_PIDMAP, ni_handle, };
	p3rt_res_t *res;
	int res_len = sizeof(*res);
	int rc;

	if (!map)
		return PTL_SEGV;

	req.t.pidmap.size = group_size;

	res_len += group_size * sizeof(ptl_pid_t);
	if (!(res = p3_malloc(res_len)))
		return PTL_NO_SPACE;
		
	p3rt_init_res(res);

	p3rt_forward(&req, sizeof(req), res, res_len);
	rc = res->status;

	if (rc == PTL_OK) {
		unsigned i;
		for (i=0; i<group_size; i++)
			map[i] = res->t.pidmap.map[i];
	}
	p3_free(res);
	return rc;
}
