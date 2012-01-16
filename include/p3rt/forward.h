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

#ifndef _PTL3_P3RT_FORWARD_H_
#define _PTL3_P3RT_FORWARD_H_

/* Here we associate the index of each function in the library dispatch
 * table with the corresponding function name, which will be prefixed
 * with "lib_".   e.g. PTL_GETID is the index for the function do_PtlGetId.
 */
#define P3RT_LIB_DISPATCH					\
P3RT_DISPATCH_ENTRY(P3RT_SET_JID ,	PtlSetJID),		\
P3RT_DISPATCH_ENTRY(P3RT_SET_RANK ,	PtlSetRank),		\
P3RT_DISPATCH_ENTRY(P3RT_SET_NIDMAP ,	PtlSetNIDMap),		\
P3RT_DISPATCH_ENTRY(P3RT_SET_PIDMAP ,	PtlSetPIDMap),		\
P3RT_DISPATCH_ENTRY(P3RT_GET_RANK ,	PtlGetRank),		\
P3RT_DISPATCH_ENTRY(P3RT_GET_PPID ,	PtlGetRankId),		\
P3RT_DISPATCH_ENTRY(P3RT_GET_NIDMAP ,	PtlGetNIDMap),		\
P3RT_DISPATCH_ENTRY(P3RT_GET_PIDMAP ,	PtlGetPIDMap)


/* assign indices for functions in the dispatch table.
 * P3RT_MAX_DISPATCH gives the number of entries in the dispatch table
 */
#define P3RT_DISPATCH_ENTRY(fcn_id,fcn) fcn_id

enum { P3RT_LIB_DISPATCH, P3RT_MAX_DISPATCH };

#undef P3RT_DISPATCH_ENTRY


struct p3rt_req {

	/* Index into Portals runtime library request dispatch function table
	 */
	unsigned call_index;

	/* Request functions need to reference at least one interface
	 * object.
	 */
	ptl_handle_ni_t handle;

	union {					/* variable length, so last */

		struct {
			ptl_jid_t jid;
			unsigned rank;
			unsigned size;
			unsigned map_sz;
			ptl_process_id_t map[1];/* variable length, so last */
		} group;

		struct {
			unsigned size;
			ptl_nid_t map[1];	/* variable length, so last */
		} nidmap;

		struct {
			unsigned size;
			ptl_pid_t map[1];	/* variable length, so last */
		} pidmap;
	} t;
};

typedef struct p3rt_req p3rt_req_t;

#define P3RT_REQ_INIT P3RT_MAX_DISPATCH, PTL_INVALID_HANDLE, }
#define p3rt_init_req(req)	\
do {				\
	memset(req, 0, sizeof(p3_libreq_t));	\
	req->call_index = P3RT_MAX_DISPATCH;	\
	req->handle = PTL_INVALID_HANDLE;	\
} while (0)


struct p3rt_res {

	int status;

	union {
		struct {
			ptl_process_id_t id;
		} id;

		struct {
			unsigned rank;
			unsigned size;
		} group;

		struct {
			unsigned size;
			ptl_nid_t map[1];	/* variable length, so last */
		} nidmap;

		struct {
			unsigned size;
			ptl_pid_t map[1];	/* variable length, so last */
		} pidmap;
	} t;
};

typedef struct p3rt_res p3rt_res_t;

#define P3RT_RES_INIT {PTL_FAIL,  }
#define p3rt_init_res(res)	\
do {				\
	memset(res, 0, sizeof(p3rt_res_t));	\
	res->status = PTL_FAIL;			\
} while (0)

typedef struct p3rt_forward {
	void *request;
	void *result;
	size_t req_len;
	size_t res_len;
} p3rt_forward_t;


/* Call this to forward a request to the Portals3 library.  Since some
 * of the requests and replies contain an iovec, they can be varible-sized,
 * and we need a length for each.
 */
extern
void p3rt_forward(void *request, size_t reqlen, void *result, size_t reslen);

#endif /* _PTL3_P3RT_FORWARD_H_ */
