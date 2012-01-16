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

#ifndef _PTL3_P3RT_DISPATCH_H_
#define _PTL3_P3RT_DISPATCH_H_

/* Call this from the library side of the forwarder to dispatch requests
 * to the P3RT library.
 */
extern 
void p3rt_dispatch(p3rt_req_t *request, p3rt_res_t *result);

extern 
char *p3rt_dispatch_name(int cid);

typedef struct p3rt_dispatch_table {
	void (*fun)(lib_ni_t *, p3rt_req_t *, p3rt_res_t *);
	char *name;
} p3rt_dispatch_table_t;

extern p3rt_dispatch_table_t p3rt_dispatch_table[];

extern void p3rt_PtlSetJID	(lib_ni_t *, p3rt_req_t *, p3rt_res_t *);
extern void p3rt_PtlSetRank	(lib_ni_t *, p3rt_req_t *, p3rt_res_t *);
extern void p3rt_PtlSetNIDMap	(lib_ni_t *, p3rt_req_t *, p3rt_res_t *);
extern void p3rt_PtlSetPIDMap	(lib_ni_t *, p3rt_req_t *, p3rt_res_t *);
extern void p3rt_PtlGetRank	(lib_ni_t *, p3rt_req_t *, p3rt_res_t *);
extern void p3rt_PtlGetRankId	(lib_ni_t *, p3rt_req_t *, p3rt_res_t *);
extern void p3rt_PtlGetNIDMap	(lib_ni_t *, p3rt_req_t *, p3rt_res_t *);
extern void p3rt_PtlGetPIDMap	(lib_ni_t *, p3rt_req_t *, p3rt_res_t *);

#endif /* _PTL3_P3RT_DISPATCH_H_ */
