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

#ifndef _PTL3_RT_P3RT_H_
#define _PTL3_RT_P3RT_H_

/* Use PtlSetRank to set the job size and process rank in the job.  
 * If called with rank and size set to -1, PtlSetRank causes the rank,
 * job size, and NID/PID maps to be initialized from the following 
 * environment variables:
 *
 *   PTL_MY_RID - Specifies my rid.  If not present, the rid value is
 *	set to (unsigned)-1, and the job size is set to zero.
 *   PTL_NIDMAP - Ordered list of nids for processes in my n-node group,
 *	for rid 0 -> n-1, colon separated.  Daemons don't need this.
 *   PTL_PIDMAP - Ordered list of pids for processes in my n-node group,
 *	for rid 0 -> n-1, colon separated.  Daemons don't need this.
 *
 * PtlSetRank returns PTL_OK on success.
 */
int PtlSetRank(ptl_handle_ni_t ni, unsigned rank, unsigned group_size);

/* Use PtlSetNIDMap/PtlSetPIDMap to initialize NID/PID maps for this
 * process.  PtlSetRank must have been called first with rank != -1,
 * size != -1.
 *
 * group_size is the number of map entries, and must be the same value as
 * the group_size parameter passed via PtlSetRank.
 *
 * Both return PTL_OK on success.
 */
int PtlSetNIDMap(ptl_handle_ni_t ni, ptl_nid_t *map, unsigned group_size);
int PtlSetPIDMap(ptl_handle_ni_t ni, ptl_pid_t *map, unsigned group_size);

/* Returns PTL_OK on success, PTL_SEGV if a passed invalid memory, and
 * PTL_FAIL otherwise.
 */
int PtlGetRank(ptl_handle_ni_t ni, unsigned *rank, unsigned *group_size);
int PtlGetRankId(ptl_handle_ni_t ni, unsigned rank, ptl_process_id_t *id);

/* Use PtlSetNIDMap/PtlSetPIDMap to query NID/PID maps for this
 * process.
 *
 * group_size is the number of map entries, and must be the same value as
 * the group_size parameter queried via PtlGetRank.  map must point to 
 * buffer large enough to hold group_size entries.
 *
 * Both return PTL_OK on success.
 */
int PtlGetNIDMap(ptl_handle_ni_t ni, ptl_nid_t *map, unsigned group_size);
int PtlGetPIDMap(ptl_handle_ni_t ni, ptl_pid_t *map, unsigned group_size);

#endif /* _PTL3_RT_P3RT_H_ */
