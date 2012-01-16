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

#ifndef _PTL3_P3_PROCESS_H_
#define _PTL3_P3_PROCESS_H_

#ifdef ENABLE_P3RT_SUPPORT
#include <p3rt/types.h>
#endif

/* Hold lib_update lock to modify any pp_process instance.
 */
typedef struct p3_process {

	int init;	/* interface count, or -1 if PtlInit not called. */

	ptl_jid_t jid;
	void *ni[PTL_MAX_INTERFACES];	/* interfaces for this process */

#ifdef ENABLE_P3RT_SUPPORT
	/* We use this to hold group data which was initialized between
	 * calls to PtlInit() and PtlNIInit(), for use by the next call to
	 * PtlNIInit().
	 */
	rt_group_data_t *next_group;
#endif
	unsigned int debug;
} p3_process_t;

#endif /* _PTL3_P3_PROCESS_H_ */
