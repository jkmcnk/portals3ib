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

#ifndef _PTL3_API_NAL_H_
#define _PTL3_API_NAL_H_

struct api_nal;
typedef struct api_nal api_nal_t;

struct api_nal {
	void *private;
	ptl_interface_t type;
	const char* (*errstr)(api_nal_t *nal, ptl_ni_fail_t nal_errno);
};

typedef struct api_eq {
	struct list_head list;		/* eq free list */
	volatile ptl_seq_t sequence;
	ptl_seq_t entries;
	ptl_event_t *base;
	ptl_eq_handler_t eq_handler;
	uint32_t id;
} api_eq_t;

typedef struct api_eqtbl {
	api_eq_t **tbl;
	unsigned int inuse;		/* count of inuse objects in table */
	unsigned int next_row;		/* next free row */
	unsigned int num_rows;		/* number of rows allocated */
} api_eqtbl_t;

typedef struct api_ni {

	p3lock(obj_alloc);

	struct list_head free_eq;
	api_eqtbl_t eq;

	struct api_nal nal;
	ptl_ni_limits_t limits;

	uint32_t id;
} api_ni_t;

#endif /* _PTL3_API_NAL_H_ */
