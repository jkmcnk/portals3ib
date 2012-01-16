/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the version 2 of the GNU General Public License
 *   as published by the Free Software Foundation.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU Lesser General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
/* Copyright 2008-2011 NEC Deutschland GmbH, NEC HPC Europe */

#ifndef NI_H_
#define NI_H_

#include <p3lib/types.h>

int lib_PtlNIInit(lib_ni_t *ni, 
		ptl_interface_t iface, 
		ptl_pid_t req_pid,
		ptl_ni_limits_t *desired,
		size_t data_sz,
		void *data,
		ptl_ni_limits_t *actual,
		ptl_handle_ni_t *ni_handle);

void lib_PtlNIFini(lib_ni_t *ni);

int lib_PtlNIDebug(lib_ni_t *ni,  
		unsigned int new_mask,
		unsigned int *old_mask);

int lib_PtlNIStatus(lib_ni_t *ni,
		ptl_sr_index_t register_index,
		ptl_sr_value_t *status);

int lib_PtlNIDist(lib_ni_t *ni, 
		ptl_nid_t nid,
		unsigned long *distance);

int lib_PtlProgress(lib_ni_t *ni, ptl_time_t timeout);

#endif /* NI_H_ */
