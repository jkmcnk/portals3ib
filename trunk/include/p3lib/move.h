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

#ifndef MOVE_H_
#define MOVE_H_

#include <p3lib/types.h>

int lib_PtlPut(lib_ni_t *ni, 
		ptl_handle_md_t md_handle,
		ptl_ack_req_t ack_req,
		ptl_process_id_t target_id,
		ptl_pt_index_t pt_index,
		ptl_ac_index_t ac_index,
		ptl_match_bits_t match_bits,
		ptl_size_t remote_offset,
		ptl_hdr_data_t hdr_data,		
		ptl_size_t local_offset,
		ptl_size_t local_len,
		int region);


int lib_PtlGet(lib_ni_t *ni, 
		ptl_handle_md_t md_handle,
		ptl_process_id_t target_id,
		ptl_pt_index_t pt_index,
		ptl_ac_index_t ac_index,
		ptl_match_bits_t match_bits,
		ptl_size_t remote_offset,
		ptl_size_t local_offset,
		ptl_size_t local_len,
		int region);

int lib_PtlGetPut(lib_ni_t *ni, 
		ptl_handle_md_t get_md_handle, 
		ptl_handle_md_t put_md_handle,
		ptl_process_id_t target_id, 
		ptl_pt_index_t pt_index,
		ptl_ac_index_t ac_index, 
		ptl_match_bits_t match_bits,
		ptl_size_t remote_offset, 
		ptl_hdr_data_t hdr_data);

#endif /* MOVE_H_ */
