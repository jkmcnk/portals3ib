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

#ifndef _PTL3_API_H_
#define _PTL3_API_H_

/*
 * Note:
 * The only function prototypes appearing in this file are those
 * described in the Portals 3.3 API specification document, or are
 * implementation extensions specifically mentioned therein.
 */

/*
 * P3.3 API spec: section 3.4
 */
int PtlInit(int *max_interfaces);
void PtlFini(void);

/*
 * P3.3 API spec: section 3.5
 */
int PtlNIInit(ptl_interface_t interface, ptl_pid_t pid,
	      ptl_ni_limits_t *desired, ptl_ni_limits_t *actual,
	      ptl_handle_ni_t *ni_handle);

int PtlNIFini(ptl_handle_ni_t ni_handle);

int PtlNIStatus(ptl_handle_ni_t ni_handle, ptl_sr_index_t register_index,
		ptl_sr_value_t *status);

int PtlNIDist(ptl_handle_ni_t ni_handle, ptl_process_id_t process,
	      unsigned long *distance);

int PtlNIHandle(ptl_handle_any_t handle, ptl_handle_ni_t *ni_handle);

/*
 * P3.3 API spec: section 3.6
 */
int PtlGetUid(ptl_handle_ni_t ni_handle, ptl_uid_t *uid);

/*
 * P3.3 API spec: section 3.7
 */
int PtlGetId(ptl_handle_ni_t ni_handle, ptl_process_id_t *id);

/*
 * P3.3 API spec: section 3.8
 */
int PtlGetJid(ptl_handle_ni_t ni_handle, ptl_jid_t *jid);

/*
 * P3.3 API spec: section 3.9
 */
int PtlMEAttach(ptl_handle_ni_t ni_handle, ptl_pt_index_t pt_index,
		ptl_process_id_t match_id, ptl_match_bits_t match_bits,
		ptl_match_bits_t ignore_bits, ptl_unlink_t unlink,
		ptl_ins_pos_t postion, ptl_handle_me_t *me_handle);

int PtlMEAttachAny(ptl_handle_ni_t ni_handle, ptl_pt_index_t *pt_index,
		   ptl_process_id_t match_id, ptl_match_bits_t match_bits,
		   ptl_match_bits_t ignore_bits, ptl_unlink_t unlink,
		   ptl_handle_me_t *me_handle);

int PtlMEInsert(ptl_handle_me_t base, ptl_process_id_t match_id,
		ptl_match_bits_t match_bits, ptl_match_bits_t ignore_bits,
		ptl_unlink_t unlink, ptl_ins_pos_t position,
		ptl_handle_me_t *me_handle);

int PtlMEUnlink(ptl_handle_me_t me_handle);

/*
 * P3.3 API spec: section 3.10
 */
int PtlMDAttach(ptl_handle_me_t me_handle, ptl_md_t md, ptl_unlink_t unlink_op,
		ptl_handle_md_t *md_handle);

int PtlMDBind(ptl_handle_ni_t ni_handle, ptl_md_t md, ptl_unlink_t unlink_op,
	      ptl_handle_md_t *md_handle);

int PtlMDUnlink(ptl_handle_md_t md_handle);

int PtlMDUpdate(ptl_handle_md_t md_handle, ptl_md_t *old_md, ptl_md_t *new_md,
		ptl_handle_eq_t eq_handle);

/*
 * P3.3 API spec: section 3.11
 */
int PtlEQAlloc(ptl_handle_ni_t ni_handle, ptl_size_t count,
	       ptl_eq_handler_t eq_handler, ptl_handle_eq_t *eq_handle);

int PtlEQFree(ptl_handle_eq_t eq_handle);

int PtlEQGet(ptl_handle_eq_t eq_handle, ptl_event_t *event);

int PtlEQWait(ptl_handle_eq_t eq_handle, ptl_event_t *event);

int PtlEQWait_timeout(ptl_handle_eq_t eq_handle, ptl_event_t *event_out);

int PtlEQPoll(ptl_handle_eq_t *eq_handles, int size, ptl_time_t timeout,
	      ptl_event_t *event, int *which_eq);

/*
 * P3.3 API spec: section 3.12
 */
int PtlACEntry(ptl_handle_ni_t ni_handle, ptl_ac_index_t ac_index,
	       ptl_process_id_t match_id, ptl_uid_t user_id, ptl_jid_t job_id,
	       ptl_pt_index_t pt_index);

/*
 * P3.3 API spec: section 3.13
 */
int PtlPut(ptl_handle_md_t md_handle, ptl_ack_req_t ack_req,
	   ptl_process_id_t target_id, ptl_pt_index_t pt_index,
	   ptl_ac_index_t ac_index, ptl_match_bits_t match_bits,
	   ptl_size_t remote_offset, ptl_hdr_data_t hdr_data);

int PtlPutRegion(ptl_handle_md_t md_handle, ptl_size_t local_offset,
		 ptl_size_t length, ptl_ack_req_t ack_req,
		 ptl_process_id_t target_id, ptl_pt_index_t pt_index,
		 ptl_ac_index_t ac_index, ptl_match_bits_t match_bits,
		 ptl_size_t remote_offset, ptl_hdr_data_t hdr_data);

int PtlGet(ptl_handle_md_t md_handle, ptl_process_id_t target_id,
	   ptl_pt_index_t pt_index, ptl_ac_index_t ac_index,
	   ptl_match_bits_t match_bits, ptl_size_t remote_offset);

int PtlGetRegion(ptl_handle_md_t md_handle, ptl_size_t local_offset,
		 ptl_size_t length, ptl_process_id_t target_id,
		 ptl_pt_index_t pt_index, ptl_ac_index_t ac_index,
		 ptl_match_bits_t match_bits, ptl_size_t remote_offset);

int PtlGetPut(ptl_handle_md_t get_md_handle, ptl_handle_md_t put_md_handle,
	      ptl_process_id_t target_id, ptl_pt_index_t pt_index,
	      ptl_ac_index_t ac_index, ptl_match_bits_t match_bits,
	      ptl_size_t remote_offset, ptl_hdr_data_t hdr_data);

int PtlNIEqDump(ptl_handle_ni_t ni_handle);

/* undocumented extension ... */
int PtlMEMDPost(ptl_handle_ni_t ni_handle, ptl_handle_me_t base,
		ptl_process_id_t match_id, ptl_match_bits_t match_bits,
		ptl_match_bits_t ignore_bits, ptl_unlink_t unlink,
		ptl_ins_pos_t position, ptl_md_t md, ptl_unlink_t unlink_op,
		ptl_handle_me_t *me_handle, ptl_handle_md_t *md_handle,
		ptl_handle_eq_t eq_handle);

#endif /* _PTL3_API_H_ */
