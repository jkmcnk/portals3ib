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

#include <p3lib/debug.h>

#ifndef _PTL3_LIB_P3LIB_H_
#define _PTL3_LIB_P3LIB_H_

extern_p3lock(lib_update);

/*extern 
int lib_fini(lib_ni_t *ni);*/

/* When the NAL detects an incoming message, it should call lib_parse() to
 * decode it and begin library processing.  If the NAL requires saved state
 * to process the remainder of the transaction it should use <nal_msg_data>
 * to give the library something that uniquely identifies this transaction.
 * The NAL callbacks will be handed the <nal_msg_data> value any time they
 * require processing for that particular transaction.  The <nal_msg_data>
 * value must be unique for the life of that transaction.  
 *
 * type is the interface type which received the header, and is used to 
 * look up the destination p3_process_t based on PID, since the library
 * guarantees that PID values are unique per interface type.  If the return
 * value is not PTL_OK the NAL should take *drop_len bytes off the wire and
 * throw them away.
 */
extern 
int lib_parse(ptl_hdr_t *hdr, unsigned long nal_msg_data,
	      ptl_interface_t type, ptl_size_t *drop_len);

/* When the NAL callbacks send or receive have finished the transaction
 * requested by the library, they should cal lib_finalize() to allow
 * the transaction to be closed.  The lib_msg_data parameter should be the
 * one given to the NAL by the library in the callback.  If the transaction
 * cannot be completed successfully, the NAL should use fail_type to
 * notify that the transaction should be completed with an error condition.
 */
extern 
int lib_finalize(lib_ni_t *ni, void *lib_msg_data, ptl_ni_fail_t fail_type);

/* The library uses this to deliver events.
 */
extern
int lib_event(lib_ni_t *ni, void *lib_msg_data, ptl_seq_t link,
	      ptl_event_kind_t ev_type, ptl_ni_fail_t fail_type);



extern void print_hdr(lib_ni_t *ni, ptl_hdr_t *hdr);
extern void lib_md_unlink(lib_ni_t *ni, lib_md_t *md);
extern void lib_me_unlink(lib_ni_t *ni, lib_me_t *me);

extern void lib_md_unlinkall(lib_ni_t *ni);
extern void lib_me_unlinkall(lib_ni_t *ni);
extern void lib_eq_freeall(lib_ni_t *ni);

extern void lib_copy_iov(lib_ni_t *ni, ptl_size_t copy_len,
						 const ptl_md_iovec_t *src_iov, ptl_size_t src_iovlen,
						 ptl_size_t src_offset, void *src_addrkey,
						 ptl_md_iovec_t *dst_iov, ptl_size_t dst_iovlen,
						 ptl_size_t dst_offset, void *dst_addrkey);

#define lib_md_2_api_md(md,api_md)								\
	do {														\
		(api_md)->start =  (md)->start;							\
		(api_md)->length = (md)->length;						\
		(api_md)->threshold = (md)->threshold;					\
		(api_md)->max_size = (md)->max_size;					\
		(api_md)->options = (md)->options;						\
		(api_md)->user_ptr = (md)->user_ptr;					\
		(api_md)->eq_handle =									\
			(md)->eq ? PTL_OBJ_HNDL((md)->eq) : PTL_EQ_NONE;	\
	} while (0)

#define PTL_ENFORCE_LIMITS(r,l)											\
	do {																\
		(r)->max_mes = MIN((r)->max_mes,(l)->max_mes);					\
		(r)->max_mds = MIN((r)->max_mds,(l)->max_mds);					\
		(r)->max_eqs = MIN((r)->max_eqs,(l)->max_eqs);					\
		(r)->max_ac_index = MIN((r)->max_ac_index,(l)->max_ac_index);	\
		(r)->max_pt_index = MIN((r)->max_pt_index,(l)->max_pt_index);	\
		(r)->max_md_iovecs = MIN((r)->max_md_iovecs,(l)->max_md_iovecs); \
		(r)->max_me_list = MIN((r)->max_me_list,(l)->max_me_list);		\
		(r)->max_getput_md = MIN((r)->max_getput_md,(l)->max_getput_md); \
	} while (0)

#define ni_stats_inc(ni,reg,val) do { (ni)->stats[(reg)] += (val); } while (0)
#define ni_stats_dec(ni,reg,val) do { (ni)->stats[(reg)] -= (val); } while (0)
#define ni_stats_set(ni,reg,val) do { (ni)->stats[(reg)]  = (val); } while (0)

#define PTL_LIKELY(x)   __builtin_expect((x),1)
#define PTL_UNLIKELY(x) __builtin_expect((x),0)

static inline ptl_sr_value_t
ni_stats_get(lib_ni_t *ni, ptl_sr_index_t reg)
{
	return ni->stats[reg];
}

static inline int
is_same_process(ptl_nid_t src_nid, ptl_pid_t src_pid, 
				ptl_nid_t des_nid, ptl_pid_t des_pid)
{
	return src_nid == des_nid && src_pid == des_pid;
}

/* Returns PTL_OK if able to set *act_pid to a valid pid.  req_pid may
 * be either a specific pid, or PTL_PID_ANY to request the next available
 * pid.  Returns PTL_PID_INVALID and leaves *act_pid unchanged on failure,
 * including if req_pid is currently in use.
 */
extern int lib_set_pid(ptl_interface_t type,
		       ptl_pid_t req_pid, ptl_pid_t *act_pid);

/* Returns pid to the pool of available pids.
 */
extern void lib_release_pid(ptl_interface_t type, ptl_pid_t pid);

/* If we have runtime support, the runtime code needs to make this 
 * function pointer reference the function that will return the PID
 * value the runtime desires.
 */
extern ptl_pid_t (*runtime_req_pid)(void);

#endif /* _PTL3_LIB_P3LIB_H_ */
