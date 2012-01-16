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

#ifndef _PTL3_API_TYPES_H_
#define _PTL3_API_TYPES_H_

/*
 * C99 standard integer types
 */
#include <stdint.h>

/*
 * Note:
 * The only types and constants appearing in this file are those
 * described in the Portals 3.3 API specification document, or are
 * implementation extensions specifically mentioned therein.
 *
 * We only used unsized types (e.g. int, long) where we really do
 * not care about the data size.  We use sized types anywhere the
 * spec calls out a size, or for anything that may go over a wire
 * (so we can interoperate in a heterogeneous cluster), or for
 * anything where this implementation depends on the type size.
 */

/*
 * P3.3 API spec: section 3.2.1
 */
typedef uint64_t ptl_size_t;

/*
 * P3.3 API spec: section 3.2.2, 3.14.1
 */
typedef uint32_t ptl_handle_any_t;
#define PTL_INVALID_HANDLE ((ptl_handle_any_t)0xffffffff)
#define PTL_HANDLE_NONE    ((ptl_handle_any_t)0x7fffffff)

typedef ptl_handle_any_t ptl_handle_ni_t;
typedef ptl_handle_any_t ptl_handle_md_t;
typedef ptl_handle_any_t ptl_handle_me_t;
typedef ptl_handle_any_t ptl_handle_eq_t;
#define PTL_EQ_NONE ((ptl_handle_eq_t)0xbfffffff)

/*
 * P3.3 API spec: section 3.2.3
 */
typedef uint32_t ptl_pt_index_t;
typedef uint32_t ptl_ac_index_t;

/*
 * P3.3 API spec: section 3.12.1
 */
#define PTL_PT_INDEX_ANY ((ptl_pt_index_t)UINT32_C(0xffffffff))

/*
 * P3.3 API spec: section 3.2.4
 */
typedef uint64_t ptl_match_bits_t;

/*
 * P3.3 API spec: section 3.2.5 
 */
typedef uint32_t ptl_interface_t;

/*
 * P3.3 API spec: section 3.2.6 
 */
typedef uint32_t ptl_nid_t;
typedef uint32_t ptl_pid_t;
typedef uint32_t ptl_uid_t;
typedef uint32_t ptl_jid_t;

#define PTL_NID_ANY ((ptl_nid_t)UINT32_C(0xffffffff))
#define PTL_PID_ANY ((ptl_pid_t)UINT32_C(0xffffffff))
#define PTL_JID_ANY ((ptl_jid_t)UINT32_C(0xffffffff))
#define PTL_UID_ANY ((ptl_uid_t)UINT32_C(0xffffffff))

/*
 * P3.3 API spec: section 3.2.7
 *
 * We don't use an enum for status register index values; rather use the
 * preprocessor so that a NAL can have its own registers, in addition to
 * the registers kept by the Portals library itself.
 *
 * Note that only PTL_SR_DROP_COUNT is specified by the API document;
 * the rest are specific to this implementation.
 */
typedef uint32_t ptl_sr_index_t;
typedef uint64_t ptl_sr_value_t;

#define PTL_SR_DROP_COUNT	 0	/* dropped requests */
#define PTL_SR_DROP_LENGTH	 1	/* data bytes in dropped requests */
#define PTL_SR_RECV_COUNT	 2
#define PTL_SR_RECV_LENGTH	 3
#define PTL_SR_SEND_COUNT	 4
#define PTL_SR_SEND_LENGTH	 5
#define PTL_SR_PTLS_MAX		 6
#define PTL_SR_PTLS_CUR		 7

#define PTL_SR_MSGS_ALLOC	 8	/* P3 messages allocated */
#define PTL_SR_MSGS_FREED	 9	/* P3 messages freed */
#define PTL_SR_MSGS_MAX		10	/* max P3 messages allocated */
#define PTL_SR_MSGS_CUR		11	/* current P3 messages allocated  */

#define PTL_SR_MES_ALLOC	12	/* match entry stats */
#define PTL_SR_MES_FREED	13
#define PTL_SR_MES_MAX		14
#define PTL_SR_MES_CUR		15

#define PTL_SR_MDS_ALLOC	16	/* memory descriptor stats */
#define PTL_SR_MDS_FREED	17
#define PTL_SR_MDS_MAX		18
#define PTL_SR_MDS_CUR		19

#define PTL_SR_EQS_ALLOC	20	/* event queue stats */
#define PTL_SR_EQS_FREED	21
#define PTL_SR_EQS_MAX		22
#define PTL_SR_EQS_CUR		23

#define PTL_SR_MD_ALIGN_128	24	/* buffer alignment stats */
#define PTL_SR_MD_ALIGN_64	25
#define PTL_SR_MD_ALIGN_32	26
#define PTL_SR_MD_ALIGN_16	27
#define PTL_SR_MD_ALIGN_8	28

#define PTL_SR_NAL_REGS_START	29

/*
 * P3.3 API spec: section 3.5.1 
 */
typedef struct {
	int max_mes;
	int max_mds;
	int max_eqs;
	int max_ac_index;
	int max_pt_index;
	int max_md_iovecs;
	int max_me_list;
	int max_getput_md;
} ptl_ni_limits_t;

/*
 * P3.3 API spec: section 3.7.1 
 */
typedef struct {
	ptl_nid_t nid;
	ptl_pid_t pid;
} ptl_process_id_t;

/*
 * P3.3 API spec: section 3.9.1
 */
typedef enum {
	PTL_RETAIN,
	PTL_UNLINK
} ptl_unlink_t;

typedef enum {
	PTL_INS_BEFORE,
	PTL_INS_AFTER
} ptl_ins_pos_t;

/*
 * P3.3 API spec: section 3.10.1 
 */
typedef struct {
	void *start;
	ptl_size_t length;
	int threshold;
	ptl_size_t max_size;
	unsigned int options;
	void *user_ptr;
	ptl_handle_eq_t eq_handle;
} ptl_md_t;

#define PTL_MD_THRESH_INF  (-1)

/*
 * values for ptl_md_t:options - combine with bitwise-or
 */
#define PTL_MD_OP_PUT			0x0001
#define PTL_MD_OP_GET			0x0002
#define PTL_MD_MANAGE_REMOTE		0x0004
#define PTL_MD_TRUNCATE			0x0008
#define PTL_MD_ACK_DISABLE		0x0010
#define PTL_MD_IOVEC			0x0020
#define PTL_MD_MAX_SIZE			0x0040
#define PTL_MD_EVENT_START_DISABLE	0x0080
#define PTL_MD_EVENT_END_DISABLE	0x0100

/*
 * P3.3 API spec: section 3.10.2
 */
#ifdef PTL_SIZET_MATCHES_SYSTEM
typedef struct iovec ptl_md_iovec_t;
#else
typedef struct {
	void *iov_base;
	ptl_size_t iov_len;
} ptl_md_iovec_t;
#endif

/*
 * P3.3 API spec: section 3.11.1 
 */
typedef enum {
	PTL_EVENT_GET_START,
	PTL_EVENT_GET_END,
	PTL_EVENT_PUT_START,
	PTL_EVENT_PUT_END,
	PTL_EVENT_GETPUT_START,
	PTL_EVENT_GETPUT_END,
	PTL_EVENT_REPLY_START,
	PTL_EVENT_REPLY_END,
	PTL_EVENT_SEND_START,
	PTL_EVENT_SEND_END,
	PTL_EVENT_ACK,
	PTL_EVENT_UNLINK
} ptl_event_kind_t;

typedef uint32_t ptl_ni_fail_t;
typedef uint32_t ptl_seq_t;
typedef uint64_t ptl_hdr_data_t;

/*
 * P3.3 API spec: section 3.11.4 
 */
typedef struct {
	ptl_event_kind_t type;
	ptl_process_id_t initiator;
	ptl_uid_t uid;
	ptl_uid_t jid;
	ptl_pt_index_t pt_index;
	ptl_match_bits_t match_bits;
	ptl_size_t rlength;
	ptl_size_t mlength;
	ptl_size_t offset;
	ptl_handle_md_t md_handle;
	ptl_md_t md;
	ptl_hdr_data_t hdr_data;
	ptl_seq_t link;
	ptl_ni_fail_t ni_fail_type;
	volatile ptl_seq_t sequence;
} ptl_event_t;

/*
 * Value of ptl_event_t:ni_fail_type for successful operations.
 * Again, we use define so that NALs can define their own failure types.
 */
#define PTL_NI_OK  0

/*
 * P3.3 API spec: section 3.11.6 
 */
typedef void (*ptl_eq_handler_t)(ptl_event_t *event);
#define PTL_EQ_HANDLER_NONE (ptl_eq_handler_t)NULL

/*
 * P3.3 API spec: section 3.11.12
 */
typedef uint32_t ptl_time_t;
#define PTL_TIME_FOREVER ((ptl_time_t)-1)

/*
 * P3.3 API spec: section 3.13.2 
 */
typedef enum {
	PTL_ACK_REQ,
	PTL_NO_ACK_REQ
} ptl_ack_req_t;

#endif /* _PTL3_API_TYPES_H_ */
