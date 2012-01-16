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

#ifndef _PTL3_LIB_TYPES_H_
#define _PTL3_LIB_TYPES_H_

/* We need these to allow for a ptl_size_t being bigger than a size_t
 * or a ssize_t.  We're going to assume a 2's complement machine, where
 * sizeof(size_t) == sizeof(ssize_t).
 */
#ifndef SIZE_T_MAX
#define SIZE_T_MAX  ((ptl_size_t)(~(size_t)0))
#endif
#ifndef SSIZE_T_MAX
#define SSIZE_T_MAX ((ptl_size_t)(~(size_t)0>>1))
#endif

typedef char api_mem_t;
typedef char lib_mem_t;

typedef enum {
	PTL_MSG_ACK = 0,
	PTL_MSG_PUT,
	PTL_MSG_GET,
	PTL_MSG_REPLY,
	PTL_MSG_GETPUT
} ptl_msg_type_t;

/* In addition to the status registers defined in p3api/types.h, this
 * implementation also supports counters for the maximum and current
 * length of a match list.  But, we keep those registers in portal
 * objects.
 */
#define LIB_SREG_COUNT PTL_SR_NAL_REGS_START

/* The Portals3 wire header.  Make sure to use specified-size types to
 * simplify 32-64 bit interoperability, and that the structs are laid out
 * to minimize the possibility of compiler-added padding.
 */
typedef struct ptl_hdr {

	ptl_process_id_t dst;
	ptl_process_id_t src;
	ptl_match_bits_t mbits;
	ptl_size_t length;
	ptl_uid_t src_uid;
	ptl_jid_t src_jid;
	uint32_t msg_type;

	union {
		struct {
			ptl_handle_md_t dst_md;
			uint32_t dst_md_gen;
		} ack;

		struct {
			ptl_size_t dst_offset;
			ptl_hdr_data_t hdr_data;
			ptl_pt_index_t ptl_index;
			ptl_ac_index_t ac_index;
			ptl_handle_md_t ack_md;
			uint32_t ack_md_gen;
		} put;

		struct {
			ptl_size_t src_offset;
			ptl_size_t rtn_offset;
			ptl_pt_index_t ptl_index;
			ptl_ac_index_t ac_index;
			ptl_handle_md_t rtn_md;
			uint32_t rtn_md_gen;
		} get;

		struct {
			ptl_size_t src_offset;
			ptl_size_t rtn_offset;
			ptl_hdr_data_t hdr_data;
			ptl_pt_index_t ptl_index;
			ptl_ac_index_t ac_index;
			ptl_handle_md_t rtn_md;
			uint32_t rtn_md_gen;
		} getput;

		struct {
			ptl_size_t dst_offset;
			ptl_handle_md_t dst_md;
			uint32_t dst_md_gen;
		} reply;
	} msg;
} ptl_hdr_t;

/*
 * Object flag bits specific to the library
 */
#define OBJ_UNLINK     PTL_OBJ_FLAG(0x010)	/* attach/insert/bind spec */
/*
 * These object flags are used just on MDs
 */
#define MD_INACTIVE    PTL_OBJ_FLAG(0x020)
/*
 * These object flags are used just on msgs
 */
#define MSG_SEND_ACK   PTL_OBJ_FLAG(0x100)	/* msg->hdr is an ack */
#define MSG_END_EV     PTL_OBJ_FLAG(0x200)
#define MSG_UNLINK_EV  PTL_OBJ_FLAG(0x400)
#define MSG_DO_UNLINK  PTL_OBJ_FLAG(0x800)	/* actually do the deed */


/* The library object types.
 */
struct lib_msg;
struct lib_me;
struct lib_md;
struct lib_eq;

typedef struct lib_msg lib_msg_t;
typedef struct lib_me lib_me_t;
typedef struct lib_md lib_md_t;
typedef struct lib_eq lib_eq_t;

/* The buffer type used to implement PtlGetPut.  lib_gpbuf_t:iov always has
 * exactly one entry, which always points to lib_gpbuf_t:buf.
 */
#define PTL_GETPUT_BUFLEN 64
#define PTL_GBPUF_WORDS ((PTL_GETPUT_BUFLEN+sizeof(long)-1)/sizeof(long))

typedef struct lib_gpbuf {
	ptl_size_t src_os;
	ptl_md_iovec_t iov;
	unsigned long buf[PTL_GBPUF_WORDS];
} lib_gpbuf_t;

/* FIXME: lib_msg_t:ev is where we build events to deliver back to the user.
 * This design only works if the actual copying of event bytes is synchronous
 * with the event delivery request.  We'll need a cache of events otherwise,
 * e.g., if the library is in NIC space, and the event bytes were moved by a
 * DMA engine; or if the library is in kernel space and event bytes were
 * moved by a separate tasklet.
 */
struct lib_msg {
	struct list_head list;	/* msg free list */
	lib_md_t *md;
	ptl_process_id_t src;
	uint32_t id;
	ptl_event_t ev;
	ptl_hdr_t hdr;
	unsigned long nal_msg_data;
	lib_gpbuf_t *buf;
};

struct lib_me {
	struct list_head list;	/* me free list or match list */
	ptl_process_id_t match_id;
	ptl_match_bits_t mbits;
	ptl_match_bits_t mask;	/* which match bits to test */
	lib_md_t *md;
	ptl_pt_index_t ptl;
	uint32_t id;
};

/* FIXME:
 * To keep MDs from being silently reused, say when an MD is unlinked with
 * a reply pending but not in-progress, we need to keep a "queued" refcount.
 */
struct lib_md {
	struct list_head list;	/* md free list */
	lib_me_t *me;
	lib_eq_t *eq;
	void *user_ptr;
	void *addrkey;
	ptl_md_iovec_t *iov;
	api_mem_t *start;
	ptl_size_t length;
	ptl_size_t offset;
	ptl_size_t max_size;
	ptl_size_t iovlen;
	ptl_size_t iov_dlen;
	int threshold;
	int pending;
	unsigned int options;
	uint32_t id;
	uint32_t generation;
};

struct lib_eq {
	struct list_head list;	/* eq free list */
	ptl_seq_t sequence;
	ptl_seq_t entries;
	ptl_size_t nbytes;
	api_mem_t *base;
#ifdef OBSOLETE
	void *addrkey;
#endif
	uint32_t id;
	int pending;
};

typedef struct lib_ptl {
	struct list_head mlist;
	ptl_sr_value_t len;
	ptl_sr_value_t maxlen;
} lib_ptl_t;

typedef struct lib_ptltab {
	lib_ptl_t *ptl;
	ptl_pt_index_t size;
} lib_ptltab_t;

typedef struct lib_ace {
	ptl_process_id_t id;
	ptl_uid_t uid;
	ptl_jid_t jid;
	ptl_pt_index_t ptl;
} lib_ace_t;

typedef struct lib_actab {
	lib_ace_t *ace;
	ptl_ac_index_t size;
} lib_actab_t;

/* We use these tables for O(1) look-up of library objects by index.
 */
typedef struct lib_metbl {
	lib_me_t **tbl;
	unsigned int inuse;		/* count of inuse objects in table */
	unsigned int next_row;		/* next free row */
	unsigned int num_rows;		/* number of rows allocated */
} lib_metbl_t;

typedef struct lib_mdtbl {
	lib_md_t **tbl;
	unsigned int inuse;		/* count of inuse objects in table */
	unsigned int next_row;		/* next free row */
	unsigned int num_rows;		/* number of rows allocated */
} lib_mdtbl_t;

typedef struct lib_eqtbl {
	lib_eq_t **tbl;
	unsigned int inuse;		/* count of inuse objects in table */
	unsigned int next_row;		/* next free row */
	unsigned int num_rows;		/* number of rows allocated */
} lib_eqtbl_t;

typedef struct lib_msgtbl {
	lib_msg_t **tbl;
	unsigned int inuse;		/* count of inuse objects in table */
	unsigned int next_row;		/* next free row */
	unsigned int num_rows;		/* number of rows allocated */
} lib_msgtbl_t;

struct lib_nal;

/* Hold obj_alloc rather than obj_update when manipulating the inuse flag
 * on interface, since what we're after is to prevent object allocations
 * from a down interface.
 *
 * The ptl_uid_t value should really be in the p3_process_t object, rather
 * than here, but until we get a spec that doesn't have a ptl_uid_t value
 * depend on the interface, it has to go here ....
 */
typedef struct lib_ni {

	p3lock(obj_alloc);
	p3lock(obj_update);

	ptl_nid_t nid;
	ptl_pid_t pid;
	ptl_uid_t uid;
	p3_process_t *owner;

#ifdef ENABLE_P3RT_SUPPORT
	rt_group_data_t *group;
#endif

	struct list_head free_eq;
	struct list_head free_me;
	struct list_head free_md;
	struct list_head free_msg;

	lib_eqtbl_t eq;
	lib_metbl_t me;
	lib_mdtbl_t md;
	lib_msgtbl_t msg;

	lib_ptltab_t ptltab;
	lib_actab_t actab;

	struct lib_nal *nal;
	ptl_ni_limits_t limits;

	uint32_t id;
	unsigned int debug;

	ptl_sr_value_t stats[LIB_SREG_COUNT];
} lib_ni_t;

#endif /* _PTL3_LIB_TYPES_H_ */
