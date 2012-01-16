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

#include <p3-config.h>

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>

/* If compiling for user-space (and maybe NIC-space), these need to be
 * the Portals3 versions of the Linux kernel include files, which
 * have been suitably modified for use in user-space code.
 */
#include <linux/list.h>

/* These are all Portals3 include files.
 */
#include <p3utils.h>

#include <p3api/types.h>
#include <p3api/debug.h>

#include <p3/lock.h>
#include <p3/handle.h>
#include <p3/process.h>
#include <p3/errno.h>
#include <p3/debug.h>

#include <p3lib/types.h>
#include <p3lib/p3lib.h>
#include <p3lib/nal.h>
#include <p3lib/p3lib_support.h>

#include <p3/obj_alloc.h>	/* MUST come after p3lib/p3lib.h */

struct local_put_args {
	lib_md_t *md;
	ptl_size_t offset;
};

/*
 * We use this allocation macro lots of times in this file to allocate
 * message objects, so we'll make it a function to save code space.
 */
static lib_msg_t *
msg_alloc(lib_ni_t *ni)
{
	lib_msg_t *msg = ptl_obj_alloc(msg, ni);
	if (msg)
		msg->buf = NULL;
	return msg;
}

void
lib_copy_iov(lib_ni_t *ni,
			 ptl_size_t copy_len,
			 const ptl_md_iovec_t *src_iov,
			 ptl_size_t src_iovlen,
			 ptl_size_t src_os,
			 void *src_ak,
			 ptl_md_iovec_t *dst_iov,
			 ptl_size_t dst_iovlen,
			 ptl_size_t dst_os,
			 void *dst_ak)
{
	int i = -1, j = -1;
	ptl_size_t src_start = 0, src_next = 0;
	ptl_size_t dst_start = 0, dst_next = 0;
	ptl_size_t len;

	src_iovlen--;	/* Now the maximum valid index for src_iov */
	dst_iovlen--;	/* Now the maximum valid index for dst_iov */

	while (copy_len) {

		while (src_os >= src_next) {
			if (i == (int)src_iovlen)
				break;
			src_start = src_next;
			src_next += src_iov[++i].iov_len;
		}
		while (dst_os >= dst_next) {
			if (j == (int)dst_iovlen)
				break;
			dst_start = dst_next;
			dst_next += dst_iov[++j].iov_len;
		}
		len = src_next > src_os ? src_next - src_os : 0;
		len = dst_next > dst_os ? MIN(len, dst_next - dst_os) : 0;
		len = MIN(len, SIZE_T_MAX);
		len = MIN(len, copy_len);

		if (!len)
			return;

		memcpy(dst_iov[j].iov_base + dst_os - dst_start,
		       src_iov[i].iov_base + src_os - src_start,
		       len);

		src_os += len;
		dst_os += len;
		copy_len -= len;
	}
	return;
}

/* Call lib_find_md() with ni->obj_update lock held
 */
static lib_md_t *
lib_find_md(lib_ni_t *ni,
			const ptl_hdr_t *mh,
			ptl_pt_index_t ptl_idx,
			ptl_ac_index_t ac_idx,
			ptl_match_bits_t mbits,
			ptl_size_t rlength,	/* requested length */
			ptl_size_t roffset,	/* requested offset */
			ptl_size_t *length_out,	/* accepted length */
			ptl_size_t *offset_out)	/* accepted offset */
{
	struct list_head *item;
	lib_ptltab_t *ptbl = &ni->ptltab;
	lib_ace_t *ace;
	lib_me_t *me;
	lib_md_t *md;
	ptl_size_t length;
	ptl_size_t offset;

	if (ptl_idx > ptbl->size) {
		if (DEBUG_P3(ni->debug, PTL_DBG_REQUEST))
			p3_print("lib_find_md:" FMT_NIDPID
					 " invalid portal index %d in req from"
					 FMT_NIDPID "\n",
					 ni->nid, ni->pid, ptl_idx, 
					 mh->src.nid, mh->src.pid);
		return NULL;
	}

	if (DEBUG_P3(ni->debug, PTL_DBG_REQUEST))
		p3_print("lib_find_md:" FMT_NIDPIDPTL " new req from"
				 FMT_NIDPID FMT_RLEN FMT_MBITS "\n",
				 ni->nid, ni->pid, ptl_idx, 
				 mh->src.nid, mh->src.pid, rlength, mbits);

	if (ac_idx > ni->actab.size) {
		if (DEBUG_P3(ni->debug, PTL_DBG_REQUEST))
			p3_print("lib_find_md:" FMT_NIDPID
					 " invalid ACE index %d in req from"
					 FMT_NIDPID "\n",
					 ni->nid, ni->pid, ac_idx,
					 mh->src.nid, mh->src.pid);
		return NULL;
	}
	/*
	 * P3.3 API spec: sections 2.3 & 3.12.1
	 */
	ace = &ni->actab.ace[ac_idx];
	if (ace->uid != PTL_UID_ANY      && ace->uid != mh->src_uid    ||
	    ace->ptl != PTL_PT_INDEX_ANY && ace->ptl != ptl_idx        ||
	    ace->jid != PTL_JID_ANY      && ace->jid != mh->src_jid    ||
	    ace->id.nid != PTL_NID_ANY   && ace->id.nid != mh->src.nid ||
	    ace->id.pid != PTL_PID_ANY   && ace->id.pid != mh->src.pid) {

		if (DEBUG_P3(ni->debug, PTL_DBG_REQUEST))
			p3_print("lib_find_md:" FMT_NIDPIDPTL
					 " ACE %d denies request from "FMT_NIDPID"\n",
					 ni->nid, ni->pid, ptl_idx,
					 ac_idx, mh->src.nid, mh->src.pid);
		return NULL;
	}
	/*
	 * P3.3 API spec: section 2.2, figure 2.5
	 */
	list_for_each(item, &ptbl->ptl[ptl_idx].mlist) {
		ptl_nid_t mnid;
		ptl_pid_t mpid;

		me = list_entry(item, typeof(*me), list);
		mnid = me->match_id.nid;
		mpid = me->match_id.pid;

		if (!TST_OBJ(me, OBJ_INUSE)) {
			if (DEBUG_P3(ni->debug, PTL_DBG_DELIVERY))
				p3_print("lib_find_md:"FMT_NIDPIDPTL
						 " idle ME %d\n",
						 ni->nid, ni->pid, ptl_idx, 
						 PTL_OBJ_INDX(me));
			continue;
		}
		if (DEBUG_P3(ni->debug, PTL_DBG_DELIVERY))
			p3_print("lib_find_md:" FMT_NIDPIDPTL " comp req"
					 FMT_NIDPID FMT_RLEN FMT_MBITS " to ME %d @ %p"
					 FMT_NIDPID FMT_MBITS FMT_IBITS "\n",
					 ni->nid, ni->pid, ptl_idx, 
					 mh->src.nid, mh->src.pid, mh->length, 
					 mh->mbits, PTL_OBJ_INDX(me), me,
					 mnid, mpid, me->mbits, ~me->mask);

		if (mnid != PTL_NID_ANY && mnid != mh->src.nid ||
		    mpid != PTL_PID_ANY && mpid != mh->src.pid)
			continue;

		if ((me->mbits ^ mbits) & me->mask ||
		    !me->md || TST_OBJ(me->md, MD_INACTIVE))
			continue;

		goto match;

	next_me: /* return here if the MD won't accept the operation */
		;
	}
	if (DEBUG_P3(ni->debug, PTL_DBG_DROP))
		p3_print("lib_find_md:" FMT_NIDPIDPTL " drop req from"
				 FMT_NIDPID FMT_RLEN FMT_MBITS ": no match\n",
				 ni->nid, ni->pid, ptl_idx, 
				 mh->src.nid, mh->src.pid, rlength, mbits);
	return NULL;
match:
	md = me->md;

	/*
	 * P3.3 API spec: section 3.10.1
	 */
	switch (mh->msg_type) {
	case PTL_MSG_PUT:
		if (md->options & PTL_MD_OP_PUT)
			break;
		goto next_me;
	case PTL_MSG_GET:
		if (md->options & PTL_MD_OP_GET)
			break;
		goto next_me;
	case PTL_MSG_GETPUT:
		if (md->options & PTL_MD_OP_GET && md->options & PTL_MD_OP_PUT)
			break;
	default:
		goto next_me;
	}

	if (!TST_OBJ(md, OBJ_INUSE)) {
		if (DEBUG_P3(ni->debug, PTL_DBG_REQUEST))
			p3_print("lib_find_md:"FMT_NIDPIDPTL" req from"
					 FMT_NIDPID FMT_RLEN FMT_MBITS
					 " matches ME %d, rejected by idle MD %d\n",
					 ni->nid, ni->pid, ptl_idx, 
					 mh->src.nid, mh->src.pid, rlength, mbits,
					 PTL_OBJ_INDX(me), PTL_OBJ_INDX(md));
		goto next_me;
	}

	offset = md->options & PTL_MD_MANAGE_REMOTE ? roffset : md->offset;
		
	if ((md->options & PTL_MD_TRUNCATE) && offset <= md->iov_dlen) {
		length = MIN(md->iov_dlen - offset, rlength);
	}
	else if (offset + rlength <= md->iov_dlen) {
		length = rlength;
	}
	else {
		if (DEBUG_P3(ni->debug, PTL_DBG_DELIVERY))
			p3_print("lib_find_md:"FMT_NIDPIDPTL" req from"
					 FMT_NIDPID FMT_RLEN FMT_MBITS
					 " matches ME %d, rejected by MD %d "
					 "w/os "FMT_PSZ_T"(%c) len "FMT_PSZ_T"\n",
					 ni->nid, ni->pid, ptl_idx, 
					 mh->src.nid, mh->src.pid, rlength, mbits,
					 PTL_OBJ_INDX(me), PTL_OBJ_INDX(md), offset,
					 (md->options & PTL_MD_MANAGE_REMOTE ?'R':'L'),
					 md->iov_dlen);
		goto next_me;
	}

	md->offset += length;
	*length_out = length;
	*offset_out = offset;

	/* Recall that when we attach or bind an MD, if 
	 * PTL_MD_MANAGE_REMOTE is set we unset PTL_MD_MAX_SIZE.
	 */
	if (md->options & PTL_MD_MAX_SIZE &&
	    md->iov_dlen - md->offset < md->max_size)
		SET_OBJ(md, MD_INACTIVE);

	return md;
}

static void
parse_ack(lib_ni_t *ni, ptl_hdr_t *mh, unsigned long nal_msg_data)
{
	lib_msg_t *msg;
	lib_md_t *md;

	p3_lock(&ni->obj_update);

	if (!(VALID_PTL_OBJ(&ni->md, mh->msg.ack.dst_md) &&
	      TST_OBJ(md=GET_PTL_OBJ(&ni->md,
								 mh->msg.ack.dst_md), OBJ_INUSE) &&
	      mh->msg.ack.dst_md_gen == md->generation)) {
		if (DEBUG_P3(ni->debug, PTL_DBG_MOVE))
			p3_print("parse_ack:" FMT_NIDPID " ack from"
					 FMT_NIDPID " references invalid MD %d\n",
					 ni->nid, ni->pid,
					 mh->src.nid, mh->src.pid, 
					 PTL_INDX(mh->msg.ack.dst_md));
		goto out_drop;
	}
	if (TST_OBJ(md, MD_INACTIVE)) {
		if (DEBUG_P3(ni->debug, PTL_DBG_MOVE))
			p3_print("parse_ack:" FMT_NIDPID " ack from"
					 FMT_NIDPID " references inactive MD %d\n",
					 ni->nid, ni->pid,
					 mh->src.nid, mh->src.pid, 
					 PTL_INDX(mh->msg.ack.dst_md));
		goto out_drop;
	}
	if (DEBUG_P3(ni->debug, PTL_DBG_MOVE)) {
		p3_print("parse_ack:" FMT_NIDPID " accept ACK from"
				 FMT_NIDPID " into MD %d (%p)\n",
				 ni->nid, ni->pid, mh->src.nid,
				 mh->src.pid, PTL_OBJ_INDX(md), md->start);
	}
	/* FIXME: If the msg allocation fails we really need to figure out
	 * how to finalize the message and deliver an event; normally we
	 * would use the msg we can't allocate to do that.  In the meantime,
	 * roll over and die, because otherwise we would violate Portals
	 * semantics.
	 */
	msg = msg_alloc(ni);
	if (!msg) {
		p3_print("parse_ack: ERROR: failed to allocate msg!\n");
		PTL_ROAD();
	}
	msg->md = md;
	msg->nal_msg_data = nal_msg_data;

	/* Hold the md while we post the ACK event. 
	 */
	md->pending++;

	/* We decrement the threshold because receiving the ACK may
	 * generate events, and is not a local operation (P3.3 API spec,
	 * section 3.10.1).
	 */
	md->threshold -= (md->threshold == PTL_MD_THRESH_INF) ? 0 : 1;
	if (md->threshold == 0)
		SET_OBJ(md, MD_INACTIVE);

	if (TST_OBJ(md, OBJ_UNLINK) && TST_OBJ(md, MD_INACTIVE))
		SET_OBJ(msg, MSG_DO_UNLINK);

	ni_stats_inc(ni, PTL_SR_RECV_COUNT, 1);

	if (!md->eq ||
	    (md->options & PTL_MD_EVENT_END_DISABLE &&
	     md->options & PTL_MD_EVENT_START_DISABLE))
		goto out;

	msg->ev.type = PTL_EVENT_ACK;
	msg->ev.initiator = mh->src;
	msg->ev.uid = mh->src_uid;
	msg->ev.jid = mh->src_jid;
	msg->ev.pt_index = (ptl_pt_index_t)(-1);
	msg->ev.match_bits = mh->mbits;
	msg->ev.rlength = 0;
	msg->ev.mlength = mh->length;
	msg->ev.offset = 0;
	msg->ev.hdr_data = 0;

	lib_md_2_api_md(md, &msg->ev.md);
	msg->ev.md_handle = PTL_OBJ_HNDL(md);

	/* Tell lib_finalize() to send an event, which in this case will be
	 * our ACK event, and an unlink event, if needed.
	 */
	SET_OBJ(msg, MSG_END_EV);
	md->eq->pending++;

	if (TST_OBJ(msg, MSG_DO_UNLINK)) {
		md->eq->pending++;
		SET_OBJ(msg, MSG_UNLINK_EV);
	}

out:
	p3_unlock(&ni->obj_update);
	
	if (PTL_UNLIKELY(is_same_process(mh->src.nid, mh->src.pid, 
									 mh->dst.nid, mh->dst.pid))) {
		lib_finalize(ni, msg, PTL_NI_OK);
	}
	else {
		ni->nal->recv(ni, nal_msg_data, msg, NULL, 0, 0, 0, 0, NULL);
	}
	return;

out_drop:
	p3_unlock(&ni->obj_update);
	
	if (PTL_LIKELY(!is_same_process(mh->src.nid, mh->src.pid, 
									mh->dst.nid, mh->dst.pid))) {
		ni->nal->recv(ni, nal_msg_data, NULL, NULL, 0, 0, 0, 0, NULL);
	}
	return;
}

static inline void
parse_local_put(lib_ni_t *ni, lib_msg_t *msg, unsigned long nal_msg_data,
				lib_md_t *md, ptl_size_t offset, ptl_size_t length)
{
	struct local_put_args *args = (struct local_put_args *)nal_msg_data;
	
	lib_copy_iov(ni, length, args->md->iov, args->md->iovlen, 
				 args->offset, NULL, md->iov, md->iovlen, offset, NULL);
	
	ptl_hdr_t hdr = msg->hdr;
	
	if (TST_OBJ(msg, MSG_SEND_ACK)) {
		/* the first call to the "lib_finalize" function 
		 * triggers the sending of the "ack" message. */
		lib_finalize(ni, msg, PTL_NI_OK);
	}
	/* the second call to the "lib_finalize" function triggers
	 * the PTL_EVENT_PUT_END event. */		
	lib_finalize(ni, msg, PTL_NI_OK);
	
	parse_ack(ni, &hdr, nal_msg_data);
}

static void
parse_put(lib_ni_t *ni, ptl_hdr_t *mh, unsigned long nal_msg_data)
{
	lib_md_t *md;
	ptl_size_t offset = 0, length = 0;
	lib_msg_t *msg;

	p3_lock(&ni->obj_update);

	md = lib_find_md(ni, mh, mh->msg.put.ptl_index, mh->msg.put.ac_index,
					 mh->mbits, mh->length, mh->msg.put.dst_offset,
					 &length, &offset);

	if (!md) {
		if (DEBUG_P3(ni->debug, PTL_DBG_DROP))
			p3_print("parse_put:" FMT_NIDPIDPTL " drop put from"
					 FMT_NIDPID FMT_LEN FMT_MBITS "\n",
					 ni->nid, ni->pid,
					 mh->msg.put.ptl_index, 
					 mh->src.nid, mh->src.pid,
					 mh->length, mh->mbits);
		goto out_drop;
	}
	if (DEBUG_P3(ni->debug, PTL_DBG_MOVE))
		p3_print("parse_put:" FMT_NIDPIDPTL " accept put from"
				 FMT_NIDPID FMT_RLEN FMT_MBITS 
				 " into MD %d (%p+"FMT_PSZ_T":"FMT_PSZ_T")\n",
				 ni->nid, ni->pid, mh->msg.put.ptl_index, 
				 mh->src.nid, mh->src.pid, mh->length,
				 mh->mbits, PTL_OBJ_INDX(md),
				 md->start, offset, length);

	/* FIXME: If the msg allocation fails we really need to figure out
	 * how to finalize the message and deliver an event; normally we
	 * would use the msg we can't allocate to do that.  In the meantime,
	 * roll over and die, because otherwise we would violate Portals
	 * semantics.
	 */
	msg = msg_alloc(ni);
	if (!msg) {
		p3_print("parse_put: ERROR: failed to allocate msg!\n");
		PTL_ROAD();
	}
	msg->md = md;
	msg->nal_msg_data = nal_msg_data;

	/* Hold the md while we receive the data.
	 */
	md->pending++;

	if ((mh->msg.put.ack_md != PTL_HANDLE_NONE) &&
	    !(md->options & PTL_MD_ACK_DISABLE)) {

		SET_OBJ(msg, MSG_SEND_ACK);
		msg->hdr.msg_type = PTL_MSG_ACK;
		msg->src = mh->src;
		msg->hdr.dst = mh->src;
		msg->hdr.src.nid = ni->nid;
		msg->hdr.src.pid = ni->pid;
		msg->hdr.msg.ack.dst_md = mh->msg.put.ack_md;
		msg->hdr.msg.ack.dst_md_gen = mh->msg.put.ack_md_gen;
		msg->hdr.length = length;
		msg->hdr.mbits = mh->mbits;
	}
	/* We decrement the threshold because receiving the message may
	 * generate events, and is not a local operation (P3.3 API spec,
	 * section 3.10.1).
	 */
	md->threshold -= (md->threshold == PTL_MD_THRESH_INF) ? 0 : 1;
	if (md->threshold == 0)
		SET_OBJ(md, MD_INACTIVE);

	if (TST_OBJ(md, OBJ_UNLINK) && TST_OBJ(md, MD_INACTIVE))
		SET_OBJ(msg, MSG_DO_UNLINK);

	ni_stats_inc(ni, PTL_SR_RECV_COUNT, 1);
	ni_stats_inc(ni, PTL_SR_RECV_LENGTH, length);

	if (!md->eq ||
	    (md->options & PTL_MD_EVENT_END_DISABLE &&
	     md->options & PTL_MD_EVENT_START_DISABLE))
		goto out;

	msg->ev.initiator = mh->src;
	msg->ev.uid = mh->src_uid;
	msg->ev.jid = mh->src_jid;
	msg->ev.pt_index = mh->msg.put.ptl_index;
	msg->ev.match_bits = mh->mbits;
	msg->ev.rlength = mh->length;
	msg->ev.mlength = length;
	msg->ev.offset = offset;
	msg->ev.hdr_data = mh->msg.put.hdr_data;

	lib_md_2_api_md(md, &msg->ev.md);
	msg->ev.md_handle = PTL_OBJ_HNDL(md);

	/* Tell lib_finalize() to send an end event, and an unlink event,
	 * if needed.  Then send start event, if needed.
	 */
	if (!(md->options & PTL_MD_EVENT_END_DISABLE)) {
		md->eq->pending++;
		SET_OBJ(msg, MSG_END_EV);
		msg->ev.type = PTL_EVENT_PUT_END;
	}
	if (TST_OBJ(msg, MSG_DO_UNLINK)) {
		md->eq->pending++;
		SET_OBJ(msg, MSG_UNLINK_EV);
	}
	if (!(md->options & PTL_MD_EVENT_START_DISABLE)) {
		md->eq->pending++;
		lib_event(ni, msg, md->eq->sequence,
			  PTL_EVENT_PUT_START, PTL_NI_OK);
	}
	else {		/* lib_event() drops the ni->obj_update lock, so we
				 * need to drop it if lib_event() isn't called, or
				 * if we jump here.
				 */
	out:
		p3_unlock(&ni->obj_update);
	}		

	if (PTL_UNLIKELY(is_same_process(mh->src.nid, mh->src.pid, 
									 mh->dst.nid, mh->dst.pid))) {
		parse_local_put(ni, msg, nal_msg_data, md, offset, length);
	}
	else {
		ni->nal->recv(ni, nal_msg_data, msg, md->iov, md->iovlen,
					  offset, length, mh->length, md->addrkey);
	}
	
	return;
out_drop:
	ni_stats_inc(ni, PTL_SR_DROP_COUNT, 1);
	ni_stats_inc(ni, PTL_SR_DROP_LENGTH, mh->length);

	p3_unlock(&ni->obj_update);
	if (PTL_LIKELY(!is_same_process(mh->src.nid, mh->src.pid, 
									mh->dst.nid, mh->dst.pid))) {
		ni->nal->recv(ni, nal_msg_data, NULL, NULL, 0, 0, 0, 
					  mh->length, NULL);
	}
	return;
}

static void
parse_reply(lib_ni_t *ni, ptl_hdr_t *mh, unsigned long nal_msg_data)
{
	lib_msg_t *msg;
	lib_md_t *md;
	ptl_size_t length, offset;
	ptl_handle_md_t dst_md_h = mh->msg.reply.dst_md;

	p3_lock(&ni->obj_update);

	if (!(VALID_PTL_OBJ(&ni->md, dst_md_h) &&
	      TST_OBJ(md=GET_PTL_OBJ(&ni->md, dst_md_h), OBJ_INUSE) &&
	      mh->msg.reply.dst_md_gen == md->generation)) {
		if (DEBUG_P3(ni->debug, PTL_DBG_MOVE))
			p3_print("parse_reply:" FMT_NIDPID " reply from"
					 FMT_NIDPID " references invalid MD %d\n",
					 ni->nid, ni->pid,
					 mh->src.nid, mh->src.pid, 
					 PTL_INDX(dst_md_h));
		goto out_drop;
	}

	if (TST_OBJ(md, MD_INACTIVE)) {
		if (DEBUG_P3(ni->debug, PTL_DBG_MOVE))
			p3_print("parse_reply:" FMT_NIDPID " reply from"
					 FMT_NIDPID " references inactive MD %d\n",
					 ni->nid, ni->pid,
					 mh->src.nid, mh->src.pid, 
					 PTL_INDX(dst_md_h));
		goto out_drop;
	}

	offset = mh->msg.reply.dst_offset;

	if (!(md->options & PTL_MD_TRUNCATE) &&
	    mh->length + offset > md->iov_dlen)
		goto out_drop;

	length = MIN(mh->length, md->iov_dlen - offset);

	if (DEBUG_P3(ni->debug, PTL_DBG_MOVE)) {
		p3_print("parse_reply:" FMT_NIDPID " accept reply from"
				 FMT_NIDPID FMT_RLEN
				 " into MD %d (%p+"FMT_PSZ_T":"FMT_PSZ_T")\n",
				 ni->nid, ni->pid, mh->src.nid,
				 mh->src.pid, mh->length, 
				 PTL_OBJ_INDX(md), md->start, offset, length);
	}
	/* FIXME: If the msg allocation fails we really need to figure out
	 * how to finalize the message and deliver an event; normally we
	 * would use the msg we can't allocate to do that.  In the meantime,
	 * roll over and die, because otherwise we would violate Portals
	 * semantics.
	 */
	msg = msg_alloc(ni);
	if (!msg) {
		p3_print("parse_reply: ERROR: failed to allocate msg!\n");
		PTL_ROAD();
	}
	msg->md = md;
	msg->nal_msg_data = nal_msg_data;

	/* Hold the md while we receive the reply.
	 */
	md->pending++;

	/* We decrement the threshold because sending the reply may
	 * generate events, and is not a local operation (P3.3 API spec,
	 * section 3.10.1).
	 */
	md->threshold -= (md->threshold == PTL_MD_THRESH_INF) ? 0 : 1;
	if (md->threshold == 0)
		SET_OBJ(md, MD_INACTIVE);

	if (TST_OBJ(md, OBJ_UNLINK) && TST_OBJ(md, MD_INACTIVE))
		SET_OBJ(msg, MSG_DO_UNLINK);

	ni_stats_inc(ni, PTL_SR_RECV_COUNT, 1);
	ni_stats_inc(ni, PTL_SR_RECV_LENGTH, length);

	if (!md->eq ||
	    (md->options & PTL_MD_EVENT_END_DISABLE &&
	     md->options & PTL_MD_EVENT_START_DISABLE))
		goto out;

	msg->ev.initiator = mh->src;
	msg->ev.uid = mh->src_uid;
	msg->ev.jid = mh->src_jid;
	msg->ev.pt_index = (ptl_pt_index_t)(-1);
	msg->ev.match_bits = 0;
	msg->ev.rlength = mh->length;
	msg->ev.mlength = length;
	msg->ev.offset = offset;
	msg->ev.hdr_data = 0;

	lib_md_2_api_md(md, &msg->ev.md);
	msg->ev.md_handle = PTL_OBJ_HNDL(md);

	/* Tell lib_finalize() to send an end event, and an unlink event,
	 * if needed.  Then send start event, if needed.
	 */
	if (!(md->options & PTL_MD_EVENT_END_DISABLE)) {
		md->eq->pending++;
		SET_OBJ(msg, MSG_END_EV);
		msg->ev.type = PTL_EVENT_REPLY_END;
	}
	if (TST_OBJ(msg, MSG_DO_UNLINK)) {
		md->eq->pending++;
		SET_OBJ(msg, MSG_UNLINK_EV);
	}
	if (!(md->options & PTL_MD_EVENT_START_DISABLE)) {
		md->eq->pending++;
		lib_event(ni, msg, md->eq->sequence,
			  PTL_EVENT_REPLY_START, PTL_NI_OK);
	}
	else {		/* lib_event() drops the ni->obj_update lock, so we
				 * need to drop it if lib_event() isn't called, or
				 * if we jump here.
				 */
	out:
		p3_unlock(&ni->obj_update);
	}
	
	if (PTL_UNLIKELY(is_same_process(mh->src.nid, mh->src.pid, 
									 mh->dst.nid, mh->dst.pid))) {
		lib_finalize(ni, msg, PTL_NI_OK);
	}
	else {
		ni->nal->recv(ni, nal_msg_data, msg, md->iov, md->iovlen,
					  offset, length, mh->length, md->addrkey);
	}
	
	return;
out_drop:
	ni_stats_inc(ni, PTL_SR_DROP_COUNT, 1);
	ni_stats_inc(ni, PTL_SR_DROP_LENGTH, mh->length);

	p3_unlock(&ni->obj_update);
	
	if (PTL_LIKELY(!is_same_process(mh->src.nid, mh->src.pid, 
									mh->dst.nid, mh->dst.pid))) {
		ni->nal->recv(ni, nal_msg_data, NULL, NULL, 0, 0, 0, 
					  mh->length, NULL);
	}
	return;
}

static inline void
parse_local_get(lib_ni_t *ni, lib_msg_t *msg, unsigned long nal_msg_data,
				lib_md_t *md, ptl_size_t offset, ptl_size_t length)
{
	lib_md_t *dst_md = (lib_md_t *)nal_msg_data;

	lib_copy_iov(ni, length, md->iov, md->iovlen, offset, NULL,
				 dst_md->iov, dst_md->iovlen, msg->hdr.msg.reply.dst_offset,
				 NULL);
	
	ptl_hdr_t hdr = msg->hdr;
	lib_finalize(ni, msg, PTL_NI_OK);
	
	parse_reply(ni, &hdr, nal_msg_data);
}

static void
parse_get(lib_ni_t *ni, ptl_hdr_t *mh, unsigned long nal_msg_data)
{
	lib_md_t *md;
	ptl_size_t offset = 0, length = 0;
	lib_msg_t *msg = NULL;

	p3_lock(&ni->obj_update);

	md = lib_find_md(ni, mh, mh->msg.get.ptl_index,
					 mh->msg.get.ac_index, mh->mbits,
					 mh->length, mh->msg.get.src_offset, &length, &offset);

	if (!md) {
		if (DEBUG_P3(ni->debug, PTL_DBG_DROP))
			p3_print("parse_get:" FMT_NIDPIDPTL " drop get from"
					 FMT_NIDPID FMT_RLEN FMT_MBITS "\n",
					 ni->nid, ni->pid,
					 mh->msg.get.ptl_index, 
					 mh->src.nid, mh->src.pid,
					 mh->length, mh->mbits);

		ni_stats_inc(ni, PTL_SR_DROP_COUNT, 1);
		ni_stats_inc(ni, PTL_SR_DROP_LENGTH, mh->length);
		goto out;
	}
	if (DEBUG_P3(ni->debug, PTL_DBG_MOVE))
		p3_print("parse_get:" FMT_NIDPIDPTL " accept get from"
				 FMT_NIDPID FMT_RLEN FMT_MBITS 
				 " into MD %d (%p+"FMT_PSZ_T":"FMT_PSZ_T")\n",
				 ni->nid, ni->pid, mh->msg.get.ptl_index, 
				 mh->src.nid, mh->src.pid, mh->length,
				 mh->mbits, PTL_OBJ_INDX(md),
				 md->start, offset, length);

	/* FIXME: If the msg allocation fails we really need to figure out
	 * how to finalize the message and deliver an event; normally we
	 * would use the msg we can't allocate to do that.  In the meantime,
	 * roll over and die, because otherwise we would violate Portals
	 * semantics.
	 */
	msg = msg_alloc(ni);
	if (!msg) {
		p3_print("parse_get: ERROR: failed to allocate msg!\n");
		PTL_ROAD();
	}
	msg->md = md;
	msg->nal_msg_data = nal_msg_data;
	
	/* Hold the md while we send the reply.
	 */
	md->pending++;

	msg->hdr.msg_type = PTL_MSG_REPLY;
	msg->hdr.dst = mh->src;
	msg->hdr.src_uid = ni->uid;
	msg->hdr.src.nid = ni->nid;
	msg->hdr.src.pid = ni->pid;
	msg->hdr.src_jid = ni->owner->jid;
	msg->hdr.msg.reply.dst_md = mh->msg.get.rtn_md;
	msg->hdr.msg.reply.dst_md_gen = mh->msg.get.rtn_md_gen;
	msg->hdr.length = length;
	msg->hdr.msg.reply.dst_offset = mh->msg.get.rtn_offset;

	/* We decrement the threshold because sending the reply may
	 * generate events, and is not a local operation (P3.3 API spec,
	 * section 3.10.1).
	 */
	md->threshold -= (md->threshold == PTL_MD_THRESH_INF) ? 0 : 1;
	if (md->threshold == 0)
		SET_OBJ(md, MD_INACTIVE);

	if (TST_OBJ(md, OBJ_UNLINK) && TST_OBJ(md, MD_INACTIVE))
		SET_OBJ(msg, MSG_DO_UNLINK);

	ni_stats_inc(ni, PTL_SR_SEND_COUNT, 1);
	ni_stats_inc(ni, PTL_SR_SEND_LENGTH, length);

	if (!md->eq ||
	    (md->options & PTL_MD_EVENT_END_DISABLE &&
	     md->options & PTL_MD_EVENT_START_DISABLE))
		goto out;

	msg->ev.initiator = mh->src;
	msg->ev.uid = mh->src_uid;
	msg->ev.jid = mh->src_jid;
	msg->ev.pt_index = mh->msg.get.ptl_index;
	msg->ev.match_bits = mh->mbits;
	msg->ev.rlength = mh->length;
	msg->ev.mlength = length;
	msg->ev.offset = offset;
	msg->ev.md_handle = PTL_OBJ_HNDL(md);
	msg->ev.hdr_data = 0;

	lib_md_2_api_md(md, &msg->ev.md);
	msg->ev.md_handle = PTL_OBJ_HNDL(md);

	/* Tell lib_finalize() to send an end event, and an unlink event,
	 * if needed.  Then send start event, if needed.
	 */
	if (!(md->options & PTL_MD_EVENT_END_DISABLE)) {
		md->eq->pending++;
		SET_OBJ(msg, MSG_END_EV);
		msg->ev.type = PTL_EVENT_GET_END;
	}
	if (TST_OBJ(msg, MSG_DO_UNLINK)) {
		md->eq->pending++;
		SET_OBJ(msg, MSG_UNLINK_EV);
	}
	if (!(md->options & PTL_MD_EVENT_START_DISABLE)) {
		md->eq->pending++;
		lib_event(ni, msg, md->eq->sequence, PTL_EVENT_GET_START, PTL_NI_OK);
	}
	else {		/* lib_event() drops the ni->obj_update lock, so we
				 * need to drop it if lib_event() isn't called, or
				 * if we jump here.
				 */
	out:
		p3_unlock(&ni->obj_update);
	}
	
	if (PTL_UNLIKELY(is_same_process(mh->src.nid, mh->src.pid, 
									 mh->dst.nid, mh->dst.pid))) {
		parse_local_get(ni, msg, nal_msg_data, md, offset, length);
	}
	else {		
		/* Complete the incoming message, which should have zero bytes.
		 * We have to wait until we're done with the message header the
		 * NAL gave us, because its storage might be associated with
		 * nal_msg_data, which this nal->recv call can destroy.
		 */
		ni->nal->recv(ni, nal_msg_data, NULL, NULL, 0, 0, 0, 0, NULL);

		if (msg)
			ni->nal->send(ni, &msg->nal_msg_data, msg, 
						  msg->hdr.dst, (lib_mem_t *)(&msg->hdr), 
						  sizeof(msg->hdr), md->iov, md->iovlen, offset, 
						  length, md->addrkey);
	}
	return;
}

static inline void
parse_local_getput(lib_ni_t *ni, lib_msg_t *msg, 
				   unsigned long nal_msg_data, lib_md_t *md, ptl_size_t length)
{
	lib_md_t **md_array = (lib_md_t **)nal_msg_data;
	ptl_hdr_t hdr;
	
	/* "lib_gpbuf_t:iov" always has exactly one entry. */		
	lib_copy_iov(ni, length, md_array[1]->iov, 
				 md_array[1]->iovlen, 0, NULL, &msg->buf->iov, 1, 0, NULL);
	
	hdr = msg->hdr;
	/* the first "lib_finalize" only sends the reply to the 
	 * initiator. */
	lib_finalize(ni, msg, PTL_NI_OK);
	
	/* memcpy the iov contents to the initiator. */
	lib_copy_iov(ni, length, &msg->buf->iov, 1, 
				 0, NULL, md_array[0]->iov, md_array[0]->iovlen, 0, NULL);
	
	/* the second "lib_finalize" actually destroys msg. */
	lib_finalize(ni, msg, PTL_NI_OK);
	
	parse_reply(ni, &hdr, nal_msg_data);
}


static void
parse_getput(lib_ni_t *ni, ptl_hdr_t *mh, unsigned long nal_msg_data)
{
	lib_md_t *md;
	ptl_size_t offset = 0, length = 0;
	lib_gpbuf_t *buf;
	lib_msg_t *msg;

	p3_lock(&ni->obj_update);

	md = lib_find_md(ni, mh, mh->msg.getput.ptl_index,
		mh->msg.getput.ac_index, mh->mbits,
		mh->length, mh->msg.getput.src_offset,
		&length, &offset);

	if (!md) {
		if (DEBUG_P3(ni->debug, PTL_DBG_DROP))
			p3_print("parse_getput:" FMT_NIDPIDPTL 
					 " drop getput from"
					 FMT_NIDPID FMT_RLEN FMT_MBITS "\n",
					 ni->nid, ni->pid,
					 mh->msg.get.ptl_index, 
					 mh->src.nid, mh->src.pid,
					 mh->length, mh->mbits);
		goto out_drop;
	}
	if (DEBUG_P3(ni->debug, PTL_DBG_MOVE))
		p3_print("parse_getput:" FMT_NIDPIDPTL " accept getput from"
				 FMT_NIDPID FMT_RLEN FMT_MBITS 
				 " into MD %d (%p+"FMT_PSZ_T":"FMT_PSZ_T")\n",
				 ni->nid, ni->pid,
				 mh->msg.getput.ptl_index, 
				 mh->src.nid, mh->src.pid, mh->length,
				 mh->mbits, PTL_OBJ_INDX(md),
				 md->start, offset, length);

	msg = msg_alloc(ni);
	buf = p3_malloc(sizeof(*msg->buf));
	if (!(msg && buf)) {
		p3_print("parse_getput: ERROR: failed to allocate msg!\n");
		if (buf)
			p3_free(buf);
		if (msg)
			ptl_obj_free(msg, ni);
		goto out_drop;
	}
	memset(buf, 0, sizeof(*msg->buf));
	msg->md = md;
	msg->nal_msg_data = nal_msg_data;

	/* Hold the md while we send the reply.
	 */
	md->pending++;

	msg->buf = buf;
	buf->src_os = offset;
	buf->iov.iov_base = buf->buf;
	buf->iov.iov_len = PTL_GETPUT_BUFLEN;

	SET_OBJ(msg, MSG_SEND_ACK);
	msg->hdr.msg_type = PTL_MSG_REPLY;
	msg->hdr.dst = mh->src;
	msg->hdr.src_uid = ni->uid;
	msg->hdr.src.nid = ni->nid;
	msg->hdr.src.pid = ni->pid;
	msg->hdr.src_jid = ni->owner->jid;
	msg->hdr.msg.reply.dst_md = mh->msg.getput.rtn_md;
	msg->hdr.msg.reply.dst_md_gen = mh->msg.getput.rtn_md_gen;
	msg->hdr.length = length;
	msg->hdr.msg.reply.dst_offset = mh->msg.getput.rtn_offset;

	md->threshold -= (md->threshold == PTL_MD_THRESH_INF) ? 0 : 1;
	if (md->threshold == 0)
		SET_OBJ(md, MD_INACTIVE);

	if (TST_OBJ(md, OBJ_UNLINK) && TST_OBJ(md, MD_INACTIVE))
		SET_OBJ(msg, MSG_DO_UNLINK);

	ni_stats_inc(ni, PTL_SR_SEND_COUNT, 1);
	ni_stats_inc(ni, PTL_SR_SEND_LENGTH, length);
	ni_stats_inc(ni, PTL_SR_RECV_COUNT, 1);
	ni_stats_inc(ni, PTL_SR_RECV_LENGTH, length);

	if (!md->eq ||
	    (md->options & PTL_MD_EVENT_END_DISABLE &&
	     md->options & PTL_MD_EVENT_START_DISABLE))
		goto out;

	msg->ev.initiator = mh->src;
	msg->ev.uid = mh->src_uid;
	msg->ev.jid = mh->src_jid;
	msg->ev.pt_index = mh->msg.getput.ptl_index;
	msg->ev.match_bits = mh->mbits;
	msg->ev.rlength = mh->length;
	msg->ev.mlength = length;
	msg->ev.offset = offset;
	msg->ev.md_handle = PTL_OBJ_HNDL(md);
	msg->ev.hdr_data = 0;

	lib_md_2_api_md(md, &msg->ev.md);
	msg->ev.md_handle = PTL_OBJ_HNDL(md);

	if (!(md->options & PTL_MD_EVENT_END_DISABLE)) {
		/*
		 * We won't actually send the end event until the reply
		 * finishes sending; see lib_finalize().
		 */
		md->eq->pending++;
		SET_OBJ(msg, MSG_END_EV);
		msg->ev.type = PTL_EVENT_GETPUT_END;
	}
	if (TST_OBJ(msg, MSG_DO_UNLINK)) {
		md->eq->pending++;
		SET_OBJ(msg, MSG_UNLINK_EV);
	}
	if (!(md->options & PTL_MD_EVENT_START_DISABLE)) {
		md->eq->pending++;
		lib_event(ni, msg, md->eq->sequence, PTL_EVENT_GETPUT_START, PTL_NI_OK);
	}
	else {		/* lib_event() drops the ni->obj_update lock, so we
				 * need to drop it if lib_event() isn't called, or
				 * if we jump here.
				 */
	out:
		p3_unlock(&ni->obj_update);
	}
	/* To be atomic, we receive into an buffer built into the msg object.
	 * Later, in lib_finalize when the receive is done, we'll swap
	 * the buffer contents with the MD contents, and send the result
	 * from the buffer.
	 */
	if (PTL_UNLIKELY(is_same_process(mh->src.nid, mh->src.pid, 
									 mh->dst.nid, mh->dst.pid))) {
		parse_local_getput(ni, msg, nal_msg_data, md, length);
	}
	else {		
		ni->nal->recv(ni, nal_msg_data, msg,
					  &msg->buf->iov, 1, 0, length, mh->length, NULL);
	}
	
	return;

out_drop:
	ni_stats_inc(ni, PTL_SR_DROP_COUNT, 1);
	ni_stats_inc(ni, PTL_SR_DROP_LENGTH, mh->length);

	p3_unlock(&ni->obj_update);
	if (PTL_LIKELY(!is_same_process(mh->src.nid, mh->src.pid, 
									mh->dst.nid, mh->dst.pid))) {
		ni->nal->recv(ni, nal_msg_data, NULL, NULL, 0, 0, 0, 
			mh->length, NULL);
	}
	
	return;
}

void print_msg_hdr(ptl_hdr_t *mh)
{
	p3_print("P3 header at %p: src" FMT_NIDPID " dst "FMT_NIDPID"\n",
			 mh, mh->src.nid, mh->src.pid, mh->dst.nid, mh->dst.pid);

	switch (mh->msg_type) {
	case PTL_MSG_ACK:
		p3_print("  Ack: dst MD %d" FMT_MLEN "\n",
				 mh->msg.ack.dst_md, mh->length);
		break;
	case PTL_MSG_PUT:
		p3_print("  Put Req: ptl %d ack MD %#08x" FMT_MBITS FMT_LEN
				 " os "FMT_PSZ_T " hdr data %#"PRIx64 "\n",
				 mh->msg.put.ptl_index, mh->msg.put.ack_md,
				 mh->mbits, mh->length,
				 mh->msg.put.dst_offset, mh->msg.put.hdr_data);
		break;
	case PTL_MSG_GET:
		p3_print("  Get Req: ptl %d rtn MD %#08x" FMT_MBITS FMT_LEN
				 " src os "FMT_PSZ_T " rtn os "FMT_PSZ_T "\n",
				 mh->msg.get.ptl_index, mh->msg.get.rtn_md,
				 mh->mbits, mh->length,
				 mh->msg.get.src_offset, mh->msg.get.rtn_offset);
		break;
	case PTL_MSG_GETPUT:
		p3_print("  GetPut Req: ptl %d rtn MD %#08x" FMT_MBITS
				 FMT_LEN " src os "FMT_PSZ_T " rtn os "
				 FMT_PSZ_T " hdr data %#"PRIx64 "\n",
				 mh->msg.getput.ptl_index, mh->msg.getput.rtn_md,
				 mh->mbits, mh->length,
				 mh->msg.getput.src_offset, mh->msg.getput.rtn_offset,
				 mh->msg.put.hdr_data);
		break;
	case PTL_MSG_REPLY:
		p3_print("  Reply: dst MD %d" FMT_MLEN
				 " dst os "FMT_PSZ_T "\n",
				 mh->msg.reply.dst_md, mh->length,
				 mh->msg.reply.dst_offset);
		break;
	default:
		p3_print( "  Unknown type %#x\n", mh->msg_type);
	}
}

int lib_parse(ptl_hdr_t *mh, unsigned long nal_msg_data,
			  ptl_interface_t type, ptl_size_t *drop_len)
{
	lib_ni_t *ni = p3lib_get_ni_pid(type, mh->dst.pid);

	if (DEBUG_P3(p3lib_debug, PTL_DBG_PARSE))
		p3_print("lib_parse: mh %p msg_data %#lx\n", mh, nal_msg_data);

	/* It doesn't matter if we lose this race; we could also
	 * lose if the NI got shut down just after we released the lock.
	 * This guarantees that during NAL shutdown, the NAL has to wait
	 * for at most the message it's currently receiving - anything
	 * coming in after that will get dropped.
	 */
	if (ni && !TST_OBJ(ni, OBJ_INUSE))
		ni = NULL;

	if (!ni || ni->nid != mh->dst.nid) {
		*drop_len = mh->length;
		goto drop;
	}
	*drop_len = 0;

	switch (mh->msg_type) {
	case PTL_MSG_ACK:
		parse_ack(ni, mh, nal_msg_data);
		return PTL_OK;
	case PTL_MSG_PUT:
		parse_put(ni, mh, nal_msg_data);
		return PTL_OK;
	case PTL_MSG_GET:
		parse_get(ni, mh, nal_msg_data);
		return PTL_OK;
	case PTL_MSG_GETPUT:
		parse_getput(ni, mh, nal_msg_data);
		return PTL_OK;
	case PTL_MSG_REPLY:
		parse_reply(ni, mh, nal_msg_data);
		return PTL_OK;
	}
	p3_print("lib_parse:" FMT_NIDPID ": ERROR: Header corrupted: "
		 "type %#x dst"FMT_NIDPID"\n", ni->nid, ni->pid,
		 mh->msg_type, mh->dst.nid, mh->dst.pid);

	/* There was something coming in, but we don't know what it was.
	 * Tell the NAL to clean up, anyway, as best as it is able.
	 */
	return PTL_FAIL;
drop:
	if (DEBUG_P3(p3lib_debug, PTL_DBG_DROP))
		p3_print("lib_parse: No match dst"FMT_NIDPID" (ni %p) "
			 "dropping "FMT_PSZ_T" bytes from"FMT_NIDPID"\n",
			 mh->dst.nid, mh->dst.pid, ni, (*drop_len),
			 mh->src.nid, mh->src.pid);
	return PTL_FAIL;
}

static inline int
process_local_put(lib_ni_t *ni, lib_msg_t *msg, lib_md_t *md,
				  ptl_size_t local_offset)
{
	struct local_put_args args;
	ptl_size_t drop_len;
	ptl_hdr_t hdr = msg->hdr;

	lib_finalize(ni, msg, PTL_NI_OK);
	
	args.md = md;
	args.offset = local_offset;
	return lib_parse(&hdr, (unsigned long)&args, 
					 ni->nal->nal_type->type, &drop_len);

}

int
lib_PtlPut(lib_ni_t *ni, 
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
		   int region)
{
	lib_md_t *md;
	lib_msg_t *msg = NULL;
	int status;
	
	p3_lock(&ni->obj_update);

	if (!(VALID_PTL_OBJ(&ni->md, md_handle) &&
	      TST_OBJ(md=GET_PTL_OBJ(&ni->md, md_handle), OBJ_INUSE) &&
	      !TST_OBJ(md, MD_INACTIVE))) {
		status = PTL_MD_INVALID;
		goto out_unlock;
	}
	/* P3.3 API spec, section 3.10.1
	 */
	if (TST_OBJ(md, MD_INACTIVE)) {
		status = PTL_OK;
		goto out_unlock;
	}
	/* P3.3 API spec, section 3.13.3
	 */
	if (region) {
		if (local_offset > md->iov_dlen || 
			local_len > md->iov_dlen - local_offset) {        	
			status = PTL_MD_ILLEGAL;
			goto out_unlock;
		}
	}
	else 
		local_len = md->iov_dlen - local_offset;

	if (DEBUG_P3(ni->debug, PTL_DBG_MOVE))
		p3_print("lib_PtlPut: " FMT_NIDPID " MD %d put to"
				 FMT_NIDPIDPTL FMT_MBITS "\n", ni->nid, ni->pid,
				 PTL_OBJ_INDX(md), target_id.nid,
				 target_id.pid, pt_index, match_bits);

	msg = msg_alloc(ni);
	if (!msg) {
		p3_print("lib_PtlPut: ERROR: failed to allocate msg!\n");
		status = PTL_NO_SPACE;
		goto out_unlock;
	}
	msg->md = md;

	/* Hold the md while we send the request/data.
	 */
	md->pending++;

	msg->hdr.msg_type = PTL_MSG_PUT;
	msg->hdr.dst = target_id;
	msg->hdr.src_uid = ni->uid;
	msg->hdr.src.nid = ni->nid;
	msg->hdr.src.pid = ni->pid;
	msg->hdr.src_jid = ni->owner->jid;
	msg->hdr.msg.put.ptl_index = pt_index;
	msg->hdr.msg.put.ac_index = ac_index;
	msg->hdr.mbits = match_bits;
	msg->hdr.length = local_len;
	msg->hdr.msg.put.dst_offset = remote_offset;
	msg->hdr.msg.put.hdr_data = hdr_data;

	msg->hdr.msg.put.ack_md =
		ack_req != PTL_NO_ACK_REQ ? md_handle : PTL_HANDLE_NONE;
	msg->hdr.msg.put.ack_md_gen = md->generation;

	/* We decrement the threshold because sending the message may
	 * generate events, and is not a local operation (P3.3 API spec,
	 * section 3.10.1).  We do it here because we won't have a chance
	 * to do it later, after we've passed the message to the NAL to send.
	 */
	md->threshold -= (md->threshold == PTL_MD_THRESH_INF) ? 0 : 1;
	if (md->threshold == 0)
		SET_OBJ(md, MD_INACTIVE);

	if (TST_OBJ(md, OBJ_UNLINK) && TST_OBJ(md, MD_INACTIVE))
		SET_OBJ(msg, MSG_DO_UNLINK);

	ni_stats_inc(ni, PTL_SR_SEND_COUNT, 1);
	ni_stats_inc(ni, PTL_SR_SEND_LENGTH, md->iov_dlen);

	if (!md->eq ||
	    (md->options & PTL_MD_EVENT_END_DISABLE &&
	     md->options & PTL_MD_EVENT_START_DISABLE))
		goto out;

	msg->ev.initiator.nid = ni->nid;
	msg->ev.initiator.pid = ni->pid;
	msg->ev.uid = ni->uid;
	msg->ev.jid = ni->owner->jid;
	msg->ev.pt_index = pt_index;
	msg->ev.match_bits = match_bits;
	msg->ev.rlength = local_len;
	msg->ev.mlength = local_len;
	msg->ev.offset = remote_offset;
	msg->ev.hdr_data = hdr_data;

	lib_md_2_api_md(md, &msg->ev.md);
	msg->ev.md_handle = PTL_OBJ_HNDL(md);

	/* Tell lib_finalize() to send an end event, and an unlink event,
	 * if needed.  Then send start event, if needed.
	 */
	if (!(md->options & PTL_MD_EVENT_END_DISABLE)) {
		md->eq->pending++;
		SET_OBJ(msg, MSG_END_EV);
		msg->ev.type = PTL_EVENT_SEND_END;
	}
	if (TST_OBJ(msg, MSG_DO_UNLINK)) {
		md->eq->pending++;
		SET_OBJ(msg, MSG_UNLINK_EV);
	}
	if (!(md->options & PTL_MD_EVENT_START_DISABLE)) {
		md->eq->pending++;
		lib_event(ni, msg, md->eq->sequence,
			  PTL_EVENT_SEND_START, PTL_NI_OK);
	}
	else {		/* lib_event() drops the ni->obj_update lock, so we
				 * need to drop it if lib_event() isn't called, or
				 * if we jump here.
				 */
	out:
		p3_unlock(&ni->obj_update);
	}
	
	if (PTL_UNLIKELY(is_same_process(ni->nid, ni->pid, 
									 target_id.nid, target_id.pid))) {
		status = process_local_put(ni, msg, md, local_offset);
	}
	else {
		status = ni->nal->send(ni, &msg->nal_msg_data, msg,  msg->hdr.dst,
							   (lib_mem_t *)(&msg->hdr), sizeof(msg->hdr),
							   md->iov, md->iovlen, local_offset, local_len,
							   md->addrkey);		
	}
	
	return status;

out_unlock:
	p3_unlock(&ni->obj_update);
	return status;
}

static inline int
process_local_get(lib_ni_t *ni, lib_msg_t *msg, lib_md_t *md)
{
	ptl_size_t drop_len;
	ptl_hdr_t hdr = msg->hdr;
	lib_finalize(ni, msg, PTL_NI_OK);
	
	return lib_parse(&hdr, (unsigned long)md,
					 ni->nal->nal_type->type, &drop_len);
}

int
lib_PtlGet(lib_ni_t *ni, 
		   ptl_handle_md_t md_handle,
		   ptl_process_id_t target_id,
		   ptl_pt_index_t pt_index,
		   ptl_ac_index_t ac_index,
		   ptl_match_bits_t match_bits,
		   ptl_size_t remote_offset,
		   ptl_size_t local_offset,
		   ptl_size_t local_len,
		   int region)
{
	lib_md_t *md;
	lib_msg_t *msg = NULL;
	int status;

	p3_lock(&ni->obj_update);

	if (!VALID_PTL_OBJ(&ni->md, md_handle) ||
	    !TST_OBJ(md=GET_PTL_OBJ(&ni->md, md_handle), OBJ_INUSE) ||
	    TST_OBJ(md, MD_INACTIVE)) {
		status = PTL_MD_INVALID;
		goto out_unlock;
	}
	/* P3.3 API spec, section 3.10.1
	 */
	if (TST_OBJ(md, MD_INACTIVE)) {
		status = PTL_OK;
		goto out_unlock;
	}
	/* P3.3 API spec, section 3.13.5
	 */
	if (region) {
		if (local_offset > md->iov_dlen ||
		    local_len > md->iov_dlen - local_offset) {
			status = PTL_MD_ILLEGAL;
			goto out_unlock;
		}
	}
	else 
		local_len = md->iov_dlen - local_offset;

	if (DEBUG_P3(ni->debug, PTL_DBG_MOVE))
		p3_print("lib_PtlGet: " FMT_NIDPID " MD %d get from"
				 FMT_NIDPIDPTL FMT_MBITS "\n",
				 ni->nid, ni->pid, PTL_OBJ_INDX(md),
				 target_id.nid, target_id.pid,
				 pt_index, match_bits);

	msg = msg_alloc(ni);
	if (!msg) {
		p3_print("lib_PtlGet: ERROR: failed to allocate msg!\n");
		status = PTL_NO_SPACE;
		goto out_unlock;
	}
	msg->md = md;

	/* Hold the md while we send the request.
	 */
	md->pending++;

	msg->hdr.msg_type = PTL_MSG_GET;
	msg->hdr.dst = target_id;
	msg->hdr.src_uid = ni->uid;
	msg->hdr.src.nid = ni->nid;
	msg->hdr.src.pid = ni->pid;
	msg->hdr.src_jid = ni->owner->jid;
	msg->hdr.msg.get.ptl_index = pt_index;
	msg->hdr.msg.get.ac_index = ac_index;
	msg->hdr.mbits = match_bits;
	msg->hdr.length = local_len;
	msg->hdr.msg.get.src_offset = remote_offset;
	msg->hdr.msg.get.rtn_offset = local_offset;
	msg->hdr.msg.get.rtn_md = md_handle;
	msg->hdr.msg.get.rtn_md_gen = md->generation;

	/* Note that sending a get request cannot generate events, so
	 * we don't decrement the md threshold.
	 */

	ni_stats_inc(ni, PTL_SR_SEND_COUNT, 1);

	p3_unlock(&ni->obj_update);
	
	if (PTL_UNLIKELY(is_same_process(ni->nid, ni->pid, 
									 target_id.nid, target_id.pid))) {
		status = process_local_get(ni, msg, md);
	}
	else {
		status = ni->nal->send(ni, &msg->nal_msg_data, msg, 
							   msg->hdr.dst, (lib_mem_t *)(&msg->hdr), 
							   sizeof(msg->hdr), NULL, 0, 0, 0, NULL);
	}
	
	return status;

out_unlock:
	p3_unlock(&ni->obj_update);
	return status;
}

static inline int
process_local_getput(lib_ni_t *ni, lib_msg_t *msg, lib_md_t *md_get,
	lib_md_t *md_put)
{
	ptl_size_t drop_len;
	ptl_hdr_t hdr = msg->hdr;
	lib_md_t *md_array[] = {md_get, md_put};
	
	lib_finalize(ni, msg, PTL_NI_OK);
	
	return lib_parse(&hdr, (unsigned long)md_array, 
					 ni->nal->nal_type->type, &drop_len);	
}

int
lib_PtlGetPut(lib_ni_t *ni, 
			  ptl_handle_md_t get_md_handle, 
			  ptl_handle_md_t put_md_handle,
			  ptl_process_id_t target_id, 
			  ptl_pt_index_t pt_index,
			  ptl_ac_index_t ac_index, 
			  ptl_match_bits_t match_bits,
			  ptl_size_t remote_offset, 
			  ptl_hdr_data_t hdr_data)
{
	lib_msg_t *msg = NULL;
	lib_md_t *gmd, *pmd;
	int status;

	p3_lock(&ni->obj_update);

	status = PTL_MD_INVALID;

	if (!VALID_PTL_OBJ(&ni->md, get_md_handle) ||
	    !TST_OBJ(gmd=GET_PTL_OBJ(&ni->md, get_md_handle), OBJ_INUSE) ||
	    TST_OBJ(gmd, MD_INACTIVE))
		goto out_unlock;
	
	if (!VALID_PTL_OBJ(&ni->md, put_md_handle) ||
	    !TST_OBJ(pmd=GET_PTL_OBJ(&ni->md, put_md_handle), OBJ_INUSE) ||
	    TST_OBJ(pmd, MD_INACTIVE)) 
		goto out_unlock;

	if (pmd->iov_dlen > (ptl_size_t)ni->limits.max_getput_md) {
		status = PTL_MD_ILLEGAL;
		goto out_unlock;
	}
	status = PTL_OK;

	/* P3.3 API spec, section 3.10.1
	 */
	if (TST_OBJ(gmd, MD_INACTIVE) || TST_OBJ(pmd, MD_INACTIVE))
		return status;

	if (DEBUG_P3(ni->debug, PTL_DBG_MOVE))
		p3_print("lib_PtlGetPut:"FMT_NIDPID" get MD %d put MD %d"
				 " getput from" FMT_NIDPIDPTL FMT_MBITS "\n", ni->nid,
				 ni->pid, PTL_OBJ_INDX(gmd), PTL_OBJ_INDX(pmd),
				 target_id.nid, target_id.pid,
				 pt_index, match_bits);

	msg = msg_alloc(ni);
	if (!msg) {
		p3_print("lib_PtlGetPut: ERROR: failed to allocate msg!\n");
		status = PTL_NO_SPACE;
		goto out_unlock;
	}
	msg->md = pmd;

	/* Hold the put md while we send the request/data.
	 */
	pmd->pending++;

	msg->hdr.msg_type = PTL_MSG_GETPUT;
	msg->hdr.dst = target_id;
	msg->hdr.src_uid = ni->uid;
	msg->hdr.src.nid = ni->nid;
	msg->hdr.src.pid = ni->pid;
	msg->hdr.src_jid = ni->owner->jid;
	msg->hdr.msg.getput.ptl_index = pt_index;
	msg->hdr.msg.getput.ac_index = ac_index;
	msg->hdr.mbits = match_bits;
	msg->hdr.length = pmd->iov_dlen;
	msg->hdr.msg.getput.src_offset = remote_offset;
	msg->hdr.msg.getput.hdr_data = hdr_data;
	msg->hdr.msg.getput.rtn_md = get_md_handle;
	msg->hdr.msg.getput.rtn_md_gen = gmd->generation;
	msg->hdr.msg.getput.rtn_offset = 0;

	/* We decrement the threshold because sending the message may
	 * generate events, and is not a local operation (P3.3 API spec,
	 * section 3.10.1).  We do it here because we won't have a chance
	 * to do it later, after we've passed the message to the NAL to send.
	 */
	pmd->threshold -= (pmd->threshold == PTL_MD_THRESH_INF) ? 0 : 1;
	if (pmd->threshold == 0)
		SET_OBJ(pmd, MD_INACTIVE);

	if (TST_OBJ(pmd, OBJ_UNLINK) && TST_OBJ(pmd, MD_INACTIVE))
		SET_OBJ(msg, MSG_DO_UNLINK);

	ni_stats_inc(ni, PTL_SR_SEND_COUNT, 1);
	ni_stats_inc(ni, PTL_SR_SEND_LENGTH, pmd->iov_dlen);

	/* Note: parse_reply takes care of events/unlinking for gmd.
	 */
	if (!pmd->eq ||
	    (pmd->options & PTL_MD_EVENT_END_DISABLE &&
	     pmd->options & PTL_MD_EVENT_START_DISABLE))
		goto out;

	msg->ev.initiator.nid = ni->nid;
	msg->ev.initiator.pid = ni->pid;
	msg->ev.uid = ni->uid;
	msg->ev.jid = ni->owner->jid;
	msg->ev.pt_index = pt_index;
	msg->ev.match_bits = match_bits;
	msg->ev.rlength = pmd->iov_dlen;
	msg->ev.mlength = pmd->iov_dlen;
	msg->ev.offset = remote_offset;
	msg->ev.hdr_data = hdr_data;

	lib_md_2_api_md(pmd, &msg->ev.md);
	msg->ev.md_handle = PTL_OBJ_HNDL(pmd);

	/* Tell lib_finalize() to send an end event, and an unlink event,
	 * if needed.  Then send start event, if needed.
	 */
	if (!(pmd->options & PTL_MD_EVENT_END_DISABLE)) {
		pmd->eq->pending++;
		SET_OBJ(msg, MSG_END_EV);
		msg->ev.type = PTL_EVENT_SEND_END;
	}
	if (TST_OBJ(msg, MSG_DO_UNLINK)) {
		pmd->eq->pending++;
		SET_OBJ(msg, MSG_UNLINK_EV);
	}
	if (!(pmd->options & PTL_MD_EVENT_START_DISABLE)) {
		pmd->eq->pending++;
		lib_event(ni, msg, pmd->eq->sequence,
				  PTL_EVENT_SEND_START, PTL_NI_OK);
	}
	else {		/* lib_event() drops the ni->obj_update lock, so we
				 * need to drop it if lib_event() isn't called, or
				 * if we jump here.
				 */
	out:
		p3_unlock(&ni->obj_update);
	}
	
	if (PTL_UNLIKELY(is_same_process(ni->nid, ni->pid, 
									 target_id.nid, target_id.pid))) {
		status = process_local_getput(ni, msg, gmd, pmd);
	}
	else {
		status = ni->nal->send(ni, &msg->nal_msg_data, msg, 
							   msg->hdr.dst, (lib_mem_t *)(&msg->hdr), 
							   sizeof(msg->hdr), pmd->iov, pmd->iovlen, 0, 
							   pmd->iov_dlen, pmd->addrkey);
	}
	
	return status;

out_unlock:
	p3_unlock(&ni->obj_update);
	return status;
}
