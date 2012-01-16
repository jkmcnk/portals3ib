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

#include <unistd.h>
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
#include <p3api/misc.h>

#include <p3/lock.h>
#include <p3/handle.h>
#include <p3/process.h>
#include <p3/errno.h>
#include <p3/debug.h>

#include <p3lib/eq.h>
#include <p3lib/types.h>
#include <p3lib/p3lib.h>
#include <p3lib/nal.h>

#include <p3/obj_alloc.h>	/* MUST come after p3lib/p3lib.h */

/* Call holding ni->obj_update lock.  Returns with the lock dropped.
 *
 * FIXME: What is the proper recourse if this routine fails?
 */
int lib_event(lib_ni_t *ni, void *lib_data, ptl_seq_t link,
			  ptl_event_kind_t ev_type, ptl_ni_fail_t fail_type)
{
	ptl_event_kind_t et;

	lib_msg_t *msg = lib_data;
	ptl_event_t *ev = &msg->ev;
	lib_eq_t *eq;
	api_mem_t *slot;
	size_t os;

	if (!(msg && (eq = msg->md->eq))) {
		p3_unlock(&ni->obj_update);
		return PTL_OK;
	}
	et = ev->type;

	ev->sequence = eq->sequence++;
	ev->link = link;
	ev->type = ev_type;
	ev->ni_fail_type = fail_type;

	slot = eq->base + (ev->sequence % eq->entries) * sizeof(ptl_event_t);
	os = offsetof(ptl_event_t, sequence);

	if (DEBUG_P3(ni->debug, PTL_DBG_EVENT))
		p3_print("lib_event:"FMT_NIDPID" MD %d ev type %d NI "
				 "fail %d ev seq %d eq pnd %d md pnd %d\n",
				 ni->nid, ni->pid, PTL_OBJ_INDX(msg->md),
				 ev->type, ev->ni_fail_type, ev->sequence,
				 eq->pending-1, msg->md->pending);

	if (eq->pending == 0) {
		p3_print("lib_event: "FMT_NIDPID" Error: Negative events "
				 "pending on EQ %"PRIu32", (%p)\n",
				 ni->nid, ni->pid, PTL_OBJ_INDX(eq), eq);
	}
	else
		eq->pending--;

	/* Write the event, making sure the event sequence number gets
	 * written last, even if we're on a machine that reorders instructions.
	 *
	 * Drop the lock because copy_to_api might sleep.
	 */
	p3_unlock(&ni->obj_update);

	memcpy(slot, ev, os);
#ifdef PTL_PROGRESS_THREAD
	pthread_mutex_lock(&lib_event_mutex);
#endif /* PTL_PROGRESS_THREAD */
	memcpy(slot + os, (char *)ev + os, sizeof(ev->sequence));
#ifdef PTL_PROGRESS_THREAD
	lib_event_counter++;
	pthread_cond_broadcast(&lib_event_cond);
	pthread_mutex_unlock(&lib_event_mutex);
#endif /* PTL_PROGRESS_THREAD */

	ev->type = et;

	return PTL_OK;
}

int lib_finalize(lib_ni_t *ni, void *lib_data, ptl_ni_fail_t fail_type)
{
	lib_msg_t *msg = lib_data;
	lib_md_t *md;
	int rc = PTL_OK;

	if (!msg)
		return PTL_OK;

	/* It doesn't matter if we lose this race; we could also
	 * lose if the NI got shut down just after we released the lock.
	 *
	 * If we know the NI is down, fail the event so we won't queue
	 * a send for an ACK or a getput reply.  This guarantees that during
	 * NAL shutdown, that once a NAL has waited for the message it's 
	 * currently receiving to complete, no new work will be queued.
	 */
	if (!TST_OBJ(ni, OBJ_INUSE))
		fail_type = PTL_NI_FAIL;

	p3_lock(&ni->obj_update);

	if (!(md = msg->md))
		goto out_free;

	if (TST_OBJ(msg, MSG_SEND_ACK)) {

		lib_nal_t *nal = ni->nal;
		CLR_OBJ(msg, MSG_SEND_ACK);

		/* We're really sending a putget reply.
		 */
		if (msg->buf) {
			struct lib_gpbuf *mbuf = msg->buf;
			ptl_size_t len = msg->hdr.length;

			/* We don't want this temporary on the stack, and
			 * we're single-threaded here, so everyone can
			 * use the same one with no locking.
			 */
			static struct lib_gpbuf tmp;
			tmp.iov.iov_base = tmp.buf;
			tmp.iov.iov_len = PTL_GETPUT_BUFLEN;

			if (!(msg->md->options & PTL_MD_EVENT_END_DISABLE)) {
				/*
				 * We don't want to actually send the end
				 * event until we're done, which isn't 
				 * until the reply we're about to send is
				 * finished.  _That_ call of lib_finalize()
				 * will send the event.
				 */
				SET_OBJ(msg, MSG_END_EV);
			}
			/* If we can still send we shouldn't reply to
			 * a message we failed.
			 */
			if (fail_type != PTL_NI_OK)
				goto event;
			p3_unlock(&ni->obj_update);

			/* Swap the received data with the MD data, then
			 * send it.
			 */
			lib_copy_iov(ni, len,  &mbuf->iov, 1, 0, NULL,
						 &tmp.iov, 1, 0, NULL);
			lib_copy_iov(ni, len, md->iov, md->iovlen, 
						 mbuf->src_os, md->addrkey,
						 &mbuf->iov, 1, 0, NULL);
			lib_copy_iov(ni, len, &tmp.iov, 1, 0, NULL, md->iov,
						 md->iovlen, mbuf->src_os, md->addrkey);
#if 0
			/* enable this print statement for getput debugging
			 * using tests/locktest.c.  It's the only way you
			 * can tell on the lockmaster who actually got the
			 * lock.
			 */
			p3_print(FMT_NIDPID": got %u sent %u\n",
					 msg->hdr.dst.nid, msg->hdr.dst.pid,
					 *(unsigned *)md->iov->iov_base,
					 *(unsigned *)mbuf->iov.iov_base);
#endif
			if (DEBUG_P3(ni->debug, PTL_DBG_REQUEST))
				p3_print("lib_finalize:"FMT_NIDPID" MD %d "
						 "sending putget reply to"
						 FMT_NIDPID"\n", ni->nid, ni->pid,
						 PTL_OBJ_INDX(msg->md),
						 msg->hdr.dst.nid, msg->hdr.dst.pid);

			if (PTL_LIKELY(!is_same_process(msg->hdr.src.nid,
											msg->hdr.src.pid, 
											msg->hdr.dst.nid,
											msg->hdr.dst.pid))) {
				rc = nal->send(ni, &msg->nal_msg_data, msg,
							   msg->hdr.dst, (lib_mem_t *)(&msg->hdr),
							   sizeof(msg->hdr), &mbuf->iov, 1, 0,
							   len, NULL);
			}
		}
		/* Well, actually we're just sending an ack.  Don't send it
		 * unless fail_type == PTL_NI_OK; if we can still send we
		 * shouldn't ACK a message we failed.
		 */
		else {
			if (fail_type != PTL_NI_OK)
				goto event;
			p3_unlock(&ni->obj_update);

			if (DEBUG_P3(ni->debug, PTL_DBG_REQUEST))
				p3_print("lib_finalize:"FMT_NIDPID" MD %d "
						 "sending ACK to"FMT_NIDPID"\n",
						 ni->nid, ni->pid, 
						 PTL_OBJ_INDX(msg->md),
						 msg->hdr.dst.nid, msg->hdr.dst.pid);
			
			if (PTL_LIKELY(!is_same_process(msg->hdr.src.nid,
											msg->hdr.src.pid, 
											msg->hdr.dst.nid,
											msg->hdr.dst.pid))) {
				rc = nal->send(ni, &msg->nal_msg_data, msg,
							   msg->hdr.dst, (lib_mem_t *)(&msg->hdr),
							   sizeof(msg->hdr), NULL, 0, 0, 0, NULL);
			}
		}
		goto out;
	}
event:
	if (TST_OBJ(msg, MSG_END_EV)) {
		CLR_OBJ(msg, MSG_END_EV);
		rc = lib_event(ni, lib_data, msg->ev.sequence, msg->ev.type, fail_type);
		if (rc != PTL_OK) {
			rc = PTL_FAIL;
			p3_lock(&ni->obj_update);
			goto out_free;
		}
		else
			p3_lock(&ni->obj_update);
	}
	if (--md->pending == 0 && TST_OBJ(msg, MSG_DO_UNLINK)) {
		if (TST_OBJ(msg, MSG_UNLINK_EV))
			lib_event(ni, lib_data, msg->ev.sequence,
					  PTL_EVENT_UNLINK, PTL_NI_OK);
		p3_lock(&ni->obj_update);
		lib_md_unlink(ni, md);
	}
out_free:
	if (msg->buf)
		p3_free(msg->buf);

	if (DEBUG_P3(ni->debug, PTL_DBG_REQUEST))
		p3_print("lib_finalize:"FMT_NIDPID" MD %d "
				 "freeing lib msg struct @ %p\n",
				 ni->nid, ni->pid, PTL_OBJ_INDX(msg->md), msg);
	
	ptl_obj_free(msg, ni);
	p3_unlock(&ni->obj_update);
out:
	return rc;
}
