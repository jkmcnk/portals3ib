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

#include <p3utils.h>

/* Blocks until a successful handshake with a partner occurs.  This is
 * tricky because we don't know when we start if our partner is ready for
 * the handshake, and we need to be sure we don't violate the Portals
 * spec in the face of that.
 */
static
void partner_handshake(ptl_process_id_t src_id, ptl_process_id_t dst_id,
		       ptl_handle_ni_t ni_h, ptl_pt_index_t ptl, 
		       ptl_match_bits_t mbits, int ace)
{
	int rc, put, sent, ack, done;
	long token = 0;

	ptl_md_t md = {};
	ptl_event_t ev;
	ptl_handle_md_t md_h;
	ptl_handle_me_t me_h;
	ptl_ack_req_t need_ack;

	timeout_val_t t_o;
	int timeout_msec = 1000;

	md.start = &token;
	md.length = sizeof(token);
	md.threshold = PTL_MD_THRESH_INF;
	md.options =
		PTL_MD_OP_PUT | PTL_MD_OP_GET |
		PTL_MD_MANAGE_REMOTE |
		PTL_MD_EVENT_START_DISABLE;

	rc = PtlEQAlloc(ni_h, 8,
			PTL_EQ_HANDLER_NONE, &md.eq_handle);
	if (rc != PTL_OK) {
		fprintf(stderr, "PtlEQAlloc() failed: %s (%d)\n",
			PtlErrorStr(rc), rc);
		exit(EXIT_FAILURE);
	}
	rc = PtlMEAttach(ni_h, ptl, dst_id, mbits, 0,
			 PTL_RETAIN, PTL_INS_AFTER, &me_h);
	if (rc != PTL_OK) {
		fprintf(stderr, "PtlMEAttach: %s\n", PtlErrorStr(rc));
		exit(EXIT_FAILURE);
	}
	rc = PtlMDAttach(me_h, md, PTL_RETAIN, &md_h);
	if (rc != PTL_OK) {
		fprintf(stderr, "PtlMDAttach: %s\n", PtlErrorStr(rc));
		exit(EXIT_FAILURE);
	}
	put = done = 0;
	need_ack = PTL_ACK_REQ;
resend:
	sent = ack = 0;
	set_timeout(&t_o, timeout_msec);
	rc = PtlPutRegion(md_h, 0, sizeof(token), need_ack,
			  dst_id, ptl, ace, mbits, 0, 0);
	if (rc != PTL_OK) {
		fprintf(stderr, "PtlPutRegion: %s\n", PtlErrorStr(rc));
		exit(EXIT_FAILURE);
	}
eq_poll:
	rc = PtlEQGet(md.eq_handle, &ev);
	switch (rc) {
	case PTL_EQ_DROPPED:
	case PTL_OK:
		if (ev.ni_fail_type != PTL_NI_OK) {
			fprintf(stderr, "NI sent %s in event.\n",
				PtlNIFailStr(ni_h, ev.ni_fail_type));
			exit(EXIT_FAILURE);
		}
		if (ev.initiator.nid == dst_id.nid &&
		    ev.initiator.pid == dst_id.pid) {
			if (ev.type == PTL_EVENT_PUT_END)
				put = 1;
			else if (ev.type == PTL_EVENT_ACK)
				ack = 1;
		}
		else if (ev.initiator.nid == src_id.nid &&
			 ev.initiator.pid == src_id.pid &&
			 ev.type == PTL_EVENT_SEND_END)
			sent = 1;
		goto eq_poll;
	case PTL_EQ_EMPTY:
		break;
	default:
		fprintf(stderr, "PtlEQPoll: %s, NI status: %s\n",
			PtlErrorStr(rc), PtlNIFailStr(ni_h, ev.ni_fail_type));
		exit(EXIT_FAILURE);
	}
	/* We don't know our partner is there until we get his put, so put
	 * again to make sure he is ready to get ours.  We have to wait for
	 * the events from the put operation or we violate the Portals spec.
	 *
	 * Also, after we think we're done, our MD unlink may be racing
	 * with our partner's last put, so if the unlink is unsuccessful
	 * assume it's because the MD is busy receiving a put.  Otherwise
	 * we can delete an event queue out from under an active MD.
	 */
	if (!done) {
		if (put && sent && ack) {
			done = 1;
			need_ack = PTL_NO_ACK_REQ;
			clear_timeout(&t_o);
			goto resend;
		}
		if (test_timeout(&t_o))
			goto resend;
	}
	else if (sent) {
		rc = PtlMDUnlink(md_h);
		if (rc != PTL_OK) 
			goto eq_poll;

		rc = PtlMEUnlink(me_h);
		if (rc != PTL_OK) 
			goto eq_poll;

		rc = PtlEQFree(md.eq_handle);
		return;
	}
	goto eq_poll;
}
