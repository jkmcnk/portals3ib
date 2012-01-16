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

#include <p3-config.h>

#include <stdlib.h>

#include <linux/list.h>

#include <portals3.h>
#include <p3utils.h>

#include <p3api/types.h>

#include <p3/lock.h>
#include <p3/handle.h>
#include <p3/process.h>

#include <p3lib/types.h>
#include <p3lib/p3lib.h>

#include "cnx.h"
#include "dbg.h"
#include "msg.h"
#include "cfg.h"

ibng_cnx_t *
ibng_cnx_create(struct ibv_context *ctx,
				struct ibv_pd *pd,
				struct ibv_cq *cq)
{
	ibng_cnx_t *cnx;

	cnx = malloc(sizeof(ibng_cnx_t));
	if(NULL == cnx)
		return NULL;

	bzero(cnx, sizeof(ibng_cnx_t));

	cnx->ctx = ctx;
	cnx->pd = pd;

	cnx->reqs_pending = ibng_iset_create(CNX_MAX_PENDING_REQS);
	if (cnx->reqs_pending == NULL) {
		IBNG_DBG("Failed to create reqs_pending.\n");
		goto fail_out;
	}

	cnx->send_list =
		ibng_req_list_create_with_buffers(ibng_config.n_send_buffers,
						  ibng_config.buffer_size,
						  cnx->pd,
						  SEND, cnx->reqs_pending);
	if (!cnx->send_list) {
		IBNG_DBG("Failed to create send_list.\n");
		goto fail_out;
	}

	cnx->recv_list =
		ibng_req_list_create_with_buffers(ibng_config.n_recv_buffers,
						  ibng_config.buffer_size,
						  cnx->pd,
						  RECV, cnx->reqs_pending);
	if (!cnx->recv_list) {
		IBNG_DBG("Failed to create recv_list.\n");
		goto fail_out;
	}

	cnx->rdma_list =
		ibng_req_list_create_with_rdma_requests(ibng_config.n_rdma_reqs,
							cnx->reqs_pending);
	if (!cnx->rdma_list) {
		IBNG_DBG("Failed to create rdma_list.\n");
		goto fail_out;
	}

	INIT_LIST_HEAD(&cnx->post_pending);
#ifdef PTL_PROGRESS_THREAD
	pthread_mutex_init(&cnx->lock, NULL);
#endif /* PTL_PROGRESS_THREAD */

	cnx->state = NEW;

	cnx->remote_pid.nid = PTL_NID_ANY;
	cnx->remote_pid.pid = PTL_PID_ANY;

	cnx->recvs_posted = cnx->sends_posted = 0;
	cnx->rdmas_out = 0;

	return cnx;

fail_out:
	ibng_cnx_destroy(cnx);

	return NULL;
}

void
ibng_cnx_destroy(ibng_cnx_t *cnx)
{
	IBNG_ASSERT(cnx->state == DISCONNECTED);

	if(NULL != cnx->rdma_list)
		ibng_req_list_destroy(cnx->rdma_list);
	if(NULL != cnx->recv_list)
		ibng_req_list_destroy(cnx->recv_list);
	if(NULL != cnx->send_list)
		ibng_req_list_destroy(cnx->send_list);
	if(NULL != cnx->reqs_pending)
		ibng_iset_destroy(cnx->reqs_pending);

#ifdef PTL_PROGRESS_THREAD
	pthread_mutex_destroy(&cnx->lock);
#endif /* PTL_PROGRESS_THREAD */

	free(cnx);
}

static inline ibng_buffer_t *
ibng_cnx_get_recv_buffer(ibng_cnx_t *cnx)
{
	ibng_buffer_t *buf;

	buf = (ibng_buffer_t *)ibng_req_list_pop(cnx->recv_list);
	if(NULL == buf) {
		return NULL;
	}

	IBNG_ASSERT(buf->req.state == FREE);

	buf->req.state = INUSE;
	buf->size = 0;
	buf->chdr = 0;
	buf->hdrsize = 0;
	buf->lib_data = buf->private = NULL; 

	IBNG_DBG("Get recv buffer: %p, %d\n", buf, (int)buf->req.key);

	return buf;
}

static inline void
ibng_cnx_put_recv_buffer(ibng_cnx_t *cnx, ibng_buffer_t *buf)
{
	IBNG_ASSERT(buf->req.type == RECV);
	IBNG_ASSERT(buf->req.state == INUSE);
	IBNG_DBG("Put recv buffer: %p, %d\n", buf, (int)buf->req.key);

	buf->req.state = FREE;
	ibng_req_list_append(cnx->recv_list, (ibng_req_t *)buf);
#ifdef DEBUG_PTL_INTERNALS
	/* poison members when releasing buf */
	buf->size = 0xdeadbeef;
	buf->chdr = 0xdeadbeef;
	buf->hdrsize = 0xf0f0f0f0f0f0f0f0ULL;
	buf->lib_data = buf->private = (void *)0xdeadbeef;
#endif /* DEBUG_PTL_INTERNALS */
}

static int
ibng_cnx_post_recv_buffer(ibng_cnx_t *cnx, ibng_buffer_t *buf)
{
	struct ibv_recv_wr *bad_wr;

	IBNG_ASSERT(buf->req.state == INUSE);

	IBNG_DBG("Posting buffer receive on cnx %p, buf %p, key %d...\n",
		 cnx, buf, buf->req.key);

	buf->private = cnx;
	buf->wr.r.wr_id = WRID_RECV(cnx, buf->req.key);
	if(ibv_post_recv(cnx->qp, &buf->wr.r, &bad_wr)) {
		ibng_cnx_put_recv_buffer(cnx, buf);
		IBNG_DBG("Posting failed.\n");
		return -1;
	}

	cnx->recvs_posted++;

	IBNG_DBG("POST receives posted on %p: %d\n", cnx, cnx->recvs_posted);

	return 0;
}

void
ibng_cnx_maintain_recv_buffers(ibng_cnx_t *cnx)
{
	ibng_cnx_lock(cnx);

	while(cnx->recvs_posted < ibng_config.n_recv_buffers) {
		ibng_buffer_t *buf = ibng_cnx_get_recv_buffer(cnx);
		if(NULL != cnx)
			ibng_cnx_post_recv_buffer(cnx, buf);
		else
			break;
	}

	ibng_cnx_unlock(cnx);
}

void
ibng_cnx_recycle_recv_buffer(ibng_cnx_t *cnx, ibng_buffer_t *buf)
{
	ibng_cnx_lock(cnx);

	if(cnx->state != DISCONNECTED &&
	   cnx->recvs_posted < ibng_config.n_recv_buffers) {
		/* repost buffer */
		if(ibng_cnx_post_recv_buffer(cnx, buf)) {
			/* failed, silently stash it back into recv buffer
			   list */
			ibng_cnx_put_recv_buffer(cnx, buf);
		}
	}
	else {
		/* sufficient receives posted: stash the buffer back into
		   recv buffer list */
		ibng_cnx_put_recv_buffer(cnx, buf);
	}

	ibng_cnx_unlock(cnx);
}

static int
post_receives(ibng_cnx_t *cnx, int n)
{
	ibng_buffer_t *buf;

	IBNG_DBG("Posting receive buffers ...\n");

	while((n > 0) &&
		  (buf = (ibng_buffer_t *)ibng_cnx_get_recv_buffer(cnx))) {
		if(ibng_cnx_post_recv_buffer(cnx, buf))
			return -1;
		n--;
	}

	return 0;
}

static int
send_buffer(ibng_cnx_t *cnx, ibng_buffer_t *buf)
{
	struct ibv_send_wr *bad_wr;
	
	IBNG_ASSERT(buf->req.state == INUSE);

	IBNG_DBG("Posting buffer send on cnx %p, buf %p, key %d ...\n",
			 cnx, buf, (int)buf->req.key);

	buf->private = cnx;
	buf->sge.length = buf->size;
	buf->wr.s.wr_id = WRID_SEND(cnx, buf->req.key);
	buf->wr.s.send_flags = IBV_SEND_SIGNALED |
		((buf->size <= ibng_config.max_inline)?IBV_SEND_INLINE:0);
	buf->wr.s.imm_data = buf->chdr;

	if(ibv_post_send(cnx->qp, &buf->wr.s, &bad_wr)) {
		IBNG_DBG("Posting failed.\n");
		ibng_cnx_put_send_buffer_now(cnx, buf);
		return -1;
	}
	IBNG_DBG("Send posted.\n");
	cnx->sends_posted++;
	return 0;
}

static int
rdma_read(ibng_cnx_t *cnx, ibng_rdma_req_t *rdma_req)
{
	struct ibv_send_wr *bad_wr;
	
	IBNG_DBG("Posting rdma read on cnx %p, buf %p, key %d ...\n",
			 cnx, rdma_req, rdma_req->req.key);

	if(ibv_post_send(cnx->qp, &(rdma_req->wr_list[0]), &bad_wr)) {
		IBNG_DBG("Posting failed.\n");
		ibng_cnx_put_rdma_req(cnx, rdma_req);
		return -1;
	}
	IBNG_DBG("RDMA read posted.\n");
	cnx->sends_posted++;
	cnx->rdmas_out++;
	return 0;	
}

static int
rdma_write(ibng_cnx_t *cnx, ibng_rdma_req_t *rdma_req)
{
	struct ibv_send_wr *bad_wr;
	
	IBNG_DBG("Posting rdma write on cnx %p, buf %p, key %d ...\n",
			 cnx, rdma_req, rdma_req->req.key);

	if(ibv_post_send(cnx->qp, &(rdma_req->wr_list[0]), &bad_wr)) {
		IBNG_DBG("Posting failed.\n");
		ibng_cnx_put_rdma_req(cnx, rdma_req);
		return -1;
	}
	IBNG_DBG("RDMA write posted.\n");
	cnx->sends_posted++;
	cnx->rdmas_out++;
	return 0;	
}

static inline
int can_post_send_p(ibng_cnx_t *cnx)
{
	/* TODO: optimize by taking into account request type (RDMA vs send) */
	return ((cnx->state == CONNECTED) &&
			(cnx->sends_posted < ibng_config.max_send_wrs) &&
			(cnx->rdmas_out < ibng_config.max_rdma_out));
}

int
ibng_cnx_post_pending_reqs(ibng_cnx_t *cnx)
{
	ibng_req_t *req;

	while(can_post_send_p(cnx) && !list_empty(&cnx->post_pending)) {
		req = list_entry(cnx->post_pending.next, ibng_req_t, link);
		list_del_init(&req->link);
		if (req->type == SEND) {
			if (send_buffer(cnx, (ibng_buffer_t *)req)) {
				return -1;
			}
		}
		else if (req->type == READ) {
			if (rdma_read(cnx, (ibng_rdma_req_t *)req)) {
				return -1;
			}
		}
		else if (req->type == WRITE) {
			if (rdma_write(cnx, (ibng_rdma_req_t *)req)) {
				return -1;
			}
		}
		else {
			/* undefined request type! this is unexpected 
			 * behaviour!!!!*/
			IBNG_ASSERT(0);
		}
	}

	return 0;
}

int
ibng_cnx_send(ibng_cnx_t *cnx, ibng_buffer_t *buf)
{
	int rv;

	ibng_cnx_lock(cnx);

	/* need to post possible pending send reqs first to maintain total
	   order */
	ibng_cnx_post_pending_reqs(cnx);

	if(!can_post_send_p(cnx)) {
		list_add_tail(&buf->req.link, &cnx->post_pending);
		rv = 0;
	}
	else
		rv = send_buffer(cnx, buf);

	ibng_cnx_unlock(cnx);

	return rv;
}

int
ibng_cnx_read(ibng_cnx_t *cnx, ibng_rdma_req_t *rr)
{
	int rv;

	rr->req.type = READ;
	rr->private = cnx;

	ibng_cnx_lock(cnx);

	/* need to post possible pending send reqs first to maintain total
	   order */
	ibng_cnx_post_pending_reqs(cnx);

	if(!can_post_send_p(cnx)) {
		list_add_tail(&rr->req.link, &cnx->post_pending);
		rv = 0;
	}
	else
		rv = rdma_read(cnx, rr);

	ibng_cnx_unlock(cnx);

	return rv;
}

int
ibng_cnx_write(ibng_cnx_t *cnx, ibng_rdma_req_t *rr)
{
	int rv;

	rr->req.type = WRITE;
	rr->private = cnx;
	
	ibng_cnx_lock(cnx);

	/* need to post possible pending send reqs first to maintain total
	   order */
	ibng_cnx_post_pending_reqs(cnx);

	if (!can_post_send_p(cnx)) {
		list_add_tail(&rr->req.link, &cnx->post_pending);
		rv = 0;		
	}
	else
		rv = rdma_write(cnx, rr);

	ibng_cnx_unlock(cnx);

	return rv;
}

static void
free_req(ibng_cnx_t *cnx, ibng_req_t *req)
{
	switch(req->type) {
	case SEND:
		IBNG_ASSERT(cnx->sends_posted > 0);
		cnx->sends_posted--;
		ibng_req_list_append(cnx->send_list, req);
		break;
	case RECV:
		IBNG_ASSERT(cnx->recvs_posted > 0);
		ibng_req_list_append(cnx->recv_list, req);
		cnx->recvs_posted--;
		break;
	case READ:
	case WRITE:
		IBNG_ASSERT(cnx->rdmas_out > 0);
		ibng_req_list_append(cnx->rdma_list, req);
		cnx->rdmas_out--;
		break;
	default:
		break;
	}
}

static void
ibng_cnx_cancel(ibng_cnx_t *cnx)
{
	int el;
	ibng_req_t *req;

	while(!list_empty(&cnx->post_pending)) {
        req = list_entry(cnx->post_pending.next, ibng_req_t, link);
        list_del_init(&req->link);
		free_req(cnx, req);
	}
	for(el = 0; el < cnx->reqs_pending->size; el++) {
		if(cnx->reqs_pending->els[el] > (void *)CNX_MAX_PENDING_REQS) {
			req = (ibng_req_t *)cnx->reqs_pending->els[el];
			if(list_empty(&req->link))
				free_req(cnx, req);
		}
	}
}

/**
 * Change the state of the connection.
 */
int 
ibng_cnx_set_state(ibng_cnx_t *cnx, ibng_cnx_state_t new_state)
{
	int rv;

	ibng_cnx_lock(cnx);

	IBNG_DBG("Setting cnx %p state: old %d, new %d\n",
			 cnx, cnx->state, new_state);

	if(cnx->state == new_state)
		goto out;

	if(new_state == CONNECTING) {
		IBNG_ASSERT(cnx->state == NEW);
		cnx->state = new_state;
		post_receives(cnx, ibng_config.n_recv_buffers);
	}
	else if(new_state == CONNECTED) {
		IBNG_ASSERT(cnx->state == CONNECTING);
		cnx->state = new_state;
		ibng_cnx_post_pending_reqs(cnx);
	}
	else if(new_state == DISCONNECTED) {
		/* we can move to disconnected state from wherever */
		cnx->state = new_state;

#ifdef PTL_IBNG_CMA
		if((rv = rdma_disconnect(cnx->cma_id))) {
			IBNG_ERROR("CMA disconnect failed (%d)!\n", rv);		
			goto out;
		}
		if(NULL != cnx->qp)
			rdma_destroy_qp(cnx->cma_id);
		if(NULL != cnx->cma_id)
			rdma_destroy_id(cnx->cma_id);
#else /* !PTL_IBNG_CMA */
		if ((rv = ib_cm_send_dreq(cnx->cm_id, NULL, 0))) {
			IBNG_ERROR("CM disconnect request sending failed (%d)!\n", rv);
			goto out;
		}
		if(NULL != cnx->qp)
			ibv_destroy_qp(cnx->qp);
		if(NULL != cnx->cm_id)
			ib_cm_destroy_id(cnx->cm_id);
#endif /* PTL_IBNG_CMA */

		ibng_cnx_cancel(cnx);		
	}

 out:
	ibng_cnx_unlock(cnx);

	return 0;
}

int
ibng_cnx_process_header(ibng_cnx_t *cnx, ibng_buffer_t *buf)
{
	ptl_hdr_t hdr;
	ptl_size_t drop_size;
	uint8_t cmd;

	IBNG_DBG("Completed recv.\n");

	bzero(&hdr, sizeof(ptl_hdr_t));

	buf->hdrsize = msg_unpack_header(&hdr, buf, cnx);

	IBNG_ASSERT((buf->size >= 2) && (buf->hdrsize >= 2) &&
			(buf->size >= buf->hdrsize));

	IBNG_DBG("Processing header: cmd %d, incoming key %d\n",
		 (int)HDR_GET_CMDID(buf->chdr), (int)EHDR_GET_KEY(buf));

	/* lib parse will call the NAL receive eventually (TODO: check if it
	   is called every time) */
	lib_parse(&hdr, (unsigned long)buf, cnx->srv->iface, &drop_size);

	cmd = HDR_GET_CMDID(buf->chdr);
	if(cmd == PTL_MSG_ACK || cmd == PTL_MSG_REPLY) {
		/* need to recycle the original send buffer that caused this
		   ack/reply */
		uint16_t key = EHDR_GET_KEY(buf);
		ibng_buffer_t *obuf = 
			(ibng_buffer_t *)ibng_iset_el(cnx->reqs_pending, key);
		ibng_cnx_put_send_buffer(cnx, obuf);
		IBNG_DBG("Release send buffer (after reply).\n");
	}

	IBNG_DBG("Drop size: " FMT_PSZ_T "\n", drop_size);

	return 0;
}

int
ibng_cnx_start_recv(ibng_cnx_t *cnx, void *lib_data,
					ptl_md_iovec_t *dst_iov,
					ptl_size_t iovlen,
					ptl_size_t offset,
					ptl_size_t mlen,
					ptl_size_t rlen) {
	IBNG_DBG("Starting receive for lib_data %p, mlen " FMT_PSZ_T ", rlen "
             FMT_PSZ_T "\n", lib_data, mlen, rlen);
	cnx->lib_data = lib_data;
	cnx->dst_iov = dst_iov;
	cnx->dst_iov_len = iovlen;
	cnx->dst_offset = offset;
	cnx->dst_mlen = mlen;
	cnx->dst_rlen = rlen;

	return 0;
}

static inline ptl_size_t
copy_to_iov(ptl_md_iovec_t *iov, ptl_size_t iovlen, ptl_size_t offset,
			ptl_size_t len, char *src, ptl_size_t buf_len)
{
	/* TODO: check for overflow of bufsize */
	ptl_size_t done = 0, i = 0, clen = 0;
	char *base;

	while(i < iovlen) {
		if(iov[i].iov_len > offset) {
			base = iov[i].iov_base + offset;
			clen = iov[i].iov_len - offset;
			offset = 0;
			break;
		}
		i++;
		offset -= iov[i].iov_len;
	}

	while(i < iovlen && done < len && done < buf_len) {
		if(done + clen > len)
			clen = len - done;
		if(done + clen > buf_len)
			clen = buf_len - done;
		memcpy(base, src + done, clen);
		done += clen;
		i++;
		if(i >= iovlen)
			break;
		base = iov[i].iov_base;
		clen = iov[i].iov_len;
	}

	return done;
}

int
ibng_cnx_cont_recv(ibng_cnx_t *cnx, void *buf, ptl_size_t buf_len)
{
	ptl_size_t clen, mlen;

	IBNG_ASSERT(buf_len <= cnx->dst_rlen);

	IBNG_DBG("Continuing receive for lib_data %p, mlen " FMT_PSZ_T ", rlen "
             FMT_PSZ_T ": recv " FMT_PSZ_T "\n",
             cnx->lib_data, cnx->dst_mlen, cnx->dst_rlen, buf_len);

	if(cnx->dst_mlen > 0) {
		IBNG_ASSERT(cnx->dst_iov != NULL);

		mlen = buf_len;
		if(mlen > cnx->dst_mlen)
			mlen = cnx->dst_mlen;
		clen = copy_to_iov(cnx->dst_iov, cnx->dst_iov_len,
						   cnx->dst_offset, cnx->dst_mlen,
						   buf, mlen);
		cnx->dst_mlen -= clen;
		cnx->dst_offset += clen;
		/* TODO: optimizable by changing iov ptr and len, instead of
		   increasing the offset (avoids skipping the offset bytes
		   prior to copying data in next copy_to_iovs() invocation) */
	}

	cnx->dst_rlen -= buf_len;
	if(cnx->dst_rlen == 0) {
		lib_finalize(cnx->srv->ni, cnx->lib_data, PTL_NI_OK);
		cnx->lib_data = NULL;
	}

	return 0;
}

#ifdef DEBUG_PTL_INTERNALS
void
ibng_cnx_dump(ibng_cnx_t *cnx)
{
	IBNG_DBG_A("Cnx %p\n", cnx);
	IBNG_DBG_A("  Remote PID: (%u, %u)\n",
			   cnx->remote_pid.nid, cnx->remote_pid.pid);
	IBNG_DBG_A("  Remote UID: %u\n", cnx->remote_uid);
	IBNG_DBG_A("  Remote JID: %u\n", cnx->remote_jid);
	IBNG_DBG_A("  State:	  %u\n", cnx->state);
	IBNG_DBG_A("  Send list:\n");
	IBNG_DBG_A("	Current: %u\n", cnx->send_list->current);
	IBNG_DBG_A("	Total:	 %u\n", cnx->send_list->total);
	IBNG_DBG_A("  Recv list:\n");
	IBNG_DBG_A("	Current: %u\n", cnx->recv_list->current);
	IBNG_DBG_A("	Total:	 %u\n", cnx->recv_list->total);
	IBNG_DBG_A("  RDMA list:\n");
	IBNG_DBG_A("	Current: %u\n", cnx->rdma_list->current);
	IBNG_DBG_A("	Total:	 %u\n", cnx->rdma_list->total);
	IBNG_DBG_A("  Request slots available: %u\n", cnx->reqs_pending->free);
	IBNG_DBG_A("  Receive requests posted: %u\n", cnx->recvs_posted);
	IBNG_DBG_A("  Currently receiving message: %p\n", cnx->lib_data);
	/* TODO: dump IB stuff */
}
#endif /* DEBUG_PTL_INTERNALS */
