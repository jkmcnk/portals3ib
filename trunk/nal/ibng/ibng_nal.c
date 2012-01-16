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
#include <string.h>

#include <linux/list.h>

#include <portals3.h>
#include <p3utils.h>

#include <p3/obj_alloc.h>

#include <p3api/types.h>

#include <p3/lock.h>
#include <p3/handle.h>
#include <p3/process.h>

#include <p3lib/types.h>
#include <p3lib/nal.h>

#include "ibng_nal.h"
#include "srv.h"
#include "dbg.h"
#include "msg.h"

#define IBNG_GET_SRV(ni) ((ibng_server_t *)ni->nal->private)

/* we support a maximum of 255 portals and ACs per process: this way we
   can stash this info in 16 bits. 16 more bits for command ID and flags
   allows us to stash the whole common header into the IMM field of the
   IB header.
   Valid indices are 0 .. 254, 255 is used to denote INVALID index.
*/
#define IBNG_MAX_PTLS 255
#define IBNG_MAX_ACS  255

static
ptl_ni_limits_t ibng_limits =
{
	.max_mes = INT_MAX,
	.max_mds = INT_MAX,
	.max_eqs = INT_MAX,
	.max_ac_index = IBNG_MAX_ACS,
	.max_pt_index = IBNG_MAX_PTLS,
	.max_md_iovecs = INT_MAX,
	.max_me_list = INT_MAX,
	.max_getput_md = INT_MAX
};

#ifdef DEBUG_PTL_INTERNALS
static ibng_server_t *dbg_srv = NULL;
#endif /* DEBUG_PTL_INTERNALS */

static char *
get_iface(void) {
	return getenv("PTL_IFACE");
}

static inline int
mr_register_p(ibng_server_t *srv, api_mem_t *base, size_t extent)
{
	/* this predicate decides whether a buffer should be registered as a
	   MR (needed for rendezvous transfers), or not (in case of eager
	   transfer); currently decision is made based on size, but could
	   be an arbitrarily complex condition */
	return (extent > srv->max_eager_size);
}

static inline int
buf_frag_p(ibng_buffer_t *buf, ptl_size_t msglen)
{
	/* this predicate decides whether a message of given size needs
	   fragmentation */
	return (msglen > (buf->max_size - EHDR_MAX_SIZE));
}

static int
recv_put_rdma(ibng_server_t *srv, ibng_cnx_t *cnx, ibng_buffer_t *buf,
			  void *lib_data,
			  ptl_md_iovec_t *dst_iov,
			  ptl_size_t iovlen,
			  ptl_size_t offset,
			  ptl_size_t len,
			  void *addrkey)
{
	uint16_t key = EHDR_GET_KEY(buf);
	ibng_rdma_req_t *rreq = NULL;
	ibng_buffer_t *nbuf = NULL;

	if(len > 0) {
		rreq = ibng_cnx_get_rdma_req(cnx);
		if(NULL == rreq) {
			IBNG_DBG("Failed to get RDMA request.\n");
			return -1;
		}

		if(msg_unpack_rdma(buf->buffer + buf->hdrsize,
						   IBV_WR_RDMA_READ,
						   dst_iov, iovlen, offset, len,
						   cnx, (ibng_reg_key_t *)addrkey, rreq)) {
			IBNG_DBG("Failed to unpack RDMA info.\n");
			goto fail_out;
		}
		rreq->lib_data = lib_data;
		rreq->private = cnx;

		ibng_rdma_req_dump(rreq);
	
		if(ibng_cnx_read(cnx, rreq)) {
			IBNG_DBG("Failed to post a RDMA read.\n");
			goto fail_out;
		}
		rreq = NULL;
	}
	else {
		lib_finalize(srv->ni, lib_data, PTL_NI_OK);
	}
	
	nbuf = ibng_cnx_get_send_buffer(cnx);
	if(NULL == nbuf) {
		IBNG_DBG("Failed to get send buffer.\n");
		goto fail_out;
	}

	msg_pack_rdma_done(nbuf, key);
	if(ibng_cnx_send(cnx, nbuf)) {
		IBNG_DBG("Failed to send RDMA done.\n");
		goto fail_out;
	}
	nbuf = NULL;

	return 0;

 fail_out:
	if(NULL != rreq)
		ibng_cnx_put_rdma_req(cnx, rreq);
	if(NULL != nbuf)
		ibng_cnx_put_send_buffer_now(cnx, nbuf);

	return -1;
}

ptl_nid_t
p3ibng_my_nid(void)
{
	return ibng_server_get_local_nid(get_iface());
}

/* ---- lib NAL interface --- */
static int
p3ibng_recv(lib_ni_t *ni,
			unsigned long nal_msg_data,
			void *lib_data,
			ptl_md_iovec_t *dst_iov,
			ptl_size_t iovlen,
			ptl_size_t offset,
			ptl_size_t mlen,
			ptl_size_t rlen,
			void *addrkey)
{
	/* mlen: length to transfer to MD; rlen: length of incoming data 
	   to receive; rlen - mlen: length of data to drop */
	ibng_server_t *srv = IBNG_GET_SRV(ni);
	ibng_req_t *req = (ibng_req_t *)nal_msg_data;
	ibng_cnx_t *cnx;
	ibng_buffer_t *buf;
	uint8_t flags, cmdid;
	int rv = PTL_OK;

	IBNG_DBG("Receive for request key %d\n", req->key);
	IBNG_DBG("Offset: " FMT_PSZ_T ", mlen " FMT_PSZ_T ", rlen " FMT_PSZ_T "\n",
			 offset, mlen, rlen);

	buf = (ibng_buffer_t *)req;
	cnx = (ibng_cnx_t *)buf->private;
	flags = HDR_GET_FLAGS(buf->chdr);
	cmdid = HDR_GET_CMDID(buf->chdr);

	if(flags & HDR_F_RDMA) {
		/* RDMA flag set */
		if(cmdid == PTL_MSG_PUT) {
			/* parse info and post a RDMA read */
			IBNG_DBG("RDMA data for put.\n");
			if(recv_put_rdma(srv, cnx, buf, lib_data,
							 dst_iov, iovlen, offset, mlen,
							 addrkey)) {
				rv = PTL_FAIL;
				goto fail_out;
			}
		}
		else if(cmdid == PTL_MSG_GET) {
			/* a subsequent send will parse info and post a RDMA write */
			IBNG_DBG("RDMA data for get.\n");
		}
		else if(cmdid == PTL_MSG_GETPUT) {
			/* getput is only supported with eager protocol */
			IBNG_DBG("RDMA data for getput.\n");
			IBNG_ASSERT(0);
		}
		else if (cmdid == PTL_MSG_REPLY) {
			/* reply is used as a signal of finished write on the initiator
			   side: just need to finalize the message */
			IBNG_DBG("RDMA GET reply.\n");
			lib_finalize(ni, lib_data, PTL_NI_OK);
		}
		else {
			/* no other commands may have RDMA flag set: if this
			   occurs, we're best off rolling over and dying */
			PTL_ROAD();
		}
	}
	else {
		if(rlen > 0) {
			/* receive data in payload */
			ibng_cnx_start_recv(cnx, lib_data, dst_iov, iovlen, offset,
								mlen, rlen);
			ibng_cnx_cont_recv(cnx, buf->buffer + buf->hdrsize,
							   buf->size - buf->hdrsize);
		}
		else if(rlen == 0) {
			/* get triggers a receive with rlen == 0 before
			   triggering another send (sending the data):
			   we must NOT finalize the message yet, otherwise
			   we trigger Portals events too early. */
			if(cmdid != PTL_MSG_GET)
				lib_finalize(ni, lib_data, PTL_NI_OK);
		}
	}

fail_out:
	IBNG_ASSERT(buf->req.type == RECV);
	
	/* TODO: review the recycling condition */
	if (!((flags & HDR_F_RDMA) && cmdid == PTL_MSG_GET) || rv != PTL_OK) {
		/* do not recycle the buffer for the "get" operations because
		 * it will be needed when performing the RDMA send. */
		ibng_cnx_recycle_recv_buffer(cnx, buf);
	}

	IBNG_PTL_RET(rv);
}

static int
send_eager(ibng_server_t *srv, ibng_cnx_t *cnx, ibng_buffer_t *buf, 
		   int whdrsize, ptl_md_iovec_t *src_iov, ptl_size_t iovlen, 
		   ptl_size_t offset, ptl_size_t len, void *addrkey,
		   unsigned long *nal_msg_data, void *lib_data, int frag)
{
	int payload_len;
	
	/* pack payload */
	if((payload_len =
		msg_pack_data(buf->buffer + whdrsize,
			  buf->max_size - whdrsize,
			  src_iov, iovlen, offset, len)) < 0) {
		IBNG_DBG("Failed to pack eager data.\n");
		IBNG_PTL_RET(PTL_NO_SPACE);
	}
		
	buf->size = whdrsize + payload_len;

	*nal_msg_data = (unsigned long)buf;

	/* in case of fragmentation, send more */
	len -= payload_len;
	offset += payload_len;

	if(len == 0)
		buf->lib_data = lib_data;

	IBNG_DBG("Sending first packet: header %d, payload %d\n",
		 whdrsize, payload_len);

	/* send */
	if(ibng_cnx_send(cnx, buf)) {
		IBNG_DBG("Failed to post send of a buffer.\n");
		IBNG_PTL_RET(PTL_UNKNOWN_ERROR);
	}

	IBNG_DBG("Sent first packet, len " FMT_PSZ_T " remaining\n", len);
	while(len > 0) {
		IBNG_ASSERT(frag);
		buf = ibng_cnx_get_send_buffer(cnx);
		if(NULL == buf) {
			IBNG_DBG("No buffers left.\n");
			IBNG_PTL_RET(PTL_NO_SPACE);
		}
		if((payload_len =
			msg_pack_data(buf->buffer, buf->max_size,
				  src_iov, iovlen, offset, len)) < 0) {
			IBNG_DBG("Failed to pack eager data.\n");
			IBNG_PTL_RET(PTL_UNKNOWN_ERROR);
		}
		buf->size = payload_len;
		len -= payload_len;
		offset += payload_len;
		if(len == 0)
			buf->lib_data = lib_data;
		IBNG_DBG("Sent next packet, len " FMT_PSZ_T " remaining\n", len);
		if(ibng_cnx_send(cnx, buf)) {
			IBNG_DBG("Failed to post send of a buffer.\n");
			ibng_cnx_put_send_buffer_now(cnx, buf);
			IBNG_PTL_RET(PTL_UNKNOWN_ERROR);
		}
	}
	
	IBNG_PTL_RET(PTL_OK);
}

static int
send_rdma_info(ibng_server_t *srv, ibng_cnx_t *cnx, ibng_buffer_t *buf, 
			   int whdrsize, ptl_md_iovec_t *iov, ptl_size_t iovlen, 
			   ptl_size_t offset, ptl_size_t len, void *addrkey,
			   unsigned long *nal_msg_data, void *lib_data)
{
	int payload_len;
	
	/* pack rdma rendezvous info */
	if((payload_len =
		msg_pack_rdma(buf->buffer + whdrsize,
			  buf->max_size - whdrsize,
			  iov, iovlen, offset, len,
			  srv, (ibng_reg_key_t *)addrkey)) < 0) {
		IBNG_DBG("Failed to pack RDMA info.\n");
		IBNG_PTL_RET(PTL_NO_SPACE);
	}
			
	buf->size = whdrsize + payload_len;

	*nal_msg_data = (unsigned long)buf;

	buf->lib_data = lib_data;

	IBNG_DBG("Sending rdma packet: header %d, payload %d\n",
			 whdrsize, payload_len);

	/* send */
	if(ibng_cnx_send(cnx, buf)) {
		IBNG_DBG("Failed to post send of a buffer.\n");
		return PTL_UNKNOWN_ERROR;
	}
	
	return PTL_OK;
}

static int
send_rdma_reply(ibng_server_t *srv, ibng_cnx_t *cnx, ibng_buffer_t *buf,
				int whdrsize, ptl_md_iovec_t *dst_iov, ptl_size_t iovlen, 
				ptl_size_t offset, ptl_size_t len, void *addrkey, 
				unsigned long *nal_msg_data, void *lib_data)
{
	ibng_buffer_t *recv_buf = (ibng_buffer_t *)(*nal_msg_data);
	
	ibng_rdma_req_t *rreq = ibng_cnx_get_rdma_req(cnx);
	
	if(NULL == rreq) {
		IBNG_DBG("Failed to get RDMA request.\n");
		return PTL_NO_SPACE;
	}
	
	/* send the data to the remote node by using RDMA write operation. */

	if(msg_unpack_rdma(recv_buf->buffer + recv_buf->hdrsize,
			   IBV_WR_RDMA_WRITE,
			   dst_iov, iovlen, offset, len,
			   cnx, (ibng_reg_key_t *)addrkey, rreq)) {
		IBNG_DBG("Failed to unpack RDMA info.\n");
		goto fail_out;
	}
	
	/* free the recv buffer after we have parsed the RDMA request. */
	ibng_cnx_recycle_recv_buffer(cnx, recv_buf);
	
	rreq->lib_data = lib_data;
	rreq->private = cnx;
	
	ibng_rdma_req_dump(rreq);

	if(ibng_cnx_write(cnx, rreq)) {
		IBNG_DBG("Failed to post a RDMA write.\n");
		goto fail_out;
	}
	
	/* send a portals reply (with no payload) to remote node signaling that
	   the RDMA write operation has completed. */
	buf->size = whdrsize;
	
	*nal_msg_data = (unsigned long)buf;

	buf->lib_data = NULL;

	IBNG_DBG("Sending the RDMA write confirmation: header %d\n", whdrsize);

	/* send */
	if(ibng_cnx_send(cnx, buf)) {
		IBNG_DBG("Failed to post send of a buffer.\n");
		return PTL_UNKNOWN_ERROR;
	}

	return PTL_OK;

fail_out:
	ibng_cnx_put_rdma_req(cnx, rreq);

	return PTL_UNKNOWN_ERROR;
}

static int
p3ibng_send(lib_ni_t *ni,
			unsigned long *nal_msg_data,
			void *lib_data,
			ptl_process_id_t dst,
			lib_mem_t *hdr,
			ptl_size_t hdrlen,
			ptl_md_iovec_t *src_iov,
			ptl_size_t iovlen,
			ptl_size_t offset,
			ptl_size_t len,
			void *addrkey)
{
	ibng_server_t *srv = IBNG_GET_SRV(ni);
	ibng_cnx_t *cnx;
	int rv = PTL_OK, rdma, frag;
	ptl_hdr_t *ptl_hdr = (ptl_hdr_t *)hdr;
	ibng_buffer_t *buf = NULL;
	int whdrsize;
	lib_msg_t *msg;

	cnx = ibng_server_get_cnx(srv, &dst);
	if(NULL == cnx) {
		IBNG_DBG("Failed to retrieve connection.\n");
		IBNG_PTL_SET_RV(rv, PTL_UNKNOWN_ERROR);
		goto fail_out;
	}

	buf = ibng_cnx_get_send_buffer(cnx);
	if(NULL == buf) {
		IBNG_DBG("No buffers left.\n");
		IBNG_PTL_SET_RV(rv, PTL_NO_SPACE);
		goto fail_out;
	}

	if (ptl_hdr->msg_type == PTL_MSG_GET) {
		rdma = mr_register_p(srv, NULL, ptl_hdr->length);
		if (rdma) {
			msg = (lib_msg_t *)lib_data;
			src_iov = msg->md->iov;
			iovlen = msg->md->iovlen;
			offset = ptl_hdr->msg.get.rtn_offset;
			len = ptl_hdr->length;
			addrkey = msg->md->addrkey;
		}
	}
	else if (ptl_hdr->msg_type == PTL_MSG_REPLY) {
		rdma = mr_register_p(srv, NULL, ptl_hdr->length);				
	}
	else {
		rdma = (src_iov != NULL)?
			mr_register_p(srv, src_iov[0].iov_base, len):0;
	}
	
	frag = rdma?0:buf_frag_p(buf, len);

	IBNG_DBG("Sending message, len " FMT_PSZ_T ", rdma %d, frag %d\n",
			 len, rdma, frag);

	/* pack header */
	whdrsize = msg_pack_header(buf, ptl_hdr, hdrlen, rdma, frag);
	if(whdrsize < 0) {
		IBNG_DBG("Failed to pack header.\n");
		IBNG_PTL_SET_RV(rv, PTL_NO_SPACE);
		goto fail_out;
	}

	if (rdma) {
		if(ptl_hdr->msg_type == PTL_MSG_REPLY) {
			rv = send_rdma_reply(srv, cnx, buf, whdrsize, src_iov, iovlen, 
								 offset, len, addrkey, nal_msg_data,
								 lib_data);		
		}
		else {
			rv = send_rdma_info(srv, cnx, buf, whdrsize, src_iov, iovlen,
								offset, len, addrkey, nal_msg_data, lib_data);
		}
	}
	else {
		rv = send_eager(srv, cnx, buf, whdrsize, src_iov, iovlen,
			offset, len, addrkey, nal_msg_data, lib_data, frag);
	}

fail_out:
	if(rv != PTL_OK) {
		if(NULL != cnx && NULL != buf)
			ibng_cnx_put_send_buffer_now(cnx, buf);
	}

	return rv;
}

static int
p3ibng_dist(lib_ni_t *ni,
			ptl_nid_t nid,
			unsigned long *dist)
{
	*dist = (ni->nid == nid)?0:1;
	IBNG_PTL_RET(PTL_OK);
}

static int
p3ibng_set_debug_flags(lib_ni_t *ni,
					   unsigned int mask)
{
	/* TODO */
	IBNG_PTL_RET(PTL_OK);
}

static int
p3ibng_progress(lib_ni_t *ni,
				ptl_time_t timeout)
{
#ifndef PTL_PROGRESS_THREAD
	int poll_timeout;
	ibng_server_t *srv = IBNG_GET_SRV(ni);
	
	if(timeout == PTL_TIME_FOREVER)
		poll_timeout = -1;
	else
		poll_timeout = (int)timeout;

	ibng_server_handle_events(srv, poll_timeout);
#endif /* PTL_PROGRESS_THREAD */

	IBNG_PTL_RET(PTL_OK);
}

static int
p3ibng_validate(lib_ni_t *ni,
				api_mem_t *base,
				size_t extent,
				void **addrkey)
{
	ibng_server_t *srv = IBNG_GET_SRV(ni);
	int rv = PTL_OK;

	if(mr_register_p(srv, base, extent)) {
		ibng_reg_key_t *rk;
		IBNG_DBG("MR registration needed (%p, %lu).\n",
			 base, (unsigned long)extent);
		rk = ibng_server_reg(srv, base, extent, NULL);
		if(NULL == rk)
			IBNG_PTL_SET_RV(rv, PTL_NO_SPACE);
		else
			*addrkey = rk;
	}
	else
		*addrkey = NULL;

	IBNG_PTL_RET(rv);
}

static inline int
is_iov_valid(ptl_md_iovec_t *iov, size_t iovlen)
{
	size_t i;
	for (i = 0; i < iovlen; i++) {
		/* - the base address of the I/O memory area mustn't be NULL.
		 * - the length of the I/O memory area must be a positive number.
		 * - note however that it is valid	
		 */
		
		if (iov[i].iov_base == NULL && iov[i].iov_len > 0) {
			/* invalid memory area: start = NULL with length > 0 */
			return PTL_MD_ILLEGAL;
		}

		if (iov[i].iov_base != NULL && iov[i].iov_len <= 0) {
			/* invalid memory area: valid start with length <= 0 */
			return PTL_MD_ILLEGAL;
		}
			
	}
	return PTL_OK;
}

static int
p3ibng_vvalidate(lib_ni_t *ni,
				 ptl_md_iovec_t *iov,
				 size_t iovlen,
				 void **addrkey)
{
	unsigned int i;
	int rv = PTL_OK;
	ibng_server_t *srv = IBNG_GET_SRV(ni);

	if (is_iov_valid(iov, iovlen) != PTL_OK) {
		return PTL_MD_ILLEGAL;
	}

	if(iovlen == 1) {
		rv = p3ibng_validate(ni, iov[0].iov_base, iov[0].iov_len,
					 addrkey);
	}
	else if(iovlen > 1) {
		/* iovecs larger than 1 are (we assume) large things, so they
		   get registered in any case, and will always be transferred
		   with a single rendezvous transfer */
		ibng_reg_key_t *rk = NULL;
		for (i = 0; i < iovlen; i++) {		
			rk = ibng_server_reg(srv,
								 iov[i].iov_base,
								 iov[i].iov_len,
								 rk);
			if(NULL == rk) {
				IBNG_PTL_SET_RV(rv, PTL_NO_SPACE);
				break;
			}
		}
		*addrkey = rk;
	}
	else {
		*addrkey = NULL;
	}

	IBNG_PTL_RET(rv);
}

static void
p3ibng_invalidate(lib_ni_t *ni,
				  api_mem_t *base,
				  size_t extent,
				  void *addrkey)
{
	ibng_server_t *srv = IBNG_GET_SRV(ni);

	if(NULL != addrkey)
		ibng_server_dereg(srv, (ibng_reg_key_t *)addrkey);
}

static void
p3ibng_vinvalidate(lib_ni_t *ni,
				   ptl_md_iovec_t *iov,
				   size_t iovlen,
				   void *addrkey)
{
	ibng_server_t *srv = IBNG_GET_SRV(ni);

	if(NULL != addrkey)
		ibng_server_dereg(srv, (ibng_reg_key_t *)addrkey);
}

/* ---- public NAL interface ---- */

lib_nal_t *
p3ibng_create_nal(ptl_interface_t type,
				  const lib_ni_t *ni,
				  ptl_nid_t *nid,
				  ptl_ni_limits_t *limits,
				  void *data,
				  size_t data_sz)
{
	ibng_server_t *srv;
	lib_nal_t *rv;
	char *dev_name;

	/* server will listen for the CM service PID (required to get the
	   peers to be able to connect to us with a (NID, PID) pair */
	dev_name = get_iface();
	IBNG_DBG("Creating IBNG NAL on interface %s\n",
             dev_name?dev_name:"unspecified");
	srv = ibng_server_create((lib_ni_t *)ni, type, dev_name);
	if(NULL == srv)
		return NULL;

	rv = (struct lib_nal *)malloc(sizeof(lib_nal_t));
	if(NULL == rv) {
		ibng_server_destroy(srv);
		return NULL;
	}

	bzero(rv, sizeof(lib_nal_t));

	/* initialize nal entrypoints */
	rv->recv = p3ibng_recv;
	rv->send = p3ibng_send;
	rv->dist = p3ibng_dist;
	rv->set_debug_flags = p3ibng_set_debug_flags;
	rv->progress = p3ibng_progress;
	rv->validate = p3ibng_validate;
	rv->vvalidate = p3ibng_vvalidate;
	rv->invalidate = p3ibng_invalidate;
	rv->vinvalidate = p3ibng_vinvalidate;

	rv->private = srv;

	*nid = ibng_server_get_nid(srv);
	*limits = ibng_limits;

#ifdef DEBUG_PTL_INTERNALS
	dbg_srv = srv;
#endif /* DEBUG_PTL_INTERNALS */

	ibng_server_start(srv);

	return rv;
}

static void
free_pending_msg(lib_ni_t *ni, lib_msg_t *msg)
{
	p3_lock(&ni->obj_update);

	if (msg->buf)
		p3_free(msg->buf);
	
	ptl_obj_free(msg, ni);
	
	p3_unlock(&ni->obj_update);
}

static void
free_pending_sends(const void *key, void *val)
{
	ibng_cnx_t *cnx = (ibng_cnx_t *)val; 
	
	ibng_req_t *req;
	lib_msg_t *msg = NULL;

	IBNG_DBG("Freeing pending sends ...\n");
	
	while(!list_empty(&cnx->post_pending)) {
		req = list_entry(cnx->post_pending.next, ibng_req_t, link);
		if (req->type == SEND) {
			IBNG_DBG("Freeing send request\n");
			ibng_buffer_t *buf = (ibng_buffer_t *)req;
			msg = buf->lib_data;
		}
		else if (req->type == READ || req->type == WRITE) {
			IBNG_DBG("Freeing RDMA request\n");
			ibng_rdma_req_t *rr = (ibng_rdma_req_t *)req;
			msg = rr->lib_data;
		}
		else {
			/* undefined request type! this is unexpected 
			 * behaviour!!!!*/
			IBNG_ASSERT(0);
		}
		if(NULL != msg)
			free_pending_msg(cnx->srv->ni, msg);
		list_del(&req->link);
	}
}

void
p3ibng_stop_nal(lib_nal_t *nal)
{
	IBNG_DBG("Stopping IBNG NAL\n");
	
	ibng_server_t *srv = (ibng_server_t *)nal->private;
	
	ibng_htable_foreach(srv->cnx_table, free_pending_sends);
	
	ibng_server_stop(srv);
}

void
p3ibng_destroy_nal(lib_nal_t *nal)
{
	if(NULL != nal->private)
		ibng_server_destroy((ibng_server_t *)nal->private);
#ifdef DEBUG_PTL_INTERNALS
	dbg_srv = NULL;
#endif /* DEBUG_PTL_INTERNALS */
}

#define IBNG_WELL_KNOWN_PIDS 128

int
p3ibng_pid_ranges(ptl_pid_t *first_ephemeral_pid,
				  ptl_pid_t *last_ephemeral_pid,
				  ptl_pid_t **well_known_pids,
				  ptl_size_t *nwkpids)
{
	unsigned i;

	*well_known_pids = p3_malloc(IBNG_WELL_KNOWN_PIDS*sizeof(ptl_pid_t));

	if (!*well_known_pids) {
		*nwkpids = 0;
		*well_known_pids = NULL;
		return -ENOMEM;
	}
	*nwkpids = IBNG_WELL_KNOWN_PIDS;
	for (i=0; i< IBNG_WELL_KNOWN_PIDS; i++)
		(*well_known_pids)[i] = i;

	*first_ephemeral_pid = IBNG_WELL_KNOWN_PIDS;
	*last_ephemeral_pid = (ptl_pid_t) - 1;

	return 0;
}

#ifdef DEBUG_PTL_INTERNALS
void
p3ibng_dump_stats(void)
{
	if(NULL == dbg_srv) {
		IBNG_DBG_A("No server was created.\n");
		return;
	}

	ibng_server_dump(dbg_srv);
}
#endif /* DEBUG_PTL_INTERNALS */
