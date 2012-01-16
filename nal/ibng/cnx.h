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

#ifndef __IBNG_CNX_H__
#define __IBNG_CNX_H__

#include <p3api/types.h>

#include <infiniband/verbs.h>
#ifdef PTL_IBNG_CMA
#  include <rdma/rdma_cma.h>
#else /* !PTL_IBNG_CMA */
#  include <infiniband/cm.h>
#endif /* PTL_IBNG_CMA */

#include "dbg.h"
#include "buf.h"
#include "ht.h"
#include "iset.h"

/*
 * Connection management.
 *
 * 1. Connection:
 *	  The current process connects to each process it needs to exchange data
 *	  with.
 *	  Each distinct target process is represented by a (NID, PID) tuple, the
 *	  connection is instantiated by QPs, one on each side, that are connected.
 *	  The local "state" of a connection is a connected QP.
 *
 * A connection is opened on demand, when it is needed the first time. It can be
 * teared down when an IB error occurs (timeout, IB cable disconnected), or
 * voluntarily, by closing it.
 */

/* max concurrent pending requests */
#define CNX_MAX_PENDING_REQS  (48*1024)

/* --- connection (to a single remote process, i.e. a (nid, pid) pair) --- */
/*
 * a connection to a peer.
 */
typedef enum {
	NEW = 0,
	CONNECTING = 1,
	CONNECTED = 2,
	DISCONNECTED = 3,
} ibng_cnx_state_t;

struct ibng_server;

typedef struct ibng_cnx ibng_cnx_t;
struct ibng_cnx {
	ibng_ht_element_t link;
	uint16_t key;

	ibng_req_list_t *send_list, *recv_list, *rdma_list;

	/* a ptr to a common (srv-wide) IB context and PD */
	struct ibv_context *ctx;
	struct ibv_pd *pd;

	/* per-connection verbs stuff */
	struct ibv_qp *qp;	/* a queue pair */

#ifdef PTL_IBNG_CMA
	/* a CMA id used for initiating a connection to a peer */
	struct rdma_cm_id *cma_id;
	struct rdma_cm_id *cma_id_replacement;
	struct rdma_conn_param conn_replacement;
#else /* !PTL_IBNG_CMA */
	/* a CM id used for initiating a connection to a peer */
	struct ib_cm_id *cm_id;
	/* a replacement cm_id. It is used when resolving the connection
	 * establishment race condition. */
	struct ib_cm_id *cm_id_replacement;
	/* other replacement data that are used when doing the cm_id 
	 * replacement. */
	struct ib_cm_req_event_param req_replacement;
#endif /* PTL_IBNG_CMA */

	ibng_cnx_state_t state;			/* connection state */

	ptl_process_id_t remote_pid;	/* portals pid of the peer */
	ptl_uid_t		 remote_uid;	/* uid of the peer process */
	ptl_jid_t		 remote_jid;	/* jid of the remote process */

	struct list_head post_pending;	/* pending sends (before connected) */

	ibng_iset_t *reqs_pending;

	unsigned int recvs_posted, sends_posted; /* numbers of currently posted
												sends and receives */
	unsigned int rdmas_out;					 /* number of outstanding rdma
												requests */

	struct ibng_server *srv;

	/* used during (multi-frag) reception */
	void *lib_data;
	ptl_md_iovec_t *dst_iov;
	ptl_size_t dst_iov_len;
	ptl_size_t dst_offset;
	ptl_size_t dst_mlen;
	ptl_size_t dst_rlen;

#ifdef PTL_PROGRESS_THREAD
	pthread_mutex_t lock;
#endif /* PTL_PROGRESS_THREAD */
};

typedef struct ibng_cnx_private_data ibng_cnx_private_data_t;
struct ibng_cnx_private_data {
	ptl_process_id_t proc_id;
	ptl_uid_t uid;	  /* uid of the peer process */
	ptl_jid_t jid;	  /* jid of the remote process */
};

/*
 * Create a new connection.
 */
ibng_cnx_t *ibng_cnx_create(struct ibv_context *ctx,
							struct ibv_pd *pd,
							struct ibv_cq *cq);

/*
 * Destroy a connection.
 */
void ibng_cnx_destroy(ibng_cnx_t *cnx);

/*
 * Send a buffer using the send ring.
 */
int ibng_cnx_send(ibng_cnx_t *cnx, ibng_buffer_t *buf);

/*
 * Maintain an adequate number of receive buffers posted.
 */
void ibng_cnx_maintain_recv_buffers(ibng_cnx_t *cnx);

/*
 * Recycle a receive buffer: re-post if number of currently posted is
 * lower than desired, otherwise put it into pre-allocated recv buffer
 * list.
 */
void ibng_cnx_recycle_recv_buffer(ibng_cnx_t *cnx, ibng_buffer_t *buf);

/*
 * Do a remote read.
 */
int ibng_cnx_read(ibng_cnx_t *cnx, ibng_rdma_req_t *rr);

/*
 * Do a remote write.
 */
int ibng_cnx_write(ibng_cnx_t *cnx, ibng_rdma_req_t *rr);

/**
 * Change the state of the connection.
 */
int ibng_cnx_set_state(ibng_cnx_t *cnx, ibng_cnx_state_t new_state);

int ibng_cnx_process_header(ibng_cnx_t *cnx, ibng_buffer_t *buf);
int ibng_cnx_start_recv(ibng_cnx_t *cnx, void *lib_data,
						ptl_md_iovec_t *dst_iov,
						ptl_size_t iovlen,
						ptl_size_t offset,
						ptl_size_t mlen,
						ptl_size_t rlen);
int ibng_cnx_cont_recv(ibng_cnx_t *cnx, void *buf, ptl_size_t buf_len);

int ibng_cnx_post_pending_reqs(ibng_cnx_t *cnx);

static inline void
ibng_cnx_lock(ibng_cnx_t *cnx)
{
#ifdef PTL_PROGRESS_THREAD
	pthread_mutex_lock(&cnx->lock);
#endif /* PTL_PROGRESS_THREAD */
}

static inline int
ibng_cnx_trylock(ibng_cnx_t *cnx)
{
#ifdef PTL_PROGRESS_THREAD
	return pthread_mutex_trylock(&cnx->lock);
#else
	return 0;
#endif /* PTL_PROGRESS_THREAD */
}

static inline void
ibng_cnx_unlock(ibng_cnx_t *cnx)
{
#ifdef PTL_PROGRESS_THREAD
	pthread_mutex_unlock(&cnx->lock);
#endif /* PTL_PROGRESS_THREAD */
}

/*
 * Acquire a send buffer for the connection.
 */
static inline ibng_buffer_t *
ibng_cnx_get_send_buffer(ibng_cnx_t *cnx)
{
	ibng_buffer_t *buf;

	ibng_cnx_lock(cnx);

	buf = (ibng_buffer_t *)ibng_req_list_pop(cnx->send_list);
	if(NULL == buf) {
		ibng_cnx_unlock(cnx);
		return NULL;
	}

	ibng_cnx_unlock(cnx);

	IBNG_ASSERT(buf->req.state == FREE);

	buf->wr.s.opcode = IBV_WR_SEND;
	buf->req.state = INUSE;
	buf->threshold = 1;
	buf->size = 0;
	buf->chdr = 0;
	buf->hdrsize = 0;
	buf->lib_data = buf->private = NULL;

	IBNG_DBG("Get send buffer: %p, %d\n", buf, (int)buf->req.key);

	return buf;
}

static inline void
ibng_cnx_put_send_buffer(ibng_cnx_t *cnx, ibng_buffer_t *buf)
{
	IBNG_ASSERT(buf->req.type == SEND);
	IBNG_ASSERT(buf->req.state == INUSE);
	IBNG_DBG("Put send buffer: %p, %d\n", buf, (int)buf->req.key);

	ibng_cnx_lock(cnx);

	IBNG_ASSERT(buf->threshold > 0);

	buf->threshold--;
	if(buf->threshold == 0) {
		buf->req.state = FREE;
		ibng_req_list_append(cnx->send_list, (ibng_req_t *)buf);
#ifdef DEBUG_PTL_INTERNALS
		/* poison members when releasing buf */
		buf->size = 0xdeadbeef;
		buf->chdr = 0xdeadbeef;
		buf->hdrsize = 0xf0f0f0f0f0f0f0f0ULL;
		buf->lib_data = buf->private = (void *)0xdeadbeef;
		buf->threshold = 0xdeadbeef;
#endif /* DEBUG_PTL_INTERNALS */
	}

	ibng_cnx_unlock(cnx);
}

static inline void
ibng_cnx_put_send_buffer_now(ibng_cnx_t *cnx, ibng_buffer_t *buf)
{
	IBNG_ASSERT(buf->req.type == SEND);
	IBNG_ASSERT(buf->req.state == INUSE);
	IBNG_DBG("Put send buffer: %p, %d\n", buf, (int)buf->req.key);

	ibng_cnx_lock(cnx);

	buf->req.state = FREE;
	ibng_req_list_append(cnx->send_list, (ibng_req_t *)buf);
#ifdef DEBUG_PTL_INTERNALS
	/* poison members when releasing buf */
	buf->size = 0xdeadbeef;
	buf->chdr = 0xdeadbeef;
	buf->hdrsize = 0xf0f0f0f0f0f0f0f0ULL;
	buf->lib_data = buf->private = (void *)0xdeadbeef;
#endif /* DEBUG_PTL_INTERNALS */

	ibng_cnx_unlock(cnx);
}

static inline ibng_rdma_req_t *
ibng_cnx_get_rdma_req(ibng_cnx_t *cnx)
{
	ibng_rdma_req_t *rreq;

	ibng_cnx_lock(cnx);

	rreq = (ibng_rdma_req_t *)ibng_req_list_pop(cnx->rdma_list);
	if(NULL == rreq) {
		ibng_cnx_unlock(cnx);
		return NULL;
	}

	ibng_cnx_unlock(cnx);

	IBNG_ASSERT(rreq->req.state == FREE);

	rreq->req.state = INUSE;
	rreq->lib_data = rreq->private = NULL;

	IBNG_DBG("Get RDMA req: %p, %d\n", rreq, (int)rreq->req.key);

	return rreq;
}

static inline void
ibng_cnx_put_rdma_req(ibng_cnx_t *cnx, ibng_rdma_req_t *rreq)
{
	IBNG_ASSERT((rreq->req.type == READ) || (rreq->req.type == WRITE));
	IBNG_ASSERT(rreq->req.state == INUSE);

	ibng_cnx_lock(cnx);

	rreq->req.state = FREE;
	ibng_req_list_append(cnx->rdma_list, (ibng_req_t *)rreq);
#ifdef DEBUG_PTL_INTERNALS
	/* poison members when releasing req */
	memset(&(rreq->wr_list[0]), 0xf0,
		   IBNG_RDMA_MAX_WRS*sizeof(struct ibv_send_wr));
	memset(&(rreq->sge_list[0]), 0xf0,
		   IBNG_RDMA_MAX_SGES*sizeof(struct ibv_sge));
	rreq->lib_data = rreq->private = (void *)0xdeadbeef;
#endif /* DEBUG_PTL_INTERNALS */

	ibng_cnx_unlock(cnx);
}

#ifdef DEBUG_PTL_INTERNALS
void ibng_cnx_dump(ibng_cnx_t *cnx);
#endif /* DEBUG_PTL_INTERNALS */

#endif /* __IBNG_CNX_H__ */
