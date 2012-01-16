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
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/time.h>
#include <poll.h>
#include <stdbool.h>

#include <linux/list.h>

#include <portals3.h>
#include <p3utils.h>

#include <p3api/types.h>

#include <p3/lock.h>
#include <p3/handle.h>
#include <p3/process.h>
#include <p3lib/types.h>
#include <p3lib/debug.h>
#include <p3lib/p3lib.h>

#include "srv.h"
#include "dbg.h"
#include "msg.h"
#include "buf.h"
#include "cfg.h"
#include "iset.h"

#define IBNG_EVENTS_PER_POLL	   100
#ifdef PTL_PROGRESS_THREAD
#   define IBNG_RETRIES_BEFORE_WAIT   10000
#   define IBNG_EVENT_POLL_TIMEOUT_MS  10
#else
#   define IBNG_RETRIES_BEFORE_WAIT   10000
#endif /* PTL_PROGRESS_THREAD */

#ifdef PTL_IBNG_CMA
#   define TIMEOUT_ROUTE_RESOLUTION_MS   (10*1000)
#   define TIMEOUT_ADDRESS_RESOLUTION_MS (10*1000)
#endif /* PTL_IBNG_CMA */

enum rej_consumer_def_type {
	REJ_CONSUMER_DEF_SEND_FAILED = 1,
	REJ_CONSUMER_DEF_QP_STATE_TRANSFER_FAILED = 2,
	REJ_CONSUMER_DEF_CNX_EXISTS = 3,
	REJ_CONSUMER_DEF_CNX_PUT_FAILED = 4,
	REJ_CONSUMER_DEF_NO_RESOURCES = 5
};

unsigned int ibng_debug_level = PTL_DBG_NI_ALL;

#ifdef PTL_IBNG_CMA
static inline uint32_t ibng_str_to_ip(const char *ip_str)
{
	uint32_t p[4], rv;

	if(4 != sscanf(ip_str, "%u.%u.%u.%u", &p[0], &p[1], &p[2], &p[3]))
		return 0;
	rv = (((((p[0] << 8) | p[1]) << 8) | p[2]) << 8) | p[3];
	return rv;
}
#endif /* PTL_IBNG_CMA */

static int
ibng_server_try_reap_cnx(ibng_server_t *srv, ibng_cnx_t *cnx)
{
	IBNG_DBG("Attempting to reap connection: %p (%d/%d/%d/%d)\n", cnx,
			 cnx->state, cnx->sends_posted, cnx->rdmas_out, cnx->recvs_posted);

	ibng_cnx_lock(cnx);
	if((cnx->state != DISCONNECTED) || (cnx->sends_posted > 0) ||
	   (cnx->rdmas_out > 0) || (cnx->recvs_posted > 0)) {
		IBNG_DBG("Connection not reaped: %d, %u, %u\n",
				 cnx->state, cnx->sends_posted, cnx->rdmas_out);
		ibng_cnx_unlock(cnx);
		return -1;
	}
	ibng_cnx_unlock(cnx);

	/* taaa-daaaaam! we're done! this connection has, after all the twists
	   and turns its destruction took, passed on, it is no more, it has ceased
	   to be, it's expired and gone to meet its maker, it's a stiff, bereft of
	   life, it rests in peace, it's pushing up the daisies, its metabolic
	   processes are now history, it's off the twig, it's kicked the bucket,
	   it's shuffled off its mortal coil, run down the curtain and joined the
	   bleeding choir invisibile! THIS IS AN EX-CONNECTION! */
	ibng_server_lock(srv);
	ibng_iset_release(srv->cnx_iset, cnx->key);
	ibng_cnx_destroy(cnx);
	srv->cnx_count--;
	ibng_server_unlock(srv);

	IBNG_DBG("Connection reaped.\n");

	return 0;
}

/*
  NOTE: this function should be used to mark a connection as disconnected.
  Disconnect occurs after (a) local closing of connection initiated by
  ibng_cnx_close, or (b) peer closing the connection, resulting in a CM DREQ
  request.
  A disconnected connection (hmmmm, contradictio in adiecto?) is not
  destroyed immediately. A connection may not be ibng_cnx_destroy()ed if there
  are pending SEND or RDMA WRs. On each future WC associated with a
  disconnected connection (ffs), ibng_server_try_reap_cnx() will be called and
  will finally destroy the connection when the number of pending requests
  drops to 0. 
*/
static void
ibng_server_disconnect_cnx(ibng_server_t *srv, ibng_cnx_t *cnx)
{
	IBNG_DBG("Disconnecting cnx: %p\n", cnx);

	ibng_cnx_set_state(cnx, DISCONNECTED);

	ibng_server_lock(srv);
	ibng_htable_remove(srv->cnx_table, &cnx->remote_pid);
	ibng_server_unlock(srv);

	ibng_server_try_reap_cnx(srv, cnx);
}

static inline int
is_local_process_id_lower(ptl_process_id_t local_proc_id, 
						  ptl_process_id_t remote_proc_id)
{
	return local_proc_id.nid < remote_proc_id.nid ||
		(local_proc_id.nid == remote_proc_id.nid &&
		 local_proc_id.pid < remote_proc_id.pid);
}

static int
create_qp(ibng_server_t *srv, ibng_cnx_t *cnx)
{
	struct ibv_qp_init_attr qpi;

	IBNG_ASSERT(cnx->qp == NULL);

	bzero(&qpi, sizeof(struct ibv_qp_init_attr));
	qpi.send_cq = srv->cq;
	qpi.recv_cq = srv->cq;
	qpi.cap.max_send_wr = ibng_config.max_send_wrs;
	qpi.cap.max_recv_wr = ibng_config.max_recv_wrs;
	qpi.cap.max_send_sge = IBNG_RDMA_MAX_SGES;
	qpi.cap.max_recv_sge = IBNG_RDMA_MAX_SGES;
	/* if 0, create_qp() will attempt auto-detection */
	qpi.cap.max_inline_data = ibng_config.max_inline; 
	qpi.qp_type = IBV_QPT_RC;
	qpi.sq_sig_all = 0;

	if(0 == qpi.cap.max_inline_data) {
		uint32_t max_inline_data;
		/* auto-detect max_inline value appropriate for the host HW:
		   just check powers of 2 - that's good enough */
		IBNG_DBG("Detecting max_inline value to use.\n");
		max_inline_data = 1 << 20;
		qpi.cap.max_inline_data = max_inline_data;
		while (max_inline_data > 0) {
#ifdef PTL_IBNG_CMA
			if(0 == rdma_create_qp(cnx->cma_id, cnx->pd, &qpi))
#else /* !PTL_IBNG_CMA */
			if(NULL != (cnx->qp = ibv_create_qp(cnx->pd, &qpi)))
#endif /* PTL_IBNG_CMA */
			{
				ibng_config.max_inline = max_inline_data;
#ifdef PTL_IBNG_CMA
				cnx->qp = cnx->cma_id->qp;
#endif /* PTL_IBNG_CMA */
				break;
			}
			max_inline_data >>= 1;
			qpi.cap.max_inline_data = max_inline_data;
		}

		if (!cnx->qp)
			IBNG_DBG("Failed to detect any max_inline value.\n");
		else
			IBNG_DBG("Queue-pair created: max_inline_data = %u.\n",
					 max_inline_data);
	}
	else {
#ifdef PTL_IBNG_CMA
		if(0 == rdma_create_qp(cnx->cma_id, cnx->pd, &qpi))
			cnx->qp = cnx->cma_id->qp;
#else /* !PTL_IBNG_CMA */
		cnx->qp = ibv_create_qp(cnx->pd, &qpi);
#endif /* PTL_IBNG_CMA */
	}
	return ((cnx->qp == NULL)?-1:0);
}

#ifdef PTL_IBNG_CMA
static int
accept_cma_connection(ibng_server_t *srv, ibng_cnx_t *cnx,
					  struct rdma_conn_param *cp) {
	struct rdma_conn_param conn_params;
	ibng_cnx_private_data_t priv_data;
	int rej_reason;

	if(create_qp(srv, cnx)) {
		IBNG_DBG("Failed to create qp.\n");
		rej_reason = REJ_CONSUMER_DEF_NO_RESOURCES;
		rdma_reject(cnx->cma_id, &rej_reason, sizeof(int));
		return -1;
	}
	
	bzero(&conn_params, sizeof(conn_params));
	conn_params.responder_resources = cp->responder_resources;
	conn_params.initiator_depth = cp->initiator_depth;
	conn_params.flow_control = cp->flow_control;
	conn_params.rnr_retry_count = cp->rnr_retry_count;
	conn_params.private_data = &priv_data;
	conn_params.private_data_len = sizeof(ibng_cnx_private_data_t);
	priv_data.proc_id = srv->local_pid;
	priv_data.uid = srv->local_uid;
	priv_data.jid = srv->local_jid;
		
	if(rdma_accept(cnx->cma_id, &conn_params)) {
		IBNG_ERROR("Failed to send CM REP.\n");
		rej_reason = REJ_CONSUMER_DEF_SEND_FAILED;
		rdma_reject(cnx->cma_id, &rej_reason, sizeof(int));
		return -1;
	}

	return 0;
}

static int
replace_cma_id_for_cnx(ibng_server_t *srv, ibng_cnx_t *cnx)
{

	rdma_destroy_qp(cnx->cma_id);
	rdma_destroy_id(cnx->cma_id);

	cnx->cma_id = cnx->cma_id_replacement;
	cnx->cma_id_replacement = NULL;
	cnx->cma_id->context = cnx;

	return accept_cma_connection(srv, cnx, &cnx->conn_replacement);
}

static void
cma_handler_addr_resolved(ibng_server_t *srv, struct rdma_cm_event *event)
{
	ibng_cnx_t *cnx = (ibng_cnx_t *)event->id->context;

	cnx->cma_id = event->id;

	/* our code should guarantee the below is always true ... */
	IBNG_ASSERT(srv->cma_id->verbs == cnx->cma_id->verbs);
	/* ... if it's not, it's a BUG, and we should die a horrible
	   ASSERTive death above, when built with debug enabled */

	if(create_qp(srv, cnx)) {
		IBNG_DBG("Failed to create qp.\n");
		ibng_server_disconnect_cnx(srv, cnx);
	}
	else {
		ibng_cnx_set_state(cnx, CONNECTING);
		if(rdma_resolve_route(cnx->cma_id, TIMEOUT_ROUTE_RESOLUTION_MS)) {
			IBNG_DBG("Failed to initiate route resolution.\n");
			ibng_server_disconnect_cnx(srv, cnx);
		}
	}
}

static void
cma_handler_route_resolved(ibng_server_t *srv, struct rdma_cm_event *event) 
{
	ibng_cnx_t *cnx = (ibng_cnx_t *)event->id->context;
	struct rdma_conn_param conn_params;
	ibng_cnx_private_data_t priv_data;

	bzero(&conn_params, sizeof(conn_params));
	conn_params.responder_resources = ibng_config.max_rdma_out;;
	conn_params.initiator_depth = ibng_config.max_rdma_out;;
	conn_params.flow_control = 0;
	conn_params.rnr_retry_count = 7;
	conn_params.retry_count = 5;
	conn_params.private_data = &priv_data;
	conn_params.private_data_len = sizeof(ibng_cnx_private_data_t);
	priv_data.proc_id = srv->local_pid;
	priv_data.uid = srv->local_uid;
	priv_data.jid = srv->local_jid;
	
	if(rdma_connect(cnx->cma_id, &conn_params)) {
		IBNG_DBG("Failed to initiate connection.\n");
		ibng_server_disconnect_cnx(srv, cnx);
	}
}

static void
cma_handler_connect_request(ibng_server_t *srv, struct rdma_cm_event *event) 
{
	ibng_cnx_private_data_t *priv_data;
	ibng_cnx_t *cnx;
	uint16_t key;
	int rej_reason;

	/* extract the (nid, pid), uid, jid from the event. */
	priv_data = (ibng_cnx_private_data_t *)event->param.conn.private_data;
	
	IBNG_DBG("CM request arrived from peer (%u, %u), uid=%u, jid=%u\n", 
			 priv_data->proc_id.nid, priv_data->proc_id.pid,
			 priv_data->uid, priv_data->jid);

	ibng_server_lock(srv);

	/* check if the connection to the remote node already exists. */
	cnx = (ibng_cnx_t *)ibng_htable_get(srv->cnx_table, &priv_data->proc_id);
	if(cnx != NULL) {
		IBNG_ERROR("Connection to the remote node already exists: (%u, %u)\n",
				   priv_data->proc_id.nid, priv_data->proc_id.pid);
		IBNG_ASSERT(cnx->state != CONNECTED);
		/* this is an obvious race where both sides attempt to establish
		   a connection at roughly the same time, resulting in both doing CM
		   connect. the issue is resolved by preserving the connection of the
		   node with the lower (nid, pid) pair.
		*/
		if (is_local_process_id_lower(srv->local_pid, priv_data->proc_id)) {
			/* preserve the connection that was initiated from the local node
			   and send the rejection message to the initiator, so it will
			   remove the connection from its hash table.
			*/
			rej_reason = REJ_CONSUMER_DEF_CNX_EXISTS;
			rdma_reject(event->id, &rej_reason, sizeof(int));
		}
		else {
			/* preserve the connection that was initiated from the remote
			   node, destroy the connection that was initiated on the local
			   node.
			*/
			cnx->cma_id_replacement = event->id;
			cnx->conn_replacement = event->param.conn;
			cnx->remote_pid = priv_data->proc_id;
			cnx->remote_uid = priv_data->uid;
			cnx->remote_jid = priv_data->jid;			
		}
		goto fail_out;
	}
	
	key = ibng_iset_acquire(srv->cnx_iset);
	if(IBNG_ISET_INVALID_IDX == key) {
		IBNG_ERROR("Failed to acquire connection key!\n");
		rej_reason = REJ_CONSUMER_DEF_NO_RESOURCES;
		rdma_reject(event->id, &rej_reason, sizeof(int));
		goto fail_out;
	}

	/* create new connection. */
	cnx = ibng_cnx_create(srv->ctx, srv->pd, srv->cq);
	if (cnx == NULL) {
		IBNG_ERROR("Failed to create connection!\n");
		ibng_iset_release(srv->cnx_iset, key);
		rej_reason = REJ_CONSUMER_DEF_NO_RESOURCES;
		rdma_reject(event->id, &rej_reason, sizeof(int));
		goto fail_out;
	}
	cnx->srv = srv;
	cnx->key = key;
	cnx->cma_id = event->id;
	cnx->cma_id->context = cnx;
	cnx->remote_pid = priv_data->proc_id;
	cnx->remote_uid = priv_data->uid;
	cnx->remote_jid = priv_data->jid;
	ibng_iset_el(srv->cnx_iset, key) = cnx;
	if(accept_cma_connection(srv, cnx, &event->param.conn)) {
		ibng_iset_release(srv->cnx_iset, key);
		ibng_cnx_destroy(cnx);
		goto fail_out;
	}
	
	IBNG_DBG("Adding connection to (%u,%u): %p\n",
			 cnx->remote_pid.nid, cnx->remote_pid.pid, cnx);
	if (ibng_htable_put(srv->cnx_table, &cnx->remote_pid, &cnx->link) != 0) {
		IBNG_ERROR("Failed to insert connection into the cnx table.\n");
		rej_reason = REJ_CONSUMER_DEF_CNX_PUT_FAILED;
		rdma_reject(event->id, &rej_reason, sizeof(int));
		ibng_iset_release(srv->cnx_iset, key);
		ibng_cnx_destroy(cnx);
		goto fail_out;
	}

	srv->cnx_count++;

	/* now that we're ready to receive, we change cnx state to
	 * CONNECTING, resulting in pre-posting recv buffers
	 */
	ibng_cnx_set_state(cnx, CONNECTING);

 fail_out:
	ibng_server_unlock(srv);	
}

static void
cma_handler_established(ibng_server_t *srv, struct rdma_cm_event *event)
{
	ibng_cnx_t *cnx = (ibng_cnx_t *)event->id->context;
	/* the connection is now ready to use. */
	ibng_cnx_set_state(cnx, CONNECTED);	
}

static void
cma_handler_disconnected(ibng_server_t *srv, struct rdma_cm_event *event)
{
	ibng_cnx_t *cnx = (ibng_cnx_t *)event->id->context;

	ibng_server_disconnect_cnx(srv, cnx);	
}

static void
cma_handler_addr_error(ibng_server_t *srv, struct rdma_cm_event *event)
{
	ibng_cnx_t *cnx = event->id->context;

	IBNG_DBG("Address resolution error.\n");

	ibng_server_disconnect_cnx(srv, cnx);
}

static void
cma_handler_route_error(ibng_server_t *srv, struct rdma_cm_event *event)
{
	ibng_cnx_t *cnx = event->id->context;

	IBNG_DBG("Route resolution error on cnx %p.\n", cnx);

	ibng_server_disconnect_cnx(srv, cnx);
}

static void
cma_handler_connect_response(ibng_server_t *srv, struct rdma_cm_event *event)
{
	IBNG_DBG("Connect response on cnx %p.\n", event->id->context);
}

static void
cma_handler_connect_error(ibng_server_t *srv, struct rdma_cm_event *event)
{
	ibng_cnx_t *cnx = event->id->context;

	IBNG_DBG("Connection error on cnx %p.\n", cnx);

	ibng_server_disconnect_cnx(srv, cnx);
}

static void
cma_handler_unreachable(ibng_server_t *srv, struct rdma_cm_event *event)
{
	ibng_cnx_t *cnx = event->id->context;

	IBNG_DBG("Target unreachable on cnx %p.\n", cnx);

	ibng_server_disconnect_cnx(srv, cnx);
}

static void
cma_handler_rejected(ibng_server_t *srv, struct rdma_cm_event *event)
{
	ibng_cnx_t *cnx = event->id->context;

	IBNG_DBG("Connection rejected on cnx %p.\n", cnx);

	if(event->param.conn.private_data_len == 4 &&
	   *((int *)event->param.conn.private_data) == 
	   REJ_CONSUMER_DEF_CNX_EXISTS) {
		IBNG_DBG("Rejection was received during the process of connection "
                 "establishing race condition resolution. This is perfectly "
                 "normal procedure.");
		replace_cma_id_for_cnx(srv, cnx);
	}
	else
		ibng_server_disconnect_cnx(srv, cnx);
}

static void
cma_handler_ignore(ibng_server_t *srv, struct rdma_cm_event *event)
{
	IBNG_DBG("Ignoring event %d on cnx %p.\n",
			 event->event, event->id->context);
}

static void
cma_handler(ibng_server_t *srv, struct rdma_cm_event *event)
{
	switch(event->event) {
	case RDMA_CM_EVENT_ADDR_RESOLVED:
		cma_handler_addr_resolved(srv, event);
		break;
	case RDMA_CM_EVENT_ADDR_ERROR:
		cma_handler_addr_error(srv, event);
		break;
	case RDMA_CM_EVENT_ROUTE_RESOLVED:
		cma_handler_route_resolved(srv, event);
		break;
	case RDMA_CM_EVENT_ROUTE_ERROR:
		cma_handler_route_error(srv, event);
		break;
	case RDMA_CM_EVENT_CONNECT_REQUEST:
		cma_handler_connect_request(srv, event);
		break;
	case RDMA_CM_EVENT_CONNECT_RESPONSE:
		cma_handler_connect_response(srv, event);
		break;
	case RDMA_CM_EVENT_CONNECT_ERROR:
		cma_handler_connect_error(srv, event);
		break;
	case RDMA_CM_EVENT_UNREACHABLE:
		cma_handler_unreachable(srv, event);
		break;
	case RDMA_CM_EVENT_REJECTED:
		cma_handler_rejected(srv, event);
		break;
    case RDMA_CM_EVENT_ESTABLISHED:
		cma_handler_established(srv, event);
		break;
	case RDMA_CM_EVENT_DISCONNECTED:
		cma_handler_disconnected(srv, event);
		break;
	case RDMA_CM_EVENT_DEVICE_REMOVAL:
		cma_handler_ignore(srv, event);
		break;
	case RDMA_CM_EVENT_MULTICAST_JOIN:
		cma_handler_ignore(srv, event);
		break;
	case RDMA_CM_EVENT_MULTICAST_ERROR:
		cma_handler_ignore(srv, event);
		break;
	case RDMA_CM_EVENT_ADDR_CHANGE:
		cma_handler_ignore(srv, event);
		break;
	case RDMA_CM_EVENT_TIMEWAIT_EXIT:
		cma_handler_ignore(srv, event);
		break;
	default:
		IBNG_ERROR("Unexpected CMA event.\n");
	}
}
#else /* !PTL_IBNG_CMA */
static int
qp_to_rtr(ibng_cnx_t *cnx, struct ib_cm_id *cm_id)
{
	struct ibv_qp_attr qp_attr;
	int qp_attr_mask, rv;

	/* first to INIT state */
	memset(&qp_attr, 0, sizeof(struct ibv_qp_attr));
	qp_attr.qp_state = IBV_QPS_INIT;

	rv = ib_cm_init_qp_attr(cm_id, &qp_attr, &qp_attr_mask);
	if(rv) {
		IBNG_ERROR("Failed to get QP attributes for INIT state (%d).\n", rv);
		return -1;
	}

	qp_attr.qp_access_flags = IBV_ACCESS_LOCAL_WRITE |
		IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_READ;
	qp_attr_mask |= IBV_QP_ACCESS_FLAGS;

	rv = ibv_modify_qp(cnx->qp, &qp_attr, qp_attr_mask);
	if(rv) {
		IBNG_ERROR("Failed to put WP into INIT state (%d).\n", rv);
		return -1;
	}
	/* then to RTR state */
	memset(&qp_attr, 0, sizeof(struct ibv_qp_attr));
	qp_attr.qp_state = IBV_QPS_RTR;
	rv = ib_cm_init_qp_attr(cm_id, &qp_attr, &qp_attr_mask);
	if(rv) {
		IBNG_ERROR("Failed to get QP attributes for RTR state (%d).\n", rv);
		return -1;
	}
	qp_attr.rq_psn = cnx->qp->qp_num;

	rv = ibv_modify_qp(cnx->qp, &qp_attr, qp_attr_mask);
	if(rv) {
		IBNG_ERROR("Failed to put QP into RTR state (%d).\n", rv);
		return -1;
	}

	/* now that we're ready to receive, we change cnx state to
	 * CONNECTING, resulting in pre-posting recv buffers
	 */
	ibng_cnx_set_state(cnx, CONNECTING);

	return 0;
}

static int
qp_to_rts(ibng_cnx_t *cnx, struct ib_cm_id *cm_id)
{
	struct ibv_qp_attr qp_attr;
	int qp_attr_mask, rv;

	memset(&qp_attr, 0, sizeof(struct ibv_qp_attr));
	qp_attr.qp_state = IBV_QPS_RTS;
	rv = ib_cm_init_qp_attr(cm_id, &qp_attr, &qp_attr_mask);
	if(rv) {
		IBNG_ERROR("Failed to get QP attributes for RTS state (%d).\n", rv);
		return -1;
	}

	rv = ibv_modify_qp(cnx->qp, &qp_attr, qp_attr_mask);
	if(rv) {
		IBNG_ERROR("Failed to put QP into RTS state (%d).\n", rv);
		return -1;
	}
	
	/* the connection is now ready to use. */
	ibng_cnx_set_state(cnx, CONNECTED);
	
	return 0;
}

static int
cm_send_rep(ibng_cnx_t *cnx, struct ib_cm_req_event_param *req,
			const ptl_process_id_t *local_proc_id,
			ptl_uid_t local_uid, ptl_jid_t local_jid)
{
	int rv;
	struct ib_cm_rep_param rep;
	ibng_cnx_private_data_t priv_data;

	memset(&rep, 0, sizeof(struct ib_cm_rep_param));
	
	rep.qp_num = cnx->qp->qp_num;
	rep.srq = 0;
	/* TODO: we should randomize starting PSN */
	rep.starting_psn = cnx->qp->qp_num; 
	rep.responder_resources = req->responder_resources;
	rep.initiator_depth = req->initiator_depth;
	rep.target_ack_delay = 20;
	rep.flow_control = req->flow_control;
	rep.rnr_retry_count = req->rnr_retry_count;
	priv_data.proc_id = *local_proc_id;
	priv_data.uid = local_uid;
	priv_data.jid = local_jid;
	
	rep.private_data = &priv_data;
	rep.private_data_len = sizeof(ibng_cnx_private_data_t);
	
	rv = ib_cm_send_rep(cnx->cm_id, &rep);
	if(rv != 0) {
		IBNG_ERROR("CM REP sending failed (%d)!\n", rv);
		return -1;
	}

	return 0;
}

static int
cm_send_rtu(ibng_cnx_t *cnx)
{
	int rv;

	rv = ib_cm_send_rtu(cnx->cm_id, NULL, 0);
	if(rv != 0) {
		IBNG_ERROR("CM RTU sending failed (%d)!\n", rv);
		return -1;
	}
	
	return 0;
}

static void
replace_cm_id_for_cnx(ibng_server_t *srv, ibng_cnx_t *cnx)
{
	cnx->cm_id = cnx->cm_id_replacement;
	cnx->cm_id_replacement = NULL;
	
	cnx->cm_id->context = cnx;
	
	if(qp_to_rtr(cnx, cnx->cm_id) != 0) {
		IBNG_ERROR("Failed to move QP to RTR.\n");
		ib_cm_send_rej(cnx->cm_id, IB_CM_REJ_CONSUMER_DEFINED,
					   NULL, 0, NULL, 0);
	}
	else if(cm_send_rep(cnx, &cnx->req_replacement, &srv->local_pid, 
				   srv->local_uid, srv->local_jid) != 0) {
		int rej_reason = REJ_CONSUMER_DEF_SEND_FAILED;
		IBNG_ERROR("Failed to send CM REP.\n");
		ib_cm_send_rej(cnx->cm_id, IB_CM_REJ_CONSUMER_DEFINED,
					   &rej_reason, sizeof(int), NULL, 0);
	}
}

static void
cm_handler_req_received(ibng_server_t *srv, struct ib_cm_event *event)
{
	ibng_cnx_private_data_t *priv_data;
	ibng_cnx_t *cnx;
	uint16_t key;
	int rej_reason;
		
	/* extract the (nid, pid), uid, jid from the event. */
	priv_data = (ibng_cnx_private_data_t *)event->private_data;
	
	IBNG_DBG("CM request arrived from peer (%u, %u), uid=%u, jid=%u\n", 
			 priv_data->proc_id.nid, priv_data->proc_id.pid,
			 priv_data->uid, priv_data->jid);

	ibng_server_lock(srv);

	/* check if the connection to the remote node already exists. */
	cnx = (ibng_cnx_t *)ibng_htable_get(srv->cnx_table, &priv_data->proc_id);
	if(cnx != NULL) {
		IBNG_ERROR("Connection to the remote node already exists: (%u, %u)\n",
				   priv_data->proc_id.nid, priv_data->proc_id.pid);
		IBNG_ASSERT(cnx->state != CONNECTED);
		/* this is an obvious race where both sides attempt to establish
		   a connection at roughly the same time, resulting in both doing CM
		   connect. the issue is resolved by preserving the connection of the
		   node with the lower (nid, pid) pair.
		*/
		if (is_local_process_id_lower(srv->local_pid, priv_data->proc_id)) {
			/* preserve the connection that was initiated from the local node
			   and send the rejection message to the initiator, so it will
			   remove the connection from its hash table.
			*/
			rej_reason = REJ_CONSUMER_DEF_CNX_EXISTS;
			ib_cm_send_rej(event->cm_id, IB_CM_REJ_CONSUMER_DEFINED,
						   &rej_reason, sizeof(int), NULL, 0);
		}
		else {
			/* preserve the connection that was initiated from the remote
			   node, destroy the connection that was initiated on the local
			   node.
			*/
			cnx->cm_id_replacement = event->cm_id;
			cnx->req_replacement = event->param.req_rcvd;
			cnx->remote_pid = priv_data->proc_id;
			cnx->remote_uid = priv_data->uid;
			cnx->remote_jid = priv_data->jid;			
		}
		goto fail_out;
	}
	
	key = ibng_iset_acquire(srv->cnx_iset);
	if(IBNG_ISET_INVALID_IDX == key) {
		IBNG_ERROR("Failed to acquire connection key!\n");
		ib_cm_send_rej(event->cm_id, IB_CM_REJ_NO_RESOURCES, NULL, 0, NULL, 0);
		goto fail_out;
	}

	/* create new connection. */
	cnx = ibng_cnx_create(srv->ctx, srv->pd, srv->cq);
	if (cnx == NULL) {
		IBNG_ERROR("Failed to create connection!\n");
		ibng_iset_release(srv->cnx_iset, key);
		ib_cm_send_rej(event->cm_id, IB_CM_REJ_NO_RESOURCES, NULL, 0, NULL, 0);
		goto fail_out;
	}
	cnx->srv = srv;
	cnx->key = key;
	ibng_iset_el(srv->cnx_iset, key) = cnx;

	if(create_qp(srv, cnx)) {
		IBNG_DBG("Failed to create qp.\n");
		ib_cm_send_rej(event->cm_id, IB_CM_REJ_NO_RESOURCES, NULL, 0, NULL, 0);
		ibng_iset_release(srv->cnx_iset, key);
		ibng_cnx_destroy(cnx);
		goto fail_out;
	}
	
	if(qp_to_rtr(cnx, event->cm_id) != 0) {
		IBNG_ERROR("Failed to move QP to RTR.\n");
		rej_reason = REJ_CONSUMER_DEF_SEND_FAILED;
		ib_cm_send_rej(event->cm_id, IB_CM_REJ_CONSUMER_DEFINED,
					   &rej_reason, sizeof(int), NULL, 0);
		ibng_iset_release(srv->cnx_iset, key);
		ibng_cnx_destroy(cnx);
		goto fail_out;
	}
	
	cnx->cm_id = event->cm_id;
	cnx->cm_id->context = cnx;
	cnx->remote_pid = priv_data->proc_id;
	cnx->remote_uid = priv_data->uid;
	cnx->remote_jid = priv_data->jid;
	
	if(cm_send_rep(cnx, &event->param.req_rcvd, &srv->local_pid,
				   srv->local_uid, srv->local_jid) != 0) {
		IBNG_ERROR("Failed to send CM REP.\n");
		rej_reason = REJ_CONSUMER_DEF_SEND_FAILED;
		ib_cm_send_rej(event->cm_id, IB_CM_REJ_CONSUMER_DEFINED,
					   &rej_reason, sizeof(int), NULL, 0);
		ibng_iset_release(srv->cnx_iset, key);
		ibng_cnx_destroy(cnx);
		goto fail_out;
	}
	
	IBNG_DBG("Adding connection to (%u,%u): %p\n",
			 cnx->remote_pid.nid, cnx->remote_pid.pid, cnx);
	if (ibng_htable_put(srv->cnx_table, &cnx->remote_pid, &cnx->link) != 0) {
		int rej_reason = REJ_CONSUMER_DEF_CNX_PUT_FAILED;
		IBNG_ERROR("Failed to insert connection into the cnx table.\n");
		ib_cm_send_rej(event->cm_id, IB_CM_REJ_CONSUMER_DEFINED,
					   &rej_reason, sizeof(int), NULL, 0);
		ibng_iset_release(srv->cnx_iset, key);
		ibng_cnx_destroy(cnx);
		goto fail_out;
	}

	srv->cnx_count++;

 fail_out:
	ibng_server_unlock(srv);
}

static void
cm_handler_rep_received(ibng_server_t *srv, struct ib_cm_event *event)
{
	ibng_cnx_t *cnx = event->cm_id->context;
	ibng_cnx_private_data_t *priv_data;

	/* extract the (nid, pid), uid, jid from the event. */
	priv_data = (ibng_cnx_private_data_t *)event->private_data;
	
	IBNG_DBG("CM request arrived from peer (%u, %u), uid=%u, jid=%u\n", 
			 priv_data->proc_id.nid, priv_data->proc_id.pid,
			 priv_data->uid, priv_data->jid);
	IBNG_ASSERT((priv_data->proc_id.nid == cnx->remote_pid.nid) &&
				(priv_data->proc_id.pid == cnx->remote_pid.pid));

	cnx->remote_uid = priv_data->uid;
	cnx->remote_jid = priv_data->jid;

	if(qp_to_rtr(cnx, event->cm_id) != 0) {
		int rej_reason = REJ_CONSUMER_DEF_QP_STATE_TRANSFER_FAILED;
		IBNG_ERROR("Failed to move QP to RTR.\n");
		ib_cm_send_rej(event->cm_id, IB_CM_REJ_CONSUMER_DEFINED,
					   &rej_reason, sizeof(int), NULL, 0);
	}
	else if(qp_to_rts(cnx, event->cm_id) != 0) {
		int rej_reason = REJ_CONSUMER_DEF_QP_STATE_TRANSFER_FAILED;
		IBNG_ERROR("Failed to move QP to RTS.\n");
		ib_cm_send_rej(event->cm_id, IB_CM_REJ_CONSUMER_DEFINED,
					   &rej_reason, sizeof(int), NULL, 0);
	}
	else if(cm_send_rtu(cnx) != 0) {
		int rej_reason = REJ_CONSUMER_DEF_SEND_FAILED;
		IBNG_ERROR("Failed to send CM RTU.\n");
		ib_cm_send_rej(event->cm_id, IB_CM_REJ_CONSUMER_DEFINED,
					   &rej_reason, sizeof(int), NULL, 0);
	}
}

static void
cm_handler_rtu_received(ibng_server_t *srv, struct ib_cm_event *event)
{
	ibng_cnx_t *cnx = event->cm_id->context;

	if(qp_to_rts(cnx, event->cm_id)) {
		int rej_reason = REJ_CONSUMER_DEF_QP_STATE_TRANSFER_FAILED;
		IBNG_DBG("Failed to move QP to RTS.\n");
		ib_cm_send_rej(event->cm_id, IB_CM_REJ_CONSUMER_DEFINED,
					   &rej_reason, sizeof(int), NULL, 0);

	}
}

static void
cm_handler_dreq_received(ibng_server_t *srv, struct ib_cm_event *event)
{
	int rv;
	
	ibng_cnx_t *cnx = event->cm_id->context;

	if((rv = ib_cm_send_drep(cnx->cm_id, NULL, 0)) != 0) {
		IBNG_ERROR("CM disconnect reply sending failed (%d)!\n", rv);
		return;
	}

	ibng_server_disconnect_cnx(srv, cnx);
}

static void
cm_handler_drep_received(ibng_server_t *srv, struct ib_cm_event *event)
{
}

static void
cm_handler_rej_received(ibng_server_t *srv, struct ib_cm_event *event)
{
	ibng_cnx_t *cnx = event->cm_id->context;
	int ari = *(int *)event->param.rej_rcvd.ari;
	
	if (event->param.rej_rcvd.reason == IB_CM_REJ_CONSUMER_DEFINED &&
		ari == REJ_CONSUMER_DEF_CNX_EXISTS) {
		/* the remote node must have already contacted us and started
		   establishing connection. */
		IBNG_ASSERT(cnx->cm_id_replacement != NULL);
		
		/* the remote node is already establishing connection to the local
		   node. thus, we should not destroy the whole ibng_cnx_t struct,
		   since we could have some pending send requests. we only have to
		   close the CM ID.
		*/
		IBNG_DBG("The CM_REJ was received during the process of connection "
				 "establishing race condition resolution. This is perfectly "
				 "normal procedure.");
		/* close the old cm_id and replace it with the cm_id of the remote
		   peer's connection. */
		replace_cm_id_for_cnx(srv, cnx);
	}
	else
		ibng_server_disconnect_cnx(srv, cnx);
}

static void
cm_handler_error_received(ibng_server_t *srv, struct ib_cm_event *event)
{
	ibng_cnx_t *cnx = event->cm_id->context;
	
	ibng_server_disconnect_cnx(srv, cnx);
}

static void
cm_handler_timeout_received(ibng_server_t *srv, struct ib_cm_event *event)
{
	ibng_cnx_t *cnx = event->cm_id->context;

	ibng_server_disconnect_cnx(srv, cnx);
}

static void
cm_handler(ibng_server_t *srv, struct ib_cm_event *event)
{
	/* handle event */
	switch(event->event) {
	case IB_CM_REQ_RECEIVED:
		IBNG_DBG("CM_REQ_RECEIVED\n");
		cm_handler_req_received(srv, event);
		break;
	case IB_CM_REP_RECEIVED:
		IBNG_DBG("CM_REP_RECEIVED\n");
		cm_handler_rep_received(srv, event);
		break;
	case IB_CM_RTU_RECEIVED:
		IBNG_DBG("CM_RTU_RECEIVED\n");
		cm_handler_rtu_received(srv, event);
		break;
	case IB_CM_DREQ_RECEIVED:
		IBNG_DBG("CM_DREQ_RECEIVED\n");
		cm_handler_dreq_received(srv, event);
		break;
	case IB_CM_DREP_RECEIVED:
		IBNG_DBG("CM_DREP_RECEIVED\n");
		cm_handler_drep_received(srv, event);
		break;
	case IB_CM_REJ_RECEIVED:
		IBNG_DBG("CM_REJ_RECEIVED\n");
		cm_handler_rej_received(srv, event);
		break;
	case IB_CM_REQ_ERROR:
		IBNG_DBG("CM_REQ_ERROR\n");
		cm_handler_error_received(srv, event);
		break;
	case IB_CM_REP_ERROR:
		IBNG_DBG("CM_REP_ERROR\n");
		cm_handler_error_received(srv, event);
		break;
	case IB_CM_DREQ_ERROR:
		IBNG_DBG("CM_DREQ_ERROR\n");
		cm_handler_error_received(srv, event);
		break;
	case IB_CM_TIMEWAIT_EXIT:
		IBNG_DBG("CM_TIMEWAIT_EXIT\n");
		cm_handler_timeout_received(srv, event);
		break;
	default:
		IBNG_ERROR("Unexpected CM event.\n");
	}
}
#endif /* PTL_IBNG_CMA */

static void
ibng_reg_key_destroy(ibng_reg_key_t *key)
{
	ibng_reg_key_t *kp;

	while(NULL != key) {
		kp = key->next;
		IBNG_DBG("Deregistering MR: base %p, len " FMT_SZ_T ", rkey: %x\n",
				 key->base, key->extent, key->mr->rkey);
		if(NULL != key->mr)
			ibv_dereg_mr(key->mr);
		free(key);
		key = kp;
	}
}

static ibng_reg_key_t *
ibng_reg_key_update(ibng_reg_key_t *key, struct ibv_mr *mr,
					void *base, size_t extent)
{
	ibng_reg_key_t *nkey;

	IBNG_ASSERT(mr != NULL);

	nkey = (ibng_reg_key_t *)malloc(sizeof(ibng_reg_key_t));
	if(NULL == nkey) {
		ibng_reg_key_destroy(key);
		return NULL;
	}
	nkey->mr = mr;
	nkey->base = base;
	nkey->extent = extent;
	nkey->next = NULL;

	/* remembering the first principle of algorithm design ("when in doubt,
	   sort!"), we sort the individual keys in the list by increasing base
	   addresses to improve performance when using the reg key later on.
	   TODO: actually, it might prove wise to make this a balanced tree
	   instead of a sorted list. with a sorted list we're still O(n) in
	   worst case, a balanced tree would give us stable O(log n). however,
	   it seems portals are not often used with iovecs longer then 1, so
	   there will be a single reg key in the list most of the time anyway. */
	
	if(NULL == key)
		return nkey;
	else if(nkey->base <= key->base) {
		nkey->next = key;
		return nkey;
	}
	else {
		ibng_reg_key_t *kp = key;
		while(NULL != kp->next && nkey->base > kp->next->base)
			kp = kp->next;
		kp->next = nkey;
		return key;
	}
}

ibng_reg_key_t *
ibng_server_reg(ibng_server_t *srv, void *base, size_t extent,
				ibng_reg_key_t *key)
{
	struct ibv_mr *mr;

	mr = ibv_reg_mr(srv->pd, base, extent,
					IBV_ACCESS_LOCAL_WRITE |
					IBV_ACCESS_REMOTE_READ |
					IBV_ACCESS_REMOTE_WRITE);
	if(NULL == mr) {
		ibng_reg_key_destroy(key);
		key = NULL;
	}
	else {
		IBNG_DBG("Registered MR: base %p, len " FMT_SZ_T ", rkey %x\n",
				 base, extent, mr->rkey);
		key = ibng_reg_key_update(key, mr, base, extent);
	}

	return key;
}

void
ibng_server_dereg(ibng_server_t *srv, ibng_reg_key_t *key)
{
	ibng_reg_key_destroy(key);
}

ibng_reg_key_t *
ibng_server_get_reg(ibng_server_t *srv, ibng_reg_key_t *key, void *base)
{
	ibng_reg_key_t *kp = key;

	while(NULL != kp) {
		if(kp->base <= base && kp->base + kp->extent > base)
			return kp;
		if(kp->base > base)
			return NULL;
		kp = kp->next;
	}
	return NULL;
}

/* hashing and comparison functions for pids */
static ibng_ht_key
pid_hash(const void *key)
{
	/* TODO: come up with a better hash */
	const ptl_process_id_t *pid = (ptl_process_id_t *)key;
	return (ibng_ht_key)(pid->nid ^ pid->pid);
}

static int
pid_cmp(const void *a, const void *b)
{
	const ptl_process_id_t *pida = (ptl_process_id_t *)a,
		*pidb = (ptl_process_id_t *)b;
	return !((pida->pid == pidb->pid) && (pida->nid == pidb->nid));
}

#ifndef PTL_IBNG_CMA
static struct ibv_context *
open_ib_device_by_name(const char *dev_name)
{
	struct ibv_device *dev = NULL, **dev_list;
	struct ibv_context *ctx = NULL;

	dev_list = ibv_get_device_list(NULL);
	if(NULL == dev_list) {
		IBNG_DBG("No device list\n");
		return NULL;
	}

	if(NULL == dev_name)
		dev = dev_list[0];
	else {
		int i = 0;
		while(dev_list[i] != NULL &&
			  strcmp(dev_list[i]->name, dev_name))
			i++;
		dev = dev_list[i];
	}
	IBNG_DBG("Using device: %p\n", dev);
	if(NULL != dev) {
		ctx = ibv_open_device(dev);
	}
	ibv_free_device_list(dev_list);

	return ctx;
}
#endif /* !PTL_IBNG_CMA */

static int
ibng_server_open_device(ibng_server_t *srv, const char *dev_name)
{
#ifdef PTL_IBNG_CMA
	struct sockaddr_in addr;
	uint32_t ip;

	if(NULL == dev_name) {
		/* CMA way does not work without an explicit local IP given as device
		   name; set it via PTL_IFACE env var */
		IBNG_DBG("No device IP given for CMA connection method\n");
		return -1;
	}
	ip = ibng_str_to_ip(dev_name);
	if(0 == ip) {
		IBNG_DBG("Invalid device IP\n");
		return -1;
	}
	srv->cma_channel = rdma_create_event_channel();
	if(NULL == srv->cma_channel) {
		IBNG_DBG("Failed to create CMA channel\n");
		return -1;
	}
	if(rdma_create_id(srv->cma_channel, &srv->cma_id, srv, RDMA_PS_TCP)) {
		IBNG_DBG("Failed to create CMA ID\n");
		return -1;
	}
	
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	/* NOTE: we bind to a *specific* RDMA device, chosen by the IP */
	IBNG_DBG("Binding server to nid %u, pid %u\n", ip, srv->local_pid.pid);
	addr.sin_addr.s_addr = htonl(ip);
	addr.sin_port = htons(srv->local_pid.pid);
	
	if(rdma_bind_addr(srv->cma_id, (struct sockaddr *)&addr)) {
		IBNG_DBG("Failed to bind CMA ID\n");
		return -1;
	}
	memcpy(&srv->local_address, &addr, sizeof(addr));
	if(NULL != srv->cma_id->verbs)
		srv->ctx = srv->cma_id->verbs;
#else /* !PTL_IBNG_CMA */
	srv->ctx = open_ib_device_by_name(dev_name);
#endif /* PTL_IBNG_CMA */
	IBNG_DBG("Using context: %p\n", srv->ctx);

	if(NULL != srv->ctx) {
		srv->dev_name = strdup(srv->ctx->device->name);
		return 0;
	}
	return -1;
}

ptl_nid_t
ibng_server_get_local_nid(const char *dev_name)
{
	ptl_nid_t rv = PTL_NID_ANY;
#ifdef PTL_IBNG_CMA
	/* for CMA, dev_name *is* the local IP associated with the device */
	return ibng_str_to_ip(dev_name);
#else /* !PTL_IBNG_CMA */
	struct ibv_context *ctx;
	uint16_t llid;

	ctx = open_ib_device_by_name(dev_name);
	if(NULL == ctx)
		return PTL_NID_ANY;

	if(0 == ibng_netmap_local_lid_get(ctx, 1, &llid))
		rv = (ptl_nid_t)llid;

	ibv_close_device(ctx);
#endif /* PTL_IBNG_CMA */

	return rv;
}

ibng_server_t *
ibng_server_create(lib_ni_t *ni, ptl_interface_t iface, const char *dev_name)
{
	ibng_server_t *srv;
	int flags;

	ibng_debug_level = p3lib_debug;

	ibng_cfg_init_from_env();

	srv = (ibng_server_t *)malloc(sizeof(ibng_server_t));
	if(NULL == srv)
		return NULL;
	bzero(srv, sizeof(ibng_server_t));

	/* NOTE: we need local_pid.pid set before calling server_open_device(),
	   as CMA connection method will require it (used as port number) */
	srv->local_pid.nid = PTL_NID_ANY;
	srv->local_pid.pid = ni->pid;
	srv->local_uid = (ptl_uid_t)geteuid();
	/* TODO: set proper jid (do we want to support jids at all?) */
	srv->local_jid = 0;
	srv->iface = iface;
	srv->ni = ni;
	/* NOTE: local_pid.nid will be set later, it requires open device
	   to get it for CM connection method */

	/* open verbs device */
	if(ibng_server_open_device(srv, dev_name)) {
		IBNG_DBG("Failed to open device.\n");
		goto fail_out;
	}

	/* set async event fd to non-blocking mode */
	flags = fcntl(srv->ctx->async_fd, F_GETFL);
	if(fcntl(srv->ctx->async_fd, F_SETFL, flags | O_NONBLOCK)) {
		IBNG_DBG("Failed to set async fd to non-blocking mode.\n");
		/* not a fatal error */
	}

	/* create a completion channel */
	srv->cc = ibv_create_comp_channel(srv->ctx);
	if(NULL == srv->cc) {
		IBNG_DBG("Failed to create completion channel.\n");
		goto fail_out;
	}

	srv->pd = ibv_alloc_pd(srv->ctx);
	if(NULL == srv->pd) {
		IBNG_DBG("Failed to alloc PD\n");
		goto fail_out;
	}

#ifdef PTL_IBNG_CMA
	if(rdma_listen(srv->cma_id, 16)) {
		IBNG_DBG("Failed to listen on CMA ID\n");
		goto fail_out;
	}
#else /* PTL_IBNG_CMA */
	/* CM connection method */
	srv->cm_dev = ib_cm_open_device(srv->ctx);
	if(NULL == srv->cm_dev) {
		IBNG_DBG("Failed to open CM\n");
		goto fail_out;
	}
	if(ib_cm_create_id(srv->cm_dev, &srv->cm_id, srv)) {
		IBNG_DBG("Failed to create CM ID\n");
		goto fail_out;
	}
	if(ib_cm_listen(srv->cm_id, __cpu_to_be64((uint64_t)ni->pid), 0)) {
		IBNG_DBG("Failed to listen on CM ID\n");
		goto fail_out;
	}

	srv->net_map = ibng_netmap_create(srv->ctx);
	if(NULL == srv->net_map) {
		IBNG_DBG("Failed to create netmap\n");
		goto fail_out;
	}
#endif /* PTL_IBNG_CMA */

	srv->cq = ibv_create_cq(srv->ctx,
							ibng_config.max_send_wrs +
							ibng_config.max_recv_wrs,
							NULL,
							srv->cc,
							0);

	if(NULL == srv->cq) {
		IBNG_DBG("Failed to create CQ\n");
		goto fail_out;
	}
	if(ibv_req_notify_cq(srv->cq, 0)) {
		IBNG_DBG("Failed to request notification\n");
		goto fail_out;
	}

	srv->cnx_count = 0;
	srv->cnx_table = ibng_htable_create(pid_hash, pid_cmp, 181);
	/* 181 is the 42nd prime ;) should use a much larger one, though */
	if(NULL == srv->cnx_table) {
		IBNG_DBG("Failed to create cnx htable\n");
		goto fail_out;
	}
	srv->cnx_iset = ibng_iset_create(IBNG_SERVER_MAX_CNX);
	if(NULL == srv->cnx_iset) {
		IBNG_DBG("Failed to create cnx iset\n");
		goto fail_out;
	}

#ifdef PTL_IBNG_CMA
	srv->local_pid.nid = ibng_str_to_ip(dev_name);
#else /* !PTL_IBNG_CMA */
	srv->local_pid.nid = IBNG_LID2NID(srv->net_map->local_lid);
#endif /* PTL_IBNG_CMA */

	srv->max_eager_size = ibng_config.eager_threshold;

#ifdef PTL_PROGRESS_THREAD
	pthread_mutex_init(&srv->lock, NULL);
#endif /* PTL_PROGRESS_THREAD */

	return srv;

fail_out:
	ibng_server_destroy(srv);

	return NULL;
}

void
ibng_server_destroy(ibng_server_t *srv)
{
	IBNG_ASSERT(srv->cnx_count == 0);

	/* all connections must be destroyed at this time, and the progress
	   thread must be stopped: call ibng_server_stop() before destroy() */
	if(srv->cnx_table)
		ibng_htable_destroy(srv->cnx_table);
	if(srv->cnx_iset)
		ibng_iset_destroy(srv->cnx_iset);
	if(srv->cq)
		ibv_destroy_cq(srv->cq);
	if(srv->cc)
		ibv_destroy_comp_channel(srv->cc);
	if(srv->pd)
		ibv_dealloc_pd(srv->pd);
#ifdef PTL_IBNG_CMA
	if(srv->cma_id)
		rdma_destroy_id(srv->cma_id);
	if(srv->cma_channel)
		rdma_destroy_event_channel(srv->cma_channel);
#else /* !PTL_IBNG_CMA */
	if(srv->net_map)
		ibng_netmap_destroy(srv->net_map);
	if(srv->cm_id)
		ib_cm_destroy_id(srv->cm_id);
	if(srv->cm_dev)
		ib_cm_close_device(srv->cm_dev);
	if(srv->ctx)
		ibv_close_device(srv->ctx);
#endif /* !PTL_IBNG_CMA */
	if(srv->dev_name)
		free(srv->dev_name);

#ifdef PTL_PROGRESS_THREAD
	pthread_mutex_destroy(&srv->lock);
#endif /* PTL_PROGRESS_THREAD */

	free(srv);
}

int
ibng_server_open_cnx(ibng_server_t *srv, ibng_cnx_t *cnx,
					 ibng_target_t *target, ptl_pid_t remote_pid)
{
#ifdef PTL_IBNG_CMA
	struct sockaddr_in addr, saddr;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(*target);
	addr.sin_port = htons((unsigned short)remote_pid);
	memcpy(&saddr, &srv->local_address, sizeof(saddr));
	saddr.sin_port = 0;

	if(rdma_create_id(srv->cma_channel, &cnx->cma_id, cnx, RDMA_PS_TCP)) {
		IBNG_DBG("Failed to create connection CMA ID.\n");
		return -1;
	}
	if(rdma_resolve_addr(cnx->cma_id, 
						 (struct sockaddr *)&saddr,
						 (struct sockaddr *)&addr,
						 TIMEOUT_ADDRESS_RESOLUTION_MS)) {
		IBNG_DBG("Failed to initiate address resolution.\n");
		return -1;
	}
#else /* !PTL_IBNG_CMA */
	struct ib_cm_req_param req;
	int rv;
	ibng_cnx_private_data_t priv_data;
		
	if(cnx->cm_id != NULL) {
		IBNG_ERROR("Connection already initiated.\n");
		return -1;
	}

	if(ib_cm_create_id(srv->cm_dev, &cnx->cm_id, cnx)) {
		IBNG_ERROR("Failed to create a CM ID (initiating).\n");
		return -1;
	}
	IBNG_DBG("Created a CM ID (initiating).\n");

	memset(&req, 0, sizeof(struct ib_cm_req_param));
	
	/* set the CM request parameters. */	
	req.primary_path = target;
	req.service_id = __cpu_to_be64((uint64_t)remote_pid);
	req.responder_resources = ibng_config.max_rdma_out;
	req.initiator_depth = ibng_config.max_rdma_out;
	req.remote_cm_response_timeout = 20;
	req.local_cm_response_timeout = 20;
	req.max_cm_retries = 5;
	/* NOTE: inifinite retries on RNR failures in order to cater to
	   receiver not posting recv buffers fast enough (which can eventually
	   occur with any setup of preposted receive buffers number, if the
	   sender sends arbitrarily long bursts). we expect other errors (not
	   RNR) will still be reported as retry_count is set to <7. */
	req.rnr_retry_count = 7;
	req.retry_count = 5;
	
	priv_data.proc_id = srv->local_pid;
	priv_data.uid = srv->local_uid;
	priv_data.jid = srv->local_jid;
	
	req.private_data = &priv_data;
	req.private_data_len = sizeof(ibng_cnx_private_data_t);
	
	req.qp_num = cnx->qp->qp_num;
	req.srq = 0;
	req.starting_psn = cnx->qp->qp_num;
	req.qp_type = IBV_QPT_RC;
	
	/* send CM request to remote node. */
	if((rv = ib_cm_send_req(cnx->cm_id, &req))) {
		IBNG_ERROR("CM request sending failed (%d)!\n", rv);
		return -1;
	}
#endif /* PTL_IBNG_CMA */

	return 0;
}

ibng_cnx_t *
ibng_server_get_cnx(ibng_server_t *srv, const ptl_process_id_t *id)
{
	ibng_cnx_t * cnx;
	uint16_t key;

	ibng_server_lock(srv);

	cnx = (ibng_cnx_t *)ibng_htable_get(srv->cnx_table, id);
	IBNG_DBG("Get cnx (%u,%u): %p\n", id->nid, id->pid, cnx);

	if(NULL == cnx) {
		ibng_target_t target;

		cnx = ibng_cnx_create(srv->ctx, srv->pd, srv->cq);
		if(NULL == cnx) {
			ibng_server_unlock(srv);
			IBNG_DBG("Failed to create the new connection (%u,%u).\n",
				id->nid, id->pid);
			return NULL;
		}

#ifndef PTL_IBNG_CMA
		if(create_qp(srv, cnx)) {
			ibng_server_unlock(srv);
			IBNG_DBG("Failed to create qp.\n");
			ibng_cnx_destroy(cnx);
			return NULL;
		}
#endif /* !PTL_IBNG_CMA */

		cnx->remote_pid = *id;
		cnx->srv = srv;

#ifdef PTL_IBNG_CMA
		target = id->nid;
#else /* !PTL_IBNG_CMA */
		if(ibng_netmap_get_path_rec(srv->net_map, (uint16_t)id->nid, &target)) {
			ibng_server_unlock(srv);
			ibng_cnx_destroy(cnx);
			IBNG_DBG("Failed to retrieve path rec for connection (%u,%u).\n",
				id->nid, id->pid);
			return NULL;
		}
#endif /* PTL_IBNG_CMA */
		
		if(ibng_server_open_cnx(srv, cnx, &target, id->pid)) {
			ibng_server_unlock(srv);
			ibng_cnx_destroy(cnx);
			IBNG_DBG("Failed to open the connection (%u,%u).\n",
				id->nid, id->pid);
			return NULL;
		}

		key = ibng_iset_acquire(srv->cnx_iset);
		if(IBNG_ISET_INVALID_IDX == key) {
			ibng_server_unlock(srv);
			ibng_cnx_destroy(cnx);
			IBNG_DBG("Failed to acquire the iset for the connection "
				"(%u,%u).\n", id->nid, id->pid);
			return NULL;
		}
		cnx->key = key;

		IBNG_DBG("Adding connection to (%u,%u), key %d: %p\n",
				 cnx->remote_pid.nid, cnx->remote_pid.pid, (int)key, cnx);

		ibng_iset_el(srv->cnx_iset, key) = cnx;
		ibng_htable_put(srv->cnx_table, &cnx->remote_pid, &cnx->link);

		srv->cnx_count++;
	}

	ibng_server_unlock(srv);

	return cnx;
}

static inline int
handle_send_completion(ibng_server_t *srv, ibng_cnx_t *cnx,
					   ibng_buffer_t *buf, struct ibv_wc *wc)
{
	IBNG_DBG("Completed send.\n");

	if(ibng_buffer_is_last_p(buf) || ibng_buffer_is_rdma_get_send_p(buf))
		lib_finalize(srv->ni, buf->lib_data, PTL_NI_OK);

	ibng_cnx_put_send_buffer(cnx, buf);
	IBNG_DBG("Release send buffer (after send completion).\n");

	ibng_cnx_lock(cnx);
	cnx->sends_posted--;
	ibng_cnx_unlock(cnx);
	
	return 0;
}

static inline int
handle_recv_completion(ibng_server_t *srv, ibng_cnx_t *cnx,
					   ibng_buffer_t *buf, struct ibv_wc *wc)
{
	buf->size = wc->byte_len;
	buf->hdrsize = 0;
	buf->chdr = 0;

	IBNG_DBG("RECV receives posted on %p: %d.\n", cnx, cnx->recvs_posted);

	if(NULL != cnx->lib_data) {
		IBNG_ASSERT(!(wc->wc_flags & IBV_WC_WITH_IMM));
		/* fragment > 1: continue with reception */
		ibng_cnx_cont_recv(cnx, buf->buffer, buf->size);
		/* recycle recv buffer immediately */
		ibng_cnx_recycle_recv_buffer(cnx, buf);
	}
	else {
		/* fragment 1: header + possible data or rdma info */
		IBNG_ASSERT(wc->wc_flags & IBV_WC_WITH_IMM);
		buf->chdr = wc->imm_data;
		if (HDR_GET_FLAGS(buf->chdr) & HDR_F_RDMA_DONE) {
			/* an ack of a RDMA put */
			uint16_t key = EHDR_GET_KEY(buf);
			ibng_buffer_t *obuf =
				(ibng_buffer_t *)ibng_iset_el(cnx->reqs_pending, key);

			IBNG_ASSERT(HDR_GET_FLAGS(obuf->chdr) & HDR_F_RDMA);

			lib_finalize(srv->ni, obuf->lib_data, PTL_NI_OK);
			ibng_cnx_put_send_buffer(cnx, obuf);
			ibng_cnx_recycle_recv_buffer(cnx, buf);
		}
		else {
			/* a portals header fragment: process it */
			ibng_cnx_process_header(cnx, buf);
			/* we still need buf in NAL receive handler, so it will be
			   reposted for receive in NAL receive handler ...
			   ... BUT: in order to maintain a constant number of preposted
			   receives, we will re-post another receive buffer */
			ibng_cnx_maintain_recv_buffers(cnx);
		}
	}

	ibng_cnx_lock(cnx);
	cnx->recvs_posted--;
	ibng_cnx_unlock(cnx);

	return 0;
}

static inline int
handle_rdma_completion(ibng_server_t *srv, ibng_cnx_t *cnx,
					   ibng_rdma_req_t *rr, struct ibv_wc *wc)
{
		IBNG_DBG("Completed rdma.\n");

		if(rr->req.type == READ) {
			/* finished put (target side) */
			IBNG_DBG("Finished put (RDMA); lib_data: %p\n", rr->lib_data);
			lib_finalize(cnx->srv->ni, rr->lib_data, PTL_NI_OK);
		}
		else if(rr->req.type == WRITE) {
			/* finished get (target side) */
			IBNG_DBG("Finished get (RDMA); lib_data: %p\n", rr->lib_data);
			lib_finalize(cnx->srv->ni, rr->lib_data, PTL_NI_OK);
		}
		else {
			IBNG_ASSERT(0);
		}
		ibng_cnx_put_rdma_req(cnx, rr);

		ibng_cnx_lock(cnx);
		cnx->sends_posted--;
		cnx->rdmas_out--;
		ibng_cnx_unlock(cnx);

		return 0;
}


static void
handle_error_completion(ibng_server_t *srv,
						ibng_cnx_t *cnx,
						struct ibv_wc *wc)
{
	/* dump all possible info on error when built with debug,
	   regardless of debug level settings */
	IBNG_DBG_A("WC (type %d, key %d): FAIL! Status %s (%d)\n",
			   WRID_TYPE(wc->wr_id), WRID_KEY(wc->wr_id),
			   ibv_wc_status_str(wc->status), wc->status);
	IBNG_DBG_A("  Opcode: %d\n", wc->opcode);
	IBNG_DBG_A("  Vendor err: %x\n", wc->vendor_err);
	IBNG_DBG_A("  Byte len: %u\n", wc->byte_len);
	IBNG_DBG_A("  Imm data: %x\n", wc->imm_data);
	IBNG_DBG_A("  QP num: %x\n", wc->qp_num);
	IBNG_DBG_A("  Src QP num: %x\n", wc->src_qp);
	IBNG_DBG_A("  Flags: %x\n", wc->wc_flags);
	
	/* we can't recover from an error: tear down the connection */
	ibng_server_disconnect_cnx(srv, cnx);
}

static inline int
ibng_server_handle_wc(ibng_server_t *srv, struct ibv_wc *wc)
{
	uint16_t key, cnx_key;
	ibng_req_t *req;
	ibng_cnx_t *cnx;

	key = WRID_KEY(wc->wr_id);
	cnx_key = WRID_CNX(wc->wr_id);

	IBNG_DBG("Handling WC with key %d for cnx key %d\n",
			 (int)key, (int)cnx_key);
	IBNG_ASSERT(key < CNX_MAX_PENDING_REQS);
	IBNG_ASSERT(cnx_key < IBNG_SERVER_MAX_CNX);

	cnx = (ibng_cnx_t *)ibng_iset_el(srv->cnx_iset, cnx_key);
	IBNG_ASSERT((uintptr_t)cnx > IBNG_ISET_INVALID_IDX);

	if(wc->status != IBV_WC_SUCCESS) {
		handle_error_completion(srv, cnx, wc);
		return -1;
	}

	req = ibng_iset_el(cnx->reqs_pending, key);
	IBNG_DBG("Request data at %p\n", req);
	/* assuming we never allocate memory < 0xffff on the heap, this assert
	   catches faulty keys */
	IBNG_ASSERT(req > (ibng_req_t *)CNX_MAX_PENDING_REQS);
	/* all the keys we get here should refer to INUSE reqs */
	IBNG_ASSERT(req->state == INUSE);

	if(WRID_IS_SEND(wc->wr_id)) {
		IBNG_ASSERT(SEND == req->type);
		handle_send_completion(srv, cnx, (ibng_buffer_t *)req, wc);
	}
	else if(WRID_IS_RECV(wc->wr_id)) {
		IBNG_ASSERT(RECV == req->type);
		handle_recv_completion(srv, cnx, (ibng_buffer_t *)req, wc);
	}
	else if(WRID_IS_RDMA(wc->wr_id)) {
		IBNG_ASSERT((READ == req->type) || (WRITE == req->type));
		handle_rdma_completion(srv, cnx, (ibng_rdma_req_t *)req, wc);
	}

	if(cnx->state == DISCONNECTED)
		ibng_server_try_reap_cnx(srv, cnx);
	else {
		ibng_cnx_lock(cnx);
		ibng_cnx_post_pending_reqs(cnx);
		ibng_cnx_unlock(cnx);
	}

	return 0;
}

/* NOTE: CM, async fds and CC/CQ are only accessed from a single thread: no
   locking necessary. */
static int
ibng_server_handle_cm(ibng_server_t *srv)
{
	ibng_cnx_private_data_t pdata;
#ifdef PTL_IBNG_CMA
	struct rdma_cm_event *event, cevent;

	if(rdma_get_cm_event(srv->cma_channel, &event)) {
		IBNG_ERROR("Failed to get CMA event.\n");
		return -1;
	}

	memcpy(&cevent, event, sizeof(*event));
	if(event->param.conn.private_data != NULL) {
		memcpy(&pdata, event->param.conn.private_data, sizeof(pdata));
		cevent.param.conn.private_data = &pdata;
	}
	else
		cevent.param.conn.private_data = NULL;
	rdma_ack_cm_event(event);

	cma_handler(srv, &cevent);
#else /* !PTL_IBNG_CMA */
	struct ib_cm_event *event, cevent;

	if(ib_cm_get_event(srv->cm_dev, &event)) {
		IBNG_ERROR("Failed to get CM event.\n");
		return -1;
	}

	memcpy(&cevent, event, sizeof(*event));
	if(event->private_data != NULL) {
		memcpy(&pdata, event->private_data, sizeof(pdata));
		cevent.private_data = &pdata;
	}
	else
		cevent.private_data = NULL;
	ib_cm_ack_event(event);
	
	cm_handler(srv, &cevent);
#endif /* PTL_IBNG_CMA */

	return 0;
}

static int
ibng_server_handle_ae(ibng_server_t *srv)
{
	struct ibv_async_event event;
	
	if(ibv_get_async_event(srv->ctx, &event)) {
		IBNG_ERROR("Failed to get async event.\n");
		return -1;
	}
	
	IBNG_DBG("Async event %d: %s\n",
			 event.event_type, ibv_event_type_str(event.event_type));

	ibv_ack_async_event(&event);

	return 0;
}

static int
ibng_server_handle_cc(ibng_server_t *srv)
{
	struct ibv_cq *ev_cq;
	void *ev_data = NULL;
	struct ibv_wc wc[IBNG_EVENTS_PER_POLL];
	int i, events;

	if(ibv_get_cq_event(srv->cc, &ev_cq, &ev_data)) {
		IBNG_ERROR("Failed to get CQ event.\n");
		return -1;
	}

	if(ibv_req_notify_cq(ev_cq, 0)) {
		IBNG_DBG("Failed to request CQ notification.\n");
		return -1;
	}

	ibv_ack_cq_events(ev_cq, 1);

	do {
		events = ibv_poll_cq(ev_cq, IBNG_EVENTS_PER_POLL, wc);
		if(events > 0) {
			for(i = 0; i < events; i++)
				ibng_server_handle_wc(srv, &wc[i]);
		}
	} while(events > 0);

	return 0;
}

static int
ibng_server_wait_for_events(ibng_server_t *srv, int timeout)
{
	struct pollfd ufds[3];
	int polled;

#ifdef PTL_IBNG_CMA
	ufds[0].fd = srv->cma_channel->fd;
#else /* !PTL_IBNG_CMA */
	ufds[0].fd = srv->cm_dev->fd;
#endif /* PTL_IBNG_CMA */
	ufds[0].events = POLLIN;
	ufds[0].revents = 0;
	
	ufds[1].fd = srv->cc->fd;
	ufds[1].events = POLLIN;
	ufds[1].revents = 0;

	ufds[2].fd = srv->ctx->async_fd;
	ufds[2].events = POLLIN;
	ufds[2].revents = 0;

	polled = poll(ufds, 3, timeout);
	if(polled < 0) {
		IBNG_ERROR("Failed to poll() IB fds.\n");
		return -1;
	}
	if(polled > 0) {
		if(ufds[0].revents == POLLIN) {
			/* handle connection events (CM or CMA) */
			if(ibng_server_handle_cm(srv))
				return -1;
		}
		if(ufds[1].revents == POLLIN) {
			/* handle completion events */
			if(ibng_server_handle_cc(srv))
				return -1;
		}
		if(ufds[2].revents == POLLIN) {
			/* handle async events */
			if(ibng_server_handle_ae(srv))
				return -1;
		}
	}

	return 0;
}

int
ibng_server_handle_events(ibng_server_t *srv, int timeout)
{
	static int iter = 0;
	struct ibv_wc wc[IBNG_EVENTS_PER_POLL];
	int i, events, total = 0;

	do {
		events = ibv_poll_cq(srv->cq, IBNG_EVENTS_PER_POLL, wc);
		if(events > 0) {
			for(i = 0; i < events; i++)
				ibng_server_handle_wc(srv, &wc[i]);
			total += events;
		}
	} while(events > 0);

	if(total > 0 || iter++ < IBNG_RETRIES_BEFORE_WAIT)
		return 0;

	iter = 0;

	return ibng_server_wait_for_events(srv, timeout);
}

static void
close_cnx(const void *key, void *val)
{
	ibng_cnx_t *cnx = (ibng_cnx_t *)val; 

	ibng_server_disconnect_cnx(cnx->srv, cnx);
}

#ifdef PTL_PROGRESS_THREAD
static void *
ibng_server_progress_thread(void *arg)
{
	ibng_server_t *srv = (ibng_server_t *)arg;

	while(srv->live)
		ibng_server_handle_events(srv, IBNG_EVENT_POLL_TIMEOUT_MS);

	return NULL;
}
#endif /* PTL_PROGRESS_THREAD */

/* NOTE: the multithreaded code is fundamentally flawed wrt. ptls events.
   it will *fail* miserably, if there is more than 1 thread calling
   ptls API. right now it's only useful for employing separate progress
   thread(s) - event notifications need to be put in the ptls library
   by adding a posix semaphore per event queue. */

int
ibng_server_start(ibng_server_t *srv)
{
#ifdef PTL_PROGRESS_THREAD
	srv->live = 1;
	if(pthread_create(&srv->progress_thread, NULL,
					  ibng_server_progress_thread, srv)) {
		srv->live = 0;
		return -1;
	}
	return 0;
#else
	return 0;
#endif /* PTL_PROGRESS_THREAD */
}

int
ibng_server_stop(ibng_server_t *srv)
{
	IBNG_DBG("Stopping server.\n");

#ifdef PTL_PROGRESS_THREAD
	/* stop and reap the progress threads */
	srv->live = 0;
	pthread_join(srv->progress_thread, NULL);
#endif /* PTL_PROGRESS_THREAD */
	/* force-close all connections */
	ibng_htable_foreach(srv->cnx_table, close_cnx);

	return 0;
}

#ifdef DEBUG_PTL_INTERNALS
static void
dump_cnx(const void *key, void *val)
{
	ibng_cnx_dump((ibng_cnx_t *)val);
}

void
ibng_server_dump(ibng_server_t *srv)
{
	IBNG_DBG_A("Server %p\n", srv);
	IBNG_DBG_A("  Local PID: (%u, %u)\n",
			   srv->local_pid.nid, srv->local_pid.pid);
	IBNG_DBG_A("  Local UID: %u\n", srv->local_uid);
	IBNG_DBG_A("  Local JID: %u\n", srv->local_jid);
	IBNG_DBG_A("  Eager proto threshold: " FMT_SZ_T "\n", srv->max_eager_size);
	ibng_htable_foreach(srv->cnx_table, dump_cnx);
}
#endif /* DEBUG_PTL_INTERNALS */
