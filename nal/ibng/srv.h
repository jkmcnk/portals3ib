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

#ifndef __IBNG_SRV_H__
#define __IBNG_SRV_H__

/* a portals NAL server:
 * - maps the network
 * - listens for connection requests (CM service # == pid) and processes CM
 *	 events
 * - manages open connections, establishes them on request
 * - manages IB events on a single completion channel for all CQs (CQ per
 * connection)
 */

#include <p3api/types.h>

#include <infiniband/verbs.h>

#ifdef PTL_IBNG_CMA
#  include <rdma/rdma_cma.h>
#else /* !PTL_IBNG_CMA */
#  include <infiniband/cm.h>
#endif /* PTL_IBNG_CMA */

#include "map.h"
#include "ht.h"
#include "cnx.h"

#ifdef PTL_IBNG_CMA
typedef uint32_t ibng_target_t;
#else /* !PTL_IBNG_CMA */
typedef struct ibv_sa_path_rec ibng_target_t;
#endif /* PTL_IBNG_CMA */

/* TODO: make configurable, eventually */
#define IBNG_SERVER_MAX_CNX 16384

#ifndef PTL_IBNG_CMA
#  define IBNG_LID2NID(lid) ((ptl_nid_t)lid);
#endif /* PTL_IBNG_CMA */

typedef struct ibng_reg_key ibng_reg_key_t;
struct ibng_reg_key {
	ibng_reg_key_t *next; /* used to link multiple MRs corresponding to
							 individual iovec elements: the address of the
							 head reg_key is used as addrkey in ptls */
	struct ibv_mr *mr;
	void *base;
	size_t extent;
};

typedef struct ibng_server ibng_server_t;
struct ibng_server {
	char *dev_name;

	/* verbs data shared by all connections */
	struct ibv_context *ctx;	   /* context */
	struct ibv_comp_channel *cc;   /* completion channel */
	struct ibv_pd *pd;			   /* a protection domain */
	/* TODO: would a shared receive queue be A Good Thing(tm)? would
	   probably improve scalability (single set of receive buffers),
	   but decrease performance ... */
	struct ibv_cq *cq;			   /* completion queue for all the
									  connections */

#ifdef PTL_IBNG_CMA
	struct sockaddr_in        local_address; /* local server address */
	struct rdma_event_channel *cma_channel;  /* CMA channel */
	struct rdma_cm_id         *cma_id;       /* CMA listening id */
#else /* !PTL_IBNG_CMA */
	/* CM data shared by the whole process */
	struct ib_cm_device *cm_dev;   /* CM device */
	struct ib_cm_id *cm_id;		   /* CM listening ID */

	ibng_netmap_t *net_map;		   /* network map */
#endif /* PTL_IBNG_CMA */

	unsigned int cnx_count;        /* number of connections */
	ibng_htable_t *cnx_table;	   /* connections, indexed by process id */
	ibng_iset_t *cnx_iset;		   /* connections, indexed by key */

	ptl_process_id_t local_pid;	   /* local process id */
	ptl_uid_t local_uid;		   /* local user id */
	ptl_jid_t local_jid;		   /* local job id */
	ptl_interface_t iface;		   /* local interface id */
	lib_ni_t *ni;

#ifdef PTL_PROGRESS_THREAD
	/* a server-wide lock */
	pthread_mutex_t lock;
	/* progress threads */
	int live;
	pthread_t progress_thread;
#endif /* PTL_PROGRESS_THREAD */

	/* various configuration parameters */
	size_t max_eager_size;
};

/*
 * Reports local LID for given device name.
 */
ptl_nid_t ibng_server_get_local_nid(const char *dev_name);

/*
 * Creates a new server instance.
 */
ibng_server_t *ibng_server_create(lib_ni_t *ni, ptl_interface_t iface,
								  const char *dev_name);

/*
 * Starts the server (CM and verbs event pumps).
 */
int ibng_server_start(ibng_server_t *srv);

/*
 * Stops the server.
 */
int ibng_server_stop(ibng_server_t *srv);

/*
 * Destroy the server.
 */
void ibng_server_destroy(ibng_server_t *srv);

/*
 * Retrieves a connection to an id-entified peer. Established a new connection,
 * if one does not exist.
 */
ibng_cnx_t *ibng_server_get_cnx(ibng_server_t *srv, const ptl_process_id_t *id);

/*
 * Initiate a connection request to a peer.
 */
int ibng_server_open_cnx(ibng_server_t *srv, ibng_cnx_t *cnx, 
						 ibng_target_t *target, ptl_pid_t remote_pid);

/*
 * Register a memory region.
 */
ibng_reg_key_t *ibng_server_reg(ibng_server_t *srv, void *base, size_t extent,
				ibng_reg_key_t *key);
/*
 * Deregister a memory region.
 */
void ibng_server_dereg(ibng_server_t *srv, ibng_reg_key_t *key);

ibng_reg_key_t *
ibng_server_get_reg(ibng_server_t *srv, ibng_reg_key_t *key, void *base);

static inline ptl_nid_t
ibng_server_get_nid(ibng_server_t *srv)
{
	return srv->local_pid.nid;
}

#ifndef PTL_PROGRESS_THREAD
/*
 * Polls for and handles any CM or CC events. Timeout value is in ms with
 * poll() timeout semantics.
 */
int ibng_server_handle_events(ibng_server_t *srv, int timeout);
#endif /* PTL_PROGRESS_THREAD */

static inline void
ibng_server_lock(ibng_server_t *srv)
{
#ifdef PTL_PROGRESS_THREAD
	pthread_mutex_lock(&srv->lock);
#endif /* PTL_PROGRESS_THREAD */
}

static inline void
ibng_server_unlock(ibng_server_t *srv)
{
#ifdef PTL_PROGRESS_THREAD
	pthread_mutex_unlock(&srv->lock);
#endif /* PTL_PROGRESS_THREAD */
}

#ifdef DEBUG_PTL_INTERNALS
void ibng_server_dump(ibng_server_t *srv);
#endif /* DEBUG_PTL_INTERNALS */

#endif /* __IBNG_SRV_H__ */
