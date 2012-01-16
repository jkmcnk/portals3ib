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

#ifndef __IBNG_BUF_H__
#define __IBNG_BUF_H__

#include <linux/list.h>
#include "iset.h"

#include <infiniband/verbs.h>

#include <p3api/types.h>

#define WR_SEND_ID			 (1ULL << 32)
#define WR_RDMA_ID			 (1ULL << 33)
#define WR_RECV_ID			 (1ULL << 34)
#define WR_KEY_SPACE		 (0xFFFFULL)
#define WR_TYPE_SPACE		 (0xFULL << 32)
#define WR_CNX_SPACE		 (0xFFFFULL << 48)

#define WR_MAKE_KEY(key)	 ((uint64_t)key & WR_KEY_SPACE)
#define WR_MAKE_CNX(cnx)	 (((uint64_t)cnx->key << 48) & WR_CNX_SPACE)

#define WRID_SEND(cnx, key)	 (WR_SEND_ID | WR_MAKE_KEY(key) | WR_MAKE_CNX(cnx))
#define WRID_RDMA(cnx, key)	 (WR_RDMA_ID | WR_MAKE_KEY(key) | WR_MAKE_CNX(cnx))
#define WRID_RECV(cnx, key)	 (WR_RECV_ID | WR_MAKE_KEY(key) | WR_MAKE_CNX(cnx))

#define WRID_IS_SEND(id)	 (id & WR_SEND_ID)
#define WRID_IS_RDMA(id)	 (id & WR_RDMA_ID)
#define WRID_IS_RECV(id)	 (id & WR_RECV_ID)

#define WRID_TYPE(id)		 ((uint8_t)((id & WR_TYPE_SPACE) >> 32))
#define WRID_KEY(id)		 ((uint16_t)(id & WR_KEY_SPACE))
#define WRID_CNX(id)		 ((uint16_t)((id & WR_CNX_SPACE) >> 48))

typedef enum {
	SEND = 0,
	RECV = 1,
	READ = 2,
	WRITE = 3
} ibng_req_type_t;

typedef enum {
	FREE  = 0,
	INUSE = 1
} ibng_req_state_t;

typedef struct ibng_req ibng_req_t;
struct ibng_req {
	struct list_head link;
	ibng_req_type_t type;
	ibng_req_state_t state;
	uint16_t key;
};

/*
 * local request data. used to keep data which was sent on a round-trip
 * between initiator to target and back again with no modifications i
 * original protocol.
 */
typedef struct ibng_req_data ibng_req_data_t;
struct ibng_req_data {
	ptl_handle_md_t local_md;
	uint32_t local_md_gen;
	ptl_size_t local_offset;
};

/*
 * send/receive/rdma requests, and a request list
 */

#define IBNG_RDMA_MAX_WRS	16
#define IBNG_RDMA_MAX_SGES	16

typedef struct ibng_rdma_req ibng_rdma_req_t;
struct ibng_rdma_req {
	ibng_req_t req;

	struct ibv_mr *mr;
	struct ibv_send_wr wr_list[IBNG_RDMA_MAX_WRS];
	struct ibv_sge sge_list[IBNG_RDMA_MAX_SGES];

	void *lib_data;

	void *private;
};

/* ibng_buffer_t
 *
 * a buffer for sending and receiving.
 */
typedef struct ibng_buffer ibng_buffer_t;
struct ibng_buffer {
	ibng_req_t req;

	void *buffer;
	unsigned int max_size, size;
	int threshold;
	struct ibv_mr *mr;
	struct ibv_sge sge;
	union {
		struct ibv_send_wr s;
		struct ibv_recv_wr r;
	} wr;
	uint32_t chdr;
	ptl_size_t hdrsize;

	ibng_req_data_t req_data;
	void *lib_data;

	void *private;
};

typedef struct ibng_req_list ibng_req_list_t;
typedef int (*ibng_req_list_grow_f)	   (ibng_req_list_t *, unsigned int,
										void *data);
typedef int (*ibng_req_list_destroy_f) (ibng_req_list_t *, void *data);
struct ibng_req_list {
	struct list_head head;
	unsigned int total, current;

	/* handlers for creation and destruction of requests */
	ibng_req_list_grow_f	grow_f;
	ibng_req_list_destroy_f destroy_f;
	void *data;

	union {
		struct {
			struct ibng_buffer_pool *pool;
		} buf;
		struct {
		} rdma;
	} u;

	/* TODO: locking, when we go for MT mode */
};

void ibng_buffer_dump(ibng_buffer_t *buf);
void ibng_rdma_req_dump(ibng_rdma_req_t *req);

ibng_req_list_t *ibng_req_list_create(ibng_req_list_grow_f grow_f,
									  ibng_req_list_destroy_f destroy_f,
									  void *data);
ibng_req_list_t *ibng_req_list_create_with_buffers(unsigned int n,
												   unsigned int size,
												   struct ibv_pd *pd,
												   ibng_req_type_t type,
												   ibng_iset_t *iset);
ibng_req_list_t *ibng_req_list_create_with_rdma_requests(unsigned int n,
														 ibng_iset_t *iset);

/*
 * Destroys a request list.
 */
void ibng_req_list_destroy(ibng_req_list_t *list);

void ibng_req_list_autosize(ibng_req_list_t *list);

static inline ibng_req_t *
ibng_req_list_pop(ibng_req_list_t *list)
{
	struct list_head *l;

	if(list_empty(&list->head)) {
		ibng_req_list_autosize(list);
		if(list_empty(&list->head))
			return NULL;
	}
	l = list->head.next;
	list_del_init(l);
	list->current--;
	return list_entry(l, ibng_req_t, link);
}

static inline void
ibng_req_list_push(ibng_req_list_t *list, ibng_req_t *req)
{
	list_add(&req->link, &list->head);
	list->current++;
}

static inline void
ibng_req_list_append(ibng_req_list_t *list, ibng_req_t *req)
{
	list_add_tail(&req->link, &list->head);
	list->current++;
}

#endif /* __IBNG_BUF_H__ */
