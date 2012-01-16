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

#include "dbg.h"
#include "buf.h"

typedef struct ibng_mem_chunk ibng_mem_chunk_t;
struct ibng_mem_chunk {
	struct list_head link;
	void *mem;
	struct ibv_mr *mr;
	unsigned int size;
};

typedef struct ibng_buffer_pool ibng_buffer_pool_t;
struct ibng_buffer_pool {
	struct list_head buffer_mem;
	struct list_head struct_mem;
	unsigned int size;
	struct ibv_pd *pd;
	ibng_req_type_t type;
};

static ibng_mem_chunk_t *
ibng_mem_chunk_create(unsigned int size, struct ibv_pd *pd)
{
	void *mem;
	ibng_mem_chunk_t *chk;
	size_t msize = sizeof(ibng_mem_chunk_t) + size;

	mem = malloc(msize);
	if(NULL == mem)
		goto fail_out;

	bzero(mem, msize);
	chk = (ibng_mem_chunk_t *)mem;
	INIT_LIST_HEAD(&chk->link);
	chk->mem = (char *)mem + sizeof(ibng_mem_chunk_t);
	chk->size = size;
	if(NULL != pd) {
		chk->mr = ibv_reg_mr(pd, chk->mem, chk->size, IBV_ACCESS_LOCAL_WRITE);
		if(NULL == chk->mr)
			goto fail_out;
	}
	else
		chk->mr = NULL;

	return chk;

 fail_out:
	if(NULL != mem)
		free(mem);

	return NULL;
}

static void
ibng_mem_chunk_destroy(ibng_mem_chunk_t *chk)
{
	if(NULL != chk->mr)
		ibv_dereg_mr(chk->mr);
	free(chk);
}

static ibng_buffer_pool_t *
ibng_buffer_pool_create(unsigned int size, ibng_req_type_t type,
						struct ibv_pd *pd)
{
	ibng_buffer_pool_t *rv =
		(ibng_buffer_pool_t *)malloc(sizeof(ibng_buffer_pool_t));

	if(NULL == rv)
		return NULL;

	rv->size = size;
	rv->pd = pd;
	rv->type = type;

	INIT_LIST_HEAD(&rv->buffer_mem);
	INIT_LIST_HEAD(&rv->struct_mem);

	return rv;
}

static void
ibng_buffer_pool_destroy(ibng_buffer_pool_t *pool)
{
	struct list_head *ptr, *tmp;
	ibng_mem_chunk_t *chk;

	list_for_each_safe(ptr, tmp, &pool->buffer_mem) {
		chk = list_entry(ptr, ibng_mem_chunk_t, link);
		ibng_mem_chunk_destroy(chk);
	}
	list_for_each_safe(ptr, tmp, &pool->struct_mem) {
		chk = list_entry(ptr, ibng_mem_chunk_t, link);
		ibng_mem_chunk_destroy(chk);
	}
}

static int
ibng_buffer_pool_grow(ibng_buffer_pool_t *pool, unsigned int n,
					  ibng_mem_chunk_t **buffer_mem_r,
					  ibng_mem_chunk_t **struct_mem_r)
{
	ibng_mem_chunk_t *buffer_mem = NULL, *struct_mem = NULL;

	buffer_mem = ibng_mem_chunk_create(n*pool->size, pool->pd);
	if(NULL == buffer_mem)
		goto fail_out;
	struct_mem = ibng_mem_chunk_create(n*sizeof(ibng_buffer_t), NULL);
	if(NULL == struct_mem)
		goto fail_out;

	list_add(&buffer_mem->link, &pool->buffer_mem);
	list_add(&struct_mem->link, &pool->struct_mem);

	*buffer_mem_r = buffer_mem;
	*struct_mem_r = struct_mem;

	return 0;

 fail_out:
	if(NULL != buffer_mem)
		ibng_mem_chunk_destroy(buffer_mem);
	if(NULL != struct_mem)
		ibng_mem_chunk_destroy(struct_mem);

	return -1;
}

static int
ibng_buffer_init(ibng_buffer_t *rv, void *mem, struct ibv_mr *mr,
				 unsigned int size, ibng_req_type_t type, uint16_t key)
{
	bzero(rv, sizeof(ibng_buffer_t));

	rv->req.type = type;
	rv->req.key = key;
	rv->req.state = FREE;
	rv->max_size = size;
	rv->buffer = mem;
	rv->mr = mr;

	rv->sge.addr = (uintptr_t)rv->buffer;
	rv->sge.lkey = rv->mr->lkey;
	rv->sge.length = size;

	/* NOTE: wr IDs and send_flags set at posting time */
	if(type == SEND) {
		rv->wr.s.sg_list = &rv->sge;
		rv->wr.s.num_sge = 1;
	}
	else if(type == RECV) {
		rv->wr.r.sg_list = &rv->sge;
		rv->wr.r.num_sge = 1;
	}

	return 0;
}

void 
ibng_buffer_dump(ibng_buffer_t *buf)
{
	IBNG_DBG("ibng_buffer_t [ size = %u, chdr = %u\n", buf->size, buf->chdr);
	if(IBNG_DEBUG_NI(PTL_DBG_NI_05)) {
		IBNG_DBG("buffer = ");
		ibng_dump_char_array((char *)buf->buffer, buf->size);
	}
	IBNG_DBG(" ]\n");
}

static ibng_rdma_req_t *
ibng_rdma_req_create(uint16_t key)
{
	ibng_rdma_req_t *rv;

	rv = (ibng_rdma_req_t *)malloc(sizeof(ibng_rdma_req_t));
	if(NULL == rv)
		return NULL;

	bzero(rv, sizeof(ibng_rdma_req_t));
	rv->req.state = FREE;
	rv->req.key = key;

	/* all the wr and sge members are set just before request posting */

	return rv;
}

static void
ibng_rdma_req_destroy(ibng_rdma_req_t *req)
{
	free(req);
}

void
ibng_rdma_req_dump(ibng_rdma_req_t *req)
{
	struct ibv_send_wr *wr;
	struct ibv_sge *sge;
	int i;

	IBNG_DBG("RDMA request (key %x):\n", (unsigned int)req->req.key);

	wr = &(req->wr_list[0]);
	while(NULL != wr) {
		IBNG_DBG("  WR raddr " UINT64_FMT ", rkey %x, sges %d\n",
				 wr->wr.rdma.remote_addr, wr->wr.rdma.rkey,
				 wr->num_sge);
		sge = wr->sg_list;
		for(i = 0; i < wr->num_sge; i++) {
			IBNG_DBG("    SGE %d, laddr " UINT64_FMT ", len %u, lkey %x\n",
					 i, sge->addr, sge->length, sge->lkey);
			sge++;
		}
		wr = wr->next;
	}
}

ibng_req_list_t *
ibng_req_list_create(ibng_req_list_grow_f grow_f,
					 ibng_req_list_destroy_f destroy_f,
					 void *data)
{
	ibng_req_list_t *rv =
		(ibng_req_list_t *)malloc(sizeof(ibng_req_list_t));

	if(NULL == rv)
		return NULL;

	bzero(rv, sizeof(ibng_req_list_t));
	INIT_LIST_HEAD(&rv->head);

	rv->grow_f = grow_f;
	rv->destroy_f = destroy_f;
	rv->data = data;

	return rv;
}

static int
list_grow_buffers(ibng_req_list_t *list, unsigned int n, void *data)
{
	ibng_buffer_t *buf;
	ibng_mem_chunk_t *buffer_mem, *struct_mem;
	char *ptr;
	unsigned int i;
	ibng_iset_t *iset = (ibng_iset_t *)data;
	uint16_t key;

	if(ibng_buffer_pool_grow(list->u.buf.pool, n,
							 &buffer_mem, &struct_mem))
		return -1;
	i = 0;
	buf = (ibng_buffer_t *)struct_mem->mem;
	ptr = (char *)buffer_mem->mem;
	list->total += n;
	while(i < n) {
		key = ibng_iset_acquire(iset);
		if(IBNG_ISET_INVALID_IDX == key) {
			IBNG_DBG("Key space overflow (only %u of %u buffers created).\n",
					 i, n);
			break;
		}
		ibng_buffer_init(buf, ptr, buffer_mem->mr,
						 list->u.buf.pool->size, 
						 list->u.buf.pool->type,
						 key);
		ibng_iset_el(iset, key) = buf;
		ibng_req_list_push(list, (ibng_req_t *)buf);
		ptr += list->u.buf.pool->size;
		buf++;
		i++;
	}

	return 0;
}

static int
list_destroy_buffers(ibng_req_list_t *list, void *data)
{
	/* TODO: release all buffer keys */
	ibng_buffer_pool_destroy(list->u.buf.pool);

	return 0;
}

ibng_req_list_t *
ibng_req_list_create_with_buffers(unsigned int n, unsigned int size,
								  struct ibv_pd *pd, ibng_req_type_t type,
								  ibng_iset_t *iset)
{
	ibng_req_list_t *rv;

	rv = ibng_req_list_create((ibng_req_list_grow_f)list_grow_buffers,
							  (ibng_req_list_destroy_f)list_destroy_buffers,
							  iset);
	if(NULL == rv)
		return NULL;

	rv->u.buf.pool = ibng_buffer_pool_create(size, type, pd);

	if(list_grow_buffers(rv, n, rv->data))
		goto fail_out;

	return rv;

fail_out:
	ibng_req_list_destroy(rv);

	return NULL;
}

static int
list_grow_rdma_reqs(ibng_req_list_t *list, int n, void *data)
{
	ibng_rdma_req_t *req;
	int i;
	ibng_iset_t *iset = (ibng_iset_t *)data;
	uint16_t key;

	for(i = 0; i < n; i++) {
		key = ibng_iset_acquire(iset);
		if(IBNG_ISET_INVALID_IDX == key) {
			IBNG_DBG("Key space overflow (only %u of %u RDMA reqs created).\n",
					 i, n);
			break;
		}
 		req = ibng_rdma_req_create(key);
		if(NULL == req) {
			ibng_iset_release(iset, key);
			IBNG_DBG("No space for req (only %u of %u RDMA reqs created).\n",
					 i, n);
			break;
		}
		ibng_iset_el(iset, key) = req;
		list->total++;
		ibng_req_list_push(list, (ibng_req_t *)req);
	}

	return 0;
}

static int
list_destroy_rdma_reqs(ibng_req_list_t *list, void *data)
{
	ibng_req_t *req;
	struct list_head *ptr, *tmp;

	list_for_each_safe(ptr, tmp, &list->head) {
		req = list_entry(ptr, ibng_req_t, link);
		ibng_iset_release((ibng_iset_t *)data, req->key);
		ibng_rdma_req_destroy((ibng_rdma_req_t *)req);
	}

	return 0;
}

ibng_req_list_t *
ibng_req_list_create_with_rdma_requests(unsigned int n, ibng_iset_t *iset)
{
	ibng_req_list_t *rv;

	rv = ibng_req_list_create((ibng_req_list_grow_f)list_grow_rdma_reqs,
							  (ibng_req_list_destroy_f)list_destroy_rdma_reqs,
							  iset);
	if(NULL == rv)
		return NULL;

	if(list_grow_rdma_reqs(rv, n, rv->data))
		goto fail_out;

	return rv;

fail_out:
	ibng_req_list_destroy(rv);

	return NULL;
}

void
ibng_req_list_destroy(ibng_req_list_t *rl)
{
	if(NULL != rl->destroy_f)
		rl->destroy_f(rl, rl->data);
	free(rl);
}

void
ibng_req_list_autosize(ibng_req_list_t *list)
{
	if((list->current == 0) && (NULL != list->grow_f)) {
		/* list empty, double the request count */
		IBNG_DBG("Autosizing list (total %u, current %u)\n",
				 list->total, list->current);
		list->grow_f(list, list->total, list->data);
		IBNG_DBG("Autosizing done (total %u, current %u)\n",
				 list->total, list->current);
	}
	/* TODO: should we ever shrink? ;) */
}
