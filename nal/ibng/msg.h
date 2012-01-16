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

#ifndef __IBNG_MSG_H__
#define __IBNG_MSG_H__

#include <portals3.h>
#include <p3utils.h>
#include <p3api/types.h>
#include <p3/lock.h>
#include <p3/handle.h>
#include <p3/process.h>
#include <p3lib/types.h>

#include "srv.h"
#include "buf.h"
#include "dbg.h"

/* --- data on the wire --- */

/*
 * common header is packed into a single 32-bit quantity, low to high bits:
 * 0-7 :  flags
 * 8-15:  cmd ID
 * 16-23: ac index
 * 24-31: ptl index
 */
#define HDR_PUT_FLAGS(hdr, fl)	  do { hdr |= fl & 0xff; } while(0)
#define HDR_CLR_FLAGS(hdr, fl)	  do { hdr &= ~((uint32_t)fl & 0xff); } while(0)
#define HDR_PUT_CMDID(hdr, id)	  do { hdr |= (id & 0xff) << 8; } while(0)
#define HDR_PUT_ACIDX(hdr, ac)	  do { hdr |= (ac & 0xff) << 16; } while(0)
#define HDR_PUT_PTIDX(hdr, pt)	  do { hdr |= (pt & 0xff) << 24; } while(0)
#define HDR_GET_FLAGS(hdr)		  (hdr & 0xff)
#define HDR_GET_CMDID(hdr)		  ((hdr >> 8) & 0xff)
#define HDR_GET_ACIDX(hdr)		  ((hdr >> 16) & 0xff)
#define HDR_GET_PTIDX(hdr)		  ((hdr >> 24) & 0xff)

/*
 * header flags
 * if a flag implies data in the extended header (in the payload), the
 * flag-related data is ordered in the same way as flags (from low to high
 * values). i.e. rbm offset comes before user data.
 */

/* generate ack or reply */
#define HDR_F_ACK		(1 << 0)
/* remote buffer management (offset specified in ext header) */
#define HDR_F_RBM		(1 << 1)
/* message payload is rdma rendezvous info (otherwise payload is data) */
#define HDR_F_RDMA		(1 << 2)
/* user data in the header */
#define HDR_F_HDATA		(1 << 3)
/* fragmented eager message */
#define HDR_F_FRAG		(1 << 4)
/* RDMA done message (only key in extended header is valid */
#define HDR_F_RDMA_DONE (1 << 5)

/* 
 * extended header is put on the wire
 */
/* size of request key */
#define EHDR_KEY_SIZE sizeof(uint16_t)
/* request key is always the first thing in the ext header */
#define EHDR_GET_KEY(buf) (*((uint16_t *)buf->buffer))

#define EHDR_MAX_SIZE (EHDR_KEY_SIZE + 3*sizeof(uint64_t))

/* TODO: currently accessing on the wire data buffers when packing/unpacking
   might be quite suboptimal due to suboptimal alignments of data items. */

/*
 * RDMA info for the peer to do a RDMA read.
 */
typedef struct ibng_rdma ibng_rdma_t;
struct ibng_rdma {
	uintptr_t raddr;
	uint32_t  rkey;
	uint32_t  len;
} __attribute__((packed));

static inline void
ptl_hdr_dump(ptl_hdr_t *hdr)
{
	IBNG_DBG("ptl_hdr_t [ dst = (%u, %u), src = (%u, %u), mbits = %llu,"
			 "length = %llu, src_uid = %u, src_jid = %u, msg_type = %u, \n",
			 hdr->dst.nid, hdr->dst.pid, hdr->src.nid, hdr->src.pid,
			 (unsigned long long)hdr->mbits, 
			 (unsigned long long)hdr->length, hdr->src_uid, hdr->src_jid,
			 hdr->msg_type);
	if(hdr->msg_type == PTL_MSG_PUT) {
		IBNG_DBG("msg.put.dst_offset = %llu, msg.put.hdr_data = %llu,"
				 "msg.put.ptl_index = %u, msg.put.ac_index = %u, "
				 "msg.put.ack_md = %u, msg.put.ack_md_gen = %u\n",
				 (unsigned long long)hdr->msg.put.dst_offset, 
				 (unsigned long long)hdr->msg.put.hdr_data,
				 hdr->msg.put.ptl_index, hdr->msg.put.ac_index,
				 hdr->msg.put.ack_md, hdr->msg.put.ack_md_gen);
	}
	else if(hdr->msg_type == PTL_MSG_GET) {
		IBNG_DBG("msg.get.src_offset = %llu, "
				 "msg.get.rtn_offset = %llu,"
				 "msg.get.ptl_index = %u, msg.get.ac_index = %u, "
				 "msg.get.rtn_md = %u, msg.get.ack_md_gen = %u\n",
				 (unsigned long long)hdr->msg.get.src_offset, 
				 (unsigned long long)hdr->msg.get.rtn_offset,
				 hdr->msg.get.ptl_index, hdr->msg.get.ac_index,
				 hdr->msg.get.rtn_md, hdr->msg.get.rtn_md_gen);
	}
	else if(hdr->msg_type == PTL_MSG_GETPUT) {
		IBNG_DBG("msg.getput.src_offset = %llu, "
				 "msg.getput.rtn_offset = %llu, "
				 "msg.getput.hdr_data = %llu, "
				 "msg.getput.ptl_index = %u, msg.getput.ac_index = %u, "
				 "msg.getput.rtn_md = %u, msg.getput.ack_md_gen = %u\n",
				 (unsigned long long)hdr->msg.getput.src_offset, 
				 (unsigned long long)hdr->msg.getput.rtn_offset,
				 (unsigned long long)hdr->msg.getput.hdr_data,
				 hdr->msg.getput.ptl_index, hdr->msg.getput.ac_index,
				 hdr->msg.getput.rtn_md, hdr->msg.getput.rtn_md_gen);
	}
	else if (hdr->msg_type == PTL_MSG_ACK){
		IBNG_DBG("msg.ack.dst_md = %u, msg.ack.dst_md_gen = %u\n",
				 hdr->msg.ack.dst_md, hdr->msg.ack.dst_md_gen);
	}
	else if (hdr->msg_type == PTL_MSG_REPLY){
		IBNG_DBG("msg.reply.dst_offset = %llu, msg.reply.dst_md = %u, "
				 "msg.reply.dst_md_gen = %u\n", 
				 (unsigned long long)hdr->msg.reply.dst_offset, 
				 hdr->msg.reply.dst_md, hdr->msg.reply.dst_md_gen);
	}	
	IBNG_DBG(" ]\n");
}

/* transformations between portals header and ibng wire header */

static inline int
msg_pack_rdma_done(ibng_buffer_t *buf, uint16_t key)
{
	/* common header: stored in buf->chdr */
	buf->chdr = 0;
	HDR_PUT_CMDID(buf->chdr, 0xff);
	HDR_PUT_ACIDX(buf->chdr, 0xff);
	HDR_PUT_PTIDX(buf->chdr, 0xff);
	buf->req_data.local_md = PTL_HANDLE_NONE;

	*((uint16_t *)(buf->buffer)) = key;
	buf->size = EHDR_KEY_SIZE;

	HDR_PUT_FLAGS(buf->chdr, HDR_F_RDMA_DONE);

	buf->wr.s.opcode = IBV_WR_SEND_WITH_IMM;

	return EHDR_KEY_SIZE;
}

static inline int
msg_pack_header(ibng_buffer_t *buf, ptl_hdr_t *hdr, ptl_size_t hdrlen,
				int rdma, int frag)
{
	int size;
	uint32_t chdr = 0;
	uint8_t flags = 0;
	
	/* common header: stored in buf->chdr */
	HDR_PUT_CMDID(chdr, hdr->msg_type);
	if(hdr->msg_type == PTL_MSG_PUT) {
		HDR_PUT_ACIDX(chdr, hdr->msg.put.ac_index);
		HDR_PUT_PTIDX(chdr, hdr->msg.put.ptl_index);
		if(hdr->msg.put.hdr_data != 0)
			flags |= HDR_F_HDATA;
		if(hdr->msg.put.dst_offset != 0)
			flags |= HDR_F_RBM;
	}
	else if(hdr->msg_type == PTL_MSG_GET) {
		HDR_PUT_ACIDX(chdr, hdr->msg.get.ac_index);
		HDR_PUT_PTIDX(chdr, hdr->msg.get.ptl_index);
		if(hdr->msg.put.dst_offset != 0)
			flags |= HDR_F_RBM;
	}
	else if(hdr->msg_type == PTL_MSG_GETPUT) {
		HDR_PUT_ACIDX(chdr, hdr->msg.getput.ac_index);
		HDR_PUT_PTIDX(chdr, hdr->msg.getput.ptl_index);
		if(hdr->msg.getput.hdr_data != 0)
			flags |= HDR_F_HDATA;
		if(hdr->msg.getput.src_offset != 0)
			flags |= HDR_F_RBM;
	}
	else {
		HDR_PUT_ACIDX(chdr, 0xff);
		HDR_PUT_PTIDX(chdr, 0xff);
		buf->req_data.local_md = PTL_HANDLE_NONE;
	}	

	/* extended header: put in buf->buffer payload */

	/* first the request key: key of the original request in case
	   of ack/reply (allows chaining of messages on the requester side),
	   or our own local key in case of a new request. */
	if(hdr->msg_type == PTL_MSG_ACK) {
		*((uint16_t *)(buf->buffer)) =
			(uint16_t)(hdr->msg.ack.dst_md & 0xffff);
		IBNG_DBG("ACK to dst_md %d\n", hdr->msg.ack.dst_md);
	}
	else if(hdr->msg_type == PTL_MSG_REPLY) {
		*((uint16_t *)(buf->buffer)) = 
			(uint16_t)(hdr->msg.reply.dst_md & 0xffff);
		IBNG_DBG("REPLY to dst_md %d\n", hdr->msg.ack.dst_md);
	}
	else
		*((uint16_t *)(buf->buffer)) = buf->req.key;
	size = EHDR_KEY_SIZE;

	if(rdma || frag || (hdr->msg_type == PTL_MSG_GET)) {
		/* size of data can not be deduced from received size in
		   case of:
		   - requests for RDMA transfers,
		   - GET requests,
		   - fragmented data,
		   so we explicitly pack it in the ext header */
		*((ptl_size_t *)(buf->buffer + size)) = hdr->length;
		size += sizeof(ptl_size_t);
		if(frag)
			flags |= HDR_F_FRAG;
		if(rdma && hdr->msg_type != PTL_MSG_REPLY)
			flags |= HDR_F_RDMA;
	}

	if(hdr->msg_type == PTL_MSG_PUT) {
		*((ptl_match_bits_t *)(buf->buffer + size)) = hdr->mbits;
		size += sizeof(ptl_match_bits_t);
		if(flags & HDR_F_HDATA) {
			*((ptl_hdr_data_t *)(buf->buffer + size)) =
				hdr->msg.put.hdr_data;
			size += sizeof(ptl_hdr_data_t);
		}
		if(flags & HDR_F_RBM) {
			*((ptl_size_t *)(buf->buffer + size)) =
				hdr->msg.put.dst_offset;
			size += sizeof(ptl_size_t);
		}
		/* store ack md and gen locally */
		if(hdr->msg.put.ack_md != PTL_INVALID_HANDLE &&
		   hdr->msg.put.ack_md != PTL_HANDLE_NONE) {
			flags |= HDR_F_ACK;
			buf->req_data.local_md = hdr->msg.put.ack_md;
			buf->req_data.local_md_gen = hdr->msg.put.ack_md_gen;
		}
		else
			buf->req_data.local_md = PTL_HANDLE_NONE;
	}
	else if(hdr->msg_type == PTL_MSG_GET) {
		*((ptl_match_bits_t *)(buf->buffer + size)) = hdr->mbits;
		size += sizeof(ptl_match_bits_t);
		if(flags & HDR_F_RBM) {
			*((ptl_size_t *)(buf->buffer + size)) =
				hdr->msg.get.src_offset;
			size += sizeof(ptl_size_t);
		}
		/* store ack md and gen locally */
		if(hdr->msg.get.rtn_md != PTL_INVALID_HANDLE &&
		   hdr->msg.get.rtn_md != PTL_HANDLE_NONE) {
			flags |= HDR_F_ACK;
			buf->req_data.local_md = hdr->msg.get.rtn_md;
			buf->req_data.local_md_gen = hdr->msg.get.rtn_md_gen;
			buf->req_data.local_offset = hdr->msg.get.rtn_offset;
		}
		else
			buf->req_data.local_md = PTL_HANDLE_NONE;
	}
	else if(hdr->msg_type == PTL_MSG_GETPUT) {
		*((ptl_match_bits_t *)(buf->buffer + size)) = hdr->mbits;
		size += sizeof(ptl_match_bits_t);
		if(flags & HDR_F_HDATA) {
			*((ptl_hdr_data_t *)(buf->buffer + size)) =
				hdr->msg.getput.hdr_data;
			size += sizeof(ptl_hdr_data_t);
		}
		if(flags & HDR_F_RBM) {
			*((ptl_size_t *)(buf->buffer + size)) =
				hdr->msg.getput.src_offset;
			size += sizeof(ptl_size_t);
		}
		/* store ack md and gen locally */
		if(hdr->msg.getput.rtn_md != PTL_INVALID_HANDLE &&
		   hdr->msg.getput.rtn_md != PTL_HANDLE_NONE) {
			flags |= HDR_F_ACK;
			buf->req_data.local_md = hdr->msg.getput.rtn_md;
			buf->req_data.local_md_gen = hdr->msg.getput.rtn_md_gen;
			buf->req_data.local_offset = hdr->msg.getput.rtn_offset;
		}
		else
			buf->req_data.local_md = PTL_HANDLE_NONE;
	}
	
	HDR_PUT_FLAGS(chdr, flags);
	buf->chdr = chdr;
	buf->size = size;
	buf->wr.s.opcode = IBV_WR_SEND_WITH_IMM;

	if(flags & HDR_F_ACK)
		buf->threshold++;
	if((flags & HDR_F_RDMA) && (hdr->msg_type == PTL_MSG_PUT))
		buf->threshold++;

	return size;
}

static inline ptl_size_t
msg_pack_data(char *buf, ptl_size_t bufsize,
			  ptl_md_iovec_t *iov, ptl_size_t iovlen,
			  ptl_size_t offset, ptl_size_t len)
{
	ptl_size_t done = 0, i = 0, clen = 0;
	char *base = NULL;

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

	while(i < iovlen && done < len) {
		if(clen > bufsize)
			clen = bufsize;
		if(done + clen > len)
			clen = len - done;
		if(bufsize - done < clen)
			return done;  /* would overflow */
		memcpy(buf + done, base, clen);
		done += clen;
		i++;
		if(i >= iovlen)
			break;
		base = iov[i].iov_base;
		clen = iov[i].iov_len;
	}

	return done;
}

/* NOTE: we do not support fragmentation when exchanging rdma rendezvous
   data. better make sure the send buffers are large enough to accomodate
   largest possible iovs. */

#define EHDR_RDMA_COUNT_TYPE uint16_t
#define EHDR_RDMA_COUNT_SIZE sizeof(EHDR_RDMA_COUNT_TYPE)

static inline int
msg_pack_rdma(char *buf, ptl_size_t bufsize,
			  ptl_md_iovec_t *iov, ptl_size_t iovlen,
			  ptl_size_t offset, ptl_size_t len,
			  ibng_server_t *srv, ibng_reg_key_t *key)
{
	ptl_size_t done = 0, i = 0, clen = 0, n = 0, plen;
	ptl_size_t size = EHDR_RDMA_COUNT_SIZE;
	char *base = NULL;
	ibng_reg_key_t *kp;
	ibng_rdma_t *p = (ibng_rdma_t *)(buf + EHDR_RDMA_COUNT_SIZE);

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
	
	/* TODO: the below code has only been proven correct (and not sure if
	   the proof is correct itself;)), not tested. therefore it requires
	   extensive testing with PtlPut()/Get() and wildly different source
	   and destination iovs. */
	while(i < iovlen && done < len) {
		/* at each iteration, the following is true:
		   - clen is the remaining length in iov[i]
		   - base is the starting address of the remainder of iov[i]
		   to process
		   - done is the size of data already taken care of
		   - len is the total size of data to take care of
		   - bufsize is the remaining space in buffer we're packing into
		*/
		if(bufsize - size < sizeof(ibng_rdma_t))
			return -1;	/* otherwise we overflow the buffer */

		/* get reg key for mem area containing current base address */
		kp = ibng_server_get_reg(srv, key, base);
		if(NULL == kp) {
			IBNG_DBG("No registration for base %p in iov " FMT_PSZ_T ".\n",
                     base, i);
			return -1;
		}
		IBNG_ASSERT(kp->mr != NULL);

		/* get maximum allowed size to transfer from iov[i] */
		if(done + clen > len)
			clen = len - done;

		/* now ... the size that we can *actually* transfer from iov[i]
		   using the reg key that contains current base is the size of
		   the intersection of registered mem & remaining iov[i] mem;
		   if valid memory areas are used, the unsigned arithmetic
		   below can't over/underflow */
		plen = (ptl_size_t)(((char *)kp->base + kp->extent) - base);
		if(clen < plen)
			plen = clen;
		p->raddr = (uintptr_t)base;
		p->len = plen;
		p->rkey = kp->mr->rkey;
		IBNG_DBG("RDMA info " FMT_PSZ_T ": raddr " UINTPTR_FMT
                 ", len %u, rkey %08x\n",
				 n, p->raddr, p->len, p->rkey);
		n++;
		p++;
		size += sizeof(ibng_rdma_t);
		clen = clen - plen;			
		done += plen;
		if(0 == clen) {
			/* move to next iov */
			i++;
			if(i >= iovlen)
				break;
			base = iov[i].iov_base;
			clen = iov[i].iov_len;
		}
		else {
			/* more data in this iov */
			base += plen;
		}
	}

	*((EHDR_RDMA_COUNT_TYPE *)buf) = n;

	return size;
}

/* TODO: take care of fragmented rdma info */
static inline int
msg_unpack_rdma(char *buf, enum ibv_wr_opcode op,
				ptl_md_iovec_t *dst_iov,
				ptl_size_t dst_iovlen,
				ptl_size_t dst_offset,
				ptl_size_t dst_len,
				ibng_cnx_t *cnx,
				ibng_reg_key_t *dst_reg_key,
				ibng_rdma_req_t *rreq)
{
	EHDR_RDMA_COUNT_TYPE n;
	ibng_rdma_t *rdma;
	ibng_reg_key_t *kp;
	int nwr, nsge;
	ptl_size_t r_len, clen, plen, i, done;
	char *r_base, *base;

	IBNG_DBG("Unpacking RDMA info into RDMA request %p\n", rreq);

	i = 0;
	while(i < dst_iovlen) {
		if(dst_iov[i].iov_len > dst_offset) {
			base = dst_iov[i].iov_base + dst_offset;
			clen = dst_iov[i].iov_len - dst_offset;
			dst_offset = 0;
			break;
		}
		i++;
		dst_offset -= dst_iov[i].iov_len;
	}

	done = 0;
	n = *((EHDR_RDMA_COUNT_TYPE *)buf);
	nwr = nsge = 0;
	rdma = (ibng_rdma_t *)(buf + EHDR_RDMA_COUNT_SIZE);
	/* this one is painful ...
	   foreach(rdma_data in message) {
		   make_wr(rdma_data)
		   while(remains(memory_to_transfer(rdma_data))) {
					add_sge_to_wr(intersection of iov and registered memory);
			   }
		   }
	*/
	while(i < dst_iovlen && n > 0 && done < dst_len &&
		  nwr < IBNG_RDMA_MAX_WRS && nsge < IBNG_RDMA_MAX_SGES) {
		IBNG_DBG("Unpacked RDMA: base %p, len %u, rkey %x\n",
				 (void *)rdma->raddr, rdma->len, rdma->rkey);
		r_len = rdma->len;
		r_base = (char *)rdma->raddr;
		rreq->wr_list[nwr].wr.rdma.remote_addr = (uintptr_t)r_base;
		rreq->wr_list[nwr].wr.rdma.rkey = rdma->rkey;
		rreq->wr_list[nwr].wr_id = WRID_RDMA(cnx, rreq->req.key);
		rreq->wr_list[nwr].opcode = op;
		rreq->wr_list[nwr].send_flags = IBV_SEND_SIGNALED;
		rreq->wr_list[nwr].num_sge = 0;
		rreq->wr_list[nwr].sg_list = &(rreq->sge_list[nsge]);
		rreq->wr_list[nwr].next = NULL;
		if(nwr > 0)
			rreq->wr_list[nwr - 1].next = &(rreq->wr_list[nwr]);
		while(i < dst_iovlen && r_len > 0 && done < dst_len &&
			  nsge < IBNG_RDMA_MAX_SGES) {
			kp = ibng_server_get_reg(cnx->srv, dst_reg_key, base);
			if(NULL == kp) {
				IBNG_DBG("No registration for base %p in iov " FMT_PSZ_T ".\n",
                         base, i);
				return -1;
			}
			if(done + clen > dst_len)
				clen = dst_len - done;
			/* intersect, intersect, intersect ... */
			plen = (ptl_size_t)(((char *)kp->base + kp->extent) - base);
			if(clen < plen)
				plen = clen;
			if(r_len < plen)
				plen = r_len;
			rreq->sge_list[nsge].addr = (uintptr_t)base;
			rreq->sge_list[nsge].length = plen;
			rreq->sge_list[nsge].lkey = kp->mr->lkey;
			rreq->wr_list[nwr].num_sge++;
			nsge++;
			r_len -= plen;
			clen -= plen;
			done += plen;
			if(0 == clen) {
				/* move to next iov */
				i++;
				if(i >= dst_iovlen)
					break;
				base = dst_iov[i].iov_base;
				clen = dst_iov[i].iov_len;
			}
			else {
				/* more space in this iov */
				base += plen;
			}
		}
		n++;
		rdma++;
		nwr++;
	}

	if(done != dst_len) {
		IBNG_DBG("Insufficient resources to fetch all (" FMT_PSZ_T " != "
                 FMT_PSZ_T ").\n",
				 done, dst_len);
		/* TODO: in case of insufficient resources, we could divide this
		   between two rdma reqs ... oh, well ... it's complicated enough
		   as it is. */
		return -1;
	}

	return 0;
}

static inline int
msg_unpack_header(ptl_hdr_t *hdr, ibng_buffer_t *buf, ibng_cnx_t *cnx)
{	
	uint32_t chdr;
	uint8_t flags;
	char *ptr;
	ptl_size_t hdrsize = 0;
	ibng_buffer_t *obuf;
	uint16_t key;
	
	chdr = buf->chdr;
	flags = HDR_GET_FLAGS(chdr);
	ptr = buf->buffer;

	bzero(hdr, sizeof(ptl_hdr_t));

	hdr->dst = cnx->srv->local_pid;
	hdr->src = cnx->remote_pid;
	hdr->src_uid = cnx->remote_uid;
	hdr->src_jid = cnx->remote_jid;

	hdr->msg_type = HDR_GET_CMDID(chdr);
	if(hdr->msg_type == PTL_MSG_PUT) {
		hdr->msg.put.ac_index = HDR_GET_ACIDX(chdr);
		hdr->msg.put.ptl_index = HDR_GET_PTIDX(chdr);
	}
	else if(hdr->msg_type == PTL_MSG_GET) {
		hdr->msg.get.ac_index = HDR_GET_ACIDX(chdr);
		hdr->msg.get.ptl_index = HDR_GET_PTIDX(chdr);
	}
	else if(hdr->msg_type == PTL_MSG_GETPUT) {
		hdr->msg.getput.ac_index = HDR_GET_ACIDX(chdr);
		hdr->msg.getput.ptl_index = HDR_GET_PTIDX(chdr);		
	}

	key = EHDR_GET_KEY(buf);
	hdrsize += EHDR_KEY_SIZE;
	if(hdr->msg_type == PTL_MSG_ACK) {
		obuf = (ibng_buffer_t *)ibng_iset_el(cnx->reqs_pending, key);
		IBNG_DBG("ACK for key %d, buf %p\n", key, obuf);
		hdr->msg.ack.dst_md = obuf->req_data.local_md;
		hdr->msg.ack.dst_md_gen = obuf->req_data.local_md_gen;
	}
	else if(hdr->msg_type == PTL_MSG_REPLY) {
		obuf = (ibng_buffer_t *)ibng_iset_el(cnx->reqs_pending, key);
		IBNG_DBG("REPLY for key %d, buf %p\n", key, obuf);
		hdr->msg.reply.dst_md = obuf->req_data.local_md;
		hdr->msg.reply.dst_md_gen = obuf->req_data.local_md_gen;
		hdr->msg.reply.dst_offset = obuf->req_data.local_offset;
	}

	if((flags & HDR_F_RDMA) || (flags & HDR_F_FRAG) ||
	   (hdr->msg_type == PTL_MSG_GET)) {
		hdr->length = *((ptl_size_t *)(ptr + hdrsize));
		hdrsize += sizeof(ptl_size_t);
	}
	else {
		hdr->length = 0; /* will be set later, once we determined the
							whole hdrsize */
	}

	if(hdr->msg_type == PTL_MSG_PUT) {
		hdr->mbits = *((ptl_match_bits_t *)(ptr + hdrsize));
		hdrsize += sizeof(ptl_match_bits_t);
		if(flags & HDR_F_HDATA) {
			hdr->msg.put.hdr_data = *((ptl_hdr_data_t *)(ptr + hdrsize));
			hdrsize += sizeof(ptl_hdr_data_t);
		}
		if(flags & HDR_F_RBM) {
			hdr->msg.put.dst_offset = *((ptl_size_t *)(ptr + hdrsize));	
			hdrsize += sizeof(ptl_size_t);
		}
		if(flags & HDR_F_ACK)
			hdr->msg.put.ack_md = (ptl_handle_md_t)key;
		else
			hdr->msg.put.ack_md = PTL_HANDLE_NONE;
	}
	else if(hdr->msg_type == PTL_MSG_GET) {		
		hdr->mbits = *((ptl_match_bits_t *)(ptr + hdrsize));
		hdrsize += sizeof(ptl_match_bits_t);
		if(flags & HDR_F_RBM) {
			hdr->msg.get.src_offset = *((ptl_size_t *)(ptr + hdrsize));
			hdrsize += sizeof(ptl_size_t);
		}
		if(flags & HDR_F_ACK)
			hdr->msg.get.rtn_md = (ptl_handle_md_t)key;
		else
			hdr->msg.get.rtn_md = PTL_HANDLE_NONE;
	}
	else if(hdr->msg_type == PTL_MSG_GETPUT) {
		hdr->mbits = *((ptl_match_bits_t *)(ptr + hdrsize));
		hdrsize += sizeof(ptl_match_bits_t);
		if(flags & HDR_F_HDATA) {
			hdr->msg.getput.hdr_data = *((ptl_hdr_data_t *)(ptr + hdrsize));
			hdrsize += sizeof(ptl_hdr_data_t);
		}
		if(flags & HDR_F_RBM) {
			hdr->msg.getput.src_offset = *((ptl_size_t *)(ptr + hdrsize));
			hdrsize += sizeof(ptl_size_t);
		}
		if(flags & HDR_F_ACK)
			hdr->msg.getput.rtn_md = (ptl_handle_md_t)key;
		else
			hdr->msg.getput.rtn_md = PTL_HANDLE_NONE;
	}

	if(0 == hdr->length) {
		/* complete payload fits in this packet, explicit length was omitted */
		hdr->length = buf->size - hdrsize;
	}

	return hdrsize;
}

static inline int
ibng_buffer_needs_reply_p(ibng_buffer_t *buf)
{
	uint8_t flags = HDR_GET_FLAGS(buf->chdr);
	return (flags & (HDR_F_ACK | flags & HDR_F_RDMA));
}

static inline int
ibng_buffer_is_last_p(ibng_buffer_t *buf)
{
	uint8_t flags = HDR_GET_FLAGS(buf->chdr);
	return ((buf->lib_data != NULL) && !(flags & HDR_F_RDMA));
}

static inline int
ibng_buffer_is_rdma_get_send_p(ibng_buffer_t *buf)
{
	uint8_t flags = HDR_GET_FLAGS(buf->chdr);
	uint8_t cmdid = HDR_GET_CMDID(buf->chdr);

	return (flags & HDR_F_RDMA) && (cmdid == PTL_MSG_GET);
}

#endif /* __IBNG_MSG_H__ */
