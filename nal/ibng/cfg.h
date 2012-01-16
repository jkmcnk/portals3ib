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

#ifndef __IBNG_CFG_H__
#define __IBNG_CFG_H__

typedef struct ibng_cfg ibng_cfg_t;
struct ibng_cfg {
	unsigned long n_recv_buffers;  /* # of receive buffers posted */
	unsigned long n_send_buffers;  /* initial # of send buffers available */
	unsigned long buffer_size;     /* size of recv and send buffers */
	unsigned long n_rdma_reqs;     /* initial # of rdma requests available */
	unsigned long max_send_wrs;    /* max send WRs per CQ */
	unsigned long max_recv_wrs;    /* max recv WRs per CQ */
	unsigned long max_rdma_out;    /* max outstanding RDMA requests */
	unsigned long max_inline;      /* max size of inline data */
	unsigned long eager_threshold; /* switch between eager and rendezvous
									  transfers at this message size */
};

extern ibng_cfg_t ibng_config;

void ibng_cfg_init_from_env(void);

#endif /* __IBNG_CFG_H__ */
