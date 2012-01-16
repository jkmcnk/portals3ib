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
#include <errno.h>

#include "cfg.h"
#include "dbg.h"

ibng_cfg_t ibng_config;

static void
ibng_cfg_init_from_defaults(void)
{
	ibng_config.n_recv_buffers = 512;
	ibng_config.n_send_buffers = 512;
	ibng_config.buffer_size = 512;
	ibng_config.n_rdma_reqs = 8;
	ibng_config.max_send_wrs = 512;
	ibng_config.max_recv_wrs = 512;
	ibng_config.max_rdma_out = 1;
    /* if set to 0, a valid max_inline parameter for the host system
       will be detected when creating the first QP */
	ibng_config.max_inline = 0;
	ibng_config.eager_threshold = 64*1024;
}

#ifdef DEBUG_PTL_INTERNALS
static void
ibng_cfg_dump(void)
{
	IBNG_DBG_A("ibng_config.n_recv_buffers = %lu\n",
			   ibng_config.n_recv_buffers);
	IBNG_DBG_A("ibng_config.n_send_buffers = %lu\n",
			   ibng_config.n_send_buffers);
	IBNG_DBG_A("ibng_config.buffer_size = %lu\n", ibng_config.buffer_size);
	IBNG_DBG_A("ibng_config.n_rdma_reqs = %lu\n", ibng_config.n_rdma_reqs);
	IBNG_DBG_A("ibng_config.max_send_wrs = %lu\n", ibng_config.max_send_wrs);
	IBNG_DBG_A("ibng_config.max_recv_wrs = %lu\n", ibng_config.max_recv_wrs);
	IBNG_DBG_A("ibng_config.max_rdma_out = %lu\n", ibng_config.max_rdma_out);
	IBNG_DBG_A("ibng_config.max_inline = %lu\n", ibng_config.max_inline);
	IBNG_DBG_A("ibng_config.eager_threshold = %lu\n",
			   ibng_config.eager_threshold);
}
#endif /* DEBUG_PTL_INTERNALS */

#define IBNG_N_RECV_BUFFERS  "IBNG_N_RECV_BUFFERS"
#define IBNG_N_SEND_BUFFERS  "IBNG_N_SEND_BUFFERS"
#define IBNG_BUFFER_SIZE     "IBNG_BUFFER_SIZE"
#define IBNG_N_RDMA_REQS     "IBNG_N_RDMA_REQS"
#define IBNG_MAX_SEND_WRS    "IBNG_MAX_SEND_WRS"
#define IBNG_MAX_RECV_WRS    "IBNG_MAX_RECV_WRS"
#define IBNG_MAX_RDMA_OUT    "IBNG_MAX_RDMA_OUT"
#define IBNG_MAX_INLINE      "IBNG_MAX_INLINE"
#define IBNG_EAGER_THRESHOLD "IBNG_EAGER_THRESHOLD"

static struct {
	const char *env;
	unsigned long *val;
} ibng_cfg_env_params[] = {
	{ IBNG_N_RECV_BUFFERS,  &ibng_config.n_recv_buffers },
	{ IBNG_N_SEND_BUFFERS,  &ibng_config.n_send_buffers },
	{ IBNG_BUFFER_SIZE,     &ibng_config.buffer_size },
	{ IBNG_N_RDMA_REQS,     &ibng_config.n_rdma_reqs },
	{ IBNG_MAX_SEND_WRS,    &ibng_config.max_send_wrs },
	{ IBNG_MAX_RECV_WRS,    &ibng_config.max_recv_wrs },
	{ IBNG_MAX_RDMA_OUT,    &ibng_config.max_rdma_out },
	{ IBNG_MAX_INLINE,      &ibng_config.max_inline },
	{ IBNG_EAGER_THRESHOLD, &ibng_config.eager_threshold },
	{ NULL, NULL }
};

void
ibng_cfg_init_from_env(void)
{
	char *tmpstr;
	unsigned long tmpval;
	int i;

	ibng_cfg_init_from_defaults();

	for(i = 0; ibng_cfg_env_params[i].env != NULL; i++) {
		tmpstr = getenv(ibng_cfg_env_params[i].env);
		if(NULL != tmpstr) {
			errno = 0;
			tmpval = strtoul(tmpstr, NULL, 10);
			if(0 == errno)
				*ibng_cfg_env_params[i].val = tmpval;
		}
	}

#ifdef DEBUG_PTL_INTERNALS
	ibng_cfg_dump();
#endif /* DEBUG_PTL_INTERNALS */
}
