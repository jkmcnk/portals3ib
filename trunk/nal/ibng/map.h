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

#ifndef __IBNG_MAP_H__
#define __IBNG_MAP_H__

#include <infiniband/verbs.h>
#include <infiniband/sa.h>

#include "map-types.h"

/*
 * creates a netmap:
 * - subnet prefix
 * - local lid
 * - subnet-wide lid->gid mapping
 */
ibng_netmap_t *ibng_netmap_create(struct ibv_context *ib_ctx);

void ibng_netmap_destroy(ibng_netmap_t *netmap);

int ibng_netmap_get_path_rec(ibng_netmap_t *netmap, uint16_t dest_lid, 
			     struct ibv_sa_path_rec *path_rec);

static inline unsigned short ibng_num_lid_gid_maps(ibng_netmap_t *netmap)
{
	return netmap->num_lid_gid_maps;
}

int ibng_netmap_local_lid_get(struct ibv_context *ib_ctx, uint8_t port_num, 
			      uint16_t *local_lid);

#endif /* __IBNG_MAP_H__ */
