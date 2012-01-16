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

#ifndef MAPTYPES_H_
#define MAPTYPES_H_

#include <stdint.h>

typedef struct ibng_netmap ibng_netmap_t;
struct ibng_netmap {
	uint64_t subnet_prefix;
	uint16_t local_lid;
	
	/* lid -> gid mappings. */
	unsigned short num_lid_gid_maps;
	uint64_t *lid_gid_maps;
};

#define NETMAP_VAR_RUN_DIR "/var/run/ibng-mad-proxy"
#define NETMAP_SERVER_SOCKET_FILENAME "socket"

#define NETMAP_OP_LID_GID_MAPPINGS_GET "netmap-lid-gid-mappings-get"  

#endif /* MAPTYPES_H_ */
