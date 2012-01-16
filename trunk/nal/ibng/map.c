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

#include "p3-config.h"

#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <inttypes.h>
#include <string.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <asm/byteorder.h>

#include <infiniband/mad.h>

#include "dbg.h"
#include "map.h"

#define IBV_QUERY_PORT_NUM_TRIES 5

int
ibng_netmap_local_lid_get(struct ibv_context *ib_ctx, uint8_t port_num,
			  uint16_t *local_lid)
{
	struct ibv_port_attr port_attr = { .state = IBV_PORT_DOWN };

	int num_tries = IBV_QUERY_PORT_NUM_TRIES;

	/* if we are the first task, we could beat the subnet manager */
	while (port_attr.state != IBV_PORT_ACTIVE && num_tries > 0) {
		if (ibv_query_port(ib_ctx, port_num, &port_attr)) {
			if (IBNG_DEBUG_NI(PTL_DBG_NI_00))
				p3_print("ERROR: IB port querying failed!\n");
			return -1;
		}
		if (port_attr.state != IBV_PORT_ACTIVE) {
			sleep(1);
			num_tries--;
		}
	}

	if (port_attr.state != IBV_PORT_ACTIVE && num_tries == 0) {
		if (IBNG_DEBUG_NI(PTL_DBG_NI_00)) {
			p3_print("ERROR: failed to acquire local LID in %d "
				"tries!\n", IBV_QUERY_PORT_NUM_TRIES);
		}
		return -1;
	}

	IBNG_DBG("Local port active (%d), LID %lu\n",
			 (int)port_attr.state, (unsigned long)port_attr.lid);

	*local_lid = port_attr.lid;

	return 0;
}

static void
lid_gid_mappings_print(ibng_netmap_t *netmap)
{
	int i;
	for (i = 0; i < netmap->num_lid_gid_maps; i++) {
		if (netmap->lid_gid_maps[i] != 0) {
			p3_print("lid=%04x gid=" GID_FMT "\n",
                     i, netmap->lid_gid_maps[i]);
		}
	}
}

#ifdef PTL_IBNG_EMBEDDED_MAD

/* NOTE: the following conditional code branch embeds MAD proxy functionality
   in the very portals NAL library. the applications using such embedded MAD
   proxy must have write access to MAD device files (normally only given to
   root on linux) */

#include "mad-proxy/netmap.h"

#define create_map(name, port, num) \
	mad_proxy_lid_gid_mappings_create(name, port, num)

#else /* !PTL_IBNG_EMBEDDED_MAD */

/* NOTE: this conditional code branch retrieves network map from MAD proxy
   daemon (that runs as root) */

#define create_map(name, port, num) \
	lid_gid_mappings_create(name, port, num)

static inline bool
send_string(int socket_fd, char *str)
{
	uint32_t str_len;

	/* +1 in the length of the write function is there because we want to
	 * also transfer the '\0' string termination character. */
	str_len = strlen(str) + 1;
	if (write(socket_fd, &str_len, sizeof(str_len)) < 0)
		return false;
	if (write(socket_fd, str, str_len) < 0)
		return false;

	return true;
}

static uint64_t *
lid_gid_mappings_create(char *dev_name, int dev_port,
						unsigned short num_lid_gid_maps)
{
	const int BUFFER_SIZE = 256;
	uint64_t *lid_gid_maps;
	int socket_fd;
	struct sockaddr_un server_address;
	size_t server_address_length;
	char op_cmd[] = NETMAP_OP_LID_GID_MAPPINGS_GET;
	char op_args[BUFFER_SIZE];
	uint32_t reply_size;
	char *serialized_mappings;
	char *str_mapping;
	int mapping_lid;
	uint64_t mapping_gid;
	ssize_t num_read, num_left;
	char *curr_pos;

	if (!dev_name)
		snprintf(op_args, BUFFER_SIZE, "%d:NULL", dev_port);
	else
		snprintf(op_args, BUFFER_SIZE, "%d:%s", dev_port, dev_name);

	socket_fd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (socket_fd < 0) {
		IBNG_ERROR("lid_gid_mappings_create (socket)");
		return NULL;
	}

	server_address.sun_family = AF_UNIX;
	snprintf(server_address.sun_path, sizeof(server_address.sun_path),
		 "%s/%s", NETMAP_VAR_RUN_DIR, NETMAP_SERVER_SOCKET_FILENAME);
	server_address_length = sizeof(server_address.sun_family) +
		strlen(server_address.sun_path) * sizeof(char);

	if (connect(socket_fd, (struct sockaddr *) &server_address,
		    server_address_length) != 0) {
		IBNG_ERROR("lid_gid_mappings_create (connect)");
		close(socket_fd);
		return NULL;
	}

	IBNG_DBG("sending command to MAD proxy: cmd=\"%s\", args=\"%s\"\n",
		 op_cmd, op_args);

	if (!send_string(socket_fd, op_cmd)) {
		IBNG_ERROR("Sending MAD proxy command failed!\n");
		close(socket_fd);
		return NULL;
	}
	if (!send_string(socket_fd, op_args)) {
		IBNG_ERROR("Sending MAD proxy args failed!\n");
		close(socket_fd);
		return NULL;
	}

	if (read(socket_fd, &reply_size, sizeof(reply_size)) < 0) {
		IBNG_ERROR("lid_gid_mappings_create (read)");
		close(socket_fd);
		return NULL;
	}

	serialized_mappings = calloc(reply_size, sizeof(char));
	if (serialized_mappings == NULL) {
		IBNG_ERROR("Cannot allocate memory for serialized mappings.\n");
		close(socket_fd);
		return NULL;
	}

	num_left = reply_size;
	curr_pos = serialized_mappings;
	while (num_left > 0) {
		num_read = read(socket_fd, curr_pos, reply_size);
		if (num_read < 0) {
			free(serialized_mappings);
			close(socket_fd);
			return NULL;
		}
		num_left -= num_read;
		curr_pos += num_read;
	}

	IBNG_DBG("serialized_mappings = \"%s\"\n", serialized_mappings);

	/* allocate memory for the mapping table. */
	lid_gid_maps = calloc(num_lid_gid_maps, sizeof(uint64_t));
	if (lid_gid_maps == NULL) {
		IBNG_ERROR("Cannot allocate memory for lid_gid_maps!\n");
		free(serialized_mappings);
		close(socket_fd);
		return NULL;
	}
	memset(lid_gid_maps, 0, num_lid_gid_maps * sizeof(uint64_t));

	str_mapping = strtok(serialized_mappings, ";");
	while (str_mapping != NULL) {
		sscanf(str_mapping, "%04x:" GID_FMT, &mapping_lid, &mapping_gid);
		IBNG_DBG("mapping_lid = %x, mapping_gid = " GID_FMT "\n", mapping_lid,
				 mapping_gid);
		lid_gid_maps[mapping_lid] = mapping_gid;
		str_mapping = strtok(NULL, ";");
	}

	free(serialized_mappings);
	close(socket_fd);

	return lid_gid_maps;
}
#endif /* PTL_IBNG_EMBEDDED_MAD */

ibng_netmap_t *
ibng_netmap_create(struct ibv_context *ib_ctx)
{
	ibng_netmap_t *netmap;
	uint16_t local_lid;

	netmap = malloc(sizeof(ibng_netmap_t));
	if (netmap == NULL) {
		if (IBNG_DEBUG_NI(PTL_DBG_NI_00)) {
			p3_print("ERROR: cannot allocate memory for "
				"netmap!\n");
		}
		return NULL;
	}

	/* TODO: is it ok for the subnet_prefix to be hard-coded???? */
	netmap->subnet_prefix = 0xfe80000000000000ULL;

	/* TODO: we need to check all ports, not just port 1. */
	if (ibng_netmap_local_lid_get(ib_ctx, 1, &local_lid) < 0) {
		if (IBNG_DEBUG_NI(PTL_DBG_NI_00))
			p3_print("ERROR: local LID retrieval failed!\n");
		free(netmap);
		return NULL;
	}
	netmap->local_lid = local_lid;

	if (IBNG_DEBUG_NI(PTL_DBG_NI_01))
		p3_print("local LID = %d\n", (int)netmap->local_lid);

	/* we create the whole LID->GID table up-front. there is no use
	 * of resizing it when the remote nodes are added dynamically. */
	netmap->num_lid_gid_maps = USHRT_MAX;
	netmap->lid_gid_maps = create_map(NULL, 0, netmap->num_lid_gid_maps);
	if (netmap->lid_gid_maps == NULL) {
		if (IBNG_DEBUG_NI(PTL_DBG_NI_00))
			p3_print("ERROR: LID->GID mappings creation failed!\n");
		free(netmap);
		return NULL;
	}

	if (IBNG_DEBUG_NI(PTL_DBG_NI_01)) {
		p3_print("LID -> GID mappings:\n");
		lid_gid_mappings_print(netmap);
	}

	return netmap;
}

void
ibng_netmap_destroy(ibng_netmap_t *netmap)
{
	/* destroy the lid->gid mappings. */
	free(netmap->lid_gid_maps);
	free(netmap);
}

int ibng_netmap_get_path_rec(ibng_netmap_t *netmap, uint16_t dest_lid,
			     struct ibv_sa_path_rec *path_rec)
{
	if(0 == netmap->lid_gid_maps[dest_lid])
		return -1;

	memset(path_rec, 0, sizeof(struct ibv_sa_path_rec));
	path_rec->slid = __cpu_to_be16(netmap->local_lid);
	path_rec->dlid = __cpu_to_be16(dest_lid);

	/* gid data is in network order already ... */
	path_rec->dgid.global.subnet_prefix =
		__cpu_to_be64(netmap->subnet_prefix);
	path_rec->dgid.global.interface_id =
		__cpu_to_be64(netmap->lid_gid_maps[dest_lid]);
	path_rec->sgid.global.subnet_prefix =
		__cpu_to_be64(netmap->subnet_prefix);
	path_rec->sgid.global.interface_id =
		__cpu_to_be64(netmap->lid_gid_maps[netmap->local_lid]);

	/* TODO: the following was taken verbatim from cmpost; should review
	   the values and the meaning ... */
	path_rec->raw_traffic = 0;
	path_rec->flow_label = 0;
	path_rec->hop_limit = 0;
	path_rec->traffic_class = 0;
	path_rec->reversible = 0x1000000;

	path_rec->numb_path = 0;
	path_rec->mtu_selector = 2;
	path_rec->rate_selector = 2;
	path_rec->packet_life_time_selector = 2;
	path_rec->preference = 0;

	path_rec->pkey = 0xffff;
	path_rec->sl = 0;
	path_rec->mtu = 4;
	path_rec->rate = 3;
	path_rec->packet_life_time = 18;

	return 0;
}
