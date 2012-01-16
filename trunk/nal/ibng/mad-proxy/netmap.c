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

#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <inttypes.h>

#include <asm/byteorder.h>

#include <infiniband/mad.h>

#include <dbg.h>
#include <ht.h>
#include "netmap.h"

#define IBV_QUERY_PORT_NUM_TRIES 5
#define SMP_QUERY_TIMEOUT 2000  /* unit is ms */

#define IB_NODE_TYPE_CA 1
#define IB_NODE_TYPE_SWITCH 2
#define	IB_NODE_TYPE_ROUTER 3

struct ib_port;

struct ib_node {
	ibng_ht_element_t link;
	int type;
	int dist;
	int numports;
	int localport;
	uint64_t nodeguid;
	uint64_t portguid;
	ib_portid_t path;
	struct ib_node *next_distance;
	struct ib_port *ports_list;
};

struct ib_port {
	int lid;
	uint64_t portguid;
	int portnum;
	int phys_state;
	struct ib_port *next;
	struct ib_node *node;
	struct ib_port *remote_port; /* null if SMA */
};

/* TODO: the global hashtable is here only for easier porting. We should
 * remove it as soon as possible!!!!! */
#define HASHTABLE_SIZE 137

static ibng_ht_key
nodes_hashtbl_hash_f(const void *key)
{
	uint64_t guid = *((uint64_t *)key);

	return ((uint32_t)(((uint32_t)(guid) * 101) ^
		((uint32_t)((guid) >> 32) * 103)));
}

static int
nodes_hashtbl_cmp_f(const void *a, const void *b)
{
	uint64_t val_a, val_b;

	val_a = *((uint64_t *)a);
	val_b = *((uint64_t *)b);

	return (int)(val_a - val_b);
}

static ibng_htable_t *nodes_hashtbl;

/* TODO: the global distance table is here only for easier porting.
 * We should remove it as soon as possible!!! */
#define MAX_HOPS 63
struct ib_node *nodes_dist[MAX_HOPS+1];     /* last is Ca list */

static inline void
decode_port_info(void *port_info, struct ib_port *port_data)
{
	mad_decode_field(port_info, IB_PORT_LID_F, &port_data->lid);
	mad_decode_field(port_info, IB_PORT_PHYS_STATE_F,
		&port_data->phys_state);
}

static struct ib_node *
create_node(struct ib_node *node_buf,
	ib_portid_t *path, int dist)
{
	struct ib_node *node;

	node = malloc(sizeof(struct ib_node));
	if (!node) {
		if (IBNG_DEBUG_NI(PTL_DBG_NI_00))
			p3_print("ERROR: cannot allocate memory for node!\n");
		return NULL;
	}

	memcpy(node, node_buf, sizeof(*node));
	node->dist = dist;
	node->path = *path;
	node->link.next = NULL;
	node->link.key = NULL;
	node->next_distance = NULL;
	node->ports_list = NULL;

	return node;
}

static struct ib_port *
create_port(struct ib_port *port_buf)
{
	struct ib_port *port;

	port = malloc(sizeof(struct ib_port));
	if (!port) {
		if (IBNG_DEBUG_NI(PTL_DBG_NI_00))
			p3_print("ERROR: cannot allocate memory for port!\n");
		return NULL;
	}
	memcpy(port, port_buf, sizeof(*port));

	return port;
}

static void
add_node_to_hashtables(struct ib_node *node, int dist)
{
	/* add node to nodes hash table. */
	ibng_htable_put(nodes_hashtbl, &node->nodeguid, &node->link);

	/* add node to the distance table. */
	if (node->type != IB_NODE_TYPE_SWITCH)
		dist = MAX_HOPS; /* special Ca list */

	node->next_distance = nodes_dist[dist];
	nodes_dist[dist] = node;
}

static void
add_port_to_node(struct ib_port *port, struct ib_node *node)
{
	port->node = node;
	port->next = node->ports_list;
	node->ports_list = port;
}

static struct ib_node *
create_and_register_node(struct ib_node *node_buf,
	ib_portid_t *path, int dist)
{
	struct ib_node *node;

	/* create local node data and add it to both tables. */
	node = create_node(node_buf, path, dist);
	if (!node) {
		if (IBNG_DEBUG_NI(PTL_DBG_NI_00))
			p3_print("ERROR: node creation failed!\n");
		return NULL;
	}
	add_node_to_hashtables(node, dist);

	return node;
}

static struct ib_port *
create_port_and_add_to_node(struct ib_port *port_buf,  struct ib_node *node)
{
	struct ib_port *port;

	port = create_port(port_buf);
	if (!port) {
		if (IBNG_DEBUG_NI(PTL_DBG_NI_00))
			p3_print("ERROR: port creation failed!\n");
		return NULL;
	}
	add_port_to_node(port, node);

	return port;
}

static int
query_node(ib_portid_t *port_id, struct ib_node *node_data,
	struct ib_port *port_data)
{
	uint8_t node_info[64];
	uint8_t port_info[64];

	if (!smp_query(node_info, port_id, IB_ATTR_NODE_INFO, 0,
		       SMP_QUERY_TIMEOUT)) {
		if (IBNG_DEBUG_NI(PTL_DBG_NI_00))
			p3_print("ERROR: smp_query(node_info) node querying "
				"function failed!\n");
		return -1;
	}

	mad_decode_field(node_info, IB_NODE_GUID_F, &node_data->nodeguid);
	mad_decode_field(node_info, IB_NODE_TYPE_F, &node_data->type);
	mad_decode_field(node_info, IB_NODE_NPORTS_F, &node_data->numports);
	mad_decode_field(node_info, IB_NODE_PORT_GUID_F, &node_data->portguid);
	mad_decode_field(node_info, IB_NODE_LOCAL_PORT_F,
			 &node_data->localport);

	if (!smp_query(port_info, port_id, IB_ATTR_PORT_INFO, 0,
		SMP_QUERY_TIMEOUT)) {
		if (IBNG_DEBUG_NI(PTL_DBG_NI_00))
			p3_print("ERROR: smp_query(port_info) node querying "
				"function failed!\n");
		return -1;
	}

	port_data->portnum = node_data->localport;
	port_data->portguid = node_data->portguid;

	decode_port_info(port_info, port_data);

	if (node_data->type != IB_NODE_TYPE_SWITCH)
		return 0;

	/* after we have the SMA information find out the real port_info for
	 * this port */
	if (!smp_query(port_info, port_id, IB_ATTR_PORT_INFO,
		node_data->localport, SMP_QUERY_TIMEOUT)) {
		if (IBNG_DEBUG_NI(PTL_DBG_NI_00))
			p3_print("ERROR: smp_query(port_info) node querying "
				"function failed!\n");
		return -1;
	}
	decode_port_info(port_info, port_data);

	return 0;
}

static int
query_port(ib_portid_t *port_id, int port_num, struct ib_port *port_data)
{
	uint8_t port_info[64];

	port_data->portnum = port_num;

	if (!smp_query(port_info, port_id, IB_ATTR_PORT_INFO, port_num,
		       SMP_QUERY_TIMEOUT)) {
		if (IBNG_DEBUG_NI(PTL_DBG_NI_00))
			p3_print("ERROR: smp_query(port_info) port querying "
				"function failed!\n");
		return -1;
	}
	decode_port_info(port_info, port_data);

	return 0;
}


static int
extend_dpath(ib_dr_path_t *path, int next_port)
{
	if (path->cnt + 2 >= (int)sizeof(path->p)) {
		if (IBNG_DEBUG_NI(PTL_DBG_NI_00))
			p3_print("ERROR: the dpath exceeds the max number of "
				"hops!\n");
		return -1;
	}
	/* add the newly discovered port to the dpath. */
	path->cnt++;
	path->p[path->cnt] = next_port;

	return path->cnt;
}

static struct ib_port *
find_port(struct ib_port *port_buf, struct ib_node *node)
{
	struct ib_port *tmp_port;

	for (tmp_port = node->ports_list; tmp_port;
		tmp_port = tmp_port->next)
		if (tmp_port->portnum == port_buf->portnum)
			return tmp_port;
	return NULL;
}

static void
link_ports(struct ib_port *local_port, struct ib_port *remote_port)
{
	if (local_port->remote_port)
		local_port->remote_port->remote_port = NULL;

	if (remote_port->remote_port)
		remote_port->remote_port->remote_port = NULL;

	local_port->remote_port = remote_port;
	remote_port->remote_port = local_port;
}

static int
handle_port(struct ib_node *node, struct ib_port *port, ib_portid_t *path,
	int port_num, int dist)
{
	int i;
	struct ib_node node_buf;
	struct ib_port port_buf;
	struct ib_node *remote_node, *existing_node;
	struct ib_port *remote_port, *existing_port;

	memset(&node_buf, 0, sizeof(node_buf));
	memset(&port_buf, 0, sizeof(port_buf));

	if (IBNG_DEBUG_NI(PTL_DBG_NI_02))
		p3_print("handling node %p(%x) port %p:%d dist %d\n", node,
			 node->nodeguid, port, port_num, dist);

	if (port->phys_state != 5) {
		/* the port physical state is not LinkUp. */
		if (IBNG_DEBUG_NI(PTL_DBG_NI_00))
			p3_print("WARNING: port->phys_state = %d differs from LinkUp!\n",
				port->phys_state);
		return -1;
	}

	if (extend_dpath(&path->drpath, port_num) < 0) {
		if (IBNG_DEBUG_NI(PTL_DBG_NI_00))
			p3_print("ERROR: the dpath extension failed!\n");
		return -1;
	}

	if (IBNG_DEBUG_NI(PTL_DBG_NI_00)) {
		p3_print("Performing query_node: drpath = ");
		for (i = 0; i < path->drpath.cnt; i++)
			fprintf(p3_out, "%d, ", path->drpath.p[i]);

		fprintf(p3_out, "\n");
	}

	if (query_node(path, &node_buf, &port_buf) < 0) {
		if (IBNG_DEBUG_NI(PTL_DBG_NI_01))
			p3_print("WARN: node_query on %s failed, skipping "
				"port!\n", portid2str(path));

		/* remove the current port_num from the path because the remote
		 * node failed to respond to a query. */
		path->drpath.cnt--;

		return -1;
	}

	existing_node = (struct ib_node *)ibng_htable_get(nodes_hashtbl,
							  &node_buf.nodeguid);
	if (existing_node)
		remote_node = existing_node;
	else {
		remote_node = create_and_register_node(&node_buf, path,
						       dist + 1);
		if (!remote_node) {
			if (IBNG_DEBUG_NI(PTL_DBG_NI_00))
				p3_print("ERROR: remote node creation "
					"failed!\n");
			return -1;
		}
	}

	existing_port = find_port(&port_buf, remote_node);
	if (existing_port) {
		remote_port = existing_port;
		if (node != remote_node || port != remote_port) {
			/* replace the existing port. */
			if (IBNG_DEBUG_NI(PTL_DBG_NI_01))
				p3_print("WARN: port moving...\n");
		}
	} else {
		remote_port = create_port_and_add_to_node(&port_buf,
							  remote_node);
		if (!remote_port) {
			if (IBNG_DEBUG_NI(PTL_DBG_NI_00))
				p3_print("ERROR: remote node's port creation "
					"failed!\n");
			return -1;
		}
	}

	if (IBNG_DEBUG_NI(PTL_DBG_NI_02)) {
		p3_print("%s -> %s {%016" PRIx64 "} portnum %d lid %d\n",
			 portid2str(path),
			 existing_node ? "known remote" : "new remote",
			 remote_node->nodeguid,
			 remote_node->type == IB_NODE_TYPE_SWITCH ?
			 0 : remote_port->portnum,
			 remote_port->lid);
	}

	/* make a link between local port and the remote port. */
	if (IBNG_DEBUG_NI(PTL_DBG_NI_02)) {
		p3_print("linking: 0x%" PRIx64 " %p->%p:%u and 0x%" PRIx64
			 " %p->%p:%u\n", node->nodeguid, node, port,
			 port->portnum, remote_node->nodeguid, remote_node,
			 remote_port, remote_port->portnum);
	}
	link_ports(port, remote_port);

	/* restore path */
	path->drpath.cnt--;

	return 0;
}

static int
discover_remote_nodes(uint64_t *lid_gid_maps)
{
	ib_portid_t local_portid = {0};
	struct ib_node node_buf;
	struct ib_port port_buf;
	struct ib_node *node;
	struct ib_port *port;
	int dist;
	int port_num;
	ib_portid_t *path;

	if (IBNG_DEBUG_NI(PTL_DBG_NI_01))
		p3_print("Performing remote nodes discovery from %s\n",
			 portid2str(&local_portid));

	memset(&node_buf, 0, sizeof(node_buf));
	memset(&port_buf, 0, sizeof(port_buf));

	/* get data about the local node. */
	if (query_node(&local_portid, &node_buf, &port_buf) < 0) {
		if (IBNG_DEBUG_NI(PTL_DBG_NI_00))
			p3_print("ERROR: local node querying failed!\n");
		return -1;
	}

	node = create_and_register_node(&node_buf, &local_portid, 0);
	if (!node) {
		if (IBNG_DEBUG_NI(PTL_DBG_NI_00))
			p3_print("ERROR: local node creation failed!\n");
		return -1;
	}

	port = create_port_and_add_to_node(&port_buf, node);
	if (!port) {
		if (IBNG_DEBUG_NI(PTL_DBG_NI_00))
			p3_print("ERROR: local node's port creation "
				"failed!\n");
		return -1;
	}

	if (node->type != IB_NODE_TYPE_SWITCH)
		if (handle_port(node, port, &local_portid,
				node->localport, 0) < 0)
			return 0;

	for (dist = 0; dist < MAX_HOPS; dist++) {

		for (node = nodes_dist[dist]; node;
		     node = node->next_distance) {

			path = &node->path;

			for (port_num = 1; port_num <= node->numports;
			     port_num++) {
				/* skip the port searching for the local
				 * ports. */
				if (port_num == node->localport)
					continue;
				if (query_port(path, port_num,
					       &port_buf) < 0) {
					if (IBNG_DEBUG_NI(PTL_DBG_NI_01))
						p3_print("WARN: can't reach "
							 "node %s, port %d!\n",
							 portid2str(path),
							 port_num);
					return 0;
				}
				port = find_port(&port_buf, node);
				if (port) {
					/* perform the further discovery only
					 * for the newly added ports. */
					continue;
				}
				port = create_port_and_add_to_node(&port_buf,
								   node);
				if (!port) {
					if (IBNG_DEBUG_NI(PTL_DBG_NI_00))
						p3_print("ERROR: remote node's"
							 " port creation failed!\n");
					return -1;
				}
				/* for switches, set the port GUID to the node
				 * GUID. */
				if (node->type == IB_NODE_TYPE_SWITCH)
					port->portguid = node->portguid;

				handle_port(node, port, path, port_num, dist);
			}
		}
	}

	/* store the mappings into the LID-GID mapping table. */
	for (dist = 0; dist <= MAX_HOPS; dist++)
		for (node = nodes_dist[dist]; node;
		     node = node->next_distance)
			for (port_num = 0, port = node->ports_list;
			     port_num < node->numports && port != NULL;
			     port_num++, port = port->next)
				lid_gid_maps[port->lid] = port->portguid;

	return 0;
}

uint64_t *
mad_proxy_lid_gid_mappings_create(char *dev_name, int dev_port,
								  unsigned short num_lid_gid_maps)
{
	uint64_t *lid_gid_maps;
	int mgmt_classes[2] = {IB_SMI_CLASS, IB_SMI_DIRECT_CLASS};

	/* allocate memory for the mapping table. */
	lid_gid_maps = calloc(num_lid_gid_maps, sizeof(uint64_t));
	if (!lid_gid_maps) {
		if (IBNG_DEBUG_NI(PTL_DBG_NI_00))
			p3_print("ERROR: cannot allocate memory for "
				"lid_gid_maps!\n");
		return NULL;
	}
	memset(lid_gid_maps, 0, num_lid_gid_maps * sizeof(uint64_t));

	/* create the nodes hash table. */
	nodes_hashtbl = ibng_htable_create(nodes_hashtbl_hash_f,
					   nodes_hashtbl_cmp_f, HASHTABLE_SIZE);
	if (!nodes_hashtbl) {
		if (IBNG_DEBUG_NI(PTL_DBG_NI_00))
			p3_print("ERROR: cannot allocate memory for "
				"lid_gid_maps!\n");
		free(lid_gid_maps);
		return NULL;
	}

	/* initialize MAD (MAnagement Datagram) RPC layer. */
	madrpc_init(dev_name, dev_port, mgmt_classes, 2);

	/* perform the discovery of the remote nodes. */
	if (discover_remote_nodes(lid_gid_maps) < 0) {
		if (IBNG_DEBUG_NI(PTL_DBG_NI_00))
			p3_print("ERROR: discovery of the remote nodes "
				"failed!\n");
		ibng_htable_destroy(nodes_hashtbl);
		free(lid_gid_maps);
		return NULL;
	}
	/* free the nodes hash table. */
	ibng_htable_destroy(nodes_hashtbl);

	return lid_gid_maps;
}
