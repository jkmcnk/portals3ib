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

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <portals3.h>
#include P3_NAL
#include <p3api/debug.h>

#include "ptl_opts.h"

#ifndef PTL_IFACE_DUP
#define PTL_IFACE_DUP 999999
#endif

/* global variables */
#define BUFSIZE 256

static int debug = 1;

/* wait for a request to complete */
static int ptl_wait(ptl_handle_eq_t eq_h, int req_type, ptl_event_t *event)
{
	int rc = PTL_OK;
	
	int done = 0;
	int got_get_start = 0;
	int got_get_end = 0;
	int got_reply_start = 0;
	int got_reply_end = 0;
	int got_unlink = 0;
	
	while (!done) {
		/* wait for a */
		if(debug) { 
			fprintf(stderr, "waiting for event\n");
		}
		
		rc = PtlEQWait(eq_h, event);
		if (rc != PTL_OK) {
			fprintf(stderr, "PtlEQWait failed. rc = %d\n", rc);
			abort();
		}
	
		switch (event->type) {
		    case PTL_EVENT_REPLY_START:
			if (debug) {
				fprintf(stderr, "\tgot reply_start\n");
			}
			
			if (req_type == 0) {
			    got_reply_start = 1;
			}
			else {
			    fprintf(stderr, "unexpected reply_start event");
			    abort();
			}
			break;
		    case PTL_EVENT_REPLY_END:
			if (debug) {
				fprintf(stderr, "\tgot reply_end\n");
			}
			
			if (req_type == 0) {
			    got_reply_end = 1;
			}
			else {
			    fprintf(stderr, "unexpected reply_end event");
			    abort();
			}
			break;
		
		
		    case PTL_EVENT_GET_START:
			if (debug) {
				fprintf(stderr, "\tgot get_start\n");
			}
			
			if (req_type == 1) {
			    got_get_start = 1;
			}
			else {
			    fprintf(stderr, "unexpected get_start event");
			    abort();
			}
			break;
		
		    case PTL_EVENT_GET_END:
			if (debug) fprintf(stderr, "\tgot get_end\n");
			if (req_type == 1) {
			    got_get_end = 1;
			}
			else {
			    fprintf(stderr, "unexpected get_end event");
			    abort();
			}
			break;
				
		    case PTL_EVENT_UNLINK:
			if (debug) {
				fprintf(stderr, "\tgot unlink\n");
			}
			
			got_unlink = 1;
			break;
		
		    default:
			fprintf(stderr, "\tunexpected event: %d\n", 
				event->type);
			abort();
		}
	
		/* the case for initiators */
		if (got_reply_start && got_reply_end && got_unlink) {
			done = 1;
			if (debug) {
				fprintf(stderr, "\tdone with request "
					"sending!\n");
			}
		}
	
		/* the case for targets */
		if (got_get_start && got_get_end) {
			done = 1;
			if (debug) {
				fprintf(stderr, "\tdone with request "
					"reception!\n");
			}
		}
	}
	
	return rc;
}


/*  Receive a message. */
static int register_md(
	ptl_process_id_t src,
	char *buf,
	int bufsize,
	ptl_handle_ni_t ni_h,
	ptl_pt_index_t portal_index,
	ptl_match_bits_t match_bits,
	ptl_handle_eq_t eq_h)
{
	int rc;

	ptl_md_t md;
	ptl_handle_me_t me_h;
	ptl_handle_md_t md_h;

	/* initialize the md for the incoming buffer */
	memset(&md, 0, sizeof(ptl_md_t));
	md.start = buf;
	md.length = bufsize;
	md.threshold = PTL_MD_THRESH_INF;  /* expect infinitely many ops (i.e.
					      receives) */
	md.options = PTL_MD_OP_GET
		| PTL_MD_MANAGE_REMOTE;     /* remotely manage buffer: we want
					      to receive every msg at offset
					      0 */
	md.user_ptr = NULL;  /* unused */
	md.eq_handle = eq_h;

	/* Create a match entry for this message. */
	rc = PtlMEAttach(ni_h, portal_index, src, match_bits, 0,
		PTL_UNLINK, PTL_INS_AFTER, &me_h);
	if (rc != PTL_OK) {
		fprintf(stderr, "ERROR PtlMEAttach: %s\n", PtlErrorStr(rc));
		exit(-1);
	}

	/* attach the memory descriptor to the match entry */
	rc = PtlMDAttach(me_h, md, PTL_UNLINK, &md_h);
	if (rc != PTL_OK) {
		fprintf(stderr, "ERROR PtlMDAttach: %s\n", PtlErrorStr(rc));
		exit(-1);
	}

	return 0;
}




/* sends a single message to a server */
static int send_get_request(
	ptl_process_id_t dest,
	char *buf,
	int bufsize,
	ptl_handle_ni_t ni_h,
	ptl_pt_index_t portal_index,
	ptl_match_bits_t match_bits,
	ptl_handle_eq_t eq_h)
{
	int rc;

	ptl_md_t md;
	ptl_handle_md_t md_h;

	/* initialize the md for the outgoing buffer */
	memset(&md, 0, sizeof(ptl_md_t));
	md.start = buf;
	md.length = bufsize;
	md.threshold = 1;  /* reply */
	md.options = PTL_MD_OP_GET
	    | PTL_MD_TRUNCATE;
	md.user_ptr = NULL;  /* unused */

	md.eq_handle = eq_h;

	/* bind the memory descriptor */
	rc = PtlMDBind(ni_h, md, PTL_UNLINK, &md_h);
	if (rc != PTL_OK) {
		fprintf(stderr, "ERROR PtlMDBind() failed: %s (%d)\n",
			PtlErrorStr(rc), rc);
		exit(-1);
	}

	/* send the "get" message to the server's memory descriptor */
	rc = PtlGet(md_h, dest, portal_index, 0, match_bits, 0);
	if (rc != PTL_OK) {
		fprintf(stderr, "ERROR PtlGet() failed: %s (%d)\n",
				PtlErrorStr(rc), rc);
		exit(-1);
	}

	return rc;
}

/*  Receives get requests from the client. */
static int ping_pong_server(
	int count,
	ptl_handle_ni_t ni_h,
	ptl_pt_index_t portal_index,
	ptl_match_bits_t match_bits)
{
	int rc;
	char buf[BUFSIZE];
	int i;
	ptl_handle_eq_t eq_h;
	ptl_process_id_t client;
	ptl_event_t event;

	/* create an event queue for the incoming buffer */
	rc = PtlEQAlloc(ni_h, 5, PTL_EQ_HANDLER_NONE, &eq_h);
	if (rc != PTL_OK) {
		fprintf(stderr, "ERROR PtlEQAlloc() failed: %s (%d)\n",
			PtlErrorStr(rc), rc);
		exit(-1);
	}

	/* anybody can send a message to the server */
	client.nid = PTL_NID_ANY;
	client.pid = PTL_PID_ANY;

	memset(buf, 0, BUFSIZE);
	register_md(client, buf, BUFSIZE, ni_h, portal_index, match_bits, eq_h);
	
	/* assign text to buffer. */
	sprintf(buf, "Hello World!!!");

	for (i = 0; i < count; i++) {

		/* receive a "get" request from the client */
		fprintf(stderr, "waiting for msg %d (match_bits=%d) "
			"from client\n", i, (int)(match_bits));

		ptl_wait(eq_h, 1, &event);

		fprintf(stderr, "response[%d] sent to client\n", i);
	}

	/* free the event queue */
	rc = PtlEQFree(eq_h);
	if (rc != PTL_OK) {
		fprintf(stderr, "ERROR PtlEQFree() failed: %s (%d)\n",
			PtlErrorStr(rc), rc);
		abort();
	}

	fprintf(stderr, "exiting server func\n");
	return 0;
}

/* sends a "get" requests to a server */
static int ping_pong_client(
        int count,
        ptl_process_id_t server,
        ptl_handle_ni_t ni_h,
        ptl_pt_index_t portal_index,
        ptl_match_bits_t match_bits)
{
	int rc;
	int i;
	char recvbuf[BUFSIZE];
	ptl_handle_eq_t eq_h;
	ptl_event_t event;

	/* initialize the buffer */
	memset(recvbuf, 0, sizeof(recvbuf));

	/* create an event queue */
	rc = PtlEQAlloc(ni_h, 5, PTL_EQ_HANDLER_NONE, &eq_h);
	if (rc != PTL_OK) {
		fprintf(stderr, "PtlEQAlloc() failed: %s (%d)\n",
			PtlErrorStr(rc), rc);
		exit(-1);
	}

	/* async send */
	for (i=0; i<count; i++) {
		
		/* clear the buffer */
		memset(recvbuf, 0, sizeof(recvbuf));


		fprintf(stderr, "%d\n",i);

		/* send "get" request. */

		if (debug) {
			fprintf(stderr, "Sending GET request.\n");
		}

		send_get_request(server, recvbuf, BUFSIZE, ni_h, portal_index, 
			match_bits, eq_h);
		

		if (debug) {
			fprintf(stderr, "Waiting for the request to "
				"complete\n");
		}

		/* waiting for the response from the server. */
		rc = ptl_wait(eq_h, 0, &event);
		fprintf(stderr, "recv'd response[%d] = \"%s\"\n", i, recvbuf);
	}

	/* free the event queue */
	rc = PtlEQFree(eq_h);
	if (rc != PTL_OK) {
		fprintf(stderr, "ERROR PtlEQFree() failed: %s (%d)\n",
			PtlErrorStr(rc), rc);
		abort();
	}

	fprintf(stderr, "exiting client func\n");
	return 0;
}

/* ----------------- COMMAND-LINE OPTIONS --------------- */

static int print_args(FILE *fp,
	const struct gengetopt_args_info *args,
	const char *prefix)
{
	fprintf(fp, "%s -----------------------------------\n", prefix);
	fprintf(fp, "%s \tPtlGet Test\n", prefix);
	fprintf(fp, "%s ------------  ARGUMENTS -----------\n", prefix);
	if (args->server_flag) {
		fprintf(fp, "%s Running as a server\n", prefix);
	}
	else {
		fprintf(fp, "%s Running as a client\n", prefix);
	}

	fprintf(fp, "%s \t--count = %d\n", prefix, args->count_arg);

	fprintf(fp, "%s \t--server-nid = %llu\n", prefix, 
		(unsigned long long)args->server_nid_arg);
	fprintf(fp, "%s \t--server-pid = %llu\n", prefix, 
		(unsigned long long)args->server_pid_arg);

	fprintf(fp, "%s -----------------------------------\n", prefix);

	return 0;
}


int
main(int argc, char *argv[])
{
	int num_if;
	int count = 1;
	int rc;
	struct gengetopt_args_info args;
	int shutdown = 1;
	ptl_interface_t iface;
	
	iface = PTL_IFACE_DEFAULT;
	
	/* fixed for all runs */
	ptl_pt_index_t portal_index=4;
	ptl_match_bits_t match_bits=5;
	
	ptl_process_id_t my_id;
	ptl_process_id_t server_id;
	ptl_handle_ni_t ni_h;
	ptl_pid_t pid = PTL_PID_ANY;
	
	/* parse command line options */
	if (cmdline_parser(argc, argv, &args) != 0) {
		printf("Usage: get_test < --server | "
			"--server-nid=NID_NUM --server-pid=PID_NUM> "
			"[--count=NUM_ITER]");
		return -1;
	}
	
	/* initialize the server ID */
	server_id.nid = (ptl_nid_t)args.server_nid_arg;
	server_id.pid = (ptl_pid_t)args.server_pid_arg;
	
	/* Initialize the library */
	if (PtlInit(&num_if) != PTL_OK) {
		fprintf(stderr, "ERROR: PtlInit() failed\n");
		return -1;
	}
	
	/* turn on debugging */
#ifdef DEBUG_PTL_INTERNALS
	PtlNIDebug(PTL_INVALID_HANDLE,
	       PTL_DBG_NI_ALL |
	       PTL_DBG_API |
	       PTL_DBG_PARSE |
	       PTL_DBG_MOVE |
	       PTL_DBG_DROP |
	       PTL_DBG_REQUEST |
	       PTL_DBG_DELIVERY |
	       PTL_DBG_MD |
	       PTL_DBG_ME |
	       PTL_DBG_UNLINK |
	       PTL_DBG_EQ |
	       PTL_DBG_EVENT |
	       PTL_DBG_MEMORY |
	       PTL_DBG_SETUP |
	       PTL_DBG_SHUTDOWN);
#endif /* DEBUG_PTL_INTERNALS */
	
	/* Initialize the interface */
	pid = (args.server_flag)? (ptl_pid_t)args.server_pid_arg : PTL_PID_ANY;
	rc = PtlNIInit(iface, pid, NULL, NULL, &ni_h);
	if (rc == PTL_OK) {
		shutdown = 1;
	}
	else if (rc == PTL_IFACE_DUP) {
		fprintf(stderr, "ERROR: PtlNIInit() IFACE already "
			"initialized: rc=%d\n",rc);
		shutdown = 0;
	}
	else {
		fprintf(stderr, "ERROR: PtlNIInit() failed: rc=%d\n", rc);
		return -1;		
	}

	/* allow anyone to talk to us */
	rc = PtlACEntry(ni_h, 0, (ptl_process_id_t){PTL_NID_ANY, PTL_PID_ANY},
		PTL_UID_ANY, PTL_JID_ANY, PTL_PT_INDEX_ANY);
	if (rc != PTL_OK) {
		fprintf(stderr, "ERROR: PtlACEntry() failed: %s\n", 
			PtlErrorStr(rc));
		return -1;
	}
	
	/* Get and print the ID of this process */
	if (PtlGetId(ni_h, &my_id) != PTL_OK) {
		printf("ERROR: PtlGetId() failed.\n");
		return -1;
	}
	
	if (args.server_flag) {
		server_id.nid = my_id.nid;
		server_id.pid = my_id.pid;
		args.server_nid_arg = my_id.nid;
		args.server_pid_arg = my_id.pid;
	}
	else if (server_id.nid == 0) {
		server_id.nid = my_id.nid;
		args.server_nid_arg = my_id.nid;
	}

	count = args.count_arg;
	
	
	printf("%s: nid = %llu, pid = %llu\n", argv[0],
		(unsigned long long) my_id.nid,
		(unsigned long long) my_id.pid);
	
	
	print_args(stdout, &args, "");
	
	
/***************** EVERYTHING ABOVE USED FOR BOTH SENDER AND RECEIVER *******/
	
	if (args.server_flag) {
		fprintf(stderr, "starting server (BUFSIZE=%d)...\n",BUFSIZE);
		ping_pong_server(count, ni_h, portal_index, match_bits);
	}
	else {
		fprintf(stderr, "starting client (BUFSIZE=%d)...\n",BUFSIZE);
		fprintf(stderr, "connecting to nid=%lx, pid=%lx.\n",
			(unsigned long)server_id.nid, 
			(unsigned long)server_id.pid);
	
		ping_pong_client(count, server_id, ni_h, portal_index, 
			match_bits);
	}
	
	/* cleanup */
	if (shutdown) {
		fprintf(stderr, "calling PtlNIFini\n");
		PtlNIFini(ni_h);
		fprintf(stderr, "calling PtlFini\n");
		PtlFini();
	}
	
	return 0;
}
