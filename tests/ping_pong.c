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

/* hello world server */

#include <p3-config.h>

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <time.h>

#include <portals3.h>
#include P3_NAL
#include <p3api/debug.h>

#include "ptl_opts.h"

#ifndef PTL_EQ_HANDLER_NONE
#define PTL_EQ_HANDLER_NONE NULL
#endif

#ifndef PtlErrorStr
#define PtlErrorStr(a) ""
#endif

/* Special stuff to handle Cray extensions to Portals MD */
#ifndef PTL_MD_EVENT_AUTO_UNLINK_ENABLE
#define PTL_MD_EVENT_AUTO_UNLINK_ENABLE 0
#endif

#ifndef PTL_MD_EVENT_MANUAL_UNLINK_ENABLE
#define PTL_MD_EVENT_MANUAL_UNLINK_ENABLE 0
#endif

#ifndef PTL_IFACE_DUP
#define PTL_IFACE_DUP 999999
#endif

#ifdef PTL_PROGRESS_THREAD
#   include <pthread.h>
typedef struct {
	int count;
	ptl_process_id_t server_id;
	ptl_handle_ni_t ni_h;
	ptl_pt_index_t portal_index;
	ptl_match_bits_t match_bits;
} thread_arg_t;
#endif /* PTL_PROGRESS_THREAD */

/* The UTCP NAL requires that the application defines where the Portals
 * API and library should send any output.
 */
FILE *utcp_api_out;
FILE *utcp_lib_out;

/* global variables */
#define BUFSIZE 256

static int debug = 1;

/* wait for a request to complete */
static int ptl_wait(ptl_handle_eq_t eq_h, int req_type, ptl_event_t *event)
{
    int rc = PTL_OK;

    int done = 0;
    int got_put_start = 0;
    int got_put_end = 0;
    int got_send_start = 0;
    int got_send_end = 0;
    int got_unlink = 0;
    int got_ack = 0;

    while (!done) {
	/* wait for a */
	    if(debug) fprintf(stderr, "waiting for event\n");
	rc = PtlEQWait(eq_h, event);
	if (rc != PTL_OK) {
	    fprintf(stderr, "PtlEQWait failed. rc = %d\n", rc);
	    abort();
	}

	/*fprintf(stderr, "received event\n");*/
	switch (event->type) {
	    case PTL_EVENT_SEND_START:
		if (debug) fprintf(stderr, "\tgot send start\n");
		if (req_type == 0) {
		    got_send_start = 1;
		}
		else {
		    fprintf(stderr, "unexpected send_start event");
		    abort();
		}
		break;
	    case PTL_EVENT_SEND_END:
		if (debug) fprintf(stderr, "\tgot send_end\n");
		if (req_type == 0) {
		    got_send_end = 1;
		}
		else {
		    fprintf(stderr, "unexpected send_end event");
		    abort();
		}
		break;


	    case PTL_EVENT_PUT_START:
		if (debug) fprintf(stderr, "\tgot put_start\n");
		if (req_type == 1) {
		    got_put_start = 1;
		}
		else {
		    fprintf(stderr, "unexpected put_start event");
		    abort();
		}
		break;

	    case PTL_EVENT_PUT_END:
		if (debug) fprintf(stderr, "\tgot put_end\n");
		if (req_type == 1) {
		    got_put_end = 1;
		}
		else {
		    fprintf(stderr, "unexpected put_start event");
		    abort();
		}
		break;

	    case PTL_EVENT_ACK:
		if (debug) fprintf(stderr, "\tgot ack\n");
		got_ack = 1;
		break;

	    case PTL_EVENT_UNLINK:
		if (debug) fprintf(stderr, "\tgot unlink\n");
		got_unlink = 1;
		break;

	    default:
		fprintf(stderr, "\tunexpected event");
		abort();
	}

	/* the case for sends */
	if (got_send_start
		&& got_send_end
		&& got_ack
		&& got_unlink) {
	    done = 1;
	    if (debug) fprintf(stderr, "\tdone with send!\n");
	}

	/* the case for receives */
	if (got_put_start
		&& got_put_end) {
	    done = 1;
	    if (debug) fprintf(stderr, "\tdone with recv!\n");
	}
    }


    return rc;
}



/*  Receive a message. */
static int post_recv(
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
	md.options = PTL_MD_OP_PUT
		| PTL_MD_MANAGE_REMOTE     /* remotely manage buffer: we want
					      to receive every msg at offset
					      0 */
		| PTL_MD_EVENT_AUTO_UNLINK_ENABLE;
	md.user_ptr = NULL;  /* unused */
	md.eq_handle = eq_h;

	/* Create a match entry for this message. */
	rc = PtlMEAttach(ni_h, portal_index, src, match_bits, 0,
			PTL_UNLINK, PTL_INS_AFTER, &me_h);
	if (rc != PTL_OK) {
		fprintf(stderr, "PtlMEAttach: %s\n", PtlErrorStr(rc));
		exit(-1);
	}

	/* attach the memory descriptor to the match entry */
	rc = PtlMDAttach(me_h, md, PTL_UNLINK, &md_h);
	if (rc != PTL_OK) {
		fprintf(stderr, "PtlMDAttach: %s\n", PtlErrorStr(rc));
		exit(-1);
	}

	return 0;
}




/* sends a single message to a server */
static int send_message(
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
	/*md.threshold = PTL_MD_THRESH_INF;*/
	md.threshold = 2;  /* send + ack */
	/*md.max_size = 0;*/
	md.options = PTL_MD_OP_PUT
	    | PTL_MD_TRUNCATE
	    | PTL_MD_EVENT_AUTO_UNLINK_ENABLE;
	md.user_ptr = NULL;  /* unused */

	md.eq_handle = eq_h;

	/* bind the memory descriptor */
	rc = PtlMDBind(ni_h, md, PTL_UNLINK, &md_h);
	if (rc != PTL_OK) {
		fprintf(stderr, "PtlMDBind() failed: %s (%d)\n",
				PtlErrorStr(rc), rc);
		exit(-1);
	}

	/* "put" the message on the server's memory descriptor */
	rc = PtlPut(md_h, PTL_ACK_REQ, dest, portal_index, 0, match_bits, 0, 0);
	if (rc != PTL_OK) {
		fprintf(stderr, "PtlPut() failed: %s (%d)\n",
				PtlErrorStr(rc), rc);
		exit(-1);
	}

	/* An explicit unlink does not generate an event */
	/*rc = PtlMDUnlink(md_h);*/

	return rc;
}





/*  Receive one message from the client, return the same
 *  message, then exit.  We're trying to model the behavior
 *  of LWFS RPC. */
static int ping_pong_server(
	int count,
	ptl_handle_ni_t ni_h,
	ptl_pt_index_t portal_index,
	ptl_match_bits_t match_bits)
{
	int rc;
	char sendbuf[BUFSIZE];
	char recvbuf[BUFSIZE];
	int i;
	ptl_handle_eq_t eq_h;
	ptl_process_id_t client;
	ptl_event_t event;

	/* create an event queue for the incoming buffer */
	rc = PtlEQAlloc(ni_h, 5, PTL_EQ_HANDLER_NONE, &eq_h);
	if (rc != PTL_OK) {
		fprintf(stderr, "PtlEQAlloc() failed: %s (%d)\n",
			PtlErrorStr(rc), rc);
		exit(-1);
	}

	/* anybody can send a message to the server */
	client.nid = PTL_NID_ANY;
	client.pid = PTL_PID_ANY;

	for(i = 0; i < BUFSIZE; i++)
		sendbuf[i] = '0' + (i % 10);
	sendbuf[BUFSIZE - 1] = 0;
	bzero(recvbuf, BUFSIZE);
	post_recv(client, recvbuf, BUFSIZE, ni_h,
		  portal_index, match_bits, eq_h);

	for (i = 0; i < count; i++) {
		/* -------------- RECEIVE A MESSAGE (ping) ---------- */

		/* receive a message from the client */
		fprintf(stderr, "waiting for msg %d (match_bits=%d) "
			"from client\n", i, (int)(match_bits));

		ptl_wait(eq_h, 1, &event);

		fprintf(stderr, "recv'd msg[%d] = \"%s\" from client "
			"(nid=%llu, pid=%llu)\n", i, recvbuf,
			(unsigned long long)event.initiator.nid,
			(unsigned long long)event.initiator.pid);

		fprintf(stderr, "sending response[%d] (match_bits=%d)"
			" to (nid=%llu, pid=%llu)\n", i, (int)(match_bits+100),
			(unsigned long long)event.initiator.nid,
			(unsigned long long)event.initiator.pid);


		/* -------------- SEND RESULT (pong) ---------- */

		memcpy(sendbuf, recvbuf, BUFSIZE);
		/* send the same message back to client */
		send_message(event.initiator, sendbuf, BUFSIZE, ni_h,
			     portal_index+1, match_bits+100, eq_h);
		ptl_wait(eq_h, 0, &event);

		fprintf(stderr, "response[%d] sent to client\n", i);
	}

	/* free the event queue */
	rc = PtlEQFree(eq_h);
	if (rc != PTL_OK) {
		fprintf(stderr, "PtlEQFree() failed: %s (%d)\n",
			PtlErrorStr(rc), rc);
		abort();
	}

	fprintf(stderr, "exiting server func\n");
	return 0;
}

/* sends a messages to a server */
static int ping_pong_client(
        int count,
        ptl_process_id_t server,
        ptl_handle_ni_t ni_h,
        ptl_pt_index_t portal_index,
        ptl_match_bits_t match_bits)
{
	int rc;
	int i;
	char sendbuf[BUFSIZE];
	char recvbuf[BUFSIZE];
	ptl_handle_eq_t ping_eq_h;
	ptl_handle_eq_t pong_eq_h;
	ptl_event_t event;

	/* initialize the buffer */
	for(i = 0; i < BUFSIZE; i++)
		sendbuf[i] = '0' + (i % 10);
	sendbuf[BUFSIZE - 1] = 0;
	bzero(recvbuf, BUFSIZE);

	/* create an event queue for the outgoing buffer */
	rc = PtlEQAlloc(ni_h, 5, PTL_EQ_HANDLER_NONE, &pong_eq_h);
	if (rc != PTL_OK) {
            fprintf(stderr, "PtlEQAlloc() failed: %s (%d)\n",
                    PtlErrorStr(rc), rc);
            exit(-1);
	}

	if (debug) fprintf(stderr, "Posting recv for pong\n");

	/* post a  receive for the result (pong) from the server */
	post_recv(server, recvbuf, BUFSIZE, ni_h,
		  portal_index+1, match_bits+100, pong_eq_h);

	/* create an event queue for the outgoing buffer */
	rc = PtlEQAlloc(ni_h, 5, PTL_EQ_HANDLER_NONE, &ping_eq_h);
	if (rc != PTL_OK) {
		fprintf(stderr, "PtlEQAlloc() failed: %s (%d)\n",
			PtlErrorStr(rc), rc);
		exit(-1);
	}

	/* async send */
	for (i=0; i<count; i++) {

		fprintf(stderr, "%d\n",i);

		/* ----- SEND MESSAGE (ping) -------- */

		if (debug) fprintf(stderr, "Sending ping\n");

		sprintf(sendbuf, "hello world %d", i);
		sendbuf[strlen(sendbuf)] = ' ';
		/* send initial message to server */
		send_message(server, sendbuf, BUFSIZE, ni_h,
			     portal_index, match_bits, ping_eq_h);

		if (debug) fprintf(stderr, "Waiting for ping to complete\n");

		rc = ptl_wait(ping_eq_h, 0, &event);
		fprintf(stderr, "sent msg[%d] (match_bits=%d) to server\n",
			i, (int)(match_bits));

		fprintf(stderr, "waiting for response[%d] (match_bits=%d) "
			"from (nid=%llu, pid=%llu)\n", i, (int)(match_bits+100),
			(unsigned long long)server.nid,
			(unsigned long long)server.pid);

		/* ----- RECV MESSAGE (pong) -------- */

		/* wait for pong from client */
		rc = ptl_wait(pong_eq_h, 1, &event);
		fprintf(stderr, "recv'd pong[%d] = \"%s\"\n", i, recvbuf);
    }

	/* free the event queue */
	rc = PtlEQFree(ping_eq_h);
	if (rc != PTL_OK) {
		fprintf(stderr, "PtlEQFree() failed: %s (%d)\n",
			PtlErrorStr(rc), rc);
		abort();
	}

	/* free the event queue */
	rc = PtlEQFree(pong_eq_h);
	if (rc != PTL_OK) {
		fprintf(stderr, "PtlEQFree() failed: %s (%d)\n",
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
	time_t now;

	/* get the current time */
	now = time(NULL);

	fprintf(fp, "%s -----------------------------------\n", prefix);
	fprintf(fp, "%s \tPing_Pong Portals Test\n", prefix);
	fprintf(fp, "%s \t%s", prefix, asctime(localtime(&now)));
	fprintf(fp, "%s ------------  ARGUMENTS -----------\n", prefix);
	if (args->server_flag) {
		fprintf(fp, "%s Running as a server\n", prefix);
	}
	else {
		fprintf(fp, "%s Running as a client\n", prefix);
	}

	fprintf(fp, "%s \t--count = %d\n", prefix, args->count_arg);

	fprintf(fp, "%s \t--server-nid = %llu\n", prefix, (unsigned long long)args->server_nid_arg);
	fprintf(fp, "%s \t--server-pid = %llu\n", prefix, (unsigned long long)args->server_pid_arg);

	fprintf(fp, "%s -----------------------------------\n", prefix);

	return 0;
}

#ifdef PTL_PROGRESS_THREAD
static void *
client_thread(void *arg)
{
	thread_arg_t *ta = (thread_arg_t *)arg;

	fprintf(stderr, "Client thread alive ...\n");
	ping_pong_client(ta->count, ta->server_id, ta->ni_h,
					 ta->portal_index, ta->match_bits);
	fprintf(stderr, "Client thread going away ...\n");

	return NULL;
}

static void *
server_thread(void *arg)
{
	thread_arg_t *ta = (thread_arg_t *)arg;

	fprintf(stderr, "Server thread alive ...\n");
	ping_pong_server(ta->count, ta->ni_h, ta->portal_index, ta->match_bits);
	fprintf(stderr, "Server thread going away ...\n");

	return NULL;
}
#endif /* PTL_PROGRESS_THREAD */

int main(int argc, char **argv)
{
    int num_if;
    int count = 1;
    int rc;
    struct gengetopt_args_info args;
    int shutdown = 1;
    ptl_interface_t iface;

#ifdef PTL_PROGRESS_THREAD
#   define N_THREADS 3
	int i;
	pthread_t thread_id[N_THREADS];
	thread_arg_t thread_arg[N_THREADS];
#endif /* PTL_PROGRESS_THREAD */

    /*
    iface = CRAY_QK_NAL;
    iface = CRAY_KERN_NAL;
    iface = CRAY_USER_NAL;
     */
    iface = PTL_IFACE_DEFAULT;

    /* fixed for all runs */
    ptl_pt_index_t portal_index = 4;
    ptl_match_bits_t match_bits = 1;

    ptl_process_id_t my_id;
    ptl_process_id_t server_id;
    ptl_handle_ni_t ni_h;
    ptl_pid_t pid = PTL_PID_ANY;

    /* parse command line options */
    if (cmdline_parser(argc, argv, &args) != 0) {
        exit(1);
    }

    /* initialize the server ID */
    server_id.nid = (ptl_nid_t)args.server_nid_arg;
    server_id.pid = (ptl_pid_t)args.server_pid_arg;

    /* Initialize the library */
    if (PtlInit(&num_if) != PTL_OK) {
        fprintf(stderr, "PtlInit() failed\n");
        exit(1);
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
    switch (rc) {
    case PTL_OK:
        shutdown = 1;
        break;
    case PTL_IFACE_DUP:
        fprintf(stderr, "PtlNIInit() IFACE already initialized: rc=%d\n",rc);
        shutdown = 0;
        break;
    default:
        fprintf(stderr, "PtlNIInit() failed: rc=%d\n",rc);
        exit(1);
    }

    /* allow anyone to talk to us */
    rc = PtlACEntry(ni_h, 0, 
		    (ptl_process_id_t){PTL_NID_ANY, PTL_PID_ANY},
		    PTL_UID_ANY, PTL_JID_ANY, PTL_PT_INDEX_ANY);
    if (rc != PTL_OK) {
      fprintf(stderr, "PtlACEntry() failed: %s\n",
	      PtlErrorStr(rc));
      exit(42);
    }

    /* Get and print the ID of this process */
    if (PtlGetId(ni_h, &my_id) != PTL_OK) {
        printf("PtlGetId() failed.\n");
        abort();
    }

    if (args.server_flag) {
        server_id.nid = my_id.nid;
        server_id.pid = my_id.pid;
        args.server_nid_arg = my_id.nid;
        args.server_pid_arg = my_id.pid;
    }
    else {
        if (server_id.nid == 0) {
            server_id.nid = my_id.nid;
            args.server_nid_arg = my_id.nid;
        }
    }

    count = args.count_arg;

    count = args.count_arg;


    printf("%s: nid = %llu, pid = %llu\n",
            argv[0],
            (unsigned long long) my_id.nid,
            (unsigned long long) my_id.pid);


    print_args(stdout, &args, "");


    /***************** EVERYTHING ABOVE USED FOR BOTH SENDER AND RECEIVER *******/

    if (args.server_flag) {
        fprintf(stderr, "starting server (BUFSIZE=%d)...\n",BUFSIZE);
#ifdef PTL_PROGRESS_THREAD
		for(i = 0; i < N_THREADS; i++) {
			thread_arg[i].count = count;
			thread_arg[i].ni_h = ni_h;
			thread_arg[i].portal_index = portal_index;
			thread_arg[i].match_bits = match_bits << i;
			if(pthread_create(&thread_id[i], NULL,
							  server_thread, &thread_arg[i]))
				abort();
		}
#else
        ping_pong_server(count, ni_h, portal_index, match_bits);
#endif /* PTL_PROGRESS_THREAD */
    }
    else {
        fprintf(stderr, "starting client (BUFSIZE=%d)...\n",BUFSIZE);
        fprintf(stderr, "connecting to nid=%lx, pid=%lx.\n",
                (unsigned long)server_id.nid, (unsigned long)server_id.pid);
#ifdef PTL_PROGRESS_THREAD
		for(i = 0; i < N_THREADS; i++) {
			thread_arg[i].count = count;
			thread_arg[i].server_id = server_id;
			thread_arg[i].ni_h = ni_h;
			thread_arg[i].portal_index = portal_index;
			thread_arg[i].match_bits = match_bits << i;
			if(pthread_create(&thread_id[i], NULL,
							  client_thread, &thread_arg[i]))
				abort();
		}
#else
        ping_pong_client(count, server_id, ni_h, portal_index, match_bits);
#endif /* PTL_PROGRESS_THREAD */
    }

#ifdef PTL_PROGRESS_THREAD
	for(i = 0; i < N_THREADS; i++)
		pthread_join(thread_id[i], NULL);
#endif /* PTL_PROGRESS_THREAD */

    /* cleanup */
    if (shutdown) {
        fprintf(stderr, "calling PtlNIFini\n");
        PtlNIFini(ni_h);
        fprintf(stderr, "calling PtlFini\n");
        PtlFini();
    }

    return 0;
}
