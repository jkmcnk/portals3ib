/*
 * This Cplant(TM) source code is part of the Portals3 Reference
 * Implementation.
 *
 * This Cplant(TM) source code is the property of Sandia National
 * Laboratories.
 *
 * This Cplant(TM) source code is copyrighted by Sandia National
 * Laboratories.
 *
 * The redistribution of this Cplant(TM) source code is subject to the
 * terms of version 2 of the GNU General Public License.
 * (See COPYING, or http://www.gnu.org/licenses/lgpl.html.)
 *
 * Cplant(TM) Copyright 1998-2006 Sandia Corporation. 
 *
 * Under the terms of Contract DE-AC04-94AL85000, there is a non-exclusive
 * license for use of this work by or on behalf of the US Government.
 * Export of this program may require a license from the United States
 * Government.
 */
/* Portals3 is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License,
 * as published by the Free Software Foundation.
 *
 * Portals3 is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Portals3; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */ 
/* Copyright 2008-2011 NEC Deutschland GmbH, NEC HPC Europe */

/*  This Portals 3.0 program tests the put latency using a ping-pong test.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <float.h>
#include <sys/time.h>

#include <portals3.h>
#include P3_NAL
#include <p3rt/p3rt.h>
#include <p3api/debug.h>

#define INFLIGHT_BITS 5
#define MAX_INFLIGHT (1 << INFLIGHT_BITS)

#include "handshake.h"

static 
const char usage[] = " \n\
put_pp [-ahv] [-d <dbg>] [-m <min>] [-M <max>] \n\
       [-i [x]<inc>] [-n <cnt>] [-o <cnt>] \n\
 \n\
	Performs a ping-pong latency test using PtlPut calls between pairs \n\
	of processes. \n\
 \n\
	The elapsed time clock for each message sent starts when PtlPut \n\
	is called from the rank n/2 process, and ends when that process \n\
	receives the PTL_EVENT_PUT_END event for the reply message sent \n\
	by the rank 1+n/2 process, for 0 <= n <= N/2, with N even. \n\
 \n\
	-a	Adds an access control entry to permit any user to access\n\
		  the MDs of this process\n\
	-d dbg	Sets the debug mask to <dbg>, which will cause the \n\
		  Portals library and the NAL to emit various debugging \n\
		  output, assuming both were configured with debugging \n\
		  enabled.  See p3api/debug.h for appropriate values.  \n\
		  See also NAL documentation or implementation for \n\
		  appropriate NAL-specific values. \n\
	-h	Prints this message. \n\
	-i inc	Sets the message size increment.  If prepended with  \n\
		  'x', e.g. '-i x2', the message size increase is \n\
		  multiplicative rather than the default additive. \n\
	-m min	Sets the size of the smallest message sent, in bytes. \n\
	-M max	Sets the upper bound on the size of messages sent. \n\
		  Inc, min, and max may be suffixed with one of the \n\
		  following multipliers: \n\
		  k	*1000 \n\
		  M	*1000*1000 \n\
		  G	*1000*1000*1000 \n\
		  Ki	*1024 \n\
		  Mi	*1024*1024 \n\
		  Gi	*1024*1024*1024 \n\
	-n cnt	Sets the number of messages sent for each message size. \n\
	-o cnt	Sets the number of outstanding puts allowed.  Increasing \n\
		  this value from 1 allows more pipelining of messages. \n\
	-v	Causes put_bw to be verbose about the progress of \n\
		  each trial. \n\
";

typedef struct msg {
	char *buf;

	ptl_handle_me_t me_h;
	ptl_handle_md_t md_h;
	ptl_handle_eq_t eq_h;

	ptl_md_t md;
	ptl_md_t md_save;

	struct timeval start;
	struct timeval end;
	unsigned id;
} msg_t;

static inline
void put(ptl_process_id_t dst_id, ptl_pt_index_t ptl, ptl_ac_index_t ace,
	 msg_t *msg, ptl_size_t len,
	 int mbits, int mbuf, int trial, int rank, int verbose)
{
	int rc;
	ptl_match_bits_t mb =
		(ptl_match_bits_t )mbits << INFLIGHT_BITS | mbuf;

	/* Restore local offset in bound memory descriptor; keep track of
	 * which trial the message buffer is used for.
	 */
	msg->id = trial;
	if (verbose) 
		printf("%d:   PtlMDUpdate: len %d trial %d, "
		       "msg %d\n", rank, (int)len, trial, mbuf);

	do {
		rc = PtlMDUpdate(msg->md_h, NULL, &msg->md_save, msg->eq_h);
	} while (rc == PTL_MD_NO_UPDATE);

	if (rc != PTL_OK) {
		fprintf(stderr, "%d:PtlMDUpdate: msg %d: %s\n",
			rank, mbuf, PtlErrorStr(rc));
		exit(EXIT_FAILURE);
	}

	gettimeofday(&msg->start, 0);

	rc = PtlPutRegion(msg->md_h, 0, len, PTL_NO_ACK_REQ,
			  dst_id, ptl, ace, mb, 0, 0);
	if (rc != PTL_OK) {
		fprintf(stderr, "%d:PtlPut: %s\n",
			rank, PtlErrorStr(rc));
		exit(EXIT_FAILURE);
	}
	if (verbose) 
		printf("%d:   PtlPut: len %d trial %d, "
		       "msg %d\n", rank, (int)len, trial, mbuf);
}

static inline
void event(msg_t *msg, ptl_event_t *ev,
	   ptl_event_kind_t evt, int rank, ptl_handle_ni_t ni_h)
{
	int rc;

	if ((rc = PtlEQWait(msg->eq_h, ev)) != PTL_OK) {
		fprintf(stderr, "%d:PtlEQWait(): %s\n",
			rank, PtlErrorStr(rc));
		exit(EXIT_FAILURE);
	}
	if (ev->ni_fail_type != PTL_NI_OK) {
		fprintf(stderr, "%d:NI sent %s in event.\n",
			rank, PtlNIFailStr(ni_h, ev->ni_fail_type));
		exit(EXIT_FAILURE);
	}
	if (ev->type != evt) {
		fprintf(stderr,	"%d:expected %s, got %s\n", rank, 
			PtlEventKindStr(evt), PtlEventKindStr(ev->type));
		exit(EXIT_FAILURE);
	}
}

/* returns the difference *tv1 - *tv0 in microseconds.
 */
static inline
double tv_diff(struct timeval *tv0, struct timeval *tv1)
{
	return (double)(tv1->tv_sec - tv0->tv_sec) * 1e6
		+ (tv1->tv_usec - tv0->tv_usec);
}

static
ptl_size_t suffix(const char *str)
{
	ptl_size_t s = 1;

	switch (*str) {
	case 'k':
		s *= 1000;
		break;
	case 'K':
		if (*(str+1) == 'i')
			s *= 1024;
		break;
	case 'M':
		if (*(str+1) == 'i')
			s *= 1024*1024;
		else
			s *= 1000*1000;
		break;
	case 'G':
		if (*(str+1) == 'i')
			s *= 1024*1024*1024;
		else
			s *= 1000*1000*1000;
		break;
	}

	return s;
}

int main(int argc, char *argv[])
{
	unsigned rank, size, src;
	int num_if, rc;

	ptl_pt_index_t ptl = 4;
	ptl_pt_index_t sync_ptl = 5;
	ptl_ac_index_t ace_any = 0;
	ptl_process_id_t src_id, dst_id;
	ptl_handle_ni_t ni_h;
	ptl_event_t ev;
	ptl_size_t len, inc = 16, start_len = 0, end_len = 64;
	unsigned sender, trials = 1000;
	unsigned inflight = 1, add_inc = 1;
	unsigned i, m, dbg = 0, done = 0, verbose = 0;

	msg_t *msg, *cmsg;

	struct timeval pgm_start;
	double et, ave_et, total_et;
	double min_et, max_et;

	while (1) {
		char *next_char;
		int c = getopt(argc, argv, "ad:hi:m:M:n:o:v");
		if (c == -1) break;

		switch (c) {
		case 'a':
			ace_any = 1;
			break;
		case 'd':
			dbg = strtoul(optarg, NULL, 0);
			break;
		case 'h':
			printf("%s", usage);
			exit(EXIT_SUCCESS);
		case 'i':
			if (*optarg == 'x') {
				optarg++;
				add_inc = 0;
			}
			inc = strtoul(optarg, &next_char, 0);
			inc *= suffix(next_char);
			break;
		case 'm':
			start_len = strtoul(optarg, &next_char, 0);
			start_len *= suffix(next_char);
			break;
		case 'M':
			end_len = strtoul(optarg, &next_char, 0);
			end_len *= suffix(next_char);
			break;
		case 'n':
			trials = strtoul(optarg, NULL, 0);
			break;
		case 'o':
			inflight = strtoul(optarg, NULL, 0);
			break;
		case 'v':
			verbose = 1;
			break;
		}
	}
	gettimeofday(&pgm_start, 0);

	/* Initialize library 
	 */
	if ((rc = PtlInit(&num_if)) != PTL_OK) {
		fprintf(stderr, "PtlInit(): %s\n", PtlErrorStr(rc));
		exit(1);
	}
	/* Turn on debugging now so we can see NAL startup debug stuff.
	 */
	if (dbg)
		PtlNIDebug(PTL_INVALID_HANDLE, dbg);

	/* Cause the runtime to initialize from environment variables.
	 * We should only do this if we don't have a job-launching service.
	 */
	if ((rc = PtlSetRank(PTL_INVALID_HANDLE, -1, -1)) != PTL_OK) {
		fprintf(stderr, "PtlSetRank(): %s\n", PtlErrorStr(rc));
		exit(EXIT_FAILURE);
	}
	/* Initialize the interface 
	 */
	if ((rc = PtlNIInit(PTL_IFACE_DEFAULT, PTL_PID_ANY,
			    NULL, NULL, &ni_h)) != PTL_OK) {
		fprintf(stderr, "PtlNIInit(): %s\n", PtlErrorStr(rc));
		exit(EXIT_FAILURE);
	}
	/* Get my rank and group size 
	 */
	if ((rc = PtlGetRank(ni_h, &rank, &size)) != PTL_OK) {
		fprintf(stderr, "PtlGetRank(): %s\n", PtlErrorStr(rc));
		exit(EXIT_FAILURE);
	}
	if (size & 1) {
		if (!rank)
			fprintf(stderr,
				"Put_pp requires an even number of tasks.\n");
		exit(EXIT_FAILURE);
	}
	sender = !(rank & 1);

	if (end_len < start_len) {
		if (rank == 0) 
			fprintf(stderr, "Error: end_len < start_len.\n");
		exit(EXIT_FAILURE);
	}
	if (inflight > MAX_INFLIGHT) {
		if (rank == 0) 
			fprintf(stderr, "Error: use inflight <= %d.\n",
				MAX_INFLIGHT);
		exit(EXIT_FAILURE);
	}
	/* Get source (initiator) and destination (target) ids
	 */
	src = rank >> 1;
	src <<= 1;
	if ((rc = PtlGetRankId(ni_h, src, &src_id)) != PTL_OK) {
		fprintf(stderr, "%d:PtlGetRankId(): %s\n",
			rank, PtlErrorStr(rc));
		exit(EXIT_FAILURE);
	}
	if ((rc = PtlGetRankId(ni_h, src+1, &dst_id)) != PTL_OK) {
		fprintf(stderr, "%d:PtlGetRankId(): %s\n",
			rank, PtlErrorStr(rc));
		exit(EXIT_FAILURE);
	}
	/* Add an access control entry to allow any user to access our
	 * MDs.
	 */
	if (ace_any) {
		rc = PtlACEntry(ni_h, ace_any, 
				(ptl_process_id_t){PTL_NID_ANY, PTL_PID_ANY},
				PTL_UID_ANY, PTL_JID_ANY, PTL_PT_INDEX_ANY);
		if (rc != PTL_OK) {
			fprintf(stderr, "%d: PtlACEntry(): %s\n",
				rank, PtlErrorStr(rc));
			exit(EXIT_FAILURE);
		}
	}
	/* Allocate the buffers and memory descriptors used for the messages.
	 * Since we want to reuse memory descriptors, if we're the target
	 * we'll allow our descriptor offsets to be managed remotely, so
	 * the initiator can always send to the start of the buffer.
	 */
	msg = malloc(inflight*sizeof(*msg));
	if (!msg) {
		perror("buffer malloc");
		exit(EXIT_FAILURE);
	}
	for (i=0; i<inflight; i++) {

		msg[i].buf = malloc(end_len);
		if (!msg[i].buf) {
			perror("buffer malloc");
			exit(EXIT_FAILURE);
		}
		memset(msg[i].buf, 0, end_len);
		memset(&msg[i].md, 0, sizeof(msg[i].md));
		msg[i].md.start = msg[i].buf;
		msg[i].md.length = end_len;
		msg[i].md.threshold = PTL_MD_THRESH_INF;
		msg[i].md.options =
			PTL_MD_OP_PUT |
			(sender ? 0 : PTL_MD_MANAGE_REMOTE) |
			PTL_MD_EVENT_START_DISABLE;
		msg[i].md.user_ptr = msg + i;

		/* create an event queue for this message.
		 */
		rc = PtlEQAlloc(ni_h, 5, PTL_EQ_HANDLER_NONE, &msg[i].eq_h);
		if (rc != PTL_OK) {
			fprintf(stderr, "%d:PtlEQAlloc(): %s\n",
				rank, PtlErrorStr(rc));
			exit(EXIT_FAILURE);
		}
		msg[i].md.eq_handle = msg[i].eq_h;

		/* If we want to reuse our memory descriptors, we need a
		 * way to reset the library memory descriptor's local
		 * offset, which gets updated on a successful operation.
		 * If we're the initiator, we'll use PtlMDUpdate to do that, 
		 * so we'll save our values here.
		 */
		msg[i].md_save = msg[i].md;

		/* Create a match entry to receive this buffer.
		 * Use the source rank as the match bits, and
		 * don't ignore any bits.
		 */
		ptl_match_bits_t mb = 
			(ptl_match_bits_t )src << INFLIGHT_BITS | i;
		rc = PtlMEAttach(ni_h, ptl, 
				 sender ? dst_id : src_id, mb, 0,
				 PTL_RETAIN, PTL_INS_AFTER,
				 &msg[i].me_h);
		if (rc != PTL_OK) {
			fprintf(stderr, "%d:PtlMEAttach: %s\n",
				rank, PtlErrorStr(rc));
			exit(EXIT_FAILURE);
		}
		/* Attach the memory descriptor to the match entry.
		 */
		rc = PtlMDAttach(msg[i].me_h, msg[i].md,
				 PTL_RETAIN, &msg[i].md_h);
		if (rc != PTL_OK) {
			fprintf(stderr, "%d:PtlMDAttach: %s\n",
				rank, PtlErrorStr(rc));
			exit(EXIT_FAILURE);
		}
	}
	/* Make sure our partner is listening.
	 */
	if (verbose)
		printf("Making sure partner is ready\n");
	partner_handshake(sender ? src_id : dst_id,
			  sender ? dst_id : src_id,
			  ni_h, sync_ptl, ~(ptl_match_bits_t)0, ace_any);
	if (verbose)
		printf("OK, partner is ready\n");

	if (rank == 0) {
		printf("\nResults for %d trial%s, ",
		       trials, (trials > 1 ? "s" : ""));
		printf("with %d message%s in flight:\n", 
		       inflight, (inflight > 1 ? "s" : ""));
		printf("  Times in microseconds.\n");
		printf("\n\
  Message    minimum    average    maximum    minimum    average    maximum\n\
   Length       ET         ET         ET      latency    latency    latency\n\
\n\
");
	}

	len = start_len;

next_size:
	total_et = 0;
	max_et = 0;
	min_et = DBL_MAX;

	i = m = 0;
	while (sender && !done) {

		if (i < trials) 
			put(dst_id, ptl, ace_any, msg+m, len, src,
			    m, i, rank, verbose);
		m += 1;
		m %= inflight;

		if (++i < inflight) continue;

		event(msg+m, &ev, PTL_EVENT_SEND_END, rank, ni_h);
		event(msg+m, &ev, PTL_EVENT_PUT_END, rank, ni_h);

		cmsg = ev.md.user_ptr;
		gettimeofday(&cmsg->end, 0);
		et = tv_diff(&cmsg->start, &cmsg->end);

		total_et += et;
		min_et = min_et < et ? min_et : et;
		max_et = max_et > et ? max_et : et;

		if (verbose)
			printf("%d:   PUT: len %d trial %d msg %d "
			       "start %f end %f et %f\n",
			       rank, (int)len, cmsg->id, (int)(cmsg-msg), 
			       tv_diff(&pgm_start, &cmsg->start),
			       tv_diff(&pgm_start, &cmsg->end), et);

		if (cmsg->id == trials-1) break;
	}

	i = 0;
	while (!sender) {

		m %= inflight;

		event(msg+m, &ev, PTL_EVENT_PUT_END, rank, ni_h);
		if (verbose)
			printf("%d:   Received len %d trial %d msg %d\n",
			       rank, (int)ev.mlength, i, m);

		put(src_id, ptl, ace_any, msg+m, len, src,
		    m, i, rank, verbose);
		event(msg+m, &ev, PTL_EVENT_SEND_END, rank, ni_h);

		if (++i == trials) break;
		m++;
	}

	ave_et = total_et / trials;

	if (rank == 0)
		printf("%9d%11.2f%11.2f%11.2f%11.2f%11.2f%11.2f\n",
		       (int)len, min_et, ave_et, max_et,
		       min_et/2, ave_et/2, max_et/2);

	if (add_inc)
		len += inc;
	else 
		if (len) len *= inc;
		else len = 1;

	if (len <= end_len) goto next_size;

	/* Make sure our partner is done.
	 */
	if (verbose)
		printf("Making sure partner is done\n");
	partner_handshake(sender ? src_id : dst_id,
			  sender ? dst_id : src_id,
			  ni_h, sync_ptl, ~(ptl_match_bits_t)1, ace_any);
	if (verbose)
		printf("OK, partner is done\n");

	/* Single-threaded user-space NALs need to poll for a little 
	 * while to make sure the shutdown handshake completes.
	 */
	{
		timeout_val_t t_o;
		set_timeout(&t_o, 500);	/* half-second from now */
		while (!test_timeout(&t_o)) {
			PtlEQGet(msg[0].eq_h, &ev);
		}
	}
	/* close down the network interface 
	 */
	PtlNIFini(ni_h);

	/* finalize library 
	 */
	PtlFini();

	for (i=0; i<inflight; i++) free(msg[i].buf);
	free(msg);

	return 0;
}

