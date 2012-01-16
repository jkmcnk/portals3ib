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

/*  This Portals 3 program sends a message around a ring.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <portals3.h>
#include P3_NAL
#include <p3rt/p3rt.h>
#include <p3api/debug.h>
#include <p3/debug.h>

#include "handshake.h"


static 
const char usage[] = "\n\
ringtest [-ahv] [-d <dbg>] [-t <cnt>] \n\
\n\
	Performs a simple communication test by passing a token from \n\
	process rank n to rank mod(n+1,N), where 0 <= n < N. \n\
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
	-t cnt	Sets the number of trips the token takes around the ring \n\
		  to <cnt>. \n\
	-v	Causes ringtest to be verbose about the progress of \n\
		  the token. \n\
";


static void test_fail(int rank, const char *str, int rc)
{
	fprintf(stderr, "%d: %s: %s (%d)\n", rank, str, PtlErrorStr(rc), rc);
}

int main(int argc, char *argv[])
{
	unsigned prev, next;
	unsigned rank, size;
	int num_if;

	ptl_pt_index_t ptl = 4;
	ptl_pt_index_t sync_ptl = 5;
	ptl_ac_index_t ace_any = 0;
	ptl_process_id_t my_id, prev_id, next_id;
	ptl_match_bits_t send_mbits, recv_mbits, ibits;
	ptl_handle_ni_t ni_h;
	ptl_handle_me_t me_h;
	ptl_md_t md;
	ptl_handle_md_t md_h;
	ptl_handle_eq_t eq_h;
	ptl_event_t ev;
	int token = 0, have_token, rc, trip = 0, count = 16;
	unsigned i, dbg = 0;
	int verbose = 0;

	while (1) {
		int c = getopt(argc, argv, "ad:ht:v");
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
		case 't':
			count = strtol(optarg, NULL, 0);
			break;
		case 'v':
			verbose = 1;
			break;
		}
	}

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
	/* Get my id
	 */
	if ((rc = PtlGetId(ni_h, &my_id)) != PTL_OK) {
		fprintf(stderr, "PtlGetId(): %s\n", PtlErrorStr(rc));
		exit(EXIT_FAILURE);
	}
	/* Get my rank and group size 
	 */
	if ((rc = PtlGetRank(ni_h, &rank, &size)) != PTL_OK) {
		fprintf(stderr, "PtlGetRank(): %s\n", PtlErrorStr(rc));
		exit(EXIT_FAILURE);
	}
	/* Figure out my next neighbor's rank and id
	 */
	next = (rank + 1) % size;
	if ((rc = PtlGetRankId(ni_h, next, &next_id)) != PTL_OK) {
		fprintf(stderr, "PtlGetRankId(): next rank: %s\n",
			PtlErrorStr(rc));
		exit(EXIT_FAILURE);
	}
	/* Figure out my previous neighbor's rank 
	 */
	prev = (rank + size - 1) % size;
	if ((rc = PtlGetRankId(ni_h, prev, &prev_id)) != PTL_OK) {
		fprintf(stderr, "PtlGetRankId(): prev rank: %s\n",
			PtlErrorStr(rc));
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
	/* All match bits are significant 
	 */
	ibits = 0;

	/* Match bits are prev rank 
	 */
	recv_mbits = (ptl_match_bits_t) prev;

	rc = PtlMEAttach(ni_h, ptl,	/* portal table index */
			 prev_id,	/* source address */
			 recv_mbits,	/* expected match bits */
			 ibits,		/* ignore bits to mask */
			 PTL_UNLINK,	/* unlink when md is unlinked */
			 PTL_INS_AFTER,
			 &me_h);
	if (rc != PTL_OK) {
		fprintf(stderr, "%d: PtlMEAttach(): %s\n",
			rank, PtlErrorStr(rc));
		exit(EXIT_FAILURE);
	}

	/* Create an event queue 
	 */
	rc = PtlEQAlloc(ni_h, 2, PTL_EQ_HANDLER_NONE, &eq_h);
	if (rc != PTL_OK) {
		fprintf(stderr, "%d: PtlEQAlloc(): %s\n",
			rank, PtlErrorStr(rc));
		exit(EXIT_FAILURE);
	}

	/* Create a memory descriptor 
	 */
	md.start = &token;			/* start address */
	md.length = sizeof(token);		/* length of buffer */
	md.threshold = PTL_MD_THRESH_INF;	/* number of expected
						 * operations on md */
	md.options =
		PTL_MD_OP_PUT | PTL_MD_MANAGE_REMOTE | PTL_MD_TRUNCATE |
		PTL_MD_EVENT_START_DISABLE;
	md.max_size = 0;
	md.user_ptr = NULL;	/* nothing to cache */
	md.eq_handle = eq_h;	/* event queue handle */

	/* Attach the memory descriptor to the match entry 
	 */
	rc = PtlMDAttach(me_h, md,	/* md to attach */
			 PTL_UNLINK,	/* unlink when threshold is 0 */
			 &md_h);
	if (rc != PTL_OK) {
		fprintf(stderr, "%d: PtlMDAttach(): %s\n",
			rank, PtlErrorStr(rc));
		exit(EXIT_FAILURE);
	}
	/* Make sure my partners are there.
	 */
	
	if (verbose)
		printf("I'm"FMT_NIDPID"\n", my_id.nid, my_id.pid);
	for (i=0; i<2; i++) {
		if (i ^ (rank & 1)) {
			if (verbose)
				printf("Making sure next partner"FMT_NIDPID
				       " is ready\n", next_id.nid, next_id.pid);
			partner_handshake(my_id, next_id, ni_h, sync_ptl,
					  ~(ptl_match_bits_t)i, ace_any);
			if (verbose)
				printf("OK, next partner is ready\n");
		}
		else {
			if (verbose)
				printf("Making sure prev partner"FMT_NIDPID
				       " is ready\n", prev_id.nid, prev_id.pid);
			partner_handshake(my_id, prev_id, ni_h, sync_ptl,
					  ~(ptl_match_bits_t)i, ace_any);
			if (verbose)
				printf("OK, prev partner is ready\n");
		}
	}

	/* Rank zero gets the token first 
	 */
	have_token = rank == 0 ? 1 : 0;

	do {
		if (have_token) {
			if (verbose || rank == 0)
				printf("%d: Sending token to %d (round %d)\n",
					rank, next, trip);

			send_mbits = (ptl_match_bits_t) rank;

			rc = PtlPut(md_h, PTL_NO_ACK_REQ,
				    next_id, ptl, ace_any, send_mbits, 0, 0);
			if (rc != PTL_OK) {
				test_fail(rank, "PtlPut", rc);
				exit(EXIT_FAILURE);
			}
			/* Wait for the send to complete 
			 */
			rc = PtlEQWait(eq_h, &ev);
			if (rc != PTL_OK && rc != PTL_EQ_DROPPED) {
				test_fail(rank, "PtlEQWait for send", rc);
				exit(EXIT_FAILURE);
			}
			/* Check for NI failure
			 */
			if (ev.ni_fail_type != PTL_NI_OK) {
				fprintf(stderr,	"%d: NI sent %s in event "
					"for send.\n", rank, 
					PtlNIFailStr(ni_h, ev.ni_fail_type));
				exit(EXIT_FAILURE);
			}
			/* Check event type 
			 */
			if (ev.type != PTL_EVENT_SEND_END) {
				fprintf(stderr,	"%d: expected "
					"PTL_EVENT_SEND_END, got %s\n",
					rank, PtlEventKindStr(ev.type));
				exit(EXIT_FAILURE);
			}
			have_token = 0;
			trip++;
		}
		if (rank > 0 && trip == count)
			break;
		
		rc = PtlEQWait(eq_h, &ev);
		if (rc != PTL_OK && rc != PTL_EQ_DROPPED) {
			test_fail(rank, "PtlEQWait for recv", rc);
			exit(EXIT_FAILURE);
		}
		/* Check for NI failure
		 */
		if (ev.ni_fail_type != PTL_NI_OK) {
			fprintf(stderr,
				"%d: NI sent %s in event for receive.\n",
				rank, PtlNIFailStr(ni_h, ev.ni_fail_type));
			exit(EXIT_FAILURE);
		}
		/* Check event type 
		 */
		if (ev.type != PTL_EVENT_PUT_END) {
			fprintf(stderr, "%d: expected "
				"PTL_EVENT_PUT_END got %s\n",
				rank, PtlEventKindStr(ev.type));
			exit(EXIT_FAILURE);
		}
		else {
			int ex_value = size * trip + rank - 1;
			have_token = 1;
			if (verbose)
				printf("%d: received token from %d"
				       " (round %d)\n",
				       rank, prev, trip);
			if (token != ex_value)
				printf("%d: round %d got token w/value %d, "
				       "should be %d\n", 
				       rank, trip, token, ex_value);
			token++;
		}
		if (rank == 0 && trip == count)
			break;
	} while (1);

	/* Close down the network interface 
	 */
	if (verbose || rank == 0) {
		printf("%d: Passed all rounds\n", rank);
	}

	PtlNIFini(ni_h);

	/* Close down library 
	 */
	PtlFini();

	return 0;
}
