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

/*  This Portals 3 program uses PtlGetPut to implement a lock.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <portals3.h>
#include P3_NAL
#include <p3rt/p3rt.h>
#include <p3/debug.h>
#include <p3api/debug.h>

#include "handshake.h"

static 
const char usage[] = "\n\
locktest [-hv] [-d <dbg>] [-e <fn>] [-t <cnt>] \n\
\n\
	Uses PtlGetPut to implement a lock.  Rank 0 is the lock master \n\
	(i.e., storage for the lock value lives there), and does not \n\
	attempt to acquire the lock. \n\
\n\
	-a	Adds an access control entry to permit any user to access\n\
		  the MDs of this process\n\
	-d dbg	Sets the debug mask to <dbg>, which will cause the \n\
		  Portals library and the NAL to emit various debugging \n\
		  output, assuming both were configured with debugging \n\
		  enabled.  See p3api/debug.h for appropriate values.  \n\
		  See also NAL documentation or implementation for \n\
		  appropriate NAL-specific values. \n\
	-e fn	Sends debug and verbose output to file <fn>; verbose \n\
		  output still also goes to stdout.\n\
	-h	Prints this message. \n\
	-l cnt	Sets the number of successful lock acquisitions to <cnt>. \n\
	-s cnt	Causes the lock acquirer to sleep <cnt> microseconds before\n\
		  attempting to acquire the lock.\n\
	-v	Causes locktest to be verbose about who owns the lock. \n\
";

int next_event(int rank, ptl_handle_ni_t ni_h, 
	       ptl_handle_eq_t *eq_h_list, int listlen, ptl_event_t *ev) 
{
	int rc, which;

	rc = PtlEQPoll(eq_h_list, listlen, 0, ev, &which);
	if (rc != PTL_OK && rc != PTL_EQ_EMPTY) {
		fprintf(stderr, "%d: PtlEQPoll(): eq "FMT_HDL_T": %s\n",
			rank, eq_h_list[which], PtlErrorStr(rc));
		if (rc != PTL_EQ_DROPPED)
			exit(EXIT_FAILURE);
	}
	if (ev->ni_fail_type != PTL_NI_OK) {
		fprintf(stderr,
			"%d: NI sent %s in %s event.\n",
			rank, PtlNIFailStr(ni_h, ev->ni_fail_type),
			PtlEventKindStr(ev->type));
		exit(EXIT_FAILURE);
	}
	return rc;
}

int main(int argc, char *argv[])
{
	unsigned rank, size, n;
	int num_if;

	ptl_pt_index_t ptl = 4;
	ptl_pt_index_t sync_ptl = 5;
	ptl_ac_index_t ace_any = 0;

	ptl_process_id_t lck_id;
	ptl_handle_ni_t ni_h;
	ptl_md_t md_lock, md_notify;
	ptl_handle_me_t me_lock_h, me_notify_h;
	ptl_handle_md_t md_lock_h, md_notify_h;
	ptl_handle_eq_t eq_lock_h, eq_notify_h;
	ptl_event_t ev;

	ptl_match_bits_t lock_mbits = ~0xa, notify_mbits = ~0xb, ibits = 0;
	ptl_process_id_t any_id = {PTL_NID_ANY, PTL_PID_ANY};

	unsigned l, count = 32, heartbeat, hb_cnt = 0;
	int lock = 0, have_lock = 0, lock_owner = 0;
	int rc, verbose = 0;
	unsigned dbg = 0, acquire_sleep = 0;

	char *fn = NULL;
	FILE *file = NULL, *out = NULL;

#define PRINTF(args...) do { if (fn) fprintf(file,args); } while (0)

	while (1) {
		int c = getopt(argc, argv, "a:d:e:hl:s:v");
		if (c == -1) break;

		switch (c) {
		case 'a':
			ace_any = 1;
			break;
		case 'd':
			dbg = strtoul(optarg, NULL, 0);
			break;
		case 'e':
			fn = strdup(optarg);
			break;
		case 'h':
			printf("%s", usage);
			exit(EXIT_SUCCESS);
		case 'l':
			count = strtol(optarg, NULL, 0);
			break;
		case 's':
			acquire_sleep = strtol(optarg, NULL, 0);
			break;
		case 'v':
			verbose = 1;
			break;
		}
	}
	if (fn) {
		file = fopen(fn, "w");
		if (!file) {
			perror("opening log file");
			exit(EXIT_FAILURE);
		}
		p3_out = file;
		out = file;
		
	}
	else
		out = stdout;

	heartbeat = count / 1000;
	if (!heartbeat)
		heartbeat = 1;

	if (acquire_sleep)
		printf("Sleeping %d microseconds before acquisition attempt\n",
		       acquire_sleep);

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
	/* Get lockmaster (rank 0) id
	 */
	if ((rc = PtlGetRankId(ni_h, 0, &lck_id)) != PTL_OK) {
		fprintf(stderr, "%d: PtlGetRankId(): %s\n",
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
			fprintf(stderr, "%d: PtlACEntry() failed: %s\n",
				rank, PtlErrorStr(rc));
			exit(EXIT_FAILURE);
		}
	}

	/* Create an event queue for lock events.  We only need this on 
	 * clients.
	 */
	if (rank) {
		rc = PtlEQAlloc(ni_h, 16, PTL_EQ_HANDLER_NONE, &eq_lock_h);
		if (rc != PTL_OK) {
			fprintf(stderr, "%d: PtlEQAlloc(): %s\n",
				rank, PtlErrorStr(rc));
			exit(EXIT_FAILURE);
		}
	}
	else
		eq_lock_h = PTL_EQ_NONE;

	/* Create a memory descriptor for the lock.
	 *
	 * Lockmaster uses it to hold the lock; clients use it to acquire
	 * lock.  If we're the lockmaster, we want no events on this MD:
	 * if clients are beating on the lock trying to acquire it, we
	 * may not have time to process all the events.  Plus, we just
	 * don't care.
	 */
	md_lock.start = &lock;
	md_lock.length = sizeof(lock);
	md_lock.threshold = PTL_MD_THRESH_INF;
	md_lock.options =
		PTL_MD_OP_PUT | PTL_MD_OP_GET |
		PTL_MD_MANAGE_REMOTE | PTL_MD_TRUNCATE |
		PTL_MD_EVENT_START_DISABLE;
	md_lock.max_size = 0;
	md_lock.user_ptr = NULL;
	md_lock.eq_handle = eq_lock_h;

	/* Lockmaster needs a match entry for clients to access lock value. 
	 */
	rc = PtlMEAttach(ni_h, ptl,
			 any_id,	/* source address */
			 lock_mbits,	/* expected match bits */
			 ibits,		/* ignore bits to mask */
			 PTL_UNLINK,	/* unlink when md is unlinked */
			 PTL_INS_AFTER,
			 &me_lock_h);
	if (rc != PTL_OK) {
		fprintf(stderr, "%d: PtlMEAttach(): %s\n",
			rank, PtlErrorStr(rc));
		exit(EXIT_FAILURE);
	}
	rc = PtlMDAttach(me_lock_h, md_lock, PTL_UNLINK, &md_lock_h);
	if (rc != PTL_OK) {
		fprintf(stderr, "%d: PtlMDAttach(): %s\n",
			rank, PtlErrorStr(rc));
		exit(EXIT_FAILURE);
	}

	/* Create an event queue for lock notification events.
	 */
	rc = PtlEQAlloc(ni_h, 16, PTL_EQ_HANDLER_NONE, &eq_notify_h);
	if (rc != PTL_OK) {
		fprintf(stderr, "%d: PtlEQAlloc(): %s\n",
			rank, PtlErrorStr(rc));
		exit(EXIT_FAILURE);
	}
	/* Create a memory descriptor for lock notification events.
	 *
	 * A client will send a message to the lockmaster  when it has
	 * acquired the lock - the lockmaster will use this to know when
	 * to terminate.
	 */
	md_notify.start = &lock_owner;
	md_notify.length = sizeof(lock_owner);
	md_notify.threshold = PTL_MD_THRESH_INF;
	md_notify.options =
		PTL_MD_OP_PUT | PTL_MD_OP_GET |
		PTL_MD_MANAGE_REMOTE | PTL_MD_TRUNCATE |
		PTL_MD_EVENT_START_DISABLE;
	md_notify.max_size = 0;
	md_notify.user_ptr = NULL;
	md_notify.eq_handle = eq_notify_h;

	/* Lockmaster needs a match entry for clients to notify on lock
	 * acquisition.  Clients need a match entry to get signals
	 * from lockmaster.
	 *
	 * Clients need a match entry to get signals from lockmaster.
	 */
	rc = PtlMEAttach(ni_h, ptl,
			 any_id,	/* source address */
			 notify_mbits,	/* expected match bits */
			 ibits,		/* ignore bits to mask */
			 PTL_UNLINK,	/* unlink when md is unlinked */
			 PTL_INS_AFTER,
			 &me_notify_h);
	if (rc != PTL_OK) {
		fprintf(stderr, "%d: PtlMEAttach(): %s\n",
			rank, PtlErrorStr(rc));
		exit(EXIT_FAILURE);
	}
	rc = PtlMDAttach(me_notify_h, md_notify, PTL_UNLINK, &md_notify_h);
	if (rc != PTL_OK) {
		fprintf(stderr, "%d: PtlMDAttach(): %s\n",
			rank, PtlErrorStr(rc));
		exit(EXIT_FAILURE);
	}
	/* Client/lockmaster handshake: it would be nice if we had a barrier
	 * operation for this, but I'm lazy...
	 *
	 * Since we ignore PutGet events on the lockmaster, there is no
	 * danger of overrunning an event queue if a client starts trying
	 * to acquire the lock before we are ready to acknowledge it.
	 */
	for (n=(rank ? rank : 1); n<(rank ? rank+1 : size); n++) {
		ptl_process_id_t tgt_id;
		ptl_match_bits_t mb;

		printf("%d: Making sure partner rank %d is ready\n",
		       rank, (rank ? 0 : n));
		if ((rc = PtlGetRankId(ni_h, n, &tgt_id)) != PTL_OK) {
			fprintf(stderr, "%d: PtlGetRankId(): rank %d: %s\n",
				rank, n, PtlErrorStr(rc));
			exit(EXIT_FAILURE);
		}
		mb = ~(ptl_match_bits_t)0 ^ (ptl_match_bits_t)n;
		partner_handshake(rank ? tgt_id : lck_id,
				  rank ? lck_id : tgt_id,
				  ni_h, sync_ptl, mb, ace_any);
	}
	printf("OK, partner%s ready\n", (rank ? " is" : "s are"));

#define dump_ev(rc,ev) \
do {									\
	char *fmt = "%20s: %22s eq: "FMT_HDL_T				\
	" seq "FMT_SEQ_T" link "FMT_SEQ_T"\n";				\
	PRINTF(fmt, PtlErrorStr(rc), PtlEventKindStr((ev)->type), 	\
	       (ev)->md.eq_handle, (ev)->sequence, (ev)->link);		\
} while(0)

	/* Lockmaster
	 */
	l = 0;
	while (rank == 0) {

		do {
			ptl_handle_eq_t eq_list[] = {eq_notify_h};
			rc = next_event(rank, ni_h, eq_list, 1, &ev);
		} while (rc == PTL_EQ_EMPTY);

		dump_ev(rc, &ev);

		if (rc != PTL_OK)
			goto done;

		if (!(ev.type == PTL_EVENT_PUT_END && ev.mlength == 0))
			continue;

		l++;

		if (verbose) {
			char *fmt = "Lock:"FMT_NIDPID" count %d\n";
			printf(fmt, ev.initiator.nid, ev.initiator.pid, l);
			PRINTF(fmt, ev.initiator.nid, ev.initiator.pid, l);
		}
		else if (l % heartbeat == 0) {
			printf(".");
			hb_cnt++;
			if (hb_cnt % 80 == 0 || l == count)
				printf("\n");
			fflush(stdout);
		}
		/* Signal lock holder to give up lock
		 */
		rc = PtlPutRegion(md_notify_h, 0, 0, PTL_ACK_REQ,
				  ev.initiator, ptl, ace_any, 
				  notify_mbits, 0, 0);
		if (rc != PTL_OK) {
			fprintf(stderr, "%d: PtlPutRegion(): %s\n",
				rank, PtlErrorStr(rc));
			exit(EXIT_FAILURE);
		}

		if (l < count)
			continue;
	done:
		/* Note that on shutdown, our notification is waiting
		 * on a clients trying to acquire a lock.  So it is
		 * normal if a lock is granted after we think we're done.
		 */		
		for (n=1; n<size; n++) {
			ptl_process_id_t client_id;
			char *fmt = "sending stop to rank %d\n";
			printf(fmt, n);
			PRINTF(fmt, n);

			rc = PtlGetRankId(ni_h, n, &client_id);
			if (rc != PTL_OK) {
				fprintf(stderr, "%d: PtlGetRankId(): %s\n",
					rank, PtlErrorStr(rc));
				exit(EXIT_FAILURE);
			}
			rc = PtlGetRegion(md_notify_h, 0, 0,client_id, ptl,
					  ace_any, notify_mbits, 0);
			if (rc != PTL_OK) {
				fprintf(stderr, "%d: PtlGetRegion(): %s\n",
					rank, PtlErrorStr(rc));
				exit(EXIT_FAILURE);
			}
		wait_shutdown:
			do {
				ptl_handle_eq_t eq_list[] = {eq_notify_h};
				rc = next_event(rank, ni_h, eq_list, 1, &ev);
			} while (rc == PTL_EQ_EMPTY);

			if (rc != PTL_OK)
				exit(EXIT_FAILURE);

			if (ev.type != PTL_EVENT_REPLY_END)
				goto wait_shutdown;
		}
		break;
	}
	/* Client
	 */
	while (rank != 0) {

		lock = rank;
	again:
		/* Need to reset our local offset back to zero due to the
		 * previous PtlGetPut.
		 */
		do {
			rc = PtlMDUpdate(md_lock_h, NULL, NULL, eq_lock_h);
		} while (rc == PTL_MD_NO_UPDATE);

		if (rc != PTL_OK) {
			fprintf(stderr, "%d: PtlMDUpdate(): %s\n",
				rank, PtlErrorStr(rc));
			exit(EXIT_FAILURE);
		}
		/* Try to acquire the lock.
		 */
		if (acquire_sleep)
			usleep(acquire_sleep);

		rc = PtlGetPut(md_lock_h, md_lock_h, lck_id,
			       ptl, ace_any, lock_mbits, 0, 0);
		if (rc != PTL_OK) {
			fprintf(stderr, "%d: PtlGetPut(): %s\n",
				rank, PtlErrorStr(rc));
			exit(EXIT_FAILURE);
		}
	event:

		do {
			ptl_handle_eq_t eq_list[] = {eq_lock_h, eq_notify_h};
			rc = next_event(rank, ni_h, eq_list, 2, &ev);
		} while (rc == PTL_EQ_EMPTY);

		dump_ev(rc, &ev);

		if (rc != PTL_OK)
			exit(EXIT_FAILURE);

		if (ev.type == PTL_EVENT_REPLY_END) {
			if (lock != 0) {
				lock = rank;
				goto again;
			}
			have_lock = 1;
			l++;
			if (verbose) {
				char *fmt = "%d: my lock count %d\n";
				printf(fmt, rank, l);
				PRINTF(fmt, rank, l);
			}
			else if (l % heartbeat == 0) {
				printf(".");
				hb_cnt++;
				if (hb_cnt % 80 == 0 || l == count)
					printf("\n");
				fflush(stdout);
			}
			/* Signal lockmaster we own the lock.
			 */
			rc = PtlPutRegion(md_notify_h, 0, 0, PTL_ACK_REQ,
					  lck_id, ptl, ace_any,
					  notify_mbits, 0, 0);
			if (rc != PTL_OK) {
				fprintf(stderr, "%d: PtlPutRegion(): "
					"%s\n", rank, PtlErrorStr(rc));
				exit(EXIT_FAILURE);
			}
			goto event;
		}
		if (ev.type == PTL_EVENT_PUT_END) {

			if (!have_lock)
				goto event;

			/* Reset the lock.
			 */
			have_lock = 0;
			lock = 0;

			goto again;
		}
		if (ev.type == PTL_EVENT_GET_END) {
			char *fmt = "\n%d: received stop from lockmaster\n";
			printf(fmt, rank);
			PRINTF(fmt, rank);
			printf("\n");
			break;
		}
		goto event;
	}
	/* Wait for things to settle down, then shut down.
	 */
	sleep(1);
	PtlFini();

	return 0;
}
