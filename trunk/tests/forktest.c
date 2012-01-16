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

/* This Portals 3.0 program tests for correct behavior across a fork().
 *
 * FIXME: When the child calls PtlFini() as required by the spec, free()
 * has problems freeing memory allocated in the parent by the API. I 
 * cannot figure out why this is happening, but "export MALLOC_CHECK_=1"
 * lets free() get past the problem.  Ugly, but I don't have time to
 * figure out what is going on.
 */

#include <p3-config.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <float.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>

#include <portals3.h>
#include P3_NAL
#include <p3rt/p3rt.h>
#include <p3api/debug.h>
#include <p3/debug.h>

#include "handshake.h"

#define INFLIGHT_BITS 5
#define MAX_INFLIGHT (1 << INFLIGHT_BITS)

static 
const char usage[] = " \n\
forktest [-ahsv] [-d <dbg>] [-m <sz>] [-M <sz>] \n\
 \n\
	Tests for proper behaviour across a fork() system call, using\n\
	PtlPut between pairs of processes, where rank n/2 processes send \n\
	data and rank 1+n/2 processes receive data, for 0 <= n <= N/2, with \n\
	N even. \n\
 \n\
	Part of a buffer is sent, both initiator and target fork, then\n\
	the remainder of the buffer is sent by both parents and children.\n\
	Data integrity is tested after the sends complete.\n\
 \n\
	Optionally, use system() rather than fork(), which tests the case\n\
	where Portals is shut down implicitly in the child after the fork.\n\
 \n\
	The elapsed time clock for each message sent starts when PtlPut \n\
	is called, and ends when an ACK is received. \n\
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
	-m sz	Sets the size of the message sent, in bytes. \n\
	-M sz	Sets the total size of messages sent. \n\
		  min and max may be suffixed with one of the \n\
		  following multipliers: \n\
		  k	*1000 \n\
		  M	*1000*1000 \n\
		  G	*1000*1000*1000 \n\
		  Ki	*1024 \n\
		  Mi	*1024*1024 \n\
		  Gi	*1024*1024*1024 \n\
	-s	Use system() to execute a shell 'sleep 1' command, rather\n\
		  than forking with the children using Portals.\n\
	-v	Causes forktest to be verbose about the progress of \n\
		  each trial. \n\
";

pid_t my_pid, child_pid, parent_pid;

unsigned rank, size, src;
int num_if;

ptl_pt_index_t ptl = 4;
ptl_pt_index_t sync_ptl = 5;
ptl_ac_index_t ace_any = 0;
ptl_process_id_t src_id, dst_id;
ptl_handle_ni_t ni_h;

ptl_nid_t *nidmap;
ptl_pid_t *pidmap;

unsigned sender;
unsigned use_system = 0;
unsigned dbg = 0, done = 0, verbose = 0;

unsigned msg_sz = 2000, buf_sz = 10000, msg_data_count, data_count, msg_count;
uint64_t *buffer, *msg_buf;

ptl_handle_me_t me_h;
ptl_handle_md_t md_h;
ptl_handle_eq_t eq_h;
ptl_md_t md, md_save;

static inline
void event(ptl_handle_eq_t eq_h, ptl_event_t *ev,
	   int rank, ptl_handle_ni_t ni_h)
{
	int rc;

	if ((rc = PtlEQWait(eq_h, ev)) != PTL_OK) {
		fprintf(stderr, "%d:%d: PtlEQWait(): %s\n",
			rank, my_pid, PtlErrorStr(rc));
		exit(EXIT_FAILURE);
	}
	if (ev->ni_fail_type != PTL_NI_OK) {
		fprintf(stderr, "%d:%d: NI sent %s in event.\n",
			rank, my_pid, PtlNIFailStr(ni_h, ev->ni_fail_type));
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

/* We allocate both bufs on sender and receiver, although sender only
 * uses msg_buf and receiver only uses buffer.
 */
void alloc_bufs()
{
	unsigned sz;

	if (verbose)
		printf("%d: Allocating buffers\n", my_pid);

	msg_sz = msg_sz & ~(sizeof(*msg_buf) - 1);

	buf_sz = buf_sz & ~(sizeof(*buffer) - 1);

	data_count = buf_sz / sizeof(*buffer);
	msg_data_count = msg_sz / sizeof(*msg_buf);
	msg_count = data_count / msg_data_count;

	sz = (1 + data_count) * sizeof(*buffer);
	buffer = malloc(sz);
	if (!buffer) {
		fprintf(stderr, "%d: buffer malloc: %s\n",
			my_pid, strerror(errno));
		exit(EXIT_FAILURE);
	}
	memset(buffer, 0, sz);

	sz = (1 + msg_data_count) * sizeof(*msg_buf);
	msg_buf = malloc(sz);
	if (!msg_buf) {
		fprintf(stderr, "%d: msg_buf malloc: %s\n",
			my_pid, strerror(errno));
		exit(EXIT_FAILURE);
	}
	memset(msg_buf, 0, sz);
}

void startup_parent()
{
	int rc;

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
			fprintf(stderr,	"forktest requires an "
				"even number of tasks.\n");
		exit(EXIT_FAILURE);
	}
	sender = !(rank & 1);

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
			fprintf(stderr, "%d: PtlACEntry(): %s\n",
				rank, PtlErrorStr(rc));
			exit(EXIT_FAILURE);
		}
	}
	/* Get our NID and PID maps so our child can use them to 
	 * initialize itself with a different PID
	 */
	nidmap = malloc(size * sizeof(ptl_nid_t));
	if (!nidmap) {
		perror("nidmap buffer malloc");
		exit(EXIT_FAILURE);
	}
	if ((rc = PtlGetNIDMap(ni_h, nidmap, size)) != PTL_OK) {
		fprintf(stderr, "Ptl_GetNIDMap(): %s\n", PtlErrorStr(rc));
		exit(EXIT_FAILURE);
	}

	pidmap = malloc(size * sizeof(ptl_pid_t));
	if (!pidmap) {
		perror("pidmap buffer malloc");
		exit(EXIT_FAILURE);
	}
	if ((rc = PtlGetPIDMap(ni_h, pidmap, size)) != PTL_OK) {
		fprintf(stderr, "Ptl_GetPIDMap(): %s\n", PtlErrorStr(rc));
		exit(EXIT_FAILURE);
	}
}

void startup_child()
{
	unsigned i;
	int rc;

	if (verbose)
		printf("%d: Child initializing Portals\n", my_pid);

	/* Initialize library 
	 */
	if ((rc = PtlInit(&num_if)) != PTL_OK) {
		fprintf(stderr, "%d: PtlInit(): %s\n",
			my_pid, PtlErrorStr(rc));
		exit(1);
	}
	/* Turn on debugging now so we can see NAL startup debug stuff.
	 */
	if (dbg)
		PtlNIDebug(PTL_INVALID_HANDLE, dbg);

	/* Initialize from the NID, PID maps we got from our parent.
	 */
	for (i=0; i<size; i++)
		pidmap[i] += size;

	if ((rc = PtlSetRank(PTL_INVALID_HANDLE, rank, size)) != PTL_OK) {
		fprintf(stderr, "%d: PtlSetRank(): %s\n",
			my_pid, PtlErrorStr(rc));
		exit(EXIT_FAILURE);
	}
	if ((rc = PtlSetNIDMap(PTL_INVALID_HANDLE, nidmap, size)) != PTL_OK) {
		fprintf(stderr, "%d: Ptl_SetNIDMap(): %s\n",
			my_pid, PtlErrorStr(rc));
		exit(EXIT_FAILURE);
	}
	if ((rc = PtlSetPIDMap(PTL_INVALID_HANDLE, pidmap, size)) != PTL_OK) {
		fprintf(stderr, "%d: Ptl_SetPIDMap(): %s\n",
			my_pid, PtlErrorStr(rc));
		exit(EXIT_FAILURE);
	}
	/* Initialize the interface 
	 */
	if (verbose)
		printf("%d:%d: child calling PtlNIInit()\n", rank, my_pid);
	if ((rc = PtlNIInit(PTL_IFACE_DEFAULT, PTL_PID_ANY,
			    NULL, NULL, &ni_h)) != PTL_OK) {
		fprintf(stderr, "%d: PtlNIInit(): %s\n",
			my_pid, PtlErrorStr(rc));
		exit(EXIT_FAILURE);
	}
	sender = !(rank & 1);

	/* Get source (initiator) and destination (target) ids
	 */
	src = rank >> 1;
	src <<= 1;
	if ((rc = PtlGetRankId(ni_h, src, &src_id)) != PTL_OK) {
		fprintf(stderr, "%d:%d: PtlGetRankId(): %s\n",
			rank, my_pid, PtlErrorStr(rc));
		exit(EXIT_FAILURE);
	}
	if ((rc = PtlGetRankId(ni_h, src+1, &dst_id)) != PTL_OK) {
		fprintf(stderr, "%d:%d: PtlGetRankId(): %s\n",
			rank, my_pid, PtlErrorStr(rc));
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
			fprintf(stderr, "%d:%d: PtlACEntry(): %s\n",
				rank, my_pid, PtlErrorStr(rc));
			exit(EXIT_FAILURE);
		}
	}
	if (verbose)
		printf("%d:%d: child finished portals startup\n",
		       rank, my_pid);
}

void deinit_child()
{
	if (verbose)
		printf("%d:%d: child calling PtlFini()\n", rank, my_pid);
	PtlFini();
}

void md_setup()
{
	int rc;

	if (verbose)
		printf("%d:%d: Setting up Portals handles, etc\n",
		       rank, my_pid);

	/* Create an MD for our buffer.
	 */
	if (sender) {
		md.start = msg_buf;
		md.length = msg_sz;
	}
	else {
		md.start = buffer;
		md.length = buf_sz;
	}
	md.threshold = PTL_MD_THRESH_INF;
	md.options = PTL_MD_OP_PUT | PTL_MD_EVENT_START_DISABLE;

	if (verbose)
		printf("%d:%d: %ld byte buffer @ %p\n",
		       rank, my_pid, (long)md.length, md.start);

	if (!sender)
		md.options |= PTL_MD_MANAGE_REMOTE;

	/* create an event queue.
	 */
	rc = PtlEQAlloc(ni_h, sender ? 5 : 2*msg_count,
			PTL_EQ_HANDLER_NONE, &eq_h);
	if (rc != PTL_OK) {
		fprintf(stderr, "%d:%d: PtlEQAlloc() failed: %s (%d)\n",
			rank, my_pid, PtlErrorStr(rc), rc);
		exit(EXIT_FAILURE);
	}
	md.eq_handle = eq_h;

	/* If we want to reuse our memory descriptors, we need a
	 * way to reset the library memory descriptor's local
	 * offset, which gets updated on a successful operation.
	 * If we're the initiator, we'll use PtlMDUpdate to do that, 
	 * so we'll save our values here.
	 */
	md_save = md;

	if (sender) {
		/* Bind the memory descriptor we use for sending.
		 */
		rc = PtlMDBind(ni_h, md, PTL_RETAIN, &md_h);
		if (rc != PTL_OK) {
			fprintf(stderr, "%d:%d: PtlMDBind: %s\n",
				rank, my_pid, PtlErrorStr(rc));
			exit(EXIT_FAILURE);
		}
	}
	else {
		/* Create a match entry to receive this buffer.
		 * Use the source rank as the match bits, and
		 * don't ignore any bits.
		 */
		ptl_match_bits_t mb = (ptl_match_bits_t)src;
		rc = PtlMEAttach(ni_h, ptl, src_id, mb, 0,
				 PTL_RETAIN, PTL_INS_AFTER, &me_h);
		if (rc != PTL_OK) {
			fprintf(stderr, "%d:%d: PtlMEAttach: %s\n",
				rank, my_pid, PtlErrorStr(rc));
			exit(EXIT_FAILURE);
		}
		/* Attach the memory descriptor to the match entry.
		 */
		rc = PtlMDAttach(me_h, md, PTL_RETAIN, &md_h);
		if (rc != PTL_OK) {
			fprintf(stderr, "%d:%d: PtlMDAttach: %s\n",
				rank, my_pid, PtlErrorStr(rc));
			exit(EXIT_FAILURE);
		}
	}
	/* Make sure our partner is listening.
	 */
	if (verbose)
		printf("%d:%d: Making sure partner is ready\n", rank, my_pid);
	partner_handshake(sender ? src_id : dst_id,
			  sender ? dst_id : src_id,
			  ni_h, sync_ptl, ~(ptl_match_bits_t)0, ace_any);
	if (verbose)
		printf("%d:%d: OK, partner is ready\n", rank, my_pid);
}

void do_fork(unsigned next_msg)
{
	unsigned os = next_msg * msg_sz;
	unsigned len = buf_sz - os;

	sleep(1);

	if (use_system) {
		if (system("sleep 1") == -1) {
			fprintf(stderr, "%d:%d: system() failed\n",
				rank, my_pid);
			exit(EXIT_FAILURE);
		}
		/* Trigger COW for buffer pages
		 */
		if (!sender) {
			if (verbose)
				printf("%d:%d: Trying to trigger COW after "
				       "system()\n", rank, my_pid);
			memset(buffer+os, 0, len);
			if (verbose)
				printf("%d:%d: continuing\n", rank, my_pid);
		}
		return;
	}
	child_pid = fork();
	sleep(1);

	if (child_pid < 0) {
		fprintf(stderr, "%d:%d: fork failed: %s\n", 
			rank, my_pid, strerror(errno));
		exit(EXIT_FAILURE);
	}
	my_pid = getpid();

	if (child_pid) {
		/* Trigger COW for buffer pages in parent
		 */
		if (!sender) {
			if (verbose)
				printf("%d:%d: Trying to trigger COW after "
				       "fork()\n", rank, my_pid);
			memset(buffer+os, 0, len);
		}
		if (verbose)
			printf("%d:%d: Making sure parent partner is ready\n",
			       rank, my_pid);
		partner_handshake(sender ? src_id : dst_id,
				  sender ? dst_id : src_id,
				  ni_h, sync_ptl,  ~(ptl_match_bits_t)2,
				  ace_any);
		if (verbose)
			printf("%d:%d: parent continuing\n", rank, my_pid);
		return;
	}
	deinit_child();
	startup_child();
	md_setup();
	partner_handshake(sender ? src_id : dst_id,
			  sender ? dst_id : src_id,
			  ni_h, sync_ptl,  ~(ptl_match_bits_t)2, ace_any);
	if (verbose)
		printf("%d:%d: child continuing\n", rank, my_pid);
}

void check_data(unsigned msg_cnt)
{
	unsigned i, j;

	for (i=0; !sender && i<msg_cnt; i++)
		for (j=0; j<msg_data_count; j++) {
			int k = j + i * msg_data_count;
			uint64_t want = 
				(uint64_t)j |
				(uint64_t)i << 23;
			if (parent_pid != my_pid && i < msg_count/2)
				want |= (uint64_t)(dst_id.pid - size) << 43;
			else
				want |= (uint64_t)dst_id.pid << 43;

			if (want != buffer[k])
				fprintf(stderr, "%d:%d: msg %d offset "
					FMT_SZ_T" expected %#"PRIx64
					" got %#"PRIx64"\n",
					rank, my_pid, i, j*sizeof(*buffer),
					want, buffer[k]);
		}
	if (!sender)
		printf("%d:%d: completed message integrity check\n",
		       rank, my_pid);
}

int main(int argc, char *argv[])
{
	ptl_process_id_t id;
	ptl_event_t ev;
	unsigned i, j;
	int rc;

	parent_pid = my_pid = getpid();

	mlockall(MCL_CURRENT|MCL_FUTURE);

	while (1) {
		char *next_char;
		int c = getopt(argc, argv, "ad:hm:M:sv");
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
		case 'm':
			msg_sz = strtoul(optarg, &next_char, 0);
			msg_sz *= suffix(next_char);
			break;
		case 'M':
			buf_sz = strtoul(optarg, &next_char, 0);
			buf_sz *= suffix(next_char);
			break;
		case 's':
			use_system = 1;
			break;
		case 'v':
			verbose = 1;
			break;
		}
	}
	alloc_bufs();
	startup_parent();

	if (rank == 0)
		printf("forktest: using %d %d-byte messages "
		       "into %d-byte buffer\n", msg_count, msg_sz, buf_sz);
	md_setup();

	i = 0;
	while (sender) {

		int ack, sent;
		ptl_match_bits_t mb = (ptl_match_bits_t )src;

		/* Restore local offset in bound memory descriptor.
		 */
		printf("%d:%d: Update offset\n", rank, my_pid);
		do {
			rc = PtlMDUpdate(md_h, NULL, &md_save, eq_h);
		} while (rc == PTL_MD_NO_UPDATE);

		if (rc != PTL_OK) {
			fprintf(stderr, "%d:PtlMDUpdate: %s\n",
				rank, PtlErrorStr(rc));
			exit(EXIT_FAILURE);
		}
		/* Pattern the message buffer.
		 */
		printf("%d:%d: pattern buf\n", rank, my_pid);
		for (j=0; j<msg_data_count; j++)
			msg_buf[j] = 
				(uint64_t)j |
				(uint64_t)i << 23 |
				(uint64_t)dst_id.pid << 43;

		printf("%d:%d: send buf\n", rank, my_pid);
		rc = PtlPutRegion(md_h, 0, msg_sz, PTL_ACK_REQ,
				  dst_id, ptl, ace_any, mb, i * msg_sz, 0);
		if (rc != PTL_OK) {
			fprintf(stderr, "%d:PtlPut: %s\n",
				rank, PtlErrorStr(rc));
			exit(EXIT_FAILURE);
		}
		if (verbose) 
			printf("%d:%d:   PtlPut: msg %d sent\n",
			       rank, my_pid, i);

		ack = sent = 0;
		do {
			event(eq_h, &ev, rank, ni_h);
			if (ev.type == PTL_EVENT_SEND_END)
				sent = 1;
			else if (ev.type == PTL_EVENT_ACK)
				ack = 1;
		} while (!(ack && sent));
		printf("%d:%d: send complete\n", rank, my_pid);

		if (++i == msg_count)
			break;

		if (i == msg_count/2) {

			/* Make sure our partner is ready to fork.
			 */
			if (verbose)
				printf("%d:%d: Making sure partner is "
				       "ready to fork\n", rank, my_pid);
			partner_handshake(sender ? src_id : dst_id,
					  sender ? dst_id : src_id,
					  ni_h, sync_ptl,
					  ~(ptl_match_bits_t)1, ace_any);
			if (verbose)
				printf("%d:%d: OK, partner is ready to fork\n",
				       rank, my_pid);

			do_fork(i);
			rc = PtlGetId(ni_h, &id);
			if (rc != PTL_OK) {
				fprintf(stderr, "%d:%d: PtlGetId: %s\n",
					rank, my_pid, PtlErrorStr(rc));
				exit(EXIT_FAILURE);
			}
			printf("rank %d process %d:"FMT_NIDPID"\n",
			       rank, my_pid, id.nid, id.pid);
		}
	}
	while (!sender) {
		event(eq_h, &ev, rank, ni_h);
		if (ev.type != PTL_EVENT_PUT_END)
			continue;

		printf("%d:%d: Received msg\n", rank, my_pid);

		if (++i == msg_count)
			break;

		if (i == msg_count/2) {

			/* Make sure our partner is ready to fork.
			 */
			if (verbose)
				printf("%d:%d: Making sure partner is "
				       "ready to fork\n", rank, my_pid);
			partner_handshake(sender ? src_id : dst_id,
					  sender ? dst_id : src_id,
					  ni_h, sync_ptl,
					  ~(ptl_match_bits_t)1, ace_any);
			if (verbose)
				printf("%d:%d: OK, partner is ready to fork\n",
				       rank, my_pid);
#if 1
			/* Check for correct data before fork.
			 */
			if (verbose)
				printf("%d:%d: Checking message integrity "
				       "before fork\n", rank, my_pid);
			check_data(i);
#endif
			do_fork(i);
			rc = PtlGetId(ni_h, &id);
			if (rc != PTL_OK) {
				fprintf(stderr, "%d:%d: PtlGetId: %s\n",
					rank, my_pid, PtlErrorStr(rc));
				exit(EXIT_FAILURE);
			}
			printf("rank %d process %d:"FMT_NIDPID"\n",
			       rank, my_pid, id.nid, id.pid);
		}
	}

	/* Make sure our partner is done.
	 */
	if (verbose)
		printf("%d:%d: Making sure partner is done\n", rank, my_pid);
	partner_handshake(sender ? src_id : dst_id,
			  sender ? dst_id : src_id,
			  ni_h, sync_ptl, ~(ptl_match_bits_t)2, ace_any);
	if (verbose)
		printf("%d:%d: OK, partner is done\n", rank, my_pid);

	fflush(stderr);
	fflush(stdout);

	/* See if we got the right data.
	 */
	check_data(msg_count);

	/* Give Portals a chance to catch up if needed.
	 */
	sleep(1);

	/* close down the network interface 
	 */
	PtlNIFini(ni_h);

	/* finalize library 
	 */
	PtlFini();

	free(buffer);
	free(msg_buf);
	wait(NULL);

	return 0;
}

