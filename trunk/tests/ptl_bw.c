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

#include <time.h>
#include <sys/time.h>

#include <portals3.h>
#include P3_NAL
#include <p3api/debug.h>

#include "ptl_opts.h"

#define FIELD_WIDTH 20
#define FLOAT_PRECISION 2
#define MESSAGE_ALIGNMENT 64
#define MAX_REQ_NUM 1000
#define MAX_MSG_SIZE (1 << 22)
#define MYBUFSIZE (MAX_MSG_SIZE + MESSAGE_ALIGNMENT)

char s_buf_original[MYBUFSIZE];
char r_buf_original[MYBUFSIZE];

int skip = 10;
int loop = 100;
int window_size = 64;
int skip_large = 2;
int loop_large = 20;
int window_size_large = 16;
int large_message_size = 8192;

static inline double
get_usecs(void)
{
    struct timeval tv;

	gettimeofday(&tv, NULL);

    return (((double)tv.tv_sec*1e6) + (double)tv.tv_usec);
}

static inline int
process_events(ptl_handle_eq_t eq_h, int sends, int recvs,
               ptl_process_id_t *peer_id)
{
    ptl_event_t event;
    int rc;

    while(sends + recvs > 0) {
        rc = PtlEQWait(eq_h, &event);
        if(PTL_OK != rc) {
            fprintf(stderr, "Failed to wait for an event: %s (%d)\n",
                    PtlErrorStr(rc), rc);
            return rc;
        }
        switch(event.type) {
        case PTL_EVENT_SEND_END:
            /* initiator: send finished */
			if(sends > 0)
				sends--;
            break;
        case PTL_EVENT_PUT_END:
            /* target: recv finished */
			if(recvs > 0)
				recvs--;
            if(NULL != peer_id) {
                *peer_id = event.initiator;
            }
            break;
        default:
            break;
        }
    }

    return PTL_OK;
}

int main(int argc, char *argv[])
{
	int i, j;
    int size;
    char *s_buf, *r_buf;
    int align_size;
    int client = 0;

    double t_start = 0.0, t_end = 0.0, t;

    int num_if, rc;
    ptl_interface_t iface;
    ptl_pt_index_t portal_index = 4;
    ptl_match_bits_t match_bits = 5;

    ptl_process_id_t my_id;
    ptl_process_id_t peer_id, *pid_ptr;
    ptl_process_id_t any_id = {PTL_NID_ANY, PTL_PID_ANY};
    ptl_handle_ni_t ni_h;

	ptl_md_t md;
	ptl_handle_md_t r_md_h, s_md_h = PTL_INVALID_HANDLE;
    ptl_handle_eq_t eq_h;
    ptl_handle_me_t me_h;

    iface = PTL_IFACE_DEFAULT;

    if(3 == argc) {
        /* client */
        client = 1;
        peer_id.nid = strtoul(argv[1], NULL, 10);
        peer_id.pid = strtoul(argv[2], NULL, 10);
    }
    else if(1 == argc) {
        /* server */
    }

    /* Initialize the library */
    if(PtlInit(&num_if) != PTL_OK) {
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

    rc = PtlNIInit(iface, PTL_PID_ANY, NULL, NULL, &ni_h);
    if(PTL_OK != rc) {
        fprintf(stderr, "Failed to initialize NI.\n");
        return 42;
    }

    /* allow anyone to talk to us */
    rc = PtlACEntry(ni_h, 0, 
                    (ptl_process_id_t){PTL_NID_ANY, PTL_PID_ANY},
                    PTL_UID_ANY, PTL_JID_ANY, PTL_PT_INDEX_ANY);
    if(PTL_OK != rc) {
        fprintf(stderr, "PtlACEntry() failed: %s\n",
                PtlErrorStr(rc));
        return 42;
    }

    /* Get and print the ID of this process */
    if(PtlGetId(ni_h, &my_id) != PTL_OK) {
        printf("PtlGetId() failed.\n");
        abort();
    }

    printf("%s: nid = %llu, pid = %llu\n",
            argv[0],
            (unsigned long long) my_id.nid,
            (unsigned long long) my_id.pid);

    align_size = MESSAGE_ALIGNMENT;

    s_buf =
        (char *) (((unsigned long) s_buf_original + (align_size - 1)) /
                  align_size * align_size);
    r_buf =
        (char *) (((unsigned long) r_buf_original + (align_size - 1)) /
                  align_size * align_size);

	/* create an event queue for the outgoing buffer */
	rc = PtlEQAlloc(ni_h, MAX_REQ_NUM, PTL_EQ_HANDLER_NONE, &eq_h);
	if(PTL_OK != rc) {
            fprintf(stderr, "Failed to allocate an EQ: %s (%d)\n",
                    PtlErrorStr(rc), rc);
            return 42;
	}

	memset(&md, 0, sizeof(ptl_md_t));
	md.start = r_buf;
	md.length = r_buf_original + MYBUFSIZE - r_buf;
	md.threshold = PTL_MD_THRESH_INF;
	md.options = PTL_MD_OP_PUT | PTL_MD_MANAGE_REMOTE | PTL_MD_ACK_DISABLE;
	md.user_ptr = NULL;
	md.eq_handle = eq_h;

	rc = PtlMEAttach(ni_h, portal_index, any_id, match_bits, 0,
                     0, PTL_INS_AFTER, &me_h);
	if(PTL_OK != rc) {
		fprintf(stderr, "Failed to attach an ME: %s (%d)\n",
                PtlErrorStr(rc), rc);
        return 42;
	}

	rc = PtlMDAttach(me_h, md, 0, &r_md_h);
	if(PTL_OK != rc) {
		fprintf(stderr, "Failed to attach an MD: %s (%d)\n",
                PtlErrorStr(rc), rc);
        return 42;
	}

	if(!client)
		pid_ptr = &peer_id;
    for(size = 1; size <= MAX_MSG_SIZE; size = (size ? size * 2 : size + 1)) {
		/* fprintf(stdout, "Size %d\n", size); */
        /* touch the data */
        for(i = 0; i < size; i++) {
            s_buf[i] = 'a';
            r_buf[i] = 'b';
        }

        if(size > large_message_size) {
            loop = loop_large;
            skip = skip_large;
			window_size = window_size_large;
        }

		memset(&md, 0, sizeof(ptl_md_t));
		md.start = s_buf;
		md.length = size;
		md.threshold = PTL_MD_THRESH_INF;
		md.options = PTL_MD_OP_PUT | PTL_MD_ACK_DISABLE;
		md.user_ptr = NULL;
		md.eq_handle = eq_h;

		rc = PtlMDBind(ni_h, md, 0, &s_md_h);
		if(PTL_OK != rc) {
			fprintf(stderr, "Failed to bind send MD: %s (%d)\n",
					PtlErrorStr(rc), rc);
			return 42;
		}

        if(client) {
            for(i = 0; i < loop + skip; i++) {
				/* if(0 == i%1000)
				   fprintf(stdout, "%d/%d\n", i, loop + skip); */
                if(i == skip) t_start = get_usecs();

				for(j = 0; j < window_size; j++) {
					rc = PtlPutRegion(s_md_h, 0, size,
									  PTL_NO_ACK_REQ, peer_id, portal_index, 0,
									  match_bits, 0, 0);
					if(PTL_OK != rc) {
						fprintf(stderr, "Failed to put: %s (%d)\n",
								PtlErrorStr(rc), rc);
						return 42;
					}
				}
				if(PTL_OK != process_events(eq_h, window_size, 0, NULL))
					return 42;
				if(PTL_OK != process_events(eq_h, 0, 1, NULL))
                    return 42;
            }

            t_end = get_usecs();
			t = t_end - t_start;
        }
        else {
            for(i = 0; i < loop + skip; i++) {
				if(PTL_OK != process_events(eq_h, 0, 1, pid_ptr))
					return 42;
				if(PTL_OK != process_events(eq_h, 0, window_size - 1, NULL))
					return 42;
				pid_ptr = NULL;
				rc = PtlPutRegion(s_md_h, 0, 1,
								  PTL_NO_ACK_REQ, peer_id, portal_index, 0,
								  match_bits, 0, 0);
				if(PTL_OK != rc) {
					fprintf(stderr, "Failed to put: %s (%d)\n",
							PtlErrorStr(rc), rc);
					return 42;
				}
				if(PTL_OK != process_events(eq_h, 1, 0, NULL))
					return 42;
			}
        }

        if(client) {
            double tmp = size*window_size*loop;

            fprintf(stdout, "%-*d%*.*f\n", 10, size, FIELD_WIDTH,
                    FLOAT_PRECISION, tmp/t);
            fflush(stdout);
        }

		PtlMDUnlink(s_md_h);
    }

	PtlMDUnlink(r_md_h);

    /* cleanup */
    PtlNIFini(ni_h);
    PtlFini();

    return 0;
}
