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

/* This program tests PtlPut to self.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <portals3.h>
#include P3_NAL
#include <p3rt/p3rt.h>
#include <p3api/debug.h>

static 
const char usage[] = "\n\
\n\
	Uses PtlPut to test sends to self.\n\
\n\
	-d dbg	Sets the debug mask to <dbg>, which will cause the \n\
		  Portals library and the NAL to emit various debugging \n\
		  output, assuming both were configured with debugging \n\
		  enabled.  See p3api/debug.h for appropriate values.  \n\
		  See also NAL documentation or implementation for \n\
		  appropriate NAL-specific values. \n\
	-h	Prints this message. \n\
";

static int data[1024];

int main(int argc, char *argv[])
{
	unsigned rank, size;
	int max_ifaces, rc;

	ptl_handle_ni_t ni_handle;
	ptl_process_id_t my_id;
	ptl_handle_eq_t eq_handle;
	ptl_handle_me_t me_handle;
	ptl_handle_md_t md_handle;
	ptl_pt_index_t pt_index = 4;
	ptl_event_t event;
	ptl_md_t md;
	unsigned dbg = 0;

	while (1) {
		int c = getopt(argc, argv, "d:h");
		if (c == -1) break;

		switch (c) {
		case 'd':
			dbg = strtoul(optarg, NULL, 0);
			break;
		case 'h':
			printf("%s", usage);
			exit(EXIT_SUCCESS);
		}
	}
	/* Initialize library 
	 */
	if ((rc = PtlInit(&max_ifaces)) != PTL_OK) {
		fprintf(stderr, "PtlNIInit(): %s\n", PtlErrorStr(rc));
		exit(EXIT_FAILURE);
	}
	/* Cause the runtime to initialize from environment variables.
	 * We should only do this if we don't have a job-launching service.
	 */
	if ((rc = PtlSetRank(PTL_INVALID_HANDLE, -1, -1)) != PTL_OK) {
		fprintf(stderr, "PtlSetRank(): %s\n", PtlErrorStr(rc));
		exit(EXIT_FAILURE);
	}
	/* Turn on debugging now so we can see NAL startup debug stuff.
	 */
	if (dbg)
		PtlNIDebug(PTL_INVALID_HANDLE, dbg);

	if ((rc = PtlNIInit(PTL_IFACE_DEFAULT, PTL_PID_ANY,
			    NULL, NULL, &ni_handle)) != PTL_OK) {
		fprintf(stderr, "PtlNIInit(): %s\n", PtlErrorStr(rc));
		exit(EXIT_FAILURE);
	}
	if ((rc = PtlGetRank(ni_handle, &rank, &size)) != PTL_OK) {
		fprintf(stderr, "PtlGetRank(): %s\n", PtlErrorStr(rc));
		exit(EXIT_FAILURE);
	}
	if ((rc = PtlGetId(ni_handle, &my_id)) != PTL_OK) {
		fprintf(stderr, "PtlGetId(): %s\n", PtlErrorStr(rc));
		exit(EXIT_FAILURE);
	}
	/* create event queue, match entry, memory descriptor
	 */
	if ((rc = PtlEQAlloc(ni_handle, 8, NULL, &eq_handle)) != PTL_OK) {
		fprintf(stderr,"PtlEQAlloc(): %s\n", PtlErrorStr(rc));
		exit(EXIT_FAILURE);
	}
	
	if ((rc = PtlMEAttach(ni_handle, pt_index, my_id, 0, 0, PTL_RETAIN, 
			      PTL_INS_BEFORE, &me_handle)) != PTL_OK) {
		fprintf(stderr,"1: PtlMEAttach(): %s\n", PtlErrorStr(rc));
		exit(EXIT_FAILURE);
	}

	md.start     = data;
	md.length    = sizeof(data);
	md.threshold = PTL_MD_THRESH_INF;
	md.max_size  = md.length;
	md.options   = PTL_MD_OP_PUT;
	md.user_ptr  = NULL;
	md.eq_handle = eq_handle;

	if ((rc = PtlMDAttach(me_handle, md,
			      PTL_RETAIN, &md_handle)) != PTL_OK) {
		fprintf(stderr,"1: PtlMDAttach(): %s\n",PtlErrorStr(rc));
		exit(EXIT_FAILURE);
	}
	if ((rc = PtlPut(md_handle, PTL_NO_ACK_REQ, my_id,
			 pt_index, 0, 0, 0, 0)) != PTL_OK) {
		fprintf(stderr,"PtlPut(): %s\n", PtlErrorStr(rc));
		exit(EXIT_FAILURE);
	}
	if ((rc = PtlEQWait(eq_handle, &event)) != PTL_OK) {
		fprintf(stderr,"PtlEQWait(): %s\n", PtlErrorStr(rc));
		exit(EXIT_FAILURE);
	}
	if ((rc = PtlEQWait(eq_handle, &event)) != PTL_OK) {
		fprintf(stderr,"PtlEQWait(): %s\n", PtlErrorStr(rc));
		exit(EXIT_FAILURE);
	}
	if ((rc = PtlEQWait(eq_handle, &event)) != PTL_OK) {
		fprintf(stderr,"PtlEQWait(): %s\n", PtlErrorStr(rc));
		exit(EXIT_FAILURE);
	}
	if ((rc = PtlEQWait(eq_handle, &event)) != PTL_OK) {
		fprintf(stderr,"PtlEQWait(): %s\n", PtlErrorStr(rc));
		exit(EXIT_FAILURE);
	}
	if ((rc = PtlMDUnlink(md_handle)) != PTL_OK) {
		fprintf(stderr,"PtlMDUnlink(): %s\n", PtlErrorStr(rc));
		exit(EXIT_FAILURE);
	}
	if ((rc = PtlMEUnlink(me_handle)) != PTL_OK) {
		fprintf(stderr,"PtlMEUnlink(): %s\n", PtlErrorStr(rc));
		exit(EXIT_FAILURE);
	}
	printf("Success!\n");
	exit(EXIT_SUCCESS);
}

