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

#include <stdio.h>
#include <stdlib.h>

#include <portals3.h>
#include <p3nal_utcp.h>

const char usage[] ="usage: utcp_nid <iface>\n";

int main(int argc, char *argv[])
{
	char buf[64] = {0,};
	char *errstr = NULL;
	ptl_handle_ni_t ni;
	ptl_process_id_t id;
	int rc, i;

	if (argc != 2) {
		fprintf(stderr, usage);
		exit(1);
	}
	snprintf(buf, 63, "PTL_IFACE=%s", argv[1]);
	putenv(buf);
	if ((rc = PtlInit(&i)) != PTL_OK) {
		errstr = "PtlInit";
		goto err;
	}
	if ((rc = PtlNIInit(PTL_IFACE_DEFAULT,
			    PTL_PID_ANY, NULL, NULL, &ni)) != PTL_OK) {
		errstr = "PtlNIInit";
		goto err;
	}
	if ((rc = PtlGetId(ni, &id)) != PTL_OK) {
		errstr = "PtlGetId";
		goto err;
	}
	printf("%u\n", (unsigned)id.nid);
	exit(EXIT_SUCCESS);

err:
	printf("%s failed: %s\n", errstr, PtlErrorStr(rc));
	exit(EXIT_FAILURE);
}
