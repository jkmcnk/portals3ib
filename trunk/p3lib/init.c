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

#include <p3-config.h>

#include <unistd.h>
#include <limits.h>
#include <string.h>

/* If compiling for user-space (and maybe NIC-space), these need to be
 * the Portals3 versions of the Linux kernel include files, which
 * have been suitably modified for use in user-space code.
 */
#include <linux/list.h>

/* These are all Portals3 include files.
 */
#include <p3utils.h>

#include <p3api/types.h>
#include <p3api/debug.h>

#include <p3/lock.h>
#include <p3/handle.h>
#include <p3/process.h>
#include <p3/errno.h>
#include <p3/debug.h>

#include <p3lib/types.h>
#include <p3lib/p3lib.h>
#include <p3lib/nal.h>
#include <p3lib/p3lib_support.h>
#include <p3lib/init.h>

#include <p3/obj_alloc.h>	/* MUST come after p3lib/p3lib.h */

unsigned int p3lib_debug;

P3LOCK_UNLOCKED(lib_update);

int lib_PtlInit()
{
	p3_process_t *pp;

	p3utils_init();

	if (!(pp = p3lib_new_process())) {
		return PTL_FAIL;
	}
	pp->init = 0;
	p3lib_nal_setup();
	
	return PTL_OK;
}

int lib_PtlFini()
{
	if (DEBUG_P3(p3lib_debug, PTL_DBG_SETUP))
		p3_print("lib_PtlFini\n");

	p3lib_free_process(p3lib_cur_process());
	p3lib_nal_teardown();
	return PTL_OK;
}
