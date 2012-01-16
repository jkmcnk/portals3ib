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

/* If compiling for user-space (and maybe NIC-space), these need to be
 * the Portals3 versions of the Linux kernel include files, which
 * have been suitably modified for use in user-space code.
 */
#include <linux/list.h>

/* These are all Portals3 include files.
 */
#include <p3utils.h>

#include <p3api/types.h>

#include <p3/lock.h>
#include <p3/handle.h>
#include <p3/process.h>
#include <p3/errno.h>
#include <p3/debug.h>

#include <p3lib/types.h>
#include <p3lib/p3lib.h>
#include <p3lib/nal.h>


#include <p3/obj_alloc.h>	/* MUST come after p3lib/p3lib.h */

void lib_eq_freeall(lib_ni_t *ni) {
	lib_eq_t *eq;
	unsigned i, j;
	
	p3_lock(&ni->obj_update);

	for (i=0; i<ni->eq.next_row; i++)
		for (j=0; j<PTL_INDX_MAX_COL; j++) {

			eq = &ni->eq.tbl[i][j];
			if (!TST_OBJ(eq, OBJ_INUSE))
				continue;

			if (ni->nal) {
#ifdef OBSOLETE
				void *ak = eq->addrkey;
				eq->addrkey = NULL;
#endif
				p3_unlock(&ni->obj_update);
#ifdef OBSOLETE
				ni->nal->invalidate(ni, eq->base,
						    eq->nbytes, ak);
#endif 
				p3_lock(&ni->obj_update);
			}
			ptl_obj_free(eq, ni);
		}
	p3_unlock(&ni->obj_update);
}

int lib_PtlEQAlloc(lib_ni_t *ni,  
		ptl_size_t count,
		void *base,
		ptl_seq_t *sequence,
		ptl_handle_eq_t *eq_handle)
{
	lib_eq_t *eq;
#ifdef OBSOLETE
	void *addrkey;
#endif
	int nbytes = count * sizeof(ptl_event_t);

	if (!(eq = ptl_obj_alloc(eq, ni))) {
		return PTL_NO_SPACE;
	}
#ifdef OBSOLETE
	/* We can't use PTL_SEGV, since the memory that we're validating
	 * wasn't allocated by the user, it was allocated on his/her behalf
	 * by the api.
	 */
	if (ni->nal->validate(ni, base, nbytes, &addrkey)) {
		ptl_obj_free(eq, ni);
		return PTL_NO_SPACE;
	}
#endif
	/* We want sequence numbers to wrap immediately, because we don't
	 * want bugs which only show up on long running jobs.
	 *
	 * For sequence number wrapping to work correctly, we must
	 * have the event queue hold a power-of-two number of events.
	 */
	eq->sequence = -count;
#ifdef OBSOLETE
	eq->addrkey = addrkey;
#endif
	eq->base = base;
	eq->entries = count;
	eq->nbytes = nbytes;
	eq->pending = 0;

	*sequence = eq->sequence;
	*eq_handle = PTL_OBJ_HNDL(eq);
	
	return PTL_OK;
}

int lib_PtlEQFree(lib_ni_t *ni,
		ptl_handle_eq_t eq_handle)
{
	lib_eq_t *eq;
	
	p3_lock(&ni->obj_update);

	if (!(VALID_PTL_OBJ(&ni->eq, eq_handle) &&
	      TST_OBJ(eq=GET_PTL_OBJ(&ni->eq, eq_handle),OBJ_INUSE))) {
		p3_unlock(&ni->obj_update);
		return PTL_EQ_INVALID;
	}
#if TO_BE_REMOVED
	ni->nal->invalidate(ni, eq->base, eq->nbytes, eq->addrkey);
#endif
	ptl_obj_free(eq, ni);

	p3_unlock(&ni->obj_update);

	return PTL_OK;
}

#ifdef PTL_PROGRESS_THREAD

pthread_cond_t  lib_event_cond    = PTHREAD_COND_INITIALIZER;
pthread_mutex_t lib_event_mutex   = PTHREAD_MUTEX_INITIALIZER;
unsigned long   lib_event_counter = 0;

#endif /* PTL_PROGRESS_THREAD */

