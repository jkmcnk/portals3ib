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
#include <sys/time.h>
#include <pthread.h>
#include <errno.h>

/* If compiling for user-space (and maybe NIC-space), these need to be
 * the Portals3 versions of the Linux kernel include files, which
 * have been suitably modified for use in user-space code.
 */
#include <linux/list.h>

/* These are all Portals3 include files.
 */
#include <p3-config.h>
#include <p3utils.h>

#include <p3/lock.h>

#include <p3api/types.h>
#include <p3api/nal.h>
#include <p3api/api.h>
#include <p3api/misc.h>
#include <p3api/debug.h>

#include <p3/handle.h>
#include <p3/process.h>
#include <p3/obj_alloc.h>
#include <p3/errno.h>
#include <p3/debug.h>

#include <p3lib/eq.h>
#include <p3lib/p3lib_support.h>

#include "init.h"
#include "request_lock.h"

static inline
int lib_eq_free(ptl_handle_eq_t eq_handle)
{
	int status;
	lib_ni_t *ni;
	
	status = p3_has_process_and_ni(eq_handle, &ni);
	if (status != PTL_OK) {
		return status;
	}
	
	return lib_PtlEQFree(ni, eq_handle);
}

int PtlEQAlloc(ptl_handle_ni_t ni_handle,
	       ptl_size_t count,
	       ptl_eq_handler_t eq_handler,
	       ptl_handle_eq_t *eq_handle)
{		
	ptl_event_t *ev;
	api_eq_t *eq;
	api_ni_t *ni;
	lib_ni_t *lib_ni;
	ptl_seq_t i;
	ptl_seq_t event_cnt = count;
	int rc, bytes;
	ptl_seq_t sequence;

	if (!eq_handle) {
		rc = PTL_SEGV;
		goto out;
	}
	if (p3_api_process.init < 0) {
		rc = PTL_NO_INIT;
		goto out;
	}
	/* OK, anybody who needs more than 2^32 events is in serious
	 * trouble anyway....
	 */
	if (count != event_cnt) {
		rc = PTL_NO_SPACE;
		goto out;
	}
	if (!event_cnt) {
		*eq_handle = PTL_EQ_NONE;
		rc = PTL_OK;
		goto out;
	}
	if (!(PTL_NI_INDEX(ni_handle) < PTL_MAX_INTERFACES &&
	      (ni = p3_api_process.ni[PTL_NI_INDEX(ni_handle)]))) {

		rc = PTL_NI_INVALID;
		goto out;
	}
	/* For sequence number wrapping to work correctly, we must
	 * have the event queue hold a power-of-two number of events.
	 */
	event_cnt = 2;
	count -= 1;
	while (count>>=1)
		event_cnt <<= 1;

	bytes = event_cnt * sizeof(ptl_event_t);
	if (!(ev = p3_malloc(bytes))) {
		rc = PTL_NO_SPACE;
		goto out;
	}	
	
	request_lock_lock();
	rc = p3_has_process_and_ni(ni_handle, &lib_ni);
	if (rc != PTL_OK) {
		request_lock_unlock();
		goto fail;
	}
	
	rc = lib_PtlEQAlloc(lib_ni, event_cnt, ev, &sequence, eq_handle);

	if (rc != PTL_OK) {
		request_lock_unlock();
		goto fail;
	}

	/* We can't allocate our api-side eq until the library assigns an
	 * index.  The good news is that the library should assign an index
	 * that we also have available, so this test should never fail.  If
	 * it does something is badly borken.
	 */
	eq = ptl_specific_obj_alloc(eq, *eq_handle, ni);
	if (!eq) {
		lib_eq_free(*eq_handle);
		rc = PTL_NO_SPACE;
		request_lock_unlock();
		goto fail;
	}
	request_lock_unlock();
	eq->sequence = sequence;
	eq->entries = event_cnt;
	eq->base = ev;
	eq->eq_handler = eq_handler;

	/* We need to be a little careful about how initialization interacts
	 * with sequence number wrapping here.
	 */
	for (i=0; i<event_cnt; i++)
		ev[i].sequence = eq->sequence - eq->entries + i;

out:
	return rc;
fail:
	p3_free(ev);
	goto out;
}

int PtlEQFree(ptl_handle_eq_t eq_handle)
{
	api_ni_t *ni;
	api_eq_t *eq;
	int rc;

	if (p3_api_process.init < 0)
		return PTL_NO_INIT;

	if (!(PTL_NI_INDEX(eq_handle) < PTL_MAX_INTERFACES &&
	      (ni = p3_api_process.ni[PTL_NI_INDEX(eq_handle)])))
		return PTL_EQ_INVALID;

	if (!(VALID_PTL_OBJ(&ni->eq, eq_handle) &&
		TST_OBJ(eq=GET_PTL_OBJ(&ni->eq,eq_handle), OBJ_INUSE)))
			return PTL_EQ_INVALID;

	request_lock_lock();
	rc = lib_eq_free(eq_handle);
	if (rc == PTL_OK) {
		p3_free(eq->base);
		ptl_obj_free(eq, ni);
	}
	request_lock_unlock();
	return rc;
}

int PtlEQGet(ptl_handle_eq_t eq_handle,	ptl_event_t *event)
{
	int eq_idx = 1;

	return PtlEQPoll(&eq_handle, eq_idx, 0, event, &eq_idx);
}

int PtlEQWait(ptl_handle_eq_t eq_handle, ptl_event_t *event)
{
	int eq_idx = 1;

	return PtlEQPoll(&eq_handle, eq_idx,
			 PTL_TIME_FOREVER, event, &eq_idx);
}

static inline
int __ptl_eq_get(api_eq_t *eq, ptl_event_t *ev)
{
	ptl_seq_t last_seq, new_seq;
	ptl_event_t *new_event;
	int rc;

#ifdef PTL_PROGRESS_THREAD
	pthread_mutex_lock(&lib_event_mutex);
#endif /* PTL_PROGRESS_THREAD */

again:
	new_event = &eq->base[eq->sequence % eq->entries];
	new_seq = new_event->sequence;

	/* OK, I've seen something with the kernel-space library on SMP
	 * Opterons that I can't explain, and I'm sorry I don't know the
	 * proper way to fix it.
	 *
	 * What I've seen is that occasionally, a read of new_event->sequence
	 * will have bit 8 (low order bit in second byte) cleared.  A short
	 * time (a few instructions' worth) later it will have the proper
	 * value.  This seems like a race between the kernel writing the 
	 * sequence number and user space reading it.  I don't understand
	 * how this could happen, but the following detects and corrects for
	 * this case based on consistency checks sequence numbers must pass.
	 */
	last_seq = eq->base[(eq->sequence - 1) % eq->entries].sequence;

	if (last_seq + 1 == eq->sequence) {
		if (new_seq + eq->entries == eq->sequence) {
			rc =  PTL_EQ_EMPTY;
			goto out;
		}
		if (new_seq == eq->sequence) {
			rc = PTL_OK;
			goto out_event;
		}
	}
	/* If the event queue has over-run, these are the only valid
	 * relationships between sequence numbers.  If we don't see one of
	 * these we've hit the race between writing and reading the sequence
	 * number.
	 */
	if (last_seq + 1 == new_seq ||
	    last_seq + 1 == new_seq + eq->entries) {
		rc = PTL_EQ_DROPPED;
		goto out_event;
	}
#if 0
	p3_print("\n__ptl_eq_get: invalid seq number: eq "FMT_HDL_T
		 " ev seq "FMT_SEQ_T" eq seq "FMT_SEQ_T" - retrying\n",
		 PTL_OBJ_HNDL(eq), new_seq, eq->sequence);
#endif
	goto again;
	
out_event:
	*ev = *new_event;
	eq->sequence = new_seq + 1;
#ifdef PTL_PROGRESS_THREAD
	lib_event_counter--;
#endif /* PTL_PROGRESS_THREAD */
out:
#ifdef PTL_PROGRESS_THREAD
	pthread_mutex_unlock(&lib_event_mutex);
#endif /* PTL_PROGRESS_THREAD */
	return rc;
}

static inline int
__ptl_eq_get_any(
				 ptl_handle_eq_t *eq_handles, 
				 int size,
				 ptl_event_t *event, 
				 int *which_eq,
				 api_eq_t **eq)
{
    int i; 
    int rc = PTL_EQ_EMPTY; 
    
    /* Check for an event on any one of the event queues */
    for (i = 0; i < size; i++) {
        api_ni_t *ni;
        ptl_handle_eq_t eq_h = eq_handles[i];

        if (!(PTL_NI_INDEX(eq_h) < PTL_MAX_INTERFACES &&
                (ni = p3_api_process.ni[PTL_NI_INDEX(eq_h)]) &&
                VALID_PTL_OBJ(&ni->eq, eq_h) &&
                TST_OBJ((*eq) = GET_PTL_OBJ(&ni->eq,eq_h),OBJ_INUSE))) {

            rc = PTL_EQ_INVALID;
            *which_eq = i;
            return rc;
        }
        if ((rc = __ptl_eq_get(*eq,event)) != PTL_EQ_EMPTY) {
            *which_eq = i;
            return rc;
        }
    }

    return rc; 
}

int PtlEQPoll(ptl_handle_eq_t *eq_handles, int size,
	      ptl_time_t timeout, ptl_event_t *event, int *which_eq)
{
	struct timeval tv0 = { 0, 0 };
	int done = 0;
	api_eq_t *eq = NULL;
	int i, rc;
	unsigned ni_idx;
#ifdef PTL_PROGRESS_THREAD
	int waitret;
	struct timespec ts;
#else
	struct timeval tv1 = { 0, 0 };
	ptl_time_t et;
#endif /* PTL_PROGRESS_THREAD */

	if (!(event && which_eq && eq_handles)) {
		rc = PTL_SEGV;
		goto out;
	}
	if (p3_api_process.init < 0) {
		rc = PTL_NO_INIT;
		goto out;
	}
	if (size <= 0) {
		rc = PTL_EQ_INVALID;
		goto out;
	}

	/* this loop seems to negate the above comment, and enforces the
	   specification requirements that all EQ handles must reference
	   the same NI */
	ni_idx = PTL_NI_INDEX(eq_handles[0]);
	for (i = 1; i < size; i++) {
		if (ni_idx != PTL_NI_INDEX(eq_handles[i])) {
			rc = PTL_EQ_INVALID;
			goto out;
		}
	}

	if(timeout > 0 && timeout != PTL_TIME_FOREVER)
		gettimeofday(&tv0, NULL);
#ifdef PTL_PROGRESS_THREAD
	else if(timeout == 0)
		done = 1;
#endif /* PTL_PROGRESS_THREAD */

again:
	/* NOTE: eq_get_any is called without *any* mutex locked; thus, we can
	   race with other polling threads (also woken up by broadcasting the
	   lib_event_cond) and with the lib posting new events; however:
	   - as a single EQ should only get polled by a single thread, racing
	   with another polling thread will in the worst case result in a fruitless
	   checking of the EQs, and
	   - re-locking later on will prevent access to a semi-posted event if
	   racing with lib posting an event.
	*/
	rc = __ptl_eq_get_any(eq_handles, size, event, which_eq, &eq);
    
	switch (rc) {
		/* nothing found... continue */
	case PTL_EQ_EMPTY:
		if(done)
			goto out;

#ifdef PTL_PROGRESS_THREAD
		if(timeout == PTL_TIME_FOREVER) {
			pthread_mutex_lock(&lib_event_mutex);
			if(lib_event_counter == 0)
				pthread_cond_wait(&lib_event_cond, &lib_event_mutex);
			pthread_mutex_unlock(&lib_event_mutex);			   
		}
		else /* timeout > 0 (== 0 case jumped to label out already) */ {
			waitret = 0;
			ts.tv_sec = tv0.tv_sec + timeout/1000;
			ts.tv_nsec = tv0.tv_usec*1000 + (timeout%1000)*1000*1000;
			pthread_mutex_lock(&lib_event_mutex);
			while(lib_event_counter == 0 && waitret != ETIMEDOUT)
				waitret = pthread_cond_timedwait(&lib_event_cond,
												 &lib_event_mutex,
												 &ts);
			if(ETIMEDOUT == waitret)
				done = 1;
			pthread_mutex_unlock(&lib_event_mutex);
		}
		/* NOTE that we race with other event polling threads as we retry
		   __ptl_eq_get_any, but we don't really care.
		   the latency implications of keeping the lib_event_mutex locked
		   throughout checking all the event queues polled are just
		   unacceptable, and polling the same EQ from multiple threads is
		   *wrong* anyway. all we sacrifice in this way is a few unneeded
		   loops over the event queues polled ... */
#else
		PtlProgress(eq_handles[0], timeout);

		if(timeout == 0)
			done = 1;
		else if(timeout != PTL_TIME_FOREVER) {
			gettimeofday(&tv1, NULL);
			et = (tv1.tv_sec - tv0.tv_sec)*1000 +
				(tv1.tv_usec - tv0.tv_usec)/1000;
			if(et > timeout)
				done = 1;
			else {
				timeout -= et;
				tv0 = tv1;
			}
		}
#endif /* PTL_PROGRESS_THREAD */
		goto again;
		
	case PTL_EQ_INVALID:
	        goto out;
	        
		/* everything else needs to go to the handler */
	default:
	        goto handler;
	}	    

handler:
	/* If the library and API are in the same memory domain, we can
	 * take advantage of the opportunity to run the event handler
	 * early, when the event is deposited in the queue. 
	 * Otherwise, we run it now.
	 */
#ifndef PTL_RUN_EQ_HANDLER_EARLY
	if (eq->eq_handler != PTL_EQ_HANDLER_NONE)
		eq->eq_handler(event);
#endif

out:
	return rc;
}
