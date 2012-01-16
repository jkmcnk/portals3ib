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


int lib_PtlGetJid(lib_ni_t *ni, 
		ptl_jid_t *jid)
{
	*jid = ni->owner->jid;
	return PTL_OK;
}

int lib_PtlGetId(lib_ni_t *ni,
		ptl_process_id_t *id)
{
	id->nid = ni->nid;
	id->pid = ni->pid;
	return PTL_OK;
}

int lib_PtlGetUid(lib_ni_t *ni, 
		ptl_uid_t *uid)
{
	*uid = ni->uid;
	return PTL_OK;
}

static inline
int test_pid_inuse_else_set(unsigned pid_bit, unsigned long *bits)
{
	unsigned word = pid_bit / BITS_IN_LONG;
	unsigned long bit = 1UL << pid_bit % BITS_IN_LONG;

	if (bits[word] & bit)
		return 1;

	bits[word] |= bit;
	return 0;
}

static inline
ptl_pid_t acquire_wkpid(nal_type_t *nt, ptl_pid_t pid)
{
	unsigned f = 0, l;
	ptl_pid_t *wkp = nt->pids_inuse->well_known_pids;

	if (!(wkp && nt->pids_inuse->num_wkpids))
		return PTL_PID_ANY;

	l = nt->pids_inuse->num_wkpids - 1;

	while (f < l) {
		unsigned m = (f+l) >> 1;

		if (pid > wkp[m])
			f = m+1;
		else
			l = m;
	}
	if (wkp[f] != pid ||
	    test_pid_inuse_else_set(f, nt->pids_inuse->wkpid)) 
		return PTL_PID_ANY;
	else
		return pid;
}

static inline
void clear_pid_inuse(unsigned pid_bit, unsigned long *bits)
{
	unsigned word = pid_bit / BITS_IN_LONG;
	unsigned long bit = 1UL << pid_bit % BITS_IN_LONG;

	bits[word] &= ~bit;
}

/* If runtime support is enabled and we're being built as a kernel module,
 * we can't directly reference a symbol in the p3rt module, as it depends
 * on us and will get loaded after us.
 *
 * Instead, we'll export a function pointer that the p3rt module can
 * initialize when it is loaded.
 */
#if defined ENABLE_P3RT_SUPPORT
ptl_pid_t (*runtime_req_pid)(void) = p3rt_runtime_pid;
#else
ptl_pid_t (*runtime_req_pid)(void);
#endif


/* Call with lib_update lock held.
 */
int lib_set_pid(ptl_interface_t type, ptl_pid_t req_pid, ptl_pid_t *act_pid)
{
	int rc = PTL_OK;
	nal_type_t *nt = __get_nal_type(type);
	lib_pids_inuse_t *pids;

	if (nt)
		pids = nt->pids_inuse;
	else
		return PTL_NI_INVALID;

	if (req_pid == PTL_PID_ANY && runtime_req_pid)
		req_pid = runtime_req_pid();

	if (pids->num_wkpids &&
	    req_pid >= *pids->first_wkpid && req_pid <= *pids->last_wkpid) {

		if ((req_pid == acquire_wkpid(nt, req_pid)) != PTL_PID_ANY) {
			*act_pid = req_pid;
			goto out;
		}
	}
	else if (req_pid == PTL_PID_ANY &&
		 pids->epids_inuse_cnt < MAX_EPIDS_IN_USE) {

		/* avoid an infinite loop if we made a mistake about how many
		 * PIDs are inuse.
		 */
		int wrap = 0;

		while(test_pid_inuse_else_set(pids->next_epid % MAX_EPIDS_IN_USE,
					      pids->epid)) {
		again:
			if (pids->next_epid >= pids->last_epid) {
				pids->next_epid = pids->first_epid;
				if (wrap++) {
					pids->epids_inuse_cnt = MAX_EPIDS_IN_USE;
					goto fail;
				}
			}
			else {
				/* PTL_PID_ANY is not a valid ephemeral value
				 */
				if (++pids->next_epid == PTL_PID_ANY)
					goto again;
			}
		}
		*act_pid = pids->next_epid;
		pids->epids_inuse_cnt++;
		goto out;
	}
	else if(!test_pid_inuse_else_set(req_pid % MAX_EPIDS_IN_USE,
					 pids->epid)) {
		*act_pid = req_pid;
		pids->epids_inuse_cnt++;
		goto out;
	}
fail:
	rc = PTL_PID_INVALID;
out:
	__put_nal_type(nt);
	return rc;
}

/* Call with lib_update lock held.
 */
void lib_release_pid(ptl_interface_t type, ptl_pid_t pid)
{
	unsigned pid_bit = pid  % MAX_EPIDS_IN_USE;
	nal_type_t *nt = __get_nal_type(type);
	lib_pids_inuse_t *pids = nt->pids_inuse;

	if (pids->num_wkpids &&
	    pid >= *pids->first_wkpid && pid <= *pids->last_wkpid)
		clear_pid_inuse(pid_bit, pids->wkpid);
	else {
		clear_pid_inuse(pid_bit, pids->epid);
		if (pids->epids_inuse_cnt >= 1)
			pids->epids_inuse_cnt--;
	}
	__put_nal_type(nt);
}
