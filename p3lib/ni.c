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
#include <p3api/debug.h>

#include <p3/lock.h>
#include <p3/handle.h>
#include <p3/process.h>
#include <p3/uid.h>
#include <p3/errno.h>
#include <p3/debug.h>

#include <p3lib/types.h>
#include <p3lib/p3lib.h>
#include <p3lib/nal.h>
#include <p3lib/p3lib_support.h>

#include <p3/obj_alloc.h>	/* MUST come after p3lib/p3lib.h */

/* Here we define the Portals library limits.  A NAL is free to reduce
 * these limits, but not exceed them.
 */
#define PTL_MAX_MATCH_ENTRIES 	PTL_MAX_OBJECTS
#define PTL_MAX_MEM_DESCRIPTORS	PTL_MAX_OBJECTS
#define PTL_MAX_EVENT_QUEUES	PTL_MAX_OBJECTS
#define PTL_MAX_PORTALS		8
#define PTL_MAX_AC_ENTRIES	8
#define PTL_MAX_IOVECS		16
#define PTL_MAX_ME_LISTLEN	PTL_MAX_OBJECTS
#define PTL_MAX_GETPUT_MD_LEN	PTL_GETPUT_BUFLEN

static
ptl_ni_limits_t ptl_lib_limits = 
{
	.max_mes = PTL_MAX_MATCH_ENTRIES,
	.max_mds = PTL_MAX_MEM_DESCRIPTORS,
	.max_eqs = PTL_MAX_EVENT_QUEUES,
	.max_ac_index = PTL_MAX_AC_ENTRIES-1,
	.max_pt_index = PTL_MAX_PORTALS-1,
	.max_md_iovecs = PTL_MAX_IOVECS,
	.max_me_list = PTL_MAX_ME_LISTLEN,
	.max_getput_md = PTL_MAX_GETPUT_MD_LEN
};

#define MAX_DIST ULONG_MAX

/* Helper function for lib_PtlNIInit to instantiate a new NAL.
 */
static 
int __new_nal_instance(lib_ni_t *ni,  
		ptl_interface_t iface, 
		ptl_ni_limits_t *desired,
		size_t data_sz,
		void *data,
		ptl_ni_limits_t *actual)
{
	unsigned i;
	int rc = PTL_NO_SPACE;

	if (!(ni->nal = lib_new_nal(iface, data, data_sz, ni, &ni->nid, actual, 
			&rc))) 
		return rc;

	ni->nal->ni = ni;

	PTL_ENFORCE_LIMITS(actual, &ptl_lib_limits);
	PTL_ENFORCE_LIMITS(actual, desired);
	ni->limits = *actual;

	ni->ptltab.size = ptl_lib_limits.max_pt_index + 1;
	ni->ptltab.ptl = p3_malloc(ni->ptltab.size * sizeof(lib_ptl_t));
	if (!ni->ptltab.ptl) 
		goto fail;
	memset(ni->ptltab.ptl, 0, ni->ptltab.size * sizeof(lib_ptl_t));

	ni->actab.size = ptl_lib_limits.max_ac_index + 1;
	ni->actab.ace = p3_malloc(ni->actab.size * sizeof(lib_ace_t));
	if (!ni->actab.ace) 
		goto fail;
	memset(ni->actab.ace, 0, ni->actab.size * sizeof(lib_ace_t));

	PTL_ALLOC_INIT_TBL(&ni->eq);
	PTL_ALLOC_INIT_TBL(&ni->me);
	PTL_ALLOC_INIT_TBL(&ni->md);
	PTL_ALLOC_INIT_TBL(&ni->msg);

	for (i=0; i<ni->ptltab.size; i++) {
		INIT_LIST_HEAD(&ni->ptltab.ptl[i].mlist);
		ni->ptltab.ptl[i].len = 0;
		ni->ptltab.ptl[i].maxlen = 0;
	}
	return rc = PTL_OK;
fail:
	if (ni->ptltab.ptl)
		p3_free(ni->ptltab.ptl);
	if (ni->nal) 
		lib_free_nal(ni->nal);
	return rc;
}

/* Look for an unused interface slot.  We fill the interface array
 * from the top to catch bugs that weren't found by testing with
 * just one NAL instance, where the ni index would otherwise be 0.
 *
 * Call with lib_update lock held; returns -1 if no slots free.
 */
static
int __free_interface_slot(p3_process_t *pp)
{
	int idx;
	for (idx=PTL_MAX_INTERFACES; --idx >= 0; ) {
		if (!pp->ni[idx])
			break;
	}
	return idx;
}

int lib_PtlNIInit(lib_ni_t *ni, 
		ptl_interface_t iface, 
		ptl_pid_t req_pid,
		ptl_ni_limits_t *desired,
		size_t data_sz,
		void *data,
		ptl_ni_limits_t *actual,
		ptl_handle_ni_t *ni_handle)
{
	ptl_pid_t pid = PTL_PID_ANY;
	p3_process_t *pp;
	unsigned i;
	int ni_idx;
	int status;

	status = PTL_NO_SPACE;

	if (!(ni = p3_malloc(sizeof(*ni))))
		return status;
	memset(ni, 0, sizeof(*ni));

	p3lock_init(&ni->obj_alloc);
	p3lock_init(&ni->obj_update);

	INIT_LIST_HEAD(&ni->free_eq);
	INIT_LIST_HEAD(&ni->free_me);
	INIT_LIST_HEAD(&ni->free_md);
	INIT_LIST_HEAD(&ni->free_msg);

	/* Some NALs, notably user-space NALs, need to have the PID available
	 * when an instance is created.  So, get a PID first.
	 */
	p3_lock(&lib_update);

	if (!(pp = __p3lib_cur_process())) {
		status = PTL_FAIL;
		goto fail_unlock_lib;
	}
	if ((status = lib_set_pid(iface, req_pid, &pid)) != PTL_OK) {
		if (status == PTL_NI_INVALID) {
			status = PTL_IFACE_INVALID;
		}
		goto fail_unlock_lib;
	}

	ni->owner = pp;
	ni->pid = pid;

	/* If a NAL wants its startup debuggable, it needs to be smart
	 * enough to look for the ni->debug value during its initialization.
	 */
	ni->debug = pp->debug;

	if (pp->jid == PTL_JID_ANY)
		pp->jid = ni->pid;

	p3_unlock(&lib_update);

	if ((status = __new_nal_instance(ni, iface, desired, data_sz, data, 
		actual) != PTL_OK)) {
		
		lib_release_pid(iface, pid);
		goto fail_ni;
	}
	
	p3_lock(&lib_update);
	p3_lock(&ni->obj_update);

	if ((ni_idx = __free_interface_slot(pp)) < 0) {
		p3_unlock(&ni->obj_update);
		lib_release_pid(iface, pid);
		goto fail_nal;
	}
#ifdef ENABLE_P3RT_SUPPORT
	if (pp->next_group) {
		ni->group = pp->next_group;
		pp->next_group = NULL;
	}
#endif /* ENABLE_P3RT_SUPPORT */
	/* Use the Portals process object's init value to track the number of
	 * interfaces used by the process.
	 */
	pp->ni[ni_idx] = ni;
	pp->init++;
	__p3lib_process_add_pid(ni, pid);

	p3_unlock(&lib_update);

	ni->id = PTL_MAKE_NI_HNDL(ni_idx);
	ni->uid = sysuid_2_ptluid(geteuid(), PTL_OBJ_HNDL(ni));

	/* The spec doesn't define something like PTL_PT_INDEX_NONE which
	 * could be used to deny access, nor does it say anything about an
	 * entry being invalid if PtlACEntry hasn't been called on it.  The
	 * only good choice seems to be to initialize all entries the way the
	 * spec says entry 0 on the default interface should be initialized.
	 */
	for (i=0; i<ni->actab.size; i++) {
		ni->actab.ace[i].id.nid = PTL_NID_ANY;
		ni->actab.ace[i].id.pid = PTL_PID_ANY;
		ni->actab.ace[i].uid = ni->uid;
		ni->actab.ace[i].jid = PTL_JID_ANY;
		ni->actab.ace[i].ptl = PTL_PT_INDEX_ANY;
	}

	*ni_handle = PTL_OBJ_HNDL(ni);
	status = PTL_OK;

	/* Use the ni inuse flag bit to signify that the interface is up.
	 */
	p3_lock(&ni->obj_alloc);
	SET_OBJ(ni, OBJ_INUSE);
	p3_unlock(&ni->obj_alloc);

	p3_unlock(&ni->obj_update);

	return status;

fail_nal:
	lib_free_nal(ni->nal);
fail_unlock_lib:
	p3_unlock(&lib_update);
fail_ni:
	p3_free(ni);
	return status;
}

void lib_PtlNIFini(lib_ni_t *ni)
{
	p3_process_t *pp = ni->owner;
	ptl_interface_t type = ni->nal->nal_type->type;
	unsigned i;

	if (DEBUG_P3(p3lib_debug, PTL_DBG_SHUTDOWN))
		p3_print("lib_PtlNIFini: shutting down ni %p p3_process %p\n",
			 ni, pp);

	/* Clear the inuse flag bit to signify that the interface is down.
	 * This will prevent any new commands from being dispatched via
	 * this interface.
	 */
	p3_lock(&ni->obj_alloc);
	CLR_OBJ(ni, OBJ_INUSE);
	p3_unlock(&ni->obj_alloc);

	/* We expect that when lib_stop_nal() returns, all references
	 * to library objects will have been released, but the NAL 
	 * memory validation service is still operational.
	 */
	lib_stop_nal(ni->nal);

	while (ni->me.inuse)
		lib_me_unlinkall(ni);
	while (ni->md.inuse)
		lib_md_unlinkall(ni);
	while (ni->eq.inuse)
		lib_eq_freeall(ni);

	/* We expect that when lib_free_nal() returns, all resources used
	 * by the NAL will have been released.
	 */
	lib_free_nal(ni->nal);
	ni->nal = NULL;

	p3_lock(&lib_update);

	lib_release_pid(type, ni->pid);
	__p3lib_process_rel_pid(ni);

	for (i=PTL_MAX_INTERFACES; --i;) {
		if (pp->ni[i] == ni) {
			ni->owner = NULL;
			pp->ni[i] = NULL;
#ifdef ENABLE_P3RT_SUPPORT
			if (pp->next_group)
				p3_free(pp->next_group);
#endif
			pp->init--;
			break;
		}
	}
	p3_unlock(&lib_update);

	p3_lock(&ni->obj_alloc);
	if (ni->eq.inuse || ni->me.inuse || ni->md.inuse || ni->msg.inuse) {
		p3_unlock(&ni->obj_alloc);
		p3_print("lib_PtlNIFini: inuse: me %d md %d eq %d msg %d\n",
			 ni->me.inuse, ni->md.inuse, 
			 ni->eq.inuse, ni->msg.inuse);
		PTL_ROAD();
	}
	p3_unlock(&ni->obj_alloc);

	PTL_ALLOC_FREE_TBL(msg, ni);
	PTL_ALLOC_FREE_TBL(md, ni);
	PTL_ALLOC_FREE_TBL(me, ni);
	PTL_ALLOC_FREE_TBL(eq, ni);

	p3_free(ni->ptltab.ptl);
	p3_free(ni->actab.ace);
#ifdef ENABLE_P3RT_SUPPORT
	if (ni->group)
		p3_free(ni->group);
#endif
	p3_free(ni);
}

int lib_PtlNIDebug(lib_ni_t *ni,  
		unsigned int new_mask,
		unsigned int *old_mask)
{
	p3lib_debug = new_mask;

	if (ni) {
		*old_mask = ni->debug;
		ni->debug = new_mask;
		ni->nal->set_debug_flags(ni, ni->debug);
	}
	else {
		p3_process_t *pp = p3lib_cur_process();
		*old_mask = pp->debug;
		pp->debug = new_mask;
	}
	
	return PTL_OK;
}

int lib_PtlNIStatus(lib_ni_t *ni,
		ptl_sr_index_t register_index,
		ptl_sr_value_t *status)
{
	int ptl;
	int rt;

	rt = PTL_OK;

	if (register_index >= 0 && register_index < LIB_SREG_COUNT) {
		*status = ni_stats_get(ni, register_index);
		goto out;
	}
	/* Look in include/p3api/misc.h for this implementation-defined
	 * madness on how to encode a status register index value to
	 * request a portal's current/maximum match list length.
	 */
	ptl = (~(1U << 31) & register_index) >> 16;

	if (ptl >= 0 && ptl <= ni->limits.max_pt_index) {

		switch(register_index & (((1U << 16)-1) | 1U << 31)) {

		case PTL_SR_MES_CUR | 1U << 31:
			*status = ni->ptltab.ptl[ptl].len;
			goto out;
		case PTL_SR_MES_MAX | 1U << 31:
			*status = ni->ptltab.ptl[ptl].maxlen;
			goto out;
		default:
			*status = 0;
		}
	}
	rt = PTL_SR_INDEX_INVALID;
out:
	return rt;
}

int lib_PtlNIDist(lib_ni_t *ni, 
		ptl_nid_t nid,
		unsigned long *distance)
{
	unsigned long dist;

	if (ni->nal->dist(ni, nid, &dist) != PTL_OK) {
		*distance = MAX_DIST;
		return PTL_PROCESS_INVALID;
	}
	*distance = dist;
	return PTL_OK;
}

int lib_PtlProgress(lib_ni_t *ni, ptl_time_t timeout)
{
	ni->nal->progress(ni, timeout);
	return PTL_OK;
}
