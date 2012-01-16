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
#include <p3/errno.h>
#include <p3/debug.h>

#include <p3lib/types.h>
#include <p3lib/p3lib.h>
#include <p3lib/nal.h>

#include <p3/obj_alloc.h>	/* MUST come after p3lib/p3lib.h */


/* Call lib_me_unlink() with ni->obj_update lock held
 */
void lib_me_unlink(lib_ni_t *ni, lib_me_t *me)
{
	lib_ptl_t *ptl = &ni->ptltab.ptl[me->ptl];

	if (me->md && me->md->me == me && TST_OBJ(me->md, OBJ_UNLINK)) {
		me->md->me = NULL;	/* avoid infinite unlink loop */
		lib_md_unlink(ni, me->md);
	}
	if (DEBUG_P3(ni->debug, PTL_DBG_UNLINK))
		p3_print("lib_me_unlink:"FMT_NIDPID": Unlinking ME %d\n",
			 ni->nid, ni->pid, PTL_OBJ_INDX(me));

	list_del(&me->list);	/* take it out of the match list */
	ptl_obj_free(me, ni);

	ptl->len--;
	if (list_empty(&ptl->mlist)) {
		/* when a given portals table entry doesn't contain any ME entries,
		 * mark it as free for the "PtlMEAttachAny" to be able to use it. */
		ptl->maxlen = 0;
		ni_stats_dec(ni, PTL_SR_PTLS_CUR, 1);
	}
}

void lib_me_unlinkall(lib_ni_t *ni)
{
	lib_me_t *me;
	lib_ptl_t *ptl;
	unsigned i;

	p3_lock(&ni->obj_update);

	for (i=0; i<ni->ptltab.size; i++) {
		ptl = &ni->ptltab.ptl[i];

		while (!list_empty(&ptl->mlist)) {
			me = container_of(ptl->mlist.next, lib_me_t, list);
			lib_me_unlink(ni, me);
		}
	}
	p3_unlock(&ni->obj_update);
}

int lib_PtlMEAttach(lib_ni_t *ni, 
		ptl_pt_index_t pt_index,
		ptl_process_id_t match_id,
		ptl_match_bits_t match_bits,
		ptl_match_bits_t ignore_bits,
		ptl_unlink_t unlink,
		ptl_ins_pos_t position,
		ptl_handle_me_t *me_handle)
{
	lib_me_t *me;
	lib_ptl_t *ptl;
	int status;

	p3_lock(&ni->obj_update);	/* prevent simultaneous attach */

	/* In general, there is no way to check if the match_id is valid,
	 * since 1) any value _might_ be a valid node id or process id,
	 * depending on the NALs involved, and 2) we cannot have complete
	 * knowledge of every nid,pid in the network without lots of extra 
	 * communications, and maybe races.  So, don't even try to check.
	 */
	if (pt_index >= ni->ptltab.size) {
		status = PTL_PT_INDEX_INVALID;
		goto out_unlock;
	}
	ptl = &ni->ptltab.ptl[pt_index];
	if (ptl->len >= (unsigned)ni->limits.max_me_list) {
		status = PTL_ME_LIST_TOO_LONG;
		goto out_unlock;
	}
	if (DEBUG_P3(ni->debug, PTL_DBG_API))
		p3_print("lib_PtlMEAttach:" FMT_NIDPID " match" 
			 FMT_NIDPIDPTL FMT_MBITS FMT_IBITS"\n",
			 ni->nid, ni->pid, 
			 match_id.nid, match_id.pid,
			 pt_index, match_bits, ignore_bits);

	me = ptl_obj_alloc(me, ni);
	if (!me) {
		status = PTL_NO_SPACE;
		goto out_unlock;
	}
	me->ptl = pt_index;
	me->match_id = match_id;
	me->mbits = match_bits;
	me->mask = ~ignore_bits;
	me->md = NULL;

	if(unlink == PTL_UNLINK)
		SET_OBJ(me, OBJ_UNLINK);

	if (list_empty(&ptl->mlist)) {
		ni_stats_inc(ni, PTL_SR_PTLS_CUR, 1);
		ni_stats_set(ni, PTL_SR_PTLS_MAX,
			     MAX(ni_stats_get(ni, PTL_SR_PTLS_CUR),
				 ni_stats_get(ni, PTL_SR_PTLS_MAX)));
	}

	if (position == PTL_INS_BEFORE)
		list_add(&me->list, &ptl->mlist);
	else
		list_add_tail(&me->list, &ptl->mlist);

	ptl->len++;
	ptl->maxlen = MAX(ptl->len, ptl->maxlen);

	*me_handle = PTL_OBJ_HNDL(me);
	status = PTL_OK;
out_unlock:
	p3_unlock(&ni->obj_update);
	
	return status;
}

int lib_PtlMEAttachAny(lib_ni_t *ni, 
		ptl_pt_index_t *pt_index,
		ptl_process_id_t match_id,
		ptl_match_bits_t match_bits,
		ptl_match_bits_t ignore_bits,
		ptl_unlink_t unlink,
		ptl_handle_me_t *me_handle)
{
	lib_me_t *me;
	lib_ptl_t *ptl;
	int pti;
	int status;

	p3_lock(&ni->obj_update);	/* prevent simultaneous attach */

	/* In general, there is no way to check if the match_id is valid,
	 * since 1) any value _might_ be a valid node id or process id,
	 * depending on the NALs involved, and 2) we cannot have complete
	 * knowledge of every nid,pid in the network without lots of extra 
	 * communications, and maybe races.  So, don't even try to check.
	 */

	/* The P3.3 API spec, section 3.9.3 says we should look for
	 * "an unused Portal table entry", and that PTL_PT_FULL is 
	 * returned if "there are no free entries in the Portal table."
	 *
	 * So this is a little ambiguous; does it mean "free at this instant"
	 * or "unused since this network interface was initialized."
	 * We're going to assume the latter was meant.
	 */
	for (pti = 0; pti<=ni->limits.max_pt_index; pti++)
		if (ni->ptltab.ptl[pti].maxlen == 0) break;

	if (pti > ni->limits.max_pt_index || pti < 0) {
		status = PTL_PT_FULL;
		goto out_unlock;
	}
	ptl = &ni->ptltab.ptl[pti];
	me = ptl_obj_alloc(me, ni);
	if (!me) {
		status = PTL_NO_SPACE;
		goto out_unlock;
	}
	if (DEBUG_P3(ni->debug, PTL_DBG_API))
		p3_print("lib_PtlMEAttachAny:" FMT_NIDPID " match" 
			 FMT_NIDPIDPTL FMT_MBITS FMT_IBITS"\n",
			 ni->nid, ni->pid, 
			 match_id.nid, match_id.pid,
			 pti, match_bits, ignore_bits);

	me->ptl = pti;
	me->match_id = match_id;
	me->mbits = match_bits;
	me->mask = ~ignore_bits;
	me->md = NULL;

	if(unlink == PTL_UNLINK)
		SET_OBJ(me, OBJ_UNLINK);

	if (list_empty(&ptl->mlist)) {
		ni_stats_inc(ni, PTL_SR_PTLS_CUR, 1);
		ni_stats_set(ni, PTL_SR_PTLS_MAX,
			     MAX(ni_stats_get(ni, PTL_SR_PTLS_CUR),
				 ni_stats_get(ni, PTL_SR_PTLS_MAX)));
	}
	list_add(&me->list, &ptl->mlist);

	ptl->len++;
	ptl->maxlen = MAX(ptl->len, ptl->maxlen);

	*pt_index = pti;
	*me_handle = PTL_OBJ_HNDL(me);
	status = PTL_OK;
out_unlock:
	p3_unlock(&ni->obj_update);
	
	return status;
}

int lib_PtlMEInsert(lib_ni_t *ni, 
		ptl_handle_me_t base,
		ptl_process_id_t match_id,
		ptl_match_bits_t match_bits,
		ptl_match_bits_t ignore_bits,
		ptl_unlink_t unlink,
		ptl_ins_pos_t position,
		ptl_handle_me_t *me_handle)
{
	lib_me_t *new, *me;
	lib_ptl_t *ptl;
	int status;

	p3_lock(&ni->obj_update);	/* prevent simultaneous insert */

	/* In general, there is no way to check if the match_id is valid,
	 * since 1) any value _might_ be a valid node id or process id,
	 * depending on the NALs involved, and 2) we cannot have complete
	 * knowledge of every nid,pid in the network without lots of extra 
	 * communications, and maybe races.  So, don't even try to check.
	 */
	if (!(VALID_PTL_OBJ(&ni->me, base) &&
	      TST_OBJ(me=GET_PTL_OBJ(&ni->me, base),OBJ_INUSE))) {
		status = PTL_ME_INVALID;
		goto out_unlock;
	}
	ptl = &ni->ptltab.ptl[me->ptl];
	if (ptl->len >= (unsigned)ni->limits.max_me_list) {
		status = PTL_ME_LIST_TOO_LONG;
		goto out_unlock;
	}
	new = ptl_obj_alloc(me, ni);
	if (!new) {
		status = PTL_NO_SPACE;
		goto out_unlock;
	}
	if (DEBUG_P3(ni->debug, PTL_DBG_API))
		p3_print("lib_PtlMEInsert:" FMT_NIDPID " match" 
			 FMT_NIDPIDPTL FMT_MBITS FMT_IBITS"\n",
			 ni->nid, ni->pid, 
			 match_id.nid, match_id.pid,
			 me->ptl, match_bits, ignore_bits);

	new->ptl = me->ptl;
	new->match_id = match_id;
	new->mbits = match_bits;
	new->mask = ~ignore_bits;
	new->md = NULL;

	if(unlink == PTL_UNLINK)
		SET_OBJ(new, OBJ_UNLINK);

	if (position == PTL_INS_BEFORE)
		list_add_tail(&new->list, &me->list);
	else
		list_add(&new->list, &me->list);

	ptl->len++;
	ptl->maxlen = MAX(ptl->len, ptl->maxlen);

	*me_handle = PTL_OBJ_HNDL(new);
	status = PTL_OK;
out_unlock:
	p3_unlock(&ni->obj_update);
	
	return status;
}

int lib_PtlMEUnlink(lib_ni_t *ni, 
		ptl_handle_me_t me_handle)
{
	lib_me_t *me;
	int status;

	p3_lock(&ni->obj_update);	/* prevent simultaneous ME unlink */

	if (!(VALID_PTL_OBJ(&ni->me, me_handle) &&
	      TST_OBJ(me=GET_PTL_OBJ(&ni->me, me_handle),OBJ_INUSE))) {
		status = PTL_ME_INVALID;
		goto out_unlock;
	}
	if (me->md && me->md->pending != 0) {
		status = PTL_ME_IN_USE;
		goto out_unlock;
	}
	lib_me_unlink(ni, me);
	status = PTL_OK;
out_unlock:
	p3_unlock(&ni->obj_update);
	
	return status;
}

static inline
void lib_me_dump(lib_me_t *me)
{
	p3_print("ME %d @ %p: next %p prev %p" FMT_MBITS FMT_IBITS 
		 " MD %d @ %p\n", PTL_OBJ_INDX(me), me, 
		 me->list.next, me->list.prev, me->mbits, ~me->mask,
		 (me->md ? PTL_OBJ_INDX(me->md) : -1U), me->md);
}

int lib_PtlTblDump(lib_ni_t *ni,  
		ptl_pt_index_t pt_index)
{
	int status;
	lib_ptl_t *ptl;
	lib_me_t *me;

	p3_lock(&ni->obj_update);	/* prevent simultaneous ME unlink */

	if (pt_index >= ni->ptltab.size) {
		status = PTL_PT_INDEX_INVALID;
		goto out_unlock;
	}
	p3_print("Portal table index "FMT_PTL_T"\n", pt_index);
	ptl = &ni->ptltab.ptl[pt_index];

	if (!list_empty(&ptl->mlist))
		list_for_each_entry(me, &ptl->mlist, list)
			lib_me_dump(me);

	status = PTL_OK;
out_unlock:
	p3_unlock(&ni->obj_update);
	
	return status;
}

int lib_PtlMEDump(lib_ni_t *ni, 
		ptl_handle_me_t me_handle)
{
	/* Incoming:
	 *	ptl_handle_me_t me
	 *
	 * Outgoing:
	 */
	lib_me_t *me;
	int status;

	p3_lock(&ni->obj_update);	/* prevent simultaneous ME unlink */

	if (!(VALID_PTL_OBJ(&ni->me, me_handle) &&
	      TST_OBJ(me=GET_PTL_OBJ(&ni->me, me_handle),OBJ_INUSE))) {
		status = PTL_ME_INVALID;
		goto out_unlock;
	}
	lib_me_dump(me);
	status = PTL_OK;
out_unlock:
	p3_unlock(&ni->obj_update);
	
	return status;
}
