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


/* Call lib_md_unlink() with ni->obj_update lock held
 */
void lib_md_unlink(lib_ni_t *ni, lib_md_t *md)
{
	/* We have to drop and reacquire the ni->obj_update lock when
	 * we invalidate, since that can sleep.  Make MD inactive so
	 * no operations can try to use it while we're invalidating.
	 */
	SET_OBJ(md, MD_INACTIVE);

	if (md->me && md->me->md == md && TST_OBJ(md->me, OBJ_UNLINK)) {
		md->me->md = NULL;	/* avoid infinite unlink loop */
		lib_me_unlink(ni, md->me);
	}
	if (DEBUG_P3(ni->debug, PTL_DBG_UNLINK))
		p3_print("lib_md_unlink:"FMT_NIDPID": Unlinking MD %d\n",
			 ni->nid, ni->pid, PTL_OBJ_INDX(md));

	/* when we unlink the message descriptor, we also have to reset the
		 * pointer to it from the match list entry (ME). If we don't do that, 
		 * we won't be able to attach another message descriptor to it 
		 * (the "lib_PtlMDAttach" function will return "PTL_ME_IN_USE") */
	if (md->me != NULL) {
		md->me->md = NULL;
	}
	md->me = NULL;
	if (ni->nal) {
		p3_unlock(&ni->obj_update);
		ni->nal->vinvalidate(ni, md->iov, md->iovlen, md->addrkey);
		p3_lock(&ni->obj_update);
	}
	p3_free(md->iov);
	ptl_obj_free(md, ni);
}

void lib_md_unlinkall(lib_ni_t *ni) {
	lib_md_t *md;
	unsigned i, j;
	
	p3_lock(&ni->obj_update);

	for (i=0; i<ni->eq.next_row; i++)
		for (j=0; j<PTL_INDX_MAX_COL; j++) {

			md = &ni->md.tbl[i][j];
			if (TST_OBJ(md, OBJ_INUSE)) 
				lib_md_unlink(ni, md);
		}
	p3_unlock(&ni->obj_update);
}

/* Call lib_md_build() with ni->obj_update lock held, to prevent races
 * on the eq being deleted.
 */
static 
int lib_md_build(lib_ni_t *ni, ptl_md_t *api_md, void *addrkey,
		 ptl_md_iovec_t *api_iov, ptl_size_t api_iovlen, 
		 lib_md_t **lib_md)
{
	lib_eq_t *eq = NULL;
	lib_md_t *md;
	/*
	 * Translate the event queue handle into a event queue pointer if
	 * requested.  Do this before allocating the MD so that it does not
	 * have to report an error after allocating and do the cleanup.
	 */
	if (api_md->eq_handle != PTL_EQ_NONE) {
		if (!(VALID_PTL_OBJ(&ni->eq, api_md->eq_handle) &&
			TST_OBJ(eq=GET_PTL_OBJ(&ni->eq,
				api_md->eq_handle),OBJ_INUSE)))
			return PTL_EQ_INVALID;
	}
	if (!(md = ptl_obj_alloc(md, ni)))
		return PTL_NO_SPACE;

	if (!(md->iov = p3_malloc(api_iovlen*sizeof(*md->iov)))) {
		ptl_obj_free(md, ni);
		return (PTL_NO_SPACE);
	}
	md->generation++;
	md->me = NULL;
	md->eq = eq;
	md->user_ptr = api_md->user_ptr;
	md->addrkey = addrkey;
	md->start = api_md->start;
	md->length = api_md->length;
	md->offset = 0;
	md->max_size = api_md->max_size;
	md->threshold = api_md->threshold;
	md->pending = 0;
	md->options = api_md->options;
	md->iovlen = api_iovlen;
	md->iov_dlen = 0;
	{
		ptl_size_t i;
		for (i=0; i<api_iovlen; i++) {
			md->iov[i].iov_base = api_iov[i].iov_base;
			md->iov[i].iov_len  = api_iov[i].iov_len;
			md->iov_dlen += md->iov[i].iov_len;
		}
	}
	if (md->threshold <= 0 && md->threshold != PTL_MD_THRESH_INF) {
		SET_OBJ(md, MD_INACTIVE);
		md->threshold = 0;
	}
	*lib_md = md;

	if (DEBUG_P3(ni->debug, PTL_DBG_MD))
		p3_print("lib_md_build:"FMT_NIDPID": New MD %d\n",
			 ni->nid, ni->pid, PTL_OBJ_INDX(md));

	return PTL_OK;
}

int lib_PtlMDAttach(lib_ni_t *ni, 
		ptl_handle_me_t me_handle,
		ptl_md_t input_md,
		ptl_md_iovec_t *iov,
		ptl_unlink_t unlink_op,
		ptl_handle_md_t *md_handle)
{
	ptl_size_t iovlen;
	lib_me_t *me;
	lib_md_t *md;
	void *addrkey;
	int status = PTL_OK;

	/* Validate is allowed to sleep, depending on implementation,
	 * so do it before taking any locks.
	 */
	iovlen = input_md.options & PTL_MD_IOVEC ? input_md.length : 1;
	if (ni->nal->vvalidate(ni, iov, iovlen, &addrkey) != PTL_OK) {
		return PTL_MD_ILLEGAL;
	}

	p3_lock(&ni->obj_update);

	if (!(VALID_PTL_OBJ(&ni->me, me_handle) &&
	      TST_OBJ(me=GET_PTL_OBJ(&ni->me, me_handle),OBJ_INUSE))) {
		status = PTL_ME_INVALID;
		goto err_unlock;
	}
	if (me->md) {
		status = PTL_ME_IN_USE;
		goto err_unlock;
	}
	status = lib_md_build(ni, &input_md, addrkey, iov, iovlen, &md);
	if (status != PTL_OK)
		goto err_unlock;

	me->md = md;
	md->me = me;
	if (unlink_op == PTL_UNLINK)
		SET_OBJ(md, OBJ_UNLINK);

	*md_handle = PTL_OBJ_HNDL(md);
	p3_unlock(&ni->obj_update);
	return status;
err_unlock:
	p3_unlock(&ni->obj_update);
	ni->nal->vinvalidate(ni, iov, iovlen, addrkey);
	return status;
}

int lib_PtlMDBind(lib_ni_t *ni, 
		ptl_md_t input_md,
		ptl_md_iovec_t *iov,
		ptl_unlink_t unlink_op,
		ptl_handle_md_t *md_handle)
{
	ptl_size_t iovlen;
	lib_md_t *md;
	void *addrkey;
	int status;

	/* Validate is allowed to sleep, depending on implementation,
	 * so do it before taking any locks.
	 */
	iovlen = input_md.options & PTL_MD_IOVEC ? input_md.length : 1;
	if (ni->nal->vvalidate(ni, iov, iovlen, &addrkey) != PTL_OK) {
		return PTL_MD_ILLEGAL;
	}

	p3_lock(&ni->obj_update);

	status = lib_md_build(ni, &input_md, addrkey, iov, iovlen, &md);
	if (status != PTL_OK) {
		p3_unlock(&ni->obj_update);
		ni->nal->vinvalidate(ni, iov, iovlen, addrkey);
		return status;
	}
	md->me = NULL;
	if (unlink_op == PTL_UNLINK) 
		SET_OBJ(md, OBJ_UNLINK);

	*md_handle = PTL_OBJ_HNDL(md);
	p3_unlock(&ni->obj_update);
	
	return PTL_OK;
}

int lib_PtlMDUnlink(lib_ni_t *ni, 
		ptl_handle_md_t md_handle)
{
	lib_md_t *md;
	int status;

	p3_lock(&ni->obj_update);	/* prevent simultaneous MD unlink */

	if (!(VALID_PTL_OBJ(&ni->md, md_handle) &&
	      TST_OBJ(md=GET_PTL_OBJ(&ni->md, md_handle),OBJ_INUSE))) {
		status = PTL_MD_INVALID;
		goto out_unlock;
	}
	if (DEBUG_P3(ni->debug, PTL_DBG_MD))
		p3_print("lib_PtlMDUnlink: " FMT_NIDPID " MD %d\n",
			 ni->nid, ni->pid, PTL_OBJ_INDX(md));

	if (md->pending != 0) {
		status = PTL_MD_IN_USE;
		goto out_unlock;
	}
	lib_md_unlink(ni, md);
	status = PTL_OK;
out_unlock:
	p3_unlock(&ni->obj_update);
	
	return status;
}

/* Call with obj_update lock held.
 */
static inline
void __lib_get_old_md(lib_md_t *md,
		ptl_md_t *api_md,
		ptl_md_iovec_t *api_iov)
{
	int i = 0;

	/* If the library MD holds an iovec, but the API didn't
	 * give us an MD set up to hold an iovec, then we have no
	 * choice but to truncate the iovec returned to the API.
	 */
	if (md->options & PTL_MD_IOVEC && api_md->options & PTL_MD_IOVEC)
		i = MIN(md->iovlen, api_md->length);

	lib_md_2_api_md(md, api_md);

	while (i--) {
		api_iov[i].iov_base = md->iov[i].iov_base;
		api_iov[i].iov_len  = md->iov[i].iov_len;
	}
}

/* Call with obj_update lock held.
 */
static inline
int __lib_md_buf_moved(ptl_md_iovec_t *new_iov, ptl_size_t new_iovlen,
		       ptl_md_iovec_t *old_iov, ptl_size_t old_iovlen)
{
	ptl_size_t i;
	int moved = 1;

	if (new_iovlen != old_iovlen)
		goto out;

	for (i=0; i<new_iovlen; i++)
		if (new_iov[i].iov_base != old_iov[i].iov_base ||
		    new_iov[i].iov_len != old_iov[i].iov_len)
			goto out;

	moved = 0;
out:
	return moved;
}

/* New version that doesn't validate the new descriptor if the buffer
 * is exactly the same.
 */
int lib_PtlMDUpdate(lib_ni_t *ni, 
		ptl_handle_md_t md_handle,
		ptl_md_t *old_md,
		ptl_md_t *new_md,
		ptl_handle_eq_t eq_handle,
		int old_md_valid,
		int new_md_valid,
		ptl_seq_t sequence,
		ptl_md_iovec_t *req_iov,
		ptl_md_iovec_t *res_iov)
{
	lib_eq_t *eq = NULL;
	lib_md_t *md = NULL;

	/* The natural, efficient implementation is to decide to commit to 
	 * an update, then validate the buffer in the new MD if needed.
	 *
	 * The problem is that validate is allowed to sleep, depending on
	 * implementation, so we'd have to drop our lock, allowing the
	 * update to be non-atomic.
	 *
	 * So, if the new buffer is exactly the same as the old buffer,
	 * we can keep the old validation.  Otherwise, we always validate 
	 * the new buffer, then take the lock, and unvalidate if we can't 
	 * do the update.
	 *
	 * The tricky part is that we must hold the object lock while we
	 * check if the MD buffer has changed, and if we decide it hasn't
	 * we can't drop the lock until we've done the update, or decided
	 * not to do it.
	 *
	 * But, if we decide the MD buffer has changed, we have to drop
	 * the lock while we validate the new one.  This allows a window 
	 * for the MD with the old buffer to be unlinked, so we must look 
	 * up the MD again by handle after reacquiring the lock.
	 */
	int new_is_validated = 0, md_buf_moved = 0;
	ptl_md_iovec_t *iov = NULL;
	void *addrkey;
	ptl_size_t i, iovlen;

	ptl_md_iovec_t *iov_old = NULL;
	ptl_size_t iovlen_old = 0;
	void *addrkey_old = NULL;
	int status;

	iovlen = new_md->options & PTL_MD_IOVEC ? new_md->length : 1;
retry:
	p3_lock(&ni->obj_update);	/* prevent simultaneous MD unlink */

	if (!(VALID_PTL_OBJ(&ni->md, md_handle) &&
	      TST_OBJ(md=GET_PTL_OBJ(&ni->md, md_handle),OBJ_INUSE))) {
		status = PTL_MD_INVALID;
		goto unlock_invalidate;
	}
	if (DEBUG_P3(ni->debug, PTL_DBG_MD))
		p3_print("lib_PtlMDUpdate: " FMT_NIDPID " MD %d\n",
			 ni->nid, ni->pid, PTL_OBJ_INDX(md));

	if (new_md_valid && 
	    (md_buf_moved = __lib_md_buf_moved(md->iov, md->iovlen,
	    		req_iov, iovlen)) &&
	    !new_is_validated) {

		p3_unlock(&ni->obj_update);

		if (ni->nal->vvalidate(ni, req_iov, iovlen, &addrkey)) {
			return PTL_MD_ILLEGAL;
		}
		new_is_validated = 1;

		iov = p3_malloc(iovlen * sizeof(*iov));
		if (!iov) {
			status = PTL_NO_SPACE;
			goto invalidate;
		}
		goto retry;
	}
	if (old_md_valid) 
		__lib_get_old_md(md, old_md, res_iov);

	if (!new_md_valid) {
		status = PTL_OK;
		goto unlock_invalidate;
	}
	if (eq_handle != PTL_EQ_NONE) {
		ptl_handle_eq_t eqh = eq_handle;
		if (!(VALID_PTL_OBJ(&ni->eq, eqh) &&
		      TST_OBJ(eq=GET_PTL_OBJ(&ni->eq, eqh),OBJ_INUSE))) {
			status = PTL_EQ_INVALID;
			goto unlock_invalidate;
		}
	}
	/* FIXME: should we be allowed to update a memory descriptor that
	 * has pending operations?  The spec is silent on the issue; I
	 * say no, in the spirit of not allowing updates if there are
	 * pending events.
	 */
	if (!eq ||
	    (eq->sequence == sequence && !eq->pending && !md->pending)) {

		if (md_buf_moved) {
			iov_old = md->iov;
			iovlen_old = md->iovlen;
			addrkey_old = md->addrkey;

			md->iov_dlen = 0;
			for (i=0; i<iovlen; i++) {
				ptl_md_iovec_t *riov = &req_iov[i];
				iov[i].iov_base = riov[i].iov_base;
				iov[i].iov_len  = riov[i].iov_len;
				md->iov_dlen += iov[i].iov_len;
			}
			md->iov = iov;
			md->iovlen = iovlen;
			md->addrkey = addrkey;
		}
		md->start = new_md->start;
		md->length = new_md->length;
		md->threshold = new_md->threshold;
		md->max_size = new_md->max_size;
		md->options = new_md->options;
		md->user_ptr = new_md->user_ptr;
		md->offset = 0;
		md->eq = NULL;

		if (TST_OBJ(md, MD_INACTIVE) &&
		    (md->threshold > 0 ||
		     md->threshold == PTL_MD_THRESH_INF)) {
			CLR_OBJ(md, MD_INACTIVE);
		}
		if (new_md->eq_handle != PTL_EQ_NONE &&
		    (VALID_PTL_OBJ(&ni->eq, new_md->eq_handle) &&
		     TST_OBJ(eq=GET_PTL_OBJ(&ni->eq,
					    new_md->eq_handle),OBJ_INUSE))) {
			md->eq = eq;
		}
		p3_unlock(&ni->obj_update);

		if (md_buf_moved) {
			ni->nal->vinvalidate(ni, iov_old, iovlen_old, 
					     addrkey_old);
			p3_free(iov_old);
		}
		status = PTL_OK;
		goto out;
	}
	status = PTL_MD_NO_UPDATE;

unlock_invalidate:
	p3_unlock(&ni->obj_update);
	if (iov)
		p3_free(iov);
invalidate:
	if (new_is_validated)
		ni->nal->vinvalidate(ni, req_iov, iovlen, addrkey);
out:
	if (DEBUG_P3(ni->debug, PTL_DBG_MD)) {
		if (!md)
			p3_print("do_PtlMDUpdate: %d\n", status);
		else if (!eq)
			p3_print("do_PtlMDUpdate: %d: MD %d md pnd %d\n",
			 status, PTL_OBJ_INDX(md), md->pending);
		else
			p3_print("do_PtlMDUpdate: %d: MD %d eq seq "FMT_SEQ_T
				 " md seq "FMT_SEQ_T" eq pnd %d md pnd %d\n",
				 status, PTL_OBJ_INDX(md), eq->sequence,
				 sequence, eq->pending, md->pending);
	}
	
	return status;
}
