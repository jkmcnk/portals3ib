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

#ifndef MD_H_
#define MD_H_

#include <p3lib/types.h>

int lib_PtlMDAttach(lib_ni_t *ni, 
		ptl_handle_me_t me_handle,
		ptl_md_t input_md,
		ptl_md_iovec_t *iov,
		ptl_unlink_t unlink_op,
		ptl_handle_md_t *md_handle);

int lib_PtlMDBind(lib_ni_t *ni, 
		ptl_md_t input_md,
		ptl_md_iovec_t *iov,
		ptl_unlink_t unlink_op,
		ptl_handle_md_t *md_handle);

int lib_PtlMDUnlink(lib_ni_t *ni,
		ptl_handle_md_t md_handle);

int lib_PtlMDUpdate(lib_ni_t *ni, 
		ptl_handle_md_t md_handle,
		ptl_md_t *old_md,
		ptl_md_t *new_md,
		ptl_handle_eq_t eq_handle,
		int old_md_valid,
		int new_md_valid,
		ptl_seq_t sequence,
		ptl_md_iovec_t *req_iov,
		ptl_md_iovec_t *res_iov);

#endif /* MD_H_ */
