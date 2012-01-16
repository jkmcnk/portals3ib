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

#ifndef ACL_H_
#define ACL_H_

#include <p3lib/types.h>

int lib_PtlACEntry(lib_ni_t *ni,  
		ptl_ac_index_t ac_index, 
		ptl_pt_index_t pt_index, 
		ptl_process_id_t match_id, 
		ptl_uid_t user_id,
		ptl_jid_t job_id);

#endif /* ACL_H_ */
