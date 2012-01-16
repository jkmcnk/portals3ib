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

#ifndef ID_H_
#define ID_H_

#include <p3lib/types.h>

int lib_PtlGetJid(lib_ni_t *ni, 
		ptl_jid_t *jid);

int lib_PtlGetId(lib_ni_t *ni,
		ptl_process_id_t *id);

int lib_PtlGetUid(lib_ni_t *ni, 
		ptl_uid_t *uid);

#endif /* ID_H_ */
