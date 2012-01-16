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

#ifndef EQ_H_
#define EQ_H_

#include <p3lib/types.h>

int lib_PtlEQAlloc(lib_ni_t *ni,  
		ptl_size_t count,
		void *base,
		ptl_seq_t *sequence,
		ptl_handle_eq_t *eq_handle);

int lib_PtlEQFree(lib_ni_t *ni,
		ptl_handle_eq_t eq_handle);

#ifdef PTL_PROGRESS_THREAD

#include <pthread.h>

extern pthread_cond_t  lib_event_cond;
extern pthread_mutex_t lib_event_mutex;
extern unsigned long   lib_event_counter;

#endif /* PTL_PROGRESS_THREAD */

#endif /* EQ_H_ */
