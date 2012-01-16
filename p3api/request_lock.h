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

#ifndef REQUEST_LOCK_H_
#define REQUEST_LOCK_H_

#ifdef PTL_PROGRESS_THREAD
#include <p3/lock.h>
#endif /* USER_PROGRESS_THREAD */

#ifdef PTL_PROGRESS_THREAD

extern_p3lock(request_lock);

static inline void request_lock_lock()
{
	p3_lock(&request_lock);
}

static inline void request_lock_unlock()
{
	p3_unlock(&request_lock);
}

#else

static inline void request_lock_lock()
{
}

static inline void request_lock_unlock()
{
}

#endif /* PTL_PROGRESS_THREAD */

#endif /* REQUEST_LOCK_H_ */
