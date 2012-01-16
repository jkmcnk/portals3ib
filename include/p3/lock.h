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

#include <stdlib.h>
#include <pthread.h>

#ifndef _PTL3_P3_LOCK_H_
#define _PTL3_P3_LOCK_H_

typedef pthread_mutex_t _p3lock;

#define _P3LOCK_INIT_UNLOCKED PTHREAD_MUTEX_INITIALIZER

#define _p3lock_init(lock) pthread_mutex_init(lock, NULL)
#define _p3lock_destroy(lock) pthread_mutex_destroy(lock)

#define _p3_lock(lock) \
	do { if (pthread_mutex_lock(lock)) abort(); } while (0)

#define _p3_unlock(lock) \
	do { if (pthread_mutex_unlock(lock)) abort(); } while (0)

#if defined WITH_DEBUG_LOCKING

#define p3lock(lock)	       int lock
#define p3lock_init(lock)      do {*lock =  1;} while (0)
#define p3lock_destroy(lock)   do {*lock = -1;} while (0)
#define p3_lock(lock)          do {*lock == 1 ? *lock = 0 : abort();} while (0)
#define p3_unlock(lock)        do {*lock == 0 ? *lock = 1 : abort();} while (0)

#define extern_p3lock(lock)    extern int lock
#define P3LOCK_UNLOCKED(lock)  int lock = 1
#define STATIC_P3LOCK_UNLOCKED(lock) static int lock = 1

#elif defined WITH_NO_LOCKING

#define p3lock(lock)
#define p3lock_init(lock)      do {} while (0)
#define p3lock_destroy(lock)   do {} while (0)
#define p3_lock(lock)          do {} while (0)
#define p3_unlock(lock)        do {} while (0)

#define extern_p3lock(lock)
#define P3LOCK_UNLOCKED(lock)
#define STATIC_P3LOCK_UNLOCKED(lock)

#else

#define p3lock(lock)           _p3lock lock
#define p3lock_init(lock)      _p3lock_init(lock)
#define p3lock_destroy(lock)   _p3lock_destroy(lock)
#define p3_lock(lock)          _p3_lock(lock)
#define p3_unlock(lock)        _p3_unlock(lock)

#define extern_p3lock(lock)    extern _p3lock lock
#define P3LOCK_UNLOCKED(lock)  _p3lock lock = _P3LOCK_INIT_UNLOCKED
#define STATIC_P3LOCK_UNLOCKED(lock) static _p3lock lock = _P3LOCK_INIT_UNLOCKED

#endif

#endif /* _PTL3_P3_LOCK_H_ */
