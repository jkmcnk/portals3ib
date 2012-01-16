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
/*
 *  Generic cache management functions. Everything is arch-specific,  
 *  but this header exists to make sure the defines/functions can be
 *  used in a generic way.
 *
 *  2000-11-13  Arjan van de Ven   <arjan@fenrus.demon.nl>
 *
 */

#ifndef _PTL3_LINUX_PREFETCH_H
#define _PTL3_LINUX_PREFETCH_H

/*
	prefetch(x) attempts to pre-emptively get the memory pointed to
	by address "x" into the CPU L1 cache. 
	prefetch(x) should not cause any kind of exception, prefetch(0) is
	specifically ok.

	prefetch() should be defined by the architecture, if not, the 
	#define below provides a no-op define.	
	
	There are 3 prefetch() macros:
	
	prefetch(x)  	- prefetches the cacheline at "x" for read
	prefetchw(x)	- prefetches the cacheline at "x" for write
	spin_lock_prefetch(x) - prefectches the spinlock *x for taking
	
	there is also PREFETCH_STRIDE which is the architecure-prefered 
	"lookahead" size for prefetching streamed operations.
	
*/

/*
 *	These cannot be do{}while(0) macros. See the mental gymnastics in
 *	the loop macro.
 */
 
#ifndef ARCH_HAS_PREFETCH
static inline void prefetch(const void *x) {;}
#endif

#ifndef ARCH_HAS_PREFETCHW
static inline void prefetchw(const void *x) {;}
#endif

#ifndef ARCH_HAS_SPINLOCK_PREFETCH
#define spin_lock_prefetch(x) prefetchw(x)
#endif

#ifndef PREFETCH_STRIDE
#define PREFETCH_STRIDE (4*L1_CACHE_BYTES)
#endif

static inline void prefetch_range(void *addr, size_t len)
{
#ifdef ARCH_HAS_PREFETCH
	char *cp;
	char *end = addr + len;

	for (cp = addr; cp < end; cp += PREFETCH_STRIDE)
		prefetch(cp);
#endif
}

#endif
