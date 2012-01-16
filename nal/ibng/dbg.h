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

#ifndef __IBNG_DBG_H__
#define __IBNG_DBG_H__

#include <p3utils.h>
#include <p3api/types.h>
#include <p3api/debug.h>
#include <p3/debug.h>

/* We use the construct DEBUG_NI(ni, mask) so that debugging generates no
 * code unless debugging is enabled, by always enclosing debugging in an
 * if-block, like this:
 *
 * if (DEBUG_NI(ni, mask_value)) {
 *	 // debugging code
 * }
 *
 * We rely for this on a compiler optimizing away the block of an if-statement
 * that is constant and false at compile-time.
 *
 * Generally, use debugging flags as follows:
 *
 * PTL_DBG_NI_00
 *   Error conditions that should only be reported when debugging is
 *   enabled.
 * PTL_DBG_NI_01
 *   Simplified info regarding connection setup/teardown
 * PTL_DBG_NI_02
 *   Detailed info regarding connection setup/teardown
 * PTL_DBG_NI_03
 *   Very detailed info regarding connection setup/teardown
 * PTL_DBG_NI_04
 *   Simplified info regarding NAL operations
 * PTL_DBG_NI_05
 *   Detailed info regarding NAL operations
 * PTL_DBG_NI_06
 *   Very detailed info regarding NAL operations
 * PTL_DBG_NI_07
 *   _Very_ detailed info regarding NAL operations
 * PTL_DBG_NI_08
 *   Impossibly detailed info regarding NAL operations
 */
#ifdef DEBUG_PTL_INTERNALS

extern unsigned int ibng_debug_level;

#	if 0
		/* Each level includes those preceeding it. */
#		define IBNG_DEBUG_NI(dbg) \
			(((ibng_debug_level & PTL_DBG_NI_ALL) | PTL_DBG_NI_00) >= (dbg))
#	else
		/* Each level is independent. */
#		define IBNG_DEBUG_NI(dbg) \
			(((PTL_DBG_NI_ALL & ibng_debug_level) && \
			(PTL_DBG_NI_00 & (dbg))) || \
			((PTL_DBG_NI_ALL & (dbg) & ibng_debug_level) && \
			!(PTL_DBG_NI_00 & (dbg))))
#	endif

#define IBNG_DBG(msg ...)				\
	do {						\
		if(IBNG_DEBUG_NI(PTL_DBG_NI_05))	\
			p3_print(msg);			\
	} while(0)

#define IBNG_DBG_A(msg ...)				\
	do {								\
		p3_print(msg);					\
	} while(0)

#define IBNG_ERROR(msg ...)				\
	do {						\
		if(IBNG_DEBUG_NI(PTL_DBG_NI_00))	\
			p3_print("ERROR: " msg);			\
	} while(0)

#define IBNG_ASSERT(cond)						\
	do {								\
		if(!(cond)) {						\
			IBNG_DBG("Assertion " # cond " failed.\n");	\
			abort();					\
		}							\
	} while(0)

#else /* DEBUG_PTL_INTERNALS */

#define IBNG_DEBUG_NI(dbg)  0

#define IBNG_DBG(msg ...) do {} while(0)
#define IBNG_DBG_A(msg ...) do {} while(0)
#define IBNG_ERROR(msg ...) do {} while(0)
#define IBNG_ASSERT(cond) do {} while(0)

#endif /* DEBUG_PTL_INTERNALS */

#define IBNG_DBG_FUNC_ENTRY IBNG_DBG("Entry: %s\n", __FUNCTION__)
#define IBNG_DBG_FUNC_EXIT IBNG_DBG("Exit: %s\n", __FUNCTION__)

#define IBNG_PTL_SET_RV(rv, code)				\
	do {										\
		IBNG_ASSERT(code == PTL_OK);			\
		rv = code;								\
	} while(0)
#define IBNG_PTL_RET(code)					\
	do {										\
		IBNG_ASSERT(code == PTL_OK);			\
		return code;							\
	} while(0)

static inline void
ibng_dump_char_array(char *array, unsigned int size)
{
	unsigned int i;
	for (i = 0; i < size; i++) {
		fprintf(p3_out, "%02x", array[i]);
	}
	fprintf(p3_out, "\n");
}

#ifdef UINT64_T_IS_ULONGLONG
#  define GID_FMT     "%016llx"
#else
#  define GID_FMT     "%016lx"
#endif /* UINT64_T_IS_ULONGLONG */

#if __WORDSIZE == 64
#  define UINTPTR_FMT "%016lx"
#  define UINT64_FMT  "%016lx"
#else
#  define UINTPTR_FMT "%08x"
#  define UINT64_FMT  "%016llx"
#endif /* __WORDISZE == 64 */

#endif /* __IBNG_DBG_H__ */
