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

#ifndef __IBNG_ISET_H__
#define __IBNG_ISET_H__

#include "dbg.h"

typedef struct ibng_iset ibng_iset_t;

#define IBNG_ISET_INVALID_IDX (uint16_t)0xffff

struct ibng_iset {
	uint16_t size, free, next;
	void *els[0];
};

static inline ibng_iset_t *
ibng_iset_create(unsigned int size)
{
	ibng_iset_t *rv = malloc(sizeof(ibng_iset_t) + size*sizeof(void *));
	uint16_t i;

	if(NULL == rv)
		return NULL;

	rv->size = size;
	rv->free = size;
	rv->next = 0;

	for(i = 0; i < size; i++)
		rv->els[i] = (void *)(uintptr_t)(i + 1);

	return rv;
}

static inline void
ibng_iset_destroy(ibng_iset_t *iset)
{
	free(iset);
}

static inline uint16_t
ibng_iset_acquire(ibng_iset_t *iset)
{
	uint16_t rv;

	if(iset->next == iset->size)
		return IBNG_ISET_INVALID_IDX;
	rv = (uint16_t)(iset->next & 0xffff);
	iset->next = (uintptr_t)iset->els[rv];
	iset->free--;
	IBNG_DBG("Index %d acquired from %p, %d available.\n",
			 (int)rv, iset, iset->free);

	return rv;
}

static inline void
ibng_iset_release(ibng_iset_t *iset, uint16_t idx)
{
	iset->els[idx] = (void *)(uintptr_t)iset->next;
	iset->next = idx;
	iset->free++;

	IBNG_DBG("Index %d released to %p, %d available.\n",
			 (int)idx, iset, iset->free);
}

#define ibng_iset_el(iset, idx) iset->els[idx]

#endif /* __IBNG_ISET_H__ */
