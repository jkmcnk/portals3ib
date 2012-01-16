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

#ifndef __IBNG_HT_H__
#define __IBNG_HT_H__

#include <errno.h>

/* a rather simple hash table implementation */

typedef unsigned int ibng_ht_key;

typedef struct ibng_ht_element ibng_ht_element_t;
struct ibng_ht_element {
	ibng_ht_element_t *next;
	const void *key;
};

typedef int ibng_ht_cmp_f(const void *a, const void *b);
typedef ibng_ht_key ibng_ht_hash_f(const void *key);

typedef struct ibng_htable ibng_htable_t;
struct ibng_htable {
	ibng_ht_cmp_f *cmp_f;
	ibng_ht_hash_f *hash_f;
	unsigned int size, elements;
	ibng_ht_element_t **buckets;
};

ibng_htable_t *ibng_htable_create(ibng_ht_hash_f *hash_f, 
								  ibng_ht_cmp_f *cmp_f, unsigned int size);
void ibng_htable_destroy(ibng_htable_t *htable);

int ibng_htable_put(ibng_htable_t *htable, const void *key, 
		    ibng_ht_element_t *element);
int ibng_htable_remove(ibng_htable_t *htable, void *key);

typedef void (*ibng_htable_f_t)(const void *key, void *value);
int ibng_htable_foreach(ibng_htable_t *htable, ibng_htable_f_t func);

static inline ibng_ht_element_t *
ibng_htable_get(ibng_htable_t *htable, const void *key)
{
	ibng_ht_key hash = htable->hash_f(key);
	ibng_ht_element_t *bucket = htable->buckets[hash % htable->size];
	
	while (bucket != NULL) {	
		if (htable->cmp_f(key, bucket->key) == 0) {
			return bucket;
		}
		bucket = bucket->next;
	}
	
	/* no element with a given key was found. */
	return NULL;
}

static inline int
ibng_htable_get_element_count(ibng_htable_t *ht)
{
	return ht->elements;
}

#endif /* __IBNG_HT_H__ */
