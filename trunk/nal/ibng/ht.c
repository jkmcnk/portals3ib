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

#include <stdlib.h>

#include "dbg.h"
#include "ht.h"

ibng_htable_t *
ibng_htable_create(ibng_ht_hash_f *hash_f,
		   ibng_ht_cmp_f *cmp_f, unsigned int size)
{
	ibng_htable_t *htable;
	
	IBNG_ASSERT(hash_f != NULL);
	IBNG_ASSERT(cmp_f != NULL);
	
	htable = malloc(sizeof(ibng_htable_t));
	if (htable == NULL) {
		if (IBNG_DEBUG_NI(PTL_DBG_NI_00)) {
			p3_print("ERROR: cannot allocate memory for "
				"htable!\n");
		}
		
		return NULL;
	}
	
	htable->hash_f = hash_f;
	htable->cmp_f = cmp_f;
	
	htable->size = size;
	htable->elements = 0;
	htable->buckets = calloc(size, sizeof(ibng_htable_t *));
	if (htable->buckets == NULL) {
		if (IBNG_DEBUG_NI(PTL_DBG_NI_00)) {
			p3_print("ERROR: cannot allocate memory for "
				"htable->buckets!\n");
		}
		
		free(htable);
		
		return NULL;
	}
	
	/* initialize bucket table (set all the table entries to NULL). */
	memset(htable->buckets, 0, size * sizeof(ibng_htable_t *));
	
	return htable;
}

void 
ibng_htable_destroy(ibng_htable_t *htable)
{
	free(htable->buckets);
	free(htable);
}

int 
ibng_htable_put(ibng_htable_t *htable, const void *key, 
		ibng_ht_element_t *element)
{
	ibng_ht_key hash;
	
	/* if the element with the same key already exists in the hash
	 * table, return an error. */
	if (ibng_htable_get(htable, key) != NULL) {
		return -EEXIST;
	}
	
	/* add the new element into hash table. */
	hash = htable->hash_f(key);
	element->key = key;
	element->next = htable->buckets[hash % htable->size];
	htable->buckets[hash % htable->size] = element;
	htable->elements++;
	
	return 0;
}

int 
ibng_htable_remove(ibng_htable_t *htable, void *key)
{
	ibng_ht_key hash = htable->hash_f(key);
	ibng_ht_element_t *bucket = htable->buckets[hash % htable->size];
	
	if (bucket == 0) {
		/* the given list of buckets doesn't contain any elements
		 * so we are positive there is no element with the given
		 * key in the hash table. */
		return -ENOENT;
	}
	
	/* do a check for the first element in the list. */ 
	if (htable->cmp_f(key, bucket->key) == 0) {
		htable->buckets[hash % htable->size] =
			htable->buckets[hash % htable->size]->next;
		htable->elements--;
		return 0;
	}
	
	/* check the rest of the list. */
	while (bucket->next != NULL) {	
		if (htable->cmp_f(key, bucket->next->key) == 0) {
			bucket->next = bucket->next->next;
			htable->elements--;
			return 0;
		}
		bucket = bucket->next;
	}
	
	/* no element with a given key was found. */
	return -ENOENT;
}

int
ibng_htable_foreach(ibng_htable_t *htable, ibng_htable_f_t func)
{
	ibng_ht_element_t *bucket, *next;
	unsigned int i;

	for(i = 0; i < htable->size; i++) {
		bucket = htable->buckets[i];
		while(NULL != bucket) {
			next = bucket->next;
			func(bucket->key, bucket);
			bucket = next;
		}
	}

	return 0;
}

