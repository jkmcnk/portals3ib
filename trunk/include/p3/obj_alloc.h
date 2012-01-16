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

#ifndef _PTL3_P3_OBJ_ALLOC_H_
#define _PTL3_P3_OBJ_ALLOC_H_

#include <string.h>

/* Grrrr.  Need these due to a case conflict in macro names used when
 * updating status registers.  Or, need to just get rid of the object
 * alloc/free macros.  Grrr.
 */
#define SR_ALLOC(obj_t) obj_t##S_ALLOC
#define SR_FREED(obj_t) obj_t##S_FREED
#define SR_CUR(obj_t)   obj_t##S_CUR
#define SR_MAX(obj_t)   obj_t##S_MAX

#define msgS_ALLOC PTL_SR_MSGS_ALLOC
#define msgS_FREED PTL_SR_MSGS_FREED
#define msgS_MAX   PTL_SR_MSGS_MAX
#define msgS_CUR   PTL_SR_MSGS_CUR

#define meS_ALLOC  PTL_SR_MES_ALLOC
#define meS_FREED  PTL_SR_MES_FREED
#define meS_MAX    PTL_SR_MES_MAX
#define meS_CUR    PTL_SR_MES_CUR

#define mdS_ALLOC   PTL_SR_MDS_ALLOC
#define mdS_FREED   PTL_SR_MDS_FREED
#define mdS_MAX     PTL_SR_MDS_MAX
#define mdS_CUR     PTL_SR_MDS_CUR

#define eqS_ALLOC   PTL_SR_EQS_ALLOC
#define eqS_FREED   PTL_SR_EQS_FREED
#define eqS_MAX     PTL_SR_EQS_MAX
#define eqS_CUR     PTL_SR_EQS_CUR

/* We need these to handle differences between API and library space.
 */
#define PTL_TYPE(obj)  api##_##obj##_t
#define PTL_FROB_SR_ALLOC(obj_t) do{} while(0)
#define PTL_FROB_SR_FREE(obj_t)  do{} while(0)

#ifdef _PTL3_LIB_P3LIB_H_
#undef PTL_TYPE
#define PTL_TYPE(obj)  lib##_##obj##_t
#ifdef PORTALS_PROFILE
#undef PTL_FROB_SR_ALLOC
#define PTL_FROB_SR_ALLOC(obj_t)			\
	do {						\
		ni->stats[SR_ALLOC(obj_t)]++;		\
		ni->stats[SR_CUR(obj_t)]++;		\
		ni->stats[SR_MAX(obj_t)] =		\
			MAX(ni->stats[SR_CUR(obj_t)],	\
			    ni->stats[SR_MAX(obj_t)]);	\
	} while(0)
#undef PTL_FROB_SR_FREE
#define PTL_FROB_SR_FREE(obj_t)				\
	do {						\
		ni->stats[SR_FREED(obj_t)]++;		\
		ni->stats[SR_CUR(obj_t)]--;		\
	} while(0)
#endif
#endif

/* This macro can be used to initialize a table of the sort the object
 * allocation macros below expect to use.
 */
#define PTL_ALLOC_INIT_TBL(table)	\
do {					\
	(table)->tbl = NULL;		\
	(table)->inuse = 0;		\
	(table)->next_row = 0;		\
	(table)->num_rows = 0;		\
} while (0)

/* This macro can be used to free a table of the sort the object
 * allocation macros below expect to use.  table must me be one of
 * me, md, eq, msg. ni should be a pointer to api_ni_t or lib_ni_t.
 */
#define PTL_ALLOC_FREE_TBL(table,ni)	\
do {					\
	unsigned i;							\
	for (i=0; i<ni->table.next_row; i++) { 				\
		p3_free(ni->table.tbl[i]);				\
	}								\
	p3_free(ni->table.tbl);						\
	ni->table.tbl = NULL;						\
} while (0)

/* Use this as a debugging aid anytime you want to make sure the
 * object ids match the objects.
 */
#define ptl_chk_oid(obj,ni)		\
do {									\
	unsigned i, j, id = 0;						\
	for (j=0; j<(ni)->obj.next_row; j++) {				\
		if (PTL_OBJ_INDX((ni)->obj.tbl[j]) != id)		\
			PTL_ROAD();					\
		for (i=1; i<PTL_INDX_MAX_COL; i++) {			\
			id++;						\
			if (PTL_OBJ_INDX((ni)->obj.tbl[j]+(i-1)) !=	\
			    PTL_OBJ_INDX((ni)->obj.tbl[j]+i)-1)		\
				PTL_ROAD();				\
		}							\
		id++;							\
	}								\
} while (0)

/*
 * We use this macro to allocate a Portals object when we just want to
 * use the next available one, and don't care what its descriptor
 * handle is. It returns NULL if there are no objects available.
 *
 * ni is a pointer to a network interface, (type lib_ni_t* or api_ni_t*).
 * obj_t must be one of me, md, eq, msg.
 *
 * This macro only cares about obj_t as a string.
 *
 * Due to use of labels this macro should be used only once per type per
 * function, or you'll get duplicate label errors.  Not a problem, really.
 */
#define ptl_obj_alloc(obj_t,ni)						\
({									\
	PTL_TYPE(obj_t) *obj = NULL;					\
	unsigned int n;							\
									\
	p3_lock(&(ni)->obj_alloc);					\
	if (!TST_OBJ((ni), OBJ_INUSE))					\
		goto _out1_##obj_t;					\
									\
	/* Is there a free object?					\
	 */								\
	if (!list_empty(&(ni)->free_##obj_t)) {				\
		struct list_head *item = (ni)->free_##obj_t.next;	\
		obj = container_of(item, PTL_TYPE(obj_t), list);	\
		list_del(item);						\
		goto _out_##obj_t;					\
	}								\
	/* If there are no free objects, we need to allocate a new row	\
	 * of them.  Do we need to expand the array of row pointers?	\
	 */								\
	if ((ni)->obj_t.next_row == (ni)->obj_t.num_rows) {		\
		PTL_TYPE(obj_t) **tbl;					\
		size_t new_sz, old_sz;					\
		if ((ni)->obj_t.num_rows == PTL_INDX_MAX_ROW)		\
			goto _out1_##obj_t;				\
		n = MIN(PTL_INDX_MAX_COL,				\
			PTL_INDX_MAX_ROW - (ni)->obj_t.num_rows);	\
		n += (ni)->obj_t.num_rows;				\
		old_sz = sizeof(PTL_TYPE(obj_t)*) * (ni)->obj_t.num_rows;\
		new_sz = sizeof(PTL_TYPE(obj_t)*) * n;			\
		if (!(tbl = p3_realloc((ni)->obj_t.tbl, old_sz, new_sz)))\
			goto _out1_##obj_t;				\
		(ni)->obj_t.num_rows = n;				\
		(ni)->obj_t.tbl = tbl;					\
	}								\
	/* We have a free row; allocate/initialize a row of objects.	\
	 */								\
	if (!((ni)->obj_t.tbl[(ni)->obj_t.next_row] = 			\
		p3_malloc(PTL_INDX_MAX_COL*sizeof(PTL_TYPE(obj_t)))))	\
		goto _out1_##obj_t;					\
	memset((ni)->obj_t.tbl[(ni)->obj_t.next_row], 0,		\
	       PTL_INDX_MAX_COL*sizeof(PTL_TYPE(obj_t)));		\
	for (n=PTL_INDX_MAX_COL; --n>0; ) {				\
		obj = &(ni)->obj_t.tbl[(ni)->obj_t.next_row][n];	\
		list_add(&obj->list, &(ni)->free_##obj_t);		\
		obj->id = (ni)->obj_t.next_row << PTL_INDX_COL_BITS	\
				| n | PTL_NI_HNDL((ni)->id);		\
	}								\
	obj = (ni)->obj_t.tbl[(ni)->obj_t.next_row];			\
	obj->id = (ni)->obj_t.next_row << PTL_INDX_COL_BITS		\
			 | PTL_NI_HNDL((ni)->id);			\
	(ni)->obj_t.next_row++;						\
_out_##obj_t:								\
	PTL_FROB_SR_ALLOC(obj_t);					\
	SET_OBJ(obj, OBJ_INUSE);					\
	{								\
		uint32_t id = obj->id;					\
		memset(obj, 0, sizeof(*obj));				\
		obj->id = id;						\
	}								\
	(ni)->obj_t.inuse++;						\
_out1_##obj_t:								\
	p3_unlock(&(ni)->obj_alloc);					\
	obj;								\
})

/*
 * We use this macro to allocate a Portals object with a specific
 * descriptor handle value.  It returns NULL if the object is in use,
 * or the handle is invalid.
 *
 * ni is a pointer to a network interface, (type lib_ni_t* or api_ni_t*).
 * obj_t must be one of me, md, eq, msg.
 *
 * This macro only cares about obj_t as a string.
 *
 * Due to use of labels this macro should be used only once per type per
 * function, or you'll get duplicate label errors.  Not a problem, really.
 */
#define ptl_specific_obj_alloc(obj_t,hndl,ni)				\
({									\
	PTL_TYPE(obj_t) *obj = NULL;					\
	unsigned int n;							\
									\
	p3_lock(&(ni)->obj_alloc);					\
	if (!TST_OBJ((ni), OBJ_INUSE))					\
		goto _out1_##obj_t;					\
									\
	/* Was the requested object ever allocated?  Is it in use?	\
	 */								\
	if (VALID_PTL_OBJ(&(ni)->obj_t,hndl)) {				\
		obj = GET_PTL_OBJ(&(ni)->obj_t, hndl);			\
		if (!TST_OBJ(obj,OBJ_INUSE)) goto _out_##obj_t;		\
		obj = NULL;						\
		goto _out1_##obj_t;					\
	}								\
	/* Try to allocate enough rows to include the requested object.	\
	 */								\
	n = PTL_ROW_INDX(hndl);						\
	if (n >= PTL_INDX_MAX_ROW) goto _out1_##obj_t;			\
	n = (n + PTL_INDX_MAX_COL) & ~(PTL_INDX_MAX_COL - 1);		\
	n = MIN(n, PTL_INDX_MAX_ROW);					\
	{								\
		PTL_TYPE(obj_t) **tbl;					\
		size_t new_sz, old_sz;					\
		old_sz = sizeof(PTL_TYPE(obj_t)*) * (ni)->obj_t.num_rows;\
		new_sz = sizeof(PTL_TYPE(obj_t)*) * n;			\
		if (!(tbl = p3_realloc((ni)->obj_t.tbl,old_sz, new_sz)))\
			goto _out1_##obj_t;				\
		(ni)->obj_t.num_rows = n;				\
		(ni)->obj_t.tbl = tbl;					\
	}								\
	/* Try to allocate objects for all the new rows.		\
	 */								\
	while ((ni)->obj_t.next_row < (ni)->obj_t.num_rows) {		\
		int i = (ni)->obj_t.next_row;				\
		if (!((ni)->obj_t.tbl[i] = 				\
			p3_malloc(PTL_INDX_MAX_COL*sizeof(PTL_TYPE(obj_t))))) \
			goto _out1_##obj_t;				\
		memset((ni)->obj_t.tbl[i], 0,				\
		       PTL_INDX_MAX_COL*sizeof(PTL_TYPE(obj_t)));	\
		n = PTL_INDX_MAX_COL;					\
		do {							\
			n--;						\
			obj = &(ni)->obj_t.tbl[(ni)->obj_t.next_row][n];\
			list_add(&obj->list, &(ni)->free_##obj_t);	\
			obj->id = (ni)->obj_t.next_row << PTL_INDX_COL_BITS \
					| n | PTL_NI_HNDL((ni)->id);	\
			if (n == 0) break;				\
		} while (1);						\
		(ni)->obj_t.next_row++;					\
	}								\
	obj = GET_PTL_OBJ(&(ni)->obj_t, hndl);				\
_out_##obj_t:								\
	list_del(&obj->list);						\
	PTL_FROB_SR_ALLOC(obj_t);					\
	SET_OBJ(obj, OBJ_INUSE);					\
	{								\
		uint32_t id = obj->id;					\
		memset(obj, 0, sizeof(*obj));				\
		obj->id = id;						\
	}								\
	(ni)->obj_t.inuse++;						\
_out1_##obj_t:								\
	p3_unlock(&(ni)->obj_alloc);					\
	obj;								\
})

/*
 * obj must be one of me, md, eq, msg; ni should be a pointer to
 * api_ni_t or lib_ni_t.  The caller is responsible for removing obj
 * from any list it may be in before calling lib_obj_free().
 *
 * It turns out that this macro uses obj both as a string and as
 * the name of the Portals3 object to free.  Sorry.
 */
#define ptl_obj_free(obj,ni)		\
do {					\
	p3_lock(&(ni)->obj_alloc);					\
	obj->id &= ~PTL_INDX_FL_MASK;					\
	list_add(&obj->list, &(ni)->free_##obj);			\
	(ni)->obj.inuse--;						\
	PTL_FROB_SR_FREE(obj);						\
	p3_unlock(&(ni)->obj_alloc);					\
} while (0)

#endif /* _PTL3_P3_OBJ_ALLOC_H_ */
