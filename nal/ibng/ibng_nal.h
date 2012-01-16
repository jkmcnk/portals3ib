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

#ifndef __IBNG_NAL_H__
#define __IBNG_NAL_H__

extern nal_create_t p3ibng_create_nal;
extern nal_stop_t p3ibng_stop_nal;
extern nal_destroy_t p3ibng_destroy_nal;
extern pid_ranges_t p3ibng_pid_ranges;

extern ptl_nid_t p3ibng_my_nid(void);

#endif /* __IBNG_NAL_H__ */
