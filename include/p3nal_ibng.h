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

/* Include this file to make the IBNG NAL available to an application.
 * An application can access multiple NALs by including more than one
 * p3nal_<nal>.h file.  In that case, the first file included defines
 * the default NAL, and any other NAL must be explicitly referenced.
 */

#ifndef _PTL3_P3NAL_IBNG_H_
#define _PTL3_P3NAL_IBNG_H_

#define PTL_IFACE_IBNG  PTL_NALTYPE_IBNG

#define PTL_IFACE_IBNG0 PTL_NALTYPE_IBNG0

#ifdef PTL_IFACE_DEFAULT
#warn  Default Portals3 interface already defined
#else
#define PTL_IFACE_DEFAULT PTL_IFACE_IBNG
#endif

#endif /* _PTL3_P3NAL_IBNG_H_ */
