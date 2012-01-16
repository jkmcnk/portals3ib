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

#include <p3-config.h>

#include <linux/list.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <asm/uaccess.h>

/* These are all Portals3 include files.
 */
#include "p3utils.h"

#include <p3api/types.h>
#include <p3api/debug.h>

#include <p3/lock.h>
#include <p3/handle.h>
#include <p3/process.h>
#include <p3/errno.h>
#include <p3/debug.h>

#include <p3lib/types.h>
#include <p3lib/p3lib.h>
#include <p3lib/nal.h>
#include <p3lib/p3lib_support.h>

#include <p3/obj_alloc.h>	/* MUST come after p3lib/p3lib.h */

#include <p3rt/types.h>
#include <p3rt/forward.h>
#include <p3rt/dispatch.h>

#include "p3_module.h"

#define P3RT_VERSION_STRING "Portals Message Passing Runtime v"PACKAGE_VERSION

/* p3rt_write implements the kernel side of Portals request forwarding.
 * It expects to read a buffer containing two (pointer, length) pairs,
 * where the first describes the request block, and the second describes
 * the result block.
 */
ssize_t p3rt_write(struct file *filep,
		    const char __user *buf, size_t count, loff_t *f_pos)
{
	p3rt_forward_t fw;
	p3rt_req_t *req;
	p3rt_res_t *res;
	ssize_t ret = sizeof(fw);

	*f_pos = 0;

	if (count != sizeof(fw)) {
		ret = -EINVAL;
		goto fail;
	}
	if (copy_from_user(&fw, buf, sizeof(fw))) {
		ret = -EFAULT;
		goto fail;
	}
	if (!(req = p3_malloc(fw.req_len))) {
		ret = -ENOMEM;
		goto fail;
	}
	if (!(res = p3_malloc(fw.res_len))) {
		ret = -ENOMEM;
		goto fail_req;
	}
	if (copy_from_user(req, (char *)fw.request, fw.req_len)) {
		ret = -EFAULT;
		goto fail_res;
	}
	if (copy_from_user(res, (char *)fw.result, fw.res_len)) {
		ret = -EFAULT;
		goto fail_res;
	}
	res->status = PTL_FAIL;
	p3rt_dispatch(req, res);

	if (copy_to_user((char *)fw.result, res, fw.res_len))
		ret = -EFAULT;

fail_res:
	p3_free(res);
fail_req:
	p3_free(req);
fail:
	return ret;
}

struct file_operations p3rt_fops = {
	.owner = THIS_MODULE,
	.write = p3rt_write,
};

static
ssize_t attr_p3rt_dev_show(struct class_device *cls, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%d:%d\n", P3RT_MAJOR, P3RT_MINOR);
}

/* The p3lib module already got our dev_t value when it initialized.  
 */
static struct cdev p3rt_cdev;
static struct class_device p3rt_class_dev = {
	.class = &p3_class,
};

static struct class_device_attribute attr_p3rt_dev = {
	.attr = { .name = "dev",
		  .owner = THIS_MODULE,
		  .mode = S_IRUGO
	},
	.show = attr_p3rt_dev_show,
};

static
int __init p3rt_init(void)
{
	int err;

	/* So the library can request a PID from us.
	 */
	runtime_req_pid = p3rt_runtime_pid;

	strlcpy(p3rt_class_dev.class_id, "p3rt", BUS_ID_SIZE);
	err = class_device_register(&p3rt_class_dev);
	if (err) 
		goto fail;

	err = class_device_create_file(&p3rt_class_dev, &attr_p3rt_dev);
	if (err)
		goto fail_class_device;

	/* Turn on the device.  Last.
	 */
	cdev_init(&p3rt_cdev, &p3rt_fops);
	p3rt_cdev.owner = THIS_MODULE;
	err = cdev_add(&p3rt_cdev, P3RT_DEV, 1);
	if (err)
		goto fail_class_dev_attr;

	printk(KERN_INFO P3RT_VERSION_STRING"\n");
	return 0;

fail_class_dev_attr:
	class_device_remove_file(&p3rt_class_dev, &attr_p3rt_dev);
fail_class_device:
	class_device_unregister(&p3rt_class_dev);
fail:
	runtime_req_pid = NULL;
	return err;
}

static
void __exit p3rt_exit(void)
{
	cdev_del(&p3rt_cdev);
	class_device_remove_file(&p3rt_class_dev, &attr_p3rt_dev);

	if (DEBUG_P3(p3lib_debug, PTL_DBG_SHUTDOWN))
		p3_print("p3rt_exit:  removing sysfs class device %s/%s\n",
			 p3_class.name, p3rt_class_dev.class_id);
	class_device_unregister(&p3rt_class_dev);
}

module_init(p3rt_init);
module_exit(p3rt_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Jim Schutt");
MODULE_VERSION(PACKAGE_VERSION);
MODULE_DESCRIPTION(P3RT_VERSION_STRING);
