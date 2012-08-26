/* -*- mode: C; fill-column: 80; c-file-style: "linux"; indent-tabs-mode: t  -*- */
#include <linux/module.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/ioctl.h>
#include <linux/slab.h>
#include <asm/uaccess.h>

#include "crypto_structures.h"
#include "crypto_ioctlmagic.h"
#include "crypto_device.h"

struct cryptodev_t cryptodev;

struct cryptodev_t* get_cryptodev(void) {
	return &cryptodev;
}

static const unsigned int cryptodev_minor = 0;

static struct class *crypto_class;

struct cryptiface_status {
	bool ready;
	int context_id;
	bool encrypt;
};

static int cryptiface_open(struct inode *inode, struct file *file)
{
	struct cryptiface_status *status = kmalloc(sizeof(*status), GFP_KERNEL);
	if(NULL == status) {
		return -ENOMEM;
	}

	status->ready = false;
	file->private_data = status;
	return 0;
}

static int cryptiface_release(struct inode *inode, struct file *file)
{
	kfree(file->private_data);
	return 0;
}


static ssize_t cryptiface_read(struct file *file, char __user *buf,
			       size_t count, loff_t *offp)
{
	return -EIO;
}

static ssize_t cryptiface_write(struct file *file, const char __user *buf,
			       size_t count, loff_t *offp)
{
	return -EIO;
}

static long cryptiface_ioctl(struct file *filp, unsigned int cmd,
			     unsigned long arg)
{
	int err = 0;
	enum cryptiface_ioctl_opnrs op;

	if (_IOC_TYPE(cmd) != CRYPTIFACE_IOCTL_MAGIC) {
		return -ENOTTY;
	}
	if (_IOC_NR(cmd) >= CRYPTIFACE_INVALID_NR) {
		return -ENOTTY;
	}
	if (_IOC_DIR(cmd) & _IOC_READ) {
		err = !access_ok(VERIFY_WRITE, (void __user *)arg,
				 _IOC_SIZE(cmd));
	} else if (_IOC_DIR(cmd) & _IOC_WRITE) {
		err = !access_ok(VERIFY_READ, (void __user *)arg,
				 _IOC_SIZE(cmd));
	}
	if (err) {
		return -EFAULT;
	}
	op = _IOC_NR(cmd);
	switch(op) {
	default: // shouldn't happen
		err = -ENOTTY;
	}
	return err;
}

static struct file_operations cryptodev_fops = {
	.owner = THIS_MODULE,
	.open = cryptiface_open,
	.read = cryptiface_read,
	.write = cryptiface_write,
	.unlocked_ioctl = cryptiface_ioctl,
	.release = cryptiface_release
};

int create_cryptiface(void)
{
	int err;

        INIT_LIST_HEAD(&cryptodev.crypto_dbs);

	crypto_class = class_create(THIS_MODULE, "crypto");
	if(IS_ERR(crypto_class)) {
		err = PTR_ERR(crypto_class);
		goto create_class_fail;
	}


	if((err = alloc_chrdev_region(&cryptodev.dev, cryptodev_minor,
				      1, "cryptiface"))) {
		printk(KERN_WARNING "Couldn't alloc chrdev region\n");
		goto alloc_chrdev_fail;
	}

	cdev_init(&cryptodev.cdev, &cryptodev_fops);
	cryptodev.cdev.owner = THIS_MODULE;
	cryptodev.cdev.ops = &cryptodev_fops;
	if((err = cdev_add(&cryptodev.cdev, cryptodev.dev, 1))) {
		printk(KERN_WARNING "Couldn't add the character device\n");
		goto cdev_add_fail;
	}

	cryptodev.device = device_create(crypto_class, 0, cryptodev.dev, 0,
					 "cryptiface");
	if(IS_ERR(cryptodev.device)) {
		printk(KERN_WARNING "Error in device_create.\n");
		err = PTR_ERR(cryptodev.device);
		goto device_create_fail;
	}

	return 0;

device_create_fail:
	cdev_del(&cryptodev.cdev);
cdev_add_fail:
	unregister_chrdev_region(cryptodev.dev, 1);
alloc_chrdev_fail:
        class_destroy(crypto_class);
create_class_fail:
	return err;
}

void destroy_cryptiface(void)
{
	// TODO: take cryptodev lock here
	while(!list_empty(&cryptodev.crypto_dbs)) {
		struct crypto_db *db = list_first_entry(
			&cryptodev.crypto_dbs, struct crypto_db, db_list);
		list_del(&db->db_list);
		// TODO: take context lock here
		kfree(db);
	}
	device_destroy(crypto_class, cryptodev.dev);
	cdev_del(&cryptodev.cdev);
	unregister_chrdev_region(cryptodev.dev, 1);
	class_destroy(crypto_class);
}
