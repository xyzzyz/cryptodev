/* -*- mode: C; fill-column: 80; c-file-style: "linux"; indent-tabs-mode: t  -*- */
#include <linux/module.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/slab.h>

#include "crypto_structures.h"
#include "crypto_device.h"

struct cryptodev_t cryptodev;

struct cryptodev_t* get_cryptodev(void) {
	return &cryptodev;
}

static const unsigned int cryptodev_minor = 0;

static struct class *crypto_class;

static struct file_operations cryptodev_fops;

int create_cryptoiface(void)
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

void destroy_cryptoiface(void)
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
