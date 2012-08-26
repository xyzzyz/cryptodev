/* -*- mode: C; fill-column: 80; c-file-style: "linux"; indent-tabs-mode: t  -*- */
#include <linux/init.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/slab.h>

#include "crypto_structures.h"
#include "crypto_algorithm.h"
#include "crypto_proc.h"
#include "crypto_module.h"

MODULE_AUTHOR("Adam Michalik <adamm@mimuw.edu.pl>");
MODULE_LICENSE("Dual BSD/GPL");

static struct class *crypto_class;

struct cryptodev_t cryptodev;

static struct file_operations cryptodev_fops;

static bool crypto_api_available(void)
{
	// TODO: implement.
	return true;
}

static int create_cryptoiface(void)
{
	int err;

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
	return err;

}

static void destroy_cryptoiface(void)
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
}

static int crypto_init(void)
{
	int err;

	printk(KERN_NOTICE "Hello, crypto!\n");

	if(!crypto_api_available()) {
		printk(KERN_WARNING "Crypto API unavailable\n");
		return -1; // TODO: errno
	}

	INIT_LIST_HEAD(&cryptodev.crypto_dbs);

	crypto_class = class_create(THIS_MODULE, "crypto");
	if(IS_ERR(crypto_class)) {
		err = PTR_ERR(crypto_class);
		goto fail;
	}

	if((err = create_cryptoiface())) {
		printk(KERN_WARNING "Couldn't create cryptoiface device.\n");
		goto create_cryptoiface_fail;
	}

	if((err = create_crypto_proc_entries())) {
		printk(KERN_WARNING "Couldn't create proc entries.\n");
		goto create_proc_entries_fail;
	}

	return 0;

create_proc_entries_fail:
	destroy_cryptoiface();
create_cryptoiface_fail:
	class_destroy(crypto_class);
fail:
	return err;
}

static void crypto_exit(void)
{
	remove_crypto_proc_entries();
	destroy_cryptoiface();
	class_destroy(crypto_class);
	printk(KERN_NOTICE "Goodbye, crypto!\n");
}


module_init(crypto_init);
module_exit(crypto_exit);
