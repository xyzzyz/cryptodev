/* -*- mode: C; fill-column: 80; c-file-style: "linux"; indent-tabs-mode: t  -*- */
#include <linux/init.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>

#include "crypto.h"

MODULE_AUTHOR("Adam Michalik <adamm@mimuw.edu.pl>");
MODULE_LICENSE("Dual BSD/GPL");

static struct class *crypto_class;

static struct cryptodev_t cryptodev;

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
	device_destroy(crypto_class, cryptodev.dev);
	cdev_del(&cryptodev.cdev);
	unregister_chrdev_region(cryptodev.dev, 1);
}

static struct proc_dir_entry *proc_cryptiface_directory = NULL;
static struct proc_dir_entry *proc_cryptiface_overview = NULL;
// TODO: refactor to support multiple algorithms.
static struct proc_dir_entry *proc_cryptiface_des = NULL;

static int create_crypto_proc_entries(void)
{
	int err;
	proc_cryptiface_directory = proc_mkdir("cryptiface", NULL);
	if(NULL == proc_cryptiface_directory) {
		printk(KERN_WARNING "Couldn't create proc directory.\n");
		err = -EIO;
		goto fail;
	}

	proc_cryptiface_overview = create_proc_entry("overview", 0644,
						     proc_cryptiface_directory);
	if(NULL == proc_cryptiface_overview) {
		printk(KERN_WARNING "Couldn't create proc 'overview' file.\n");
		err = -EIO;
		goto overview_fail;
	}

	proc_cryptiface_des = create_proc_entry("des", 0644,
						proc_cryptiface_directory);
	if(NULL == proc_cryptiface_des) {
		printk(KERN_WARNING "Couldn't create proc 'des' file.\n");
		err = -EIO;
		goto des_fail;
	}

	return 0;

des_fail:
	remove_proc_entry("overview", proc_cryptiface_directory);
	proc_cryptiface_overview = NULL;
overview_fail:
	remove_proc_entry("cryptiface", NULL);
	proc_cryptiface_directory = NULL;
fail:
	return err;
}

static void remove_crypto_proc_entries(void)
{
	remove_proc_entry("des", proc_cryptiface_directory);
	proc_cryptiface_des = NULL;
	remove_proc_entry("overview", proc_cryptiface_directory);
	proc_cryptiface_overview = NULL;
	remove_proc_entry("cryptiface", NULL);
	proc_cryptiface_directory = NULL;
}

static int crypto_init(void)
{
	int err;

	printk(KERN_NOTICE "Hello, crypto!\n");

	if(!crypto_api_available()) {
		printk(KERN_WARNING "Crypto API unavailable\n");
		return -1; // TODO: errno
	}

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
