/* -*- mode: C; fill-column: 80; c-file-style: "linux"; indent-tabs-mode: t  -*- */
#include <linux/init.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/cdev.h>

#include "crypto.h"

MODULE_AUTHOR("Adam Michalik <adamm@mimuw.edu.pl>");
MODULE_LICENSE("Dual BSD/GPL");

static struct class *crypto_class;

static int crypto_init(void)
{
	printk(KERN_NOTICE "Hello, crypto!\n");

	crypto_class = class_create(THIS_MODULE, "crypto");
	if(IS_ERR(crypto_class)) {
		return PTR_ERR(crypto_class);
	}
	return 0;
}

static void crypto_exit(void)
{
	class_destroy(crypto_class);
	printk(KERN_NOTICE "Goodbye, crypto!\n");
}


module_init(crypto_init);
module_exit(crypto_exit);
