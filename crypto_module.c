/* -*- mode: C; fill-column: 80; c-file-style: "linux"; indent-tabs-mode: t  -*- */
#include <linux/init.h>
#include <linux/module.h>
#include <linux/cdev.h>

#include "crypto_structures.h"
#include "crypto_algorithm.h"
#include "crypto_proc.h"
#include "crypto_device.h"

MODULE_AUTHOR("Adam Michalik <adamm@mimuw.edu.pl>");
MODULE_LICENSE("Dual BSD/GPL");

static bool crypto_api_available(void)
{
	// TODO: implement.
	return true;
}

static int crypto_init(void)
{
	int err;

	printk(KERN_NOTICE "Hello, crypto!\n");

	if(!crypto_api_available()) {
		printk(KERN_WARNING "Crypto API unavailable\n");
		return -1; // TODO: errno
	}

	if((err = create_cryptiface())) {
		printk(KERN_WARNING "Couldn't create cryptiface device.\n");
		goto create_cryptiface_fail;
	}

	if((err = create_crypto_proc_entries())) {
		printk(KERN_WARNING "Couldn't create proc entries.\n");
		goto create_proc_entries_fail;
	}

	return 0;

create_proc_entries_fail:
	destroy_cryptiface();
create_cryptiface_fail:
	return err;
}

static void crypto_exit(void)
{
	remove_crypto_proc_entries();
	destroy_cryptiface();
	printk(KERN_NOTICE "Goodbye, crypto!\n");
}


module_init(crypto_init);
module_exit(crypto_exit);
