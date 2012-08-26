/* -*- mode: C; fill-column: 80; c-file-style: "linux"; indent-tabs-mode: t  -*- */
#include <linux/module.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/ioctl.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <asm/uaccess.h>

#include "crypto_structures.h"
#include "crypto_algorithm.h"
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
	int algorithm;
	int context_id;
	bool encrypt;
};

static int cryptiface_ioctl_setcurrent(struct cryptiface_status *status,
				       int algorithm, int context_id,
				       int encrypt)
{
	if(algorithm < 0 || algorithm >= CRYPTIFACE_ALG_INVALID) {
		printk(KERN_DEBUG "setcurrent with invalid algorithm: %d\n",
		       algorithm);
		return -EINVAL;
	}
	if(context_id < 0 || context_id >= CRYPTO_MAX_CONTEXT_COUNT) {
		printk(KERN_DEBUG "setcurrent with invalid context id: %d\n",
		       context_id);
		return -EINVAL;
	}
	status->algorithm = algorithm;
	status->context_id = context_id;
	status->encrypt = encrypt;
	status->ready = true;
	return 0;
}

static int cryptiface_ioctl_addkey(int algorithm, char *key, size_t size)
{
	struct crypto_db *db;
	int result = 0, ix;

	if(algorithm < 0 || algorithm >= CRYPTIFACE_ALG_INVALID) {
		printk(KERN_DEBUG "addkey with invalid algorithm: %d\n",
		       algorithm);
		result = -EINVAL;
		goto out;
	}
	if(!is_valid_key(key, size)) {
		printk(KERN_WARNING "invalid key\n");
		result = -EINVAL;
		goto out;
	}

	// TODO: lock
	db = get_or_create_crypto_db(&get_cryptodev()->crypto_dbs,
				     current_euid());
	if(NULL == db) {
		result = -ENOMEM;
		goto out;
	}

	ix = acquire_free_context_index(db);
	if(-1 == ix) {
		result = -ENOMEM;
		goto out;
	} else {
		result = add_key_to_db(db, ix, key, size);
		if(result >= 0) {
			result = ix;
		}
		release_context_index(db, ix);
	}

out:
	return result;
}

static int cryptiface_ioctl_delkey(int algorithm, int id)
{
	int result = 0;
	struct crypto_db *db;
	if(algorithm < 0 || algorithm >= CRYPTIFACE_ALG_INVALID) {
		printk(KERN_DEBUG "delkey with invalid algorithm: %d\n",
		       algorithm);
		result = -EINVAL;
		goto out;
	}
	if(id < 0 || id >= CRYPTO_MAX_CONTEXT_COUNT) {
		printk(KERN_DEBUG "invalid context id");
	}

	// TODO: lock
	db = get_or_create_crypto_db(&get_cryptodev()->crypto_dbs,
				     current_euid());
	if(NULL == db) {
		result = -ENOMEM;
		goto out;
	}

	acquire_context_index(db, id);
	result = delete_key_from_db(db, id);
	release_context_index(db, id);

out:
	return result;
}


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
	// TODO: take context lock
	return -EIO;
}

static long cryptiface_ioctl(struct file *file, unsigned int cmd,
			     unsigned long arg)
{
	int err = 0;
	enum __cryptiface_ioctl_opnrs op;

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
	case CRYPTIFACE_SETCURRENT_NR: {
		struct __cryptiface_setcurrent_op op_info;
		if(copy_from_user(&op_info, (void __user *)arg,
				  sizeof(op_info))) {
			return -EFAULT;
		}
		return cryptiface_ioctl_setcurrent(file->private_data,
						   op_info.algorithm,
						   op_info.context_id,
						   op_info.encrypt);
	}
	case CRYPTIFACE_ADDKEY_NR: {
		struct __cryptiface_addkey_op op_info;
		char key[CRYPTO_MAX_KEY_LENGTH+1] = {0};
		if(copy_from_user(&op_info, (void __user *)arg,
				  sizeof(op_info))) {
			return -EFAULT;
		}
		if(op_info.key_size > CRYPTO_MAX_KEY_LENGTH) {
			printk(KERN_DEBUG "insane key size");
			return -ENOMEM;
		}
		if(copy_from_user(key, op_info.key, op_info.key_size)) {
			return -EFAULT;
		}

		return cryptiface_ioctl_addkey(op_info.algorithm,
					       key,
					       op_info.key_size);

	}
	case CRYPTIFACE_DELKEY_NR: {
		struct __cryptiface_delkey_op op_info;
		if(copy_from_user(&op_info, (void __user *)arg,
				  sizeof(op_info))) {
			return -EFAULT;
		}
		return cryptiface_ioctl_delkey(op_info.algorithm,
					       op_info.context_id);

	}
	default: // shouldn't happen
		err = -ENOTTY;
	}
	return -EIO; // shouldn't happen
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
