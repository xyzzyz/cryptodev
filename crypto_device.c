/* -*- mode: C; fill-column: 80; c-file-style: "linux"; indent-tabs-mode: t  -*- */
#include <linux/module.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/ioctl.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
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

struct cryptiface_result {
	struct scatterlist *sg;
	size_t length;

	struct list_head result_list;
};

struct cryptiface_status {
	struct crypto_db *db;
	struct crypto_blkcipher *tfm;
	bool encrypt;

	struct mutex write_mutex;

	wait_queue_head_t new_result_waitqueue;
	spinlock_t results_queue_lock;

	struct list_head results_queue;
};

static const char* get_alg_name(enum crypto_algorithms alg)
{
	switch(alg) {
	case CRYPTIFACE_ALG_DES:
		return "ecb(des)";
	default:
		return NULL;
	}
}

static int cryptiface_ioctl_setcurrent(struct cryptiface_status *status,
				       int algorithm, int context_id,
				       int encrypt)
{
	struct crypto_context *context;
	struct crypto_blkcipher *tfm;
	int err;
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

	tfm = crypto_alloc_blkcipher(get_alg_name(algorithm), 0, 0);
	if(IS_ERR(tfm)) {
		printk(KERN_DEBUG "alloc_blkcipher %s failed\n",
		       get_alg_name(algorithm));
		return PTR_ERR(tfm);
	}

	context = &status->db->contexts[context_id];
	if(mutex_lock_interruptible(&context->context_mutex)) {
		err = -ERESTARTSYS;
		goto fail;
	}
	if(!context->is_active) {
		printk(KERN_DEBUG "trying to setcurrent invalid context: %d\n",
		       context_id);
		err = -EINVAL;
		goto unlock;
	}
	err = crypto_blkcipher_setkey(tfm, context->key, context->key_len);
	mutex_unlock(&context->context_mutex);
	if (err) {
		printk(KERN_DEBUG "setkey() failed flags=%x\n",
		       crypto_blkcipher_get_flags(tfm));
		goto fail;
	}

	if(status->tfm != NULL) {
		crypto_free_blkcipher(status->tfm);
	}
	status->tfm = tfm;
	status->encrypt = encrypt;
	return 0;
unlock:
	mutex_unlock(&context->context_mutex);
fail:
	crypto_free_blkcipher(tfm);
	return err;
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

	if(mutex_lock_interruptible(&get_cryptodev()->crypto_dbs_mutex)) {
		return -ERESTARTSYS;
	}
	db = get_or_create_crypto_db(&get_cryptodev()->crypto_dbs,
				     current_euid());
	mutex_unlock(&get_cryptodev()->crypto_dbs_mutex);
	if(NULL == db) {
		result = -ENOMEM;
		goto out;
	}

	ix = acquire_free_context_index(db);
	if(ix < 0) {
		result = ix;
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

	if(mutex_lock_interruptible(&get_cryptodev()->crypto_dbs_mutex)) {
		return -ERESTARTSYS;
	}
	db = get_or_create_crypto_db(&get_cryptodev()->crypto_dbs,
				     current_euid());
	mutex_unlock(&get_cryptodev()->crypto_dbs_mutex);
	if(NULL == db) {
		result = -ENOMEM;
		goto out;
	}

	if(acquire_context_index(db, id)) {
		return -ERESTARTSYS;
	}
	result = delete_key_from_db(db, id);
	release_context_index(db, id);

out:
	return result;
}

static int cryptiface_ioctl_numresults(struct cryptiface_status *status) {
	struct list_head *head;
	int count = 0;
	spin_lock(&status->results_queue_lock);
	list_for_each(head, &status->results_queue) {
		count++;
	}
	spin_unlock(&status->results_queue_lock);
	return count;
}

static int cryptiface_open(struct inode *inode, struct file *file)
{
	struct crypto_db *db;
	struct cryptiface_status *status = kmalloc(sizeof(*status), GFP_KERNEL);
	int err;
	if(NULL == status) {
		return -ENOMEM;
	}
	if(mutex_lock_interruptible(&get_cryptodev()->crypto_dbs_mutex)) {
		err = -ERESTARTSYS;
		goto fail;
	}
	db = get_or_create_crypto_db(&get_cryptodev()->crypto_dbs,
				     current_euid());
	mutex_unlock(&get_cryptodev()->crypto_dbs_mutex);
	if(NULL == db) {
		err = -ENOMEM;
		goto fail;
	}
	status->tfm = NULL;
	status->db = db;
	mutex_init(&status->write_mutex);
	init_waitqueue_head(&status->new_result_waitqueue);
	spin_lock_init(&status->results_queue_lock);
	INIT_LIST_HEAD(&status->results_queue);
	file->private_data = status;
	return 0;
fail:
	kfree(status);
	return err;
}

static int cryptiface_release(struct inode *inode, struct file *file)
{
	struct cryptiface_status *status = file->private_data;
	if(NULL != status->tfm) {
		crypto_free_blkcipher(status->tfm);
	}
	kfree(status);
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
	struct cryptiface_status *status = file->private_data;
	struct cryptiface_result *result_data;
	int page_count = count/PAGE_SIZE;
	size_t remaining_data = count;
	int i; int err;
	char *page; char **pages;
	struct scatterlist *sg;
	struct blkcipher_desc desc;
	if(NULL == status->tfm) {
		printk(KERN_DEBUG "writing to cryptiface without setting key\n");
		return -EINVAL;
	}

	// To avoid potential corruption of encryption context,
	// only one process can be writing to a given fd at a time
	if(mutex_lock_interruptible(&status->write_mutex)) {
		return -ERESTARTSYS;
	}

	if(count % PAGE_SIZE != 0) {
		page_count++;
	}

	result_data = kmalloc(sizeof(*result_data), GFP_KERNEL);
	if(NULL == result_data) {
		err = -ENOMEM;
		goto out;
	}

	pages = kmalloc(page_count*sizeof(*pages), GFP_KERNEL);
	if(NULL == pages) {
		err = -ENOMEM;
		goto free_result_data;
	}

	sg = kmalloc(page_count*sizeof(*sg), GFP_KERNEL);
	if(NULL == sg) {
		err = -ENOMEM;
		goto free_pages_list;
	}
	sg_init_table(sg, page_count);
	for(i = 0; i<page_count; i++) {
		page = (void*) __get_free_page(GFP_KERNEL);
		if(NULL == page) {
			i--;
			err = -ENOMEM;
			goto err_free_pages;
		}
		pages[i] = page;
		if(copy_from_user(page, buf, min(remaining_data,
						 (size_t) PAGE_SIZE))) {
			err = -EFAULT;
			goto err_free_pages;
		}
		if(remaining_data < PAGE_SIZE) {
			// zero fill
			memset(page+remaining_data, 0,
			       PAGE_SIZE-remaining_data);
		}
		sg_set_buf(&sg[i], page, PAGE_SIZE);
		remaining_data -= min(remaining_data, (size_t) PAGE_SIZE);
	}

	desc.tfm = status->tfm;
	desc.flags = 0;
	// TODO: %8 is DES only
	remaining_data = count + ((count%8 !=0) ? 8 - count%8 : 0);
	if(status->encrypt) {
		err = crypto_blkcipher_encrypt(&desc, sg, sg,
					       remaining_data);
	} else {
		err = crypto_blkcipher_decrypt(&desc, sg, sg,
					       remaining_data);
	}
	if(err) {
		printk(KERN_DEBUG "encryption/decryption error\n");
		goto err_free_pages;
	}

	result_data->sg = sg;
	result_data->length = remaining_data;

	spin_lock(&status->results_queue_lock);
	list_add_tail(&result_data->result_list, &status->results_queue);
	spin_unlock(&status->results_queue_lock);
	wake_up_interruptible(&status->new_result_waitqueue);

	kfree(pages);
	err = count;
	goto out;

err_free_pages:
	kfree(sg);
	for(;i >= 0; i--) {
		free_page((unsigned long) pages[i]);
	}
free_pages_list:
	kfree(pages);
free_result_data:
	kfree(result_data);
out:
	mutex_unlock(&status->write_mutex);
	return err;
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
		if(op_info.key_size > 2*CRYPTO_MAX_KEY_LENGTH) {
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
	case CRYPTIFACE_NUMRESULTS_NR: {
		return cryptiface_ioctl_numresults(file->private_data);
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
	mutex_init(&cryptodev.crypto_dbs_mutex);

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
	mutex_lock(&get_cryptodev()->crypto_dbs_mutex);
	while(!list_empty(&cryptodev.crypto_dbs)) {
		struct crypto_db *db = list_first_entry(
			&cryptodev.crypto_dbs, struct crypto_db, db_list);
		list_del(&db->db_list);
		kfree(db);
	}
	device_destroy(crypto_class, cryptodev.dev);
	cdev_del(&cryptodev.cdev);
	unregister_chrdev_region(cryptodev.dev, 1);
	class_destroy(crypto_class);
	mutex_unlock(&get_cryptodev()->crypto_dbs_mutex);
}
