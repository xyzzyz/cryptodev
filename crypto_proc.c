/* -*- mode: C; fill-column: 80; c-file-style: "linux"; indent-tabs-mode: t  -*- */
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/sched.h>
#include <linux/cdev.h>
#include <asm/uaccess.h>

#include "crypto_structures.h"
#include "crypto_algorithm.h"
#include "crypto_device.h"
#include "crypto_proc.h"

static void* proc_overview_seq_start(struct seq_file *s, loff_t *pos)
{
	uid_t uid;
	struct crypto_db *db;

	if(*pos >= CRYPTO_MAX_CONTEXT_COUNT) {
		return NULL;
	}

	uid  = current_euid();
	// TODO: lock
	db = get_or_create_crypto_db(&get_cryptodev()->crypto_dbs, uid);
	if(NULL == db) {
		return NULL;
	}
	return &db->contexts[*pos];
}

static void* proc_overview_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
	uid_t uid;
	struct crypto_db *db;

	(*pos)++;
	if(*pos >= CRYPTO_MAX_CONTEXT_COUNT) {
		return NULL;
	}

	uid = current_euid();
	// TODO: lock
	db = get_or_create_crypto_db(&get_cryptodev()->crypto_dbs,
						       uid);
	if(NULL == db) {
		return NULL;
	}
	return &db->contexts[*pos];
}

static void proc_overview_seq_stop(struct seq_file *s, void *v) {}

static int proc_overview_seq_show(struct seq_file *s, void *v) {
	uid_t uid = current_euid();
	struct crypto_db *db = get_or_create_crypto_db(
		&get_cryptodev()->crypto_dbs, uid);
	struct crypto_context *context = v;
	size_t ix = context - db->contexts;
	if(context->is_active) {
		seq_printf(s, "%zd\tdes\t%ld\t%ld\t%ld\n",
			   ix, context->added_time,
			   context->encoded_count, context->decoded_count);
	}

	return 0;
}

static struct seq_operations proc_overview_seq_ops = {
	.start = proc_overview_seq_start,
	.next = proc_overview_seq_next,
	.stop = proc_overview_seq_stop,
	.show = proc_overview_seq_show
};

static int proc_overview_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &proc_overview_seq_ops);
}


static struct file_operations proc_overview_file_ops = {
	.owner = THIS_MODULE,
	.open = proc_overview_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release
};

static int proc_des_read(char *buffer, char **start, off_t offset, int count,
			 int *eof, void *data)
{
	int result, written;
	uid_t uid  = current_euid();
	struct crypto_db *db;
	struct new_context_info *info;

	if(offset > 0) {
		*eof = 1;
		return 0;
	}

	if(count <= 10) {
		// We do not support small reads
		return -EINVAL;
	}

	// TODO: lock
	db = get_or_create_crypto_db(&get_cryptodev()->crypto_dbs, uid);
	if(NULL == db) {
		result = -ENOMEM;
		goto out;
	}

	if(mutex_lock_interruptible(&db->new_context_wait_mutex)) {
		result = -ERESTARTSYS;
		goto out;
	}
	if(wait_event_interruptible(db->new_context_created_waitqueue,
				    !list_empty(&db->new_contexts_queue))) {
		result = -ERESTARTSYS;
		goto mutex_unlock;
	}
	spin_lock(&db->new_contexts_list_lock);
	info = list_first_entry(&db->new_contexts_queue,
				struct new_context_info,
				contexts);
	list_del(&info->contexts);
	spin_unlock(&db->new_contexts_list_lock);
	written = sprintf(buffer, "%d", info->ix);
	kfree(info);
	result = min(written, count);

mutex_unlock:
	mutex_unlock(&db->new_context_wait_mutex);
out:
	return result;
}

static int proc_des_write(struct file *file, const char __user *buffer,
			  unsigned long count, void *data)
{
	if(count < 2) {
		printk(KERN_WARNING "Call to write() with too little bytes");
		return -EINVAL;
	}
	if(count >= CRYPTO_MAX_KEY_LENGTH + 1) {
		printk(KERN_WARNING "Key too long");
		return -E2BIG;
	}
	{
		// We add 2 to have null terminator.
		char tmp_buffer[CRYPTO_MAX_KEY_LENGTH+2] = {0};
		int ix; int err;
		struct crypto_db *db;

		if(copy_from_user(tmp_buffer, buffer, count)) {
			return -EFAULT;
		}

		db = get_or_create_crypto_db(
			&get_cryptodev()->crypto_dbs, current_euid());
		if(NULL == db) {
			printk(KERN_WARNING "get_or_create_crypto_db failed\n");
			return -ENOMEM;
		}

		switch(tmp_buffer[0]) {
		case 'A':
			if(!is_valid_key(tmp_buffer+1, count-1)) {
				printk(KERN_WARNING "invalid key\n");
				return -EINVAL;
			}
			ix = acquire_free_context_index(db);
			if(-1 == ix) {
				return -ENOMEM;
			} else {
				err = add_key_to_db(db, ix, tmp_buffer+1,
						    count-1);
				release_context_index(db, ix);
				if(err) {
					return err;
				}
			}
			break;
		case 'D':
			// tmp_buffer is null terminated, so we don't pass len
			ix = get_key_index(tmp_buffer+1);
			if(ix < 0) {
				printk(KERN_WARNING "invalid index\n");
				return -EINVAL;
			}
			acquire_context_index(db, ix);
			err = delete_key_from_db(db, ix);
			release_context_index(db, ix);
			if(err) {
				return err;
			}
			break;
		default:
			printk(KERN_WARNING "unknown operation\n");
			return -EINVAL;
			break;
		}
		return count;
	}
}

static struct proc_dir_entry *proc_cryptiface_directory = NULL;
static struct proc_dir_entry *proc_cryptiface_overview = NULL;
// TODO: refactor to support multiple algorithms.
static struct proc_dir_entry *proc_cryptiface_des = NULL;

int create_crypto_proc_entries(void)
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
	proc_cryptiface_overview->proc_fops = &proc_overview_file_ops;

	proc_cryptiface_des = create_proc_entry("des", 0666,
						proc_cryptiface_directory);
	if(NULL == proc_cryptiface_des) {
		printk(KERN_WARNING "Couldn't create proc 'des' file.\n");
		err = -EIO;
		goto des_fail;
	}
	proc_cryptiface_des->read_proc = proc_des_read;
	proc_cryptiface_des->write_proc = proc_des_write;

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

void remove_crypto_proc_entries(void)
{
	remove_proc_entry("des", proc_cryptiface_directory);
	proc_cryptiface_des = NULL;
	remove_proc_entry("overview", proc_cryptiface_directory);
	proc_cryptiface_overview = NULL;
	remove_proc_entry("cryptiface", NULL);
	proc_cryptiface_directory = NULL;
}
