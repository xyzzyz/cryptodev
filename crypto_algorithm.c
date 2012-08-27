/* -*- mode: C; fill-column: 80; c-file-style: "linux"; indent-tabs-mode: t  -*- */
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/ctype.h>
#include <linux/sched.h>
#include <linux/cdev.h>

#include "crypto_structures.h"
#include "crypto_algorithm.h"

static void initialize_crypto_db(struct crypto_db *db, uid_t uid)
{
	int i;
	INIT_LIST_HEAD(&db->new_contexts_queue);
	init_waitqueue_head(&db->new_context_created_waitqueue);
	spin_lock_init(&db->new_contexts_list_lock);
	mutex_init(&db->new_context_wait_mutex);
	db->uid = uid;
	memset(db->contexts, 0,
	       CRYPTO_MAX_CONTEXT_COUNT*sizeof(struct crypto_context));
	for(i = 0; i<CRYPTO_MAX_CONTEXT_COUNT; i++) {
		mutex_init(&db->contexts[i].context_mutex);
	}
}

struct crypto_db* create_crypto_db(uid_t uid)
{
	struct crypto_db *db = kmalloc(sizeof(*db), GFP_KERNEL);
	if(NULL == db) {
		return NULL;
	}
	initialize_crypto_db(db, uid);
	return db;
}

struct crypto_db* get_or_create_crypto_db(struct list_head *dbs, uid_t uid)
{
	struct crypto_db *db_entry;
	struct list_head *head;
	list_for_each(head, dbs) {
		db_entry = list_entry(head, struct crypto_db, db_list);
		if(db_entry->uid == uid) {
			return db_entry;
		}
	}
	// db for given uid not found
	printk(KERN_INFO "Creating new crypto db for uid %d\n", uid);
	db_entry = create_crypto_db(uid);
	if(NULL == db_entry) {
		return NULL;
	}
	list_add(&db_entry->db_list, dbs);
	return db_entry;
}

int get_key_index(char *buf) {
	unsigned long key;
	if(strict_strtoul(buf, 10, &key)) {
		return -EINVAL;
	}
	if(key < CRYPTO_MAX_CONTEXT_COUNT) {
		return key;
	} else {
		return -EINVAL;
	}
}

bool is_valid_key(char *buf, int len)
{
	int i;
	if(len != 2*CRYPTO_MAX_KEY_LENGTH) {
		return false;
	}
	for(i = 0; i<len; i++) {
		if(!isxdigit(buf[i])) {
			return false;
		}
	}
	return true;
}

static void hex_string_to_bytes(char *hex, int hex_len,
                                char *out) {
  int i;
  for(i = 0; i<hex_len/2; i++) {
    sscanf(hex+2*i, "%2hhx", &out[i]);
  }
}


int add_key_to_db(struct crypto_db *db, int ix,
			 char *buf, int len)
{
	struct new_context_info *info;

	printk(KERN_INFO "adding key to db, ix %d, len %d", ix, len/2);
	memset(db->contexts[ix].key, 0, len/2);
	hex_string_to_bytes(buf, len, db->contexts[ix].key);
	db->contexts[ix].key_len = len/2;
	db->contexts[ix].added_time = get_seconds();
	db->contexts[ix].encoded_count = 0;
	db->contexts[ix].decoded_count = 0;

	info = kmalloc(sizeof(*info), GFP_KERNEL);
	if(NULL == info) {
		return -ENOMEM;
	}
	info->ix = ix;
	spin_lock(&db->new_contexts_list_lock);
	list_add_tail(&info->contexts, &db->new_contexts_queue);
	spin_unlock(&db->new_contexts_list_lock);
	wake_up_interruptible(&db->new_context_created_waitqueue);
	db->contexts[ix].is_active = true;
	return 0;
}

int delete_key_from_db(struct crypto_db* db, int ix) {
	if(!db->contexts[ix].is_active) {
		// context is inactive
		return -EINVAL;
	}

	db->contexts[ix].is_active = false;
	return 0;
}

int acquire_free_context_index(struct crypto_db* db) {
	int i, ix = -ENOSPC;
	for(i = 0; i<CRYPTO_MAX_CONTEXT_COUNT; i++) {
		if(mutex_lock_interruptible(&db->contexts[i].context_mutex)) {
			return -ERESTARTSYS;
		}
		if(!db->contexts[i].is_active) {
			ix = i;
			break;
		}
		mutex_unlock(&db->contexts[i].context_mutex);
	}
	return ix;
}

int acquire_context_index(struct crypto_db* db, int ix) {
	return mutex_lock_interruptible(&db->contexts[ix].context_mutex);
}

void release_context_index(struct crypto_db* db, int ix) {
	mutex_unlock(&db->contexts[ix].context_mutex);
}
