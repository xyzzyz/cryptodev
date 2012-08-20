/* -*- mode: C; fill-column: 80; c-file-style: "linux"; indent-tabs-mode: t  -*- */
#ifndef CRYPTO_ALGORITHM_H
#define CRYPTO_ALGORITHM_H

#include <linux/cred.h>
#include <stddef.h>

enum { CRYPTO_MAX_CONTEXT_COUNT = 128 };
enum { CRYPTO_MAX_KEY_LENGTH = 128 };


struct crypto_context {
	bool is_active;
	char key[CRYPTO_MAX_KEY_LENGTH];
	int key_len;
	unsigned long added_time;
	unsigned long encoded_count;
	unsigned long decoded_count;
};

struct new_context_info {
	int ix;
	struct list_head contexts;
};

struct crypto_db {
	uid_t uid;
	struct crypto_context contexts[CRYPTO_MAX_CONTEXT_COUNT];
	struct list_head db_list;

	struct list_head new_contexts_queue;
};

struct crypto_db* create_crypto_db(uid_t uid);
struct crypto_db* get_or_create_crypto_db(struct list_head *dbs, uid_t uid);

int get_key_index(char *buf);
bool is_valid_key(char *buf, int len);
int add_key_to_db(struct crypto_db *db, int ix,
		   char *buf, int len);
int delete_key_from_db(struct crypto_db *db, int ix);

int acquire_free_context_index(struct crypto_db *db);
void acquire_context_index(struct crypto_db *db, int ix);
void release_context_index(struct crypto_db *db, int ix);

#endif
