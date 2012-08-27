/* -*- mode: C; fill-column: 80; c-file-style: "linux"; indent-tabs-mode: t  -*- */

// #include "crypto_structures.h"

struct crypto_db* create_crypto_db(uid_t uid);
struct crypto_db* get_or_create_crypto_db(struct list_head *dbs, uid_t uid);

int get_key_index(char *buf);
bool is_valid_key(char *buf, int len);
int add_key_to_db(struct crypto_db *db, int ix,
		   char *buf, int len);
int delete_key_from_db(struct crypto_db *db, int ix);

int acquire_free_context_index(struct crypto_db *db);
int acquire_context_index(struct crypto_db *db, int ix);
void release_context_index(struct crypto_db *db, int ix);
