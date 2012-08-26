/* -*- mode: C; fill-column: 80; c-file-style: "linux"; indent-tabs-mode: t  -*- */

// #include <linux/cdev.h>

struct cryptodev_t {
	dev_t dev;
	struct cdev cdev;
	struct device *device;
	struct list_head crypto_dbs;
};


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

	struct mutex new_context_wait_mutex;
	wait_queue_head_t new_context_created_waitqueue;
	spinlock_t new_contexts_list_lock;
	struct list_head new_contexts_queue;
};
