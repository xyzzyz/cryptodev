/* -*- mode: C; fill-column: 80; c-file-style: "linux"; indent-tabs-mode: t  -*- */

struct __cryptiface_setcurrent_op {
	int algorithm;
	int context_id;
	int encrypt;
};

struct __cryptiface_addkey_op {
	int algorithm;
	const char *key;
	size_t key_size;
};

struct __cryptiface_delkey_op {
	int algorithm;
	int context_id;
};

struct __cryptiface_sizeresults_op {
	size_t *results;
	int count;
};

enum __cryptiface_ioctl_opnrs {
	CRYPTIFACE_SETCURRENT_NR,
	CRYPTIFACE_ADDKEY_NR,
	CRYPTIFACE_DELKEY_NR,
	CRYPTIFACE_NUMRESULTS_NR,
	CRYPTIFACE_SIZERESULTS_NR,
	CRYPTIFACE_INVALID_NR
};

enum crypto_algorithms { CRYPTIFACE_ALG_DES, CRYPTIFACE_ALG_INVALID };

#define CRYPTIFACE_IOCTL_MAGIC 0xCC
#define CRYPTIFACE_IOCTL_SETCURRENT _IOW(CRYPTIFACE_IOCTL_MAGIC,        \
                                         CRYPTIFACE_SETCURRENT_NR,      \
                                         struct __cryptiface_setcurrent_op*)
#define CRYPTIFACE_IOCTL_ADDKEY _IOW(CRYPTIFACE_IOCTL_MAGIC,            \
                                     CRYPTIFACE_ADDKEY_NR,              \
                                     struct __cryptiface_addkey_op*)
#define CRYPTIFACE_IOCTL_DELKEY _IOW(CRYPTIFACE_IOCTL_MAGIC,            \
                                     CRYPTIFACE_DELKEY_NR,              \
                                     struct __cryptiface_delkey_op*)
#define CRYPTIFACE_IOCTL_NUMRESULTS _IO(CRYPTIFACE_IOCTL_MAGIC,		\
					CRYPTIFACE_NUMRESULTS_NR)
#define CRYPTIFACE_IOCTL_SIZERESULTS _IOR(CRYPTIFACE_IOCTL_MAGIC,	\
					  CRYPTIFACE_SIZERESULTS_NR,	\
					  struct __cryptiface_sizeresults_op*) 
