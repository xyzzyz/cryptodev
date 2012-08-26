struct cryptiface_setcurrent_op {
  int algorithm;
  int context_id;
  int encrypt;
};

struct cryptiface_addkey_op {
  int algorithm;
  char *key;
  size_t key_size;
};

struct cryptiface_delkey_op {
  int algorithm;
  int context_id;
};

enum cryptiface_ioctl_opnrs {
  CRYPTIFACE_SETCURRENT_NR,
  CRYPTIFACE_ADDKEY_NR,
  CRYPTIFACE_DELKEY_NR,
  CRYPTIFACE_NUMRESULTS_NR,
  CRYPTIFACE_SIZERESULTS_NR,
  CRYPTIFACE_INVALID_NR
};

#define CRYPTIFACE_IOCTL_MAGIC 0xCC
#define CRYPTIFACE_IOCTL_SETCURRENT _IOW(CRYPTIFACE_IOCTL_MAGIC,        \
                                         CRYPTIFACE_SETCURRENT_NR,      \
                                         struct cryptiface_setcurrent_op)
#define CRYPTIFACE_IOCTL_ADDKEY _IOW(CRYPTIFACE_IOCTL_MAGIC,            \
                                     CRYPTIFACE_ADDKEY_NR,              \
                                     struct cryptiface_addkey_op)
#define CRYPTIFACE_IOCTL_DELKEY _IOW(CRYPTIFACE_IOCTL_MAGIC, 2,         \
                                     CRYPTIFACE_DELKEY_NR,              \
                                     struct cryptiface_delkey_op)
#define CRYPTIFACE_IOCTL_NUMRESULTS
#define CRYPTIFACE_IOCTL_SIZERESULTS
