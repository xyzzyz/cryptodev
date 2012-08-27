#include <errno.h>

#include <string.h>
#include <stddef.h>

#include "cryptiface.h"

int
cryptiface_setcurrent(int fd, int algorithm, int id, int encrypt)
{
  struct __cryptiface_setcurrent_op op_info;
  op_info.algorithm = algorithm;
  op_info.context_id = id;
  op_info.encrypt = encrypt;
  return ioctl(fd, CRYPTIFACE_IOCTL_SETCURRENT, &op_info);
}

int
cryptiface_addkey(int fd, int algorithm, const char *key)
{
  struct __cryptiface_addkey_op op_info;
  int len = strlen(key);
  op_info.algorithm = algorithm;
  op_info.key = key;
  op_info.key_size = len;
  return ioctl(fd, CRYPTIFACE_IOCTL_ADDKEY, &op_info);
}

int
cryptiface_delkey(int fd, int algorithm, int id)
{
  struct __cryptiface_delkey_op op_info;
  op_info.algorithm = algorithm;
  op_info.context_id = id;
  return ioctl(fd, CRYPTIFACE_IOCTL_DELKEY, &op_info);
}

int
cryptiface_numresults(int fd)
{
  return ioctl(fd, CRYPTIFACE_IOCTL_NUMRESULTS);
}

int
cryptiface_sizeresults(int fd, size_t *res, int n)
{
  return -EIO;
}
