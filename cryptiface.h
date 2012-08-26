#ifndef CRYPTOIFACE_H // include guards, for clueless user
#define CRYPTOIFACE_H

#include <linux/ioctl.h>

#include "cryptoiface_ioctlmagic.h"

int cryptiface_setcurrent(int fd, int algorithm, int id, int encrypt);
int cryptiface_addkey(int fd, int algorithm, char *key);
int cryptiface_delkey(int fd, int algorithm, int id);
int cryptiface_numresults(int fd);
int cryptiface_sizeresults(int fd, size_t *res, int n);

#endif
