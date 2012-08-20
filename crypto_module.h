/* -*- mode: C; fill-column: 80; c-file-style: "linux"; indent-tabs-mode: t  -*- */
#ifndef CRYPTO_MODULE_H
#define CRYPTO_MODULE_H

#include "crypto_algorithm.h"

static const unsigned int cryptodev_minor = 0;

struct cryptodev_t {
	dev_t dev;
	struct cdev cdev;
	struct device *device;
	struct list_head crypto_dbs;
};

#endif
