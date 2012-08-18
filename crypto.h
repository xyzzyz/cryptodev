/* -*- mode: C; fill-column: 80; c-file-style: "linux"; indent-tabs-mode: t  -*- */
#ifndef CRYPTO_H
#define CRYPTO_H

static const unsigned int cryptodev_minor = 0;

struct cryptodev_t {
	dev_t dev;
	struct cdev cdev;
	struct device *device;
};

#endif
