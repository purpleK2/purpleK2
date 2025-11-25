#ifndef DEV_INITRD_H
#define DEV_INITRD_H

#include <dev/device.h>
#include <memory/heap/kheap.h>
#include <stddef.h>
#include <util/string.h>

void dev_initrd_init(void *ramfs_disk);

int dev_initrd_read(struct device *dev, void *buffer, size_t size,
                    size_t offset);
int dev_initrd_write(struct device *dev, const void *buffer, size_t size,
                     size_t offset);

#endif // DEV_INITRD_H