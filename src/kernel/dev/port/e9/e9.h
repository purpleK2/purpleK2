#ifndef E9_H
#define E9_H 1

#define PORT 0xe9

#include <dev/device.h>
#include <io.h>
#include <memory/heap/kheap.h>

#include <string.h>

void dev_e9_init();

int dev_e9_read(struct device *dev, void *buffer, size_t size, size_t offset);
int dev_e9_write(struct device *dev, const void *buffer, size_t size,
                 size_t offset);
int dev_e9_ioctl(struct device *dev, int request, void *arg);

#endif // E9_H