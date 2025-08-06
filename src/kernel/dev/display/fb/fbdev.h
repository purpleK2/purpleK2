#ifndef FB_DEVICE_H
#define FB_DEVICE_H

#include <dev/device.h>
#include <stddef.h>

void dev_fb_init();

int dev_fb_write(device_t *dev, const void *buffer, size_t size, size_t offset);
int dev_fb_read(device_t *dev, void *buffer, size_t size, size_t offset);
int dev_fb_ioctl(device_t *dev, int request, void *argp);

#endif // FB_DEVICE_H
