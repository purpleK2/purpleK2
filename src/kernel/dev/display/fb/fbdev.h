#ifndef FB_DEVICE_H
#define FB_DEVICE_H

#include <dev/device.h>
#include <stddef.h>

typedef struct fb_info {
    uint64_t width;
    uint64_t height;
    uint64_t pitch;
    uint64_t bpp;
} fb_info_t;

#define FB_IOCTL_GET_INFO 0x1001

void dev_fb_init();

int dev_fb_write(device_t *dev, const void *buffer, size_t size, size_t offset);
int dev_fb_read(device_t *dev, void *buffer, size_t size, size_t offset);
int dev_fb_ioctl(device_t *dev, int request, void *argp);
int dev_fb_mmap(device_t *dev, void *addr, size_t length, int prot, int flags, size_t offset);

#endif // FB_DEVICE_H
