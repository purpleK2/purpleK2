#include "fbdev.h"
#include "kernel.h"
#include "limine.h"

#include <errors.h>
#include <memory/heap/kheap.h>
#include <string.h>

void dev_fb_init() {
    device_t *dev = kmalloc(sizeof(device_t));
    memcpy(dev->name, "fb0", DEVICE_NAME_MAX);
    dev->type          = DEVICE_TYPE_BLOCK;
    dev->write         = dev_fb_write;
    dev->read          = dev_fb_read;
    dev->ioctl         = dev_fb_ioctl;
    dev->dev_node_path = "fb0";
    dev->data          = get_bootloader_data()->framebuffer;
    register_device(dev);
}

int dev_fb_write(device_t *dev, const void *buffer, size_t size,
                 size_t offset) {
    struct limine_framebuffer *fb = (struct limine_framebuffer *)dev->data;
    size_t fb_size                = fb->pitch * fb->height;

    if (offset >= fb_size) {
        return -EINVAL;
    }

    if (offset + size > fb_size) {
        size = fb_size - offset;
    }

    size_t pixel_size = fb->bpp / 8;
    if (pixel_size < 3) {
        return -EINVAL; // unsupported format
    }

    uint8_t *dst       = (uint8_t *)fb->address + offset;
    const uint8_t *src = (const uint8_t *)buffer;

    size_t processed = 0;
    while (processed + 3 <= size) {
        dst[0] = src[2]; // B
        dst[1] = src[1]; // G
        dst[2] = src[0]; // R

        if (pixel_size == 4) {
            dst[3] = 0xFF;
        }

        dst       += pixel_size;
        src       += 3;
        processed += 3;
    }

    return EOK;
}
int dev_fb_read(device_t *dev, void *buffer, size_t size, size_t offset) {
}
int dev_fb_ioctl(device_t *dev, int request, void *argp) {
}
