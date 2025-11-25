#include "e9.h"

void dev_e9_init() {
    device_t *dev = kmalloc(sizeof(device_t));
    memcpy(dev->name, "e9", DEVICE_NAME_MAX);
    dev->type          = DEVICE_TYPE_CHAR;
    dev->read          = dev_e9_read;
    dev->write         = dev_e9_write;
    dev->ioctl         = dev_e9_ioctl;
    dev->dev_node_path = "e9";
    dev->data          = "e9-dbg";
    register_device(dev);
}

int dev_e9_read(struct device *dev, void *buffer, size_t size, size_t offset) {
    (void)dev;
    (void)offset;
    (void)buffer;
    (void)size;
    return 0;
}

int dev_e9_write(struct device *dev, const void *buffer, size_t size,
                 size_t offset) {

    (void)dev;
    (void)offset;

    for (size_t i = 0; i < size; i++) {
        _outb(PORT, ((char *)buffer)[i]);
    }

    return 0;
}

int dev_e9_ioctl(struct device *dev, int request, void *arg) {
    (void)dev;
    (void)request;
    (void)arg;
    return 0;
}
