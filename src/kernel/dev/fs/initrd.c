#include "initrd.h"

#include <memory/heap/kheap.h>

void dev_initrd_init(void *ramfs_disk) {
    device_t *dev = kmalloc(sizeof(device_t));
    memcpy(dev->name, "ram0", DEVICE_NAME_MAX);
    dev->type          = DEVICE_TYPE_BLOCK;
    dev->read          = dev_initrd_read;
    dev->write         = dev_initrd_write;
    dev->dev_node_path = "zram0";
    dev->data          = ramfs_disk;
    register_device(dev);
}

int dev_initrd_read(struct device *dev, void *buffer, size_t size,
                    size_t offset) {
    void *initrd_disk = dev->data;
    for (size_t i = 0; i < size; i++) {
        ((char *)buffer)[i] = ((char *)initrd_disk)[offset + i];
    }
    return 0;
}

int dev_initrd_write(struct device *dev, const void *buffer, size_t size,
                     size_t offset) {
    (void)dev;
    (void)buffer;
    (void)size;
    (void)offset;
    return 0;
}
