#include "device.h"

#include <memory/heap/kheap.h>

#include <stdio.h>
#include <string.h>

device_t *device_table[DEVICES_MAX];
int device_count = 0;

int register_device(device_t *dev) {
    if (device_count >= DEVICES_MAX) {
        kprintf_warn("Device table full!\n");
        return -1;
    }
    device_table[device_count++] = dev;
    debugf_debug("Device '%s' registered with type %s\n", dev->name,
                 dev->type == DEVICE_TYPE_BLOCK ? "BLK" : "CHR");

    return 0;
}

device_t *get_device(const char *name) {
    for (int i = 0; i < device_count; i++) {
        if (strcmp(device_table[i]->name, name) == 0) {
            return device_table[i];
        }
    }
    return NULL;
}

int unregister_device(const char *name) {

    device_t *dev = get_device(name);
    if (dev == NULL) {
        return -1;
    }

    kfree(dev);

    return 0;
}
