#ifndef DEVICE_H
#define DEVICE_H 1

#include <stddef.h>
#include <stdint.h>

#define DEVICES_MAX     1024
#define DEVICE_NAME_MAX 32

typedef struct device device_t;

extern int device_count;
extern device_t *device_table[DEVICES_MAX];

/*
 * Major device types:
 * - 1: Psudo devices
 * - 2: Block storage devices
 * - 3: TTYs
 * - 4: Screen related devices
 */

typedef enum {
    DEVICE_TYPE_BLOCK,
    DEVICE_TYPE_CHAR
} device_type_t;

typedef struct device {
    char name[DEVICE_NAME_MAX];

    char *dev_node_path;

    int major; // major device number see above for specification
    int minor; // minor device number see above for specification

    device_type_t type;
    int (*read)(struct device *dev, void *buffer, size_t size, size_t offset);
    int (*write)(struct device *dev, const void *buffer, size_t size,
                 size_t offset);
    int (*ioctl)(struct device *dev, int request, void *arg);
    void *data;
} device_t;

int register_device(device_t *dev);
device_t *get_device(const char *name);
int unregister_device(const char *name);

#endif // DEVICE_H
