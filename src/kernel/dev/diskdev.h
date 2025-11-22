#ifndef DISKDEV_H
#define DISKDEV_H 1

#include "dev/device.h"
#include <stdint.h>

typedef enum disk_namespace {
    DISK_NAMESPACE_INVALID = -1,
    DISK_NAMESPACE_PATA = 0, // /dev/hdX
    DISK_NAMESPACE_MODERN = 1, // /dev/sdX
    DISK_NAMESPACE_NVME = 2, // /dev/ndXnY
    DISK_NAMESPACE_FLOPPY = 3, // /dev/fdX
    DISK_NAMESPACE_OPTICAL = 4, // /dev/optX (this is like CD-ROM, CD-RW, DVD, etc)
} disk_namespace_e;

typedef struct disk_device {
    disk_namespace_e namespace;
    union {
        struct {
            int controller;
            int namespace; 
            // i have no idea if this is correct, i dont know much about nvme drives but from what i read it should be
        } nvmeid;

        struct {
            char letter;
        } id;
    };

    // populated by the API, NOT BY THE DRIVER
    device_t *dev;

    uint32_t block_size;
    uint64_t block_count;

    int (*read)(struct disk_device *disk, uint8_t *buffer, uint64_t lba,
                uint32_t sector_count);
    int (*write)(struct disk_device *disk, const uint8_t *buffer, uint64_t lba,
                 uint32_t sector_count);

    void *data;
    
} disk_device_t;

typedef struct diskdev_node {
    disk_device_t *disk;
    struct diskdev_node *next;
} diskdev_node_t;

 
int register_disk_device(disk_device_t *disk);
disk_device_t *get_disk_by_id(disk_namespace_e ns, char id_letter);
disk_device_t *get_disk_by_nvmeid(int controller, int namespace);
int unregister_disk_device(disk_namespace_e ns, char id_letter);
disk_device_t *get_diskdev(const char *name);

#endif // DISKDEV_H