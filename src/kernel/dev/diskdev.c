#include "diskdev.h"
#include "dev/device.h"
#include "errors.h"
#include "memory/heap/kheap.h"
#include "string.h"
#include <stdio.h>

static int diskdev_read(struct device *dev, void *buffer, size_t size, size_t offset) {
    disk_device_t *disk = (disk_device_t *)dev->data;
    if (!disk || !disk->read) {
        return -1;
    }

    uint32_t sector_size = disk->block_size;
    uint64_t start_lba   = offset / sector_size;
    uint32_t sector_count =
        (size + sector_size - 1) / sector_size; // round up to nearest sector

    return disk->read(disk, (uint8_t *)buffer, start_lba, sector_count);
}

static int diskdev_write(struct device *dev, const void *buffer, size_t size, size_t offset) {
    disk_device_t *disk = (disk_device_t *)dev->data;
    if (!disk || !disk->write) {
        return -1;
    }

    uint32_t sector_size = disk->block_size;
    uint64_t start_lba   = offset / sector_size;
    uint32_t sector_count =
        (size + sector_size - 1) / sector_size; // round up to nearest sector

    return disk->write(disk, (const uint8_t *)buffer, start_lba, sector_count);
}

static int diskdev_ctl(struct device *dev, int request, void *arg) {
    (void)request;
    (void)arg;
    debugf_warn("diskdev_ctl not implemented on disk device %s\n", dev->name);
    return -ENOIMPL;
}

int register_disk_device(disk_device_t *disk) {
    char prefix[8];
    char final_name[32];

    switch (disk->namespace) {
    case DISK_NAMESPACE_PATA:
        snprintf(prefix, sizeof(prefix), "hd");
        break;
    case DISK_NAMESPACE_MODERN:
        snprintf(prefix, sizeof(prefix), "sd");
        break;
    case DISK_NAMESPACE_NVME:
        snprintf(prefix, sizeof(prefix), "nd");
        break;
    case DISK_NAMESPACE_FLOPPY:
        snprintf(prefix, sizeof(prefix), "fd");
        break;
    case DISK_NAMESPACE_OPTICAL:
        snprintf(prefix, sizeof(prefix), "opt");
        break;
    default:
        return EINVAL;
    }

    if (disk->namespace == DISK_NAMESPACE_NVME) {
        snprintf(final_name, sizeof(final_name), "%s%dn%d",
                 prefix,
                 disk->nvmeid.controller,
                 disk->nvmeid.namespace);
    } else {
        snprintf(final_name, sizeof(final_name), "%s%c",
                 prefix,
                 disk->id.letter);
    }

    if (disk->dev != NULL) {
        debugf_warn("Disk device %s already registered!\n", final_name);
        return -EUNFB;
    }

    device_t *dev = kmalloc(sizeof(device_t));
    if (!dev) {
        return -ENOMEM;
    }

    snprintf(dev->name, DEVICE_NAME_MAX, "%s", final_name);
    dev->major        = 2;
    dev->minor        = 0;
    dev->type         = DEVICE_TYPE_BLOCK;
    dev->read         = diskdev_read;
    dev->write        = diskdev_write;
    dev->ioctl        = diskdev_ctl;
    dev->data         = (void *)disk;
    dev->dev_node_path = strdup(final_name);
    if (!dev->dev_node_path) {
        kfree(dev);
        return -ENOMEM;
    }

    register_device(dev);
    disk->dev = dev;

    return EOK;
}

disk_device_t *get_disk_by_id(disk_namespace_e ns, char id_letter) {
    char prefix[8];
    char final_name[32];

    switch (ns) {
    case DISK_NAMESPACE_PATA:
        snprintf(prefix, sizeof(prefix), "hd");
        break;
    case DISK_NAMESPACE_MODERN:
        snprintf(prefix, sizeof(prefix), "sd");
        break;
    case DISK_NAMESPACE_NVME:
        snprintf(prefix, sizeof(prefix), "nd");
        break;
    case DISK_NAMESPACE_FLOPPY:
        snprintf(prefix, sizeof(prefix), "fd");
        break;
    case DISK_NAMESPACE_OPTICAL:
        snprintf(prefix, sizeof(prefix), "opt");
        break;
    default:
        return NULL;
    }

    snprintf(final_name, sizeof(final_name), "%s%c",
             prefix,
             id_letter);

    device_t *dev = get_device(final_name);
    if (!dev) {
        return NULL;
    }

    return (disk_device_t *)dev->data;
}

disk_device_t *get_disk_by_nvmeid(int controller, int namespace) {
    char final_name[32];

    snprintf(final_name, sizeof(final_name), "nd%dn%d",
             controller,
             namespace);

    device_t *dev = get_device(final_name);
    if (!dev) {
        return NULL;
    }

    return (disk_device_t *)dev->data;
}

int unregister_disk_device(disk_namespace_e ns, char id_letter) {
    char prefix[8];
    char final_name[32];

    switch (ns) {
    case DISK_NAMESPACE_PATA:
        snprintf(prefix, sizeof(prefix), "hd");
        break;
    case DISK_NAMESPACE_MODERN:
        snprintf(prefix, sizeof(prefix), "sd");
        break;
    case DISK_NAMESPACE_NVME:
        snprintf(prefix, sizeof(prefix), "nd");
        break;
    case DISK_NAMESPACE_FLOPPY:
        snprintf(prefix, sizeof(prefix), "fd");
        break;
    case DISK_NAMESPACE_OPTICAL:
        snprintf(prefix, sizeof(prefix), "opt");
        break;
    default:
        return EINVAL;
    }

    snprintf(final_name, sizeof(final_name), "%s%c",
             prefix,
             id_letter);

    return unregister_device(final_name);
}
