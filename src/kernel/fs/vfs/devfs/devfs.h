/*#ifndef VFS_DEVFS_H
#define VFS_DEVFS_H

#include "dev/device.h"
#include <fs/vfs/vfs.h>

int devfs_read(vnode_t *vnode, void *buf, size_t size, size_t offset);
int devfs_write(vnode_t *vnode, const void *buf, size_t size, size_t offset);

int devfs_add_dev(device_t *dev);

void devfs_init();

#endif // VFS_DEVFS_H*/