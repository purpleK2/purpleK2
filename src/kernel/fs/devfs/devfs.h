#ifndef DEVFS_H
#define DEVFS_H 1

#include <dev/device.h>
#include <fs/file_io.h>
#include <fs/vfs/vfs.h>

typedef enum devfs_ftype {
    DEVFS_TYPE_DIR,
    DEVFS_TYPE_CHAR,
    DEVFS_TYPE_BLOCK,
    DEVFS_TYPE_FILE,
} devfs_ftype_t;

typedef struct devfs_node {
    char *name;

    devfs_ftype_t type;

    device_t *device;

    struct devfs_node *sibling;
    struct devfs_node *child;
} devfs_node_t;

typedef struct devfs {
    struct devfs_node *root_node;

    size_t devfs_size; // node count?
} devfs_t;

devfs_t *devfs_create();
devfs_node_t *devfs_create_node(devfs_ftype_t ftype);
int devfs_find_node(devfs_t *devfs, char *path, devfs_node_t **out);
int devfs_find_or_create_node(devfs_t *ramfs, char *path,
                              devfs_ftype_t ramfs_ftype, devfs_node_t **out);

int devfs_append_child(devfs_node_t *parent, devfs_node_t *child);
int devfs_node_add(devfs_t *ramfs, char *path, devfs_node_t **out);

int devfs_vfs_init(devfs_t *ramfs, char *mount_path);

int devfs_print(devfs_node_t *devfs, int lvl);

int devfs_open(vnode_t **vnode_r, int flags, bool clone, fileio_t **fio_out);
int devfs_close(vnode_t *vnode, int flags, bool clone);

int devfs_ioctl(vnode_t *vnode, int request, void *arg);
int devfs_read(vnode_t *vn, size_t *bytes, size_t *offset, void *out);
int devfs_write(vnode_t *vn, void *buf, size_t *bytes, size_t *offset);

#endif // DEVFS_H
