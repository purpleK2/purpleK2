#ifndef RAMFS_H
#define RAMFS_H 1

#include <fs/vfs/vfs.h>

#include <stdbool.h>
#include <stddef.h>

typedef enum ramfs_ftype {
    RAMFS_FILE,
    RAMFS_DIRECTORY
} ramfs_ftype_t;

typedef struct ramfs_node {
    char *name;

    ramfs_ftype_t type;

    size_t size;
    void *data;

    struct ramfs_node *sibling;
    struct ramfs_node *child;
} ramfs_node_t;

// basically the "/"
typedef struct ramfs {
    ramfs_node_t *root_node; // the first file in the RAMFS

    size_t ramfs_size; // the total size of the files in RAMFS
} ramfs_t;

ramfs_t *ramfs_create();
ramfs_node_t *ramfs_create_node(ramfs_ftype_t ftype);
int ramfs_find_node(ramfs_t *ramfs, char *path, ramfs_node_t **out);
int ramfs_find_or_create_node(ramfs_t *ramfs, char *path,
                              ramfs_ftype_t ramfs_ftype, ramfs_node_t **out);

int ramfs_append_child(ramfs_node_t *parent, ramfs_node_t *child);
int ramfs_node_add(ramfs_t *ramfs, char *path, ramfs_node_t **out);

int ramfs_print(ramfs_node_t *node, int lvl);

int ramfs_vfs_init(ramfs_t *ramfs, char *mount_path);

int ramfs_open(vnode_t **vnode_r, int flags, bool clone, fileio_t **fio_out);
int ramfs_close(vnode_t *vnode, int flags, bool clone);

int ramfs_read(vnode_t *vn, size_t *bytes, size_t *offset, void *out);
int ramfs_write(vnode_t *vn, void *buf, size_t *bytes, size_t *offset);

#endif