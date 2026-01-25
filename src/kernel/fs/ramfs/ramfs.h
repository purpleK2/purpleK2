
#ifndef RAMFS_H
#define RAMFS_H 1
#include <fs/vfs/vfs.h>
#include <stdbool.h>
#include <stddef.h>

typedef enum ramfs_ftype {
    RAMFS_FILE,
    RAMFS_DIRECTORY,
    RAMFS_SYMLINK
} ramfs_ftype_t;

typedef struct ramfs_node {
    char *name;
    ramfs_ftype_t type;
    size_t size;
    void *data;

    int mode;

    struct ramfs_node *sibling;
    struct ramfs_node *child;
} ramfs_node_t;

typedef struct ramfs {
    ramfs_node_t *root_node;
    size_t ramfs_size;
} ramfs_t;

ramfs_t *ramfs_create_fs();
ramfs_node_t *ramfs_create_node(ramfs_ftype_t ftype);
int ramfs_find_node(ramfs_t *ramfs, char *path, ramfs_node_t **out);
int ramfs_find_or_create_node(ramfs_t *ramfs, char *path,
                              ramfs_ftype_t ramfs_ftype, ramfs_node_t **out);
int ramfs_append_child(ramfs_node_t *parent, ramfs_node_t *child);
int ramfs_node_add(ramfs_t *ramfs, char *path, ramfs_node_t **out);
int ramfs_print(ramfs_node_t *node, int lvl);

void ramfs_init(void);
int ramfs_vfs_init(ramfs_t *ramfs, char *mount_path);

int ramfs_open(vnode_t **vnode_r, int flags, bool clone, fileio_t **fio_out);
int ramfs_close(vnode_t *vnode, int flags, bool clone);
int ramfs_read(vnode_t *vn, size_t *bytes, size_t *offset, void *out);
int ramfs_write(vnode_t *vn, void *buf, size_t *bytes, size_t *offset);
int ramfs_ioctl(vnode_t *vnode, int request, void *arg);
int ramfs_lookup(vnode_t *parent, const char *name, vnode_t **out);
int ramfs_readdir(vnode_t *vnode, dirent_t *entries, size_t *count);
int ramfs_readlink(vnode_t *vnode, char *buf, size_t size);
int ramfs_mkdir(vnode_t *parent, const char *name, int mode);
int ramfs_rmdir(vnode_t *parent, const char *name);
int ramfs_create(vnode_t *parent, const char *name, mode_t mode, vnode_t **out);
int ramfs_remove(vnode_t *parent, const char *name);
int ramfs_symlink(vnode_t *parent, const char *name, const char *target);

#endif
