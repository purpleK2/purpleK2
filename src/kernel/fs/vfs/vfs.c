#include "vfs.h"

#include <memory/heap/kheap.h>

#include <string.h>

#include <errors.h>

vfs_t *vfs_list = NULL;

vfs_t *vfs_create(vfs_fstype_t fs_type, void *fs_data) {
    vfs_t *vfs = kmalloc(sizeof(vfs_t));
    memset(vfs, 0, sizeof(vfs_t));

    vfs->fs_type = fs_type;

    vfs->ops = kmalloc(sizeof(vfsops_t));
    memset(vfs->ops, 0, sizeof(vfsops_t));

    // vfs->root_vnode = vnode_create(root_path, NULL);

    vfs->vfs_data = fs_data;

    return vfs;
}

int vfs_mount(vfs_t *vfs, char *path, void *rootvn_data) {
    if (!vfs) {
        return ENULLPTR;
    }

    vfs->root_vnode           = vnode_create(path, rootvn_data);
    vfs->root_vnode->root_vfs = vfs;

    return EOK;
}

int vfs_append(vfs_t *vfs) {
    if (!vfs_list) {
        vfs_list = vfs;
    }

    vfs_t *v;
    for (v = vfs_list; v->next != NULL; v = v->next)
        ;

    v->next = vfs;

    return EOK;
}

vnode_t *vnode_create(char *path, void *data) {
    vnode_t *vnode = kmalloc(sizeof(vnode_t));
    memset(vnode, 0, sizeof(vnode_t));

    vnode->path = strdup(path);

    vnode->ops = kmalloc(sizeof(vnops_t));
    memset(vnode->ops, 0, sizeof(vnops_t));

    return vnode;
}

int vfs_open(vfs_t *vfs, char *path, int flags, vnode_t **out) {
    vnode_t *file = vnode_create(path, NULL);

    file->root_vfs = vfs;
    memcpy(file->ops, vfs->root_vnode->ops, sizeof(vnops_t));

    *out = file;

    return vfs->root_vnode->ops->open(out, flags, false);
}

int vfs_read(vnode_t *vnode, size_t size, size_t offset, void *out) {
    return vnode->ops->read(vnode, size, offset, out);
}

int vfs_write(vnode_t *vnode, void *buf, size_t size, size_t offset) {
    return vnode->ops->write(vnode, buf, size, offset);
}

int vfs_close(vnode_t *vnode) {
    return vnode->ops->close(vnode, 0, false);
}