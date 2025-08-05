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

    vfs_append(vfs);

    return vfs;
}

vfs_t *vfs_mount(void *fs, vfs_fstype_t fs_type, char *path,
                 void *rootvn_data) {
    if (!fs) {
        return NULL;
    }

    vfs_t *vfs = vfs_create(fs_type, fs);

    vfs_t *rootvfs; // the vfs in which the mountpoint resides
    if (vfs_resolve_mount(path, &rootvfs) != EOK) {
        rootvfs = vfs;
    }

    vfs->root_vnode           = vnode_create(rootvfs, path, rootvn_data);
    // the vfs in which the new filesystem resides
    vfs->root_vnode->vfs_here = vfs;

    return vfs;
}

int vfs_append(vfs_t *vfs) {
    if (!vfs_list) {
        vfs_list = vfs;
        return EOK;
    }

    vfs_t *v;
    for (v = vfs_list; v->next != NULL; v = v->next)
        ;

    v->next = vfs;

    return EOK;
}

vnode_t *vnode_create(vfs_t *root_vfs, char *path, void *data) {
    vnode_t *vnode = kmalloc(sizeof(vnode_t));
    memset(vnode, 0, sizeof(vnode_t));

    vnode->path = strdup(path);

    vnode->root_vfs  = root_vfs;
    vnode->node_data = data;

    vnode->ops = kmalloc(sizeof(vnops_t));
    memset(vnode->ops, 0, sizeof(vnops_t));

    return vnode;
}

int vfs_resolve_mount(char *path, vfs_t **out) {
    vfs_t *v = vfs_list;
    for (; v != NULL; v = v->next) {
        if (!v->root_vnode) {
            return ENULLPTR;
        }

        char *prefix = v->root_vnode->path;

        // this way we are sure it compares all of the mnt prefix string
        if (strncmp(path, prefix, strlen(prefix)) == 0) {
            *out = v;
            break;
        }
    }

    if (!v) {
        return ENOENT;
    }

    return EOK;
}

int vfs_open(vfs_t *vfs, char *path, int flags, fileio_t **out) {
    vnode_t *vn_file  = vnode_create(vfs, path, NULL);
    vn_file->vfs_here = vfs;
    memcpy(vn_file->ops, vfs->root_vnode->ops, sizeof(vnops_t));
    // ignore the mountpoint part
    vn_file->path += strlen(vfs->root_vnode->path);

    fileio_t *fio_file = fio_create();

    if (vn_file->ops->open(&vn_file, flags, false, &fio_file) != EOK) {
        kfree(vn_file->path);
        kfree(vn_file);
        return ENOENT;
    }

    fio_file->private = vn_file;

    *out = fio_file;

    // put it back just in case
    vn_file->path -= strlen(vfs->root_vnode->path);

    return EOK;
}

int vfs_read(vnode_t *vnode, size_t size, size_t offset, void *out) {
    if (!vnode) {
        return ENULLPTR;
    }

    int ret = vnode->ops->read(vnode, &size, &offset, out);

    return ret;
}

int vfs_write(vnode_t *vnode, void *buf, size_t size, size_t offset) {
    if (!vnode) {
        return ENULLPTR;
    }

    int ret = vnode->ops->write(vnode, buf, &size, &offset);

    return ret;
}

int vfs_close(vnode_t *vnode) {
    if (!vnode) {
        return ENULLPTR;
    }

    int r = vnode->ops->close(vnode, 0, false);

    if (r != EOK) {
        return r;
    }

    kfree(vnode);

    return EOK;
}
