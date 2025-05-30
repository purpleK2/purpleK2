#include "vfs.h"

#include <memory/heap/kheap.h>

#include <string.h>

static fs_node_t *vfs_root_node = NULL;
static AVLTree *vfs_mount_table = NULL;

static int vfs_mount_compare(const void *a, const void *b) {
    return strcmp((const char *)a, (const char *)b);
}

fs_node_t *vfs_root(void) {
    return vfs_root_node;
}

int vfs_register(fs_vfs_t *vfs) {
    if (!vfs_mount_table)
        vfs_mount_table = avl_create(vfs_mount_compare);
    if (!vfs_root_node && vfs && vfs->root)
        vfs_root_node = vfs->root;
    return 0;
}

int vfs_unregister(fs_vfs_t *vfs) {
    return 0;
}

int vfs_mount(const char *path, fs_vfs_t *vfs, int flags) {
    fs_mount_t *mount = kmalloc(sizeof(fs_mount_t));
    if (!mount)
        return -1;
    mount->vfs    = vfs;
    mount->flags  = flags;
    mount->path   = strdup(path);
    mount->prefix = strdup(path);
    mount->node   = vfs->root;
    if (avl_insert(vfs_mount_table, mount->prefix, mount) != 0) {
        kfree(mount);
        return -1;
    }
    return 0;
}

int vfs_unmount(const char *path) {
    return avl_remove(vfs_mount_table, (void *)path);
}

static fs_mount_t *vfs_resolve_mount(const char *path) {
    AVLNode *node    = avl_first(vfs_mount_table);
    fs_mount_t *best = NULL;
    while (node) {
        fs_mount_t *mount = (fs_mount_t *)avl_node_value(node);
        if (strncmp(path, mount->prefix, strlen(mount->prefix)) == 0) {
            if (!best || strlen(mount->prefix) > strlen(best->prefix)) {
                best = mount;
            }
        }
        node = avl_next(node);
    }
    return best;
}

int vfs_lookup(const char *path, fs_node_t **out) {
    fs_mount_t *mnt = vfs_resolve_mount(path);
    if (!mnt)
        return -1;
    fs_node_t *current = mnt->node;
    char *dup          = strdup(path + strlen(mnt->prefix));
    char *token        = strtok(dup, "/");
    while (token) {
        if (!current->ops || !current->ops->lookup) {
            kfree(dup);
            return -1;
        }
        if (current->ops->lookup(current, token, &current) != 0) {
            kfree(dup);
            return -1;
        }
        token = strtok(NULL, "/");
    }
    *out = current;
    kfree(dup);
    return 0;
}

int vfs_open(const char *path, int flags, fs_open_file_t **out) {
    fs_node_t *node;
    if (vfs_lookup(path, &node) != 0)
        return -1;
    fs_open_file_t *file = kmalloc(sizeof(fs_open_file_t));
    file->node           = node;
    file->offset         = 0;
    file->flags          = flags;
    if (node->ops && node->ops->open)
        node->ops->open(node, file);
    *out = file;
    return 0;
}

int vfs_close(fs_open_file_t *file) {
    if (file->node->ops && file->node->ops->close)
        file->node->ops->close(file->node, file);
    kfree(file);
    return 0;
}

int vfs_read(fs_open_file_t *file, void *buf, size_t len) {
    if (!file->node->ops || !file->node->ops->read)
        return -1;
    int r = file->node->ops->read(file->node, buf, len, file->offset);
    if (r > 0)
        file->offset += r;
    return r;
}

int vfs_write(fs_open_file_t *file, const void *buf, size_t len) {
    if (!file->node->ops || !file->node->ops->write)
        return -1;
    int w = file->node->ops->write(file->node, buf, len, file->offset);
    if (w > 0)
        file->offset += w;
    return w;
}

int vfs_seek(fs_open_file_t *file, size_t offset, int whence) {
    if (!file->node->ops || !file->node->ops->seek)
        return -1;
    return file->node->ops->seek(file->node, offset, whence);
}

int vfs_stat(const char *path, stat_t *st) {
    fs_node_t *node;
    if (vfs_lookup(path, &node) != 0)
        return -1;
    if (!node->ops || !node->ops->stat)
        return -1;
    return node->ops->stat(node, st);
}

int vfs_mkdir(const char *path, int flags) {
    fs_node_t *dir;
    char *dup  = strdup(path);
    char *base = strrchr(dup, '/');
    if (!base || base == dup)
        return -1;
    *base = 0;
    base++;
    if (vfs_lookup(dup, &dir) != 0) {
        kfree(dup);
        return -1;
    }
    if (!dir->ops || !dir->ops->mkdir) {
        kfree(dup);
        return -1;
    }
    int res = dir->ops->mkdir(dir, base, flags);
    kfree(dup);
    return res;
}

int vfs_unlink(const char *path) {
    fs_node_t *dir;
    char *dup  = strdup(path);
    char *base = strrchr(dup, '/');
    if (!base || base == dup)
        return -1;
    *base = 0;
    base++;
    if (vfs_lookup(dup, &dir) != 0) {
        kfree(dup);
        return -1;
    }
    if (!dir->ops || !dir->ops->unlink) {
        kfree(dup);
        return -1;
    }
    int res = dir->ops->unlink(dir, base);
    kfree(dup);
    return res;
}

int vfs_rename(const char *oldpath, const char *newpath) {
    fs_node_t *old_dir, *new_dir;
    char *old      = strdup(oldpath);
    char *new      = strdup(newpath);
    char *old_base = strrchr(old, '/');
    char *new_base = strrchr(new, '/');
    if (!old_base || !new_base)
        return -1;
    *old_base = 0;
    *new_base = 0;
    old_base++;
    new_base++;
    if (vfs_lookup(old, &old_dir) != 0 || vfs_lookup(new, &new_dir) != 0) {
        kfree(old);
        kfree(new);
        return -1;
    }
    if (!old_dir->ops || !old_dir->ops->rename) {
        kfree(old);
        kfree(new);
        return -1;
    }
    int res = old_dir->ops->rename(old_dir, old_base, new_dir, new_base);
    kfree(old);
    kfree(new);
    return res;
}

int vfs_sync(void) {
    AVLNode *node = avl_first(vfs_mount_table);
    while (node) {
        fs_mount_t *mnt = avl_node_value(node);
        if (mnt->vfs && mnt->vfs->ops && mnt->vfs->ops->sync)
            mnt->vfs->ops->sync(mnt->vfs);
        node = avl_next(node);
    }
    return 0;
}

int vfs_create(const char *path, fs_node_type type, int flags) {
    fs_node_t *parent;
    char *dup  = strdup(path);
    char *name = strrchr(dup, '/');
    if (!name || name == dup) {
        kfree(dup);
        return -1;
    }
    *name = 0;
    name++;
    if (strlen(name) == 0) {
        kfree(dup);
        return -1;
    }
    if (vfs_lookup(dup, &parent) != 0) {
        kfree(dup);
        return -1;
    }
    if (parent->vfs && parent->vfs->ops && parent->vfs->ops->create) {
        if (parent->vfs->ops->create(parent->vfs, parent, name, type, flags) !=
            0) {
            kfree(dup);
            return -1;
        }
    } else {
        kfree(dup);
        return -1;
    }
    kfree(dup);
    return 0;
}