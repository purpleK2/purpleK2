#include "fakefs.h"
#include "fs/vfs/vfs.h"
#include <memory/heap/kheap.h>
#include <stdio.h>
#include <util/string.h>

typedef struct {
    char *content;
    size_t size;
} fake_file_data_t;

static int string_comparator(const void *a, const void *b) {
    return strcmp((const char *)a, (const char *)b);
}

static int fake_lookup(fs_node_t *dir, const char *name, fs_node_t **out) {
    if (!dir || dir->type != VDIR || !dir->children)
        return -1;
    *out = avl_find(dir->children, (void *)name);
    return *out ? 0 : -1;
}

static int fake_read(fs_node_t *node, char *buf, size_t len, size_t offset) {
    if (node->type != VREG || !node->data)
        return -1;
    fake_file_data_t *data = node->data;
    if (offset >= data->size)
        return 0;
    if (offset + len > data->size)
        len = data->size - offset;
    memcpy(buf, data->content + offset, len);
    return len;
}

static int fake_write(fs_node_t *node, const char *buf, size_t len,
                      size_t offset) {
    if (node->type != VREG)
        return -1;
    fake_file_data_t *data = node->data;
    if (!data) {
        data       = kcalloc(1, sizeof(fake_file_data_t));
        node->data = data;
    }

    size_t new_size = offset + len;
    if (new_size > data->size) {
        data->content = krealloc(data->content, new_size);
        data->size    = new_size;
    }

    memcpy(data->content + offset, buf, len);
    return len;
}

static int fake_mkdir(fs_node_t *dir, const char *name, int flags) {
    if (!dir || dir->type != VDIR)
        return -1;
    if (avl_find(dir->children, (void *)name))
        return -1;
    fs_node_t *child = kcalloc(1, sizeof(fs_node_t));
    child->name      = strdup(name);
    child->type      = VDIR;
    child->ops       = dir->ops;
    child->parent    = dir;
    child->children  = avl_create(string_comparator);
    avl_insert(dir->children, child->name, child);
    return 0;
}

static int fake_unlink(fs_node_t *dir, const char *name) {
    if (!dir || dir->type != VDIR)
        return -1;
    fs_node_t *child = avl_find(dir->children, (void *)name);
    if (!child)
        return -1;
    avl_remove(dir->children, (void *)name);
    kfree(child->name);
    if (child->type == VREG && child->data) {
        fake_file_data_t *data = child->data;
        kfree(data->content);
        kfree(data);
    }
    if (child->type == VDIR && child->children) {
        // TODO: recursively free children
    }
    kfree(child);
    return 0;
}

static int fake_stat(fs_node_t *node, stat_t *st) {
    if (!node || !st)
        return -1;
    memset(st, 0, sizeof(stat_t));
    st->st_mode = (node->type == VDIR ? 0040000 : 0100000) | 0777;
    st->st_size = node->type == VREG && node->data
                      ? ((fake_file_data_t *)node->data)->size
                      : 0;
    return 0;
}

static int fake_create_node(fs_vfs_t *vfs, fs_node_t *dir, const char *name,
                            fs_node_type type, int flags) {
    if (!dir || dir->type != VDIR)
        return -1;
    if (avl_find(dir->children, (void *)name))
        return -1;
    fs_node_t *child = kcalloc(1, sizeof(fs_node_t));
    child->name      = strdup(name);
    child->type      = type;
    child->ops       = dir->ops;
    child->parent    = dir;
    if (type == VDIR)
        child->children = avl_create(string_comparator);
    avl_insert(dir->children, child->name, child);
    return 0;
}

static int fakefs_open(fs_node_t *node, fs_open_file_t *file) {
    if (!node || node->type != VREG)
        return -1;
    file->node   = node;
    file->offset = 0;
    file->data   = node->data;
    file->flags  = 0;
    file->len    = node->data ? ((fake_file_data_t *)node->data)->size : 0;
    file->mode   = 0;
    return 0;
}

static int fakefs_close(fs_node_t *node, fs_open_file_t *file) {
    if (!file || !file->node)
        return -1;
    file->node = NULL;
    return 0;
}

static int fakefs_seek(fs_node_t *node, size_t offset, int whence) {
    fs_open_file_t *file = (fs_open_file_t *)node->data;
    if (!file)
        return -1;

    switch (whence) {
    case 0:
        file->offset = offset;
        break;
    case 1:
        file->offset += offset;
        break;
    case 2:
        file->offset = file->len + offset;
        break;
    default:
        return -1;
    }
    return 0;
}

static fs_node_ops_t fake_node_ops = {.open   = fakefs_open,
                                      .close  = fakefs_close,
                                      .read   = fake_read,
                                      .write  = fake_write,
                                      .lookup = fake_lookup,
                                      .mkdir  = fake_mkdir,
                                      .unlink = fake_unlink,
                                      .stat   = fake_stat,
                                      .seek   = fakefs_seek};

static fs_vfs_ops_t fake_vfs_ops = {.create = fake_create_node};

fs_vfs_t *fakefs_create(void) {
    fs_vfs_t *vfs = kcalloc(1, sizeof(fs_vfs_t));
    vfs->type     = FS_TMP;
    vfs->ops      = &fake_vfs_ops;

    fs_node_t *root = kcalloc(1, sizeof(fs_node_t));
    root->name      = strdup("/");
    root->type      = VDIR;
    root->ops       = &fake_node_ops;
    root->vfs       = vfs;
    root->children  = avl_create(string_comparator);

    vfs->root = root;
    return vfs;
}
