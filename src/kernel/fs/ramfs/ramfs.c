#include "ramfs.h"

#include <memory/heap/kheap.h>

#include <stdio.h>
#include <string.h>

#include <errors.h>

#include <util/macro.h>

#include <fs/file_io.h>

ramfs_t *ramfs_create() {
    ramfs_t *ramfs = kmalloc(sizeof(ramfs_t));
    memset(ramfs, 0, sizeof(ramfs_t));
    return ramfs;
}

ramfs_node_t *ramfs_create_node(ramfs_ftype_t ftype) {
    ramfs_node_t *node = kmalloc(sizeof(ramfs_node_t));
    memset(node, 0, sizeof(ramfs_node_t));

    node->type = ftype;

    return node;
}

int ramfs_find_node(ramfs_t *ramfs, char *path, ramfs_node_t **out) {
    ramfs_node_t *cur_node = ramfs->root_node;
    *out                   = NULL;

    // use this to check for parents, and eventually create them
    if (path[0] == '/') {
        path++;
    }

    char *name_dup = strdup(path);
    char *temp     = name_dup;
    char *dir;

    // j = level of current node
    for (int j = 0; *temp; j++) {
        dir = strtok_r(NULL, "/", &temp);

        for (; cur_node != NULL; cur_node = cur_node->sibling) {
            if (strcmp(cur_node->name, dir) != 0)
                continue;

            // if there's more to parse, go to the child
            if (*temp) {
                cur_node = cur_node->child;
                break;
            }

            // we should be fine and we can exit the loop
            break;
        }
    }

    kfree(name_dup);

    *out = cur_node;

    if (!cur_node) {
        return -1;
    }

    return 0;
}

// @param path the path of the node that needs to be created
// @param out the node that represents the given path
int ramfs_node_add(ramfs_t *ramfs, char *path, ramfs_node_t **out) {
    if (!ramfs || !ramfs->root_node || !path) {
        return ENULLPTR;
    }

    // use this to check for parents, and eventually create them
    if (path[0] == '/') {
        path++;
    }

    char *name_dup = strdup(path);
    char *temp     = name_dup;
    char *dir;

    ramfs_node_t *cur_node = ramfs->root_node;

    ramfs_ftype_t rt;

    // j = level of current node
    for (int j = 0; *temp; j++) {
        dir = strtok_r(NULL, "/", &temp);

        for (; cur_node != NULL; cur_node = cur_node->sibling) {

            if (*temp) {
                rt = RAMFS_DIRECTORY;
            } else {
                rt = RAMFS_FILE;
            }

            if (strcmp(cur_node->name, dir) != 0) {
                if (cur_node->sibling) {
                    continue;
                }

                // we just create the entries
                ramfs_node_t *n = ramfs_create_node(rt);
                n->name         = strdup(dir);

                continue;
            }

            if (cur_node->type != rt) {
                continue;
            }

            // we should be fine and we can exit the loop
            break;
        }

        // go to the child
        if (*temp) {
            if (strchr(temp, '/')) {
                rt = RAMFS_DIRECTORY;
            } else {
                rt = RAMFS_FILE;
            }

            if (!cur_node->child) {
                ramfs_node_t *n = ramfs_create_node(rt);
                n->name         = strdup(temp);

                ramfs_append_child(cur_node, n);
            }

            cur_node = cur_node->child;
        } else {
            *out = cur_node;
        }

        if (!cur_node) {
            // something went really wrong lol
            return EUNFB;
        }
    }

    return EOK;
}

// @returns 0 if a node was found
// @returns 1 if a node wasn't found and it has been created
int ramfs_find_or_create_node(ramfs_t *ramfs, char *path,
                              ramfs_ftype_t ramfs_ftype, ramfs_node_t **out) {

    ramfs_node_t *found = NULL;
    ramfs_find_node(ramfs, path, &found);

    if (!found) {
        *out = ramfs_create_node(ramfs_ftype);
        return 1;
    }

    *out = found;
    return 0;
}

// appends a node to a list of a parent's children
int ramfs_append_child(ramfs_node_t *parent, ramfs_node_t *child) {
    if (!parent->child) {
        parent->child = child;
        return 0;
    }

    ramfs_node_t *last_child;
    for (last_child = parent->child; last_child->sibling != NULL;
         last_child = last_child->sibling)
        ;
    last_child->sibling = child;

    return 0;
}

int ramfs_print(ramfs_node_t *node, int lvl) {
    if (!node) {
        return -1;
    }

    int a = lvl;

    while (a--) {
        kprintf("  ");
    }

    switch (node->type) {
    case RAMFS_DIRECTORY:
        kprintf("+ %-20s", node->name);
        break;

    case RAMFS_FILE:
        kprintf("  %-20s", node->name);
        kprintf(" | % 10zuB", node->size, node->data);
        break;
    }

    kprintf("\n");

    if (node->child) {
        ramfs_print(node->child, lvl + 1);
    }

    if (node->sibling) {
        ramfs_print(node->sibling, lvl);
    }
    return 0;
}

size_t ramfs_get_node_size(ramfs_node_t *node) {
    if (!node) {
        return ENULLPTR;
    }

    size_t s;

    switch (node->type) {
    case RAMFS_FILE:
        s = node->size;
        break;

    case RAMFS_DIRECTORY:
        for (ramfs_node_t *n = node->child; n != NULL; n = n->sibling) {
            s += ramfs_get_node_size(n);
        }

        break;
    }

    return s;
}

// VFS operations

// VNODE operations

int ramfs_open(vnode_t **vnode_r, int flags, bool clone, fileio_t **fio_out) {
    UNUSED(flags);
    UNUSED(clone);

    // TODO: flags
    // TODO: clone

    // 1. find the file in the RAMFS

    vnode_t *vnode = *vnode_r;
    if (!vnode || !vnode_r) {
        return ENULLPTR;
    }

    // vfs_data should have the root RAMFS struct
    ramfs_t *ramfs = vnode->root_vfs->vfs_data;

    if (!ramfs) {
        return ENULLPTR;
    }

    ramfs_node_t *ramfs_node;

    ramfs_find_node(ramfs, vnode->path, &ramfs_node);

    if (!ramfs_node) {
        if (!(flags & V_CREATE)) {
            return ENOENT;
        }

        // create the node
        if (ramfs_node_add(ramfs, vnode->path, &ramfs_node) != EOK) {
            return EUNFB;
        }

        if (ramfs_node->type == RAMFS_FILE) {
            ramfs_node->size = 10; // give it a size to start
        }
    }

    // this is the RAMFS node to be attached to the vnode
    ramfs_node_t *v_ramfs_node = kmalloc(sizeof(ramfs_node_t));
    memcpy(v_ramfs_node, ramfs_node, sizeof(ramfs_node_t));

    // 2. create a buffer for the file (do not use the original file buffer)

    v_ramfs_node->size = ramfs_get_node_size(ramfs_node);
    v_ramfs_node->data = kmalloc(v_ramfs_node->size);

    if (v_ramfs_node->type == RAMFS_DIRECTORY) {
        // TODO

        // 03/08/2025: there's nothing to do i think, but i'll keep it here just
        // in case
    } else {
        memcpy(v_ramfs_node->data, ramfs_node->data, v_ramfs_node->size);
    }

    v_ramfs_node->child   = NULL;
    v_ramfs_node->sibling = NULL;

    vnode->node_data = v_ramfs_node;

    fileio_t *fio = *fio_out;
    if (!fio || !fio_out) {
        return ENULLPTR;
    }

    fio->buf_start = v_ramfs_node->data;
    fio->size      = v_ramfs_node->size;

    return EOK;
}

int ramfs_read(vnode_t *vn, size_t *bytes, size_t *offset, void *out) {
    if (!vn) {
        return ENULLPTR;
    }

    memset(out, 0, (*bytes));

    ramfs_node_t *ramfs_node = vn->node_data;
    if (!ramfs_node) {
        return ENULLPTR;
    }

    if ((*bytes) > ramfs_node->size) {
        (*bytes) = ramfs_node->size;
    } else if ((*offset) >= ramfs_node->size) {
        return ENOCFG;
    }

    if ((*bytes) + (*offset) > ramfs_node->size) {
        // read whatever remains that can be copied
        (*bytes) = (ramfs_node->size - (*offset));
    }

    void *src = ramfs_node->data + (*offset);

    memcpy(out, src, (*bytes));

    return EOK;
}

int ramfs_write(vnode_t *vn, void *buf, size_t *bytes, size_t *offset) {
    if (!vn) {
        return ENULLPTR;
    }

    ramfs_node_t *ramfs_node = vn->node_data;
    if (!ramfs_node) {
        return ENULLPTR;
    }

    if ((*bytes) + (*offset) > ramfs_node->size) {
        // we need to do some relocation
        size_t more = ((*bytes) + (*offset)) - ramfs_node->size;

        void *new_data    = krealloc(ramfs_node->data, ramfs_node->size + more);
        ramfs_node->data  = new_data;
        ramfs_node->size += more;
    }

    void *dst = ramfs_node->data + (*offset);

    memcpy(dst, buf, (*bytes));

    return EOK;
}

int ramfs_close(vnode_t *vnode, int flags, bool clone) {
    UNUSED(flags);
    UNUSED(clone);

    // TODO: flags
    // TODO: clone

    if (!vnode) {
        return ENULLPTR;
    }

    ramfs_node_t *ramfs_node = vnode->node_data;
    if (!ramfs_node) {
        return ENULLPTR;
    }

    // we'll sync the new buffer

    ramfs_t *ramfs = vnode->root_vfs->vfs_data;
    if (!ramfs) {
        return ENULLPTR;
    }

    ramfs_node_t *ramfs_node_original;
    ramfs_find_node(ramfs, vnode->path, &ramfs_node_original);

    if (!ramfs_node_original) {
        return ENOENT; // this file is probably not ours
    }

    if (ramfs_node_original->data != ramfs_node->data) {
        kfree(ramfs_node_original->data);
        // the old node points to the (probably updated) data
        ramfs_node_original->data = ramfs_node->data;
        ramfs_node_original->size = ramfs_node->size;
    }

    // get rid of the RAMFS node on vnode
    kfree(vnode->node_data);

    return EOK;
}

int ramfs_ioctl(vnode_t *vnode, int request, void *arg) {
    if (!vnode) {
        return ENULLPTR;
    }

    UNUSED(request);
    UNUSED(arg);

    return ENOIMPL;
}

vnops_t ramfs_vnops = {
    .open  = ramfs_open,
    .close = ramfs_close,

    .read  = ramfs_read,
    .write = ramfs_write,
    .ioctl = ramfs_ioctl,
};

int ramfs_vfs_init(ramfs_t *ramfs, char *path) {
    if (!ramfs || !path) {
        return ENULLPTR;
    }

    vfs_t *vfs = vfs_mount(ramfs, VFS_RAMFS, path, ramfs);

    memcpy(vfs->root_vnode->ops, &ramfs_vnops, sizeof(vnops_t));

    return 0;
}
