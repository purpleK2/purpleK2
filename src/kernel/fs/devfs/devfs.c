#include "devfs.h"

#include <errors.h>
#include <memory/heap/kheap.h>
#include <stdio.h>
#include <string.h>
#include <util/macro.h>

devfs_t *devfs_create() {
    devfs_t *devfs = kmalloc(sizeof(devfs_t));
    if (!devfs) {
        return NULL;
    }

    memset(devfs, 0, sizeof(devfs_t));
    return devfs;
}

devfs_node_t *devfs_create_node(devfs_ftype_t ftype) {
    devfs_node_t *node = kmalloc(sizeof(devfs_node_t));
    if (!node) {
        return NULL;
    }

    memset(node, 0, sizeof(devfs_node_t));
    node->type = ftype;

    return node;
}

int devfs_find_node(devfs_t *devfs, char *path, devfs_node_t **out) {
    // root node here is "/", actual devices are its children
    devfs_node_t *cur_node = devfs->root_node->child;
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
        UNUSED(j);
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

int devfs_node_add(devfs_t *devfs, char *path, devfs_node_t **out) {
    if (!devfs || !devfs->root_node || !path) {
        return ENULLPTR;
    }

    // use this to check for parents, and eventually create them
    if (path[0] == '/') {
        path++;
    }

    char *name_dup = strdup(path);
    char *temp     = name_dup;
    char *dir;

    devfs_node_t *cur_node = devfs->root_node;

    devfs_ftype_t rt;

    // j = level of current node
    for (int j = 0; *temp; j++) {
        UNUSED(j);
        dir = strtok_r(NULL, "/", &temp);

        for (; cur_node != NULL; cur_node = cur_node->sibling) {

            if (*temp) {
                rt = DEVFS_TYPE_DIR;
            } else {
                device_t *dev = device_table[0];
                for (int i = 0; i < device_count; i++) {
                    if (strcmp(device_table[i]->dev_node_path, dir) == 0) {
                        dev = device_table[i];
                        rt  = dev->type == DEVICE_TYPE_BLOCK ? DEVFS_TYPE_BLOCK
                                                             : DEVFS_TYPE_CHAR;
                        break;
                    }
                }
                rt = DEVFS_TYPE_FILE;
            }

            if (strcmp(cur_node->name, dir) != 0) {
                if (cur_node->sibling) {
                    continue;
                }

                // we just create the entries
                devfs_node_t *n = devfs_create_node(rt);
                n->name         = strdup(dir);
                device_t *dev   = device_table[0];
                for (int i = 0; i < device_count; i++) {
                    if (strcmp(device_table[i]->dev_node_path, dir) == 0) {
                        dev = device_table[i];
                        break;
                    }
                }
                n->device = dev;

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
                rt = DEVFS_TYPE_DIR;
            } else {
                device_t *dev = device_table[0];
                for (int i = 0; i < device_count; i++) {
                    if (strcmp(device_table[i]->dev_node_path, dir) == 0) {
                        dev = device_table[i];
                        rt  = dev->type == DEVICE_TYPE_BLOCK ? DEVFS_TYPE_BLOCK
                                                             : DEVFS_TYPE_CHAR;
                        break;
                    }
                }
                rt = DEVFS_TYPE_FILE;
            }

            if (!cur_node->child) {
                devfs_node_t *n = devfs_create_node(rt);
                n->name         = strdup(temp);
                device_t *dev   = device_table[0];
                for (int i = 0; i < device_count; i++) {
                    if (strcmp(device_table[i]->dev_node_path, dir) == 0) {
                        dev = device_table[i];
                        break;
                    }
                }
                n->device = dev;

                devfs_append_child(cur_node, n);
            }

            cur_node = cur_node->child;
        } else {
            *out = cur_node;
        }

        if (!cur_node) {
            return EUNFB;
        }
    }

    return EOK;
}

int devfs_append_child(devfs_node_t *parent, devfs_node_t *child) {
    if (!parent->child) {
        parent->child = child;
        return 0;
    }

    devfs_node_t *last_child;
    for (last_child = parent->child; last_child->sibling != NULL;
         last_child = last_child->sibling)
        ;
    last_child->sibling = child;

    return 0;
}

int devfs_find_or_create_node(devfs_t *devfs, char *path,
                              devfs_ftype_t devfs_ftype, devfs_node_t **out) {

    devfs_node_t *found = NULL;
    devfs_find_node(devfs, path, &found);

    if (!found) {
        *out = devfs_create_node(devfs_ftype);
        return 1;
    }

    *out = found;
    return 0;
}

vnops_t devfs_vnops = {
    .open  = devfs_open,
    .close = devfs_close,

    .read  = devfs_read,
    .write = devfs_write,
    .ioctl = devfs_ioctl,
};

int devfs_vfs_init(devfs_t *ramfs, char *mount_path) {
    if (!ramfs || !mount_path) {
        return ENULLPTR;
    }

    vfs_t *vfs = vfs_mount(ramfs, VFS_DEVFS, mount_path, ramfs);

    if (!vfs) {
        return EUNFB;
    }

    memcpy(vfs->root_vnode->ops, &devfs_vnops, sizeof(vnops_t));

    // create the root node for devfs
    devfs_node_t *root_node = devfs_create_node(DEVFS_TYPE_DIR);
    if (!root_node) {
        return ENOMEM;
    }
    root_node->name = strdup("/");
    if (!root_node->name) {
        kfree(root_node);
        return ENOMEM;
    }
    vfs->root_vnode->node_data = root_node;
    ramfs->root_node           = root_node;
    ramfs->devfs_size          = 0;
    ramfs->root_node->device   = NULL;
    ramfs->root_node->sibling  = NULL;
    ramfs->root_node->child    = NULL;
    ramfs->root_node->type     = DEVFS_TYPE_DIR;

    // loop over devices and add them to the devfs
    for (int i = 0; i < device_count; i++) {
        device_t *dev = device_table[i];
        if (!dev) {
            continue;
        }

        devfs_node_t *devfs_node =
            devfs_create_node(dev->type == DEVICE_TYPE_BLOCK ? DEVFS_TYPE_BLOCK
                                                             : DEVFS_TYPE_CHAR);
        devfs_node->name   = strdup(dev->dev_node_path);
        devfs_node->device = dev;

        if (devfs_append_child(ramfs->root_node, devfs_node) != EOK) {
            return EUNFB;
        }
    }

    return EOK;
}

// add new devices, remove old ones
int devfs_refresh(devfs_t *devfs) {
    if (!devfs || !devfs->root_node) {
        return ENULLPTR;
    }

    devfs_node_t *root = devfs->root_node;

    devfs_node_t *prev = NULL;
    devfs_node_t *cur  = root->child;

    while (cur) {
        devfs_node_t *next = cur->sibling;

        bool still_exists = false;

        for (int i = 0; i < device_count; i++) {
            if (!device_table[i]) {
                continue;
            }

            if (strcmp(device_table[i]->dev_node_path, cur->name) == 0) {
                still_exists = true;
                break;
            }
        }

        if (!still_exists) {
            if (prev) {
                prev->sibling = next;
            } else {
                root->child = next;
            }

            if (cur->name) {
                kfree(cur->name);
            }
            kfree(cur);

            cur = next;
            continue;
        }

        prev = cur;
        cur = next;
    }

    for (int i = 0; i < device_count; i++) {
        device_t *dev = device_table[i];
        if (!dev) {
            continue;
        }

        bool found = false;

        devfs_node_t *node = root->child;
        while (node) {
            if (strcmp(node->name, dev->dev_node_path) == 0) {
                found = true;
                break;
            }
            node = node->sibling;
        }

        if (!found) {
            devfs_node_t *new_node = devfs_create_node(
                dev->type == DEVICE_TYPE_BLOCK ? DEVFS_TYPE_BLOCK : DEVFS_TYPE_CHAR
            );
            if (!new_node) {
                return ENOMEM;
            }

            new_node->name   = strdup(dev->dev_node_path);
            new_node->device = dev;

            if (!new_node->name) {
                kfree(new_node);
                return ENOMEM;
            }

            devfs_append_child(root, new_node);
        }
    }

    return EOK;
}


int devfs_open(vnode_t **vnode_r, int flags, bool clone, fileio_t **fio_out) {
    UNUSED(flags);
    UNUSED(clone);

    // 1. find the file in the DEVFS
    vnode_t *vnode = *vnode_r;
    if (!vnode || !vnode_r) {
        return ENULLPTR;
    }

    // vfs_data should have the root DEVFS struct
    devfs_t *devfs = vnode->root_vfs->vfs_data;

    if (!devfs) {
        return ENULLPTR;
    }

    devfs_node_t *devfs_node;

    devfs_find_node(devfs, vnode->path, &devfs_node);

    if (!devfs_node) {
        if (!(flags & V_CREATE)) {
            return ENOENT;
        }

        // create the node
        if (devfs_node_add(devfs, vnode->path, &devfs_node) != EOK) {
            return EUNFB;
        }
    }

    vnode->node_data = devfs_node;

    fileio_t *fio_file = *fio_out;
    if (!fio_file || !fio_out) {
        return ENOMEM;
    }

    fio_file->buf_start = NULL;
    fio_file->flags |= SPECIAL_FILE_TYPE_DEVICE;
    fio_file->size = 0;

    return EOK;
}

int devfs_close(vnode_t *vnode, int flags, bool clone) {
    UNUSED(flags);
    UNUSED(clone);
    if (!vnode) {
        return ENULLPTR;
    }


    return EOK;
}

int devfs_ioctl(vnode_t *vnode, int request, void *arg) {
    if (!vnode) {
        return ENULLPTR;
    }

    device_t *dev =
        vnode->node_data ? ((devfs_node_t *)vnode->node_data)->device : NULL;

    if (!dev || !dev->ioctl) {
        return ENOIMPL;
    }

    return dev->ioctl(dev, request, arg);
}

int devfs_read(vnode_t *vn, size_t *bytes, size_t *offset, void *out) {
    
    if (!vn || !bytes || !offset || !out) {
        return ENULLPTR;
    }

    device_t *dev = vn->node_data ? ((devfs_node_t *)vn->node_data)->device : NULL;
    
    if (!dev || !dev->read) {
        return ENOIMPL;
    }

    return dev->read(dev, out, *bytes, *offset);
}

int devfs_write(vnode_t *vn, void *buf, size_t *bytes, size_t *offset) {
    if (!vn || !buf || !bytes || !offset) {
        return ENULLPTR;
    }

    device_t *dev =
        vn->node_data ? ((devfs_node_t *)vn->node_data)->device : NULL;

    if (!dev || !dev->write) {
        return ENOIMPL;
    }

    return dev->write(dev, buf, *bytes, *offset);
}

int devfs_print(devfs_node_t *devfs, int lvl) {
    if (!devfs) {
        return -1;
    }

    int a = lvl;

    while (a--) {
        kprintf("  ");
    }

    switch (devfs->type) {
    case DEVFS_TYPE_DIR:
        kprintf("+ %-20s", devfs->name);
        break;

    case DEVFS_TYPE_FILE:
        kprintf("  %-20s", devfs->name);
        kprintf(" | % 10zuB", devfs->device ? 0 : 0);
        break;

    case DEVFS_TYPE_CHAR:
    case DEVFS_TYPE_BLOCK:
        kprintf("  %-20s", devfs->name);
        break;
    }

    kprintf("\n");

    if (devfs->child) {
        devfs_print(devfs->child, lvl + 1);
    }

    if (devfs->sibling) {
        devfs_print(devfs->sibling, lvl);
    }

    return 0;
}
