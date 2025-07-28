#include "ramfs.h"

#include <memory/heap/kheap.h>

#include <stdio.h>
#include <string.h>

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

// @returns 0 if a node was found
// @returns 1 if a node wasn't found and it has been created
int ramfs_find_or_create_node(ramfs_t *ramfs, char *path,
                              ramfs_ftype_t ramfs_ftype, ramfs_node_t **out) {
    ramfs_node_t *cur_node = ramfs->root_node;

    // use this to check for parents, and eventually create them
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
                continue;
            }

            // we should be fine and we can exit the loop
            break;
        }
    }

    kfree(name_dup);

    if (!cur_node) {
        *out = ramfs_create_node(ramfs_ftype);
        return 1;
    } else {
        *out = cur_node;
    }

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
        kprintf("\t");
    }

    kprintf("%s --- ", node->name);
    switch (node->type) {
    case RAMFS_DIRECTORY:
        kprintf("DIRECTORY\n");
        break;

    case RAMFS_FILE:
        kprintf("SIZE: %zu; BUFFER:%p\n", node->size, node->data);
        break;
    }

    if (node->child) {
        ramfs_print(node->child, lvl + 1);
    }

    if (node->sibling) {
        ramfs_print(node->sibling, lvl);
    }
    return 0;
}