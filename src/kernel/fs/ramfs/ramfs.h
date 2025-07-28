#ifndef RAMFS_H
#define RAMFS_H 1

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
} ramfs_t;

ramfs_t *ramfs_create();
ramfs_node_t *ramfs_create_node(ramfs_ftype_t ftype);

int ramfs_find_or_create_node(ramfs_t *ramfs, char *path,
                              ramfs_ftype_t ramfs_ftype, ramfs_node_t **out);

int ramfs_append_child(ramfs_node_t *parent, ramfs_node_t *child);

int ramfs_print(ramfs_node_t *node, int lvl);

#endif