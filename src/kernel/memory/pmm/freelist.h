#ifndef FREELIST_H
#define FREELIST_H 1

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <limine.h>

typedef struct freelist_node {
    size_t length; // length is in bytes

    struct freelist_node *next;
} flnode_t;

flnode_t *pmm_node_create(LIMINE_PTR(struct limine_memmap_entry *)
                              memmap_entry);

void fl_append(flnode_t **root, flnode_t *node);

#endif
