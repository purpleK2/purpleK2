#include "freelist.h"

#include <memory/pmm/pmm.h>
#include <string.h>

flnode_t *pmm_node_create(LIMINE_PTR(struct limine_memmap_entry *)
                              memmap_entry) {

    if (!memmap_entry) {
        return NULL;
    }

    flnode_t *fl_node = (flnode_t *)PHYS_TO_VIRTUAL(memmap_entry->base);
    memset(fl_node, 0, sizeof(flnode_t));

    fl_node->length = memmap_entry->length;

    return fl_node;
}

void fl_append(flnode_t **root, flnode_t *node) {
    if (!root || !node) {
        return;
    }

    if (!(*root)) {
        *root = node;
        return;
    }

    for (flnode_t *f = *root; f != NULL; f = f->next) {
        if (!f->next) {
            f->next = node;
            return;
        }
    }
}