/*
        Freelist memory allocator/manager

        (C) RepubblicaTech 2024
*/

#include "pmm.h"

#include <kernel.h>
#include <limine.h>

#include <util/string.h>
#include <util/util.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#include <spinlock.h>

#include <autoconf.h>

lock_t PMM_LOCK;

int usable_entry_count;

extern struct limine_memmap_response *memmap_response;
extern void _hcf();

freelist_node *fl_head;

void pmm_init() {
    // array of nodes (used only on initialization)
    freelist_node *fl_nodes[limine_parsed_data.usable_entry_count];

    usable_entry_count = 0;
    for (uint64_t i = 0; i < memmap_response->entry_count; i++) {
        struct limine_memmap_entry *memmap_entry = memmap_response->entries[i];

        if (memmap_entry->type != LIMINE_MEMMAP_USABLE)
            continue;

        usable_entry_count++;
    }
    // create a freelist entry that points to the start of each usable address
    // and link them
    // @note temp is a temporary counter for the fl_nodes array
    for (uint64_t i = 0, temp = 0; i < memmap_response->entry_count; i++) {
        struct limine_memmap_entry *memmap_entry = memmap_response->entries[i];

        if (memmap_entry->type != LIMINE_MEMMAP_USABLE)
            continue;

        freelist_node *fl_node =
            (freelist_node *)PHYS_TO_VIRTUAL(memmap_entry->base);
        fl_node->length = memmap_entry->length;

        if (temp == 0)
            fl_head = fl_node;

        fl_nodes[temp] = fl_node;

        temp++;
    }

    for (int i = 0; i < usable_entry_count; i++) {
        if (i < usable_entry_count - 1) {
            fl_nodes[i]->next = fl_nodes[i + 1];
        } else {
            fl_nodes[i]->next = NULL;
        }
    }

    kprintf_info("Found %d usable regions\n", usable_entry_count);

    // prints all nodes
    for (freelist_node *fl_node = fl_head; fl_node != NULL;
         fl_node                = fl_node->next) {
        debugf_debug("ENTRY n. %p\n", fl_node);
        debugf_debug("\tlength: %llx\n", fl_node->length);
        debugf_debug("\tnext: %p\n", fl_node->next);
    }
}

// Returns the count of the entries.
int get_freelist_entry_count() {
    return usable_entry_count;
}

/*
        "Refreshes" the list of entries

        @returns head of nodes
*/
freelist_node *fl_update_nodes() {
    usable_entry_count = 0;
    for (freelist_node *i = fl_head; i != NULL;
         i                = i->next, usable_entry_count++)
        ;

    return fl_head;
}

int pmm_allocs = 0; // keeping track of how many times pmm_alloc was called
int pmm_frees  = 0; // keeping track of how many times pmm_free was called

// Omar, this is a PAGE FRAME allocator no need for custom <bytes> parameter
void *pmm_alloc_page() {
    pmm_allocs++;
#ifdef CONFIG_PMM_DEBUG
    debugf_debug("--- Allocation n.%d ---\n", pmm_allocs);
#endif

    void *ptr = NULL;
    freelist_node *cur_node;
    for (cur_node = fl_head; cur_node != NULL; cur_node = cur_node->next) {
#ifdef CONFIG_PMM_DEBUG
        debugf_debug("Looking for available memory at address %p\n", cur_node);
#endif

        if (cur_node->length >= PFRAME_SIZE)
            break;

// if not, go to the next block
#ifdef CONFIG_PMM_DEBUG
        debugf_debug("Not enough memory found at %p. Going on...", cur_node);
#endif
    }

    // if we've got here and nothing was found, then kernel panic
    if (cur_node == NULL) {
        kprintf_panic("OUT OF MEMORY!!\n");
        _hcf();
    }

#ifdef CONFIG_PMM_DEBUG
    debugf_debug("allocated %lu byte%sat address %p\n", PFRAME_SIZE,
                 PFRAME_SIZE > 1 ? "s " : " ", cur_node);
#endif

    ptr = (void *)(cur_node);

    if (cur_node->length - PFRAME_SIZE <= 0) {
        fl_head = fl_head->next;
    } else {
        // we'll "increment" that node
        freelist_node *new_node = (ptr + PFRAME_SIZE);
        new_node->length        = (cur_node->length - PFRAME_SIZE);
        new_node->next          = cur_node->next;
        fl_head                 = new_node;
    }

    fl_update_nodes();

#ifdef CONFIG_PMM_DEBUG
    debugf_debug("old head %p is now %p\n", ptr, fl_head);
    debugf_debug("\tsize: %zx\n", fl_head->length);
    debugf_debug("\tnext: %p\n", fl_head->next);
#endif

    // zero out the whole allocated region
    memset((void *)ptr, 0, PFRAME_SIZE);

    // we need the physical address of the free entry
    return (void *)VIRT_TO_PHYSICAL(ptr);
}

void *pmm_alloc_pages(size_t pages) {
    void *ptr = pmm_alloc_page();
    for (size_t i = 1; i < pages; i++) {
        pmm_alloc_page();
    }

    return ptr;
}

void pmm_free(void *ptr, size_t pages) {
    pmm_frees++;
#ifdef CONFIG_PMM_DEBUG
    debugf_debug("--- Deallocation n.%d ---\n", pmm_frees);

    debugf_debug("deallocating address range %p-%p\n\n", ptr,
                 ptr + (pages * PFRAME_SIZE));
#endif

    freelist_node *fl_deallocated = (freelist_node *)PHYS_TO_VIRTUAL(ptr);
    fl_deallocated->length        = PFRAME_SIZE * pages;
    fl_deallocated->next          = NULL;

    // add the node to end of list

    freelist_node *fl_last = NULL;
    for (fl_last = fl_head; fl_last->next != NULL; fl_last = fl_last->next)
        ;

    fl_last->next = fl_deallocated;
}
