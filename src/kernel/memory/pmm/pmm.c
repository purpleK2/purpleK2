/*
        Freelist memory allocator/manager

        (C) RepubblicaTech 2024
*/

#include "pmm.h"

#include <autoconf.h>
#include <kernel.h>
#include <limine.h>
#include <spinlock.h>
#include <util/util.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include <stdatomic.h>

atomic_flag PMM_LOCK = ATOMIC_FLAG_INIT;

extern void _hcf();

flnode_t *pmm_headnode = NULL;
int usable_entry_count = 0;

void pmm_init(LIMINE_PTR(struct limine_memmap_response *) memmap_response) {
    if (!memmap_response) {
        kprintf_panic("No memmap response given!\n");
    }

    usable_entry_count = 0;
    for (uint64_t i = 0; i < memmap_response->entry_count; i++) {
        struct limine_memmap_entry *memmap_entry = memmap_response->entries[i];

        if (memmap_entry->type != LIMINE_MEMMAP_USABLE)
            continue;

        flnode_t *fl_node = pmm_node_create(memmap_entry);

        fl_append(&pmm_headnode, fl_node);

        usable_entry_count++;
    }

    kprintf_info("Found %d usable regions\n", usable_entry_count);

    // prints all nodes
    for (flnode_t *fl_node = pmm_headnode; fl_node != NULL;
         fl_node           = fl_node->next) {
        debugf_debug("ENTRY @ %p\n", fl_node);
        debugf_debug("\tlength: %llx\n", fl_node->length);
        if (fl_node->next) {
            debugf_debug("\tnext: %p\n", fl_node->next);
        } else {
            debugf_debug("\tEND\n");
        }
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
flnode_t *fl_update_nodes() {
    usable_entry_count = 0;
    for (flnode_t *i = pmm_headnode; i != NULL;
         i           = i->next, usable_entry_count++)
        ;

    return pmm_headnode;
}

int pmm_allocs = 0; // keeping track of how many times pmm_alloc was called
int pmm_frees  = 0; // keeping track of how many times pmm_free was called

// Omar, this is a PAGE FRAME allocator no need for custom <bytes> parameter
void *pmm_alloc_page() {
    spinlock_acquire(&PMM_LOCK);
    pmm_allocs++;
#ifdef CONFIG_PMM_DEBUG
    debugf_debug("--- Allocation n.%d ---\n", pmm_allocs);
#endif

    void *ptr = NULL;
    flnode_t *cur_node;
    for (cur_node = pmm_headnode; cur_node != NULL; cur_node = cur_node->next) {
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
        kprintf_panic("OUT OF MEMORY!");
        _hcf();
    }

#ifdef CONFIG_PMM_DEBUG
    debugf_debug("allocated %lu byte%sat address %p\n", PFRAME_SIZE,
                 PFRAME_SIZE > 1 ? "s " : " ", cur_node);
#endif

    ptr = (void *)(cur_node);

    if (cur_node->length - PFRAME_SIZE <= 0) {
        pmm_headnode = pmm_headnode->next;
    } else {
        // shift the node
        flnode_t *new_node = (ptr + PFRAME_SIZE);
        new_node->length   = (cur_node->length - PFRAME_SIZE);
        new_node->next     = cur_node->next;
        pmm_headnode       = new_node;
    }

    fl_update_nodes();

#ifdef CONFIG_PMM_DEBUG
    debugf_debug("old head %p is now %p\n", ptr, fl_head);
    debugf_debug("\tsize: %zx\n", fl_head->length);
    debugf_debug("\tnext: %p\n", fl_head->next);
#endif

    // zero out the whole allocated region
    memset((void *)ptr, 0, PFRAME_SIZE);

    spinlock_release(&PMM_LOCK);

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
    spinlock_acquire(&PMM_LOCK);
    pmm_frees++;
#ifdef CONFIG_PMM_DEBUG
    debugf_debug("--- Deallocation n.%d ---\n", pmm_frees);

    debugf_debug("deallocating address range %p-%p\n\n", ptr,
                 ptr + (pages * PFRAME_SIZE));
#endif

    flnode_t *deallocated = (flnode_t *)PHYS_TO_VIRTUAL(ptr);

    // you can check vmm.c for an explanation of the same behaviour
    for (flnode_t *f = pmm_headnode; f != NULL; f = f->next) {
        flnode_t *next = f->next;

        if (next < deallocated) {
            continue;
        }

        if ((f + (f->length)) == deallocated) {
            f->length += (PFRAME_SIZE * pages);
        } else if ((f - (PFRAME_SIZE * pages)) == deallocated) {
            flnode_t *new = next - (PFRAME_SIZE * pages);
            new->length   = next->length + (PFRAME_SIZE * pages);
            new->next     = next->next;
            f->next       = new;
        } else {
            deallocated->length = (PFRAME_SIZE * pages);
            deallocated->next   = next;
            f->next             = deallocated;
        }

        break;
    }

    fl_update_nodes();

    spinlock_release(&PMM_LOCK);
}
