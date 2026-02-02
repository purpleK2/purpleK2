/*
        Freelist memory allocator/manager with reference counting

        (C) RepubblicaTech 2024
*/

#include "pmm.h"
#include "paging/paging.h"

#include <autoconf.h>
#include <kernel.h>
#include <limine.h>
#include <util/util.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include <stdatomic.h>

extern void _hcf();

pmm_t pmm = {0};

void pmm_init(LIMINE_PTR(struct limine_memmap_response *) memmap_response) {
    if (!memmap_response) {
        kprintf_panic("No memmap response given!\n");
    }

    spinlock_release(&pmm.PMM_LOCK);
    pmm.total_memory = 0;
    pmm.used_memory  = 0;
    pmm.pages_info = NULL;
    pmm.total_pages = 0;
    pmm.pages_info_base = 0;

    pmm.usable_entry_count = 0;
    
    uint64_t lowest_base = UINT64_MAX;
    uint64_t highest_end = 0;
    
    for (uint64_t i = 0; i < memmap_response->entry_count; i++) {
        struct limine_memmap_entry *memmap_entry = memmap_response->entries[i];

        if (memmap_entry->type != LIMINE_MEMMAP_USABLE)
            continue;

        uint64_t entry_pages = memmap_entry->length / PFRAME_SIZE;
        pmm.total_pages += entry_pages;
        
        if (memmap_entry->base < lowest_base) {
            lowest_base = memmap_entry->base;
        }
        
        uint64_t entry_end = memmap_entry->base + memmap_entry->length;
        if (entry_end > highest_end) {
            highest_end = entry_end;
        }
    }
    
    pmm.pages_info_base = lowest_base;
    
    for (uint64_t i = 0; i < memmap_response->entry_count; i++) {
        struct limine_memmap_entry *memmap_entry = memmap_response->entries[i];

        if (memmap_entry->type != LIMINE_MEMMAP_USABLE)
            continue;

        flnode_t *fl_node = pmm_node_create(memmap_entry);

        fl_append(&pmm.head, fl_node);

        pmm.total_memory += fl_node->length;

        pmm.usable_entry_count++;
    }

    kprintf_info("Found %d usable regions\n", pmm.usable_entry_count);
    kprintf_info("Total pages: %llu\n", pmm.total_pages);

#ifdef CONFIG_PMM_DEBUG
    // prints all nodes
    for (flnode_t *fl_node = pmm.head; fl_node != NULL;
         fl_node           = fl_node->next) {
        debugf_debug("ENTRY @ %p\n", fl_node);
        debugf_debug("\tlength: %llx\n", fl_node->length);
        if (fl_node->next) {
            debugf_debug("\tnext: %p\n", fl_node->next);
        } else {
            debugf_debug("\tEND\n");
        }
    }
#endif
}

void pmm_init_refcount() {
    if (pmm.total_pages == 0) {
        kprintf_panic("PMM not initialized before refcount init!\n");
    }
    
    // Allocate memory for page_t array
    size_t pages_info_size = pmm.total_pages * sizeof(page_t);
    size_t pages_needed = (pages_info_size + PFRAME_SIZE - 1) / PFRAME_SIZE;
    
    kprintf_info("Allocating %zu pages for reference counting\n", pages_needed);
    
    void *pages_info_phys = pmm_alloc_pages(pages_needed);
    if (!pages_info_phys) {
        kprintf_panic("Failed to allocate memory for page reference counting!\n");
    }
    
    pmm.pages_info = (page_t *)PHYS_TO_VIRTUAL(pages_info_phys);
    
    memset(pmm.pages_info, 0, pages_info_size);
    
    kprintf_info("Reference counting initialized for %llu pages\n", pmm.total_pages);
}

// Returns the count of the entries.
int get_freelist_entry_count() {
    return pmm.usable_entry_count;
}

/*
        "Refreshes" the list of entries

        @returns head of nodes
*/
flnode_t *fl_update_nodes() {
    pmm.usable_entry_count = 0;
    for (flnode_t *i = pmm.head; i != NULL; i = i->next) {
        pmm.usable_entry_count++;
    }

#ifdef CONFIG_PMM_DEBUG
    debugf_debug("Used memory: %llu MiB\n", pmm.used_memory / 1024 / 1024);
#endif

    return pmm.head;
}

page_t *pmm_page_info(void *phys_addr) {
    if (!pmm.pages_info) {
        return NULL;
    }
    
    uint64_t page_index = ((uint64_t)phys_addr - pmm.pages_info_base) / PFRAME_SIZE;
    
    if (page_index >= pmm.total_pages) {
#ifdef CONFIG_PMM_DEBUG
        debugf_debug("Invalid page index %llu (max: %llu)\n", page_index, pmm.total_pages);
#endif
        return NULL;
    }
    
    return &pmm.pages_info[page_index];
}

void pmm_page_ref_inc(void *phys_addr) {
    page_t *page = pmm_page_info(phys_addr);
    if (page) {
        atomic_fetch_add(&page->ref_count, 1);
#ifdef CONFIG_PMM_DEBUG
        debugf_debug("Page %p refcount incremented to %d\n", phys_addr, 
                     atomic_load(&page->ref_count));
#endif
    }
}

void pmm_page_ref_dec(void *phys_addr) {
    page_t *page = pmm_page_info(phys_addr);
    if (page) {
        int old_count = atomic_fetch_sub(&page->ref_count, 1);
#ifdef CONFIG_PMM_DEBUG
        debugf_debug("Page %p refcount decremented to %d\n", phys_addr, old_count - 1);
#endif
        if (old_count == 1) {
            pmm_free(phys_addr, 1);
        }
    }
}

int pmm_page_ref_count(void *phys_addr) {
    page_t *page = pmm_page_info(phys_addr);
    if (page) {
        return atomic_load(&page->ref_count);
    }
    return 0;
}

// Omar, this is a PAGE FRAME allocator no need for custom <bytes> parameter
void *pmm_alloc_page() {
    spinlock_acquire(&pmm.PMM_LOCK);
    pmm.pmm_allocs++;
#ifdef CONFIG_PMM_DEBUG
    debugf_debug("--- Allocation n.%d ---\n", pmm.pmm_allocs);
#endif

    void *ptr = NULL;
    flnode_t *cur_node;
    for (cur_node = pmm.head; cur_node != NULL; cur_node = cur_node->next) {
#ifdef CONFIG_PMM_DEBUG
        debugf_debug("Looking for available memory at address %p\n", cur_node);
#endif

        if (cur_node->length >= PFRAME_SIZE)
            break;

#ifdef CONFIG_PMM_DEBUG
        debugf_debug("Not enough memory found at %p. Going on...", cur_node);
#endif
    }

    if (cur_node == NULL) {
        kpanic("No more physical memory available!");
        _hcf();
    }

#ifdef CONFIG_PMM_DEBUG
    debugf_debug("allocated %lu byte%sat address %p\n", PFRAME_SIZE,
                 PFRAME_SIZE > 1 ? "s " : " ", cur_node);
#endif

    ptr = (void *)(cur_node);

    if (cur_node->length - PFRAME_SIZE <= 0) {
        pmm.head = pmm.head->next;
    } else {
        flnode_t *new_node = (ptr + PFRAME_SIZE);
        new_node->length   = (cur_node->length - PFRAME_SIZE);
        new_node->next     = cur_node->next;
        pmm.head           = new_node;

#ifdef CONFIG_PMM_DEBUG
        debugf_debug("old head %p is now %p\n", ptr, pmm.head);
#endif
    }

    pmm.used_memory += PFRAME_SIZE;
    fl_update_nodes();

    memset((void *)ptr, 0, PFRAME_SIZE);

    void *phys_addr = (void *)VIRT_TO_PHYSICAL(ptr);
    
    if (pmm.pages_info) {
        page_t *page = pmm_page_info(phys_addr);
        if (page) {
            atomic_store(&page->ref_count, 1);
        }
    }

    spinlock_release(&pmm.PMM_LOCK);

    return phys_addr;
}

void *pmm_alloc_pages(size_t pages) {
    void *ptr = pmm_alloc_page();
    for (size_t i = 1; i < pages; i++) {
        pmm_alloc_page();
    }

    return ptr;
}

static void pmm_free_internal(void *ptr, size_t pages) {
    spinlock_acquire(&pmm.PMM_LOCK);
    pmm.pmm_frees++;
#ifdef CONFIG_PMM_DEBUG
    debugf_debug("--- Deallocation n.%d ---\n", pmm.pmm_frees);

    debugf_debug("deallocating address range %p-%p\n\n", ptr,
                 ptr + (pages * PFRAME_SIZE));
#endif

    flnode_t *deallocated = (flnode_t *)PHYS_TO_VIRTUAL(ptr);

    flnode_t *f = pmm.head;
    while (!is_addr_mapped((uint64_t)f)) {
        f = f->next;
        flnode_t *next = f->next;

        if (next < deallocated) {
            continue;
        }

        if ((f + (f->length)) == deallocated) {
#ifdef CONFIG_PMM_DEBUG
            debugf_debug("This node %p has claimed %zu pages\n", f, pages);
#endif
            f->length += (PFRAME_SIZE * pages);
        } else if ((f - (PFRAME_SIZE * pages)) == deallocated) {
            flnode_t *new = next - (PFRAME_SIZE * pages);
            new->length   = next->length + (PFRAME_SIZE * pages);
            new->next     = next->next;
            f->next       = new;

#ifdef CONFIG_PMM_DEBUG
            debugf_debug("Reclaimed pointer %p has claimed %zu pages\n", f,
                         pages);
#endif
        } else {
            deallocated->length = (PFRAME_SIZE * pages);
            deallocated->next   = next;
            f->next             = deallocated;
#ifdef CONFIG_PMM_DEBUG
            debugf_debug("Created node %p with %zu pages\n", deallocated,
                         pages);
#endif
        }

        break;
    }

#ifdef CONFIG_PMM_DEBUG
    debugf_debug("Pointer %p reclaimed OK!\n", ptr);
#endif

    fl_update_nodes();

    spinlock_release(&pmm.PMM_LOCK);
}

void pmm_free(void *ptr, size_t pages) {
    if (!pmm.pages_info) {
        pmm_free_internal(ptr, pages);
        return;
    }

    for (size_t i = 0; i < pages; i++) {
        void *page_addr = ptr + (i * PFRAME_SIZE);
        page_t *page = pmm_page_info(page_addr);
        
        if (!page) {
#ifdef CONFIG_PMM_DEBUG
            debugf_debug("Warning: freeing page %p with no info structure\n", page_addr);
#endif
            continue;
        }
        
        int old_count = atomic_fetch_sub(&page->ref_count, 1);
        
#ifdef CONFIG_PMM_DEBUG
        debugf_debug("Page %p refcount: %d -> %d\n", page_addr, old_count, old_count - 1);
#endif
        
        // Only actually free if this was the last reference
        if (old_count == 1) {
            pmm_free_internal(page_addr, 1);
        } else if (old_count <= 0) {
#ifdef CONFIG_PMM_DEBUG
            debugf_debug("Warning: freeing page %p with refcount %d\n", page_addr, old_count);
#endif
        }
    }
}