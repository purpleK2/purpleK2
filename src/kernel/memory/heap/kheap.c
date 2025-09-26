#include "kheap.h"
#include "interrupts/isr.h"
#include "stdio.h"

#include <memory/vmm/vflags.h>
#include <memory/vmm/vmm.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define PAGE_SIZE     4096
#define MAX_PAGES     64
#define MAX_HEAP_SIZE (PAGE_SIZE * MAX_PAGES)

#define MIN_ORDER 3
#define MAX_ORDER 18

typedef struct block_header {
    struct block_header *next;
    size_t order;
    bool free;
} block_header_t;

static block_header_t *free_lists[MAX_ORDER + 1]; // free lists by order
static void *heap_base  = NULL;                   // base of managed region
static heap_stats stats = {0};

static inline size_t order_to_size(size_t order) {
    return (size_t)1 << order;
}

static inline size_t size_to_order(size_t size) {
    size_t order = MIN_ORDER;
    while (order <= MAX_ORDER && order_to_size(order) < size) {
        order++;
    }
    return order;
}

// Return block index within heap (for buddy calculation)
static inline size_t block_index(block_header_t *block, size_t order) {
    uintptr_t offset = (uintptr_t)block - (uintptr_t)heap_base;
    return offset / order_to_size(order);
}

static inline block_header_t *buddy_of(block_header_t *block, size_t order) {
    size_t idx             = block_index(block, order);
    uintptr_t buddy_offset = (idx ^ 1) * order_to_size(order); // flip last bit
    return (block_header_t *)((uintptr_t)heap_base + buddy_offset);
}

// Check if block is within heap bounds
static inline bool is_valid_block(block_header_t *block) {
    uintptr_t block_addr = (uintptr_t)block;
    uintptr_t heap_start = (uintptr_t)heap_base;
    uintptr_t heap_end   = heap_start + MAX_HEAP_SIZE;
    return block_addr >= heap_start && block_addr < heap_end;
}

static void add_block(size_t order, block_header_t *block) {
    if (!is_valid_block(block)) {
        kprintf_panic("add_block: invalid block address");
        _hcf();
    }
    block->order      = order;
    block->free       = true;
    block->next       = free_lists[order];
    free_lists[order] = block;
}

static void remove_block(size_t order, block_header_t *block) {
    if (!is_valid_block(block)) {
        kprintf_panic("remove_block: invalid block address");
        _hcf();
    }

    block_header_t *prev = NULL, *cur = free_lists[order];
    while (cur) {
        if (cur == block) {
            if (prev)
                prev->next = cur->next;
            else
                free_lists[order] = cur->next;
            block->next = NULL;
            return;
        }
        prev = cur;
        cur  = cur->next;
    }
    kprintf_panic("remove_block: block not found in freelist");
    _hcf();
}

void kmalloc_init() {
    memset(free_lists, 0, sizeof(free_lists));
    memset(&stats, 0, sizeof(stats));

    heap_base =
        valloc(get_current_ctx(), MAX_PAGES, VMO_KERNEL_RW | VMO_NX, NULL);
    if (!heap_base) {
        kprintf_panic("kmalloc_init: failed to allocate heap");
        _hcf();
    }

    // Initialize the entire heap as one large free block
    block_header_t *block = (block_header_t *)heap_base;
    add_block(MAX_ORDER, block);
    stats.current_pages_used = MAX_PAGES;
}

static block_header_t *split_block(size_t order) {
    if (order > MAX_ORDER) {
        return NULL;
    }

    // Find a free block of sufficient size
    size_t i = order;
    while (i <= MAX_ORDER && !free_lists[i])
        i++;

    if (i > MAX_ORDER) {
        return NULL; // No blocks available
    }

    block_header_t *block = free_lists[i];
    if (!block) {
        return NULL;
    }

    remove_block(i, block);

    // Split the block down to the required order
    while (i > order) {
        i--;
        size_t half_size      = order_to_size(i);
        block_header_t *buddy = (block_header_t *)((char *)block + half_size);
        add_block(i, buddy);
    }

    block->order = order;
    return block;
}

void *kmalloc(size_t size) {
    if (size == 0)
        return NULL;

    size_t needed = size + sizeof(block_header_t);
    size_t order  = size_to_order(needed);

    // Handle very large allocations outside buddy system
    if (order > MAX_ORDER) {
        size_t pages = (needed + PAGE_SIZE - 1) / PAGE_SIZE;
        void *ptr =
            valloc(get_current_ctx(), pages, VMO_KERNEL_RW | VMO_NX, NULL);
        if (!ptr) {
            return NULL;
        }

        block_header_t *block = (block_header_t *)ptr;
        block->order          = pages; // Store page count, not size order
        block->free           = false;
        block->next           = NULL;

        stats.total_allocs++;
        stats.total_bytes_allocated += pages * PAGE_SIZE;
        stats.current_pages_used    += pages;
        return block + 1;
    }

    // Try to get a block from the free list
    block_header_t *block = free_lists[order];
    if (block) {
        remove_block(order, block);
    } else {
        block = split_block(order);
        if (!block)
            return NULL;
    }

    block->free  = false;
    block->order = order;

    stats.total_allocs++;
    stats.total_bytes_allocated += order_to_size(order);
    return block + 1;
}

void kfree(void *ptr) {
    if (!ptr)
        return;

    block_header_t *block = ((block_header_t *)ptr) - 1;

    // Handle large allocations outside buddy system
    if (block->order > MAX_ORDER) {
        size_t pages = block->order; // This is page count, not order
        vfree(get_current_ctx(), block, true);
        stats.total_frees++;
        stats.total_bytes_freed  += pages * PAGE_SIZE;
        stats.current_pages_used -= pages;
        return;
    }

    if (!is_valid_block(block)) {
        kprintf_panic("kfree: invalid block address");
        _hcf();
    }

    size_t order = block->order;
    block->free  = true;

    // Coalesce with buddy blocks
    while (order < MAX_ORDER) {
        block_header_t *buddy = buddy_of(block, order);

        // Check if buddy is valid and free
        if (!is_valid_block(buddy) || !buddy->free || buddy->order != order)
            break;

        remove_block(order, buddy);

        // Make sure we keep the lower address block
        if (block > buddy) {
            block = buddy;
        }

        order++;
        block->order = order;
    }

    add_block(order, block);

    stats.total_frees++;
    stats.total_bytes_freed += order_to_size(order);
}

void *kcalloc(size_t num, size_t size) {
    // Check for overflow
    if (num != 0 && size > SIZE_MAX / num) {
        return NULL;
    }

    size_t total = num * size;
    void *ptr    = kmalloc(total);
    if (ptr)
        memset(ptr, 0, total);
    return ptr;
}

void *krealloc(void *ptr, size_t new_size) {
    if (!ptr)
        return kmalloc(new_size);
    if (new_size == 0) {
        kfree(ptr);
        return NULL;
    }

    block_header_t *block = ((block_header_t *)ptr) - 1;
    size_t old_size;

    // Calculate old usable size correctly
    if (block->order > MAX_ORDER) {
        // Large allocation - order stores page count
        old_size = (block->order * PAGE_SIZE) - sizeof(block_header_t);
    } else {
        // Normal buddy allocation
        old_size = order_to_size(block->order) - sizeof(block_header_t);
    }

    // If new size fits in current block, just return it
    if (old_size >= new_size)
        return ptr;

    // Allocate new block
    void *new_ptr = kmalloc(new_size);
    if (!new_ptr)
        return NULL;

    // Copy old data and free old block
    memcpy(new_ptr, ptr, old_size < new_size ? old_size : new_size);
    kfree(ptr);
    return new_ptr;
}

const heap_stats *kmalloc_get_stats(void) {
    return &stats;
}