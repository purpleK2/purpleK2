#include "kheap.h"

#include <memory/vmm/vflags.h>
#include <memory/vmm/vma.h>
#include <memory/vmm/vmm.h>

#include <string.h>

#define ALIGN8(x)      (((x) + 7) & ~7)
#define MIN_BLOCK_SIZE 16
#define MAX_BLOCK_SIZE (PAGE_SIZE * MAX_PAGES)

typedef struct block_header {
    struct block_header *next;
    size_t size;
    bool free;
} block_header_t;

static block_header_t *free_lists[SIZE_CLASS_COUNT] = {0};
static heap_stats stats                             = {0};

static inline size_t size_class_index(size_t size) {
    size_t cls_size = MIN_BLOCK_SIZE;
    for (size_t i = 0; i < SIZE_CLASS_COUNT; i++) {
        if (size <= cls_size)
            return i;
        cls_size <<= 1;
    }
    return SIZE_CLASS_COUNT - 1;
}

static inline size_t size_class_size(size_t index) {
    return MIN_BLOCK_SIZE << index;
}

static void add_block_to_free_list(block_header_t *block) {
    size_t idx      = size_class_index(block->size);
    block->free     = true;
    block->next     = free_lists[idx];
    free_lists[idx] = block;
}

static void remove_block_from_free_list(block_header_t **list_head,
                                        block_header_t *block) {
    block_header_t *prev = NULL;
    block_header_t *cur  = *list_head;
    while (cur) {
        if (cur == block) {
            if (prev)
                prev->next = cur->next;
            else
                *list_head = cur->next;
            cur->next = NULL;
            return;
        }
        prev = cur;
        cur  = cur->next;
    }
}

static block_header_t *split_block(block_header_t *block, size_t size) {
    if (block->size >= size + sizeof(block_header_t) + MIN_BLOCK_SIZE) {
        block_header_t *new_block =
            (block_header_t *)((char *)(block + 1) + size);
        new_block->size = block->size - size - sizeof(block_header_t);
        new_block->free = true;
        new_block->next = NULL;
        block->size     = size;
        add_block_to_free_list(new_block);
        return block;
    }
    return block;
}

static block_header_t *request_new_page(size_t size_class_idx) {
    size_t block_size      = size_class_size(size_class_idx);
    size_t blocks_per_page = PAGE_SIZE / (block_size + sizeof(block_header_t));
    if (blocks_per_page == 0)
        blocks_per_page = 1; // at least 1 block per page

    size_t pages = (ROUND_UP(block_size, PFRAME_SIZE) / PFRAME_SIZE);

    void *page = valloc(get_current_ctx(), pages, VMO_KERNEL_RW | VMO_NX, NULL);
    if (!page)
        return NULL;

    // Create blocks in page and add them to free list
    char *ptr = (char *)page;
    for (size_t i = 0; i < blocks_per_page; i++) {
        block_header_t *block =
            (block_header_t *)(ptr + i * (block_size + sizeof(block_header_t)));
        block->size = block_size;
        block->free = true;
        block->next = NULL;
        add_block_to_free_list(block);
        stats.current_pages_used++;
    }
    return free_lists[size_class_idx]; // return first free block in this size
                                       // class
}

void kmalloc_init() {
    memset(free_lists, 0, sizeof(free_lists));
    memset(&stats, 0, sizeof(stats));
}

// Find suitable free block for size, or request page if none found
static block_header_t *find_block(size_t size) {
    size_t idx = size_class_index(size);
    for (size_t i = idx; i < SIZE_CLASS_COUNT; i++) {
        block_header_t *list = free_lists[i];
        if (list) {
            // take first block in list
            remove_block_from_free_list(&free_lists[i], list);
            if (list->size > size) {
                // split block and add remainder back
                split_block(list, size);
            }
            list->free = false;
            return list;
        }
        // no free block in this class, try next larger size class
    }
    // no block found, request new page for requested size class
    block_header_t *new_block = request_new_page(idx);
    if (!new_block)
        return NULL;
    // allocate from new blocks
    remove_block_from_free_list(&free_lists[idx], new_block);
    new_block->free = false;
    if (new_block->size > size) {
        split_block(new_block, size);
    }
    return new_block;
}

void *kmalloc(size_t size) {
    if (size == 0)
        return NULL;
    size = ALIGN8(size);
    if (size > MAX_BLOCK_SIZE) {
        // Large alloc: allocate whole pages
        size_t pages =
            (size + sizeof(block_header_t) + PAGE_SIZE - 1) / PAGE_SIZE;
        void *ptr =
            valloc(get_current_ctx(), pages, VMO_KERNEL_RW | VMO_NX, NULL);
        if (!ptr)
            return NULL;
        // Use block header at start of allocated pages
        block_header_t *block = (block_header_t *)ptr;
        block->size           = pages * PAGE_SIZE - sizeof(block_header_t);
        block->free           = false;
        block->next           = NULL;
        stats.total_allocs++;
        stats.total_bytes_allocated += block->size;
        stats.current_pages_used    += pages;
        return block + 1;
    }
    block_header_t *block = find_block(size);
    if (!block)
        return NULL;
    stats.total_allocs++;
    stats.total_bytes_allocated += block->size;
    return block + 1;
}

void kfree(void *ptr) {
    if (!ptr)
        return;
    block_header_t *block = ((block_header_t *)ptr) - 1;
    if (block->free)
        return;
    size_t size = block->size;
    block->free = true;
    stats.total_frees++;
    stats.total_bytes_freed += size;

    if (size > MAX_BLOCK_SIZE / 2) {
        size_t pages =
            (size + sizeof(block_header_t) + PAGE_SIZE - 1) / PAGE_SIZE;
        stats.current_pages_used -= pages;
        vfree(get_current_ctx(), block, true);
        return;
    }

    add_block_to_free_list(block);
}

void *kcalloc(size_t num, size_t size) {
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
    if (block->size >= new_size)
        return ptr;

    void *new_ptr = kmalloc(new_size);
    if (!new_ptr)
        return NULL;
    memcpy(new_ptr, ptr, block->size);
    kfree(ptr);
    return new_ptr;
}

// Optional: function to get stats pointer
const heap_stats *kmalloc_get_stats(void) {
    return &stats;
}
