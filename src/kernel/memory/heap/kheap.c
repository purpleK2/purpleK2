#include "kheap.h"
#include "memory/pmm/pmm.h"
#include "stdio.h"

#include <memory/vmm/vflags.h>
#include <memory/vmm/vmm.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define MIN_CACHE_ORDER 3  // 2^3 = 8 bytes min alloc
#define MAX_CACHE_ORDER 12 // 2^12 = 4096 (1 page)
#define NUM_CACHES      (MAX_CACHE_ORDER - MIN_CACHE_ORDER + 1)

static kmem_cache_t caches[NUM_CACHES];
static heap_stats stats = {0};

/// Align up to nearest multiple
static inline size_t align_up(size_t n, size_t align) {
    return (n + align - 1) & ~(align - 1);
}

/// Pick cache for allocation size
static inline kmem_cache_t *get_cache_for_size(size_t size) {
    size_t order = MIN_CACHE_ORDER;
    while ((1UL << order) < size && order <= MAX_CACHE_ORDER) {
        order++;
    }
    if (order > MAX_CACHE_ORDER)
        return NULL;
    return &caches[order - MIN_CACHE_ORDER];
}

/// Carve a new page into objects and build freelist
static void refill_cache(kmem_cache_t *cache) {
    void *page = valloc(get_current_vmc(), 1, VMO_KERNEL_RW | VMO_NX, NULL);
    if (!page) {
        kprintf_panic("SLUB: out of memory in refill_cache");
        _hcf();
    }

    size_t obj_size = cache->obj_size;
    size_t capacity = PFRAME_SIZE / obj_size;
    uint8_t *cursor = (uint8_t *)page;

    for (size_t i = 0; i < capacity; i++) {
        void *obj      = cursor + i * obj_size;
        *(void **)obj  = cache->partial; // push onto freelist
        cache->partial = obj;
        cache->total_count++;
        cache->free_count++;
    }

    stats.current_pages_used++;
}

/// Initialize all caches
void kmalloc_init() {
    memset(&stats, 0, sizeof(stats));
    memset(caches, 0, sizeof(caches));

    for (size_t order = MIN_CACHE_ORDER; order <= MAX_CACHE_ORDER; order++) {
        kmem_cache_t *cache = &caches[order - MIN_CACHE_ORDER];
        cache->obj_size     = 1UL << order;
        cache->align        = cache->obj_size;
        cache->partial      = NULL;
    }
}

/// Allocate memory
void *kmalloc(size_t size) {
    if (size == 0)
        return NULL;

    kmem_cache_t *cache = get_cache_for_size(size);
    if (!cache) {
        // Large object: fall back to page allocator
        size_t pages = (size + PFRAME_SIZE - 1) / PFRAME_SIZE;
        void *ptr =
            valloc(get_current_vmc(), pages, VMO_KERNEL_RW | VMO_NX, NULL);
        if (!ptr)
            return NULL;
        stats.total_allocs++;
        stats.total_bytes_allocated += pages * PFRAME_SIZE;
        stats.current_pages_used    += pages;
        return ptr;
    }

    if (!cache->partial) {
        refill_cache(cache);
    }

    void *obj      = cache->partial;
    cache->partial = *(void **)obj;
    cache->free_count--;

    stats.total_allocs++;
    stats.total_bytes_allocated += cache->obj_size;

    return (void *)obj;
}

/// Free memory
void kfree(void *ptr) {
    if (!ptr)
        return;

    uintptr_t addr      = (uintptr_t)ptr;
    uintptr_t page_base = addr & ~(PFRAME_SIZE - 1);

    // Find which cache this belongs to by size
    // (simple: iterate caches and check obj_size fits within page)
    kmem_cache_t *cache = NULL;
    for (size_t i = 0; i < NUM_CACHES; i++) {
        if (caches[i].obj_size <= PFRAME_SIZE) {
            uintptr_t offset = addr - page_base;
            if (offset % caches[i].obj_size == 0) {
                cache = &caches[i];
                break;
            }
        }
    }

    if (!cache) {
        // Large allocation: free whole pages
        size_t pages = 1; // we don’t track exact pages here (could extend)
        vfree(get_current_vmc(), (void *)page_base, true);
        stats.total_frees++;
        stats.total_bytes_freed  += pages * PFRAME_SIZE;
        stats.current_pages_used -= pages;
        return;
    }

    *(void **)ptr  = cache->partial;
    cache->partial = ptr;
    cache->free_count++;

    stats.total_frees++;
    stats.total_bytes_freed += cache->obj_size;
}

void *kcalloc(size_t num, size_t size) {
    if (num != 0 && size > SIZE_MAX / num)
        return NULL;
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

    // crude: allocate new and copy
    void *new_ptr = kmalloc(new_size);
    if (!new_ptr)
        return NULL;

    memcpy(new_ptr, ptr, new_size); // assume caller knows old size
    kfree(ptr);
    return new_ptr;
}

const heap_stats *kmalloc_get_stats(void) {
    return &stats;
}
