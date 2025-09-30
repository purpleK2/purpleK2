#ifndef KMALLOC_H
#define KMALLOC_H 1

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define PAGE_SIZE 4096

void kmalloc_init(void);

void *kmalloc(size_t size);
void kfree(void *ptr);
void *krealloc(void *ptr, size_t new_size);
void *kcalloc(size_t num, size_t size);

typedef struct heap_stats {
    size_t total_allocs;
    size_t total_frees;
    size_t total_bytes_allocated;
    size_t total_bytes_freed;
    size_t current_pages_used;
} heap_stats;

/// Per-cache metadata (like Linux SLUB’s kmem_cache)
typedef struct kmem_cache {
    size_t obj_size;    // object size for this cache
    size_t align;       // alignment
    void *partial;      // freelist of objects (single-linked list)
    size_t free_count;  // number of free objects (for stats)
    size_t total_count; // total objects ever carved (for stats)
} kmem_cache_t;

const heap_stats *kmalloc_get_stats(void);

#endif // KMALLOC_H
