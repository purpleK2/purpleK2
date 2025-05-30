#ifndef KMALLOC_H
#define KMALLOC_H 1

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define PAGE_SIZE        4096
#define MAX_PAGES        64
#define SIZE_CLASS_COUNT 12

void kmalloc_init();

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

const heap_stats *kmalloc_get_stats(void);

#endif // KMALLOC_H
