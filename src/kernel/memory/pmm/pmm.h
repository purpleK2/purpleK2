#ifndef PMM_H
#define PMM_H 1

#include <kernel.h>
#include <memory/pmm/freelist.h>
#include <spinlock.h>
#include <stdatomic.h>
#include <stddef.h>

#define PFRAME_SIZE 0x1000 // each page frame is 4KB wide

extern struct bootloader_data limine_parsed_data;

#define PHYS_TO_VIRTUAL(ADDR)                                                  \
    (((uint64_t)(ADDR)) > limine_parsed_data.hhdm_offset                       \
         ? ((uint64_t)(ADDR))                                                  \
         : ((uint64_t)(ADDR)) + limine_parsed_data.hhdm_offset)

#define VIRT_TO_PHYSICAL(ADDR)                                                 \
    (((uint64_t)(ADDR)) < limine_parsed_data.hhdm_offset                       \
         ? ((uint64_t)(ADDR))                                                  \
         : ((uint64_t)(ADDR)) - limine_parsed_data.hhdm_offset)

// Page information structure for reference counting
typedef struct page {
    atomic_int ref_count;
} page_t;

typedef struct pmm {
    flnode_t *head;
    uint64_t total_memory;
    uint64_t used_memory;
    int pmm_allocs;
    int pmm_frees;
    int usable_entry_count;
    atomic_flag PMM_LOCK;
    page_t *pages_info;        // Array of page structures
    uint64_t total_pages;      // Total number of pages in system
    uint64_t pages_info_base;  // Physical base address for page array calculation
} pmm_t;

void pmm_init(LIMINE_PTR(struct limine_memmap_response *) memmap_response);
void pmm_init_refcount();
void *pmm_alloc_page();
void *pmm_alloc_pages(size_t pages);
void *pmm_alloc_contiguous_pages(size_t pages);
void pmm_free(void *ptr, size_t pages);

// Reference counting functions
page_t *pmm_page_info(void *phys_addr);
void pmm_page_ref_inc(void *phys_addr);
void pmm_page_ref_dec(void *phys_addr);
int pmm_page_ref_count(void *phys_addr);

#endif