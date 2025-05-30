#ifndef PMM_H
#define PMM_H 1

#include <kernel.h>
#include <memory/pmm/freelist.h>

#include <stddef.h>

#define PFRAME_SIZE 0x1000 // each page frame is 4KB wide

extern struct bootloader_data limine_parsed_data;
#define HHDM_OFFSET limine_parsed_data.hhdm_offset

#define PHYS_TO_VIRTUAL(ADDR)                                                  \
    ((uint64_t)ADDR > HHDM_OFFSET ? (uint64_t)ADDR                             \
                                  : (uint64_t)ADDR + HHDM_OFFSET)

#define VIRT_TO_PHYSICAL(ADDR)                                                 \
    ((uint64_t)ADDR < HHDM_OFFSET ? (uint64_t)ADDR                             \
                                  : (uint64_t)ADDR - HHDM_OFFSET)

void pmm_init();

void *pmm_alloc_page();
void *pmm_alloc_pages(size_t pages);
void pmm_free(void *ptr, size_t pages);

#endif
