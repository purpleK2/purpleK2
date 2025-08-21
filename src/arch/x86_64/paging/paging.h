#ifndef PAGING_H
#define PAGING_H 1

#include <interrupts/isr.h>

/*
        --- Some definitions ---

        PMLT: Page Map Level Table. Refers to a generic page table in any level
                                                                (e.g. PDPT, PDT,
   PT)

        PMLE: Page Map Level Entry. Refers to an entry in a PMLT
                                                                (e.g. PDPE, PDE,
   PE)

        PG: suffix that refers to paging-related macros and constants
*/

#include <memory/pmm/pmm.h>

#define VIRT_BASE limine_parsed_data.kernel_base_virtual
#define PHYS_BASE limine_parsed_data.kernel_base_physical

// PMLT entry is 8-bytes wide instead of 4, so the entries are halved
#define PMLT_ENTRIES 512

// PMLE Flags
// from
// https://github.com/tyler-ottman/tellurium-os/blob/01cf40ba4ab872e81bc98d6c740174c42b029376/kernel/memory/vmm.h#L15
#define PMLE_PRESENT        1
#define PMLE_WRITE          (1 << 1)
#define PMLE_USER           (1 << 2)
#define PMLE_PWT            (1 << 3)
#define PMLE_PCD            (1 << 4)
#define PMLE_ACCESSED       (1 << 5)
#define PMLE_NOT_EXECUTABLE (1ull << 63)

// Page privileges attributes
// from
// https://github.com/Tix3Dev/apoptOS/blob/370fd34a6d3c87a9d1a16d1a2ec072bd1836ba6c/src/kernel/memory/virtual/vmm.h#L39
#define PMLE_KERNEL_READ       PMLE_PRESENT
#define PMLE_KERNEL_READ_WRITE PMLE_PRESENT | PMLE_WRITE
#define PMLE_USER_READ         PMLE_PRESENT | PMLE_USER
#define PMLE_USER_READ_WRITE   PMLE_PRESENT | PMLE_WRITE | PMLE_USER
#define AHCI_MMIO_FLAGS (PMLE_PRESENT | PMLE_WRITE | PMLE_PCD | PMLE_ACCESSED | PMLE_NOT_EXECUTABLE)

// by
// https://github.com/malwarepad/cavOS/blob/646237dfd6c4173a4c059cccd74c63dd31cfd052/src/kernel/include/paging.h

// physical address offset mask
#define PG_ADDR_MASK 0xfffffffff000
// eg.
// 0xffff8000000520ab
// 0x    fffffffff000

#define PG_FLAGS(a)    ((a) & ~(PG_ADDR_MASK))
#define PG_GET_ADDR(x) ((x) & PG_ADDR_MASK)

#define PMLT_MASK 0x1ff

// virtual address macros to get the PMLEs
#define PML4_INDEX(a) ((a >> 39) & PMLT_MASK)
#define PDP_INDEX(a)  ((a >> 30) & PMLT_MASK)
#define PDIR_INDEX(a) ((a >> 21) & PMLT_MASK)
#define PTAB_INDEX(a) ((a >> 12) & PMLT_MASK)
#define PG_OFFSET(a)  ((a) & PG_FLAGS_MASK)

// PAT
#define PAT_UNCACHEABLE     0
#define PAT_WRITE_COMBINING 1
#define PAT_WRITE_THROUGH   4
#define PAT_WRITE_PROTECTED 5
#define PAT_WRITEBACK       6
#define PAT_UNCACHED        7

void pf_handler(void *ctx);

/********************
 *   PAGING STUFF   *
 ********************/

extern uint64_t *_get_pml4();

uint64_t *get_limine_pml4();
uint64_t *get_kernel_pml4();

// sets the PML4 table to use
// note: given address MUST be physical, NOT a virtual one
extern void _load_pml4(uint64_t *pml4_base);

// flushes a virtual address in the TLB
extern void _invalidate(uint64_t virtual);

uint64_t *get_pmlt(uint64_t *pml_table, uint64_t pml_index);
uint64_t get_page_entry(uint64_t *pml4_table, uint64_t virtual);
uint64_t pg_virtual_to_phys(uint64_t *pml4_table, uint64_t virtual);

uint64_t *get_create_pmlt(uint64_t *pml_table, uint64_t pmlt_index,
                          uint64_t flags);

void unmap_page(uint64_t *pml4_table, uint64_t virtual);
void unmap_region(uint64_t *pml4_table, uint64_t virtual_start, uint64_t len);

void map_phys_to_page(uint64_t *pml4_table, uint64_t physical, uint64_t virtual,
                      uint64_t flags);
void map_region_to_page(uint64_t *pml4_table, uint64_t physical_start,
                        uint64_t virtual_start, uint64_t len, uint64_t flags);

void copy_range_to_pagemap(uint64_t *dst_pml4, uint64_t *src_pml4,
                           uint64_t virt_start, size_t len);

uint64_t vmo_to_page_flags(uint64_t vmo_flags);
uint64_t page_to_vmo_flags(uint64_t pg_flags);

void paging_init(uint64_t *kernel_pml4);

#endif
