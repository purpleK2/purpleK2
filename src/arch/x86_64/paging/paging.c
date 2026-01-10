#include "paging.h"

#include <autoconf.h>
#include <kernel.h>
#include <limine.h>

#include <cpu.h>

#include <memory/pmm/pmm.h>
#include <memory/vmm/vflags.h>
#include <smp/ipi.h>

#include <scheduler/scheduler.h>

#include <interrupts/irq.h>

#include <util/util.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* http://wiki.osdev.org/Exceptions#Page_Fault

 31              15                             4               0
+---+--  --+---+-----+---+--  --+---+----+----+---+---+---+---+---+
|   Reserved   | SGX |   Reserved   | SS | PK | I | R | U | W | P |
+---+--  --+---+-----+---+--  --+---+----+----+---+---+---+---+---+

Bit			Name					Description
P	 	Present 					1 ->
page-protection fault; 0 -> non-present page

W	 	Write 						1 -> write
access; 0 -> read access

U	 	User 						1 -> CPL = 3.
This does not necessarily mean that the page fault was a privilege violation.

R	 	Reserved write 				1 -> one or more page
directory entries contain reserved bits which are set to 1. This only applies
when the PSE or PAE flags in CR4 are set to 1.

I	 	Instruction Fetch 			1 -> instruction fetch.
This only applies when the No-Execute bit is supported and enabled.

PK  	Protection key 				1 -> protection-key violation.
The PKRU register (for user-mode accesses) or PKRS MSR (for supervisor-mode
accesses) specifies the protection key rights.

SS  	Shadow stack 				1 -> shadow stack access.

SGX 	Software Guard Extensions 	1 -> SGX violation. The fault is
unrelated to ordinary paging.

*/

#define PG_MASK(a) (a & 0b1)

#define PG_PRESENT(x)  PG_MASK(x)
#define PG_WR_RD(x)    PG_MASK(x >> 1)
#define PG_RING(x)     PG_MASK(x >> 2)
#define PG_RESERVED(x) PG_MASK(x >> 3)
#define PG_IF(x)       PG_MASK(x >> 4)
#define PG_PK(x)       PG_MASK(x >> 5)
#define PG_SS(x)       PG_MASK(x >> 6)
#define PG_SGX(x)      PG_MASK(x >> 14)

/*
        Page fault code handler

        Simply gives information about a page fault error code
        (C) RepubblicaTech 2024
*/
void pf_handler(registers_t *ctx) {
    uint64_t pf_error_code = (uint64_t)ctx->error;

    if (PG_IF(pf_error_code)) {
        debugf_debug("Killing process %d, because of a page fault from the %d (1 is user, 0 is kernel).ss=%x, cs=%x rip: %.16llx, fault_addr: %.16llx, instr_fetch: %s\n",
            PG_RING(pf_error_code), 
            get_current_pcb()->pid, ctx->ss, ctx->cs, ctx->rip, cpu_get_cr(2),
            PG_IF(pf_error_code) == 1 ? "yes" : "no");
        debugf_debug("CR3: %.16llx\n", cpu_get_cr(3));
        proc_exit();
        yield(ctx);
        return;
    }

    stdio_panic_init();
    bsod_init();

    debugf(ANSI_COLOR_BLUE);
    mprintf("--- PANIC! ---\n");
    mprintf("Page fault code %016b\n\n-------------------------------\n",
            pf_error_code);

    switch (PG_PRESENT(pf_error_code)) {
    case 0:
        mprintf(PG_RING(pf_error_code) == 0 ? "Kernel " : "User ");
        mprintf(PG_WR_RD(pf_error_code) == 0 ? "read attempt of a "
                                             : "write attempt to a ");
        mprintf("non-present page entry\n\n");
        break;

    case 1:
        mprintf("Page-level protection violation\n\n");

    default:
        break;
    }

    // CR2 contains the address that caused the fault
    uint64_t cr2 = cpu_get_cr(2);
    mprintf("\nAttempt to access address %llx\n\n", cr2);

    mprintf("RESERVED WRITE: %d\n", PG_RESERVED(pf_error_code));
    mprintf("INSTRUCTION_FETCH: %d\n", PG_IF(pf_error_code));
    mprintf("PROTECTION_KEY_VIOLATION: %d\n", PG_PK(pf_error_code));
    mprintf("SHADOW_STACK_ACCESS: %d\n", PG_SS(pf_error_code));
    mprintf("SGX_VIOLATION: %d\n", PG_SGX(pf_error_code));

    panic_common(ctx);

    debugf(ANSI_COLOR_RESET);
}

/********************
 *   PAGING STUFF   *
 ********************/

uint64_t *get_pmlt(uint64_t *pml_table, uint64_t pml_index) {
    uint64_t page_entry       = pml_table[pml_index];
    uint64_t actual_page_addr = PG_GET_ADDR(page_entry);
    if (!actual_page_addr) {
        debugf_warn("Page entry address returned NULL!\n");
    }

    return (uint64_t *)(PHYS_TO_VIRTUAL(actual_page_addr));
}

uint64_t *get_create_pmlt(uint64_t *pml_table, uint64_t pmlt_index,
                          uint64_t flags) {
    // is there something at pml_table[pmlt_index]?
    if (!(pml_table[pmlt_index] & PMLE_PRESENT)) {
#ifdef CONFIG_PAGING_DEBUG
        debugf_debug("Table %llp entry %llx is not present, creating it...\n",
                     pml_table, pmlt_index);
#endif

        pml_table[pmlt_index] = (uint64_t)pmm_alloc_page() | flags;
    }

#ifdef CONFIG_PAGING_DEBUG
    debugf_debug("Table %llp entry %llx contents:%llx flags:%llx\n", pml_table,
                 pmlt_index, pml_table[pmlt_index], flags);
#endif

    return get_pmlt(pml_table, pmlt_index);
}

// given the PML4 table and a virtual address, returns the page entry with its
// flags
uint64_t get_page_entry(uint64_t *pml4_table, uint64_t virtual) {
    uint64_t pml4_index = PML4_INDEX(virtual);
    uint64_t pdp_index  = PDP_INDEX(virtual);
    uint64_t pdir_index = PDIR_INDEX(virtual);
    uint64_t ptab_index = PTAB_INDEX(virtual);

    uint64_t *pdp_table  = get_pmlt(pml4_table, pml4_index);
    uint64_t *pdir_table = get_pmlt(pdp_table, pdp_index);
    uint64_t *page_table = get_pmlt(pdir_table, pdir_index);

    return page_table[ptab_index];
}

// given the PML4 table and a virtual address, returns its physical address
uint64_t pg_virtual_to_phys(uint64_t *pml4_table, uint64_t virtual) {
    return PG_GET_ADDR(get_page_entry(pml4_table, virtual));
}

bool is_mapped(uint64_t *pml4_table, uint64_t address) {
    uint64_t pml4_index = PML4_INDEX(address);
    uint64_t pdp_index  = PDP_INDEX(address);
    uint64_t pdir_index = PDIR_INDEX(address);
    uint64_t ptab_index = PTAB_INDEX(address);

    uint64_t *pdp_table  = get_create_pmlt(pml4_table, pml4_index, 0b111);
    uint64_t *pdir_table = get_create_pmlt(pdp_table, pdp_index, 0b111);
    uint64_t *page_table = get_create_pmlt(pdir_table, pdir_index, 0b111);

    if (page_table[ptab_index] & 0b1) {
        return true;
    } else {
        return false;
    }
}

// map a page frame to a physical address that gets mapped to a virtual one
void map_phys_to_page(uint64_t *pml4_table, uint64_t physical, uint64_t virtual,
                      uint64_t flags) {
    // if (virtual % PFRAME_SIZE) {
    // 	kprintf_panic("Attempted to map non-aligned addresses (phys)%llx
    // (virt)%llx!\n", physical, virtual); 	_hcf();
    // }

    uint64_t pml4_index = PML4_INDEX(virtual);
    uint64_t pdp_index  = PDP_INDEX(virtual);
    uint64_t pdir_index = PDIR_INDEX(virtual);
    uint64_t ptab_index = PTAB_INDEX(virtual);

    uint64_t *pdp_table =
        get_create_pmlt(pml4_table, pml4_index, (flags & 0b111));
    uint64_t *pdir_table =
        get_create_pmlt(pdp_table, pdp_index, (flags & ~(PMLE_PAT) & 0b111));
    uint64_t *page_table =
        get_create_pmlt(pdir_table, pdir_index, (flags & ~(PMLE_PAT) & 0b111));

    page_table[ptab_index] = PG_GET_ADDR(physical) | flags;

#ifdef CONFIG_PAGING_DEBUG
    debugf_debug("Virtual address %llx mapped to %llx\n", virtual, physical);
#endif

    _invalidate(virtual);
    if (get_bootloader_data()->smp_enabled) {
        tlb_shootdown(virtual);
    }
}

void unmap_page(uint64_t *pml4_table, uint64_t virtual) {
    uint64_t pml4_index = PML4_INDEX(virtual);
    uint64_t pdp_index  = PDP_INDEX(virtual);
    uint64_t pdir_index = PDIR_INDEX(virtual);
    uint64_t ptab_index = PTAB_INDEX(virtual);

    uint64_t *pdp_table  = get_pmlt(pml4_table, pml4_index);
    uint64_t *pdir_table = get_pmlt(pdp_table, pdp_index);
    uint64_t *page_table = get_pmlt(pdir_table, pdir_index);

    page_table[ptab_index] = 0x0;

    _invalidate(virtual);
    if (get_bootloader_data()->smp_enabled) {
        tlb_shootdown(virtual);
    }
}

// maps a page region to its physical range
// @param len is in pages
void map_region(uint64_t *pml4_table, uint64_t physical_start,
                uint64_t virtual_start, uint64_t pages, uint64_t flags) {
#ifdef CONFIG_PAGING_DEBUG
    debugf_debug("Mapping address range (phys)%llx-%llx (virt)%llx-%llx\n",
                 physical_start, physical_start + pages, virtual_start,
                 virtual_start + pages);
#endif

    for (uint64_t i = 0; i < pages; i++) {
        uint64_t phys = physical_start + (i * PFRAME_SIZE);
        uint64_t virt = virtual_start + (i * PFRAME_SIZE);
        map_phys_to_page(pml4_table, phys, virt, flags);
    }
}

void unmap_region(uint64_t *pml4_table, uint64_t virtual_start,
                  uint64_t pages) {

#ifdef CONFIG_PAGING_DEBUG
    debugf_debug("Unmapping address range (virt)%llx-%llx\n", virtual_start,
                 virtual_start + pages);
#endif
    for (uint64_t i = 0; i < pages; i++) {
        uint64_t virt = virtual_start + (i * PFRAME_SIZE);
        unmap_page(pml4_table, virt);
    }
}

// Copy a virtual address range of a pagemap to another one
// The virtual-to-physical mappings will be copied
void copy_range_to_pagemap(uint64_t *dst_pml4, uint64_t *src_pml4,
                           uint64_t virt_start, size_t len) {

    uint64_t phys_start =
        pg_virtual_to_phys((uint64_t *)PHYS_TO_VIRTUAL(src_pml4), virt_start);
    uint64_t page_entry_flags = PG_FLAGS(
        get_page_entry((uint64_t *)PHYS_TO_VIRTUAL(src_pml4), virt_start));

    map_region((uint64_t *)PHYS_TO_VIRTUAL(dst_pml4), phys_start, virt_start,
               len, page_entry_flags);
}

// for VMM
uint64_t vmo_to_page_flags(uint64_t vmo_flags) {
    uint64_t pg_flags = 0x0;

    if (vmo_flags & VMO_PRESENT)
        pg_flags |= PMLE_PRESENT;
    if (vmo_flags & VMO_RW)
        pg_flags |= PMLE_WRITE;
    if (vmo_flags & VMO_USER)
        pg_flags |= PMLE_USER;
    if (vmo_flags & VMO_NX)
        pg_flags |= PMLE_NOT_EXECUTABLE;

    return pg_flags;
}

uint64_t page_to_vmo_flags(uint64_t pg_flags) {
    uint64_t vmo_flags = 0x0;

    if (pg_flags & PMLE_PRESENT)
        vmo_flags |= VMO_PRESENT;
    if (pg_flags & PMLE_WRITE)
        vmo_flags |= VMO_RW;
    if (pg_flags & PMLE_USER)
        vmo_flags |= VMO_USER;

    return vmo_flags;
}

// Paging initialization

uint64_t *limine_pml4; // Limine's PML4 table
uint64_t *get_limine_pml4() {
    return limine_pml4;
}

uint64_t *global_pml4;
uint64_t *get_kernel_pml4() {
    return global_pml4;
}

extern struct limine_memmap_response *memmap_response;

void pat_init(void) {
    uint64_t custom_pat =
        ((uint64_t)PAT_WRITEBACK) |          // Entry 0: WB
        ((uint64_t)PAT_WRITE_THROUGH << 8) | // Entry 1: WT
        ((uint64_t)PAT_UNCACHEABLE
         << 16) | // Entry 2: UC (should be minus but fuck that)
        ((uint64_t)PAT_UNCACHEABLE << 24) |   // Entry 3: UC
        ((uint64_t)PAT_WRITEBACK << 32) |     // Entry 4: WB
        ((uint64_t)PAT_WRITE_THROUGH << 40) | // Entry 5: WT
        ((uint64_t)PAT_WRITE_COMBINING
         << 48) | // Entry 6: WC <-- important for the framebuffer so it doesnt
                  // have ass performance
        ((uint64_t)PAT_UNCACHEABLE << 56); // Entry 7: UC

    debugf_debug("Old PAT: 0x%.16llx\n", _cpu_get_msr(0x277));
    _cpu_set_msr(0x277, custom_pat);
    debugf_debug("New PAT: 0x%.16llx\n", _cpu_get_msr(0x277));
}

// this initializes kernel-level paging
// `kernel_pml4` should already be `pmm_alloc()`'d
void paging_init(uint64_t *kernel_pml4) {
    if (kernel_pml4 == NULL) {
        kernel_pml4 = pmm_alloc_page();
    }

    limine_pml4 = _get_pml4();
    debugf_debug("Limine's PML4 sits at %llp\n", limine_pml4);

    pat_init();

    /*
            24/12/2024

            GUYS WE CAN MAP INDIVIDUAL KERNEL SECTIONS WITH PROPER PERMISSIONS
       AND WITHOUT PAGE FAULT AND REBOOT LET'S GOOOO
    */

    // kernel addresses
    uint64_t a_kernel_end = (uint64_t)&__kernel_end; // higher half kernel end

    uint64_t a_kernel_text_start = (uint64_t)&__kernel_text_start;
    uint64_t a_kernel_text_end   = (uint64_t)&__kernel_text_end;
    a_kernel_text_end            = ROUND_UP(a_kernel_text_end, PFRAME_SIZE);
    uint64_t kernel_text_len =
        ROUND_UP(a_kernel_text_end - a_kernel_text_start, PFRAME_SIZE);
    map_region(kernel_pml4, a_kernel_text_start - VIRT_BASE + PHYS_BASE,
               a_kernel_text_start, (kernel_text_len / PFRAME_SIZE),
               PMLE_KERNEL_READ_WRITE);

    uint64_t a_kernel_rodata_start = (uint64_t)&__kernel_rodata_start;
    uint64_t a_kernel_rodata_end   = (uint64_t)&__kernel_rodata_end;
    a_kernel_rodata_end            = ROUND_UP(a_kernel_rodata_end, PFRAME_SIZE);
    uint64_t kernel_rodata_len =
        ROUND_UP(a_kernel_rodata_end - a_kernel_rodata_start, PFRAME_SIZE);
    map_region(kernel_pml4, a_kernel_rodata_start - VIRT_BASE + PHYS_BASE,
               a_kernel_rodata_start, (kernel_rodata_len / PFRAME_SIZE),
               PMLE_KERNEL_READ | PMLE_NOT_EXECUTABLE);

    uint64_t a_kernel_data_start = (uint64_t)&__kernel_data_start;
    uint64_t a_kernel_data_end   = (uint64_t)&__kernel_data_end;
    a_kernel_data_end            = ROUND_UP(a_kernel_data_end, PFRAME_SIZE);
    uint64_t kernel_data_len =
        ROUND_UP(a_kernel_data_end - a_kernel_data_start, PFRAME_SIZE);

    map_region(kernel_pml4, a_kernel_data_start - VIRT_BASE + PHYS_BASE,
               a_kernel_data_start, kernel_data_len / PFRAME_SIZE,
               PMLE_KERNEL_READ_WRITE | PMLE_NOT_EXECUTABLE);

    uint64_t kernel_other_start = a_kernel_data_end;
    uint64_t kernel_other_len =
        ROUND_UP(a_kernel_end - kernel_other_start, PFRAME_SIZE);
    map_region(kernel_pml4, kernel_other_start - VIRT_BASE + PHYS_BASE,
               kernel_other_start, kernel_other_len / PFRAME_SIZE,
               PMLE_KERNEL_READ_WRITE | PMLE_NOT_EXECUTABLE);

    uint64_t a_limine_reqs_start = (uint64_t)&__limine_reqs_start;
    uint64_t a_limine_reqs_end   = (uint64_t)&__limine_reqs_end;
    uint64_t limine_reqs_len =
        ROUND_UP(a_limine_reqs_end - a_limine_reqs_start, PFRAME_SIZE);
    map_region(kernel_pml4, a_limine_reqs_start - VIRT_BASE + PHYS_BASE,
               a_limine_reqs_start, (limine_reqs_len / PFRAME_SIZE),
               PMLE_KERNEL_READ_WRITE | PMLE_NOT_EXECUTABLE);

    // map the whole memory
    for (uint64_t i = 0; i < memmap_response->entry_count; i++) {
        struct limine_memmap_entry *memmap_entry = memmap_response->entries[i];

        if (memmap_entry->type == LIMINE_MEMMAP_RESERVED)
            continue;

        if (memmap_entry->type == LIMINE_MEMMAP_FRAMEBUFFER) {
            map_region(kernel_pml4, memmap_entry->base,
                       PHYS_TO_VIRTUAL(memmap_entry->base),
                       (memmap_entry->length / PFRAME_SIZE),
                       PMLE_FRAMEBUFFER_WC);
            continue;
        }

        map_region(kernel_pml4, memmap_entry->base,
                   PHYS_TO_VIRTUAL(memmap_entry->base),
                   (memmap_entry->length / PFRAME_SIZE), PMLE_USER_READ_WRITE);
    }

    debugf_debug("Our PML4 sits at %llp\n", kernel_pml4);
    global_pml4 = (uint64_t *)VIRT_TO_PHYSICAL(kernel_pml4);

    // load our page table
    debugf_debug("Loading pml4 %llp into CR3\n", global_pml4);
    _load_pml4(global_pml4);
    debugf_debug("Guys, we're in.\n");
}

bool is_addr_mapped(uint64_t address) {
    uint64_t pml4_index = PML4_INDEX(address);
    uint64_t pdp_index  = PDP_INDEX(address);
    uint64_t pdir_index = PDIR_INDEX(address);
    uint64_t ptab_index = PTAB_INDEX(address);

    uint64_t *pml4_table = _get_pml4();
    pml4_table = (uint64_t *)PHYS_TO_VIRTUAL(pml4_table);

    if (!(pml4_table[pml4_index] & PMLE_PRESENT)) {
        return false;
    }

    uint64_t *pdp_table = (uint64_t *)PHYS_TO_VIRTUAL(
        PG_GET_ADDR(pml4_table[pml4_index])
    );
    
    if (!(pdp_table[pdp_index] & PMLE_PRESENT)) {
        return false;
    }

    uint64_t *pdir_table = (uint64_t *)PHYS_TO_VIRTUAL(
        PG_GET_ADDR(pdp_table[pdp_index])
    );
    
    if (!(pdir_table[pdir_index] & PMLE_PRESENT)) {
        return false;
    }

    uint64_t *page_table = (uint64_t *)PHYS_TO_VIRTUAL(
        PG_GET_ADDR(pdir_table[pdir_index])
    );
    
    return (page_table[ptab_index] & PMLE_PRESENT) != 0;
}

bool is_addr_mapped_in(uint64_t *pml4_table, uint64_t address) {
    uint64_t pml4_index = PML4_INDEX(address);
    uint64_t pdp_index  = PDP_INDEX(address);
    uint64_t pdir_index = PDIR_INDEX(address);
    uint64_t ptab_index = PTAB_INDEX(address);

    if (!(pml4_table[pml4_index] & PMLE_PRESENT)) {
        return false;
    }

    uint64_t *pdp_table = (uint64_t *)PHYS_TO_VIRTUAL(
        PG_GET_ADDR(pml4_table[pml4_index])
    );
    if (!(pdp_table[pdp_index] & PMLE_PRESENT)) {
        return false;
    }

    uint64_t *pdir_table = (uint64_t *)PHYS_TO_VIRTUAL(
        PG_GET_ADDR(pdp_table[pdp_index])
    );
    if (!(pdir_table[pdir_index] & PMLE_PRESENT)) {
        return false;
    }

    uint64_t *page_table = (uint64_t *)PHYS_TO_VIRTUAL(
        PG_GET_ADDR(pdir_table[pdir_index])
    );
    
    return (page_table[ptab_index] & PMLE_PRESENT) != 0;
}
