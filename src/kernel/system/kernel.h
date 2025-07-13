/*
        A simple structure to save some bootloader requests that might be useful
   later

        Original idea by
   https://github.com/malwarepad/cavOS/blob/master/src/kernel/include/bootloader.h
*/

#ifndef KERNEL_H
#define KERNEL_H 1

#include <limine.h>

#include <stdbool.h>
#include <stddef.h>

// these come from the linker
// from
// https://github.com/malwarepad/cavOS/blob/3ddf0b2f8d72aee57a13a906c19bde403e425c0d/src/kernel/include/bootloader.h#L7
extern uint64_t __kernel_text_start, __kernel_text_end;
extern uint64_t __kernel_rodata_start, __kernel_rodata_end;
extern uint64_t __kernel_data_start, __kernel_data_end;
extern uint64_t __kernel_start, __kernel_end;

extern uint64_t __limine_reqs_start, __limine_reqs_end;

typedef struct bootloader_data {

    // Memory Map
    size_t memory_total;
    size_t memory_usable_total;
    uint64_t memmap_entry_count;
    uint64_t usable_entry_count;

    LIMINE_PTR(struct limine_memmap_entry **) limine_memory_map;

    uint64_t hhdm_offset;

    uint64_t kernel_base_physical;
    uint64_t kernel_base_virtual;

    // ACPI/MMIO related stuff
    uint64_t *rsdp_table_address;

    uint64_t p_lapic_base;
    uint32_t p_ioapic_base;

    // framebuffer
    struct limine_framebuffer *framebuffer;

    // SMP stuff
    uint64_t cpu_count;
    LIMINE_PTR(struct limine_smp_info **) cpus;
    bool smp_enabled; // * do not remove or tlb handler will shit itself

    uint64_t boot_time; // milliseconds since boot

    // scheduler
    bool scheduler_enabled;

    void *kernel_file_data;
    size_t kernel_file_size;
} bootloader_data;

struct bootloader_data *get_bootloader_data();

#endif
