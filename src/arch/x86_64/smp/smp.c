#include "smp.h"

#include <apic/lapic/lapic.h>
#include <gdt/gdt.h>
#include <idt/idt.h>
#include <interrupts/isr.h>
#include <kernel.h>
#include <memory/heap/kheap.h>
#include <memory/vmm/vmm.h>
#include <paging/paging.h>
#include <scheduler/scheduler.h>
#include <smp/ipi.h>
#include <tsc/tsc.h>
#include <util/util.h>

#include <stdint.h>
#include <stdio.h>

struct tlb_shootdown_event **events;

extern vmm_context_t *kernel_vmm_ctx;

int smp_init() {

    bootloader_data *bootloader_data = get_bootloader_data();

    register_ipi();

    if (bootloader_data->cpu_count == 1) {
        kprintf_info("SMP init: no other CPUs detected\n");
        return 0;
    }

    events = (struct tlb_shootdown_event **)kcalloc(
        sizeof(struct tlb_shootdown_event *) * bootloader_data->cpu_count,
        sizeof(struct tlb_shootdown_event));

    kprintf_info("SMP init: %d CPUs detected\n", bootloader_data->cpu_count);
    for (uint64_t i = 0; i < bootloader_data->cpu_count; i++) {
        struct limine_smp_info *cpu = bootloader_data->cpus[i];

        if (cpu->processor_id == 0) {
            // dont init the bsp (limine shouldnt give it but just in case)
            continue;
        }

        kprintf_info("Starting CPU %lu...\n", cpu->processor_id);

        cpu->goto_address = mp_trampoline;
    }

    return 0;
}

void mp_trampoline(struct limine_smp_info *cpu) {
    UNUSED(cpu);

    asm("cli");
    gdt_init();
    idt_init();
    isr_init();

    vmm_switch_ctx(kernel_vmm_ctx);

    lapic_init();

    register_ipi();

    tsc_init();

    asm("sti");

    lapic_timer_init();

    debugf_ok("CPU %lu initialized and ready.\n", lapic_get_id());

    for (;;)
        ;
}

uint8_t get_cpu() {
    return (uint8_t)(lapic_get_id());
}
