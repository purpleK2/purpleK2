#include "hpet.h"

#include <apic/ioapic/ioapic.h>
#include <interrupts/irq.h>
#include <memory/heap/kheap.h>
#include <memory/pmm/pmm.h>
#include <paging/paging.h>
#include <uacpi/acpi.h>
#include <uacpi/tables.h>

#include <stdio.h>

uint64_t hpet_base_glob      = 0;
uint64_t hpet_counter        = 0;
bool hpet_initialized        = false;
hpet_timer_t hpet_timers[32] = {0}; // 32 timers, max supported by HPET

int hpet_init(void) {

    uacpi_table *hpet_table = kmalloc(sizeof(uacpi_table));
    if (uacpi_table_find_by_signature("HPET", hpet_table) != UACPI_STATUS_OK) {
        kprintf("HPET table not found!\n");
        return -1;
    }

    struct acpi_hpet *hpet = (struct acpi_hpet *)hpet_table->ptr;
    if (hpet == NULL) {
        kprintf("HPET table is NULL!\n");
        kfree(hpet_table);
        return -1;
    }

    debugf_debug("HPET base address: %.16llx\n", hpet->address.address);

    // map the address
    uint64_t hpet_base = hpet->address.address;
    map_region_to_page((uint64_t *)PHYS_TO_VIRTUAL(get_kernel_pml4()),
                       hpet_base, PHYS_TO_VIRTUAL(hpet_base), 0x1000,
                       PMLE_KERNEL_READ_WRITE);
    hpet_base_glob = hpet_base; // save the base address globally

    // enable the HPET
    hpet_cap_reg_t *hpet_capabilities =
        (hpet_cap_reg_t *)(PHYS_TO_VIRTUAL(hpet_base));
    if (!(hpet_capabilities->raw & 0x1)) {
        kprintf("HPET is not enabled!\n");
        kfree(hpet_table);
        return -1;
    }
    debugf_debug("HPET Counter Clock Period: %llu ns\n",
                 HPET_GET_CLK_PERIOD(*hpet_capabilities) / 1000000);
    debugf_debug("HPET Revision ID: %hhu\n",
                 HPET_GET_REV_ID(*hpet_capabilities));
    debugf_debug("HPET Timer amount: %hhu\n",
                 HPET_GET_NUM_TIM_CAP(*hpet_capabilities) + 1);
    debugf_debug("HPET Supports 64-Bit: %hhu\n",
                 HPET_GET_COUNT_SIZE_CAP(*hpet_capabilities));
    debugf_debug("HPET can replace RTC and PIT: %hhu\n",
                 HPET_GET_LEG_RT_CAP(*hpet_capabilities));

    hpet_gcr_reg_t *hpet_global_config =
        (hpet_gcr_reg_t *)(PHYS_TO_VIRTUAL(hpet_base + 0x10));

    hpet_global_config->raw = 0b01; // standard mode and enable

    int hpet_next_allowed_irq = 0;

    for (int i = 0; i < HPET_GET_NUM_TIM_CAP(*hpet_capabilities) + 1; i++) {
        hpet_timer_entry_t *hpet_timer = (hpet_timer_entry_t *)(PHYS_TO_VIRTUAL(
            hpet_base + 0x100 + (i * 0x20)));

        // get bit 4 to check if it supports periodic mode
        if (BIT_GET(4, hpet_timer->conf_and_cap_reg)) {
            debugf_debug("    HPET Timer %d supports periodic mode.\n", i);
        } else {
            debugf_debug("    HPET Timer %d does not support periodic mode.\n",
                         i);
        }

        BIT_SET(hpet_timer->conf_and_cap_reg, 1);    // edge triggered mode
        BIT_SET(hpet_timer->conf_and_cap_reg, 3);    // enable periodic mode
        BIT_CLEAR(hpet_timer->conf_and_cap_reg, 8);  // ensure 64-bit mode
        BIT_CLEAR(hpet_timer->conf_and_cap_reg, 14); // no FSB mode

        // get higher 32 bits of the conf and cap reg to see what irqs are
        // allowed
        uint32_t allowed_irqs =
            (hpet_timer->conf_and_cap_reg >> 32) & 0xFFFFFFFF;
        int32_t first_irq = hpet_next_allowed_irq;
        // print every allowed irq using each bit to determine if it's set
        if (allowed_irqs == 0) {
            debugf_debug("    HPET Timer %d does not support any IRQs.\n", i);
        } else {
            debugf_debug("    HPET Timer %d supports the following IRQs:", i);
            for (int j = 0; j < 32; j++) {
                if (allowed_irqs & (1 << j)) {
                    debugf(COLOR(ANSI_COLOR_GRAY, "%d, "), j);
                    if (j == first_irq) {
                        first_irq = j; // save the first allowed IRQ
                    }
                }
            }
            debugf("\n");
        }

        hpet_timer->fsb_reg = 0; // reset the FSB register

        debugf_debug("   HPET Timer %d using IRQ %d\n", i, first_irq);

        if (i == 0) {
            // timer 0 is the main timer, the interval is 1µs
            hpet_timer->comp_val_reg = 100; // 100 ticks = 1µs
        } else {
            hpet_timer->comp_val_reg = 0;
        }

        // BIT_SET(hpet_timer->conf_and_cap_reg, 2); // enable the timer

        hpet_timers[i].entry   = hpet_timer;
        hpet_timers[i].irq_num = first_irq;

        hpet_next_allowed_irq++;
    }

    hpet_halt();

    // register_hpet_irq(0, hpet_main_timer); // timer 0 will be the main timer
    // duh
    //  hpet_start();

    return 0;
}

void register_hpet_irq(int timer, irq_handler handler) {
    ioapic_registerHandler(hpet_timers[timer].irq_num, handler);
}

uint64_t hpet_timer_get_value(int timer) {
    hpet_timer_entry_t *hpet_timer = (hpet_timer_entry_t *)(PHYS_TO_VIRTUAL(
        hpet_base_glob + 0x100 + (timer * 0x20)));

    return hpet_timer->comp_val_reg;
}

void hpet_halt(void) {
    hpet_gcr_reg_t *hpet_global_config =
        (hpet_gcr_reg_t *)(PHYS_TO_VIRTUAL(hpet_base_glob + 0x10));
    hpet_global_config->raw = 0; // disable HPET
}

uint64_t hpet_start(void) {
    hpet_gcr_reg_t *hpet_global_config =
        (hpet_gcr_reg_t *)(PHYS_TO_VIRTUAL(hpet_base_glob + 0x10));
    hpet_global_config->raw |= 0b1; // enable HPET
    return hpet_base_glob;
}

uint64_t hpet_get_base(void) {
    return hpet_base_glob;
}

uint64_t hpet_get_main_counter(void) {
    hpet_halt();
    hpet_mcv_reg_t *hpet_main_counter =
        (hpet_mcv_reg_t *)(PHYS_TO_VIRTUAL(hpet_base_glob + 0x0F0));
    uint64_t val = hpet_main_counter->raw;
    hpet_start();
    return val;
}

uint64_t hpet_get_counter() {
    return hpet_counter;
}

void hpet_main_timer(void *ctx) {
}
