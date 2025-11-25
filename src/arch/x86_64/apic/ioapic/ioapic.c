#include "ioapic.h"

#include <apic/lapic/lapic.h>

#include <acpi/tables/madt.h>
#include <acpi/uacpi/acpi.h>
#include <acpi/uacpi/tables.h>
#include <acpi/uacpi/uacpi.h>

#include <memory/heap/kheap.h>
#include <memory/pmm/pmm.h>
#include <paging/paging.h>

#include <interrupts/isr.h>

#include <stdint.h>
#include <stdio.h>

#include <time.h>

uint64_t ioapic_base = 0;

void set_ioapic_base(uint64_t base) {
    ioapic_base = base;
}

irq_handler apic_irq_handlers[IOAPIC_REDTBL_ENTRIES];

uint32_t ioapic_reg_read(uint8_t reg) {
    uint32_t volatile *regsel = (uint32_t volatile *)ioapic_base;
    regsel[0]                 = reg;

    return regsel[4];
}

void ioapic_reg_write(uint8_t reg, uint32_t value) {
    uint32_t volatile *regsel = (uint32_t volatile *)ioapic_base;
    regsel[0]                 = reg;

    regsel[4] = value;
}

void apic_irq_handler(void *ctx) {
    registers_t *regs = ctx;

    int apic_irq = regs->interrupt - IOAPIC_IRQ_OFFSET;

    uint64_t apic_isr = lapic_read_reg(LAPIC_INSERVICE_REG);
    uint64_t apic_irr = lapic_read_reg(LAPIC_INT_REQ_REG);

    if (apic_irq_handlers[apic_irq] != NULL) {
        apic_irq_handlers[apic_irq](regs);
    } else {
        debugf_warn("Unhandled IRQ %d  ISR=%llx  IRR=%llx\n", apic_irq,
                    apic_isr, apic_irr);
    }

    lapic_send_eoi();
}

void ioapic_registerHandler(int irq, irq_handler handler) {
    apic_irq_handlers[irq] = handler;
}

void ioapic_unregisterHandler(int irq) {
    if (irq >= 0 && irq < IOAPIC_REDTBL_ENTRIES) {
        apic_irq_handlers[irq] = NULL;
    }
}

// maps an I/O APIC IRQ to an interrupt that calls the handler if fired
// @param irq			- The hardware interrupt that'll be fired
// @param interrupt		- The interrupt vector that will be written to
// the I/O APIC
// @param handler		- The ISR that will be called when the interrupt
// gets fired

void ioapic_map_irq(int irq, int interrupt, irq_handler handler) {
    uint32_t redtble_lo = (0 << 16) |    // Unmask the entry
                          (0 << 11) |    // Destination mode
                          (0b000 << 8) | // Delivery mode
                          interrupt;     // interrupt vector
    ioapic_reg_write(0x10 + (2 * irq), redtble_lo);

    uint32_t redtble_hi = (lapic_get_id() << 24);
    ioapic_reg_write(0x10 + (2 * irq) + 1, redtble_hi);

    isr_registerHandler(interrupt, handler);
}

// expects that uACPI is initialized
void ioapic_init() {
    uacpi_table *table = kmalloc(sizeof(uacpi_table));
    uacpi_table_find_by_signature(ACPI_MADT_SIGNATURE, table);
    struct acpi_madt *madt = table->ptr;

    struct acpi_madt_ioapic *madt_record_ioapic =
        madt_find_record(madt, ACPI_MADT_ENTRY_TYPE_IOAPIC);

    debugf_debug("I/O APIC base: %llx\n", madt_record_ioapic->address);

    ioapic_base = PHYS_TO_VIRTUAL(madt_record_ioapic->address);

    map_region_to_page((uint64_t *)PHYS_TO_VIRTUAL(get_kernel_pml4()),
                       madt_record_ioapic->address, ioapic_base, 0x1000,
                       PMLE_KERNEL_READ_WRITE);

    uint8_t ioapic_max_redir_entry = (ioapic_reg_read(0x01) >> 16) & 0xFF;
    debugf_debug("Redirection entries: %hhu\n", ioapic_max_redir_entry + 1);
    debugf_debug("Global I/O APIC IRQ base: %llx\n",
                 madt_record_ioapic->gsi_base);

    // find the first redirection entry, we should then be good to parse the
    // others
    struct acpi_madt_interrupt_source_override *ioapic_isos =
        madt_find_record(madt, ACPI_MADT_ENTRY_TYPE_INTERRUPT_SOURCE_OVERRIDE);
    int redirection_entries = 1;
    for (; ioapic_isos[redirection_entries].hdr.type ==
           ACPI_MADT_ENTRY_TYPE_INTERRUPT_SOURCE_OVERRIDE;
         redirection_entries++)
        ;

    for (int i = 0; i < redirection_entries; i++) {
        debugf_debug("Redirection entry n.%d:\n", i + 1);
        debugf_debug("\tLegacy PIC IRQ: %hhu\n", ioapic_isos[i].source);
        debugf_debug("\tRemapped IRQ: %hhu\n", ioapic_isos[i].gsi);

        if (ioapic_isos[i].source != ioapic_isos[i].gsi) {
            ioapic_map_irq(ioapic_isos[i].gsi,
                           ioapic_isos[i].source + IOAPIC_IRQ_OFFSET,
                           apic_irq_handler);

            ioapic_map_irq(ioapic_isos[i].source,
                           ioapic_isos[i].gsi + IOAPIC_IRQ_OFFSET,
                           apic_irq_handler);
        }
    }

    for (int i = 0; i < IOAPIC_REDTBL_ENTRIES; i++) {
        // to map the other normal interrupts, we'll just check if it's masked
        // or not
        if (ioapic_reg_read(0x10 + (2 * i)) & (1 << 16)) {
            ioapic_map_irq(i, i + IOAPIC_IRQ_OFFSET, apic_irq_handler);
        }
    }

    irq_registerHandler(0, timer_tick);

    kfree(table);
    kfree(madt);
}
