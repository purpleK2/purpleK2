#include "irq.h"

#include <apic/ioapic/ioapic.h>
#include <apic/lapic/lapic.h>
#include <cpu.h>
#include <interrupts/isr.h>
#include <io.h>
#include <pic/pic.h>

#include <stddef.h>
#include <stdio.h>

int change_to_kernel_pml4_on_int = 0;

void irq_init() {
    for (int i = 0; i < 16; i++) {
        isr_registerHandler(PIC_REMAP_OFFSET + i, pic_irq_handler);
    }

    // trusting yeint on this pt.2
    // _enable_interrupts();
}

void irq_sendEOI(uint8_t irq) {
    if (is_lapic_enabled()) {
        lapic_send_eoi();
    } else {
        pic_sendEOI(irq);
    }
}

// this function should be used after checking if the APIC is supported or not
void irq_registerHandler(int irq, irq_handler handler) {
    debugf_debug("Registering handler for IRQ %d\n", irq);
    if (is_lapic_enabled()) {
        ioapic_registerHandler(irq, handler);
    } else {
        pic_registerHandler(irq, handler);
    }
}

void irq_unregisterHandler(int irq) {
    if (is_lapic_enabled()) {
        ioapic_unregisterHandler(irq);
    } else {
        pic_unregisterHandler(irq);
    }
}
