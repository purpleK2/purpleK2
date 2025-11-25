#include "irq.h"

#include <pic/pic.h>

#include <interrupts/isr.h>

#include <io.h>
#include <stdio.h>

#include <stddef.h>

#include <apic/ioapic/ioapic.h>
#include <apic/lapic/lapic.h>
#include <cpu.h>

void irq_init() {
    pic_config(PIC_REMAP_OFFSET, PIC_REMAP_OFFSET + 8);

    for (int i = 0; i < 16; i++) {
        isr_registerHandler(PIC_REMAP_OFFSET + i, pic_irq_handler);
    }

    _enable_interrupts();
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
