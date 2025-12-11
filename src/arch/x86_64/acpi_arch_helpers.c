#include "acpi_arch_helpers.h"

#include <uacpi/uacpi.h>

#include <apic/ioapic/ioapic.h>
#include <apic/lapic/lapic.h>
#include <pic/pic.h>

#include <interrupts/irq.h>
#include <interrupts/isr.h>

#include <memory/heap/kheap.h>

#include <stdio.h>

uacpi_handle *uacpi_ctxs;
uacpi_interrupt_handler *uacpi_handlers;
// the maximum IRQ we have registered + 1
uint32_t irq_count = 0;

void uacpi_irq_handler(registers_t *ctx) {
    int irq = ctx->interrupt;
    if (is_lapic_enabled()) {
        irq -= IOAPIC_IRQ_OFFSET;
    } else {
        irq -= PIC_REMAP_OFFSET;
    }

    if (!uacpi_handlers[irq]) {
        debugf("[UACPI] Unhandled IRQ %lld\n", ctx->interrupt);
        return;
    }

    if (!uacpi_ctxs[irq]) {
        debugf("[UACPI] No uACPI context give to this IRQ (%lld)\n",
               ctx->interrupt);
    }

    uacpi_handle uacpi_ctx = uacpi_ctxs[irq];
    uacpi_handlers[irq](uacpi_ctx);
}

void uacpi_register_handler(uint32_t irq, uacpi_handle ctx,
                            uacpi_interrupt_handler handler) {
    if (irq > irq_count || !irq_count) {
        irq_count = (irq + 1);

        uacpi_ctxs     = krealloc(uacpi_ctxs, sizeof(uacpi_handle) * irq_count);
        uacpi_handlers = krealloc(uacpi_handlers,
                                  sizeof(uacpi_interrupt_handler) * irq_count);
    }

    uacpi_ctxs[irq]     = ctx;
    uacpi_handlers[irq] = handler;

    irq_registerHandler(irq, uacpi_irq_handler);
}

void uacpi_unregister_handler(uint32_t irq) {
    if (irq > irq_count || !irq_count) {
        return;
    }

    uacpi_ctxs[irq]     = NULL;
    uacpi_handlers[irq] = NULL;

    irq_unregisterHandler(irq);
}
