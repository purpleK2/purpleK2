#ifndef IOAPIC_H
#define IOAPIC_H 1

#include <stdint.h>

#include <interrupts/irq.h>

#define IOAPIC_REDTBL_ENTRIES 24

#define IOAPIC_REG_VER 0x01

#define IOAPIC_RETBL_START 0x10

#define IOAPIC_IRQ_OFFSET 0x20

void set_ioapic_base(uint64_t base);

void ioapic_registerHandler(int irq, irq_handler handler);

void ioapic_init();

#endif