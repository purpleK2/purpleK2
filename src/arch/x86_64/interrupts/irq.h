#ifndef IRQ_H
#define IRQ_H 1

#include <interrupts/isr.h>

#include <stdint.h>

typedef void (*irq_handler)(registers_t *ctx);

void irq_sendEOI(uint8_t irq);

extern void _enable_interrupts();
extern void _disable_interrupts();

extern int change_to_kernel_pml4_on_int;

void irq_init();

void irq_registerHandler(int irq, irq_handler handler);
void irq_unregisterHandler(int irq);

#endif
