#ifndef IRQ_H
#define IRQ_H 1

#include <stdint.h>

#include "isr.h"

typedef void (*irq_handler)(void *ctx);

void irq_registerHandler(int irq, irq_handler handler);

extern void _enable_interrupts();
extern void _disable_interrupts();

void irq_init();

#endif
