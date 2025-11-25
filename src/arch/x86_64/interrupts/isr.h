#ifndef ISR_H
#define ISR_H 1

#include <stdint.h>
#include <util/macro.h>

#include <cpu.h>

typedef void (*isrHandler)(void *ctx);

void print_reg_dump(void *ctx);

void isr_init();
void isr_registerHandler(int interrupt, isrHandler handler);

void panic_common(void *ctx);

extern void _hcf();

#endif
