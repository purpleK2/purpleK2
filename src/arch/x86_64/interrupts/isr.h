#ifndef ISR_H
#define ISR_H 1

#include <stdint.h>
#include <util/macro.h>

#include <cpu.h>

typedef void (*isrHandler)(registers_t *ctx);
struct stackFrame {
    struct stackFrame *rbp;
    uint64_t rip;
};

void print_reg_dump(registers_t *ctx);

void isr_init();
void isr_registerHandler(int interrupt, isrHandler handler);

void print_stack_trace(uint64_t rbp, uint64_t rip);
void panic_common(registers_t *ctx);

extern void _hcf();

#endif
