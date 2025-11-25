
#ifndef FPU_H
#define FPU_H 1

#include <cpu.h>
#include <interrupts/isr.h>
#include <stdbool.h>

extern bool fpu_enabled;

void init_fpu();

#endif // FPU_H