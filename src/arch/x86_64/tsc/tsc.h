#ifndef TSC_H
#define TSC_H 1

#include <interrupts/isr.h>

#include <stdbool.h>
#include <stdint.h>

extern bool tsc;
extern uint64_t tsc_frequency;

extern uint64_t _get_tsc();
void tsc_tick_handler(void *ctx);
void tsc_sleep(uint64_t microseconds);
uint64_t get_cpu_freq_msr();

void tsc_init();

#endif
