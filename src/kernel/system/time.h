#ifndef TIME_H
#define TIME_H 1

#include <interrupts/isr.h>

#include <stdint.h>

uint64_t get_ticks();
void set_ticks(uint64_t new);

void timer_tick(void *ctx);
void scheduler_timer_tick(void *ctx);

#endif