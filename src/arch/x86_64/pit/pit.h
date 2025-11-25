#ifndef PIT_H
#define PIT_H 1

#include <interrupts/irq.h>

#include <stdint.h>

#define PIT_CH0_DATA 0x40
#define PIT_CH1_DATA 0x41
#define PIT_CH2_DATA 0x42
#define PIT_MODE_CMD 0x43

// PIT runs at 1.1931812 MHz (~2 million Hertz)
#define CONST_PIT_CLOCK 1193181

uint64_t get_ticks();

void pit_sleep(uint32_t millis);

void pit_init(const uint32_t freq);

#endif