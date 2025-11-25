#include "pit.h"

#include <io.h>
#include <stdbool.h>

#include <util/util.h>

#include <time.h>

void pit_sleep(uint32_t millis) {
    uint64_t last_tick = get_ticks() + millis;
    while (get_ticks() < last_tick)
        ;
}

void pit_init(const uint32_t freq) {
    set_ticks(0);

    uint32_t divisor = CONST_PIT_CLOCK / freq;

    // --- 0x36 0011 0110 ---

    // 00: 	select channel 0
    // 11: 	access high AND low byte

    // 011: Mode 3 (square wave generator)
    // 0:	16-bit binary
    _outb(PIT_MODE_CMD, 0x36);
    // set the PIT frequency (freq/PIT's clock frequency)
    _outb(PIT_CH0_DATA, (uint8_t)(divisor & 0xFF));
    _io_wait();
    _outb(PIT_CH0_DATA, (uint8_t)((divisor >> 8) & 0xFF));
}
