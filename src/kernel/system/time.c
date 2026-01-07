#include "time.h"

#include <interrupts/irq.h>
#include <scheduler/scheduler.h>
#include <util/util.h>

static uint64_t ticks;

uint64_t get_ticks() {
    return ticks;
}

void set_ticks(uint64_t new) {
    ticks = new;
}

void timer_tick(registers_t *ctx) {
    UNUSED(ctx);

    set_ticks(get_ticks() + 1);
}

void scheduler_timer_tick(registers_t *ctx) {
    timer_tick(ctx);
    yield();
}
