#include "time.h"

#include <scheduler/scheduler.h>
#include <util/util.h>

#include <stdio.h>

static uint64_t ticks;

uint64_t get_ticks() {
    return ticks;
}

void set_ticks(uint64_t new) {
    ticks = new;
}

void timer_tick(void *ctx) {
    UNUSED(ctx);

    set_ticks(get_ticks() + 1);
}

void scheduler_timer_tick(void *ctx) {
    timer_tick(ctx);

    yield();
}
