#include "tsc.h"

#include <interrupts/isr.h>
#include <pit/pit.h>
#include <util/util.h>

#include <stdio.h>

uint64_t tsc_frequency = 0;

void tsc_sleep(uint64_t microseconds) {
    asm volatile("cli");
    uint64_t start = _get_tsc();

    uint64_t cycles_to_wait = (tsc_frequency / 1000000) * microseconds;

    while ((_get_tsc() - start) < cycles_to_wait)
        ;
    asm volatile("sti");
}

uint64_t get_cpu_freq_msr() {
    uint64_t start_tsc, end_tsc;

    start_tsc = _get_tsc();

    pit_sleep(1000);

    end_tsc = _get_tsc();

    uint64_t tsc_diff = end_tsc - start_tsc; // Convert to seconds

    return tsc_diff;
}

void tsc_init() {
    tsc_frequency = get_cpu_freq_msr();

    debugf_debug("Successfully initialized TSC with CPU Frequency %llu Hz\n",
                 tsc_frequency);
}
