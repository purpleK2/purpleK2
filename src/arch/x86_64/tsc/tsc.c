#include "tsc.h"
#include "kernel.h"
#include "scheduler/scheduler.h"

#include <cpuid.h>
#include <interrupts/isr.h>
#include <stdio.h>
#include <time.h>
#include <util/util.h>

volatile uint64_t tsc_ticks = 0;

uint64_t cpu_frequency_hz1 = 0;

uint64_t get_cpu_freq_cpuid() {
    uint32_t eax, ebx, ecx, edx;
    __get_cpuid(0x15, &eax, &ebx, &ecx, &edx);

    if (eax == 0 || ebx == 0) {
        // Unsupported or no info, fallback or return 0
        return 0;
    }

    // crystal frequency (Hz)
    uint64_t crystal_hz =
        (ecx != 0) ? ecx : 25000000; // fallback 25 MHz if zero

    // TSC frequency = crystal_hz * (EBX / EAX)
    uint64_t tsc_freq = (crystal_hz * (uint64_t)ebx) / eax;

    return tsc_freq;
}

void tsc_tick_handler(void *ctx) {
    UNUSED(ctx);

    debugf(".");

    static uint64_t last_tsc = 0;
    uint64_t current_tsc     = _get_tsc();

    if (last_tsc == 0) {
        last_tsc = current_tsc;
        return;
    }

    uint64_t elapsed_tsc = current_tsc - last_tsc;
    uint64_t elapsed_ms  = (elapsed_tsc * 1000) / cpu_frequency_hz1;

    if (elapsed_ms > 0) {
        tsc_ticks += elapsed_ms;
        set_ticks(get_ticks() + elapsed_ms);
        last_tsc += (cpu_frequency_hz1 * elapsed_ms) / 1000;
    }
}

void tsc_sleep(uint64_t microseconds) {
    asm volatile("cli");
    uint64_t start = _get_tsc();

    uint64_t cycles_to_wait = (microseconds * cpu_frequency_hz1) / 1000000;

    while ((_get_tsc() - start) < cycles_to_wait)
        ;
    asm volatile("sti");
}

uint64_t get_cpu_freq_msr() {
    uint64_t start_tsc, end_tsc;

    start_tsc = _get_tsc();

    tsc_sleep(1000000); // sleep 1 second = 1,000,000 µs

    end_tsc = _get_tsc();

    uint64_t tsc_diff = end_tsc - start_tsc;

    return tsc_diff;
}

void tsc_init() {
    isr_registerHandler(238, tsc_tick_handler);

    cpu_frequency_hz1 = get_cpu_freq_cpuid();
    if (cpu_frequency_hz1 == 0) {
        debugf_debug("CPUID leaf 0x15 unsupported, fallback to slow method\n");
        cpu_frequency_hz1 =
            get_cpu_freq_msr(); // fallback to your previous slow method
    }

    debugf_debug("Successfully initialized TSC with CPU Frequency %llu Hz\n",
                 cpu_frequency_hz1);
}
