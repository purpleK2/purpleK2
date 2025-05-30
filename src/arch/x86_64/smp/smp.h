#ifndef SMP_H
#define SMP_H 1

#include <limine.h>

struct tlb_shootdown_event {
    uint64_t virtual;
    uint64_t length;
};

extern struct tlb_shootdown_event **events;

int smp_init();
void mp_trampoline(struct limine_smp_info *cpu);

uint8_t get_cpu();

#endif