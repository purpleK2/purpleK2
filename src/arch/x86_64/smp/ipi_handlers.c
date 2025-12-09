#include <apic/lapic/lapic.h>
#include <interrupts/isr.h>
#include <memory/vmm/vmm.h>
#include <scheduler/scheduler.h>
#include <smp/smp.h>

#include <stdio.h>

void do_nothing_and_shut_up_im_talking_to_you_vector_254_yes_you_just_dont_spam_logs_ok_thanks(
    registers_t *ctx) {
    (void)ctx;
    lapic_send_eoi();
}

void ipi_handler_halt(registers_t *ctx) {
    // beauty only 💅
    uint64_t cpu = get_cpu();
    debugf_warn("Processor %lu halted over IPI @ %.16llx\n", cpu,
                ((registers_t *)ctx)->rip);
    lapic_send_eoi();

    // actual halting
    asm("cli");
    for (;;)
        asm("hlt");
}

void ipi_handler_tlb_flush(registers_t *ctx) {
    uint64_t cpu = get_cpu();

    debugf_debug("Processor %lu flushed TLB @ %llx\n", cpu,
                 ((registers_t *)ctx)->rip);

    _load_pml4(get_current_vmc()->pml4_table);
    lapic_send_eoi();
}

void ipi_handler_reschedule(registers_t *ctx) {
    uint64_t cpu = get_cpu();
    debugf_debug("Processor %lu rescheduled @ %.16llx\n", cpu,
                 ((registers_t *)ctx)->rip);
    lapic_send_eoi();
}

void ipi_handler_test(registers_t *ctx) {
    uint64_t cpu = get_cpu();
    debugf_debug("Processor %lu received test IPI @ %.16llx\n", cpu,
                 ((registers_t *)ctx)->rip);
    lapic_send_eoi();
}
