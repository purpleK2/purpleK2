#include <smp/ipi.h>

#include <apic/lapic/lapic.h>
#include <interrupts/isr.h>
#include <util/string.h>

extern void ipi_handler_halt(void *ctx);
extern void ipi_handler_tlb_flush(void *ctx);
extern void ipi_handler_reschedule(void *ctx);
extern void ipi_handler_test(void *ctx);
extern void
do_nothing_and_shut_up_im_talking_to_you_vector_254_yes_you_just_dont_spam_logs_ok_thanks(
    void *ctx);

void register_ipi(void) {
    isr_registerHandler(IPI_VECTOR_HALT, ipi_handler_halt);
    isr_registerHandler(IPI_VECTOR_TLB_FLUSH, ipi_handler_tlb_flush);
    isr_registerHandler(IPI_VECTOR_RESCHEDULE, ipi_handler_reschedule);
    isr_registerHandler(IPI_VECTOR_TEST, ipi_handler_test);

    // isr_registerHandler(
    //     254,
    //     do_nothing_and_shut_up_im_talking_to_you_vector_254_yes_you_just_dont_spam_logs_ok_thanks);
    //     // * note: this is not malware. Context: the logs would always be
    //     full with "Unhandled interrupt 254"
}

void ipi_send(uint8_t vector, uint8_t cpu) {
    // set the cpu-id register in ICR1
    uint32_t icr1 = (uint32_t)cpu << 24;
    lapic_write_reg(LAPIC_ICR1_REG, icr1);

    // send le IPI
    uint32_t icr0 = vector | (0 << 8) | (0 << 11) | (1 << 14) | (0 << 15) |
                    (LDT_NO_SHORTHAND << 18);
    lapic_write_reg(LAPIC_ICR0_REG, icr0);
}

void ipi_broadcast(uint8_t vector) {
    // broadcast and ipi to all other LAPICs except our
    uint32_t icr0 = vector | (0 << 8) | (0 << 11) | (1 << 14) | (0 << 15) |
                    (LDT_ALL_LAPICS_NOT_US << 18);
    lapic_write_reg(LAPIC_ICR0_REG, icr0);
}

void ipi_self(uint8_t vector) {
    // send an ipi to your own LAPIC for testing porpuses
    uint32_t icr0 = vector | (0 << 8) | (0 << 11) | (1 << 14) | (0 << 15) |
                    (LDT_SEND_TO_US << 18);
    lapic_write_reg(LAPIC_ICR0_REG, icr0);
}

void tlb_shootdown(uint64_t virtual) {
    ipi_broadcast(IPI_VECTOR_TLB_FLUSH);
}