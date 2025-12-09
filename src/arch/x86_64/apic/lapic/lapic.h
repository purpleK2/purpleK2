#ifndef LAPIC_H
#define LAPIC_H 1

#include <stdbool.h>
#include <stdint.h>

#include <interrupts/isr.h>

#define LAPIC_BASE_MSR  0x1B
#define LAPIC_BASE_MASK 0xffffff000

#define LAPIC_ID_REG         0x020
#define LAPIC_VER_REG        0x030
#define LAPIC_TASKPR_REG     0x080
#define LAPIC_EOI_REG        0x0B0
#define LAPIC_LOCAL_DEST_REG 0x0D0
#define LAPIC_DEST_FMT_REG   0x0E0
#define LAPIC_SPURIOUS_REG   0x0F0
#define MAX_LAPIC_TICKS      0xFFFFFFFFFFFFFFFF

#define LAPIC_INSERVICE_REG 0x100
#define LAPIC_INT_REQ_REG   0x200

#define LAPIC_CMCI_REG 0x2f0

#define LAPIC_ICR0_REG 0x300
#define LAPIC_ICR1_REG 0x310

#define LAPIC_TIMER_REG         0x320
#define LAPIC_THERM_REG         0x330
#define LAPIC_PERFMON_COUNT_REG 0x340
#define LAPIC_LINT0_REG         0x350
#define LAPIC_LINT1_REG         0x360
#define LAPIC_ERR_REG           0x370

#define LAPIC_TIMER_INIT_CNT 0x380
#define LAPIC_TIMER_CURR_CNT 0x390
#define LAPIC_TIMER_DIV_REG  0x3E0

#define LAPIC_ENABLE_BIT (1 << 8)

#define LAPIC_IRQ_OFFSET 0x20

#define LAPIC_TIMER_VECTOR    0
#define LAPIC_SPURIOUS_VECTOR 0xFF

#define LAPIC_DISABLE (1 << 16)
#define LAPIC_NMI     (4 << 8)

// LDT: Lapic Destination Type
#define LDT_NO_SHORTHAND      0b00
#define LDT_SEND_TO_US        0b01
#define LDT_ALL_LAPICS        0b10
#define LDT_ALL_LAPICS_NOT_US 0b11

bool is_lapic_enabled();

void set_lapic_base(uint64_t base);

void lapic_write_reg(uint64_t reg, uint32_t value);
uint64_t lapic_read_reg(uint64_t reg);

uint64_t lapic_get_id();
void lapic_send_eoi();

void lapic_init();

uint32_t lapic_timer_calibrate_pit(void);
uint32_t calibrate_apic_timer_tsc(void);
void lapic_timer_init();
void lapic_timer_handler(registers_t *ctx);

#endif