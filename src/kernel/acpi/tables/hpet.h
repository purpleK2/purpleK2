#ifndef HPET_H
#define HPET_H 1

#include "interrupts/irq.h"
#include <stdint.h>

#define SET_BIT(x, bit)   ((x) |= (1ULL << (bit)))
#define CLEAR_BIT(x, bit) ((x) &= ~(1ULL << (bit)))
#define GET_BIT(x, bit)   (((x) >> (bit)) & 1)

#define HPET_GET_REV_ID(cap)         ((uint8_t)((cap).raw & 0xFF))
#define HPET_GET_NUM_TIM_CAP(cap)    ((uint8_t)(((cap).raw >> 8) & 0x1F))
#define HPET_GET_COUNT_SIZE_CAP(cap) (((cap).raw >> 13) & 0x1)
#define HPET_GET_LEG_RT_CAP(cap)     (((cap).raw >> 15) & 0x1)
#define HPET_GET_VENDOR_ID(cap)      ((uint16_t)(((cap).raw >> 16) & 0xFFFF))
#define HPET_GET_CLK_PERIOD(cap)     ((uint32_t)((cap).raw >> 32))

typedef struct hpet_cap_reg {
    uint64_t raw;
} hpet_cap_reg_t;

typedef struct hpet_gcr_reg {
    uint64_t raw;
} hpet_gcr_reg_t;

typedef struct hpet_mcv_reg {
    uint64_t raw;
} hpet_mcv_reg_t;

typedef struct hpet_timer_entry {
    uint64_t conf_and_cap_reg;
    uint64_t comp_val_reg;
    uint64_t fsb_reg;
} hpet_timer_entry_t;

typedef struct hpet_timer {
    hpet_timer_entry_t *entry;
    int irq_num;
} hpet_timer_t;

int hpet_init(void);

void register_hpet_irq(int timer, irq_handler handler);
uint64_t hpet_timer_get_value(int timer);
void hpet_halt(void);
uint64_t hpet_start(void);
uint64_t hpet_get_base(void);
uint64_t hpet_get_counter(void);

#endif // HPET_H