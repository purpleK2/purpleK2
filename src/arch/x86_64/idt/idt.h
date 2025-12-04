#ifndef IDT_H
#define IDT_H 1

#define IDT_MAX_DESCRIPTORS 256

#include <stdint.h>

#include <util/macro.h>

extern void *isr_stub_table[];

typedef enum {
    IDT_FLAG_GATE_TASK       = 0x5,
    IDT_FLAG_GATE_16BIT_INT  = 0x6,
    IDT_FLAG_GATE_16BIT_TRAP = 0x7,
    IDT_FLAG_GATE_32BIT_INT  = 0xE,
    IDT_FLAG_GATE_32BIT_TRAP = 0xF,

    IDT_FLAG_RING0 = (0 << 5),
    IDT_FLAG_RING1 = (1 << 5),
    IDT_FLAG_RING2 = (2 << 5),
    IDT_FLAG_RING3 = (3 << 5),

    IDT_FLAG_PRESENT = 0x80,

} IDT_FLAGS;

typedef struct idt_entry {
    uint16_t base_low;  // The lower 16 bits of the ISR's address
    uint16_t kernel_cs; // The GDT segment selector that the CPU will load into
                        // CS before calling the ISR
    uint8_t ist; // The IST in the TSS that the CPU will load into RSP; set to
                 // zero for now
    uint8_t attributes; // Type and attributes; see the IDT page
    uint16_t base_mid;  // The higher 16 bits of the lower 32 bits of the ISR's
                        // address
    uint32_t base_high; // The higher 32 bits of the ISR's address
    uint32_t reserved;  // Set to zero
} PACKED idt_entry_t;

typedef struct {
    uint16_t limit;
    idt_entry_t *base;
} PACKED idtr_t;

void idt_init();
void idt_set_gate(uint8_t index, void *base, uint16_t selector, uint8_t flags);

void idt_gate_enable(int interrupt);
void idt_gate_disable(int interrupt);

#endif
