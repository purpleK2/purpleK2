#include "idt.h"

#include <gdt/gdt.h>

#include <util/binary.h>
#include <util/util.h>

#include <stdbool.h>
#include <stdio.h>

typedef struct {
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
} __attribute__((packed)) idt_entry_t;

typedef struct {
    uint16_t limit;
    idt_entry_t *base;
} __attribute__((packed)) idtr_t;

__attribute__((
    aligned(0x10))) static idt_entry_t idt_entries[IDT_MAX_DESCRIPTORS];

static idtr_t idtr;

static bool vectors[IDT_MAX_DESCRIPTORS];

void idt_init() {
    idtr.base  = (idt_entry_t *)&idt_entries[0];
    idtr.limit = (uint16_t)sizeof(idt_entry_t) * IDT_MAX_DESCRIPTORS - 1;

    debugf_debug("IDTR:\n");
    debugf_debug("\tbase: %p\n", idtr.base);
    debugf_debug("\tlimit: %x\n", idtr.limit);

    for (uint16_t vector = 0; vector < IDT_MAX_DESCRIPTORS; vector++) {
        idt_set_gate(vector, isr_stub_table[vector], GDT_CODE_SEGMENT, 0x8E);
        vectors[vector] = true;
    }

    debugf_debug("All 256 gates enabled\n");
    debugf_debug("Loading IDTR\n");

    __asm__ volatile("lidt %0" : : "m"(idtr)); // load the new IDT
    __asm__ volatile("sti");                   // set the interrupt flag
}

void idt_set_gate(uint8_t index, void *base, uint16_t selector, uint8_t flags) {
    idt_entries[index].base_low   = (uint64_t)base & 0xFFFF;
    idt_entries[index].kernel_cs  = selector;
    idt_entries[index].ist        = 0;
    idt_entries[index].attributes = flags;
    idt_entries[index].base_mid   = ((uint64_t)base >> 16) & 0xFFFF;
    idt_entries[index].base_high  = ((uint64_t)base >> 32) & 0xFFFFFFFF;
    idt_entries[index].reserved   = 0;
}

void idt_gate_enable(int interrupt) {
    FLAG_SET(idt_entries[interrupt].attributes, IDT_FLAG_PRESENT);
}

void idt_gate_disable(int interrupt) {
    FLAG_UNSET(idt_entries[interrupt].attributes, IDT_FLAG_PRESENT);
}
