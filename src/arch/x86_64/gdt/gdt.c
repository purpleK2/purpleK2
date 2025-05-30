#include "gdt.h"

#include <stdint.h>
#include <stdio.h>

gdt_pointer_t gdtr;
gdt_entry_t gdt_entries[5];

extern void _load_gdt(gdt_pointer_t *descriptor);
extern void _reload_segments(uint64_t cs, uint64_t ds);

// https://wiki.osdev.org/GDT_Tutorial#Flat_/_Long_Mode_Setup
void gdt_init() {
    gdt_entries[0] = (gdt_entry_t)GDT_ENTRY(0, 0, 0, 0); // Null Segment
    gdt_entries[1] = (gdt_entry_t)GDT_ENTRY(0, 0xFFFFF, 0x9A,
                                            0xA); // 64-bit kernel code segment
    gdt_entries[2] = (gdt_entry_t)GDT_ENTRY(0, 0xFFFFF, 0x92,
                                            0xC); // 64-bit kernel data segment
    gdt_entries[3] = (gdt_entry_t)GDT_ENTRY(0, 0xFFFFF, 0xFA,
                                            0xA); // 64-bit user code segment
    gdt_entries[4] = (gdt_entry_t)GDT_ENTRY(0, 0xFFFFF, 0xF2,
                                            0xC); // 64-bit user data segment

    gdtr.size    = (uint16_t)(sizeof(gdt_entries) - 1);
    gdtr.pointer = (gdt_entry_t *)&gdt_entries;

    debugf_debug("GDTR:\n");
    debugf_debug("\tsize: %u\n", gdtr.size);
    debugf_debug("\tpointer: %llp\n", gdtr.pointer);

    debugf_debug("Loading GDTR %llp\n", (uint64_t *)&gdtr);
    _load_gdt(&gdtr);

    _reload_segments(GDT_CODE_SEGMENT, GDT_DATA_SEGMENT);
}
