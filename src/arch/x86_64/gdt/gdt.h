#ifndef GDT_H
#define GDT_H 1

#include <stdint.h>

#define GDT_CODE_SEGMENT 0x08
#define GDT_DATA_SEGMENT 0x10

// Helper macros
#define GDT_LIMIT_LOW(limit)  (limit & 0xFFFF)
#define GDT_BASE_LOW(base)    (base & 0xFFFF)
#define GDT_BASE_MIDDLE(base) ((base >> 16) & 0xFF)
#define GDT_FLAGS_HI_LIMIT(limit, flags)                                       \
    (((limit >> 16) & 0xF) | ((flags << 4) & 0xF0))
#define GDT_BASE_HIGH(base) ((base >> 24) & 0xFF)

#define GDT_ENTRY(base, limit, access, flags)                                  \
    {                                                                          \
        GDT_LIMIT_LOW(limit), GDT_BASE_LOW(base), GDT_BASE_MIDDLE(base),       \
            access, GDT_FLAGS_HI_LIMIT(limit, flags), GDT_BASE_HIGH(base)      \
    }

typedef struct {
    uint16_t limit_low;           // limit & 0xFF
    uint16_t base_low;            // base & 0xFF
    uint8_t base_middle;          // (base >> 16) & 0xFF
    uint8_t access;               // access
    uint8_t limit_high_and_flags; // ((limit >> 16) & 0xF) | (flags & 0xF0)
    uint8_t base_high;            // (base >> 24) & 0xF
} __attribute__((packed)) gdt_entry_t;

typedef struct {
    uint16_t size;
    gdt_entry_t *pointer;
} __attribute__((packed)) gdt_pointer_t;

void gdt_init();

#endif
