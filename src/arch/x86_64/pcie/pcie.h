#ifndef PCIE_H
#define PCIE_H 1

#include <stddef.h>
#include <stdint.h>

typedef enum {
    PCIE_HEADER_T0 = 0,
    PCIE_HEADER_T1 = 1
} pcie_header_type;

typedef struct {
    uint16_t vendor_id;
    uint16_t device_id;

    uint16_t status_reg;
    uint16_t command_reg;

    uint16_t classcode_hi;
    uint8_t classcode_lo;

    uint8_t revision_id;

    uint8_t bist; // what the heck is this

    uint8_t header_type;

    uint8_t plt; // Primary Latency Timer
    uint8_t cache_line_size;
} pcie_header_t;

typedef struct {
    uint32_t bars[6];

    uint32_t reserved0;

    uint16_t subsystem_id;
    uint16_t subsystem_vendor_id;

    char reserved1[7];

    uint8_t capabilities_ptr;

    uint16_t reserved2[6]; // we don't need MAX_LAT not MAX_GNT

    uint8_t irq_pin;
    uint8_t irq_line;
} pcie_header0_t;

int pcie_devices_init();

#endif