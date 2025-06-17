#ifndef PCIE_H
#define PCIE_H 1

#include <stddef.h>
#include <stdint.h>

#define PCIE_HEADT0_BARS 6
#define PCIE_HEADT1_BARS 2

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
    uint32_t bars[PCIE_HEADT0_BARS];

    uint32_t reserved0;

    uint16_t subsystem_id;
    uint16_t subsystem_vendor_id;

    char reserved1[7];

    uint8_t capabilities_ptr;

    uint16_t reserved2[6]; // we don't need MAX_LAT not MAX_GNT

    uint8_t irq_pin;
    uint8_t irq_line;
} pcie_header0_t;

typedef struct {
    uint32_t bars[PCIE_HEADT1_BARS];

    uint8_t slt; // Secondary Latency Timer

    uint8_t subordinate_busnumber;
    uint8_t secondary_busnumber;
    uint8_t primary_busnumber;

    uint16_t secondary_status_reg;

    uint8_t io_limit_lo;
    uint8_t io_base_lo;

    uint16_t memory_limit;
    uint16_t memory_base;

    uint16_t prefetchable_limit_lo;
    uint16_t prefetchable_base_lo;

    uint32_t prefetchable_base_hi;
    uint32_t prefetchable_limit_hi;

    uint16_t io_limit_hi;
    uint16_t io_base_hi;

    uint8_t reserved[3];

    uint8_t capabilities_ptr;

    uint32_t expansionrom_base;

    uint16_t bridge_control;

    uint8_t irq_pin;
    uint8_t irq_line;
} pcie_header1_t;

int pcie_devices_init();

#endif