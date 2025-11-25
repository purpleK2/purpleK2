#ifndef PCIE_H
#define PCIE_H

#include <fs/ustar/ustar.h>
#include <io.h>
#include <memory/heap/kheap.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <util/string.h>

#define MAX_VENDOR_NAME 128
#define MAX_DEVICE_NAME 128

#define PCI_CONFIG_ADDRESS 0xCF8
#define PCI_CONFIG_DATA    0xCFC

#define PCI_ADDR(s, b, d, f) (((b << 20) | (d << 15) | (f << 12)) + s)

typedef enum {
    PCI_TYPE_PIO  = 0,
    PCI_TYPE_MMIO = 1
} pci_type_t;

typedef struct pci_device {
    uint8_t bus, device, function;

    uint16_t vendor_id, device_id;

    uint8_t class_code, subclass, prog_if, header_type;

    char vendor_str[MAX_VENDOR_NAME];
    char device_str[MAX_DEVICE_NAME];

    uint32_t bar[6];
    uint8_t irq_line, irq_pin;

    pci_type_t type;
    struct pci_device *next;
} pci_device_t;

typedef struct {
    uint8_t class_code;
    const char *class_name;
} pci_class_t;

typedef struct {
    uint8_t class_code;
    uint8_t subclass;
    const char *subclass_name;
} pci_subclass_t;

extern pci_device_t *pci_devices_head;

void pci_scan(ustar_file_tree_t *pci_ids);
void pci_print_devices(ustar_file_tree_t *pci_ids);
void pci_print_info(uint8_t bus, uint8_t device, uint8_t function);
void pci_free_list();
uint32_t pci_config_read(uint8_t bus, uint8_t device, uint8_t function,
                         uint8_t offset);

pci_device_t *pci_add_device(uint8_t bus, uint8_t device, uint8_t function,
                             ustar_file_tree_t *pci_ids);
void pci_lookup_vendor_device(pci_device_t *dev, const char *pci_ids,
                              size_t length);
void pci_print_list();

#endif