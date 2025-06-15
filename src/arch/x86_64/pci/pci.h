#ifndef PCI_H
#define PCI_H 1

#endif

#include <fs/cpio/newc.h>

#define MAX_VENDOR_NAME 128
#define MAX_DEVICE_NAME 128

#define PCI_CONFIG_ADDRESS 0xCF8
#define PCI_CONFIG_DATA    0xCFC

#define PCI_ADDR(s, b, d, f) (((b << 20) | (d << 15) | (f << 12)) + s)

typedef enum {
    PCI_BAR_TYPE_NONE = 0, // Unused BAR
    PCI_BAR_TYPE_PIO  = 1, // Port I/O
    PCI_BAR_TYPE_MMIO = 2  // Memory-Mapped I/O
} pci_bar_type_t;

typedef struct pci_device {
    uint8_t bus, device, function;

    uint16_t vendor_id, device_id;

    uint8_t class_code, subclass, prog_if, header_type;

    char vendor_str[MAX_VENDOR_NAME];
    char device_str[MAX_DEVICE_NAME];

    uint32_t bar[6];
    uint8_t bar_type[6]; // New field to store type of each BAR
    uint8_t irq_line, irq_pin;

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

void pci_scan(cpio_file_t *pci_ids);
void pci_print_devices(cpio_file_t *pci_ids);
void pci_print_info(uint8_t bus, uint8_t device, uint8_t function);
void pci_free_list();
uint32_t pci_config_read(uint8_t bus, uint8_t device, uint8_t function,
                         uint8_t offset);

pci_device_t *pci_add_device(uint8_t bus, uint8_t device, uint8_t function,
                             cpio_file_t *pci_ids);
void pci_lookup_vendor_device(pci_device_t *dev, const char *pci_ids,
                              size_t length);
void pci_print_list();
