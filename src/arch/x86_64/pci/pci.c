#include "pci.h"

#include <memory/heap/kheap.h>

#include <stdio.h>
#include <string.h>

#include <io.h>

#include <autoconf.h>

pci_device_t *pci_devices_head = NULL;

pci_device_t *get_pcihead() {
    return pci_devices_head;
}

static const pci_class_t pci_classes[] = {
    {0x0, "Unclassified"},
    {0x1, "Mass Storage Controller"},
    {0x2, "Network Controller"},
    {0x3, "Display Controller"},
    {0x4, "Multimedia Controller"},
    {0x5, "Memory Controller"},
    {0x6, "Bridge"},
    {0x7, "Simple Communication Controller"},
    {0x8, "Base System Peripheral"},
    {0x9, "Input Device Controller"},
    {0xA, "Docking Station"},
    {0xB, "Processor"},
    {0xC, "Serial Bus Controller"},
    {0xD, "Wireless Controller"},
    {0xE, "Intelligent Controller"},
    {0xF, "Satellite Communications Controller"},
    {0x10, "Encryption Controller"},
    {0x11, "Signal Processing Controller"},
    {0x12, "Processing Accelerator"},
    {0x13, "Non-Essential Instrumentation"},
    {0xFF, "Unknown Class"}};

static const pci_subclass_t pci_subclasses[] = {
    {0x1, 0x6, "SATA Controller"},
    {0x1, 0x7, "Serial Attached SCSI Controller"},
    {0x2, 0x0, "Ethernet Controller"},
    {0x2, 0x1, "Token Ring Controller"},
    {0x2, 0x2, "FDDI Controller"},
    {0x2, 0x3, "ATM Controller"},
    {0x3, 0x0, "VGA-Compatible Controller"},
    {0x3, 0x1, "XGA Controller"},
    {0x3, 0x2, "3D Controller"},
    {0x6, 0x0, "Host Bridge"},
    {0x6, 0x1, "ISA Bridge"},
    {0x6, 0x2, "EISA Bridge"},
    {0x6, 0x3, "Microchannel Bridge"},
    {0x6, 0x4, "PCI-to-PCI Bridge"},
    {0x6, 0x5, "PCMCIA Bridge"},
    {0xC, 0x0, "FireWire (IEEE 1394) Controller"},
    {0xC, 0x1, "ACCESS Bus Controller"},
    {0xC, 0x2, "SSA Controller"},
    {0xC, 0x3, "USB Controller"},
    {0xC, 0x4, "Fibre Channel Controller"},
    {0xC, 0x5, "SMBus Controller"},
    {0xC, 0x6, "InfiniBand Controller"},
    {0xC, 0x7, "IPMI Interface"},
    {0xC, 0x8, "SERCOS Interface (IEC 61491)"},
    {0xC, 0x9, "CANbus Controller"},
    {0xFF, 0xFF, "Unknown Subclass"}};

const char *pci_get_class_name(uint8_t class_code) {
    for (size_t i = 0; i < sizeof(pci_classes) / sizeof(pci_classes[0]); i++) {
        if (pci_classes[i].class_code == class_code)
            return pci_classes[i].class_name;
    }
    return "Unknown Class";
}

const char *pci_get_subclass_name(uint8_t class_code, uint8_t subclass) {
    for (size_t i = 0; i < sizeof(pci_subclasses) / sizeof(pci_subclasses[0]);
         i++) {
        if (pci_subclasses[i].class_code == class_code &&
            pci_subclasses[i].subclass == subclass)
            return pci_subclasses[i].subclass_name;
    }
    return "Unknown Subclass";
}

uint32_t pci_config_read(uint8_t bus, uint8_t device, uint8_t function,
                         uint8_t offset) {
    uint32_t address = (1U << 31) | ((uint32_t)bus << 16) |
                       ((uint32_t)device << 11) | ((uint32_t)function << 8) |
                       (offset & 0xFC);
    _outl(PCI_CONFIG_ADDRESS, address);
    return _inl(PCI_CONFIG_DATA);
}

pci_device_t *pci_add_device(uint8_t bus, uint8_t device, uint8_t function,
                             cpio_file_t *pci_ids) {
    uint32_t vendor_device = pci_config_read(bus, device, function, 0);
    if ((vendor_device & 0xFFFF) == 0xFFFF)
        return NULL;

    pci_device_t *new_dev = kmalloc(sizeof(pci_device_t));
    memset(new_dev, 0, sizeof(pci_device_t));

    new_dev->bus         = bus;
    new_dev->device      = device;
    new_dev->function    = function;
    new_dev->vendor_id   = vendor_device & 0xFFFF;
    new_dev->device_id   = (vendor_device >> 16) & 0xFFFF;
    uint32_t class_info  = pci_config_read(bus, device, function, 8);
    new_dev->class_code  = (class_info >> 24) & 0xFF;
    new_dev->subclass    = (class_info >> 16) & 0xFF;
    new_dev->prog_if     = (class_info >> 8) & 0xFF;
    new_dev->header_type = pci_config_read(bus, device, function, 0x0C) & 0xFF;
    pci_lookup_vendor_device(new_dev, pci_ids->data, pci_ids->filesize);

    // Initialize BARs and BAR types to zero
    for (int i = 0; i < 6; i++) {
        new_dev->bar[i]      = 0;
        new_dev->bar_type[i] = PCI_BAR_TYPE_NONE;
    }

    // Read BARs and determine their types
    int bar_count =
        (new_dev->header_type == 0) ? 6 : 2; // Type 0: 6 BARs, Type 1: 2 BARs
    for (int i = 0; i < bar_count; i++) {
        uint32_t bar = pci_config_read(bus, device, function, 0x10 + (i * 4));
        new_dev->bar[i] = bar; // Store raw BAR value initially
        if (bar == 0) {
            new_dev->bar_type[i] = PCI_BAR_TYPE_NONE; // Unused BAR
            continue;
        }
        if (bar & 0x1) {
            // I/O mapped (PIO)
            new_dev->bar[i]      = bar & ~0x3; // Clear low 2 bits for alignment
            new_dev->bar_type[i] = PCI_BAR_TYPE_PIO;
        } else {
            // Memory mapped I/O (MMIO)
            new_dev->bar[i]      = bar & ~0xF; // Clear low 4 bits for alignment
            new_dev->bar_type[i] = PCI_BAR_TYPE_MMIO;
        }
    }

    // Read IRQ line and pin
    uint32_t config_data = pci_config_read(bus, device, function, 0x3C);
    uint8_t irq_line     = (config_data >> 0) & 0xFF; // Interrupt Line at 0x3C
    uint8_t irq_pin      = (config_data >> 8) & 0xFF; // Interrupt Pin at 0x3D

    if (irq_pin > 4) {
        debugf_warn("Invalid IRQ Pin %d for device %d:%d:%d\n", irq_pin, bus,
                    device, function);
        irq_pin = 0; // Handle as no interrupt
    }

    new_dev->irq_line = irq_line;
    new_dev->irq_pin  = irq_pin;

    new_dev->next    = pci_devices_head;
    pci_devices_head = new_dev;
    return new_dev;
}

void pci_scan(cpio_file_t *pci_ids) {
    for (uint16_t bus = 0; bus < 256; bus++) {
        for (uint8_t device = 0; device < 32; device++) {
            for (uint8_t function = 0; function < 8; function++) {
                pci_add_device(bus, device, function, pci_ids);
            }
        }
    }
}

void pci_lookup_vendor_device(pci_device_t *dev, const char *pci_ids,
                              size_t length) {
    size_t i                              = 0;
    char vendor_name[PCI_MAX_VENDOR_NAME] = "Unknown Vendor";
    char device_name[PCI_MAX_DEVICE_NAME] = "Unknown Device";
    int found_vendor                      = 0;

    if (dev->vendor_id == 0x1234) {
        memcpy(vendor_name, "QEMU", PCI_MAX_VENDOR_NAME);
        if (dev->device_id == 0x1111) {
            memcpy(device_name, "Emulated VGA Display Controller",
                   PCI_MAX_DEVICE_NAME);
        } else if (dev->device_id == 0x0001) {
            memcpy(device_name, "Virtio Block Device", PCI_MAX_DEVICE_NAME);
        } else if (dev->device_id == 0x0002) {
            memcpy(device_name, "Virtio Network Device", PCI_MAX_DEVICE_NAME);
        }

        strcpy(dev->vendor_str, vendor_name);
        strcpy(dev->device_str, device_name);

        return;
    }

    while (i < length) {
        if (pci_ids[i] == '#') {
            while (i < length && pci_ids[i] != '\n')
                i++;
            i++;
            continue;
        }
        if (pci_ids[i] != '\t') {
            uint16_t v_id = 0;
            size_t j      = 0;
            while (i < length && pci_ids[i] != ' ' && j < 4) {
                v_id = (v_id << 4) | (pci_ids[i] >= '0' && pci_ids[i] <= '9'
                                          ? pci_ids[i] - '0'
                                          : (pci_ids[i] | 32) - 'a' + 10);
                i++;
                j++;
            }
            while (i < length && pci_ids[i] == ' ')
                i++;
            size_t k = 0;
            while (i < length && pci_ids[i] != '\n' &&
                   k < PCI_MAX_VENDOR_NAME - 1) {
                vendor_name[k++] = pci_ids[i++];
            }
            vendor_name[k] = '\0';
            if (v_id == dev->vendor_id) {
                found_vendor = 1;
            }
        } else if (found_vendor) {
            i++;
            uint16_t d_id = 0;
            size_t j      = 0;
            while (i < length && pci_ids[i] != ' ' && j < 4) {
                d_id = (d_id << 4) | (pci_ids[i] >= '0' && pci_ids[i] <= '9'
                                          ? pci_ids[i] - '0'
                                          : (pci_ids[i] | 32) - 'a' + 10);
                i++;
                j++;
            }
            while (i < length && pci_ids[i] == ' ')
                i++;
            size_t k = 0;
            while (i < length && pci_ids[i] != '\n' &&
                   k < PCI_MAX_DEVICE_NAME - 1) {
                device_name[k++] = pci_ids[i++];
            }
            device_name[k] = '\0';
            if (d_id == dev->device_id) {
                break;
            }
        }
        while (i < length && pci_ids[i] != '\n')
            i++;
        i++;
    }
    strcpy(dev->vendor_str, vendor_name);
    strcpy(dev->device_str, device_name);
}

void pci_print_info(uint8_t bus, uint8_t device, uint8_t function) {
    pci_device_t *dev = pci_devices_head;
    while (dev) {
        if (dev->bus == bus && dev->device == device &&
            dev->function == function) {
#ifdef CONFIG_PCI_DEBUG
            mprintf("PCI Device: %s %s (%04x:%04x)\n", dev->vendor_str,
                    dev->device_str, dev->vendor_id, dev->device_id);
#else
            kprintf("PCI Device: %s %s (%04x:%04x)\n", dev->vendor_str,
                    dev->device_str, dev->vendor_id, dev->device_id);
#endif
            return;
        }
        dev = dev->next;
    }
    debugf_warn("PCI Device not found.\n");
}

void pci_print_list() {
    pci_device_t *dev = pci_devices_head;
    while (dev) {
#ifdef CONFIG_PCI_DEBUG
        mprintf("[%.02hhx:%.02hhx.%.01hhx] %s %s (%04x:%04x)\n", dev->bus,
                dev->device, dev->function, dev->vendor_str, dev->device_str,
                dev->vendor_id, dev->device_id);
        debugf("\t%s; %s (Class: 0x%02x, Sub-Class: 0x%02x)\n",
               pci_get_class_name(dev->class_code),
               pci_get_subclass_name(dev->class_code, dev->subclass),
               dev->class_code, dev->subclass);
        debugf("\t%s\n",
               dev->header_type == 0 ? "Single Function" : "Multi-Function");
        debugf("\t%s\n", dev->prog_if == 0 ? "No Programming Interface"
                                           : "Programming Interface");
#else
        mprintf("[%.02hhx:%.02hhx.%.01hhx] %s %s (%04x:%04x)\n", dev->bus,
                dev->device, dev->function, dev->vendor_str, dev->device_str,
                dev->vendor_id, dev->device_id);
#endif
        switch (dev->irq_pin) {
        case 1:
#ifdef CONFIG_PCI_DEBUG
            debugf("\tIRQ INTA\n");
#endif
            break;
        case 2:
#ifdef CONFIG_PCI_DEBUG
            debugf("\tIRQ INTB\n");
#endif
            break;
        case 3:
#ifdef CONFIG_PCI_DEBUG
            debugf("\tIRQ INTC\n");
#endif
            break;
        case 4:
#ifdef CONFIG_PCI_DEBUG
            debugf("\tIRQ INTD\n");
#endif
            break;
        default:
#ifdef CONFIG_PCI_DEBUG
            debugf("\tNo IRQ (%d)\n", dev->irq_pin);
#endif
            break;
        }

        if (dev->irq_pin != 0 && dev->irq_pin <= 4) {
#ifdef CONFIG_PCI_DEBUG
            debugf("\tIRQ %d\n", dev->irq_line);
#endif
        }

        for (int i = 0; i < 6; i++) {
            const char *bar_type_str;
            switch (dev->bar_type[i]) {
            case PCI_BAR_TYPE_NONE:
                bar_type_str = "Unused";
                break;
            case PCI_BAR_TYPE_PIO:
                bar_type_str = "PIO";
                break;
            case PCI_BAR_TYPE_MMIO:
                bar_type_str = "MMIO";
                break;
            default:
                bar_type_str = "Unknown";
                break;
            }
#ifdef CONFIG_PCI_DEBUG
            debugf("\tBAR%d: 0x%08x (%s)\n", i, dev->bar[i], bar_type_str);
#endif
        }
        dev = dev->next;
    }
}
