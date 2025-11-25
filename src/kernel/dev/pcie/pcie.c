#include "pcie.h"
#include "stdio.h"
#include <memory/heap/kheap.h>
#include <util/string.h>

pci_device_t *pci_devices_head = NULL;

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
                             ustar_file_tree_t *pci_ids) {
    uint32_t vendor_device = pci_config_read(bus, device, function, 0);
    if ((vendor_device & 0xFFFF) == 0xFFFF)
        return NULL;

    pci_device_t *new_dev = (pci_device_t *)kmalloc(sizeof(pci_device_t));
    new_dev->bus          = bus;
    new_dev->device       = device;
    new_dev->function     = function;
    new_dev->vendor_id    = vendor_device & 0xFFFF;
    new_dev->device_id    = (vendor_device >> 16) & 0xFFFF;
    uint32_t class_info   = pci_config_read(bus, device, function, 8);
    new_dev->class_code   = (class_info >> 24) & 0xFF;
    new_dev->subclass     = (class_info >> 16) & 0xFF;
    new_dev->prog_if      = (class_info >> 8) & 0xFF;
    new_dev->header_type  = pci_config_read(bus, device, function, 0x0C) & 0xFF;
    pci_lookup_vendor_device(new_dev, pci_ids->found_files[0]->start,
                             pci_ids->found_files[0]->size);

    // read BARs
    for (int i = 0; i < 6; i++) {
        uint32_t bar = pci_config_read(bus, device, function, 0x10 + (i * 4));
        if (bar == 0)
            break;
        if ((bar & 0x1) == 0) {
            // Memory mapped I/O
            new_dev->bar[i] = bar & ~0xF;
            new_dev->type   = PCI_TYPE_MMIO;
        } else {
            // I/O mapped
            new_dev->bar[i] = bar & ~0x3;
            new_dev->type   = PCI_TYPE_PIO;
        }
    }
    // read IRQ line and pin
    uint8_t irq_line =
        pci_config_read(bus, device, function, 0x3C); // Read the interrupt line
    uint8_t irq_pin =
        pci_config_read(bus, device, function, 0x3D); // Read the interrupt pin

    new_dev->irq_line = irq_line; // Directly assign the interrupt line
    new_dev->irq_pin  = irq_pin;  // Directly assign the interrupt pin

    kprintf("IRQ Pin: %d\n", new_dev->irq_pin);

    new_dev->next    = pci_devices_head;
    pci_devices_head = new_dev;
    return new_dev;
}

void pci_scan(ustar_file_tree_t *pci_ids) {
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
    size_t i                          = 0;
    char vendor_name[MAX_VENDOR_NAME] = "Unknown Vendor";
    char device_name[MAX_DEVICE_NAME] = "Unknown Device";
    int found_vendor                  = 0;

    if (dev->vendor_id == 0x1234) {
        memcpy(vendor_name, "QEMU", MAX_VENDOR_NAME);
        if (dev->device_id == 0x1111) {
            memcpy(device_name, "Emulated VGA Display Controller",
                   MAX_DEVICE_NAME);
        } else if (dev->device_id == 0x0001) {
            memcpy(device_name, "Virtio Block Device", MAX_DEVICE_NAME);
        } else if (dev->device_id == 0x0002) {
            memcpy(device_name, "Virtio Network Device", MAX_DEVICE_NAME);
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
                   k < MAX_VENDOR_NAME - 1) {
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
                   k < MAX_DEVICE_NAME - 1) {
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
            kprintf("PCI Device: %s %s (%04x:%04x)\n", dev->vendor_str,
                    dev->device_str, dev->vendor_id, dev->device_id);
            return;
        }
        dev = dev->next;
    }
    kprintf("PCI Device not found.\n");
}

void pci_print_list() {
    pci_device_t *dev = pci_devices_head;
    while (dev) {
        debugf("PCI Device: Bus %d, Device %d, Function %d\n", dev->bus,
               dev->device, dev->function);
        debugf("  %s %s (%04x:%04x)\n", dev->vendor_str, dev->device_str,
               dev->vendor_id, dev->device_id);
        debugf("  %s; %s (Class: 0x%02x, Sub-Class: 0x%02x)\n",
               pci_get_class_name(dev->class_code),
               pci_get_subclass_name(dev->class_code, dev->subclass),
               dev->class_code, dev->subclass);
        debugf("  %s\n",
               dev->header_type == 0 ? "Single Function" : "Multi-Function");
        debugf("  %s\n", dev->prog_if == 0 ? "No Programming Interface"
                                           : "Programming Interface");
        debugf("  %s\n", dev->type == PCI_TYPE_MMIO ? "MMIO" : "PIO");

        switch (dev->irq_pin) {
        case 1:
            debugf("  IRQ INTA\n");
            break;
        case 2:
            debugf("  IRQ INTB\n");
            break;
        case 3:
            debugf("  IRQ INTC\n");
            break;
        case 4:
            debugf("  IRQ INTD\n");
            break;
        default:
            debugf("  No IRQ (%d)\n", dev->irq_pin);
            break;
        }

        if (dev->irq_pin != 0 && dev->irq_pin <= 4) {
            debugf("  IRQ %d\n", dev->irq_line);
        }

        debugf("  BAR0: 0x%08x\n", dev->bar[0]);
        debugf("  BAR1: 0x%08x\n", dev->bar[1]);
        debugf("  BAR2: 0x%08x\n", dev->bar[2]);
        debugf("  BAR3: 0x%08x\n", dev->bar[3]);
        debugf("  BAR4: 0x%08x\n", dev->bar[4]);
        debugf("  BAR5: 0x%08x\n", dev->bar[5]);
        dev = dev->next;
    }
}
