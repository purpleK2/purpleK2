/*
    PCIe rev2.1-compliant implementation for purpleK2

    (C) 2025 RepubblicaTech
*/

#include "pcie.h"

#include <memory/heap/kheap.h>

#include <uacpi/acpi.h>
#include <uacpi/tables.h>
#include <uacpi/uacpi.h>

#include <paging/paging.h>

#include <stdio.h>
#include <string.h>

#include <math.h>

pcie_device_t *pcie_devices_head = NULL;
pcie_device_t *get_pcie_dev_head() {
    return pcie_devices_head;
}

// FOR INTERNAL USE ONLY
pcie_device_t *pcie_dev_tail = NULL;

// @param pci_ids pointer to a CPIO-type pci.ids file
// @param vendor_out a 128-byte (minimum size) string that will contain the
// vendor name
// @param device_out a 128-byte (minimum size) string that will contain the
// device name
pcie_status pcie_lookup_vendor_device(pcie_header_t *header,
                                      cpio_file_t *pci_ids, char *vendor_out,
                                      char *device_out) {
    if (!header) {
        mprintf_warn("No PCIe device header was given!\n");
        return PCIE_STATUS_ENULLPTR;
    }

    if (!pci_ids) {
        mprintf_warn("No pci.ids file was given!\n");
        return PCIE_STATUS_ENULLPTR;
    }

    if (!vendor_out || !device_out) {
        mprintf_warn("No output string was given!\n");
        return PCIE_STATUS_ENULLPTR;
    }

    if (header->vendor_id == 0xFFFF) {
        // debugf_warn("Found illegal vendor %hx!\n", header->vendor_id);
        return PCIE_STATUS_EINVALID;
    }

    // special treatment :)
    // also very wacky, we'll be fine for now
    if (header->vendor_id == 0x1234) {
        strncpy(vendor_out, "QEMU", strlen("QEMU") + 1);
        if (header->device_id == 0x1111) {
            strncpy(device_out, "Emulated VGA Display Controller",
                    strlen("Emulated VGA Display Controller") + 1);
        } else if (header->device_id == 0x0001) {
            strncpy(device_out, "Virtio Block Device",
                    strlen("Virtio Block Device") + 1);
        } else if (header->device_id == 0x0002) {
            strncpy(device_out, "Virtio Network Device",
                    strlen("Virtio Network Device") + 1);
        }

        return PCIE_STATUS_OK;
    }

    // will be used later for making sure that we already found vendor
    // and/or device
    vendor_out[0] = '\0';
    device_out[0] = '\0';

    // parsing mode
    // 0 = vendor parsing
    // 1 = device parsing
    int parsing_mode;

    // start parsing the file
    char *ids = pci_ids->data;
    for (uint64_t i = 0; i < pci_ids->filesize;) {
        // ignore # and newlines
        switch (ids[i]) {
        case '#':
            while (ids[i] != '\n') {
                i++;
            }
            continue;

        case '\n':
            parsing_mode = 0;
            i++;
            continue;
        case '\t':
            parsing_mode = 1;
            i++;

            if (ids[i] == '\t') {
                // we won't do sub-stuff
                while (ids[i] != '\n') {
                    i++;
                }
                continue;
            }

            if (vendor_out[0] == '\0') {
                // we didn't find the vendor yet
                parsing_mode = 0;
                while (ids[i] != '\n') {
                    i++;
                }
            }

            if (device_out[0] != '\0') {
                // we can get out of here
                return PCIE_STATUS_OK;
            }
            continue;

        default:
            break;
        }

        // here we should only have IDs

        // check if we should parse vendors or devices
        switch (parsing_mode) {
        case 0:
            if (vendor_out[0] != '\0') {
                parsing_mode = 1;
                break;
            }

            int vendor_id = nxatoi(&ids[i], 4);

            if (header->vendor_id != vendor_id) {
                while (ids[i] != '\n') {
                    i++;
                }
                continue;
            }

            // we found a proper vendor ID
            i += 6; // length of ID + 2 spaces

            uint64_t j;
            // length of vendor string
            for (j = i; ids[j] != '\n'; j++)
                ;

            strncpy(vendor_out, &ids[i], (j - i) + 1);

            i = j; // we can go to the end of the row

            parsing_mode = 1;
            break;

        case 1:
            if (device_out[0] != '\0') {
                // we're done
                return PCIE_STATUS_OK;
            }

            int device_id = nxatoi(&ids[i], 4);

            if (header->device_id != device_id) {
                while (ids[i] != '\n') {
                    i++;
                }
                continue;
            }

            // we found a proper device ID
            i += 6; // length of ID + 2 spaces

            uint64_t k;
            // length of device string
            for (k = i; ids[k] != '\n'; k++)
                ;

            strncpy(device_out, &ids[i], (k - i) + 1);
            device_out[k - i] = '\0';

            parsing_mode = 1;
            break;

        default:
            debugf_warn("Invalid PCIe parsing mode! (expected 0/1, found %d)\n",
                        parsing_mode);
            parsing_mode = 0;
            break;
        }
    }

    debugf_warn("Unable to lookup the PCIe vendor/device!\n");
    return PCIE_STATUS_ENOPCIENF;
}

pcie_status dump_pcie_dev_info(pcie_device_t *pcie) {
    if (!pcie) {
        debugf_warn("Invalid PCIe device pointer!\n");
        return PCIE_STATUS_ENULLPTR;
    }

    mprintf("[%.02hhx:%.02hhx.%.01hhx] %s %s (%.04hx:%.04hx) (rev %.02hhu)\n",
            pcie->bus, pcie->device, pcie->function, pcie->vendor_str,
            pcie->device_str, pcie->vendor_id, pcie->device_id, pcie->revision);

    switch (pcie->header_type) {
    case PCIE_HEADER_T0:
        for (int i = 0; i < PCIE_HEADT0_BARS; i++) {
            debugf("\tBAR%d: 0x%.08lx\n", i, pcie->bars[i]);
        }
        break;

    case PCIE_HEADER_T1:
        for (int i = 0; i < PCIE_HEADT1_BARS; i++) {
            debugf("\tBAR%d: 0x%.08lx\n", i, pcie->bars[i]);
        }
        break;

    default:
        debugf_warn("Unknown PCIe header type %.02d\n!", pcie->header_type);
        return PCIE_STATUS_EINVALID;
    }

    debugf("\tIRQ Line:%hhu\n", pcie->irq_line);
    debugf("\tIRQ Pin:%hhu\n", pcie->irq_pin);

    return PCIE_STATUS_OK;
}

pcie_status add_pcie_device(void *pcie_addr, cpio_file_t *pci_ids,
                            uint8_t bus_range) {
    pcie_header_t *pcie_header = kmalloc(sizeof(pcie_header_t));
    memcpy(pcie_header, pcie_addr, sizeof(pcie_header_t));

    char *vendor = kmalloc(PCIE_MAX_VENDOR_NAME * sizeof(char));
    char *device = kmalloc(PCIE_MAX_DEVICE_NAME * sizeof(char));
    memset(vendor, 0, PCIE_MAX_VENDOR_NAME);
    memset(device, 0, PCIE_MAX_VENDOR_NAME);

    switch (pcie_lookup_vendor_device(pcie_header, pci_ids, vendor, device)) {
    case PCIE_STATUS_OK:
        break;

    case PCIE_STATUS_EINVALID:
        // debugf_warn("Attempted to lookup for a non-existent device!\n");
        return PCIE_STATUS_EINVALID;

    default:
        debugf_warn("Couldn't lookup PCIe vendor and/or device name!\n");
        return PCIE_STATUS_ENOPCIENF;
    }

    pcie_device_t *pcie_device = kmalloc(sizeof(pcie_device_t));
    memset(pcie_device, 0, sizeof(pcie_device_t));

    pcie_device->vendor_id = pcie_header->vendor_id;
    pcie_device->device_id = pcie_header->device_id;

    pcie_device->vendor_str = vendor;
    pcie_device->device_str = device;

    pcie_device->header_type = pcie_header->header_type;

    pcie_device->class_code =
        (pcie_header->classcode_lo) | (pcie_header->classcode_lo << 8);

    uint64_t pcie_addr_phys = pg_virtual_to_phys(
        (uint64_t *)PHYS_TO_VIRTUAL(_get_pml4()), (uint64_t)pcie_addr);

    pcie_device->device   = (uint8_t)((pcie_addr_phys >> 15) & 0x1f);
    pcie_device->function = (uint8_t)((pcie_addr_phys >> 12) & 0x7);

    pcie_device->bus = (uint8_t)((pcie_addr_phys >> 20) & bus_range);

    pcie_device->revision = pcie_header->revision_id;

    uint32_t *bars = NULL;

    void *p = (pcie_addr + sizeof(pcie_header_t));

    switch (pcie_header->header_type) {
    case PCIE_HEADER_T0:
        pcie_header0_t *header0 = kmalloc(sizeof(pcie_header0_t));
        memcpy(header0, p, sizeof(pcie_header0_t));

        pcie_device->irq_line = header0->irq_line;
        pcie_device->irq_pin  = header0->irq_pin;

        bars = kmalloc(sizeof(uint32_t) * PCIE_HEADT0_BARS);
        memcpy(bars, header0->bars, sizeof(uint32_t) * PCIE_HEADT0_BARS);

        pcie_device->bars = bars;

        kfree(header0);
        break;

    case PCIE_HEADER_T1:
        pcie_header1_t *header1 = kmalloc(sizeof(pcie_header1_t));
        memcpy(header1, p, sizeof(pcie_header1_t));

        pcie_device->irq_line = header1->irq_line;
        pcie_device->irq_pin  = header1->irq_pin;

        bars = kmalloc(sizeof(uint32_t) * PCIE_HEADT1_BARS);
        memcpy(bars, header1->bars, sizeof(uint32_t) * PCIE_HEADT1_BARS);

        pcie_device->bars = bars;

        kfree(header1);
        break;

    default:
        debugf_warn("Unknown PCIe header type %.02d!",
                    pcie_header->header_type);
        kfree(pcie_header);
        return PCIE_STATUS_EUNKNOWN;
    }

    if (!pcie_devices_head) {
        // initialization state, we should be here only once
        pcie_devices_head = pcie_device;
        pcie_dev_tail     = pcie_device;
    } else {
        pcie_dev_tail->next = pcie_device;
        pcie_dev_tail       = pcie_dev_tail->next;
    }

    dump_pcie_dev_info(pcie_device);

    kfree(pcie_header);
    return PCIE_STATUS_OK;
}

pcie_status pcie_devices_init(cpio_file_t *pci_ids) {
    struct uacpi_table *table = kmalloc(sizeof(struct uacpi_table));
    memset(table, 0, sizeof(struct uacpi_table));

    if (uacpi_table_find_by_signature(ACPI_MCFG_SIGNATURE, table) !=
        UACPI_STATUS_OK) {

        debugf_warn("Couldn't find table '%s' successfully\n",
                    ACPI_MCFG_SIGNATURE);

        kfree(table);
        return PCIE_STATUS_ENOMCFG;
    }

    if (!table->hdr) {
        debugf_warn("Invalid %s table pointer!\n", ACPI_MCFG_SIGNATURE);

        kfree(table);
        return PCIE_STATUS_ENULLPTR;
    }

    struct acpi_mcfg *mcfg = (struct acpi_mcfg *)table->hdr;
    struct acpi_mcfg_allocation mcfg_space;

    int mcfg_spaces = (mcfg->hdr.length - sizeof(mcfg->hdr)) /
                      sizeof(struct acpi_mcfg_allocation);

    debugf_debug("Found %d config space%s\n", mcfg_spaces,
                 mcfg_spaces == 1 ? "" : "s");

    if (mcfg_spaces < 1) {
        kprintf_warn("No valid config spaces were found!\n");

        kfree(table);
        return PCIE_STATUS_ENOCFGSP;
    }

    for (int i = 0; i < mcfg_spaces; i++) {
        mcfg_space = mcfg->entries[i];
        debugf("PCIe BASE_ADDR: %llx; SEGMENT: %hu; BUS_RANGE: "
               "%hhu - %hhu\n",
               mcfg_space.address, mcfg_space.segment, mcfg_space.start_bus,
               mcfg_space.end_bus);

        for (uint8_t device = 0; device < 32; device++) {
            for (uint8_t function = 0; function < 8; function++) {
                uint64_t addr =
                    (mcfg_space.address) + PCIE_OFFSET(0, device, function);

                // we should map the base address
                // according to the spec, each device is 4K long
                map_region_to_page((uint64_t *)PHYS_TO_VIRTUAL(_get_pml4()),
                                   addr, PHYS_TO_VIRTUAL(addr), 0x1000,
                                   PMLE_KERNEL_READ_WRITE);

                switch (add_pcie_device((void *)PHYS_TO_VIRTUAL(addr), pci_ids,
                                        mcfg_space.end_bus -
                                            mcfg_space.start_bus)) {
                case PCIE_STATUS_OK:
                    continue;

                case PCIE_STATUS_EINVALID:
                    // debugf_debug("Non-existent PCIe device at "
                    //              "[%.02hhx:%.02hhx.%.01hhx]\n",
                    //              0, device, function);
                    continue;

                default:
                    // debugf_warn("Couldn't parse info for PCIe device "
                    //             "[%.02hhx:%.02hhx.%.01hhx]!\n",
                    //             0, device, function);
                    //
                    kfree(table);
                    return PCIE_STATUS_ENOPCIENF;
                }
            }
        }
    }

    kfree(table);

    return PCIE_STATUS_OK;
}