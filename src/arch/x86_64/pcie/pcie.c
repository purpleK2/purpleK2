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

    // will be used later for making sure that we already found vendor and/or
    // device
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

pcie_status dump_pcie_info(void *pcie_addr, cpio_file_t *pci_ids) {
    pcie_header_t *pcie_header = kmalloc(sizeof(pcie_header_t));
    memcpy(pcie_header, pcie_addr, sizeof(pcie_header_t));

    char *vendor = kmalloc(PCIE_MAX_VENDOR_NAME * sizeof(char));
    char *device = kmalloc(PCIE_MAX_DEVICE_NAME * sizeof(char));
    memset(vendor, 0, PCIE_MAX_VENDOR_NAME);
    memset(device, 0, PCIE_MAX_VENDOR_NAME);

    if (pcie_lookup_vendor_device(pcie_header, pci_ids, vendor, device) !=
        PCIE_STATUS_OK) {
        mprintf_warn("Couldn't lookup PCIe vendor and/or device name!\n");
    }

    kprintf("%s %s\n", vendor, device);

    void *p = (pcie_addr + sizeof(pcie_header_t));

    switch (pcie_header->header_type) {
    case PCIE_HEADER_T0:
        pcie_header0_t *header0 = kmalloc(sizeof(pcie_header0_t));
        memcpy(header0, p, sizeof(pcie_header0_t));

        kfree(header0);
        break;

    case PCIE_HEADER_T1:
        pcie_header1_t *header1 = kmalloc(sizeof(pcie_header1_t));
        memcpy(header1, p, sizeof(pcie_header1_t));

        kfree(header1);
        break;

    default:
        debugf_warn("Unknown PCIe header type %.02d!",
                    pcie_header->header_type);
        kfree(pcie_header);
        return PCIE_STATUS_EUNKNOWN;
    }

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

    for (int i = 0; i < mcfg_spaces; i++) {
        mcfg_space = mcfg->entries[i];
        mprintf("[PCIE::%.02d] PCIe BASE_ADDR: %llx; SEGMENT: %hu; BUS_RANGE: "
                "%hhu - %hhu\n",
                i, mcfg_space.address, mcfg_space.segment, mcfg_space.start_bus,
                mcfg_space.end_bus);

        // we should map the base address
        // according to the spec, each device is 4K long
        map_region_to_page((uint64_t *)PHYS_TO_VIRTUAL(_get_pml4()),
                           mcfg_space.address,
                           PHYS_TO_VIRTUAL(mcfg_space.address), 0x1000,
                           PMLE_KERNEL_READ_WRITE);

        if (dump_pcie_info((void *)PHYS_TO_VIRTUAL(mcfg_space.address),
                           pci_ids) != 0) {
            debugf_warn("Couldn't parse PCIe device info!\n");

            kfree(table);
            return PCIE_STATUS_ENOPCIENF;
        }
    }

    if (mcfg_spaces < 1) {
        kprintf_warn("No valid config spaces were found!\n");

        kfree(table);
        return PCIE_STATUS_ENOCFGSP;
    }

    kfree(table);

    return PCIE_STATUS_OK;
}