/*
    PCIe rev2.1-compliant implementation for purpleK2

    (C) 2025 RepubblicaTech
*/

#include "pcie.h"

#include <memory/heap/kheap.h>

#include <uacpi/acpi.h>
#include <uacpi/tables.h>
#include <uacpi/uacpi.h>

#include <string.h>

#include <paging/paging.h>

#include <stdio.h>

int dump_pcie_info(void *pcie_addr) {
    pcie_header_t *pcie_header = kmalloc(sizeof(pcie_header_t));
    memcpy(pcie_header, pcie_addr, sizeof(pcie_header_t));

    mprintf("\t%hx:%hx (rev %.02d) (header type %.02d)\n",
            pcie_header->vendor_id, pcie_header->device_id,
            pcie_header->revision_id, pcie_header->header_type);
    debugf("\tMemory AND I/O requests: %sSUPPORTED\n",
           pcie_header->command_reg & (1 << 2) ? "NOT " : "");

    void *p = (pcie_addr + sizeof(pcie_header_t));
    kprintf("\tPCIE_HEADER. %p\n", p);

    switch (pcie_header->header_type) {
    case PCIE_HEADER_T0:
        pcie_header0_t *header0 = kmalloc(sizeof(pcie_header0_t));
        memcpy(header0, p, sizeof(pcie_header0_t));

        for (int i = 0; i < PCIE_HEADT0_BARS; i++) {
            debugf("\tBAR%d: 0x%08lx\n", i, header0->bars[i]);
        }

        debugf("\tIRQ Pin: %hhu\n", header0->irq_pin);
        debugf("\tIRQ Line: %hhu\n", header0->irq_line);

        kfree(header0);
        break;

    case PCIE_HEADER_T1:
        pcie_header1_t *header1 = kmalloc(sizeof(pcie_header1_t));
        memcpy(header1, p, sizeof(pcie_header1_t));

        for (int i = 0; i < PCIE_HEADT1_BARS; i++) {
            debugf("\tBAR%d: 0x%08lx\n", i, header1->bars[i]);
        }

        kfree(header1);
        break;

    default:
        debugf_warn("Unknown PCIe header type %.02d!",
                    pcie_header->header_type);
        kfree(pcie_header);
        return -1;
    }

    kfree(pcie_header);
    return 0;
}

int pcie_devices_init() {
    struct uacpi_table *table = kmalloc(sizeof(struct uacpi_table));

    if (uacpi_table_find_by_signature(ACPI_MCFG_SIGNATURE, table) !=
        UACPI_STATUS_OK) {

        debugf_warn("No such table %s\n", ACPI_MCFG_SIGNATURE);

        kfree(table);
        return -1;
    }

    if (!table->hdr) {
        debugf_warn("Invalid %s table pointer!\n", ACPI_MCFG_SIGNATURE);
        kfree(table);
        return -1;
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

        if (dump_pcie_info((void *)PHYS_TO_VIRTUAL(mcfg_space.address)) != 0) {
            debugf_warn("Couldn't parse PCIe device info!\n");

            kfree(table);
            return -2;
        }
    }

    kfree(table);

    return 0;
}