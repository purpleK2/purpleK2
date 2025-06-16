#include "pcie.h"

#include <memory/heap/kheap.h>

#include <uacpi/acpi.h>
#include <uacpi/tables.h>
#include <uacpi/uacpi.h>

#include <paging/paging.h>

#include <stdio.h>

void dump_pcie_info(void *pcie_addr) {
    pcie_header_t *pcie_header = pcie_addr;

    mprintf("\t%hx:%hx (rev %.02d) (header type %02d)\n",
            pcie_header->vendor_id, pcie_header->device_id,
            pcie_header->revision_id, pcie_header->header_type);
    mprintf("\tMemory AND I/O requests: %sSUPPORTED\n",
            pcie_header->command_reg & (1 << 2) ? "NOT " : "");

    void *p = (pcie_addr + sizeof(pcie_header_t));

    switch (pcie_header->header_type) {
    case PCIE_HEADER_T0:
        pcie_header0_t *header0 = p;

        for (int i = 0; i < 6; i++) {
            mprintf("\tBAR%d: 0x%08lx\n", i, header0->bars[i]);
        }

        mprintf("\tIRQ Pin: %hhu\n", header0->irq_pin);
        mprintf("\tIRQ Line: %hhu\n", header0->irq_line);
        break;

    default:
        break;
    }
}

int pcie_devices_init() {
    struct uacpi_table *table = kmalloc(sizeof(struct uacpi_table));

    uacpi_table_find_by_signature(ACPI_MCFG_SIGNATURE, table);

    if (!table->hdr) {
        debugf_warn("No table %s found!\n", ACPI_MCFG_SIGNATURE);
        return -1;
    }

    struct acpi_mcfg *mcfg = (struct acpi_mcfg *)table->hdr;
    struct acpi_mcfg_allocation mcfg_space;

    int mcfg_spaces =
        (mcfg->hdr.length - 0x2c) / sizeof(struct acpi_mcfg_allocation);

    debugf_debug("Found %d config space%s\n", mcfg_spaces,
                 mcfg_spaces == 1 ? "" : "s");

    debugf(ANSI_COLOR_GRAY);
    for (int i = 0; i < mcfg_spaces; i++) {
        mcfg_space = mcfg->entries[i];
        mprintf("PCIe device n.%d\n"
                "\tBASE_ADDR: %llx; SEGMENT: %hu; BUS_RANGE: "
                "%hhu - %hhu\n",
                i + 1, mcfg_space.address, mcfg_space.segment,
                mcfg_space.start_bus, mcfg_space.end_bus);

        // we should map the base address
        // according to the spec, each device is 4K long
        map_region_to_page(_get_pml4(), mcfg_space.address,
                           PHYS_TO_VIRTUAL(mcfg_space.address), 0x1000,
                           PMLE_KERNEL_READ_WRITE);

        debugf(ANSI_COLOR_RESET);

        dump_pcie_info((void *)PHYS_TO_VIRTUAL(mcfg_space.address));
    }

    kfree(table);

    return 0;
}