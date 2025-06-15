#include "pcie.h"

#include <memory/heap/kheap.h>

#include <uacpi/acpi.h>
#include <uacpi/tables.h>
#include <uacpi/uacpi.h>

#include <stdio.h>

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
        (mcfg->hdr.length - (sizeof(mcfg->hdr) + sizeof(mcfg->rsvd))) /
        sizeof(struct acpi_mcfg_allocation);

    debugf_debug("Found %d config spaces\n", mcfg_spaces);

    for (int i = 0; i < mcfg_spaces; i++) {
        mcfg_space = mcfg->entries[i];
        debugf_debug("PCI device %d BASE_ADDR: %llx; SEGMENT: %hu; BUS_RANGE: "
                     "%hhu - %hhu\n",
                     i + 1, mcfg_space.address, mcfg_space.segment,
                     mcfg_space.start_bus, mcfg_space.end_bus);
    }

    kfree(table);

    return 0;
}