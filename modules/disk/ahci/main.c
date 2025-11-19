#include "ahci.h"
#include "paging/paging.h"
#include <stdio.h>

#include <module/modinfo.h>

const modinfo_t modinfo = {.name        = "ahci",
                           .version     = "1.0.0",
                           .author      = "NotNekodev & Ivan_Holy",
                           .description = "AHCI (SATA) Driver for PurpleK2",
                           .license     = "MIT",
                           .url      = "https://github.com/purplek2/PurpleK2",
                           .priority = MOD_PRIO_HIGHEST,
                           .deps = {"kernel", NULL}}; // terminated with a \0

HBA_MEM *abar = NULL;

void module_exit() {
    kprintf("Example Module exiting!\n");
}

void module_entry() {
    pci_device_t *sata = detect_controller();

    map_region_to_page((uint64_t *)PHYS_TO_VIRTUAL(_get_pml4()), sata->bar[5],
                       PHYS_TO_VIRTUAL(sata->bar[5]), 0x20000, AHCI_MMIO_FLAGS);

    abar = (HBA_MEM *)PHYS_TO_VIRTUAL(sata->bar[5]);

    int sata_port = get_sata_port(abar);

    port_rebase(&abar->ports[sata_port]);

    probe_port(abar);

    test_ahci();
}