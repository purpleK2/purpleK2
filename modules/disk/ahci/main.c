#include "ahci.h"
#include "fs/devfs/devfs.h"
#include "memory/heap/kheap.h"
#include "paging/paging.h"
#include "util/assert.h"
#include <stdio.h>

#include <module/modinfo.h>

#include <dev/diskdev.h>
#include <string.h>

const modinfo_t modinfo = {.name        = "ahci",
                           .version     = "1.0.0",
                           .author      = "NotNekodev & Ivan_Holy",
                           .description = "AHCI (SATA) Driver for PurpleK2",
                           .license     = "MIT",
                           .url      = "https://github.com/purplek2/PurpleK2",
                           .priority = MOD_PRIO_HIGHEST,
                           .deps = {"kernel", NULL}}; // terminated with a \0

HBA_MEM *abar = NULL;

char letter_counter = 'a';

void module_exit() {
    kprintf("AHCI module unloaded\n");
}

static int ahci_diskdev_read(struct disk_device *disk, uint8_t *buffer, uint64_t lba,
                uint32_t sector_count) {
    return ahci_read((HBA_PORT *)disk->data, lba, sector_count, buffer);
}

static int ahci_diskdev_write(struct disk_device *disk, const uint8_t *buffer, uint64_t lba,
                 uint32_t sector_count) {
    return ahci_write((HBA_PORT *)disk->data, lba, sector_count, (void *)buffer);
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

    disk_device_t *ahci_disk = kmalloc(sizeof(disk_device_t));
    assert(ahci_disk != NULL);
    memset(ahci_disk, 0, sizeof(disk_device_t));
    ahci_disk->namespace = DISK_NAMESPACE_MODERN;
    ahci_disk->id.letter = letter_counter++;
    ahci_disk->block_size = 512;
    ahci_disk->block_count = 1000000000; // TODO: get real

    ahci_disk->read = ahci_diskdev_read;
    ahci_disk->write = ahci_diskdev_write;

    ahci_disk->data = (void *)&abar->ports[sata_port];

    register_disk_device(ahci_disk);
}
