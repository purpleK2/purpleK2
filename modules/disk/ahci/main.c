#include "ahci.h"
#include "errors.h"
#include "memory/heap/kheap.h"
#include "paging/paging.h"
#include "util/dump.h"
#include <util/assert.h>
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
char opt_letter_counter = 'a';

void module_exit() {
    kprintf("AHCI module unloaded\n");
}

static int ahci_diskdev_read(struct disk_device *disk, uint8_t *buffer, uint64_t lba,
                uint32_t sector_count) {
    bool i = ahci_read((HBA_PORT *)disk->data, lba, sector_count, buffer);

    if (i == true) {
        return 0;
    } else {
        return -EIO;
    }
}

static int ahci_diskdev_write(struct disk_device *disk, const uint8_t *buffer, uint64_t lba,
                 uint32_t sector_count) {
    bool i =  ahci_write((HBA_PORT *)disk->data, lba, sector_count, (void *)buffer);

    if (i == true) {
        return 0;
    } else {
        return -EIO;
    }
}

// SCSI / ATAPI stuff :3
static int ahci_diskdev_read_atapi(struct disk_device *disk, uint8_t *buffer, 
                                   uint64_t lba, uint32_t sector_count) {
    bool i =  ahci_read_atapi((HBA_PORT *)disk->data, lba, sector_count, buffer);
    if (i == true) {
        return 0;
    } else {
        return -EIO;
    }
}

static int ahci_diskdev_write_atapi(struct disk_device *disk, const uint8_t *buffer, 
                                    uint64_t lba, uint32_t sector_count) {
    if (!ahci_atapi_is_writable((HBA_PORT *)disk->data)) {
        kprintf_warn("Attempted write to read-only ATAPI device\n");
        return -EIO;
    }
    bool i =  ahci_write_atapi((HBA_PORT *)disk->data, lba, sector_count, (void *)buffer);
    if (i == true) {
        return 0;
    } else {
        return -EIO;
    }
}

void module_entry() {
    pci_device_t *sata = detect_controller();

    map_region_to_page((uint64_t *)PHYS_TO_VIRTUAL(_get_pml4()), sata->bar[5],
                       PHYS_TO_VIRTUAL(sata->bar[5]), 0x20000, AHCI_MMIO_FLAGS);

    abar = (HBA_MEM *)PHYS_TO_VIRTUAL(sata->bar[5]);

    probe_port(abar);

    for (int i = 0; i < 32; i++) {
        if (drivetypes[i] == DRV_SATA) {
            HBA_PORT *port = &abar->ports[i];

            port_rebase(port);

            disk_device_t *disk = kmalloc(sizeof(disk_device_t));
            assert(disk != NULL);
            memset(disk, 0, sizeof(disk_device_t));

            disk->namespace   = DISK_NAMESPACE_MODERN;
            disk->id.letter   = letter_counter++;
            disk->block_size  = 512;
            disk->block_count = 1000000000; // TODO: identify

            disk->read  = ahci_diskdev_read;
            disk->write = ahci_diskdev_write;

            disk->data = (void *)port;

            char buffer[512];

            int i = ahci_read((HBA_PORT *)port, 0, 1, buffer);

            hex_dump_debug(buffer, 1 * 512);

            register_disk_device(disk);

            debugf_debug("AHCI: Registered SATA disk at port %d as /dev/sd%c\n",
                    i, disk->id.letter);
        } else if (drivetypes[i] == DRV_SATAPI) {
            HBA_PORT *port = &abar->ports[i];

            port_rebase(port);

            disk_device_t *disk = kmalloc(sizeof(disk_device_t));
            assert(disk != NULL);
            memset(disk, 0, sizeof(disk_device_t));

            disk->namespace   = DISK_NAMESPACE_OPTICAL;
            disk->id.letter   = opt_letter_counter++;
            disk->block_size  = ATAPI_SECTOR_SIZE;
            disk->block_count = ahci_get_atapi_capacity(port);

            disk->read  = ahci_diskdev_read_atapi;
            disk->write = ahci_diskdev_write_atapi;

            disk->data = (void *)port;

            char buffer[2049];

            //int i = ahci_read_atapi((HBA_PORT *)port, 0, 1, buffer);
            //hex_dump_debug(buffer, 1 * 512);

            register_disk_device(disk);

            debugf_debug("AHCI: Registered ATAPI disk at port %d as /dev/opt%c\n",
                    i, disk->id.letter);
        }
    }

    test_ahci();

    // simple test
    fileio_t *fd = open("/dev/opta", 0);
    if (fd) {
        char buffer[512];
        read(fd, 512, buffer);
        hex_dump_debug(buffer, 512);
        close(fd);
    } else {
        kprintf_warn("Failed to open /dev/sda for reading test data\n");
    }

    
}
