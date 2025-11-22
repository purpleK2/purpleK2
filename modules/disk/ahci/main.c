#include "ahci.h"
#include "errors.h"
#include "fs/file_io.h"
#include "fs/part/part.h"
#include "memory/heap/kheap.h"
#include "memory/pmm/pmm.h"
#include "paging/paging.h"
#include "util/dump.h"
#include <util/assert.h>
#include <stdio.h>

#include <module/modinfo.h>

#include <dev/diskdev.h>
#include <string.h>

const modinfo_t modinfo = {.name        = "ahci",
                           .version     = "1.1.0",
                           .author      = "NotNekodev & Ivan_Holy",
                           .description = "AHCI (SATA + ATAPI) Driver for PurpleK2",
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

static int ahci_sata_diskdev_read(struct disk_device *disk, uint8_t *buffer, uint64_t lba,
                                   uint32_t sector_count) {
    bool i = ahci_sata_read((HBA_PORT *)disk->data, lba, sector_count, buffer);
    if (i == true) {
        return 0;
    } else {
        return -EIO;
    }
}
static int ahci_sata_diskdev_write(struct disk_device *disk, const uint8_t *buffer, uint64_t lba,
                 uint32_t sector_count) {
    bool i =  ahci_sata_write((HBA_PORT *)disk->data, lba, sector_count, (void *)buffer);

    if (i == true) {
        return 0;
    } else {
        return -EIO;
    }
}

// ATAPI stuff :3
static int ahci_atapi_diskdev_read(struct disk_device *disk, uint8_t *buffer, 
                                   uint64_t lba, uint32_t sector_count) {
    char *tmp = kmalloc(disk->block_size * sector_count);
    bool i =  ahci_atapi_read((HBA_PORT *)disk->data, lba, sector_count, buffer);
    memcpy(buffer, tmp, disk->block_size * sector_count);
    kfree(tmp);
    
    if (i == true) {
        return 0;
    } else {
        return -EIO;
    }
}

static int ahci_atapi_diskdev_write(struct disk_device *disk, const uint8_t *buffer, 
                                    uint64_t lba, uint32_t sector_count) {
    if (!ahci_atapi_is_writable((HBA_PORT *)disk->data)) {
        debugf_warn("Attempted write to read-only ATAPI device\n");
        return -EIO;
    }

    bool i =  ahci_atapi_write((HBA_PORT *)disk->data, lba, sector_count, (void *)buffer);

    if (i == true) {
        return 0;
    } else {
        return -EIO;
    }
}

void module_entry() {
    pci_device_t *sata = ahci_detect_controller();

    map_region_to_page((uint64_t *)PHYS_TO_VIRTUAL(_get_pml4()), sata->bar[5],
                       PHYS_TO_VIRTUAL(sata->bar[5]), 0x20000, AHCI_MMIO_FLAGS);

    abar = (HBA_MEM *)PHYS_TO_VIRTUAL(sata->bar[5]);

    ahci_probe_ports(abar);

    for (int i = 0; i < 32; i++) {
        if (drivetypes[i] == DRV_SATA) {
            HBA_PORT *port = &abar->ports[i];

            ahci_port_rebase(port);

            disk_device_t *disk = kmalloc(sizeof(disk_device_t));
            assert(disk != NULL);
            memset(disk, 0, sizeof(disk_device_t));

            disk->namespace   = DISK_NAMESPACE_MODERN;
            disk->id.letter   = letter_counter++;
            disk->block_size  = ahci_sata_get_block_size(port);
            disk->block_count = ahci_sata_get_capacity(port);

            disk->read  = ahci_sata_diskdev_read;
            disk->write = ahci_sata_diskdev_write;

            disk->data = (void *)port;

            register_disk_device(disk);

            debugf_debug("AHCI: Registered SATA disk at port %d as /dev/sd%c\n\tBlock size: %u bytes\n\tBlock count: %u blocks\n\tSize: %u MB\n",
                    i, disk->id.letter, disk->block_size, disk->block_count, disk->block_size * disk->block_count / (1024 * 1024));

            partition_t *partitions = NULL;
            parse_partitions(disk, &partitions);
            // print partitons
            partition_t *current = partitions;
            while (current) {
                debugf_debug("  Partition: %s, Start LBA: %llu, Size: %llu sectors\n",
                        current->dev_path, current->start_lba, current->size_sectors);
                current = current->next;
            }

            char *buf = kmalloc(512);
            char bufStack[512];
            ahci_sata_read(port, 0, 1, buf);
            hex_dump_debug(buf, 512);

            uint64_t phys_heap = pg_virtual_to_phys((uint64_t*)PHYS_TO_VIRTUAL(_get_pml4()), (uint64_t)buf);
            uint64_t phys_stack = pg_virtual_to_phys((uint64_t*)PHYS_TO_VIRTUAL(_get_pml4()), (uint64_t)bufStack);
            kprintf("Heap: 0x%.16llx (0x%p)\nStack: 0x%.16llx (0x%p) [0x%.16llx]\n", phys_heap, buf, phys_stack, bufStack, VIRT_TO_PHYSICAL(bufStack));

            kfree(buf);
        } else if (drivetypes[i] == DRV_SATAPI) {
            HBA_PORT *port = &abar->ports[i];

            ahci_port_rebase(port);

            disk_device_t *disk = kmalloc(sizeof(disk_device_t));
            assert(disk != NULL);
            memset(disk, 0, sizeof(disk_device_t));

            disk->namespace   = DISK_NAMESPACE_OPTICAL;
            disk->id.letter   = opt_letter_counter++;
            disk->block_size  = ATAPI_SECTOR_SIZE;
            disk->block_count = ahci_atapi_get_capacity(port);

            disk->read  = ahci_atapi_diskdev_read;
            disk->write = ahci_atapi_diskdev_write;

            disk->data = (void *)port;

            register_disk_device(disk);

            debugf_debug("AHCI: Registered ATAPI disk at port %d as /dev/opt%c\n\tBlock size: %u bytes\n\tBlock count: %u blocks\n\tSize: %u MB\n",
                    i, disk->id.letter, disk->block_size, disk->block_count, disk->block_size * disk->block_count / (1024 * 1024));
        }
    }
}
