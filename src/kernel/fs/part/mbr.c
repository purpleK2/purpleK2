#include "mbr.h"

#include <memory/heap/kheap.h>
#include <stdbool.h>
#include <stdio.h>

partition_info_t *g_partitions = NULL;

const char *get_partition_type_name(uint8_t type) {
    switch (type) {
    case 0x00:
        return "Empty";
    case 0x01:
        return "FAT12";
    case 0x04:
        return "FAT16 <32MB";
    case 0x05:
        return "Extended";
    case 0x06:
        return "FAT16";
    case 0x07:
        return "NTFS/HPFS/exFAT";
    case 0x0B:
        return "FAT32";
    case 0x0C:
        return "FAT32 LBA";
    case 0x0E:
        return "FAT16 LBA";
    case 0x0F:
        return "Extended LBA";
    case 0x11:
        return "Hidden FAT12";
    case 0x12:
        return "Compaq diagnostics";
    case 0x14:
        return "Hidden FAT16 <32MB";
    case 0x16:
        return "Hidden FAT16";
    case 0x17:
        return "Hidden HPFS/NTFS";
    case 0x1B:
        return "Hidden FAT32";
    case 0x1C:
        return "Hidden FAT32 LBA";
    case 0x1E:
        return "Hidden FAT16 LBA";
    case 0x82:
        return "Linux swap";
    case 0x83:
        return "Linux";
    case 0x84:
        return "OS/2 hidden";
    case 0x85:
        return "Linux extended";
    case 0x8E:
        return "Linux LVM";
    case 0xA5:
        return "FreeBSD";
    case 0xA6:
        return "OpenBSD";
    case 0xA8:
        return "Darwin UFS";
    case 0xA9:
        return "NetBSD";
    case 0xAB:
        return "Darwin boot";
    case 0xAF:
        return "HFS / HFS+";
    case 0xEE:
        return "GPT";
    case 0xEF:
        return "EFI System";
    case 0xFD:
        return "Linux RAID";
    default:
        return "Unknown";
    }
}

int is_extended_partition(uint8_t type) {
    return (type == 0x05 || type == 0x0F || type == 0x85);
}

partition_info_t *add_partition(partition_info_t **head, uint8_t type,
                                uint8_t status, uint32_t start_lba,
                                uint32_t size_sectors, uint8_t is_extended,
                                uint8_t is_logical) {
    partition_info_t *new_part = kmalloc(sizeof(partition_info_t));
    if (!new_part)
        return NULL;

    new_part->type         = type;
    new_part->status       = status;
    new_part->start_lba    = start_lba;
    new_part->size_sectors = size_sectors;
    new_part->is_extended  = is_extended;
    new_part->is_logical   = is_logical;
    new_part->next         = NULL;

    if (*head == NULL) {
        *head = new_part;
    } else {
        partition_info_t *current = *head;
        while (current->next) {
            current = current->next;
        }
        current->next = new_part;
    }

    return new_part;
}

int parse_ebr(char *dev_path, uint32_t ebr_lba, uint32_t extended_start_lba,
              partition_info_t **partitions) {
    /*mbr_t ebr;

    detect_disk(abar);

    int port = get_sata_port(abar);

    if (ahci_read(&abar->ports[port], ebr_lba, 1, &ebr) != true) {
        kprintf("Error: Failed to read EBR at LBA %u\n", ebr_lba);
        return -1;
    }

    if (ebr.signature != 0xAA55) {
        kprintf("Error: Invalid EBR signature at LBA %u\n", ebr_lba);
        return -1;
    }

    if (ebr.partitions[0].type != 0 && ebr.partitions[0].sectors > 0) {
        uint32_t logical_start = ebr_lba + ebr.partitions[0].lba_first;

        add_partition(partitions, ebr.partitions[0].type,
                      ebr.partitions[0].status, logical_start,
                      ebr.partitions[0].sectors, 0,
                      1); // Not extended, is logical
    }

    if (ebr.partitions[1].type != 0 && ebr.partitions[1].sectors > 0) {
        if (is_extended_partition(ebr.partitions[1].type)) {
            uint32_t next_ebr_lba =
                extended_start_lba + ebr.partitions[1].lba_first;
            return parse_ebr(abar, next_ebr_lba, extended_start_lba,
                             partitions);
        }
    }

    return 0;*/
}

int parse_mbr(char *dev_path, partition_info_t **partitions) {
    /*mbr_t mbr;

    detect_disk(abar);

    int port = get_sata_port(abar);

    if (ahci_read(&abar->ports[port], 0, 1, &mbr) != true) {
        kprintf("Error: Failed to read MBR\n");
        return -1;
    }

    if (mbr.signature != 0xAA55) {
        kprintf("Error: Invalid MBR signature (0x%04X)\n", mbr.signature);
        return -1;
    }

    for (int i = 0; i < 4; i++) {
        partition_entry_t *part = &mbr.partitions[i];

        if (part->type == 0 || part->sectors == 0) {
            continue;
        }

        if (is_extended_partition(part->type)) {

            add_partition(partitions, part->type, part->status, part->lba_first,
                          part->sectors, 1, 0);

            if (parse_ebr(abar, part->lba_first, part->lba_first, partitions) !=
                0) {
                kprintf("Error parsing EBR chain\n");
            }
        } else {
            kprintf("\n");
            add_partition(partitions, part->type, part->status, part->lba_first,
                          part->sectors, 0, 0);
        }
    }

    return 0;*/
}

void print_partition_summary(partition_info_t *partitions) {
    int count                 = 0;
    partition_info_t *current = partitions;

    kprintf("\n=== PARTITION SUMMARY ===\n");
    while (current) {
        kprintf("Partition %d:\n", ++count);
        kprintf("  Type: %s (0x%02X)\n", get_partition_type_name(current->type),
                current->type);
        kprintf("  Start LBA: %u\n", current->start_lba);
        kprintf("  Size: %u sectors (%.2f MB)\n", current->size_sectors,
                (current->size_sectors * 512.0) / (1024.0 * 1024.0));
        kprintf("  Properties: %s%s%s\n",
                current->status == 0x80 ? "Bootable " : "",
                current->is_extended ? "Extended " : "",
                current->is_logical ? "Logical" : "Primary");
        kprintf("\n");
        current = current->next;
    }
    kprintf("Total partitions found: %d\n", count);
}

void free_partitions(partition_info_t *partitions) {
    while (partitions) {
        partition_info_t *next = partitions->next;
        kfree(partitions);
        partitions = next;
    }
}

partition_info_t *get_partition_by_index(partition_info_t *partitions,
                                         int index) {
    int count                 = 0;
    partition_info_t *current = partitions;

    while (current && count < index) {
        current = current->next;
        count++;
    }

    return current;
}

partition_info_t **find_partitions_by_type(partition_info_t *partitions,
                                           uint8_t type, int *found_count) {
    *found_count              = 0;
    partition_info_t *current = partitions;

    while (current) {
        if (current->type == type) {
            (*found_count)++;
        }
        current = current->next;
    }

    if (*found_count == 0) {
        return NULL;
    }

    partition_info_t **results =
        kmalloc(sizeof(partition_info_t *) * (*found_count));
    if (!results) {
        *found_count = 0;
        return NULL;
    }

    current   = partitions;
    int index = 0;
    while (current && index < *found_count) {
        if (current->type == type) {
            results[index++] = current;
        }
        current = current->next;
    }

    return results;
}