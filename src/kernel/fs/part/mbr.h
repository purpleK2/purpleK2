#ifndef MBR_H
#define MBR_H

#include <ahci/ahci.h>

#include <stdint.h>

typedef struct {
    uint8_t status;
    uint8_t chs_first[3];
    uint8_t type;
    uint8_t chs_last[3];
    uint32_t lba_first;
    uint32_t sectors;
} __attribute__((packed)) partition_entry_t;

typedef struct {
    uint8_t bootcode[446];
    partition_entry_t partitions[4];
    uint16_t signature;
} __attribute__((packed)) mbr_t;

typedef struct partition_info {
    uint8_t type;
    uint8_t status;
    uint32_t start_lba;
    uint32_t size_sectors;
    uint8_t is_extended;
    uint8_t is_logical;
    struct partition_info *next;
} partition_info_t;

// extern
extern partition_info_t *g_partitions;

// silly little helpers :3
const char *get_partition_type_name(uint8_t type);
int is_extended_partition(uint8_t type);
partition_info_t *add_partition(partition_info_t **head, uint8_t type,
                                uint8_t status, uint32_t start_lba,
                                uint32_t size_sectors, uint8_t is_extended,
                                uint8_t is_logical);

// real stuff :O
int parse_ebr(HBA_MEM *abar, uint32_t ebr_lba, uint32_t extended_start_lba,
              partition_info_t **partitions);
int parse_mbr(HBA_MEM *abar, partition_info_t **partitions);

// utils
void print_partition_summary(partition_info_t *partitions);
void free_partitions(partition_info_t *partitions);

#endif // MBR_H