#ifndef PART_H
#define PART_H

#include "dev/diskdev.h"
#include <fs/fsid.h>
#include <stdint.h>

typedef struct partition {
    disk_device_t *parent_disk;
    char *dev_path;
    fsid_t fsid;
    uint64_t start_lba;
    uint64_t size_sectors;
    struct partition *next;
} partition_t;

typedef struct part_parser {
    const char *id;
    int (*probe)(disk_device_t *disk, partition_t **out);
    void (*register_callback)();
    void (*unregister_callback)();
    struct part_parser *next;
} part_parser_t;

int register_part_parser(part_parser_t *parser);
int unregister_part_parser(const char *id);
part_parser_t *get_part_parser(const char *id);

void register_partiton_dev(partition_t *part);

int parse_partitions(disk_device_t *disk, partition_t **partitions);

#endif
