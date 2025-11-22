#include "dev/diskdev.h"
#include "fs/file_io.h"
#include "fs/part/part.h"
#include "mbr.h"
#include "memory/heap/kheap.h"
#include "util/dump.h"
#include <stdio.h>

#include <module/modinfo.h>
#include <util/assert.h>

const modinfo_t modinfo = {.name        = "mbr",
                           .version     = "1.0.0",
                           .author      = "NotNekodev",
                           .description = "MBR partition parser module",
                           .license     = "MIT",
                           .url      = "https://github.com/purplek2/PurpleK2",
                           .priority = MOD_PRIO_HIGH,
                           .deps = {"kernel", NULL}}; // terminated with a \0

static int mbr_probe(disk_device_t *disk, partition_t **out) {
    char *dev_path = disk->dev->dev_node_path;
    assert(dev_path != NULL);

    int part_count = 0;

    partition_info_t *partitions = NULL;
    char buf[64];
    snprintf(buf, 64, "/dev/%s", dev_path);
    if (parse_mbr(buf, &partitions) != 0) {
        return -1;
    }

    if (partitions == NULL) {
        return -1;
    }

    partition_t *part_list = NULL;
    partition_info_t *current = partitions;
    while (current) {
        partition_t *part = kmalloc(sizeof(partition_t));
        assert(part != NULL);

        part->parent_disk = disk;

        part->dev_path = kmalloc(32);
        assert(part->dev_path != NULL);
        snprintf(part->dev_path, 32, "%s%d", dev_path, ++part_count);

        part->start_lba = current->start_lba;
        part->size_sectors = current->size_sectors;

        register_partiton_dev(part);

        char buf2[64];
        snprintf(buf2, 64, "/dev/%s", part->dev_path);
        fileio_t *fd = open(buf2, 0);
        assert(fd != NULL);
        char buf3[512];
        seek(fd, 2048 * 512, SEEK_SET);
        read(fd, 512, buf3);
        hex_dump_debug(buf3, 512);
        close(fd);

        part->next = part_list;
        part_list = part;
        current = current->next;
    }

    free_partitions(partitions);
    *out = part_list;
    return 0;
}

static void mbr_register_callback() {
    debugf_debug("MBR partition parser registered\n");
}

static void mbr_unregister_callback() {
    // idk what to put here
}

static part_parser_t mbr_parser = {
    .id = "mbr",
    .probe = mbr_probe,
    .register_callback = mbr_register_callback,
    .unregister_callback = mbr_unregister_callback,
    .next = NULL
};

void module_exit() {
    unregister_part_parser("mbr");
}

void module_entry() {
    register_part_parser(&mbr_parser);

    
}