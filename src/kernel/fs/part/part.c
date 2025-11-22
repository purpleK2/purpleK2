#include "part.h"
#include "util/macro.h"
#include <string.h>
#include <memory/heap/kheap.h>
#include <util/assert.h>
#include <stdio.h>

static part_parser_t *parser_list = NULL;

int register_part_parser(part_parser_t *parser)
{
    if (!parser || !parser->id)
        return -1;

    part_parser_t *cur = parser_list;
    while (cur) {
        if (strcmp(cur->id, parser->id) == 0)
            return -1;
        cur = cur->next;
    }

    parser->next = parser_list;
    parser_list = parser;

    if (parser->register_callback)
        parser->register_callback();

    return 0;
}

int unregister_part_parser(const char *id)
{
    if (!id)
        return -1;

    part_parser_t *cur = parser_list;
    part_parser_t *prev = NULL;

    while (cur) {
        if (strcmp(cur->id, id) == 0) {
            if (prev)
                prev->next = cur->next;
            else
                parser_list = cur->next;

            if (cur->unregister_callback)
                cur->unregister_callback();

            return 0;
        }
        prev = cur;
        cur = cur->next;
    }

    return -1;
}

part_parser_t *get_part_parser(const char *id)
{
    if (!id)
        return NULL;

    part_parser_t *cur = parser_list;
    while (cur) {
        if (strcmp(cur->id, id) == 0)
            return cur;
        cur = cur->next;
    }
    return NULL;
}

int parse_partitions(disk_device_t *disk, partition_t **out)
{
    if (!disk || !out)
        return -1;

    part_parser_t *cur = parser_list;
    while (cur) {
        partition_t *parsed = NULL;

        int r = cur->probe(disk, &parsed);
        if (r == 0 && parsed != NULL) {
            *out = parsed;
            return 0;
        }

        cur = cur->next;
    }

    return -1;
}

static int partdev_read(struct device *dev, void *buffer, size_t size, size_t offset) {
    assert(dev != NULL && dev->data != NULL);
    partition_t *part = (partition_t *)dev->data;
    assert(part->parent_disk != NULL);

    uint64_t sector_size = part->parent_disk->block_size;

    if (offset >= part->size_sectors * sector_size)
        return 0;

    if (offset + size > part->size_sectors * sector_size)
        size = part->size_sectors * sector_size - offset;

    uint64_t start_lba   = part->start_lba + (ROUND_DOWN(offset, sector_size));
    uint32_t sector_count = ROUND_UP(size, sector_size);

    return part->parent_disk->read(part->parent_disk, buffer, start_lba, sector_count);
}

static int partdev_write(struct device *dev, const void *buffer, size_t size, size_t offset) {
    assert(dev != NULL && dev->data != NULL);
    partition_t *part = (partition_t *)dev->data;
    assert(part->parent_disk != NULL);

    uint64_t sector_size = part->parent_disk->block_size;

    uint64_t start_lba   = part->start_lba + (ROUND_DOWN(offset, sector_size));
    uint32_t sector_count = ROUND_UP(size, sector_size);

    return part->parent_disk->write(part->parent_disk, buffer, start_lba, sector_count);
}

static int partdev_ioctl(struct device *dev, int request, void *arg) {
    (void)dev;
    (void)request;
    (void)arg;
    return -1;
}

void register_partiton_dev(partition_t *part) {
    assert(part != NULL);
    device_t *dev = kmalloc(sizeof(device_t));
    assert(dev != NULL);
    memset(dev, 0, sizeof(device_t));

    snprintf(dev->name, DEVICE_NAME_MAX, "%s", part->dev_path);
    dev->dev_node_path = part->dev_path;
    dev->major = 2;
    dev->minor = 1;
    dev->type = DEVICE_TYPE_BLOCK;

    dev->read = partdev_read;
    dev->write = partdev_write;
    dev->ioctl = partdev_ioctl;

    dev->dev_node_path = strdup(part->dev_path);
    assert(dev->dev_node_path != NULL);

    dev->data = (void *)part;

    int r = register_device(dev);
    assert(r == 0);
}
