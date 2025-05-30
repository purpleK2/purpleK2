#include "newc.h"
#include "memory/heap/kheap.h"
#include <stdio.h>
#include <util/string.h>

#define align4(x) (((x) + 3) & ~3)

typedef struct {
    uint8_t *pos;
    uint8_t *end;
} cpio_reader_t;

static uint64_t parse_hex(char *buf, size_t len) {
    char temp[17] = {0}; // 16 hex digits max for 64-bit
    memcpy(temp, buf, len);
    return strtoull(temp, NULL, 16);
}

static int cpio_reader_next(cpio_reader_t *reader, cpio_file_t *file) {
    if ((size_t)(reader->end - reader->pos) < 110) {
        debugf_warn("cpio: Not enough data for header\n");
        return -1;
    }

    // Check magic
    if (memcmp(reader->pos, "070701", 6) != 0 &&
        memcmp(reader->pos, "070702", 6) != 0) {
        debugf_warn("cpio: Invalid magic number\n");
        return -1;
    }

    uint8_t *pos = reader->pos + 6;

    file->ino        = parse_hex((char *)pos, 8);
    pos             += 8;
    file->mode       = parse_hex((char *)pos, 8);
    pos             += 8;
    file->uid        = parse_hex((char *)pos, 8);
    pos             += 8;
    file->gid        = parse_hex((char *)pos, 8);
    pos             += 8;
    file->nlink      = parse_hex((char *)pos, 8);
    pos             += 8;
    file->mtime      = parse_hex((char *)pos, 8);
    pos             += 8;
    file->filesize   = parse_hex((char *)pos, 8);
    pos             += 8;
    file->devmajor   = parse_hex((char *)pos, 8);
    pos             += 8;
    file->devminor   = parse_hex((char *)pos, 8);
    pos             += 8;
    file->rdevmajor  = parse_hex((char *)pos, 8);
    pos             += 8;
    file->rdevminor  = parse_hex((char *)pos, 8);
    pos             += 8;
    file->namesize   = parse_hex((char *)pos, 8);
    pos             += 8;
    file->check      = parse_hex((char *)pos, 8);
    pos             += 8;

    reader->pos = pos;

    // Bounds check
    if ((size_t)(reader->end - reader->pos) < file->namesize) {
        debugf_warn("cpio: Not enough data for filename\n");
        return -1;
    }

    char *filename = kmalloc(file->namesize);
    if (!filename) {
        debugf_warn("cpio: Memory allocation failed for filename\n");
        return -1;
    }

    memcpy(filename, reader->pos, file->namesize);
    reader->pos += file->namesize;
    reader->pos  = (uint8_t *)align4((uintptr_t)reader->pos);

    if (filename[file->namesize - 1] != '\0') {
        debugf_warn("cpio: Filename not null-terminated\n");
        kfree(filename);
        return -1;
    }

    // Check for end-of-archive marker
    if (strcmp(filename, "TRAILER!!!") == 0) {
        debugf_debug("cpio: End of archive marker found\n");
        kfree(filename);
        return 1;
    }

    file->filename = filename;

    if ((size_t)(reader->end - reader->pos) < file->filesize) {
        debugf_warn("cpio: Not enough data for file content\n");
        return -1;
    }

    file->data = kmalloc(file->filesize);
    if (!file->data) {
        debugf_warn("cpio: Memory allocation failed for file data\n");
        return -1;
    }

    memcpy(file->data, reader->pos, file->filesize);
    reader->pos += file->filesize;
    reader->pos  = (uint8_t *)align4((uintptr_t)reader->pos);

    debugf_debug("cpio: Parsed file '%s' (size: %llu bytes)\n", file->filename,
                 file->filesize);

    return 0;
}

int cpio_fs_parse(cpio_fs_t *fs, void *data, size_t size) {
    cpio_reader_t reader = {
        .pos = (uint8_t *)data,
        .end = (uint8_t *)data + size,
    };

    fs->files        = NULL;
    fs->file_count   = 0;
    fs->archive_data = data;
    fs->archive_size = size;

    size_t capacity = 4;
    fs->files       = kmalloc(capacity * sizeof(cpio_file_t));
    if (!fs->files)
        return -1;

    while (reader.pos < reader.end) {
        if (fs->file_count == capacity) {
            capacity *= 2;
            cpio_file_t *new_files =
                krealloc(fs->files, capacity * sizeof(cpio_file_t));
            if (!new_files)
                return -1;
            fs->files = new_files;
        }

        cpio_file_t *file = &fs->files[fs->file_count];
        memset(file, 0, sizeof(cpio_file_t));

        int res = cpio_reader_next(&reader, file);
        if (res == 1)
            break; // End marker
        if (res < 0)
            return -1;

        fs->file_count++;
    }

    return 0;
}

size_t cpio_fs_read(cpio_fs_t *fs, const char *filename, void *buffer,
                    size_t bufsize) {
    for (size_t i = 0; i < fs->file_count; ++i) {
        if (strcmp(fs->files[i].filename, filename) == 0) {
            size_t len = fs->files[i].filesize;
            if (len > bufsize)
                len = bufsize;
            memcpy(buffer, fs->files[i].data, len);
            return len;
        }
    }
    return 0;
}

cpio_file_t *cpio_fs_get_file(cpio_fs_t *fs, const char *filename) {
    for (size_t i = 0; i < fs->file_count; ++i) {
        if (strcmp(fs->files[i].filename, filename) == 0) {
            return &fs->files[i];
        }
    }
    return NULL;
}

void cpio_fs_free(cpio_fs_t *fs) {
    for (size_t i = 0; i < fs->file_count; ++i) {
        kfree(fs->files[i].filename);
        kfree(fs->files[i].data);
    }
    kfree(fs->files);
    fs->files      = NULL;
    fs->file_count = 0;
}
