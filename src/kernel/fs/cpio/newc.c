#include "newc.h"

#include <memory/heap/kheap.h>

#include <stdio.h>
#include <string.h>

#include <errors.h>

#include <util/assert.h>

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

int cpio_fs_parse(cpio_t *fs, void *data, size_t size) {
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

size_t cpio_fs_read(cpio_t *fs, const char *filename, void *buffer,
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

cpio_file_t *cpio_fs_get_file(cpio_t *fs, const char *filename) {
    for (size_t i = 0; i < fs->file_count; ++i) {
        if (strcmp(fs->files[i].filename, filename) == 0) {
            return &fs->files[i];
        }
    }
    return NULL;
}

void cpio_fs_free(cpio_t *fs) {
    for (size_t i = 0; i < fs->file_count; ++i) {
        kfree(fs->files[i].filename);
        kfree(fs->files[i].data);
    }
    kfree(fs->files);
    fs->files      = NULL;
    fs->file_count = 0;
}

/** Extracts a CPIO archive
 * @param cpio the CPIO archive struct
 * @param dest_path the destination path (eg. /)
 */
int cpio_extract(cpio_t *cpio, char *dest_path) {
    if (!cpio || !dest_path) {
        debugf_warn("Missing CPIO archive, or destination path (%p, %p).\n",
                    cpio, dest_path);
        return ENULLPTR;
    }

    // track the full path of a file
    size_t s   = 20;
    char *path = kmalloc(s);
    memset(path, 0, s);
    if ((strlen(dest_path) + 1) > s) {
        path = krealloc(path, (strlen(dest_path) + 1));
        s    = (strlen(dest_path) + 1);
    }

    debugf_debug("Extracting CPIO to %s\n", dest_path);

    // Create the directory first
    // TODO? don't hardcode the mode?
    vfs_mkdir(dest_path, 0755);

    for (size_t i = 0; i < cpio->file_count; i++) {
        memset(path, 0, s);
        strcat(path, dest_path);

        cpio_file_t *file = &cpio->files[i];

        debugf_debug("CPIO path %s\n", file->filename);

        char *name_dup = strdup(file->filename);
        char *temp     = name_dup;
        char *dir;

        if (file->namesize + 1 > s) {
            s    = file->namesize + 1;
            path = krealloc(path, s);
        }

        while (*temp) {
            /*
            A note for future Omar:
            this call is laid out like this because:
            - dir has the first occurrence of "/"
            - temp will point to AFTER the occurrence,
              something like, (dir + offset until next occurrence of "/"), if
              there's any, or else it will simply point to the string terminator
            (0)
            */
            dir = strtok_r(NULL, "/", &temp);

            if (strlen(path) + strlen(dir) + 2 > s) {
                s    = strlen(path) + strlen(dir) + 1;
                path = krealloc(path, s);
            }

            strcat(path, "/");
            strcat(path, dir);

            debugf_debug("path=%s\n", path);

            int flags = 0;

            vnode_t *v;
            fileio_t *f;

            // lookup the path
            if (vfs_lookup(path, &v) == EOK) {
                // it exists, simply skip
                continue;
            }

            // create the file if it doesn't
            flags |= V_CREATE;

            if (*temp) {
                // a directory should exist
                flags |= V_DIR;
            }

            char *dup = strdup(path);
            if (vfs_open(dup, flags, &f) != EOK) {
                debugf_warn("Can't create %s!\n", path);
                kfree(dup);
            }

            // go on if this is a directory
            if ((*temp)) {
                continue;
            }

            // if a file has been created
            if (write(f, file->data, file->filesize) != EOK) {
                debugf_warn("Couldn't write to %s!\n", path);
            }
            close(f);
        }

        kfree(name_dup);
    }

    return 0;
}

// create a RAMFS structure from the given CPIO archive
int cpio_ramfs_init(cpio_t *fs, ramfs_t *ramfs) {
    if (!fs || !ramfs) {
        debugf_warn("Missing CPIO archive or RAMFS root struct!\n");
        return -1;
    }

    if (!ramfs->root_node) {
        debugf_warn("RAMFS root_node must be created before calling "
                    "cpio_ramfs_init!\n");
        return -1;
    }

    ramfs_node_t *cur_node = ramfs->root_node; // Start at the existing root
    ramfs_node_t *next_node;

    for (size_t i = 0; i < fs->file_count; i++) {
        cpio_file_t *file = &fs->files[i];

        char *name_dup = strdup(file->filename);
        char *temp     = name_dup;
        char *dir;

        // Reset to root for each file
        cur_node = ramfs->root_node;

        for (int j = 0; *temp; j++) {
            dir = strtok_r(NULL, "/", &temp);

            ramfs_ftype_t rt;
            if (*temp) {
                rt = RAMFS_DIRECTORY;
            } else {
                rt = RAMFS_FILE;
            }

            // Look for existing node in current directory
            ramfs_node_t *found = NULL;
            if (cur_node->type == RAMFS_DIRECTORY) {
                for (ramfs_node_t *child = cur_node->child; child != NULL;
                     child               = child->sibling) {
                    if (strcmp(child->name, dir) == 0) {
                        found = child;
                        break;
                    }
                }
            }

            if (found) {
                // Node exists, descend into it
                cur_node = found;
            } else {
                // Create new node
                next_node       = ramfs_create_node(rt);
                next_node->name = strdup(dir);

                if (rt == RAMFS_FILE) {
                    next_node->size = file->filesize;
                    next_node->data = file->data;
                }

                // Add as child of current node
                ramfs_append_child(cur_node, next_node);

                // Descend into new node if it's a directory
                if (*temp) {
                    cur_node = next_node;
                }
            }
        }

        kfree(name_dup);
    }

    return 0;
}
