#ifndef NEWC_H
#define NEWC_H 1

#include <stddef.h>
#include <stdint.h>

#include <fs/ramfs/ramfs.h>

typedef struct {
    char cmagic[6];     // "070701" or "070702"
    uint64_t ino;       // Inode number
    uint64_t mode;      // File mode (type and permissions)
    uint64_t uid;       // User ID of owner
    uint64_t gid;       // Group ID of owner
    uint64_t nlink;     // Number of hard links
    uint64_t mtime;     // Modification time (in seconds since epoch)
    uint64_t filesize;  // Size of the file in bytes
    uint64_t devmajor;  // Major device number (for device files)
    uint64_t devminor;  // Minor device number (for device files)
    uint64_t rdevmajor; // Major device number for the file
    uint64_t rdevminor; // Minor device number for the file
    uint64_t namesize;  // Size of the filename
    uint64_t check;     // Checksum (not used in newc format)

    char *filename;
    void *data;
} cpio_file_t;

typedef struct {
    cpio_file_t *files;
    size_t file_count;
    void *archive_data;
    size_t archive_size;
} cpio_fs_t;

int cpio_fs_parse(cpio_fs_t *fs, void *data, size_t size);
size_t cpio_fs_read(cpio_fs_t *fs, const char *filename, void *buffer,
                    size_t bufsize);
void cpio_fs_free(cpio_fs_t *fs);
cpio_file_t *cpio_fs_get_file(cpio_fs_t *fs, const char *filename);

int cpio_ramfs_init(cpio_fs_t *fs, ramfs_t *ramfs);

#endif // NEWC_H
