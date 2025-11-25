#ifndef USTAR_H
#define USTAR_H 1

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define USTAR_SECTOR_ALIGN 0x200 // 512 bytes

#define USTAR_FILE_IDENTIFIER "ustar"

typedef enum {
    USTAR_FILE_NORMAL,
    USTAR_FILE_HARDLINK,
    USTAR_FILE_SYMLINK,
    USTAR_FILE_CHARACTER_DEVICE,
    USTAR_FILE_BLOCK_DEVICE,
    USTAR_FILE_DIRECTORY,
    USTAR_FILE_NAMED_PIPE
} ustar_file_type;

typedef struct ustar_file_header {
    char path[100];

    char mode[8];

    char uid[8];
    char gid[8];

    char size[12];          // OCTAL BASE >:c
    char last_modified[12]; // Unix time (still octal >:/ )

    char checksum[8];

    char file_type;

    char linked_filename[100];

    char identifier[6]; // "ustar\0" (null-terminated)
    char version[2];

    char owner_name[32];
    char group_name[32];

    char dev_major_number[8];
    char dev_minor_number[8];

    char prefix[155];
} __attribute__((packed)) ustar_file_header;

typedef struct ustar_fs_t {
    size_t file_count;
    ustar_file_header **files; // pointer to files and directories

    // other stuff (maybe?)
} ustar_fs_t;

typedef struct ustar_file_t {
    void *start;

    char *path;
    size_t size;

    ustar_file_type type;
} ustar_file_t;

// to use with `file_lookup` and other fs-related lookup functions
typedef struct ustar_file_tree_t {
    size_t count;
    ustar_file_t **found_files;
} ustar_file_tree_t;

ustar_fs_t *ramfs_init(void *ramfs);

ustar_file_tree_t *file_lookup(ustar_fs_t *fs, char *filename);

#endif
