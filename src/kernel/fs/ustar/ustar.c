#include "ustar.h"

#include <memory/heap/kheap.h>

#include <util/string.h>
#include <util/util.h>

// returns a custom structure with their files and their count
ustar_fs_t *ramfs_init(void *ramfs) {
    ustar_file_header *ustar_start = (ustar_file_header *)ramfs;

    if (strncmp(USTAR_FILE_IDENTIFIER, ustar_start->identifier,
                sizeof(USTAR_FILE_IDENTIFIER)) != 0) {
        debugf_warn("Identifier's not correct, found \"%6s\"\n",
                    ustar_start->identifier);
    }

    // start parsing all files
    void *ptr                 = ustar_start;
    ustar_file_header *header = (ustar_file_header *)ptr;
    size_t files_found        = 0;
    do {
        if (strncmp(USTAR_FILE_IDENTIFIER, header->identifier,
                    sizeof(USTAR_FILE_IDENTIFIER)) == 0) {
            debugf_ok("Found entry %s\n", header->path);
            files_found++;
        }

        size_t entry_size = (size_t)oct2bin(header->size, 11);

        ptr    += (((entry_size + 511) / 512) + 1) * 512;
        header  = (ustar_file_header *)ptr;
    } while (strncmp(USTAR_FILE_IDENTIFIER, header->identifier,
                     sizeof(USTAR_FILE_IDENTIFIER)) == 0);

    ustar_fs_t *ustar_structure = kmalloc(sizeof(ustar_fs_t));
    memset(ustar_structure, 0, sizeof(ustar_fs_t));
    ustar_structure->file_count = files_found;
    ustar_structure->files = kmalloc(files_found * sizeof(ustar_file_header));
    memset(ustar_structure->files, 0, sizeof(ustar_file_header) * files_found);

    ptr = ustar_start;
    for (size_t i = 0; i < ustar_structure->file_count; i++) {
        ustar_file_header *header = (ustar_file_header *)ptr;

        if (strncmp(USTAR_FILE_IDENTIFIER, header->identifier,
                    sizeof(USTAR_FILE_IDENTIFIER)) != 0)
            continue; // we should be done with parsing

        ustar_structure->files[i] = header;

        size_t entry_size = (size_t)oct2bin(header->size, 11);

        ptr += (((entry_size + 511) / 512) + 1) * 512;
    }

    debugf_ok("Found %zu files\n", ustar_structure->file_count);

    return ustar_structure;
}

// returns a struct with all the found files
ustar_file_tree_t *file_lookup(ustar_fs_t *fs, char *path) {
    ustar_file_t **found_files = kmalloc(sizeof(ustar_file_t));
    ustar_file_header *file_header;
    size_t found       = 0;
    ustar_file_t *file = NULL;
    for (size_t i = 0; i < fs->file_count; i++) {
        file_header = fs->files[i];

        if (strstr(file_header->path, path) == NULL)
            continue;

        int ustar_entry_type = oct2bin(&file_header->file_type, 1);
        switch (ustar_entry_type) {
        case USTAR_FILE_DIRECTORY:
            void *temp = file_header;
            ustar_file_header *next_file =
                (ustar_file_header *)(temp + USTAR_SECTOR_ALIGN);

            // if the directory contains what we need, we'll walk throught it
            if (strstr(next_file->path, file_header->path) != NULL)
                continue;

            break;

        default:
            void *file_ptr =
                ((void *)file_header) +
                USTAR_SECTOR_ALIGN; // don't use sizeof(file header)...
            size_t file_size = (size_t)oct2bin(file_header->size, 11);

            file        = kmalloc(sizeof(ustar_file_t));
            file->path  = file_header->path;
            file->size  = file_size;
            file->start = file_ptr;

            file->type = (ustar_file_type)ustar_entry_type;

            break;
        }

        // we found a file, we're going to save it to our array
        found++;
        found_files = krealloc(found_files, sizeof(ustar_file_t) * found);

        found_files[found - 1] = file;
    }

    ustar_file_tree_t *file_tree = kmalloc(sizeof(ustar_file_tree_t));
    file_tree->count             = found;
    file_tree->found_files       = found_files;

    return file_tree;
}
