#include "types.h"
#ifndef FILE_IO_H
#define FILE_IO_H 1

#include <stddef.h>

typedef enum fseek {
    SEEK_SET = 0, // start of file buffer
    SEEK_CUR = 1, // current offset of file buffer
    SEEK_END = 2  // end of file buffer
} fseek_t;

typedef enum fcntl_cmd {
    F_GETFL = 0,
    F_SETFL = 1,
} fcntl_cmd_t;

#define O_APPEND    (1 << 0) // append mode
#define O_CREATE    (1 << 1) // todo: file permissions on creation
#define O_DIRECTORY (1 << 2) // must be a directory
// TODO: #define O_PATH      // return a file descriptor
#define PIPE_READ_END  (1 << 2)
#define PIPE_WRITE_END (1 << 3)

#define SPECIAL_FILE_TYPE_PIPE   (1 << 4)
#define SPECIAL_FILE_TYPE_DEVICE (1 << 5)

/*
    Proper structs and functions for file I/O
*/

typedef struct file_io {
    void *buf_start; // actual file data
    size_t size;     // file size

    size_t flags; // flags _/(0 o 0)\_

    // for reading and writing
    size_t offset;

    void *private; // for internal use (aka you put the vnode in here :P)
} fileio_t;

fileio_t *fio_create();

fileio_t *open(const char *path, int flags, mode_t mode);
size_t read(fileio_t *file, size_t size, void *out);
int write(fileio_t *file, void *buf, size_t size);
int close(fileio_t *file);

size_t seek(fileio_t *file, size_t offset, fseek_t whence);

size_t fcntl(fileio_t *file, fcntl_cmd_t cmd, void *arg);

int fs_list(const char *path, int max_depth);

#endif
