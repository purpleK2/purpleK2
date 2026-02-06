#ifndef FD_H
#define FD_H 1

#include <stddef.h>
#include <stdint.h>

typedef enum fd_type {
    FD_NONE = 0,
    FD_FILE,
    FD_DIR
} fd_type_t;

typedef struct fd_entry {
    fd_type_t type;
    void *ptr;
} fd_entry_t;

typedef struct fd_table {
    fd_entry_t *entries;
    size_t size;
} fd_table_t;

int  fd_alloc(fd_table_t *ft, fd_type_t type, void *ptr);
void *fd_get(fd_table_t *ft, int fd, fd_type_t expected);
int  fd_free(fd_table_t *ft, int fd);

#endif // FD_H