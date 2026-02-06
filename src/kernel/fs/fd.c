#include "errors.h"
#include "memory/heap/kheap.h"
#include "fd.h"
#include <string.h>

#define FD_START 0

static int fd_grow(fd_table_t *ft, size_t new_size) {
    fd_entry_t *n =
        krealloc(ft->entries, new_size * sizeof(fd_entry_t));
    if (!n)
        return -ENOMEM;

    for (size_t i = ft->size; i < new_size; i++) {
        n[i].type = FD_NONE;
        n[i].ptr  = NULL;
    }

    ft->entries = n;
    ft->size = new_size;
    return 0;
}

int fd_alloc(fd_table_t *ft, fd_type_t type, void *ptr) {
    if (!ft)
        return -EINVAL;

    for (size_t i = FD_START; i < ft->size; i++) {
        if (ft->entries[i].type == FD_NONE) {
            ft->entries[i].type = type;
            ft->entries[i].ptr  = ptr;
            return (int)i;
        }
    }

    size_t old = ft->size;
    size_t new = old ? old * 2 : 8;
    if (new < FD_START + 1)
        new = FD_START + 1;

    int ret = fd_grow(ft, new);
    if (ret < 0)
        return ret;

    ft->entries[old].type = type;
    ft->entries[old].ptr  = ptr;
    return (int)old;
}

void *fd_get(fd_table_t *ft, int fd, fd_type_t expected) {
    if (!ft || fd < 0 || (size_t)fd >= ft->size)
        return NULL;

    fd_entry_t *e = &ft->entries[fd];
    if (e->type != expected)
        return NULL;

    return e->ptr;
}

int fd_free(fd_table_t *ft, int fd) {
    if (!ft || fd < 0 || (size_t)fd >= ft->size)
        return -EBADF;

    if (ft->entries[fd].type == FD_NONE)
        return -EBADF;

    ft->entries[fd].type = FD_NONE;
    ft->entries[fd].ptr  = NULL;
    return 0;
}
