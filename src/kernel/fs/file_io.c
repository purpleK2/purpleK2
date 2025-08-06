#include "file_io.h"

#include <errors.h>

#include <fs/vfs/vfs.h>

#include <memory/heap/kheap.h>

#include <string.h>

#include <stdio.h>

#include <util/macro.h>

int f2vflags(int fio_flags) {
    int vflags = 0;

    if (fio_flags & (O_CREATE)) {
        vflags |= V_CREATE;
    }
    /*  just keep it commented for now
    if (fio_flags & (O_DIRECTORY)) {
        vflags |= V_DIR;
    }
    */

    return vflags;
}

fileio_t *fio_create() {
    fileio_t *fio = kmalloc(sizeof(fileio_t));
    memset(fio, 0, sizeof(fileio_t));

    return fio;
}

fileio_t *open(char *path, int flags) {
    UNUSED(flags);

    fileio_t *f = NULL;

    vfs_t *parent_vfs;
    if (vfs_resolve_mount(path, &parent_vfs) != 0) {
        f = NULL;
        return f;
    }

    if (vfs_open(parent_vfs, path, f2vflags(flags), &f) != 0) {
        f = NULL;
        return f;
    }

    f->offset = 0;

    // the flags we opened the file with
    f->flags = flags;

    return f;
}

int read(fileio_t *file, size_t size, void *out) {
    if (!file) {
        return ENULLPTR;
    }

    vnode_t *vn = file->private;

    if (file->offset >= file->size) {
        return 0;
    }

    if (size > file->size) {
        size = (file->size - file->offset);
    }

    if (vfs_read(vn, size, file->offset, out) != 0) {
        return -EIO;
    }

    file->offset += size;

    return size;
}

int write(fileio_t *file, void *buf, size_t size) {
    vnode_t *vn = file->private;

    size_t offset = file->offset;
    if (file->flags & O_APPEND) {
        offset += file->size;
    }

    if (vfs_write(vn, buf, size, offset) != 0) {
        return -EIO;
    }

    file->offset += size;

    return EOK;
}

int close(fileio_t *file) {
    vnode_t *vn = file->private;

    if (vfs_close(vn) != 0) {
        return -1;
    }

    kfree(file);

    return EOK;
}

size_t seek(fileio_t *file, size_t offset, fseek_t whence) {
    if (!file) {
        return -ENULLPTR;
    }

    switch (whence) {
    case SEEK_CUR:
        file->offset += offset;
        break;

    case SEEK_END:
        file->offset = (file->size + offset);
        break;

    case SEEK_SET:
        file->offset = offset;
        break;

    default:
        // just don't do anything
        break;
    }

    return file->offset;
}

size_t fcntl(fileio_t *file, fcntl_cmd_t cmd, void *arg) {
    switch (cmd) {
    case F_GETFL:
        return file->flags;

    case F_SETFL:
        size_t flags = *(size_t *)arg;

        // we can only apply some flags, mask everything else
        // just in case (+ we're just going to OR them here :)
        file->flags |= (flags & (O_APPEND));

        break;

    default:
        break;
    }

    return EOK;
}
