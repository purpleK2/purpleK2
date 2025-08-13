#include "syscall.h"

#include <fs/file_io.h>
#include <fs/vfs/vfs.h>
#include <scheduler/scheduler.h>

#include <stdint.h>
#include <util/macro.h>

void sys_exit(int status) {
    UNUSED(status);

    proc_exit();
}

int sys_open(char *path, int mode) {
    pcb_t *current = get_current_pcb();

    if (!path || !current) {
        return -1;
    }

    current->fds[current->fd_count++] = open(path, mode);
    if (current->fds[current->fd_count - 1] == NULL) {
        return -1;
    }

    return current->fd_count - 1;
}

int sys_read(int fd, char *buf, int count) {
    pcb_t *current = get_current_pcb();

    if (fd < 0 || fd >= current->fd_count || !buf || count <= 0) {
        return -1;
    }

    fileio_t *file = current->fds[fd];
    if (!file) {
        return -1;
    }

    return read(file, count, buf);
}

int sys_write(int fd, const char *buf, int count) {
    pcb_t *current = get_current_pcb();

    if (fd < 0 || fd >= current->fd_count || !buf || count <= 0) {
        return -1;
    }

    fileio_t *file = current->fds[fd];
    if (!file) {
        return -1;
    }

    return write(file, (void *)buf, count);
}

int sys_close(int fd) {
    pcb_t *current = get_current_pcb();

    if (fd < 0 || fd >= current->fd_count) {
        return -1;
    }

    fileio_t *file = current->fds[fd];
    if (!file) {
        return -1;
    }

    close(file);
    current->fds[fd] = NULL;

    return 0;
}

int sys_ioctl(int fd, int request, void *arg) {
    pcb_t *current = get_current_pcb();

    if (fd < 0 || fd >= current->fd_count) {
        return -1;
    }

    fileio_t *file = current->fds[fd];
    if (!file) {
        return -1;
    }

    return vfs_ioctl(file->private, request, arg);
}

int sys_seek(int fd, int whence, int offset) {
    pcb_t *current = get_current_pcb();

    if (fd < 0 || fd >= current->fd_count) {
        return -1;
    }

    fileio_t *file = current->fds[fd];
    if (!file) {
        return -1;
    }

    return seek(file, whence, offset);
}

int sys_fcntl(int fd, int op, void *arg) {
    pcb_t *current = get_current_pcb();

    if (fd < 0 || fd >= current->fd_count) {
        return -1;
    }

    fileio_t *file = current->fds[fd];
    if (!file) {
        return -1;
    }

    return fcntl(file, op, arg);
}

long handle_syscall(long num, long arg1, long arg2, long arg3, long arg4,
                    long arg5, long arg6) {
    switch (num) {
    case SYS_exit:
        sys_exit(arg1);
        break;
    case SYS_open:
        return sys_open((char *)(uintptr_t)arg1, arg2);
    case SYS_read:
        return sys_read(arg1, (char *)(uintptr_t)arg2, arg3);
    case SYS_write:
        return sys_write(arg1, (const char *)(uintptr_t)arg2, arg3);
    case SYS_close:
        return sys_close(arg1);
    case SYS_ioctl:
        return sys_ioctl(arg1, arg2, (void *)(uintptr_t)arg3);
    case SYS_seek:
        return sys_seek(arg1, arg2, arg3);
    case SYS_fcntl:
        return sys_fcntl(arg1, arg2, (void *)(uintptr_t)arg3);
    default:
        return -1;
    }
    return 0;
}