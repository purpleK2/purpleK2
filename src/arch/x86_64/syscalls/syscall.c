#include "syscall.h"
#include "cpu.h"
#include "stdio.h"
#include "user/user.h"

#include <fs/file_io.h>
#include <fs/vfs/vfs.h>
#include <scheduler/scheduler.h>

#include <memory/heap/kheap.h>

#include <stdint.h>
#include <string.h>
#include <util/macro.h>

void sys_exit(int status, registers_t *ctx) {

    proc_exit(status);
    yield(ctx);
}

int sys_open(char *path, int flags, mode_t mode) {
    pcb_t *current = get_current_pcb();

    if (!path || !current) {
        return -1;
    }

    current->fds =
        krealloc(current->fds, sizeof(fileio_t *) * (++current->fd_count));

    current->fds[current->fd_count - 1] = open(path, flags, mode); // TODO: get flags
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

    if (fd == current->fd_count - 1) {
        current->fds =
            krealloc(current->fds, sizeof(fileio_t *) * (--current->fd_count));
    }

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

int sys_dup(int fd) {
    pcb_t *current = get_current_pcb();
    if (fd < 0 || fd >= current->fd_count) {
        return -1;
    }

    fileio_t *file = current->fds[fd];

    fileio_t *new_file = kmalloc(sizeof(fileio_t));
    memcpy(new_file, file, sizeof(fileio_t));

    current->fds =
        krealloc(current->fds, sizeof(fileio_t *) * (++current->fd_count));

    current->fds[current->fd_count - 1] = new_file;
    if (current->fds[current->fd_count - 1] == NULL) {
        return -1;
    }

    return current->fd_count - 1;
}

int sys_getpid(void) {
    pcb_t *current = get_current_pcb();
    if (!current) {
        return -1;
    }
    return current->pid;
}

int sys_getuid(void)  { return get_current_cred()->uid; }
int sys_geteuid(void) { return get_current_cred()->euid; }
int sys_getgid(void)  { return get_current_cred()->gid; }
int sys_getegid(void) { return get_current_cred()->egid; }

int sys_getresuid(uid_t *ruid, uid_t *euid, uid_t *suid) {
    user_cred_t *c = get_current_cred();
    if (!ruid || !euid || !suid) return -1;
    *ruid = c->uid;
    *euid = c->euid;
    *suid = c->suid;
    return 0;
}

int sys_getresgid(gid_t *rgid, gid_t *egid, gid_t *sgid) {
    user_cred_t *c = get_current_cred();
    if (!rgid || !egid || !sgid) return -1;
    *rgid = c->gid;
    *egid = c->egid;
    *sgid = c->sgid;
    return 0;
}

int sys_setuid(uid_t uid) {
    user_cred_t *c = get_current_cred();

    if (is_privileged()) {
        c->uid  = uid;
        c->euid = uid;
        c->suid = uid;
        return 0;
    }

    if (uid == c->uid || uid == c->suid) {
        c->euid = uid;
        return 0;
    }

    return -1;
}

int sys_seteuid(uid_t euid) {
    user_cred_t *c = get_current_cred();

    if (is_privileged() ||
        euid == c->uid ||
        euid == c->suid) {
        c->euid = euid;
        return 0;
    }

    return -1;
}

int sys_setreuid(uid_t ruid, uid_t euid) {
    user_cred_t *c = get_current_cred();

    if (!is_privileged()) {
        if ((ruid != (uid_t)-1 &&
             ruid != c->uid &&
             ruid != c->euid) ||
            (euid != (uid_t)-1 &&
             euid != c->uid &&
             euid != c->euid &&
             euid != c->suid))
            return -1;
    }

    if (ruid != (uid_t)-1)
        c->uid = ruid;
    if (euid != (uid_t)-1)
        c->euid = euid;

    if (ruid != (uid_t)-1 || euid != (uid_t)-1)
        c->suid = c->euid;

    return 0;
}

int sys_setresuid(uid_t ruid, uid_t euid, uid_t suid) {
    user_cred_t *c = get_current_cred();

    if (!is_privileged()) {
        if ((ruid != (uid_t)-1 &&
             ruid != c->uid &&
             ruid != c->euid &&
             ruid != c->suid) ||
            (euid != (uid_t)-1 &&
             euid != c->uid &&
             euid != c->euid &&
             euid != c->suid) ||
            (suid != (uid_t)-1 &&
             suid != c->uid &&
             suid != c->euid &&
             suid != c->suid))
            return -1;
    }

    if (ruid != (uid_t)-1) c->uid  = ruid;
    if (euid != (uid_t)-1) c->euid = euid;
    if (suid != (uid_t)-1) c->suid = suid;

    return 0;
}

int sys_setgid(gid_t gid) {
    user_cred_t *c = get_current_cred();

    if (is_privileged()) {
        c->gid  = gid;
        c->egid = gid;
        c->sgid = gid;
        return 0;
    }

    if (gid == c->gid || gid == c->sgid) {
        c->egid = gid;
        return 0;
    }

    return -1;
}

int sys_setegid(gid_t egid) {
    user_cred_t *c = get_current_cred();

    if (is_privileged() ||
        egid == c->gid ||
        egid == c->sgid) {
        c->egid = egid;
        return 0;
    }

    return -1;
}

int sys_setregid(gid_t rgid, gid_t egid) {
    user_cred_t *c = get_current_cred();

    if (!is_privileged()) {
        if ((rgid != (gid_t)-1 &&
             rgid != c->gid &&
             rgid != c->egid) ||
            (egid != (gid_t)-1 &&
             egid != c->gid &&
             egid != c->egid &&
             egid != c->sgid))
            return -1;
    }

    if (rgid != (gid_t)-1)
        c->gid = rgid;
    if (egid != (gid_t)-1)
        c->egid = egid;

    if (rgid != (gid_t)-1 || egid != (gid_t)-1)
        c->sgid = c->egid;

    return 0;
}

int sys_setresgid(gid_t rgid, gid_t egid, gid_t sgid) {
    user_cred_t *c = get_current_cred();

    if (!is_privileged()) {
        if ((rgid != (gid_t)-1 &&
             rgid != c->gid &&
             rgid != c->egid &&
             rgid != c->sgid) ||
            (egid != (gid_t)-1 &&
             egid != c->gid &&
             egid != c->egid &&
             egid != c->sgid) ||
            (sgid != (gid_t)-1 &&
             sgid != c->gid &&
             sgid != c->egid &&
             sgid != c->sgid))
            return -1;
    }

    if (rgid != (gid_t)-1) c->gid  = rgid;
    if (egid != (gid_t)-1) c->egid = egid;
    if (sgid != (gid_t)-1) c->sgid = sgid;

    return 0;
}

long handle_syscall(registers_t *ctx) {
    long num = ctx->rax;
    long arg1        = ctx->rdi;
    long arg2        = ctx->rsi;
    long arg3        = ctx->rdx;
    long arg4        = ctx->r8;
    long arg5        = ctx->r9;
    long arg6        = ctx->r10;

    UNUSED(arg4);
    UNUSED(arg5);
    UNUSED(arg6);
    switch (num) {
    case SYS_exit:
        sys_exit(arg1, ctx);
        break;
    case SYS_open:
        return sys_open((char *)(uintptr_t)arg1, arg2, (mode_t)arg3);
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
    case SYS_dup:
        return sys_dup(arg1);
    case SYS_getpid:
        return sys_getpid();
    case SYS_getuid:
        return sys_getuid();
    case SYS_geteuid:
        return sys_geteuid();
    case SYS_getgid:
        return sys_getgid();
    case SYS_getegid:
        return sys_getegid();
    case SYS_setuid:
        return sys_setuid((uid_t)arg1);
    case SYS_seteuid:
        return sys_seteuid((uid_t)arg1);
    case SYS_setreuid:
        return sys_setreuid((uid_t)arg1, (uid_t)arg2);
    case SYS_setresuid:
        return sys_setresuid((uid_t)arg1, (uid_t)arg2, (uid_t)arg3);
    case SYS_getresuid:
        return sys_getresuid(
            (uid_t *)(uintptr_t)arg1,
            (uid_t *)(uintptr_t)arg2,
            (uid_t *)(uintptr_t)arg3
        );

    case SYS_setgid:
        return sys_setgid((gid_t)arg1);
    case SYS_setegid:
        return sys_setegid((gid_t)arg1);
    case SYS_setregid:
        return sys_setregid((gid_t)arg1, (gid_t)arg2);
    case SYS_setresgid:
        return sys_setresgid((gid_t)arg1, (gid_t)arg2, (gid_t)arg3);
    case SYS_getresgid:
        return sys_getresgid(
            (gid_t *)(uintptr_t)arg1,
            (gid_t *)(uintptr_t)arg2,
            (gid_t *)(uintptr_t)arg3
        );

    default:
        return -1;
    }
    return 0;
}