#include "syscall.h"
#include "cpu.h"
#include "user/user.h"
#include "uaccess.h"

#include <fs/file_io.h>
#include <fs/vfs/vfs.h>
#include <scheduler/scheduler.h>

#include <memory/heap/kheap.h>

#include <stdint.h>
#include <string.h>
#include <util/macro.h>

static registers_t *current_syscall_ctx[256];

void set_syscall_context(registers_t *ctx) {
    current_syscall_ctx[get_current_cpu()] = ctx;
}

registers_t *get_syscall_context(void) {
    return current_syscall_ctx[get_current_cpu()];
}

void sys_exit(int status) {
    registers_t *ctx = get_syscall_context();
    proc_exit(status);
    yield(ctx);
}

int sys_open(const char __user *path, int flags, mode_t mode) {
    pcb_t *current = get_current_pcb();

    if (!path || !current) {
        return -1;
    }

    char kpath[4096];
    if (copy_from_user(kpath, path, sizeof(kpath)) != 0) {
        return -1;
    }
    kpath[sizeof(kpath) - 1] = '\0'; // Ensure null termination

    current->fds =
        krealloc(current->fds, sizeof(fileio_t *) * (++current->fd_count));

    current->fds[current->fd_count - 1] = open(kpath, flags, mode);
    if (current->fds[current->fd_count - 1] == NULL) {
        return -1;
    }

    return current->fd_count - 1;
}

int sys_read(int fd, char __user *buf, int count) {
    pcb_t *current = get_current_pcb();

    if (fd < 0 || fd >= current->fd_count || !buf || count <= 0) {
        return -1;
    }

    fileio_t *file = current->fds[fd];
    if (!file) {
        return -1;
    }

    char *kbuf = kmalloc(count);
    if (!kbuf) {
        return -1;
    }

    int bytes_read = read(file, count, kbuf);
    if (bytes_read < 0) {
        kfree(kbuf);
        return -1;
    }

    if (copy_to_user(buf, kbuf, bytes_read) != 0) {
        kfree(kbuf);
        return -1;
    }

    kfree(kbuf);
    return bytes_read;
}

int sys_write(int fd, const char __user *buf, int count) {
    pcb_t *current = get_current_pcb();

    if (fd < 0 || fd >= current->fd_count || !buf || count <= 0) {
        return -1;
    }

    fileio_t *file = current->fds[fd];
    if (!file) {
        return -1;
    }

    char *kbuf = kmalloc(count);
    if (!kbuf) {
        return -1;
    }

    if (copy_from_user(kbuf, buf, count) != 0) {
        kfree(kbuf);
        return -1;
    }

    int bytes_written = write(file, kbuf, count);
    kfree(kbuf);
    return bytes_written;
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

int sys_fork(void) {
    registers_t *ctx = get_syscall_context();
    if (!ctx) {
        return -1;
    }

    int child_pid = proc_fork(ctx);

    if (child_pid < 0) {
        return -1;
    }
 
    ctx->rax = child_pid;
    return child_pid;
}

int sys_getuid(void)  { return get_current_cred()->uid; }
int sys_geteuid(void) { return get_current_cred()->euid; }
int sys_getgid(void)  { return get_current_cred()->gid; }
int sys_getegid(void) { return get_current_cred()->egid; }

int sys_getresuid(uid_t __user *ruid, uid_t __user *euid, uid_t __user *suid) {
    user_cred_t *c = get_current_cred();
    if (!ruid || !euid || !suid) return -1;

    if (copy_to_user(ruid, &c->uid, sizeof(uid_t)) != 0)
        return -1;
    if (copy_to_user(euid, &c->euid, sizeof(uid_t)) != 0)
        return -1;
    if (copy_to_user(suid, &c->suid, sizeof(uid_t)) != 0)
        return -1;

    return 0;
}

int sys_getresgid(gid_t __user *rgid, gid_t __user *egid, gid_t __user *sgid) {
    user_cred_t *c = get_current_cred();
    if (!rgid || !egid || !sgid) return -1;

    if (copy_to_user(rgid, &c->gid, sizeof(gid_t)) != 0)
        return -1;
    if (copy_to_user(egid, &c->egid, sizeof(gid_t)) != 0)
        return -1;
    if (copy_to_user(sgid, &c->sgid, sizeof(gid_t)) != 0)
        return -1;

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

void* syscall_table[] = {
    (void*)sys_exit,
    (void*)sys_open,
    (void*)sys_read,
    (void*)sys_write,
    (void*)sys_close,
    (void*)sys_ioctl,
    (void*)sys_seek,
    (void*)sys_fcntl,
    (void*)sys_dup,
    (void*)sys_getpid,
    (void*)sys_getuid,
    (void*)sys_geteuid,
    (void*)sys_getgid,
    (void*)sys_getegid,
    (void*)sys_setuid,
    (void*)sys_seteuid,
    (void*)sys_setreuid,
    (void*)sys_setresuid,
    (void*)sys_getresuid,
    (void*)sys_setgid,
    (void*)sys_setegid,
    (void*)sys_setregid,
    (void*)sys_setresgid,
    (void*)sys_getresgid,
    (void*)sys_fork
};