#include "procfs.h"

#include <memory/heap/kheap.h>
#include <stdio.h>
#include <string.h>
#include <util/macro.h>

#include <errors.h>

#include <cpu.h>

// features
// create the ProcFS (fake) volume
procfs_t *procfs_create() {
    procfs_t *p = kmalloc(sizeof(procfs_t));
    memset(p, 0, sizeof(procfs_t));

    return p;
}

void procfs_destroy_proc(procfs_pcb_t *proc) {
    for (size_t t = 0; t < proc->tcb_count; t++) {
        procfs_tcb_t *thread = proc->tcbs[t];
        if (!thread) {
            continue;
        }
        kfree(thread->tinfo);
        kfree(thread);
    }
    kfree(proc->tcbs);

    kfree(proc->procinfo->data);
    kfree(proc->procinfo);
    kfree(proc);
}

// destroy the ProcFS (stil fake) volume
void procfs_destroy(procfs_t *procfs) {
    for (size_t p = 0; p < procfs->pcb_count; p++) {
        if (!procfs->procs[p]) {
            continue;
        }

        procfs_destroy_proc(procfs->procs[p]);
    }

    kfree(procfs->procs);
    kfree(procfs);
}

void procfs_info_add(procfs_info_t *info, char *buf, size_t offset,
                     size_t size) {
    if (!info) {
        return;
    }

    char *d = info->data; // data

    if (!d) {
        d = kmalloc(ROUND_UP((size + offset) + 1, PROCFS_FILESZ)); // for '\0'
    }

    if (info->size < (offset + size)) {
        d = krealloc(d, ROUND_UP(offset + size, PROCFS_FILESZ));
    }

    memcpy(&d[offset], buf, size);
    d[offset + size] = '\0';

    if (d != info->data) {
        info->data = d;
    }
}

// returns the offset into the file of the FIRST occurrence of `key`
int procfs_info_find(procfs_info_t *info, char *key) {
    if (!info || !info->data) {
        return -1;
    }

    int off = -1;

    char *occ = strstr(info->data, key);
    if (occ) {
        off = ((void *)occ - info->data);
    }

    return off;
}

// return the length of the line of the FIRST occurrence of `key`
int procfs_info_linelen(procfs_info_t *info, char *key) {
    if (!info || !info->data) {
        return -1;
    }

    int offset = procfs_info_find(info, key);

    if (offset < 0) {
        return -1;
    }

    char *buf = info->data;
    int len   = 0;

    while (buf[len + offset] != '\n') {
        len++;
    }

    return (len + 1);
}

void procfs_info_del(procfs_info_t *info, size_t offset, size_t size) {
    if (!info || !info->data) {
        return;
    }

    char *d  = info->data; // data
    size_t s = offset + size;
    if (s > info->size) {
        s = info->size - offset;
    }

    memcpy(&d[offset], &d[offset + size], s);

    s = (offset + size) - info->size;
    memset(&d[size + offset], 0, s);
}

// parse TCB attributes to write to a tinfo file
procfs_info_t *procfs_tinfo_create(tcb_t *tcb) {
    if (!tcb) {
        return NULL;
    }

    // should be enough for a single line
    char *buf = kmalloc(100);
    memset(buf, 0, 100);

    procfs_info_t *tinfo = kmalloc(sizeof(procfs_info_t));
    memset(tinfo, 0, sizeof(procfs_info_t));

    // this is veeeery wacky

    // flags
    snprintf(buf, 100, "TF_USER::%d\n", (tcb->flags & TF_MODE_USER) ? 1 : 0);
    procfs_info_add(tinfo, buf, 0, strlen(buf));
    int offset = procfs_info_linelen(tinfo, buf);

    snprintf(buf, 100, "TF_BUSY::%d\n", (tcb->flags & TF_BUSY) ? 1 : 0);
    procfs_info_add(tinfo, buf, offset, strlen(buf));
    offset += procfs_info_linelen(tinfo, buf);

    snprintf(buf, 100, "TF_DETACHED::%d\n", (tcb->flags & TF_DETACHED) ? 1 : 0);
    procfs_info_add(tinfo, buf, offset, strlen(buf));
    offset += procfs_info_linelen(tinfo, buf);

    // entry point (suppose we are called first on process creation)
    snprintf(buf, 100, "ENTRY::%016llx\n", tcb->regs->rip);
    procfs_info_add(tinfo, buf, offset, strlen(buf));
    offset += procfs_info_linelen(tinfo, buf);

    // stack
    snprintf(buf, 100, "STACK::%016llx\n", tcb->regs->rbp);
    procfs_info_add(tinfo, buf, offset, strlen(buf));
    offset += procfs_info_linelen(tinfo, buf);

    tinfo->size = strlen(tinfo->data);

    return tinfo;
}

// parse PCB attributes to write to a procinfo file
procfs_info_t *procfs_procinfo_create(pcb_t *pcb) {
    if (!pcb) {
        return NULL;
    }

    // should be enough for a single line
    char *buf = kmalloc(100);
    memset(buf, 0, 100);

    procfs_info_t *procinfo = kmalloc(sizeof(procfs_info_t));
    memset(procinfo, 0, sizeof(procfs_info_t));

    // fd count
    snprintf(buf, 100, "FD_COUNT::%d\n", pcb->fd_count);
    procfs_info_add(procinfo, buf, 0, strlen(buf) + 1);
    int offset = procfs_info_linelen(procinfo, buf);

    // tcb count
    snprintf(buf, 100, "TCB_COUNT::%d\n", pcb->thread_count);
    procfs_info_add(procinfo, buf, offset, strlen(buf) + 1);
    offset += procfs_info_linelen(procinfo, buf);

    // cpu where is currently running
    snprintf(buf, 100, "CURRENT_CPU::%d\n", get_current_cpu());
    procfs_info_add(procinfo, buf, offset, strlen(buf) + 1);
    offset += procfs_info_linelen(procinfo, buf);

    // signal handler? (later)

    procinfo->size = strlen(procinfo->data);
    return procinfo;
}

// create a ProcFS tid_file (/proc/1/2)
procfs_tcb_t *procfs_thread_create(tcb_t *tcb) {
    if (!tcb) {
        return NULL;
    }

    procfs_tcb_t *procfs_tcb = kmalloc(sizeof(procfs_tcb_t));
    memset(procfs_tcb, 0, sizeof(procfs_tcb_t));

    procfs_tcb->tid = tcb->tid;
    procfs_tcb->tcb = tcb;

    // tinfo file
    procfs_info_t *tinfo = procfs_tinfo_create(tcb);
    procfs_tcb->tinfo    = tinfo;

    return procfs_tcb;
}

// create a ProcFS pid_file (eg. /proc/1)
procfs_pcb_t *procfs_proc_create(pcb_t *pcb) {
    if (!pcb) {
        return NULL;
    }

    procfs_pcb_t *procfs_pcb = kmalloc(sizeof(procfs_pcb_t));
    memset(procfs_pcb, 0, sizeof(procfs_pcb));

    // copy PCB info to structure
    procfs_pcb->pcb = pcb;
    procfs_pcb->pid = pcb->pid;
    // TODO: exec

    // procinfo file
    procfs_pcb->procinfo = procfs_procinfo_create(pcb);

    procfs_pcb->tcb_count = pcb->thread_count;
    procfs_pcb->tcbs = kcalloc(procfs_pcb->tcb_count, sizeof(procfs_tcb_t *));

    // create every single thread file
    for (size_t i = 0; i < procfs_pcb->tcb_count; i++) {
        procfs_pcb->tcbs[i] = procfs_thread_create(pcb->threads[i]);
    }

    return procfs_pcb;
}

void procfs_proc_append(procfs_t *procfs, procfs_pcb_t *proc) {
    if (!procfs || !proc) {
        return;
    }

    procfs->procs                        = krealloc(procfs->procs,
                                                    (sizeof(procfs_pcb_t *) * (++procfs->pcb_count)));
    procfs->procs[procfs->pcb_count - 1] = proc;
}

void procfs_proc_remove(procfs_t *procfs, int pid) {
    if (!procfs || !procfs->procs) {
        return;
    }

    for (int i = 0; i < procfs->pcb_count; i++) {
        if (!procfs->procs[i] || procfs->procs[i]->pid != pid) {
            continue;
        }

        procfs_destroy_proc(procfs->procs[i]);
        procfs->procs[i] = NULL;

        if (i == (procfs->pcb_count - 1)) {
            procfs->procs =
                krealloc(procfs->procs, (sizeof(procfs_pcb_t *) * i));
            procfs->pcb_count = i;
        }
    }
}

// find the pid given the procFS
procfs_pcb_t *procfs_find_proc(procfs_t *procfs, int pid) {
    if (!procfs || pid < 0) {
        return NULL;
    }

    for (size_t i = 0; i < procfs->pcb_count; i++) {
        if (procfs->procs[i] && procfs->procs[i]->pid == pid) {
            return procfs->procs[i];
        }
    }

    return NULL;
}

// find the tid given the procFS
procfs_tcb_t *procfs_find_thread(procfs_t *procfs, int pid, int tid) {
    if (!procfs || pid < 0 || tid < 0) {
        return NULL;
    }

    procfs_pcb_t *proc = procfs_find_proc(procfs, pid);

    if (!proc) {
        return NULL;
    }

    for (size_t i = 0; i < proc->tcb_count; i++) {
        if (proc->tcbs[i] && proc->tcbs[i]->tid == tid) {
            return proc->tcbs[i];
        }
    }

    return NULL;
}

// find the tid given the procFS FILE
procfs_tcb_t *procfs_find_thread_from_proc(procfs_pcb_t *proc, int tid) {
    if (!proc || tid < 0) {
        return NULL;
    }

    for (size_t i = 0; i < proc->tcb_count; i++) {
        if (proc->tcbs[i] && proc->tcbs[i]->tid == tid) {
            return proc->tcbs[i];
        }
    }

    return NULL;
}

// /proc/p can contain many files
// /proc/p/t SHOULD contain only the tinfo tile

// find a file INSIDE a /proc/p "dir"
void *procfs_find_in_proc(procfs_pcb_t *proc, char *file, int *ftype) {
    if (!proc || !file) {
        return NULL;
    }

    void *f = NULL;

    // bunch of file names
    if (strcmp(file, PROCFS_FNAME_PROCINFO) == 0) {
        *ftype = PROCFS_FILE_INFO;
        f      = proc->procinfo;
    } else if (strcmp(file, PROCFS_FNAME_FDS) == 0) {
        *ftype = PROCFS_FILE_FDS;
        f      = proc->pcb->fds;
    } else {
        int tid = atoi(file);

        f      = procfs_find_thread_from_proc(proc, tid);
        *ftype = PROCFS_FILE_THREAD;
    }

    return f;
}

// ProcFS path parsing
// eg.      /proc/1 would return that the path points to a proc file
//          /proc/1/4/tinfo returns the tinfo file
//          /proc/self should return the current process

// @param ftype we will write the file type we found with the given path
// cuz we are returning a void*
void *procfs_find(procfs_t *procfs, char *path, int *ftype) {
    if (!procfs || !path || !ftype) {
        return NULL;
    }

    // ye
    if (strncmp(path, "/proc/", strlen("/proc/")) == 0) {
        path += strlen("/proc/");
    }

    char *name_dup = strdup(path);
    char *temp     = name_dup;
    char *file;

    void *f = NULL;
    int pid;
    procfs_pcb_t *proc = NULL;
    int tid;

    // i -> depth into the FS
    // 0 -> we are in the procFS root
    // 1 -> we are in a pid file
    // 2 -> we are in a thread file
    // anything else is illegal :3c
    for (int i = 0; *temp; i++) {
        file = strtok_r(NULL, "/", &temp);

        switch (i) {
        case 0:
            // there are only PIDs or the /self in the procFS root
            if (strcmp(file, "self") == 0) {
                pcb_t *p = get_current_pcb();
                proc     = procfs_find_proc(procfs, p->pid);
            } else {
                pid  = atoi(file);
                proc = procfs_find_proc(procfs, pid);
            }

            if (!(*temp)) {
                *ftype = PROCFS_FILE_PROC;
                return proc;
            }
            break;

        case 1:
            // inside /proc/p there are many files
            f = procfs_find_in_proc(proc, file, ftype);

            if (!(*temp)) {
                return f;
            }

        case 2:
            // there's only the tinfo file (for now)
            procfs_tcb_t *tcb = f;

            return tcb->tinfo;

        default:
            debugf_panic("WHY ARE WE HERE LOL\n");
            break;
        }
    }

    return f;
}

size_t procfs_get_node_size(procfs_vnode_t *pvnode) {
    if (!pvnode) {
        return 0;
    }

    size_t s = 0;

    switch (pvnode->type) {
    case PROCFS_FILE_INFO:
        s = ((procfs_info_t *)pvnode->file)->size;
        break;

    default:
        break;
    }
}

void *procfs_get_node_buf(procfs_vnode_t *pvnode) {
    if (!pvnode) {
        return NULL;
    }

    void *p = NULL;

    switch (pvnode->type) {
    case PROCFS_FILE_INFO:
        p = ((procfs_info_t *)pvnode->file)->data;
        break;

    default:
        break;
    }
}

// vnode functions (open, read, write, close)

int procfs_open(vnode_t **vout, int flags, bool clone, fileio_t **fout) {
    UNUSED(clone); // TODO: use the clone :kekw:

    if (!vout || !(*vout)) {
        return ENULLPTR;
    }

    vnode_t *vnode   = *vout;
    procfs_t *procfs = vnode->root_vfs->vfs_data;

    // find procfs file
    int ftype;
    void *file = procfs_find(procfs, vnode->path, &ftype);
    if (!file) {
        // we won't create the file :3
        return ENOENT;
    }

    procfs_vnode_t *pvnode = kmalloc(sizeof(procfs_vnode_t));
    memset(pvnode, 0, sizeof(procfs_vnode_t));
    pvnode->file = file;
    pvnode->type = ftype;

    vnode->node_data = pvnode;

    // create fio_t struct
    fileio_t *fio = *fout;
    if (!fout || !fio) {
        return ENULLPTR;
    }

    fio->buf_start = procfs_get_node_buf(pvnode);
    fio->size      = procfs_get_node_size(pvnode);
    fio->private   = vnode;

    return EOK;
}

int procfs_read(vnode_t *vnode, size_t *size, size_t *offset, void *out) {
    // depends on the file

    if (!vnode) {
        return -ENULLPTR;
    }

    memset(out, 0, (*size));

    procfs_vnode_t *pvnode = vnode->node_data;
    void *buf              = procfs_get_node_buf(pvnode);
    size_t buf_size        = procfs_get_node_size(pvnode);

    if ((*size) > buf_size) {
        (*size) = buf_size;
    } else if ((*offset) >= buf_size) {
        return EINVAL;
    }

    if ((*size) + (*offset) > buf_size) {
        // read whatever remains that can be copied
        (*size) = (buf_size - (*offset));
    }

    void *src = buf + (*offset);

    memcpy(out, src, (*size));

    return EOK;
}

int procfs_write(vnode_t *vnode, void *buf, size_t *size, size_t *offset) {
    UNUSED(vnode);
    UNUSED(buf);
    UNUSED(size);
    UNUSED(offset);

    debugf("STOP! YOU VIOLATED THE LAW!\n");
    return EACCES;
}

int procfs_close(vnode_t *vnode, int flags, bool clone) {
    UNUSED(flags);
    UNUSED(clone);

    if (!vnode) {
        return ENULLPTR;
    }

    procfs_vnode_t *pvnode = vnode->node_data;
    if (!pvnode) {
        return ENULLPTR;
    }

    // get rid of the RAMFS node on vnode
    kfree(vnode->node_data);
    vnode->node_data = NULL;

    return EOK;
}

int procfs_ioctl(vnode_t *vnode, int request, void *arg) {
    if (!vnode) {
        return ENULLPTR;
    }

    UNUSED(request);
    UNUSED(arg);

    return ENOIMPL;
}

struct vnode_ops procfs_vnops = {.open  = procfs_open,
                                 .close = procfs_close,
                                 .read  = procfs_read,
                                 .write = procfs_write,
                                 .ioctl = procfs_ioctl};

// vfs functions

int procfs_vfs_init(procfs_t *procfs, char *path) {
    if (!procfs || !path) {
        return ENULLPTR;
    }

    vfs_t *vfs = vfs_mount(procfs, VFS_PROCFS, path, procfs);
    memcpy(vfs->root_vnode->ops, &procfs_vnops, sizeof(vnops_t));

    return 0;
}

// test function ^)
void procfs_print(procfs_t *procfs) {
    if (!procfs) {
        return;
    }

    for (int i = 0; i < procfs->pcb_count; i++) {
        procfs_pcb_t *p = procfs->procs[i];
        if (p) {
            kprintf("|- %d\n", p->pid);
            for (int j = 0; j < p->tcb_count; j++) {
                procfs_tcb_t *t = p->tcbs[j];
                if (t) {
                    kprintf("|\t|- %d\n", j);
                    kprintf("|\t|  |_ tinfo\n");
                }
            }
            if (p->pcb->fds) {
                kprintf("|\t|-fds\n");
                for (int j = 0; j < p->pcb->fd_count; j++) {
                    kprintf("|\t  |- %d[%p]\n", j, p->pcb->fds[j]);
                }
            }
            kprintf("|\t|_procinfo\n");
        }
    }
}