#ifndef PROCFS_H
#define PROCFS_H 1

#include <fs/vfs/vfs.h>
#include <scheduler/scheduler.h>

#include <stdbool.h>
#include <stddef.h>

#define PROCFS_FNAME_PROCINFO "procinfo"
#define PROCFS_FNAME_TINFO    "tinfo"
#define PROCFS_FNAME_FDS      "fds"

// idea: each file is going to be a multiple of 512 bytes :bigbrain:
#define PROCFS_FILESZ 512

#define PROCFS_INFO_BUFSZ 100

/*
    procFS implementation for purpleK2

    Designed by NotNekodev
    Implementation by Omar
*/

typedef enum procfs_vfs_ftype {
    PROCFS_FILE_PROC,
    PROCFS_FILE_THREAD,
    PROCFS_FILE_INFO, // procinfo and tinfo are all the same struct
    PROCFS_FILE_FDS,  // file descriptors
} procfs_vftype_t;

// the tinfo/procinfo file
/*
    Format of the file
    value::key
*/
typedef struct procfs_info {
    size_t size;
    void *data;
} procfs_info_t;

typedef struct procfs_thread {
    uint64_t tid;
    tcb_t *tcb; // the thread we're talking about

    procfs_info_t *tinfo;
} procfs_tcb_t;

typedef struct procfs_process {
    uint64_t pid;
    pcb_t *pcb; // the process we're talking about

    procfs_info_t *procinfo;
    void *exec; // should it be a void* ?

    size_t tcb_count;
    procfs_tcb_t **tcbs;
} procfs_pcb_t;

// "the disk formatted in procFS"
typedef struct procfs {
    procfs_pcb_t **procs;
    size_t pcb_count;
} procfs_t;

// the procFS node that will be attached to the vnode
typedef struct procfs_vnode {
    void *file; // points to one of the structs above
    procfs_vftype_t type;
} procfs_vnode_t;

procfs_t *procfs_create();
void procfs_destroy(procfs_t *procfs);

void procfs_info_add(procfs_info_t *info, char *buf, size_t offset,
                     size_t size);
void procfs_info_del(procfs_info_t *info, size_t offset, size_t size);

int procfs_info_find(procfs_info_t *info, char *key);
int procfs_info_linelen(procfs_info_t *info, char *key);

procfs_info_t *procfs_tinfo_create(tcb_t *tcb);
procfs_info_t *procfs_procinfo_create(pcb_t *pcb);

procfs_tcb_t *procfs_thread_create(tcb_t *tcb);
procfs_pcb_t *procfs_proc_create(pcb_t *pcb);

void procfs_proc_append(procfs_t *procfs, procfs_pcb_t *proc);

procfs_pcb_t *procfs_find_proc(procfs_t *procfs, int pid);
procfs_tcb_t *procfs_find_thread(procfs_t *procfs, int pid, int tid);

void *procfs_find(procfs_t *procfs, char *path, int *ftype);

int procfs_open(vnode_t **vout, int flags, bool clone, fileio_t **fout);
int procfs_read(vnode_t *vnode, size_t *size, size_t *offset, void *out);
int procfs_write(vnode_t *vnode, void *buf, size_t *size, size_t *offset);
int procfs_close(vnode_t *vnode, int flags, bool clone);
int procfs_ioctl(vnode_t *vnode, int request, void *arg);

int procfs_vfs_init(procfs_t *procfs, char *path);

void procfs_print(procfs_t *procfs);

#endif