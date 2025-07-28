#ifndef SCHEDULER_H
#define SCHEDULER_H 1

// #include <fs/vfs/vfs.h>
#include <interrupts/isr.h>

#include <limits.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <types.h>

#define SCHED_PROC_USER            0x01
#define SCHED_PROC_KERNEL_PAGE_MAP 0x02
#define SCHED_PROC_KERNEL_STACK    0x04

typedef enum proc_state {
    PROC_STATE_READY,
    PROC_STATE_RUNNING,
    PROC_STATE_STOPPED
} proc_state_t;

typedef struct proc {
    pid_t pid;

    struct {
        uid_t user;
        gid_t group;
    } whoami;

    registers_t regs;
    uint64_t *pml4;

    uint64_t time_slice;
    int sched_flags;

    fd_t current_fd;
    // fs_open_file_t **fd_table;

    int errno;
    proc_state_t state;

    uint8_t current_core;
    uint8_t preferred_core;
    struct proc *next;
} proc_t;

typedef struct core_scheduler {
    uint8_t core_id;
    proc_t *current_proc;
    proc_t *idle_proc;

    proc_t *run_queue_head;
    proc_t *run_queue_tail;
    size_t run_queue_size;

    uint64_t context_switches;
    uint64_t last_schedule_time;

    uint32_t flags;
    uint64_t default_time_slice;

    lock_t lock;
} core_scheduler_t;

typedef struct scheduler_manager {
    core_scheduler_t **core_schedulers;
    size_t core_count;

    proc_t *process_list_head;
    size_t process_count;

    pid_t next_pid;

    uint64_t load_balance_interval;
    uint64_t last_load_balance;

    lock_t glob_lock;
} scheduler_manager_t;

extern scheduler_manager_t *scheduler_manager;

void scheduler_init();
void scheduler_init_cpu(uint8_t core);

proc_t *scheduler_add(void (*entry_point)(), int flags);
void scheduler_remove(proc_t *proc);

proc_t *get_current_process();
void scheduler_switch_context(proc_t *proc, registers_t *current_regs);

void scheduler_schedule(void *ctx);

#define PROC_TIME_SLICE 10

#endif
