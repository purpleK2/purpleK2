#ifndef SCHEDULER_H
#define SCHEDULER_H

#include <fs/file_io.h>
#include <interrupts/isr.h>
#include <memory/vmm/vmm.h>
#include <scheduler/signals.h>

#include <types.h>

// Time Slice, not that "ts"
#define SCHEDULER_THREAD_TS 10

#define SCHEDULER_STACK_PAGES 2
// keeping this just in case
#define SCHEDULER_STACKSZ (PFRAME_SIZE * SCHEDULER_STACK_PAGES)

#define TF_MODE_USER (1 << 0)
#define TF_BUSY      (1 << 1)
#define TF_DETACHED  (1 << 2)

#define TIME_SLICE_TICKS 10

typedef struct task_context {
    uint64_t r15, r14, r13, r12, r11, r10, r9, r8;
    uint64_t rsi, rdi, rbp, rdx, rcx, rbx, rax;
    uint64_t rip, cs, rflags, rsp, ss;

    void *fpu; // 512 bytes memory region
} task_regs_t;

typedef enum pcb_state {
    PROC_NEW,
    PROC_READY,
    PROC_RUNNING,
    PROC_WAIT_FOR_THREAD,
    PROC_DEAD,
} pcb_state_t;

typedef enum tcb_state {
    THREAD_NEW,     // useful for handling the stack on yield()
    THREAD_READY,   // good to go
    THREAD_RUNNING, // should be only one per CPU
    THREAD_WAITING, // I/O, syscall, ...
    THREAD_DEAD,
} tcb_state_t;

typedef struct process pcb_t;
typedef struct thread tcb_t;

typedef struct thread {
    int tid;
    struct process *parent;

    size_t time_slice;

    tcb_state_t state;
    int flags;

    task_regs_t *regs;

    lock_t lock;

    struct thread *next;

    // TODO: thread-local storage
} tcb_t;

typedef struct process {
    int pid;

    struct process *parent;
    int children_count; // diddy really likes this value >:)
    struct process **children;

    pcb_state_t state;

    int thread_count;
    tcb_t **threads;
    tcb_t *main_thread;

    int fd_count;
    fileio_t **fds;
    fileio_t *cwd; // just in case: Current Working Directory

    int cpu; // the cpu we're running on

    vmm_context_t *vmm_ctx;

    struct owner {
        int gid;
        int uid;
    } owner;

    void (*signal_handler)(int);
} pcb_t;

typedef struct cpu_thread_queue {
    size_t count;
    tcb_t *head;
} cpu_queue_t;

/* from arch/[TARGET]/scheduler.asm */
extern void context_load(task_regs_t *ctx);
extern void context_save(task_regs_t *out);
extern void fpu_save(void *ctx);
extern void fpu_restore(void *ctx);
extern __attribute__((noreturn)) void scheduler_idle();

int pcb_destroy(int pid);
int thread_destroy(int pid, int tid);
int proc_exit();

// inits the scheduler on every CPU
// with an "init" process
int init_scheduler(void (*p)());
/*
    the "init" function is a custom function
    that the developer can assign it to:
    a simple idle function, an initialization function (that will be called for
    every CPU), whatever.
*/

int init_cpu_scheduler(int cpu,
                       void (*p)()); // inits the scheduler for a specific CPU
                                     // with a custom process and a thread queue

int proc_create(void (*entry)(), int flags);
int thread_create(pcb_t *parent, void (*entry)(), int flags);
int pcb_destroy(int pid);
pcb_t *get_current_pcb();
int thread_destroy(int pid, int tid);

void yield(); // gets called by the lapic timer on each cpu

#endif // SCHEDULER_H
