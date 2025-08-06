#ifndef SCHEDULER_H
#define SCHEDULER_H

#include <fs/file_io.h>
#include <interrupts/isr.h>
#include <memory/vmm/vmm.h>
#include <scheduler/signals.h>

#include <system/limits.h>
#include <types.h>

#define TF_MODE_USER 0x1
#define TF_BUSY      0x2
#define TF_DETACHED  0x4

#define TIME_SLICE_TICKS 10
#define MAX_CPUS         64

struct PCB;
struct TCB;

typedef struct TaskContext {
    uint64_t r15, r14, r13, r12, r11, r10, r9, r8;
    uint64_t rsi, rdi, rbp, rbx, rdx, rcx, rax;
    uint64_t rip, cs, rflags, rsp, ss;
} TaskContext;

typedef struct ThreadQueue {
    struct TCB *idle_proc;

    struct TCB *head;
    int count;
} ThreadQueue_t;

typedef enum PCB_State {
    PROC_RUNNING         = 0x0,
    PROC_STARTABLE       = 0x1,
    PROC_WAIT_FOR_THREAD = 0x2,
    PROC_DEAD            = 0x3,
} PCB_State_t;

typedef enum TCB_State {
    THREAD_RUNNING   = 0x0,
    THREAD_STARTABLE = 0x1,
    THREAD_WAITING   = 0x2,
    THREAD_DEAD      = 0x3,
} TCB_State_t;

struct KernelStack {
    uint8_t stack[SCHED_KSTACK_SIZE];
};

typedef struct TCB {
    int tid;
    TaskContext *ctx;
    struct PCB *parent;

    void *entry_point;
    TCB_State_t state;

    struct KernelStack *stack;
    void *tls;

    int signal_mask;
    int flags;

    lock_t lock;

    struct TCB *next;
} TCB_t;

typedef struct PCB {
    int pid;

    int tid_counter;
    int fd_counter;

    struct file_io *fds[SCHED_MAX_FD_CNT];
    struct file_io *cwd;

    int cpu; // the cpu the thread is running on

    TCB_t *threads[SCHED_MAX_THREAD_CNT]; // threads[0] = main_thread;

    vmm_context_t *pagemap;

    struct SigHandler signal_handlers[SIGCNT];

    lock_t lock;
    int flags;

    PCB_State_t state;

    struct PCB *parent; // Null if no parent
    struct PCB **children;
    int child_count; // diddy really likes this value >:)

    struct {
        int uid;
        int gid;
    } owner;
} PCB_t;

int init_scheduler(); // inits the scheduler on every CPU with an idle process

int init_cpu_scheduler(int cpu); // inits the scheduler for a specific CPU with
                                 // an idle process and a thread queue

int proc_create(int ppid, void *entry);
int thread_create(PCB_t *proc, void *entry, int flags);
int proc_exit(int pid);
int thread_exit(int pid, int tid);

void schedule(registers_t *regs); // gets called by the lapic timer on each cpu

#endif // SCHEDULER_H
