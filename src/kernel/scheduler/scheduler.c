
// scheduler.c
#include <cpu.h>
#include <memory/heap/kheap.h>
#include <scheduler/scheduler.h>
#include <smp/smp.h>
#include <string.h>
#include <system/kernel.h>

static ThreadQueue_t thread_queues[MAX_CPUS];
static TCB_t *current_threads[MAX_CPUS];
static int cpu_count;

extern void context_switch(TaskContext **old_ctx, TaskContext *new_ctx);
extern void fpu_save(void *ctx);
extern void fpu_restore(void *ctx);

__attribute__((noreturn)) void idle_loop() {
    while (1)
        asm volatile("hlt");
}

int init_scheduler() {
    cpu_count = get_bootloader_data()->cpu_count;
    for (int i = 0; i < cpu_count; ++i)
        init_cpu_scheduler(i);
    return 0;
}

int init_cpu_scheduler(int cpu) {
    thread_queues[cpu].head  = NULL;
    thread_queues[cpu].count = 0;

    PCB_t *idle_proc = kmalloc(sizeof(PCB_t));
    memset(idle_proc, 0, sizeof(PCB_t));
    idle_proc->pid = -1;

    TCB_t *idle_thread = kmalloc(sizeof(TCB_t));
    memset(idle_thread, 0, sizeof(TCB_t));
    idle_thread->tid    = -1;
    idle_thread->state  = THREAD_RUNNING;
    idle_thread->stack  = kmalloc(sizeof(struct KernelStack));
    idle_thread->parent = idle_proc;
    idle_thread->flags  = 0;

    TaskContext *ctx = (TaskContext *)((uint8_t *)idle_thread->stack +
                                       SCHED_KSTACK_SIZE - sizeof(TaskContext));
    memset(ctx, 0, sizeof(TaskContext));
    ctx->rip         = (uint64_t)&idle_loop;
    ctx->cs          = 0x08;
    ctx->ss          = 0x10;
    ctx->rflags      = 0x202;
    idle_thread->ctx = ctx;

    thread_queues[cpu].idle_proc = idle_thread;
    current_threads[cpu]         = idle_thread;
    return 0;
}

static TCB_t *pick_next_thread(int cpu) {
    TCB_t *head = thread_queues[cpu].head;
    while (head) {
        if (head->state == THREAD_STARTABLE)
            return head;
        head = head->next;
    }
    return thread_queues[cpu].idle_proc;
}

void schedule(registers_t *regs) {
    int cpu        = get_cpu();
    TCB_t *current = current_threads[cpu];
    if (current->state == THREAD_RUNNING)
        current->state = THREAD_STARTABLE;

    fpu_save(current);

    TCB_t *next          = pick_next_thread(cpu);
    current_threads[cpu] = next;
    next->state          = THREAD_RUNNING;

    if (current != next)
        context_switch(&current->ctx, next->ctx);

    fpu_restore(next);
}

int proc_create(int ppid, void *entry) {
    static int global_pid = 1;
    PCB_t *proc           = kmalloc(sizeof(PCB_t));
    memset(proc, 0, sizeof(PCB_t));
    proc->pid     = __sync_fetch_and_add(&global_pid, 1);
    proc->state   = PROC_STARTABLE;
    proc->pagemap = vmm_ctx_init(get_kernel_pml4(), 0);
    proc->cwd     = NULL;
    thread_create(proc, entry, TF_MODE_USER);
    return proc->pid;
}

int thread_create(PCB_t *proc, void *entry, int flags) {
    TCB_t *thread = kmalloc(sizeof(TCB_t));
    memset(thread, 0, sizeof(TCB_t));
    thread->tid         = proc->tid_counter++;
    thread->entry_point = entry;
    thread->flags       = flags;
    thread->state       = THREAD_STARTABLE;
    thread->parent      = proc;
    thread->stack       = kmalloc(sizeof(struct KernelStack));

    TaskContext *ctx = (TaskContext *)((uint8_t *)thread->stack +
                                       SCHED_KSTACK_SIZE - sizeof(TaskContext));
    memset(ctx, 0, sizeof(TaskContext));
    ctx->rip    = (uint64_t)entry;
    ctx->cs     = (flags & TF_MODE_USER) ? 0x1B : 0x08;
    ctx->ss     = (flags & TF_MODE_USER) ? 0x23 : 0x10;
    ctx->rflags = 0x202;
    ctx->rsp    = (uint64_t)ctx + sizeof(TaskContext);
    thread->ctx = ctx;

    int cpu = 0, min = thread_queues[0].count;
    for (int i = 1; i < cpu_count; ++i) {
        if (thread_queues[i].count < min) {
            cpu = i;
            min = thread_queues[i].count;
        }
    }

    thread->next            = thread_queues[cpu].head;
    thread_queues[cpu].head = thread;
    thread_queues[cpu].count++;
    proc->threads[thread->tid] = thread;
    return thread->tid;
}

int proc_exit(int pid) {
    // Mark process and threads as dead.
    return 0;
}

int thread_exit(int pid, int tid) {
    // Mark thread as dead.
    return 0;
}
