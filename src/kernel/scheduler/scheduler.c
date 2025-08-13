#include "scheduler.h"

#include <cpu.h>
#include <errors.h>
#include <kernel.h>
#include <string.h>

#include <memory/heap/kheap.h>
#include <memory/vmm/vflags.h>
#include <memory/vmm/vmm.h>

#include <smp/smp.h>

#include <stdio.h>

static cpu_queue_t *thread_queues;
static tcb_t **current_threads;
static int cpu_count;

int init_scheduler(void (*p)()) {
    cpu_count = get_bootloader_data()->cpu_count;

    thread_queues   = kmalloc(sizeof(cpu_queue_t) * cpu_count);
    current_threads = kmalloc(sizeof(tcb_t *) * cpu_count);
    memset(thread_queues, 0, sizeof(cpu_queue_t) * cpu_count);
    memset(current_threads, 0, sizeof(tcb_t *) * cpu_count);

    for (int i = 0; i < cpu_count; ++i)
        init_cpu_scheduler(i, p);
    return 0;
}

static tcb_t *pick_next_thread(int cpu) {
    tcb_t *thread = thread_queues[cpu].head;

    for (; thread != NULL; thread = thread->next) {
        if (thread->state == THREAD_READY)
            return thread;
    }

    return NULL;
}

// I WANT ALL OF THE BITS :speaking_head: :fire: :fire:
static int64_t global_pid = -1;

int proc_create(void (*entry)(), int flags) {
    pcb_t *proc = kmalloc(sizeof(pcb_t));
    memset(proc, 0, sizeof(pcb_t));
    proc->pid   = __sync_fetch_and_add(&global_pid, 1);
    proc->state = PROC_READY;

    uint64_t *pagemap = pmm_alloc_page();
    int vflags        = (flags & TF_MODE_USER ? VMO_USER_RW : VMO_KERNEL_RW);
    proc->vmm_ctx     = vmm_ctx_init(pagemap, vflags);
    proc->cwd         = NULL;
    thread_create(proc, entry, flags);
    return proc->pid;
}

int thread_create(pcb_t *parent, void (*entry)(), int flags) {
    tcb_t *thread = kmalloc(sizeof(tcb_t));
    memset(thread, 0, sizeof(tcb_t));
    thread->tid    = __sync_fetch_and_add(&parent->thread_count, 1);
    thread->flags  = flags;
    thread->state  = THREAD_READY;
    thread->parent = parent;

    thread->time_slice = SCHEDULER_THREAD_TS;

    void *stack =
        (void *)PHYS_TO_VIRTUAL(pmm_alloc_pages(SCHEDULER_STACK_PAGES));

    task_regs_t *ctx = kmalloc(sizeof(task_regs_t));
    memset(ctx, 0, sizeof(task_regs_t));

    ctx->rip     = (uint64_t)entry;
    ctx->cs      = (flags & TF_MODE_USER) ? 0x1B : 0x08;
    ctx->ss      = (flags & TF_MODE_USER) ? 0x23 : 0x10;
    ctx->rflags  = 0x202;
    ctx->rsp     = (uint64_t)(stack + SCHEDULER_STACKSZ);
    ctx->fpu     = (void *)PHYS_TO_VIRTUAL(pmm_alloc_page());
    thread->regs = ctx;

    int cpu = 0;
    int min = thread_queues[0].count;
    for (int i = 1; i < cpu_count; ++i) {
        if (thread_queues[i].count < min) {
            cpu = i;
            min = thread_queues[i].count;
        }
    }

    thread->next            = thread_queues[cpu].head;
    thread_queues[cpu].head = thread;
    thread_queues[cpu].count++;

    parent->threads =
        krealloc(parent->threads, sizeof(tcb_t *) * parent->thread_count);
    parent->threads[thread->tid] = thread;

    if (!current_threads[cpu]) {
        current_threads[cpu] = thread;
    }

    return thread->tid;
}

pcb_t *pcb_lookup(int pid) {
    int cpu  = get_cpu();
    tcb_t *t = thread_queues[cpu].head;
    pcb_t *p = NULL;
    for (; t != NULL; t = t->next) {
        p = t->parent;
        if (!p) { // ...somehow??
            continue;
        }

        if (p->pid == pid) {
            break;
        }
    }

    return p;
}

tcb_t *tcb_lookup(int pid, int tid) {
    int cpu  = get_cpu();
    tcb_t *t = thread_queues[cpu].head;

    for (; t != NULL; t = t->next) {
        if (!t->parent) {
            continue;
        }

        pcb_t *parent = t->parent;
        if (parent->pid != pid) {
            continue;
        }

        if (t->tid != tid) {
            continue;
        }
    }

    return t;
}

int init_cpu_scheduler(int cpu, void (*p)()) {
    proc_create(p, 0);
    return 0;
}

int pcb_destroy(int pid) {
    // Mark process and threads as dead.
    pcb_t *p = pcb_lookup(pid);
    if (!p) {
        return ENULLPTR;
    }

    p->state = PROC_DEAD;
    for (int i = 0; i < p->thread_count; i++) {
        if (!p->threads[i]) {
            continue;
        }

        tcb_t *t = p->threads[i];
        t->state = THREAD_DEAD;
    }

    return EOK;
}

int thread_destroy(int pid, int tid) {
    tcb_t *t = tcb_lookup(pid, tid);
    if (!t) {
        return ENULLPTR;
    }

    t->state = THREAD_DEAD;

    return EOK;
}

// destroys current process
int proc_exit() {
    int cpu        = get_cpu();
    tcb_t *current = current_threads[cpu];

    return pcb_destroy(current->parent->pid);
}

void yield() {
    int cpu        = get_cpu();
    tcb_t *current = current_threads[cpu];
    tcb_t *next;

    switch (current->state) {
    case THREAD_READY:
        next        = current;
        next->state = THREAD_RUNNING;
        break;

    case THREAD_RUNNING:
        if (--current->time_slice > 0) {
            fpu_save(current->regs->fpu);
            context_save(current->regs);
            return;
        }

        current->state      = THREAD_READY;
        current->time_slice = SCHEDULER_THREAD_TS;
        break;

    case THREAD_WAITING:
    case THREAD_DEAD:
        next = pick_next_thread(cpu);
        if (!next) {
            mprintf_warn(
                "No more processes left to run. If you want, you can "
                "reboot your compooter, or you can keep your computer on to "
                "unlock a very high electrical bill :kekw:\n");
            scheduler_idle(); // good luck getting out of here >:D
        }
        break;
    }

    fpu_restore(next->regs->fpu);

    current_threads[cpu] = next;
    next->state          = THREAD_RUNNING;

    // it instantly returns to the RIP in here
    context_load(next->regs);
}
