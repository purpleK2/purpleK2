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

// SHOULD BE CALLED **ONLY ONCE** IN KSTART. NOWHERE ELSE.
int init_scheduler() {
    cpu_count = get_bootloader_data()->cpu_count;

    thread_queues   = kmalloc(sizeof(cpu_queue_t) * cpu_count);
    current_threads = kmalloc(sizeof(tcb_t *) * cpu_count);
    memset(thread_queues, 0, sizeof(cpu_queue_t) * cpu_count);
    memset(current_threads, 0, sizeof(tcb_t *) * cpu_count);
    return 0;
}

static tcb_t *pick_next_thread(int cpu) {
    tcb_t *thread = thread_queues[cpu].head;

    for (; thread != NULL; thread = thread->next) {
        if (thread->state == THREAD_READY) {
            return thread;
        }
    }

    return NULL;
}

// I WANT ALL OF THE BITS :speaking_head: :fire: :fire:
static uint64_t global_pid = 0;

// @param name name of the process (it's optional)
int proc_create(void (*entry)(), int flags, char *name) {
    pcb_t *proc = kmalloc(sizeof(pcb_t));
    memset(proc, 0, sizeof(pcb_t));
    proc->pid   = __sync_fetch_and_add(&global_pid, 1);
    proc->state = PROC_READY;

    if (name) {
        proc->name = strdup(name);
    }

    proc->fds      = NULL;
    proc->fd_count = 0;

    int vflags        = (flags & TF_MODE_USER ? VMO_USER_RW : VMO_KERNEL_RW);
    proc->vmm_ctx     = vmc_init(NULL, vflags);
    proc->cwd         = NULL;
    thread_create(proc, entry, flags);

    debugf("Created new process with entry %p PID=%d\n", entry, proc->pid);

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

    // so the struct sits on the top of the stack
    registers_t *ctx = kmalloc(sizeof(registers_t));
    memset(ctx, 0, sizeof(registers_t));

    ctx->rip     = (uint64_t)entry;
    ctx->cs      = (flags & TF_MODE_USER) ? 0x1B : 0x08;
    ctx->ss      = (flags & TF_MODE_USER) ? 0x23 : 0x10;
    ctx->ds      = (flags & TF_MODE_USER) ? 0x23 : 0x10;
    ctx->rflags  = 0x202;
    ctx->rsp     = (uint64_t)(stack + SCHEDULER_STACKSZ);
    thread->regs = ctx;
    thread->fpu  = (void *)PHYS_TO_VIRTUAL(pmm_alloc_page());

    int cpu                 = get_cpu();
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

// creates the "init process" per-CPU
int init_cpu_scheduler(void (*p)()) {
    proc_create(p, 0, "initproc");
    return 0;
}

int pcb_destroy(int pid) {
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

    // also remove it from the queue in the next yield just like the thread

    return EOK;
}

void thread_push_to_queue(tcb_t *to_push) {
    int cpu   = get_cpu();
    tcb_t **p = &thread_queues[cpu].head;

    while (*p && *p != to_push) {
        p = &(*p)->next;
    }
    if (*p == NULL) {
        return;
    }
    *p            = to_push->next;
    to_push->next = NULL;

    tcb_t **q = &thread_queues[cpu].head;
    while (*q) {
        q = &(*q)->next;
    }
    *q = to_push;
}

void thread_remove_from_queue(tcb_t *to_remove) {
    int cpu   = get_cpu();
    tcb_t **p = &thread_queues[cpu].head;

    while (*p && *p != to_remove) {
        p = &(*p)->next;
    }

    if (*p == NULL) {
        return;
    }

    *p              = to_remove->next;
    to_remove->next = NULL;
}

int thread_destroy(int pid, int tid) {
    tcb_t *t = tcb_lookup(pid, tid);
    if (!t) {
        return ENULLPTR;
    }

    t->state = THREAD_DEAD;

    // thread_remove_from_queue(t);
    // actually cleanup in the next yield

    return EOK;
}

pcb_t *get_current_pcb() {
    int cpu        = get_cpu();
    tcb_t *current = current_threads[cpu];
    return current ? current->parent : NULL;
}

// destroys current process
int proc_exit() {
    int cpu        = get_cpu();
    tcb_t *current = current_threads[cpu];

    int ret = pcb_destroy(current->parent->pid);
    return ret;
}

void yield(registers_t *regs) {
    int cpu        = get_cpu();
    tcb_t *current = current_threads[cpu];
    tcb_t *next;

    switch (current->state) {
    case THREAD_READY:
        next = current;
        break;

    case THREAD_RUNNING:
        if (--current->time_slice > 0) {
            return;
        }

        fpu_save(current->fpu);
        // RIP context_save (08/2025-11/2025)
        // TODO: find some way to save registers if regs == NULL
        memcpy(current->regs, regs, sizeof(registers_t));

        current->state      = THREAD_READY;
        current->time_slice = SCHEDULER_THREAD_TS;

        thread_push_to_queue(current);

        next = pick_next_thread(cpu);
        break;

    case THREAD_WAITING:
    case THREAD_DEAD:
        thread_remove_from_queue(current);
        next = pick_next_thread(cpu);
        break;
    }

    if (!next) {
        mprintf_warn(
            "No more processes left to run. If you want, you can "
            "reboot your compooter, or, you can keep your computer on to "
            "unlock a very high electrical bill :kekw:\n");
        scheduler_idle(); // good luck getting out of here >^D
    }

    current_threads[cpu] = next;
    next->state          = THREAD_RUNNING;

    fpu_restore(next->fpu);
    // it instantly returns to the RIP in here
    if (!regs) {
        // we won't return from here
        context_load(next->regs);
    }
    // or else... just do it the gentle way
    memcpy(regs, next->regs, sizeof(registers_t));
}
